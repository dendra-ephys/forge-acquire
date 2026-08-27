//! Windows process containment for production-owned helper processes.
//!
//! The process is created suspended, assigned to a `KILL_ON_JOB_CLOSE` Job
//! Object, and resumed only after assignment succeeds.  This is intentionally
//! independent of the Windows service host and is not registered here; the
//! caller must opt into the module explicitly.
//!
//! The process creation path does not invoke a shell. Existing callers may
//! explicitly retain the legacy inherited environment/current-directory
//! policy; production workers can instead provide a deterministic Unicode
//! environment block and absolute current directory.

#![cfg(windows)]

use std::ffi::{c_void, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Read;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::ptr::null;
use std::time::{Duration, Instant};

use forge_protocol_v1::sha256;
use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, HANDLE, STILL_ACTIVE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, GetProcessTimes,
    ResumeThread, TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::windows_deployment_security::LockedDeploymentFileProof;

const MAX_WINDOWS_COMMAND_LINE_U16: usize = 32_767;
const MAX_WINDOWS_ENVIRONMENT_U16: usize = 32_767;
const CLEANUP_WAIT_MS: u32 = 250;
const CLEANUP_EXIT_CODE: u32 = 0xE0F0;
const JOB_TERMINATION_EXIT_CODE: u32 = 0xE001;

/// The operation that produced a successful wait proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainedProcessWaitMethod {
    GracefulWait,
    JobObjectTermination,
}

/// A bounded, handle-based process exit proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainedProcessWaitEvidence {
    pub method: ContainedProcessWaitMethod,
    pub wait_deadline_ms: u32,
    pub wait_elapsed_ms: u32,
    pub wait_result: &'static str,
    pub exit_code: u32,
    pub job_active_processes_after_wait: u32,
    pub job_empty_proven: bool,
}

/// Non-lossy terminal observation for stop paths.  Unlike the older success
/// proof, this retains the failure facts needed to write an honest failed SCM
/// receipt after a durable StopIntent has been accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalObservationV1 {
    pub primary_wait_observed: bool,
    pub primary_exit_code: Option<u32>,
    pub job_active_processes: Option<u32>,
    pub forced_termination_attempted: bool,
    pub forced_termination_succeeded: bool,
    pub wait_error: Option<String>,
    pub query_error: Option<String>,
    pub terminate_error: Option<String>,
    pub observed_at_qpc_ns: u64,
}

/// Stable identity captured before the primary thread is resumed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainedProcessIdentity {
    pub pid: u32,
    pub creation_time_100ns: u64,
    pub executable_path: PathBuf,
    pub executable_sha256: [u8; 32],
}

/// Current service executable evidence held through the owner-spawn gate.
/// The denied write/delete sharing protects this opened file object from a
/// later pathname replacement while its final path, identity, link count and
/// SHA-256 are checked.  It does not prove the already-mapped service image's
/// provenance or Authenticode/WDAC/package policy; those remain separate
/// release gates.
pub struct LockedCurrentProcessIdentity {
    identity: ContainedProcessIdentity,
    _executable_lock: File,
}

impl LockedCurrentProcessIdentity {
    pub fn identity(&self) -> &ContainedProcessIdentity {
        &self.identity
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainedProcessContainmentEvidence {
    pub created_suspended: bool,
    pub kill_on_job_close_configured: bool,
    pub job_assigned_before_resume: bool,
    pub executable_rehashed_before_resume: bool,
}

/// Evidence describing whether process-wide module/DLL resolution inputs were
/// inherited or supplied as one explicit deterministic launch context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainedProcessLaunchContextEvidence {
    pub environment_inherited: bool,
    pub current_directory_inherited: bool,
    pub environment_entry_count: u16,
    pub environment_sha256: [u8; 32],
    pub current_directory: Option<PathBuf>,
}

/// Explicit launch context for a worker whose environment and current
/// directory are part of its evidence boundary. Environment names are treated
/// case-insensitively, as Windows does, and duplicate names are rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainedProcessLaunchOptions {
    environment: Vec<(OsString, OsString)>,
    current_directory: PathBuf,
}

impl ContainedProcessLaunchOptions {
    pub fn explicit(
        environment: Vec<(OsString, OsString)>,
        current_directory: impl Into<PathBuf>,
    ) -> io::Result<Self> {
        let options = Self {
            environment,
            current_directory: current_directory.into(),
        };
        let _ = prepare_explicit_launch_context(&options)?;
        Ok(options)
    }
}

impl ContainedProcessContainmentEvidence {
    /// The only evidence accepted by qualification as a successful spawn
    /// gate.  Keeping this check typed (rather than reconstructing booleans in
    /// a receipt builder) makes every missing creation/assignment/reverify
    /// fact fail closed.
    #[cfg_attr(not(feature = "qualification-harness"), allow(dead_code))]
    pub fn validate(self) -> io::Result<()> {
        if self.created_suspended
            && self.kill_on_job_close_configured
            && self.job_assigned_before_resume
            && self.executable_rehashed_before_resume
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "contained process lacks a complete suspended Job/executable proof",
            ))
        }
    }
}

struct OwnedHandle(HANDLE);

// A Windows kernel handle is movable between threads.  This wrapper owns one
// reference and closes it exactly once; all operations remain handle-based.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    fn new(handle: HANDLE, name: &'static str) -> io::Result<Self> {
        if handle.is_null() {
            return Err(io::Error::other(format!("{name} returned a null handle")));
        }
        Ok(Self(handle))
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// A process whose complete lifetime is contained by a Job Object.
pub struct ContainedProcess {
    process: OwnedHandle,
    _thread: OwnedHandle,
    job: OwnedHandle,
    identity: ContainedProcessIdentity,
    launch_context: ContainedProcessLaunchContextEvidence,
    finished: bool,
}

impl std::fmt::Debug for ContainedProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContainedProcess")
            .field("identity", &self.identity)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl ContainedProcess {
    /// Creates a process without a shell and assigns it before releasing its
    /// primary thread.  The executable is canonicalized and hashed both before
    /// and after creation; a change is treated as a fail-closed TOCTOU error.
    #[cfg(test)]
    pub fn spawn(executable: impl AsRef<Path>, args: &[OsString]) -> io::Result<Self> {
        let executable = canonical_executable(executable.as_ref())?;
        let ancestors = crate::windows_deployment_security::lock_test_deployment_ancestor_chain(
            executable.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "test executable has no parent")
            })?,
        )?;
        let mut proof = crate::windows_deployment_security::lock_deployment_file_proof(
            &executable,
            &ancestors,
        )?;
        Self::spawn_verified(&mut proof, args)
    }

    /// Production entry point. A crate-private retained file proof replaces a
    /// caller-supplied path/hash convention; the child is not resumed unless
    /// the same handle identity and bytes survive CreateProcessW unchanged.
    pub(crate) fn spawn_verified(
        executable_proof: &mut LockedDeploymentFileProof,
        args: &[OsString],
    ) -> io::Result<Self> {
        Self::spawn_verified_inner(executable_proof, args, None)
    }

    /// Production worker entry point with an explicit environment and current
    /// directory. This prevents ambient `PATH`, `PYTHONPATH`, working-directory
    /// and user-profile state from silently changing worker resolution.
    pub(crate) fn spawn_verified_with_options(
        executable_proof: &mut LockedDeploymentFileProof,
        args: &[OsString],
        options: &ContainedProcessLaunchOptions,
    ) -> io::Result<Self> {
        Self::spawn_verified_inner(executable_proof, args, Some(options))
    }

    fn spawn_verified_inner(
        executable_proof: &mut LockedDeploymentFileProof,
        args: &[OsString],
        options: Option<&ContainedProcessLaunchOptions>,
    ) -> io::Result<Self> {
        executable_proof.reverify()?;
        let expected_executable_sha256 = executable_proof.sha256_bytes();
        if expected_executable_sha256 == [0; 32] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected contained executable SHA-256 is zero",
            ));
        }
        let executable = canonical_executable(executable_proof.path())?;
        let mut command_line = build_command_line(&executable, args)?;
        let application_name = wide_null(executable.as_os_str(), "executable")?;

        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        let mut process_information: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let prepared_context = options.map(prepare_explicit_launch_context).transpose()?;
        let (creation_flags, environment, current_directory, launch_context) =
            if let Some(prepared) = prepared_context.as_ref() {
                (
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    prepared.environment_block.as_ptr().cast::<c_void>(),
                    prepared.current_directory_wide.as_ptr(),
                    prepared.evidence.clone(),
                )
            } else {
                (
                    CREATE_SUSPENDED | CREATE_NO_WINDOW,
                    null(),
                    null(),
                    ContainedProcessLaunchContextEvidence {
                        environment_inherited: true,
                        current_directory_inherited: true,
                        environment_entry_count: 0,
                        environment_sha256: [0; 32],
                        current_directory: None,
                    },
                )
            };
        let created = unsafe {
            CreateProcessW(
                application_name.as_ptr(),
                command_line.as_mut_ptr(),
                null(),
                null(),
                0,
                creation_flags,
                environment,
                current_directory,
                &startup,
                &mut process_information,
            )
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }

        let process = match OwnedHandle::new(process_information.hProcess, "CreateProcessW process")
        {
            Ok(value) => value,
            Err(error) => {
                // A successful CreateProcessW should always return both handles,
                // but close the thread handle if the defensive check fails.
                if !process_information.hThread.is_null() {
                    unsafe { CloseHandle(process_information.hThread) };
                }
                return Err(error);
            }
        };
        let thread = match OwnedHandle::new(process_information.hThread, "CreateProcessW thread") {
            Ok(value) => value,
            Err(error) => {
                unsafe {
                    TerminateProcess(process.0, CLEANUP_EXIT_CODE);
                    let _ = WaitForSingleObject(process.0, CLEANUP_WAIT_MS);
                }
                return Err(error);
            }
        };

        let job = match create_kill_on_close_job() {
            Ok(value) => value,
            Err(error) => {
                let cleanup = terminate_suspended_process(process.0, None);
                return Err(combine_failure("create Job Object", error, cleanup));
            }
        };

        if let Err(error) = assign_process_to_job(job.0, process.0) {
            let cleanup = terminate_suspended_process(process.0, Some(job.0));
            return Err(combine_failure(
                "assign process to Job Object",
                error,
                cleanup,
            ));
        }

        let post_creation_hash = match executable_proof.reverify() {
            Ok(()) => executable_proof.sha256_bytes(),
            Err(error) => {
                let cleanup = terminate_assigned_process(process.0, job.0);
                return Err(combine_failure(
                    "reverify stable executable after creation",
                    error,
                    cleanup,
                ));
            }
        };
        if post_creation_hash != expected_executable_sha256 {
            let cleanup = terminate_assigned_process(process.0, job.0);
            return Err(combine_failure(
                "executable changed during contained spawn",
                io::Error::new(io::ErrorKind::InvalidData, "executable SHA-256 changed"),
                cleanup,
            ));
        }

        let creation_time_100ns = match process_creation_time(process.0) {
            Ok(value) => value,
            Err(error) => {
                let cleanup = terminate_assigned_process(process.0, job.0);
                return Err(combine_failure(
                    "query contained process creation time",
                    error,
                    cleanup,
                ));
            }
        };
        let pid = process_information.dwProcessId;
        let resumed = unsafe { ResumeThread(thread.0) };
        if resumed != 1 {
            let error = if resumed == u32::MAX {
                io::Error::last_os_error()
            } else {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("ResumeThread returned unexpected prior suspend count {resumed}"),
                )
            };
            let cleanup = terminate_assigned_process(process.0, job.0);
            return Err(combine_failure("resume contained process", error, cleanup));
        }

        Ok(Self {
            process,
            _thread: thread,
            job,
            identity: ContainedProcessIdentity {
                pid,
                creation_time_100ns,
                executable_path: executable,
                executable_sha256: post_creation_hash,
            },
            launch_context,
            finished: false,
        })
    }

    pub fn identity(&self) -> &ContainedProcessIdentity {
        &self.identity
    }

    pub fn containment_evidence(&self) -> ContainedProcessContainmentEvidence {
        ContainedProcessContainmentEvidence {
            created_suspended: true,
            kill_on_job_close_configured: true,
            job_assigned_before_resume: true,
            executable_rehashed_before_resume: true,
        }
    }

    pub fn launch_context_evidence(&self) -> &ContainedProcessLaunchContextEvidence {
        &self.launch_context
    }

    /// Returns `None` while the process is still active.  This is a status
    /// query, not an exit proof; callers must use `wait_for_exit` or
    /// `terminate_and_reap` for receipt evidence.
    pub fn query_exit_code(&self) -> io::Result<Option<u32>> {
        let mut code = 0_u32;
        if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if code == STILL_ACTIVE as u32 {
            Ok(None)
        } else {
            Ok(Some(code))
        }
    }

    /// Waits for normal process exit using only the retained process handle.
    pub fn wait_for_exit(
        &mut self,
        deadline: Duration,
    ) -> io::Result<ContainedProcessWaitEvidence> {
        self.wait_with_method(deadline, ContainedProcessWaitMethod::GracefulWait)
    }

    /// Terminates the complete Job Object and proves process exit before
    /// returning.  No thread termination is used.
    #[allow(dead_code)] // Compatibility path retained for process-contained tests.
    pub fn terminate_and_reap(
        &mut self,
        remaining_budget: Duration,
    ) -> io::Result<ContainedProcessWaitEvidence> {
        let started = Instant::now();
        if remaining_budget.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "contained termination has zero remaining budget",
            ));
        }
        if self.finished {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "contained process has already been finished",
            ));
        }
        if self.query_exit_code()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process exited before Job Object termination was requested",
            ));
        }
        if unsafe { TerminateJobObject(self.job.0, JOB_TERMINATION_EXIT_CODE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let remaining = remaining_after_elapsed(
            remaining_budget,
            started.elapsed(),
            "contained termination exhausted its budget before reap wait",
        )?;
        self.wait_with_method(remaining, ContainedProcessWaitMethod::JobObjectTermination)
    }

    /// Attempts forced containment teardown without discarding an observation
    /// when a wait, exit-code query, job query, or termination call fails.
    /// This is intentionally not a success proof; callers must still reject
    /// it unless all fields establish a clean terminal state.
    pub fn terminate_and_observe(&mut self, remaining_budget: Duration) -> TerminalObservationV1 {
        let started = Instant::now();
        let mut observation = TerminalObservationV1 {
            primary_wait_observed: false,
            primary_exit_code: None,
            job_active_processes: None,
            forced_termination_attempted: false,
            forced_termination_succeeded: false,
            wait_error: None,
            query_error: None,
            terminate_error: None,
            observed_at_qpc_ns: 0,
        };
        match self.query_exit_code() {
            Ok(code) => observation.primary_exit_code = code,
            Err(error) => observation.query_error = Some(error.to_string()),
        }
        if observation.primary_exit_code.is_none() && observation.query_error.is_none() {
            observation.forced_termination_attempted = true;
            if unsafe { TerminateJobObject(self.job.0, JOB_TERMINATION_EXIT_CODE) } == 0 {
                observation.terminate_error = Some(io::Error::last_os_error().to_string());
            } else {
                observation.forced_termination_succeeded = true;
            }
        }
        match remaining_after_elapsed(
            remaining_budget,
            started.elapsed(),
            "contained terminal observation has no remaining reap budget",
        ) {
            Ok(remaining) => {
                match self
                    .wait_with_method(remaining, ContainedProcessWaitMethod::JobObjectTermination)
                {
                    Ok(evidence) => {
                        observation.primary_wait_observed = true;
                        observation.primary_exit_code = Some(evidence.exit_code);
                        observation.job_active_processes =
                            Some(evidence.job_active_processes_after_wait);
                    }
                    Err(error) => observation.wait_error = Some(error.to_string()),
                }
            }
            Err(error) => observation.wait_error = Some(error.to_string()),
        }
        if observation.job_active_processes.is_none() {
            match job_active_processes(self.job.0) {
                Ok(value) => observation.job_active_processes = Some(value),
                Err(error) if observation.query_error.is_none() => {
                    observation.query_error = Some(error.to_string())
                }
                Err(_) => {}
            }
        }
        observation.observed_at_qpc_ns =
            u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        observation
    }

    fn wait_with_method(
        &mut self,
        deadline: Duration,
        method: ContainedProcessWaitMethod,
    ) -> io::Result<ContainedProcessWaitEvidence> {
        if deadline.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "contained process wait has zero remaining budget",
            ));
        }
        if self.finished {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "contained process has already been finished",
            ));
        }
        let deadline_ms = duration_millis_u32(deadline)?;
        let started = Instant::now();
        let result = unsafe { WaitForSingleObject(self.process.0, deadline_ms) };
        match result {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("contained process did not exit within {deadline_ms} ms"),
                ))
            }
            WAIT_FAILED => return Err(io::Error::last_os_error()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WaitForSingleObject returned an unexpected result",
                ))
            }
        }
        if started.elapsed() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "contained process exit was observed after its deadline",
            ));
        }
        let exit_code = self.query_exit_code()?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "signaled process handle still reports STILL_ACTIVE",
            )
        })?;
        let mut active_processes = job_active_processes(self.job.0)?;
        while active_processes != 0 {
            let elapsed = started.elapsed();
            if elapsed >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "contained primary process exited but Job still has {active_processes} active process(es) at the deadline"
                    ),
                ));
            }
            std::thread::sleep((deadline - elapsed).min(Duration::from_millis(10)));
            active_processes = job_active_processes(self.job.0)?;
        }
        let elapsed = started.elapsed();
        if elapsed > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "empty Job was observed after its deadline",
            ));
        }
        let elapsed_ms = duration_millis_ceil_u32(elapsed)?;
        self.finished = true;
        Ok(ContainedProcessWaitEvidence {
            method,
            wait_deadline_ms: deadline_ms,
            wait_elapsed_ms: elapsed_ms,
            wait_result: "signaled_reaped",
            exit_code,
            job_active_processes_after_wait: active_processes,
            job_empty_proven: true,
        })
    }
}

#[cfg(test)]
pub fn current_process_identity() -> io::Result<ContainedProcessIdentity> {
    Ok(lock_current_process_identity()?.identity)
}

pub fn lock_current_process_identity() -> io::Result<LockedCurrentProcessIdentity> {
    let current_path = canonical_executable(&std::env::current_exe()?)?;
    let mut executable_lock = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&current_path)?;
    // The lock is already held before this handle-derived identity check, so
    // a later path replacement cannot make these observations refer to a
    // different file object during owner creation.
    let stable = crate::windows_deployment_security::inspect_stable_deployment_path(&current_path)?;
    if stable.is_directory || stable.link_count != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "current service executable is not a single-link regular file",
        ));
    }
    let mut bytes = Vec::new();
    executable_lock.read_to_end(&mut bytes)?;
    let executable_sha256 = sha256(&bytes);
    if executable_sha256 == [0; 32] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "current service executable SHA-256 is zero",
        ));
    }
    let pid = unsafe { GetCurrentProcessId() };
    if pid == 0 {
        return Err(io::Error::last_os_error());
    }
    let creation_time_100ns = process_creation_time(unsafe { GetCurrentProcess() })?;
    Ok(LockedCurrentProcessIdentity {
        identity: ContainedProcessIdentity {
            pid,
            creation_time_100ns,
            executable_path: PathBuf::from(stable.canonical_path),
            executable_sha256,
        },
        _executable_lock: executable_lock,
    })
}

impl Drop for ContainedProcess {
    fn drop(&mut self) {
        if !self.finished {
            // Drop must never block.  KILL_ON_JOB_CLOSE provides the best
            // available asynchronous containment fallback; callers must use
            // terminate_and_reap/finish when a receipt needs proof.
            unsafe {
                let _ = TerminateJobObject(self.job.0, JOB_TERMINATION_EXIT_CODE);
            }
        }
        // Fields are dropped in declaration order and close the process,
        // primary-thread, and Job handles exactly once.
    }
}

fn canonical_executable(path: &Path) -> io::Result<PathBuf> {
    reject_nul(path.as_os_str(), "executable")?;
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "contained executable must be an absolute path",
        ));
    }
    let canonical = std::fs::canonicalize(path)?;
    let metadata = std::fs::metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "contained executable must be a regular file",
        ));
    }
    reject_nul(canonical.as_os_str(), "canonical executable")?;
    Ok(canonical)
}

fn reject_nul(value: &OsStr, label: &'static str) -> io::Result<()> {
    if value.encode_wide().any(|unit| unit == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} contains an embedded NUL"),
        ));
    }
    Ok(())
}

fn wide_null(value: &OsStr, label: &'static str) -> io::Result<Vec<u16>> {
    reject_nul(value, label)?;
    let mut wide: Vec<u16> = value.encode_wide().collect();
    wide.push(0);
    Ok(wide)
}

/// Quotes one argument using the Windows CRT backslash/quote convention.
/// Empty arguments are rejected to avoid an ambiguous command contract.
pub fn quote_windows_argument(value: &OsStr) -> io::Result<Vec<u16>> {
    reject_nul(value, "command-line argument")?;
    let units: Vec<u16> = value.encode_wide().collect();
    if units.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty command-line arguments are not accepted",
        ));
    }
    if !units.iter().any(|unit| matches!(*unit, 0x20 | 0x09 | 0x22)) {
        return Ok(units);
    }
    let mut output = Vec::with_capacity(units.len() + 2);
    output.push(b'"' as u16);
    let mut backslashes = 0_usize;
    for unit in units {
        if unit == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            output.push(unit);
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            output.push(unit);
        }
        backslashes = 0;
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    output.push(b'"' as u16);
    Ok(output)
}

/// Builds a mutable, NUL-terminated CreateProcessW command line.
pub fn build_command_line(executable: &Path, args: &[OsString]) -> io::Result<Vec<u16>> {
    reject_nul(executable.as_os_str(), "executable")?;
    if executable.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable path is empty",
        ));
    }
    let mut output = quote_windows_argument(executable.as_os_str())?;
    for argument in args {
        output.push(b' ' as u16);
        output.extend(quote_windows_argument(argument)?);
    }
    if output.len() + 1 > MAX_WINDOWS_COMMAND_LINE_U16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CreateProcessW command line exceeds the Windows limit",
        ));
    }
    output.push(0);
    Ok(output)
}

struct PreparedExplicitLaunchContext {
    environment_block: Vec<u16>,
    current_directory_wide: Vec<u16>,
    evidence: ContainedProcessLaunchContextEvidence,
}

fn prepare_explicit_launch_context(
    options: &ContainedProcessLaunchOptions,
) -> io::Result<PreparedExplicitLaunchContext> {
    let current_directory = std::fs::canonicalize(&options.current_directory)?;
    if !current_directory.is_absolute() || !current_directory.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "contained process current directory must be an existing absolute directory",
        ));
    }
    let current_directory_wide = wide_null(
        current_directory.as_os_str(),
        "contained process current directory",
    )?;

    let mut entries = Vec::with_capacity(options.environment.len());
    for (name, value) in &options.environment {
        let name_text = name.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "contained process environment name must be Unicode ASCII",
            )
        })?;
        if name_text.is_empty()
            || !name_text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "contained process environment name must match [A-Za-z0-9_]+",
            ));
        }
        if value.encode_wide().any(|unit| unit == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "contained process environment value contains NUL",
            ));
        }
        entries.push((name_text.to_ascii_uppercase(), value.clone()));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "contained process environment contains a case-insensitive duplicate",
        ));
    }

    let environment_entry_count = u16::try_from(entries.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "contained process environment has too many entries",
        )
    })?;
    let mut environment_block = Vec::new();
    for (name, value) in entries {
        environment_block.extend(name.encode_utf16());
        environment_block.push(u16::from(b'='));
        environment_block.extend(value.encode_wide());
        environment_block.push(0);
    }
    if environment_block.is_empty() {
        environment_block.push(0);
    }
    environment_block.push(0);
    if environment_block.len() > MAX_WINDOWS_ENVIRONMENT_U16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "contained process environment exceeds the Windows Unicode limit",
        ));
    }
    let mut environment_bytes = Vec::with_capacity(environment_block.len() * 2);
    for unit in &environment_block {
        environment_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let environment_sha256 = sha256(&environment_bytes);

    Ok(PreparedExplicitLaunchContext {
        environment_block,
        current_directory_wide,
        evidence: ContainedProcessLaunchContextEvidence {
            environment_inherited: false,
            current_directory_inherited: false,
            environment_entry_count,
            environment_sha256,
            current_directory: Some(current_directory),
        },
    })
}

fn create_kill_on_close_job() -> io::Result<OwnedHandle> {
    let job = unsafe { CreateJobObjectW(null(), null()) };
    let job = OwnedHandle::new(job, "CreateJobObjectW")?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let configured = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const c_void,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if configured == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

fn assign_process_to_job(job: HANDLE, process: HANDLE) -> io::Result<()> {
    if unsafe { AssignProcessToJobObject(job, process) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn job_active_processes(job: HANDLE) -> io::Result<u32> {
    let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
    let queried = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            &mut accounting as *mut _ as *mut c_void,
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    };
    if queried == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(accounting.ActiveProcesses)
    }
}

fn terminate_suspended_process(process: HANDLE, job: Option<HANDLE>) -> io::Result<()> {
    let mut first_error = None;
    if let Some(job) = job {
        if unsafe { TerminateJobObject(job, CLEANUP_EXIT_CODE) } == 0 {
            first_error = Some(io::Error::last_os_error());
        }
    }
    if first_error.is_some() && unsafe { TerminateProcess(process, CLEANUP_EXIT_CODE) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let wait = unsafe { WaitForSingleObject(process, CLEANUP_WAIT_MS) };
    if wait == WAIT_OBJECT_0 {
        return Ok(());
    }
    // A second bounded TerminateProcess closes the race where Job termination
    // was accepted but the process had not yet become signaled.
    let second_error = if unsafe { TerminateProcess(process, CLEANUP_EXIT_CODE) } == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    let second_wait = unsafe { WaitForSingleObject(process, CLEANUP_WAIT_MS) };
    if second_wait == WAIT_OBJECT_0 {
        return Ok(());
    }
    let reason = match second_wait {
        WAIT_FAILED => io::Error::last_os_error(),
        WAIT_TIMEOUT => io::Error::new(
            io::ErrorKind::TimedOut,
            "failed spawn process was not proven exited within cleanup deadline",
        ),
        _ => io::Error::new(
            io::ErrorKind::InvalidData,
            "cleanup wait returned an unexpected result",
        ),
    };
    if let Some(error) = second_error.or(first_error) {
        Err(io::Error::other(format!(
            "{reason}; termination error: {error}"
        )))
    } else {
        Err(reason)
    }
}

fn terminate_assigned_process(process: HANDLE, job: HANDLE) -> io::Result<()> {
    terminate_suspended_process(process, Some(job))
}

fn combine_failure(
    context: &'static str,
    primary: io::Error,
    cleanup: io::Result<()>,
) -> io::Error {
    match cleanup {
        Ok(()) => io::Error::new(primary.kind(), format!("{context}: {primary}")),
        Err(cleanup_error) => io::Error::other(format!(
            "{context}: {primary}; bounded cleanup failed: {cleanup_error}"
        )),
    }
}

fn process_creation_time(process: HANDLE) -> io::Result<u64> {
    let mut creation: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };
    if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if value == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process creation time is zero",
        ));
    }
    Ok(value)
}

fn remaining_after_elapsed(
    budget: Duration,
    elapsed: Duration,
    exhausted_message: &'static str,
) -> io::Result<Duration> {
    if budget.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, exhausted_message));
    }
    budget
        .checked_sub(elapsed)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, exhausted_message))
}

fn duration_millis_u32(value: Duration) -> io::Result<u32> {
    u32::try_from(value.as_millis()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "wait deadline exceeds the Windows DWORD millisecond bound",
        )
    })
}

fn duration_millis_ceil_u32(value: Duration) -> io::Result<u32> {
    let nanos = value.as_nanos();
    let millis = nanos
        .checked_add(999_999)
        .ok_or_else(|| io::Error::other("wait elapsed duration overflow"))?
        / 1_000_000;
    u32::try_from(millis).map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "wait elapsed duration exceeds evidence representation",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    fn decode(units: &[u16]) -> String {
        String::from_utf16(units).expect("test command line is UTF-16")
    }

    fn cmd() -> PathBuf {
        let root = std::env::var_os("SystemRoot").expect("SystemRoot is set");
        PathBuf::from(root).join("System32").join("cmd.exe")
    }

    fn copied_cmd(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "forge-contained-process-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let executable = root.join("cmd.exe");
        std::fs::copy(cmd(), &executable).unwrap();
        executable
    }

    #[test]
    fn windows_quote_matrix_is_deterministic() {
        let cases = [
            ("plain", "plain"),
            ("with space", r#""with space""#),
            ("quote\"", "\"quote\\\"\""),
            ("slash\\", "slash\\"),
            ("slash\\\"quote", "\"slash\\\\\\\"quote\""),
        ];
        for (input, expected) in cases {
            assert_eq!(
                decode(&quote_windows_argument(OsStr::new(input)).unwrap()),
                expected
            );
        }
        assert!(quote_windows_argument(OsStr::new("")).is_err());
        assert!(quote_windows_argument(
            OsString::from_wide(&[b'a' as u16, 0, b'b' as u16]).as_os_str()
        )
        .is_err());
    }

    #[test]
    fn command_line_is_nul_terminated_and_shell_free() {
        let line =
            build_command_line(&cmd(), &[OsString::from("/c"), OsString::from("exit 7")]).unwrap();
        assert_eq!(line.last(), Some(&0));
        let decoded = decode(&line[..line.len() - 1]);
        assert!(decoded.contains("cmd.exe"));
        assert!(decoded.contains("/c"));
    }

    #[test]
    fn explicit_launch_context_is_sorted_hashed_and_does_not_inherit() {
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let first = ContainedProcessLaunchOptions::explicit(
            vec![
                (OsString::from("ZETA"), OsString::from("last")),
                (OsString::from("alpha"), OsString::from("first")),
            ],
            &root,
        )
        .unwrap();
        let second = ContainedProcessLaunchOptions::explicit(
            vec![
                (OsString::from("ALPHA"), OsString::from("first")),
                (OsString::from("zeta"), OsString::from("last")),
            ],
            &root,
        )
        .unwrap();
        let first = prepare_explicit_launch_context(&first).unwrap();
        let second = prepare_explicit_launch_context(&second).unwrap();
        assert_eq!(first.environment_block, second.environment_block);
        assert_eq!(first.evidence, second.evidence);
        assert_eq!(
            first
                .environment_block
                .iter()
                .rev()
                .take(2)
                .copied()
                .collect::<Vec<_>>(),
            vec![0, 0]
        );
        assert!(!first.evidence.environment_inherited);
        assert!(!first.evidence.current_directory_inherited);
        assert_eq!(first.evidence.environment_entry_count, 2);
        assert_ne!(first.evidence.environment_sha256, [0; 32]);
        assert_eq!(
            first.evidence.current_directory.as_deref(),
            Some(root.as_path())
        );
    }

    #[test]
    fn explicit_launch_context_rejects_ambient_ambiguity() {
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(ContainedProcessLaunchOptions::explicit(
            vec![
                (OsString::from("Path"), OsString::from("one")),
                (OsString::from("PATH"), OsString::from("two")),
            ],
            &root,
        )
        .is_err());
        assert!(ContainedProcessLaunchOptions::explicit(
            vec![(OsString::from("BAD=NAME"), OsString::from("value"))],
            &root,
        )
        .is_err());
        assert!(ContainedProcessLaunchOptions::explicit(
            vec![(
                OsString::from("GOOD"),
                OsString::from_wide(&[b'a' as u16, 0, b'b' as u16]),
            )],
            &root,
        )
        .is_err());
        assert!(
            ContainedProcessLaunchOptions::explicit(Vec::new(), PathBuf::from("relative")).is_err()
        );
    }

    #[test]
    fn contained_process_normal_exit_has_identity_and_exit_evidence() {
        let executable = copied_cmd("normal");
        let mut process = ContainedProcess::spawn(
            &executable,
            &[
                OsString::from("/d"),
                OsString::from("/c"),
                OsString::from("exit"),
                OsString::from("7"),
            ],
        )
        .unwrap();
        assert!(process.identity().pid != 0);
        assert!(process.identity().creation_time_100ns != 0);
        assert_eq!(process.identity().executable_sha256.len(), 32);
        assert_eq!(
            process.containment_evidence(),
            ContainedProcessContainmentEvidence {
                created_suspended: true,
                kill_on_job_close_configured: true,
                job_assigned_before_resume: true,
                executable_rehashed_before_resume: true,
            }
        );
        let evidence = process.wait_for_exit(Duration::from_secs(5)).unwrap();
        assert_eq!(evidence.method, ContainedProcessWaitMethod::GracefulWait);
        assert_eq!(evidence.wait_result, "signaled_reaped");
        assert_eq!(evidence.exit_code, 7);
        assert_eq!(evidence.job_active_processes_after_wait, 0);
        assert!(evidence.job_empty_proven);
        std::fs::remove_file(&executable).unwrap();
        std::fs::remove_dir(executable.parent().unwrap()).unwrap();
    }

    #[test]
    fn every_missing_spawn_gate_fact_is_rejected() {
        let complete = ContainedProcessContainmentEvidence {
            created_suspended: true,
            kill_on_job_close_configured: true,
            job_assigned_before_resume: true,
            executable_rehashed_before_resume: true,
        };
        complete.validate().unwrap();
        for index in 0..4 {
            let mut candidate = complete;
            match index {
                0 => candidate.created_suspended = false,
                1 => candidate.kill_on_job_close_configured = false,
                2 => candidate.job_assigned_before_resume = false,
                3 => candidate.executable_rehashed_before_resume = false,
                _ => unreachable!(),
            }
            assert!(candidate.validate().is_err());
        }
    }

    #[test]
    fn job_termination_is_bounded_and_pid_is_reaped() {
        let executable = copied_cmd("terminate");
        let mut process = ContainedProcess::spawn(
            &executable,
            &[
                OsString::from("/c"),
                OsString::from("ping -n 30 127.0.0.1 >NUL"),
            ],
        )
        .unwrap();
        assert!(process.query_exit_code().unwrap().is_none());
        let evidence = process.terminate_and_reap(Duration::from_secs(5)).unwrap();
        assert_eq!(
            evidence.method,
            ContainedProcessWaitMethod::JobObjectTermination
        );
        assert_eq!(evidence.wait_result, "signaled_reaped");
        assert_eq!(evidence.job_active_processes_after_wait, 0);
        assert!(evidence.job_empty_proven);
        let handle: HANDLE = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                process.identity().pid,
            )
        };
        if !handle.is_null() {
            let mut exit_code = 0_u32;
            assert_eq!(unsafe { GetExitCodeProcess(handle, &mut exit_code) }, 1);
            assert_ne!(exit_code, STILL_ACTIVE as u32);
            unsafe { CloseHandle(handle) };
        }
        std::fs::remove_file(&executable).unwrap();
        std::fs::remove_dir(executable.parent().unwrap()).unwrap();
    }

    #[test]
    fn elapsed_setup_is_subtracted_instead_of_resetting_the_reap_budget() {
        assert_eq!(
            remaining_after_elapsed(Duration::from_secs(5), Duration::from_secs(2), "exhausted")
                .unwrap(),
            Duration::from_secs(3)
        );
        assert!(remaining_after_elapsed(Duration::ZERO, Duration::ZERO, "exhausted").is_err());
        assert!(remaining_after_elapsed(
            Duration::from_secs(5),
            Duration::from_secs(5),
            "exhausted"
        )
        .is_err());
        assert!(remaining_after_elapsed(
            Duration::from_secs(5),
            Duration::from_secs(6),
            "exhausted"
        )
        .is_err());
    }

    #[test]
    fn zero_remaining_budget_forces_but_never_starts_a_wait() {
        let executable = copied_cmd("zero-budget");
        let mut process = ContainedProcess::spawn(
            &executable,
            &[
                OsString::from("/c"),
                OsString::from("ping -n 30 127.0.0.1 >NUL"),
            ],
        )
        .unwrap();
        let started = Instant::now();
        let observation = process.terminate_and_observe(Duration::ZERO);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(observation.forced_termination_attempted);
        assert!(observation.forced_termination_succeeded);
        assert!(!observation.primary_wait_observed);
        assert!(observation
            .wait_error
            .as_deref()
            .is_some_and(|message| message.contains("no remaining reap budget")));
        // A separate test-only cleanup wait is allowed after the no-wait fact
        // has been observed; production never receives a renewed Stop budget.
        process.wait_for_exit(Duration::from_secs(5)).unwrap();
        std::fs::remove_file(&executable).unwrap();
        std::fs::remove_dir(executable.parent().unwrap()).unwrap();
    }

    #[test]
    fn invalid_executable_and_arguments_fail_closed() {
        assert!(ContainedProcess::spawn(PathBuf::from("relative.exe"), &[]).is_err());
        assert!(ContainedProcess::spawn(cmd().join("missing.exe"), &[]).is_err());
        assert!(build_command_line(&cmd(), &[OsString::new()]).is_err());
        assert!(build_command_line(&PathBuf::from(""), &[]).is_err());
    }

    #[test]
    fn current_process_identity_is_handle_bound() {
        let identity = current_process_identity().unwrap();
        assert_eq!(identity.pid, std::process::id());
        assert!(identity.creation_time_100ns > 0);
        assert!(identity.executable_path.is_absolute());
        assert_ne!(identity.executable_sha256, [0; 32]);
    }
}
