#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_service::service::ServiceAccess;
use windows_service::service::{
    ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceExitCode,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::ipc::lookup_account_sid;
use crate::ipc::{call_secure_pipe_bounded, canonical_sid_string, wait_for_secure_pipe};
use crate::scm_owner_protocol::{
    decode_response, encode_request, qpc_now_ns, validate_activation_response,
    validate_ready_response, validate_response_for_request, ExpectedOwnerControlPeer,
    ScmOwnerCommandV1, ScmOwnerRequestV1, ScmOwnerResponseV1, SCM_OWNER_REQUEST_SCHEMA,
};
use crate::scm_stop_receipt::{
    publish_scm_stop_receipt_v1, publish_stop_intent_v1, scm_stop_evidence_paths_v1,
    verify_owner_stop_outcome_for_intent_v1, verify_scm_stop_receipt_v1, ScmFinalStatusV1,
    ScmStopEvidenceSourceV1, ScmStopLedgerWriterV1, ScmStopReasonV1, ScmStopReceiptV1,
    ScmStopVerificationExpectationV1, ScmTerminalCommitQualificationV1, StableFileBindingV1,
    StopIntentKindV1, StopIntentV1, StopProcessIdentityV1, SCM_STOP_RECEIPT_SCHEMA,
};
use crate::windows_contained_process::{
    lock_current_process_identity, ContainedProcess, ContainedProcessWaitEvidence,
};
use crate::windows_deployment_manifest::{
    load_and_verify_windows_deployment_manifest_v1, WindowsDeploymentManifestExpectationV1,
};
use crate::windows_deployment_security::{
    inspect_stable_deployment_path, lock_deployment_ancestor_chain, lock_deployment_file_proof,
    lock_exact_deployment_leaf_chain, require_canonical_deployment_path,
    verify_deployment_ancestor_dacl, verify_file_or_directory_dacl, DeploymentSecuritySpec,
    LockedDeploymentFileProof,
};
use crate::windows_service_install::{verify_scm_service_contract, ScmServiceContractExpectation};
use crate::windows_service_owner::owner_launch_arguments;
use crate::ProtectedDirectPodPolicyReference;

pub const SERVICE_NAME: &str = "ForgeAcquire";
pub const SERVICE_ACCOUNT_NAME: &str = r"NT SERVICE\ForgeAcquire";
pub const DEFAULT_ANALYSIS_PIPE_NAME: &str = r"\\.\pipe\forge-acqd-analysis-v2";
pub const DEFAULT_HARDWARE_PIPE_NAME: &str = r"\\.\pipe\forge-acqd-hardware-v2";
pub const SCM_RESTART_DELAYS_SECONDS: [u64; 3] = [5, 15, 60];
pub const SCM_FAILURE_RESET_SECONDS: u64 = 86_400;
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
const EXIT_INITIALIZATION_FAILED: u32 = 1;
const EXIT_OWNER_FAILED: u32 = 2;
const EXIT_STOP_EVIDENCE_FAILED: u32 = 3;
const START_HARD_DEADLINE: Duration = Duration::from_secs(20);
const OWNER_STARTUP_REAP_BUDGET: Duration = Duration::from_secs(5);
const STATUS_HEARTBEAT: Duration = Duration::from_secs(1);
const STATUS_WAIT_HINT: Duration = Duration::from_secs(5);
const OWNER_PIPE_PROBE_MS: u32 = 250;
const OWNER_PIPE_WAIT_MS: u32 = 500;
const OWNER_PIPE_IO_MS: u32 = 2_000;
const OWNER_COMMAND_LEAD_NS: u64 = 5_000_000_000;
const STOP_TOTAL_DEADLINE_NS: u64 = 15_000_000_000;
const STOP_FORCE_REAP_RESERVE_NS: u64 = 5_000_000_000;
const RUNTIME_STOP_COMMIT_QUALIFICATION: ScmTerminalCommitQualificationV1 =
    ScmTerminalCommitQualificationV1::UnqualifiedSynchronousIo;
const RUNTIME_STOP_FINAL_STATUS: ScmFinalStatusV1 = ScmFinalStatusV1::Failed;
const OWNER_POLL_INTERVAL: Duration = Duration::from_millis(100);
const STOP_REASON_NONE: u8 = 0;
const STOP_REASON_CONTROL_STOP: u8 = 1;
const STOP_REASON_CONTROL_SHUTDOWN: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StopDeadlineBudget {
    control_qpc_ns: u64,
    graceful_cutoff_qpc_ns: u64,
    final_deadline_qpc_ns: u64,
}

impl StopDeadlineBudget {
    fn from_control_qpc(control_qpc_ns: u64) -> io::Result<Self> {
        if control_qpc_ns == 0
            || STOP_FORCE_REAP_RESERVE_NS == 0
            || STOP_FORCE_REAP_RESERVE_NS >= STOP_TOTAL_DEADLINE_NS
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SCM Stop deadline origin/reserve is invalid",
            ));
        }
        let final_deadline_qpc_ns = control_qpc_ns
            .checked_add(STOP_TOTAL_DEADLINE_NS)
            .ok_or_else(|| io::Error::other("SCM Stop final QPC deadline overflow"))?;
        let graceful_cutoff_qpc_ns = final_deadline_qpc_ns
            .checked_sub(STOP_FORCE_REAP_RESERVE_NS)
            .filter(|cutoff| *cutoff > control_qpc_ns)
            .ok_or_else(|| io::Error::other("SCM Stop graceful cutoff is invalid"))?;
        Ok(Self {
            control_qpc_ns,
            graceful_cutoff_qpc_ns,
            final_deadline_qpc_ns,
        })
    }

    fn graceful_remaining_with<F>(&self, clock: F) -> io::Result<Duration>
    where
        F: FnOnce() -> io::Result<u64>,
    {
        remaining_duration_at(self.control_qpc_ns, clock()?, self.graceful_cutoff_qpc_ns)
    }

    fn final_remaining_with<F>(&self, clock: F) -> io::Result<Duration>
    where
        F: FnOnce() -> io::Result<u64>,
    {
        remaining_duration_at(self.control_qpc_ns, clock()?, self.final_deadline_qpc_ns)
    }

    fn force_reap_remaining_with<F>(&self, clock: F) -> io::Result<Duration>
    where
        F: FnOnce() -> io::Result<u64>,
    {
        let remaining = self.final_remaining_with(clock)?;
        Ok(remaining.min(Duration::from_nanos(STOP_FORCE_REAP_RESERVE_NS)))
    }
}

fn remaining_duration_at(
    control_qpc_ns: u64,
    now_qpc_ns: u64,
    deadline_qpc_ns: u64,
) -> io::Result<Duration> {
    if control_qpc_ns == 0 || now_qpc_ns == 0 || deadline_qpc_ns == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SCM Stop QPC values must be nonzero",
        ));
    }
    if now_qpc_ns < control_qpc_ns {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SCM Stop QPC clock moved backwards before its callback origin",
        ));
    }
    let remaining_ns = deadline_qpc_ns.checked_sub(now_qpc_ns).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "SCM Stop absolute deadline has elapsed",
        )
    })?;
    if remaining_ns == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "SCM Stop absolute deadline has zero remaining budget",
        ));
    }
    Ok(Duration::from_nanos(remaining_ns))
}

static SERVICE_CONFIG: OnceLock<ServiceDispatchConfig> = OnceLock::new();
static SERVICE_TERMINAL_ERROR: OnceLock<Mutex<Option<String>>> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceHostConfig {
    pub data_root: PathBuf,
    pub operator_sid: String,
    pub pipe_name: String,
    pub hardware_pipe_name: String,
    pub analysis_worker_sid: Option<String>,
    pub analysis_pipe_name: String,
    pub direct_pod_policy: Option<ProtectedDirectPodPolicyReference>,
}

/// SCM-only launch material. Keeping the deployment manifest outside the
/// business-owner configuration prevents the contained owner from treating an
/// arbitrary command-line path as an authorization input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceDispatchConfig {
    host: ServiceHostConfig,
    deployment_manifest_path: PathBuf,
}

impl ServiceHostConfig {
    pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> io::Result<Self> {
        let mut arguments = arguments.into_iter();
        let mut data_root = None;
        let mut operator_sid = None;
        let mut pipe_name = None;
        let mut hardware_pipe_name = None;
        let mut analysis_worker_sid = None;
        let mut analysis_pipe_name = None;
        let mut direct_pod_policy_path = None;
        let mut direct_pod_policy_sha256 = None;
        let mut internal_approval_authority_sha256 = None;
        while let Some(argument) = arguments.next() {
            let argument = argument.into_string().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "service argument is not Unicode",
                )
            })?;
            let value = arguments.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("missing value after {argument}"),
                )
            })?;
            let value = value.into_string().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "service value is not Unicode")
            })?;
            match argument.as_str() {
                "--data-root" if data_root.is_none() => data_root = Some(PathBuf::from(value)),
                "--operator-sid" if operator_sid.is_none() => operator_sid = Some(value),
                "--pipe" if pipe_name.is_none() => pipe_name = Some(value),
                "--hardware-pipe" if hardware_pipe_name.is_none() => {
                    hardware_pipe_name = Some(value)
                }
                "--analysis-worker-sid" if analysis_worker_sid.is_none() => {
                    analysis_worker_sid = Some(value)
                }
                "--analysis-pipe" if analysis_pipe_name.is_none() => {
                    analysis_pipe_name = Some(value)
                }
                "--direct-pod-policy" if direct_pod_policy_path.is_none() => {
                    direct_pod_policy_path = Some(PathBuf::from(value))
                }
                "--direct-pod-policy-sha256" if direct_pod_policy_sha256.is_none() => {
                    direct_pod_policy_sha256 = Some(value)
                }
                "--internal-approval-authority-sha256"
                    if internal_approval_authority_sha256.is_none() =>
                {
                    internal_approval_authority_sha256 = Some(value)
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown or duplicate service option: {argument}"),
                    ))
                }
            }
        }
        let data_root = data_root.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "--data-root is required")
        })?;
        let operator_sid = operator_sid.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "--operator-sid is required")
        })?;
        let operator_sid = canonical_sid_string(&operator_sid)?;
        let analysis_worker_sid = analysis_worker_sid
            .as_deref()
            .map(canonical_sid_string)
            .transpose()?;
        if analysis_pipe_name.is_some() && analysis_worker_sid.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--analysis-pipe requires --analysis-worker-sid",
            ));
        }
        if !data_root.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "service data root must be absolute",
            ));
        }
        let metadata = std::fs::metadata(&data_root)?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "service data root is not a directory",
            ));
        }
        let pipe_name = pipe_name.unwrap_or_else(|| crate::ipc::DEFAULT_PIPE_NAME.to_owned());
        let hardware_pipe_name =
            hardware_pipe_name.unwrap_or_else(|| DEFAULT_HARDWARE_PIPE_NAME.to_owned());
        let analysis_pipe_name =
            analysis_pipe_name.unwrap_or_else(|| DEFAULT_ANALYSIS_PIPE_NAME.to_owned());
        let direct_pod_policy = match (
            direct_pod_policy_path,
            direct_pod_policy_sha256,
            internal_approval_authority_sha256,
        ) {
            (None, None, None) => None,
            (Some(path), Some(policy_hash), Some(authority_hash)) => Some(
                ProtectedDirectPodPolicyReference::from_hex(path, &policy_hash, &authority_hash)?,
            ),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "direct-Pod policy path, policy hash, and internal approval-authority hash are all required together",
                ))
            }
        };
        if pipe_name.eq_ignore_ascii_case(&hardware_pipe_name)
            || (analysis_worker_sid.is_some()
                && (pipe_name.eq_ignore_ascii_case(&analysis_pipe_name)
                    || hardware_pipe_name.eq_ignore_ascii_case(&analysis_pipe_name)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control, hardware, and enabled analysis pipes must be distinct",
            ));
        }
        Ok(Self {
            data_root,
            operator_sid,
            pipe_name,
            hardware_pipe_name,
            analysis_worker_sid,
            analysis_pipe_name,
            direct_pod_policy,
        })
    }
}

impl ServiceDispatchConfig {
    /// Parses the public SCM entrypoint. The deployment manifest is required
    /// here, but intentionally excluded from `ServiceHostConfig` and all
    /// internal owner launch material.
    pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> io::Result<Self> {
        let mut retained = Vec::new();
        let mut values = arguments.into_iter();
        let mut deployment_manifest_path = None;
        while let Some(argument) = values.next() {
            if argument == "--deployment-manifest" {
                let value = values.next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing value after --deployment-manifest",
                    )
                })?;
                if deployment_manifest_path
                    .replace(PathBuf::from(value))
                    .is_some()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "duplicate --deployment-manifest",
                    ));
                }
            } else {
                let value = values.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "service option lacks a value")
                })?;
                retained.extend([argument, value]);
            }
        }
        let deployment_manifest_path = deployment_manifest_path.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SCM service-dispatch requires --deployment-manifest",
            )
        })?;
        if !deployment_manifest_path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "deployment manifest path must be absolute",
            ));
        }
        Ok(Self {
            host: ServiceHostConfig::parse(retained)?,
            deployment_manifest_path,
        })
    }
}

pub fn start_service_dispatcher(config: ServiceDispatchConfig) -> windows_service::Result<()> {
    SERVICE_CONFIG.set(config).map_err(|_| {
        windows_service::Error::Winapi(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "service configuration was initialized twice",
        ))
    })?;
    SERVICE_TERMINAL_ERROR.set(Mutex::new(None)).map_err(|_| {
        windows_service::Error::Winapi(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "service terminal result was initialized twice",
        ))
    })?;
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    let terminal_error = SERVICE_TERMINAL_ERROR
        .get()
        .ok_or_else(|| {
            windows_service::Error::Winapi(io::Error::other(
                "service terminal result storage is unavailable",
            ))
        })?
        .lock()
        .map_err(|_| {
            windows_service::Error::Winapi(io::Error::other(
                "service terminal result mutex is poisoned",
            ))
        })?
        .take();
    match terminal_error {
        Some(message) => Err(windows_service::Error::Winapi(io::Error::other(message))),
        None => Ok(()),
    }
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    let Some(config) = SERVICE_CONFIG.get().cloned() else {
        record_terminal_error("service configuration is unavailable".to_owned());
        return;
    };
    if let Err(error) = run_service(config.host, config.deployment_manifest_path) {
        record_terminal_error(error.to_string());
    }
}

fn record_terminal_error(message: String) {
    if let Some(result) = SERVICE_TERMINAL_ERROR.get() {
        if let Ok(mut result) = result.lock() {
            *result = Some(message);
        }
    }
}

fn run_service(
    config: ServiceHostConfig,
    deployment_manifest_path: PathBuf,
) -> windows_service::Result<()> {
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_reason = Arc::new(AtomicU8::new(STOP_REASON_NONE));
    let stop_control_qpc_ns = Arc::new(AtomicU64::new(0));
    let handler_stop_requested = Arc::clone(&stop_requested);
    let handler_stop_reason = Arc::clone(&stop_reason);
    let handler_stop_control_qpc_ns = Arc::clone(&stop_control_qpc_ns);
    let event_handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // The SCM callback must remain bounded even if every owner thread,
            // journal barrier, DLL call, and named-pipe handler is wedged. QPC
            // is one constant-time kernel query; there is no I/O, lock, wait,
            // allocation, or receipt work on this callback thread.
            let control_qpc_ns = qpc_now_ns().unwrap_or(0);
            let reason = if event == ServiceControl::Stop {
                STOP_REASON_CONTROL_STOP
            } else {
                STOP_REASON_CONTROL_SHUTDOWN
            };
            if handler_stop_reason
                .compare_exchange(
                    STOP_REASON_NONE,
                    reason,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                handler_stop_control_qpc_ns.store(control_qpc_ns, Ordering::Release);
            }
            handler_stop_requested.store(true, Ordering::Release);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    set_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
        1,
        Duration::from_secs(10),
    )?;

    // Hold this handle through the owner-spawn gate.  This is a stable-file
    // check, not a claim about the already-mapped image or code provenance.
    let locked_supervisor =
        lock_current_process_identity().map_err(windows_service::Error::Winapi)?;
    let supervisor = locked_supervisor.identity();
    let service_sid =
        lookup_account_sid(SERVICE_ACCOUNT_NAME).map_err(windows_service::Error::Winapi)?;
    let deployment_spec = DeploymentSecuritySpec::new(&service_sid, &config.operator_sid)
        .map_err(windows_service::Error::Winapi)?;
    let data_root_identity = inspect_stable_deployment_path(&config.data_root)
        .map_err(windows_service::Error::Winapi)?;
    require_canonical_deployment_path(&config.data_root, &data_root_identity)
        .map_err(windows_service::Error::Winapi)?;
    let _locked_data_root_ancestors =
        lock_deployment_ancestor_chain(&config.data_root, &config.operator_sid)
            .map_err(windows_service::Error::Winapi)?;
    let manifest_parent = deployment_manifest_path.parent().ok_or_else(|| {
        windows_service::Error::Winapi(io::Error::new(
            io::ErrorKind::InvalidData,
            "deployment manifest has no parent directory",
        ))
    })?;
    let locked_manifest_ancestors =
        lock_exact_deployment_leaf_chain(manifest_parent, &config.operator_sid, &deployment_spec)
            .map_err(windows_service::Error::Winapi)?;
    let mut executable_proof =
        lock_deployment_file_proof(&supervisor.executable_path, &locked_manifest_ancestors)
            .map_err(windows_service::Error::Winapi)?;
    let manifest_proof =
        lock_deployment_file_proof(&deployment_manifest_path, &locked_manifest_ancestors)
            .map_err(windows_service::Error::Winapi)?;
    require_canonical_deployment_path(&deployment_manifest_path, manifest_proof.identity())
        .map_err(windows_service::Error::Winapi)?;
    // Retain the manifest file handle for the entire SCM process lifetime.
    // The manifest is not a signature; it only binds locally protected bytes,
    // paths and exact ACL contracts before any business owner is spawned.
    let _locked_deployment_manifest = verify_deployment_startup_gate(
        &config,
        &deployment_manifest_path,
        supervisor,
        manifest_proof,
        &mut executable_proof,
    )
    .map_err(windows_service::Error::Winapi)?;
    let service_instance_id =
        fresh_service_instance_id().map_err(windows_service::Error::Winapi)?;
    let owner_control_pipe = owner_control_pipe_name(&service_instance_id);
    let owner_arguments = owner_launch_arguments(
        &config,
        service_instance_id,
        supervisor.pid,
        supervisor.creation_time_100ns,
        supervisor.executable_sha256,
        supervisor.executable_sha256,
        &owner_control_pipe,
    )
    .map_err(windows_service::Error::Winapi)?;
    let mut owner = match ContainedProcess::spawn_verified(&mut executable_proof, &owner_arguments)
    {
        Ok(owner) => owner,
        Err(error) => {
            set_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(EXIT_INITIALIZATION_FAILED),
                0,
                Duration::ZERO,
            )?;
            return Err(windows_service::Error::Winapi(error));
        }
    };
    let containment = owner.containment_evidence();
    if !containment.created_suspended
        || !containment.kill_on_job_close_configured
        || !containment.job_assigned_before_resume
        || !containment.executable_rehashed_before_resume
    {
        let _ = terminate_owner_for_startup(&mut owner);
        return Err(windows_service::Error::Winapi(io::Error::other(
            "service owner lacks complete pre-resume Job containment evidence",
        )));
    }
    let expected_peer = ExpectedOwnerControlPeer {
        service_instance_id,
        supervisor_pid: supervisor.pid,
        supervisor_creation_time_100ns: supervisor.creation_time_100ns,
        supervisor_executable_sha256: supervisor.executable_sha256,
        owner_pid: owner.identity().pid,
        owner_creation_time_100ns: owner.identity().creation_time_100ns,
        owner_executable_sha256: owner.identity().executable_sha256,
    };

    let startup_started = Instant::now();
    let mut checkpoint = 1_u32;
    let mut last_checkpoint = startup_started;
    loop {
        if stop_requested.load(Ordering::Acquire) {
            return stop_owner_before_ready(
                &status_handle,
                &expected_peer,
                owner,
                &config,
                stop_reason.load(Ordering::Acquire),
                stop_control_qpc_ns.load(Ordering::Acquire),
            );
        }
        if let Some(exit_code) = owner
            .query_exit_code()
            .map_err(windows_service::Error::Winapi)?
        {
            let evidence = owner
                .wait_for_exit(Duration::from_secs(1))
                .map_err(windows_service::Error::Winapi)?;
            let error = io::Error::other(format!(
                "service owner exited during startup with code {exit_code}; wait evidence: {evidence:?}"
            ));
            set_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(EXIT_INITIALIZATION_FAILED),
                0,
                Duration::ZERO,
            )?;
            return Err(windows_service::Error::Winapi(error));
        }
        if wait_for_secure_pipe(&owner_control_pipe, OWNER_PIPE_PROBE_MS).is_ok() {
            break;
        }
        if startup_started.elapsed() >= START_HARD_DEADLINE {
            let evidence =
                terminate_owner_for_startup(&mut owner).map_err(windows_service::Error::Winapi)?;
            set_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(EXIT_INITIALIZATION_FAILED),
                0,
                Duration::ZERO,
            )?;
            return Err(windows_service::Error::Winapi(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("service owner was not ready within 20 seconds; {evidence:?}"),
            )));
        }
        update_pending_checkpoint(
            &status_handle,
            ServiceState::StartPending,
            &mut checkpoint,
            &mut last_checkpoint,
        )?;
        std::thread::sleep(OWNER_POLL_INTERVAL);
    }

    if stop_requested.load(Ordering::Acquire) {
        return stop_owner_before_ready(
            &status_handle,
            &expected_peer,
            owner,
            &config,
            stop_reason.load(Ordering::Acquire),
            stop_control_qpc_ns.load(Ordering::Acquire),
        );
    }
    let ready_request = match owner_request(&expected_peer, ScmOwnerCommandV1::QueryReady, 1, 1) {
        Ok(request) => request,
        Err(error) => {
            return fail_owner_start(&status_handle, &mut owner, "build QueryReady", error)
        }
    };
    let ready_response = match transact_owner_request(&owner_control_pipe, &ready_request) {
        Ok(response) => response,
        Err(error) => {
            return fail_owner_start(&status_handle, &mut owner, "transact QueryReady", error)
        }
    };
    if let Err(error) = validate_ready_response(
        &ready_response,
        &config.pipe_name,
        &config.hardware_pipe_name,
        config
            .analysis_worker_sid
            .as_ref()
            .map(|_| config.analysis_pipe_name.as_str()),
    ) {
        return fail_owner_start(&status_handle, &mut owner, "validate QueryReady", error);
    }
    if stop_requested.load(Ordering::Acquire) {
        return stop_owner(
            &status_handle,
            owner,
            StopOwnerContext {
                owner_control_pipe: &owner_control_pipe,
                expected_peer: &expected_peer,
                command_sequence: 2,
                config: &config,
                stop_reason: stop_reason.load(Ordering::Acquire),
                stop_control_qpc_ns: stop_control_qpc_ns.load(Ordering::Acquire),
            },
        );
    }
    if let Err(error) = set_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
        0,
        Duration::ZERO,
    ) {
        return fail_owner_start(&status_handle, &mut owner, "report Running", error);
    }
    if stop_requested.load(Ordering::Acquire) {
        return stop_owner(
            &status_handle,
            owner,
            StopOwnerContext {
                owner_control_pipe: &owner_control_pipe,
                expected_peer: &expected_peer,
                command_sequence: 2,
                config: &config,
                stop_reason: stop_reason.load(Ordering::Acquire),
                stop_control_qpc_ns: stop_control_qpc_ns.load(Ordering::Acquire),
            },
        );
    }
    let activate_request =
        match owner_request(&expected_peer, ScmOwnerCommandV1::ActivatePublic, 2, 2) {
            Ok(request) => request,
            Err(error) => {
                return fail_owner_start(&status_handle, &mut owner, "build ActivatePublic", error)
            }
        };
    let activate_response = match transact_owner_request(&owner_control_pipe, &activate_request) {
        Ok(response) => response,
        Err(error) => {
            return fail_owner_start(&status_handle, &mut owner, "transact ActivatePublic", error)
        }
    };
    if let Err(error) = validate_activation_response(&activate_response) {
        return fail_owner_start(&status_handle, &mut owner, "validate ActivatePublic", error);
    }

    loop {
        if stop_requested.load(Ordering::Acquire) {
            return stop_owner(
                &status_handle,
                owner,
                StopOwnerContext {
                    owner_control_pipe: &owner_control_pipe,
                    expected_peer: &expected_peer,
                    command_sequence: 3,
                    config: &config,
                    stop_reason: stop_reason.load(Ordering::Acquire),
                    stop_control_qpc_ns: stop_control_qpc_ns.load(Ordering::Acquire),
                },
            );
        }
        if let Some(exit_code) = owner
            .query_exit_code()
            .map_err(windows_service::Error::Winapi)?
        {
            let evidence = owner
                .wait_for_exit(Duration::from_secs(1))
                .map_err(windows_service::Error::Winapi)?;
            set_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(EXIT_OWNER_FAILED),
                0,
                Duration::ZERO,
            )?;
            return Err(windows_service::Error::Winapi(io::Error::other(format!(
                "service owner exited unexpectedly with code {exit_code}; wait evidence: {evidence:?}"
            ))));
        }
        std::thread::sleep(OWNER_POLL_INTERVAL);
    }
}

fn canonical_service_dispatch_arguments(
    config: &ServiceHostConfig,
    manifest_path: &Path,
) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("service-dispatch"),
        OsString::from("--data-root"),
        config.data_root.as_os_str().to_owned(),
        OsString::from("--operator-sid"),
        OsString::from(&config.operator_sid),
        OsString::from("--pipe"),
        OsString::from(&config.pipe_name),
        OsString::from("--hardware-pipe"),
        OsString::from(&config.hardware_pipe_name),
        OsString::from("--deployment-manifest"),
        manifest_path.as_os_str().to_owned(),
    ];
    if let Some(worker_sid) = &config.analysis_worker_sid {
        arguments.extend([
            OsString::from("--analysis-worker-sid"),
            OsString::from(worker_sid),
            OsString::from("--analysis-pipe"),
            OsString::from(&config.analysis_pipe_name),
        ]);
    }
    if let Some(policy) = &config.direct_pod_policy {
        arguments.extend([
            OsString::from("--direct-pod-policy"),
            policy.path().as_os_str().to_owned(),
            OsString::from("--direct-pod-policy-sha256"),
            OsString::from(policy.expected_file_sha256_hex()),
            OsString::from("--internal-approval-authority-sha256"),
            OsString::from(policy.expected_approval_authority_sha256_hex()),
        ]);
    }
    arguments
}

pub(crate) fn quote_windows_scm_argument(value: &OsStr) -> io::Result<String> {
    let units = value.encode_wide().collect::<Vec<_>>();
    if units.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCM argument contains NUL",
        ));
    }
    let needs_quotes =
        units.is_empty() || units.iter().any(|unit| matches!(*unit, 0x20 | 0x09 | 0x22));
    let mut output = Vec::with_capacity(units.len() + 2);
    if needs_quotes {
        output.push(u16::from(b'\"'));
    }
    let mut slashes = 0_usize;
    for unit in units {
        if unit == u16::from(b'\\') {
            slashes += 1;
        } else if unit == u16::from(b'\"') {
            output.extend(std::iter::repeat_n(u16::from(b'\\'), slashes * 2 + 1));
            output.push(unit);
            slashes = 0;
        } else {
            output.extend(std::iter::repeat_n(u16::from(b'\\'), slashes));
            output.push(unit);
            slashes = 0;
        }
    }
    if needs_quotes {
        output.extend(std::iter::repeat_n(u16::from(b'\\'), slashes * 2));
        output.push(u16::from(b'\"'));
    } else {
        output.extend(std::iter::repeat_n(u16::from(b'\\'), slashes));
    }
    OsString::from_wide(&output)
        .into_string()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SCM argument is not Unicode"))
}

fn canonical_scm_launch_command(
    executable: &Path,
    config: &ServiceHostConfig,
    manifest_path: &Path,
) -> io::Result<String> {
    let mut command = quote_windows_scm_argument(executable.as_os_str())?;
    for argument in canonical_service_dispatch_arguments(config, manifest_path) {
        command.push(' ');
        command.push_str(&quote_windows_scm_argument(&argument)?);
    }
    Ok(command)
}

fn expected_failure_actions() -> ServiceFailureActions {
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(
            SCM_FAILURE_RESET_SECONDS,
        )),
        reboot_msg: None,
        command: None,
        actions: Some(
            SCM_RESTART_DELAYS_SECONDS
                .into_iter()
                .map(|seconds| ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(seconds),
                })
                .collect(),
        ),
    }
}

fn verify_deployment_startup_gate(
    config: &ServiceHostConfig,
    _manifest_path: &Path,
    supervisor: &crate::windows_contained_process::ContainedProcessIdentity,
    manifest_proof: LockedDeploymentFileProof,
    executable_proof: &mut LockedDeploymentFileProof,
) -> io::Result<crate::windows_deployment_manifest::LockedWindowsDeploymentManifestV1> {
    let service_sid = lookup_account_sid(SERVICE_ACCOUNT_NAME)?;
    let spec = DeploymentSecuritySpec::new(&service_sid, &config.operator_sid)?;
    let executable_path = PathBuf::from(&executable_proof.identity().canonical_path);
    let manifest_path = PathBuf::from(&manifest_proof.identity().canonical_path);
    let executable_bytes = executable_proof.identity().bytes;
    let executable_sha256_hex = hex_sha256(&supervisor.executable_sha256);
    let expected = WindowsDeploymentManifestExpectationV1 {
        manifest_path: manifest_path.clone(),
        executable_path: executable_path.clone(),
        executable_sha256_hex,
        executable_bytes,
        service_sid,
        service_config: config.clone(),
    };
    let locked = load_and_verify_windows_deployment_manifest_v1(
        &expected,
        manifest_proof,
        executable_proof,
    )?;
    let manifest = locked.manifest();
    let expected_dacl = &manifest.dacl;
    if expected_dacl.runtime_pipe_dacl_qualified
        || expected_dacl.service_object_contract_sha256_hex
            != spec.service_object_contract_sha256_hex()
        || expected_dacl.executable_parent_contract_sha256_hex
            != spec.file_or_directory_contract_sha256_hex(true)
        || expected_dacl.executable_contract_sha256_hex
            != spec.file_or_directory_contract_sha256_hex(false)
        || expected_dacl.data_root_contract_sha256_hex
            != spec.ancestor_directory_contract_sha256_hex()
        || expected_dacl.manifest_contract_sha256_hex
            != spec.file_or_directory_contract_sha256_hex(false)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deployment manifest DACL contract does not match the runtime principals",
        ));
    }
    let data_root_evidence = verify_deployment_ancestor_dacl(&config.data_root, &spec)?;
    if !data_root_evidence.protected || !data_root_evidence.matches {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deployment data root DACL readback was not exact",
        ));
    }
    for target in [
        executable_path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "service executable has no parent",
            )
        })?,
        executable_path.as_path(),
        manifest_path.as_path(),
    ] {
        let evidence = verify_file_or_directory_dacl(target, &spec)?;
        if !evidence.protected || !evidence.matches {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "deployment file-system DACL readback was not exact",
            ));
        }
        if target == executable_path.as_path()
            && evidence.object_sha256_hex.as_deref()
                != Some(manifest.executable_sha256_hex.as_str())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "handle-bound executable hash differs from deployment manifest",
            ));
        }
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::READ_CONTROL | ServiceAccess::QUERY_CONFIG,
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
    let expected_command = canonical_scm_launch_command(&executable_path, config, &manifest_path)?;
    let failure_actions = expected_failure_actions();
    let contract = ScmServiceContractExpectation {
        launch_command_line: OsStr::new(&expected_command),
        start_type: ServiceStartType::OnDemand,
        failure_actions: &failure_actions,
    };
    verify_scm_service_contract(&service, &contract, &spec)?;
    Ok(locked)
}

fn hex_sha256(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_sha256_16(value: &[u8; 16]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_time_ns() -> io::Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::Error::other("system clock is before Unix epoch"))?
            .as_nanos(),
    )
    .map_err(|_| io::Error::other("system wall clock exceeds u64 nanoseconds"))
}

fn stop_reason_from_latch(value: u8) -> io::Result<ScmStopReasonV1> {
    match value {
        STOP_REASON_CONTROL_STOP => Ok(ScmStopReasonV1::ServiceControlStop),
        STOP_REASON_CONTROL_SHUTDOWN => Ok(ScmStopReasonV1::ServiceControlShutdown),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SCM stop latch has no authoritative Stop/Shutdown reason",
        )),
    }
}

fn fresh_service_instance_id() -> io::Result<[u8; 32]> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };

    let mut value = [0_u8; 32];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            value.as_mut_ptr(),
            value.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 || value == [0; 32] {
        Err(io::Error::other(
            "failed to obtain a nonzero SCM service-instance ID",
        ))
    } else {
        Ok(value)
    }
}

fn owner_control_pipe_name(service_instance_id: &[u8; 32]) -> String {
    let mut suffix = String::with_capacity(64);
    for byte in service_instance_id {
        use std::fmt::Write as _;
        let _ = write!(&mut suffix, "{byte:02x}");
    }
    format!(r"\\.\pipe\forge-acqd-owner-{suffix}")
}

fn owner_request(
    identity: &ExpectedOwnerControlPeer,
    command: ScmOwnerCommandV1,
    command_sequence: u64,
    request_id: u64,
) -> io::Result<ScmOwnerRequestV1> {
    let now = qpc_now_ns()?;
    let deadline_qpc_ns = now.checked_add(OWNER_COMMAND_LEAD_NS).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "owner command QPC deadline overflow",
        )
    })?;
    owner_request_with_deadline(
        identity,
        command,
        command_sequence,
        request_id,
        deadline_qpc_ns,
        None,
    )
}

fn owner_request_with_deadline(
    identity: &ExpectedOwnerControlPeer,
    command: ScmOwnerCommandV1,
    command_sequence: u64,
    request_id: u64,
    deadline_qpc_ns: u64,
    stop_intent: Option<StableFileBindingV1>,
) -> io::Result<ScmOwnerRequestV1> {
    Ok(ScmOwnerRequestV1 {
        schema: SCM_OWNER_REQUEST_SCHEMA.to_owned(),
        service_instance_id: identity.service_instance_id,
        supervisor_pid: identity.supervisor_pid,
        supervisor_creation_time_100ns: identity.supervisor_creation_time_100ns,
        owner_pid: identity.owner_pid,
        owner_creation_time_100ns: identity.owner_creation_time_100ns,
        supervisor_executable_sha256: identity.supervisor_executable_sha256,
        owner_executable_sha256: identity.owner_executable_sha256,
        command_sequence,
        request_id,
        deadline_qpc_ns,
        command,
        stop_intent,
    })
}

fn transact_owner_request(
    owner_control_pipe: &str,
    request: &ScmOwnerRequestV1,
) -> windows_service::Result<ScmOwnerResponseV1> {
    let encoded = encode_request(request).map_err(windows_service::Error::Winapi)?;
    transact_encoded_owner_request(
        owner_control_pipe,
        &encoded,
        OWNER_PIPE_WAIT_MS,
        OWNER_PIPE_IO_MS,
        request,
    )
}

fn transact_owner_request_before_graceful_cutoff(
    owner_control_pipe: &str,
    request: &ScmOwnerRequestV1,
    budget: &StopDeadlineBudget,
) -> windows_service::Result<ScmOwnerResponseV1> {
    let encoded = encode_request(request).map_err(windows_service::Error::Winapi)?;
    // Encode first, then derive Windows wait limits from the same callback-
    // anchored cutoff so serialization time cannot silently reset the budget.
    let remaining = budget
        .graceful_remaining_with(qpc_now_ns)
        .map_err(windows_service::Error::Winapi)?;
    let (wait_timeout_ms, io_timeout_ms) =
        owner_pipe_timeouts(remaining).map_err(windows_service::Error::Winapi)?;
    transact_encoded_owner_request(
        owner_control_pipe,
        &encoded,
        wait_timeout_ms,
        io_timeout_ms,
        request,
    )
}

fn transact_encoded_owner_request(
    owner_control_pipe: &str,
    encoded_request: &[u8],
    wait_timeout_ms: u32,
    io_timeout_ms: u32,
    request: &ScmOwnerRequestV1,
) -> windows_service::Result<ScmOwnerResponseV1> {
    let encoded_response = call_secure_pipe_bounded(
        owner_control_pipe,
        encoded_request,
        wait_timeout_ms,
        io_timeout_ms,
    )
    .map_err(windows_service::Error::Winapi)?;
    let response = decode_response(&encoded_response).map_err(windows_service::Error::Winapi)?;
    validate_response_for_request(request, &response).map_err(windows_service::Error::Winapi)?;
    Ok(response)
}

fn owner_pipe_timeouts(remaining: Duration) -> io::Result<(u32, u32)> {
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "SCM owner pipe has zero remaining Stop budget",
        ));
    }
    // Floor to milliseconds so the combined WaitNamedPipe + overlapped-I/O
    // limits never round beyond the remaining QPC budget.
    let remaining_ms = u32::try_from(remaining.as_millis()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCM owner pipe remaining budget exceeds DWORD milliseconds",
        )
    })?;
    if remaining_ms == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "SCM owner pipe remaining budget is below one millisecond",
        ));
    }
    let capped_total = remaining_ms.min(OWNER_PIPE_WAIT_MS + OWNER_PIPE_IO_MS);
    let wait_timeout_ms = OWNER_PIPE_WAIT_MS.min(capped_total.saturating_sub(1));
    let io_timeout_ms = capped_total - wait_timeout_ms;
    if io_timeout_ms == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "SCM owner pipe has no remaining I/O budget",
        ));
    }
    Ok((wait_timeout_ms, io_timeout_ms))
}

fn fail_owner_start(
    status_handle: &ServiceStatusHandle,
    owner: &mut ContainedProcess,
    context: &'static str,
    error: impl std::fmt::Display,
) -> windows_service::Result<()> {
    let cleanup = terminate_owner_for_startup(owner);
    set_status(
        status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        ServiceExitCode::ServiceSpecific(EXIT_INITIALIZATION_FAILED),
        0,
        Duration::ZERO,
    )?;
    let message = match cleanup {
        Ok(evidence) => format!("{context} failed: {error}; owner cleanup={evidence:?}"),
        Err(cleanup_error) => {
            format!("{context} failed: {error}; bounded owner cleanup also failed: {cleanup_error}")
        }
    };
    Err(windows_service::Error::Winapi(io::Error::other(message)))
}

fn stop_owner_before_ready(
    status_handle: &ServiceStatusHandle,
    expected_peer: &ExpectedOwnerControlPeer,
    owner: ContainedProcess,
    config: &ServiceHostConfig,
    stop_reason: u8,
    stop_control_qpc_ns: u64,
) -> windows_service::Result<()> {
    set_status(
        status_handle,
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
        1,
        STATUS_WAIT_HINT,
    )?;
    let reason = stop_reason_from_latch(stop_reason).map_err(windows_service::Error::Winapi)?;
    let control_wall_time_unix_ns = unix_time_ns().map_err(windows_service::Error::Winapi)?;
    let budget = StopDeadlineBudget::from_control_qpc(stop_control_qpc_ns)
        .map_err(windows_service::Error::Winapi)?;
    stop_owner_with_unknown_context(
        status_handle,
        expected_peer,
        owner,
        UnknownStopContext {
            config,
            reason,
            intent_kind: StopIntentKindV1::StartupBeforeOwnerReady,
            control_wall_time_unix_ns,
            budget,
        },
    )
}

struct StopOwnerContext<'a> {
    owner_control_pipe: &'a str,
    expected_peer: &'a ExpectedOwnerControlPeer,
    command_sequence: u64,
    config: &'a ServiceHostConfig,
    stop_reason: u8,
    stop_control_qpc_ns: u64,
}

fn stop_owner(
    status_handle: &ServiceStatusHandle,
    mut owner: ContainedProcess,
    context: StopOwnerContext<'_>,
) -> windows_service::Result<()> {
    let StopOwnerContext {
        owner_control_pipe,
        expected_peer,
        command_sequence,
        config,
        stop_reason,
        stop_control_qpc_ns,
    } = context;
    let mut checkpoint = 1_u32;
    let mut last_checkpoint = Instant::now();
    set_status(
        status_handle,
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
        checkpoint,
        STATUS_WAIT_HINT,
    )?;

    let reason = stop_reason_from_latch(stop_reason).map_err(windows_service::Error::Winapi)?;
    let control_wall_time_unix_ns = unix_time_ns().map_err(windows_service::Error::Winapi)?;
    let budget = StopDeadlineBudget::from_control_qpc(stop_control_qpc_ns)
        .map_err(windows_service::Error::Winapi)?;
    // The owner has the exact Run identity but the supervisor cannot trust a
    // post-shutdown snapshot. Get it before persisting the intent, then bind
    // the following non-idempotent private request to that exact intent.
    let snapshot_request = owner_request_with_deadline(
        expected_peer,
        ScmOwnerCommandV1::GetSnapshot,
        command_sequence,
        command_sequence,
        budget.final_deadline_qpc_ns,
        None,
    )
    .map_err(windows_service::Error::Winapi)?;
    let snapshot_response = match transact_owner_request_before_graceful_cutoff(
        owner_control_pipe,
        &snapshot_request,
        &budget,
    ) {
        Ok(response) if response.accepted => response,
        Ok(_) => {
            return stop_owner_with_unknown_context(
                status_handle,
                expected_peer,
                owner,
                UnknownStopContext {
                    config,
                    reason,
                    intent_kind: StopIntentKindV1::RuntimeSnapshotUnavailable,
                    control_wall_time_unix_ns,
                    budget,
                },
            )
        }
        Err(_) => {
            return stop_owner_with_unknown_context(
                status_handle,
                expected_peer,
                owner,
                UnknownStopContext {
                    config,
                    reason,
                    intent_kind: StopIntentKindV1::RuntimeSnapshotUnavailable,
                    control_wall_time_unix_ns,
                    budget,
                },
            )
        }
    };
    let active_run_at_intent = snapshot_response.active_epoch.is_some();
    let run_id_hex = match (active_run_at_intent, snapshot_response.active_run_id) {
        (false, None) => None,
        (true, Some(run_id)) => Some(hex_sha256_16(&run_id)),
        _ => {
            return stop_owner_with_unknown_context(
                status_handle,
                expected_peer,
                owner,
                UnknownStopContext {
                    config,
                    reason,
                    intent_kind: StopIntentKindV1::RuntimeSnapshotUnavailable,
                    control_wall_time_unix_ns,
                    budget,
                },
            )
        }
    };
    let intent = StopIntentV1 {
        schema: SCM_STOP_RECEIPT_SCHEMA.to_owned(),
        service_name: SERVICE_NAME.to_owned(),
        service_instance_id_hex: hex_sha256(&expected_peer.service_instance_id),
        run_id_hex: run_id_hex.clone(),
        owner_process: StopProcessIdentityV1 {
            pid: expected_peer.owner_pid,
            creation_time_100ns: expected_peer.owner_creation_time_100ns,
        },
        reason,
        intent_kind: StopIntentKindV1::RuntimeGracefulShutdown,
        scm_control_wall_time_unix_ns: control_wall_time_unix_ns,
        scm_control_monotonic_ns: budget.control_qpc_ns,
        deadline_monotonic_ns: budget.final_deadline_qpc_ns,
        private_request_sequence: Some(command_sequence + 1),
        private_epoch: Some(command_sequence + 1),
        run_state_wire: Some(snapshot_response.run_state_wire),
        active_run_at_intent,
        intent_sha256_hex: String::new(),
    };
    let persisted = match persist_stop_intent(config, expected_peer, &intent) {
        Ok(persisted) => persisted,
        Err(error) => {
            let cleanup = terminate_owner_for_stop(&mut owner, &budget);
            return stop_without_receipt(
                status_handle,
                format!("persist runtime StopIntent failed: {error}; cleanup={cleanup:?}"),
            );
        }
    };

    // Never retry this command. If transport/FACK fails, its execution state is
    // ambiguous; graceful observation ends at the callback-anchored cutoff and
    // leaves the final five seconds exclusively for complete-Job teardown. A
    // later receipt is explicitly fail-closed in that path.
    let shutdown_request = owner_request_with_deadline(
        expected_peer,
        ScmOwnerCommandV1::GracefulShutdown,
        command_sequence + 1,
        command_sequence + 1,
        budget.final_deadline_qpc_ns,
        Some(persisted.intent_binding.clone()),
    )
    .map_err(windows_service::Error::Winapi)?;
    let control_fack_observed = transact_owner_request_before_graceful_cutoff(
        owner_control_pipe,
        &shutdown_request,
        &budget,
    )
    .is_ok_and(|response| response.accepted);
    let graceful_evidence = loop {
        if budget.graceful_remaining_with(qpc_now_ns).is_err() {
            break None;
        }
        match owner.query_exit_code() {
            Ok(Some(_)) => {
                let remaining = match budget.graceful_remaining_with(qpc_now_ns) {
                    Ok(remaining) => remaining,
                    Err(_) => break None,
                };
                match owner.wait_for_exit(remaining) {
                    Ok(evidence) => break Some(evidence),
                    // A lingering Job child or late primary exit consumes only
                    // the graceful budget; the reserved force phase follows.
                    Err(_) => break None,
                }
            }
            Ok(None) => {}
            Err(_) => break None,
        }
        update_pending_checkpoint(
            status_handle,
            ServiceState::StopPending,
            &mut checkpoint,
            &mut last_checkpoint,
        )?;
        let remaining = match budget.graceful_remaining_with(qpc_now_ns) {
            Ok(remaining) => remaining,
            Err(_) => break None,
        };
        // SCM checkpoint and wait-hint refreshes never create a new deadline;
        // even the polling sleep is clipped to the callback-anchored cutoff.
        std::thread::sleep(OWNER_POLL_INTERVAL.min(remaining));
    };
    if let Some(evidence) = graceful_evidence {
        return complete_stop_receipt(
            status_handle,
            StopReceiptCompletionContext {
                expected_peer,
                paths: persisted.paths,
                intent_binding: persisted.intent_binding,
                ledger: persisted.ledger,
                control_fack_observed,
                evidence,
                forced_termination: false,
                run_id_hex,
            },
        );
    }
    let evidence =
        terminate_owner_for_stop(&mut owner, &budget).map_err(windows_service::Error::Winapi)?;
    complete_stop_receipt(
        status_handle,
        StopReceiptCompletionContext {
            expected_peer,
            paths: persisted.paths,
            intent_binding: persisted.intent_binding,
            ledger: persisted.ledger,
            control_fack_observed,
            evidence,
            forced_termination: true,
            run_id_hex,
        },
    )
}

struct PersistedStopIntent {
    paths: crate::scm_stop_receipt::ScmStopEvidencePathsV1,
    intent_binding: StableFileBindingV1,
    ledger: ScmStopLedgerWriterV1,
}

fn persist_stop_intent(
    config: &ServiceHostConfig,
    expected_peer: &ExpectedOwnerControlPeer,
    intent: &StopIntentV1,
) -> io::Result<PersistedStopIntent> {
    // B1 bounds every pipe/process/Job wait against the callback QPC budget,
    // but these create-new + sync_all/sync_data operations remain synchronous.
    // A stalled filesystem can therefore still exceed the final deadline;
    // moving durable I/O behind a separately supervised design is explicitly
    // the open B2 boundary, not something this wait-budget patch claims.
    let paths = scm_stop_evidence_paths_v1(&config.data_root, &expected_peer.service_instance_id)?;
    let intent_binding = publish_stop_intent_v1(&paths.intent_path, intent)?;
    let mut ledger = ScmStopLedgerWriterV1::create_new(&paths.ledger_path)?;
    ledger.append_intent(intent_binding.clone())?;
    Ok(PersistedStopIntent {
        paths,
        intent_binding,
        ledger,
    })
}

struct UnknownStopContext<'a> {
    config: &'a ServiceHostConfig,
    reason: ScmStopReasonV1,
    intent_kind: StopIntentKindV1,
    control_wall_time_unix_ns: u64,
    budget: StopDeadlineBudget,
}

fn stop_owner_with_unknown_context(
    status_handle: &ServiceStatusHandle,
    expected_peer: &ExpectedOwnerControlPeer,
    mut owner: ContainedProcess,
    context: UnknownStopContext<'_>,
) -> windows_service::Result<()> {
    let UnknownStopContext {
        config,
        reason,
        intent_kind,
        control_wall_time_unix_ns,
        budget,
    } = context;
    debug_assert!(intent_kind != StopIntentKindV1::RuntimeGracefulShutdown);
    let intent = StopIntentV1 {
        schema: SCM_STOP_RECEIPT_SCHEMA.to_owned(),
        service_name: SERVICE_NAME.to_owned(),
        service_instance_id_hex: hex_sha256(&expected_peer.service_instance_id),
        run_id_hex: None,
        owner_process: StopProcessIdentityV1 {
            pid: expected_peer.owner_pid,
            creation_time_100ns: expected_peer.owner_creation_time_100ns,
        },
        reason,
        intent_kind,
        scm_control_wall_time_unix_ns: control_wall_time_unix_ns,
        scm_control_monotonic_ns: budget.control_qpc_ns,
        deadline_monotonic_ns: budget.final_deadline_qpc_ns,
        private_request_sequence: None,
        private_epoch: None,
        run_state_wire: None,
        active_run_at_intent: false,
        intent_sha256_hex: String::new(),
    };
    let persisted = match persist_stop_intent(config, expected_peer, &intent) {
        Ok(persisted) => persisted,
        Err(error) => {
            let cleanup = terminate_owner_for_stop(&mut owner, &budget);
            return stop_without_receipt(
                status_handle,
                format!("persist unknown-context StopIntent failed: {error}; cleanup={cleanup:?}"),
            );
        }
    };
    let forced_termination = owner
        .query_exit_code()
        .map_err(windows_service::Error::Winapi)?
        .is_none();
    let evidence =
        terminate_owner_for_stop(&mut owner, &budget).map_err(windows_service::Error::Winapi)?;
    complete_stop_receipt(
        status_handle,
        StopReceiptCompletionContext {
            expected_peer,
            paths: persisted.paths,
            intent_binding: persisted.intent_binding,
            ledger: persisted.ledger,
            control_fack_observed: false,
            evidence,
            forced_termination,
            run_id_hex: None,
        },
    )
}

struct StopReceiptCompletionContext<'a> {
    expected_peer: &'a ExpectedOwnerControlPeer,
    paths: crate::scm_stop_receipt::ScmStopEvidencePathsV1,
    intent_binding: StableFileBindingV1,
    ledger: ScmStopLedgerWriterV1,
    control_fack_observed: bool,
    evidence: ContainedProcessWaitEvidence,
    forced_termination: bool,
    run_id_hex: Option<String>,
}

fn complete_stop_receipt(
    status_handle: &ServiceStatusHandle,
    context: StopReceiptCompletionContext<'_>,
) -> windows_service::Result<()> {
    // Owner-outcome verification, ledger finish, and receipt publication can
    // perform synchronous filesystem work. B1 never extends the QPC deadline
    // for them, but only B2 can make those I/O operations externally bounded.
    let StopReceiptCompletionContext {
        expected_peer,
        paths,
        intent_binding,
        mut ledger,
        control_fack_observed,
        evidence,
        forced_termination,
        run_id_hex,
    } = context;
    let outcome = if !forced_termination && evidence.exit_code == 0 && control_fack_observed {
        match verify_owner_stop_outcome_for_intent_v1(&intent_binding, &paths.outcome_path) {
            Ok(verified) => {
                if ledger
                    .append_owner_outcome(verified.outcome_binding.clone())
                    .is_ok()
                {
                    Some(verified.outcome_binding)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let ledger = match ledger.finish() {
        Ok(value) => value,
        Err(error) => {
            return stop_without_receipt(
                status_handle,
                format!("finish SCM stop ledger failed: {error}"),
            )
        }
    };
    let evidence_prepared_monotonic_ns = match qpc_now_ns() {
        Ok(value) => value,
        Err(error) => {
            return stop_without_receipt(
                status_handle,
                format!("read SCM stop evidence-prepared clock failed: {error}"),
            )
        }
    };
    let intent = match crate::scm_stop_receipt::load_bound_stop_intent_v1(&intent_binding) {
        Ok(value) => value,
        Err(error) => {
            return stop_without_receipt(
                status_handle,
                format!("reload SCM StopIntent failed: {error}"),
            )
        }
    };
    let elapsed_ns =
        match evidence_prepared_monotonic_ns.checked_sub(intent.scm_control_monotonic_ns) {
            Some(value) => value,
            None => {
                return stop_without_receipt(
                    status_handle,
                    "SCM stop completion precedes intent".to_owned(),
                )
            }
        };
    let receipt = ScmStopReceiptV1 {
        schema: SCM_STOP_RECEIPT_SCHEMA.to_owned(),
        evidence_source: ScmStopEvidenceSourceV1::UnqualifiedWindowsRuntime,
        // This in-service synchronous publisher cannot observe its own durable
        // publication after the fact. Even an early evidence-prepared QPC
        // sample plus a clean owner/Job outcome is therefore failure evidence,
        // never a bounded terminal SCM commit.
        terminal_commit_qualification: RUNTIME_STOP_COMMIT_QUALIFICATION,
        service_name: SERVICE_NAME.to_owned(),
        service_instance_id_hex: hex_sha256(&expected_peer.service_instance_id),
        run_id_hex,
        owner_process: StopProcessIdentityV1 {
            pid: expected_peer.owner_pid,
            creation_time_100ns: expected_peer.owner_creation_time_100ns,
        },
        intent: intent_binding.clone(),
        outcome: outcome.clone(),
        ledger,
        owner_exit_code: Some(evidence.exit_code),
        forced_termination,
        retained_process_exit_observed: true,
        job_active_processes_after_wait: evidence.job_active_processes_after_wait,
        job_empty_proven: evidence.job_empty_proven,
        stop_completed_wall_time_unix_ns: match unix_time_ns() {
            Ok(value) => value,
            Err(error) => {
                return stop_without_receipt(
                    status_handle,
                    format!("read SCM stop wall clock failed: {error}"),
                )
            }
        },
        stop_completed_monotonic_ns: evidence_prepared_monotonic_ns,
        elapsed_ns,
        final_scm_status: RUNTIME_STOP_FINAL_STATUS,
        bounded_stop_complete: false,
        receipt_sha256_hex: String::new(),
    };
    let receipt_binding = match publish_scm_stop_receipt_v1(&paths.receipt_path, &receipt) {
        Ok(value) => value,
        Err(error) => {
            return stop_without_receipt(
                status_handle,
                format!("publish SCM stop receipt failed: {error}"),
            )
        }
    };
    let expected = ScmStopVerificationExpectationV1 {
        service_name: SERVICE_NAME.to_owned(),
        service_instance_id_hex: hex_sha256(&expected_peer.service_instance_id),
        run_id_hex: intent.run_id_hex,
        owner_process: StopProcessIdentityV1 {
            pid: expected_peer.owner_pid,
            creation_time_100ns: expected_peer.owner_creation_time_100ns,
        },
        intent_path: paths.intent_path,
        outcome_path: outcome.as_ref().map(|_| paths.outcome_path),
        receipt_path: paths.receipt_path,
        ledger_path: paths.ledger_path,
        expected_intent_sha256_hex: intent_binding.sha256_hex,
        expected_outcome_sha256_hex: outcome.as_ref().map(|binding| binding.sha256_hex.clone()),
        expected_receipt_sha256_hex: receipt_binding.sha256_hex,
        deadline_span_max_ns: STOP_TOTAL_DEADLINE_NS,
        expected_evidence_source: ScmStopEvidenceSourceV1::UnqualifiedWindowsRuntime,
        expected_terminal_commit_qualification: RUNTIME_STOP_COMMIT_QUALIFICATION,
        require_real_scm: false,
    };
    let report = match verify_scm_stop_receipt_v1(&expected) {
        Ok(report) => report,
        Err(error) => {
            return stop_without_receipt(
                status_handle,
                format!("verify SCM stop receipt failed: {error}"),
            )
        }
    };
    if report.bounded_stop_complete || report.real_scm_pass {
        return stop_without_receipt(
            status_handle,
            "unqualified synchronous SCM receipt was incorrectly promoted".to_owned(),
        );
    }
    stop_without_receipt(
        status_handle,
        "SCM stop evidence was published and verified, but synchronous in-service I/O cannot qualify a bounded terminal commit"
            .to_owned(),
    )
}

fn stop_without_receipt(
    status_handle: &ServiceStatusHandle,
    message: String,
) -> windows_service::Result<()> {
    set_status(
        status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        ServiceExitCode::ServiceSpecific(EXIT_STOP_EVIDENCE_FAILED),
        0,
        Duration::ZERO,
    )?;
    Err(windows_service::Error::Winapi(io::Error::other(message)))
}

fn terminate_owner_for_startup(
    owner: &mut ContainedProcess,
) -> io::Result<ContainedProcessWaitEvidence> {
    terminate_owner_with_budget(owner, OWNER_STARTUP_REAP_BUDGET)
}

fn terminate_owner_for_stop(
    owner: &mut ContainedProcess,
    budget: &StopDeadlineBudget,
) -> io::Result<ContainedProcessWaitEvidence> {
    match budget.force_reap_remaining_with(qpc_now_ns) {
        Ok(remaining) => terminate_owner_with_budget(owner, remaining),
        Err(deadline_error) => {
            // The final deadline or the monotonic clock is already unusable.
            // Force containment teardown, but pass zero so no wait can start
            // and never relabel this fail-closed path as bounded success.
            let teardown = terminate_owner_with_budget(owner, Duration::ZERO);
            Err(io::Error::other(format!(
                "SCM Stop has no trustworthy reap budget ({deadline_error}); immediate no-wait teardown={teardown:?}"
            )))
        }
    }
}

fn terminate_owner_with_budget(
    owner: &mut ContainedProcess,
    remaining_budget: Duration,
) -> io::Result<ContainedProcessWaitEvidence> {
    // Intent has already been made durable before this path.  Use the
    // non-lossy terminal observation so a future failed-receipt branch has
    // wait/query/terminate facts instead of a bare early `?` return. The
    // contained process subtracts query/terminate time from this exact caller-
    // supplied remainder; it never creates a fresh five-second window.
    let observation = owner.terminate_and_observe(remaining_budget);
    if observation.primary_wait_observed
        && observation.primary_exit_code.is_some()
        && observation.job_active_processes == Some(0)
        && observation.wait_error.is_none()
        && observation.query_error.is_none()
        && observation.terminate_error.is_none()
    {
        return Ok(ContainedProcessWaitEvidence {
            method:
                crate::windows_contained_process::ContainedProcessWaitMethod::JobObjectTermination,
            wait_deadline_ms: u32::try_from(remaining_budget.as_millis()).unwrap_or(u32::MAX),
            wait_elapsed_ms: u32::try_from(observation.observed_at_qpc_ns / 1_000_000)
                .unwrap_or(u32::MAX),
            wait_result: "observed_reaped",
            exit_code: observation.primary_exit_code.unwrap_or_default(),
            job_active_processes_after_wait: 0,
            job_empty_proven: true,
        });
    }
    Err(io::Error::other(format!(
        "owner terminal observation is not a clean reap: wait={:?}; query={:?}; terminate={:?}; job={:?}",
        observation.wait_error, observation.query_error, observation.terminate_error, observation.job_active_processes
    )))
}

fn update_pending_checkpoint(
    status_handle: &ServiceStatusHandle,
    state: ServiceState,
    checkpoint: &mut u32,
    last_checkpoint: &mut Instant,
) -> windows_service::Result<()> {
    if last_checkpoint.elapsed() < STATUS_HEARTBEAT {
        return Ok(());
    }
    *checkpoint = checkpoint.checked_add(1).ok_or_else(|| {
        windows_service::Error::Winapi(io::Error::new(
            io::ErrorKind::InvalidData,
            "SCM pending checkpoint overflow",
        ))
    })?;
    set_status(
        status_handle,
        state,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
        *checkpoint,
        STATUS_WAIT_HINT,
    )?;
    *last_checkpoint = Instant::now();
    Ok(())
}

fn set_status(
    handle: &ServiceStatusHandle,
    current_state: ServiceState,
    controls_accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    checkpoint: u32,
    wait_hint: Duration,
) -> windows_service::Result<()> {
    handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state,
        controls_accepted,
        exit_code,
        checkpoint,
        wait_hint,
        process_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn runtime_stop_is_frozen_to_unqualified_failure_evidence() {
        assert_eq!(
            RUNTIME_STOP_COMMIT_QUALIFICATION,
            ScmTerminalCommitQualificationV1::UnqualifiedSynchronousIo
        );
        assert_eq!(RUNTIME_STOP_FINAL_STATUS, ScmFinalStatusV1::Failed);
        assert_ne!(
            RUNTIME_STOP_COMMIT_QUALIFICATION,
            ScmTerminalCommitQualificationV1::ExternalScmWatcherObserved
        );
    }

    #[test]
    fn private_named_pipe_transport_defaults_are_frozen_at_v2() {
        assert_eq!(crate::ipc::DEFAULT_PIPE_NAME, r"\\.\pipe\forge-acqd-v2");
        assert_eq!(
            DEFAULT_HARDWARE_PIPE_NAME,
            r"\\.\pipe\forge-acqd-hardware-v2"
        );
        assert_eq!(
            DEFAULT_ANALYSIS_PIPE_NAME,
            r"\\.\pipe\forge-acqd-analysis-v2"
        );
        assert_ne!(crate::ipc::DEFAULT_PIPE_NAME, r"\\.\pipe\forge-acqd-v1");
        assert_ne!(
            DEFAULT_HARDWARE_PIPE_NAME,
            r"\\.\pipe\forge-acqd-hardware-v1"
        );
        assert_ne!(
            DEFAULT_ANALYSIS_PIPE_NAME,
            r"\\.\pipe\forge-acqd-analysis-v1"
        );
        let owner_pipe = owner_control_pipe_name(&[0xAB; 32]);
        assert_eq!(
            owner_pipe,
            format!(r"\\.\pipe\forge-acqd-owner-{}", "ab".repeat(32))
        );
        assert!(owner_pipe.len() < 240);
    }

    #[test]
    fn owner_request_freezes_process_identity_and_bounded_qpc_deadline() {
        let identity = ExpectedOwnerControlPeer {
            service_instance_id: [1; 32],
            supervisor_pid: 101,
            supervisor_creation_time_100ns: 102,
            supervisor_executable_sha256: [3; 32],
            owner_pid: 201,
            owner_creation_time_100ns: 202,
            owner_executable_sha256: [4; 32],
        };
        let before = qpc_now_ns().unwrap();
        let request = owner_request(&identity, ScmOwnerCommandV1::QueryReady, 1, 7).unwrap();
        let after = qpc_now_ns().unwrap();
        assert_eq!(request.service_instance_id, identity.service_instance_id);
        assert_eq!(request.supervisor_pid, identity.supervisor_pid);
        assert_eq!(request.owner_pid, identity.owner_pid);
        assert_eq!(request.command_sequence, 1);
        assert_eq!(request.request_id, 7);
        assert!(request.deadline_qpc_ns > before);
        assert!(request.deadline_qpc_ns <= after + OWNER_COMMAND_LEAD_NS);
    }

    #[test]
    fn stop_private_request_reuses_the_original_absolute_deadline() {
        let identity = ExpectedOwnerControlPeer {
            service_instance_id: [1; 32],
            supervisor_pid: 101,
            supervisor_creation_time_100ns: 102,
            supervisor_executable_sha256: [3; 32],
            owner_pid: 201,
            owner_creation_time_100ns: 202,
            owner_executable_sha256: [4; 32],
        };
        let control_qpc_ns = 1_000_000_000;
        let absolute_deadline = control_qpc_ns + STOP_TOTAL_DEADLINE_NS;
        let intent = StableFileBindingV1 {
            path: r"C:\forge\stop.intent.json".to_owned(),
            sha256_hex: "11".repeat(32),
            file_identity: crate::scm_stop_receipt::StableFileIdentityV1 {
                volume_serial_number: 1,
                file_index: 2,
                bytes: 3,
            },
        };
        let request = owner_request_with_deadline(
            &identity,
            ScmOwnerCommandV1::GracefulShutdown,
            4,
            4,
            absolute_deadline,
            Some(intent),
        )
        .unwrap();
        assert_eq!(request.deadline_qpc_ns, absolute_deadline);
        let simulated_after_snapshot = control_qpc_ns + 6_000_000_000;
        assert_eq!(
            request.deadline_qpc_ns - simulated_after_snapshot,
            9_000_000_000
        );
    }

    #[test]
    fn stop_budget_consumes_prior_work_and_reserves_only_the_force_tail() {
        let control = 1_000_000_000;
        let budget = StopDeadlineBudget::from_control_qpc(control).unwrap();
        assert_eq!(
            budget.graceful_cutoff_qpc_ns,
            control + STOP_TOTAL_DEADLINE_NS - STOP_FORCE_REAP_RESERVE_NS
        );
        assert_eq!(
            budget.final_deadline_qpc_ns,
            control + STOP_TOTAL_DEADLINE_NS
        );

        let after_snapshot_and_persist = control + 6_000_000_000;
        assert_eq!(
            budget
                .graceful_remaining_with(|| Ok(after_snapshot_and_persist))
                .unwrap(),
            Duration::from_secs(4)
        );
        assert_eq!(
            budget
                .final_remaining_with(|| Ok(after_snapshot_and_persist))
                .unwrap(),
            Duration::from_secs(9)
        );
        // Even when force is requested early, Job reap never consumes more
        // than the explicitly reserved five-second tail.
        assert_eq!(
            budget
                .force_reap_remaining_with(|| Ok(after_snapshot_and_persist))
                .unwrap(),
            Duration::from_secs(5)
        );

        assert!(budget
            .graceful_remaining_with(|| Ok(budget.graceful_cutoff_qpc_ns))
            .is_err());
        assert_eq!(
            budget
                .force_reap_remaining_with(|| Ok(budget.graceful_cutoff_qpc_ns))
                .unwrap(),
            Duration::from_secs(5)
        );
        assert_eq!(
            budget
                .force_reap_remaining_with(|| Ok(budget.graceful_cutoff_qpc_ns + 2_000_000_000))
                .unwrap(),
            Duration::from_secs(3)
        );
        assert!(budget
            .force_reap_remaining_with(|| Ok(budget.final_deadline_qpc_ns))
            .is_err());
    }

    #[test]
    fn stop_budget_clock_overflow_backwards_and_zero_are_fail_closed() {
        assert!(StopDeadlineBudget::from_control_qpc(0).is_err());
        assert!(
            StopDeadlineBudget::from_control_qpc(u64::MAX - STOP_TOTAL_DEADLINE_NS + 1).is_err()
        );
        let control = 20_000_000_000;
        let budget = StopDeadlineBudget::from_control_qpc(control).unwrap();
        assert!(budget.graceful_remaining_with(|| Ok(control - 1)).is_err());
        assert!(budget
            .final_remaining_with(|| Err(io::Error::other("injected QPC failure")))
            .is_err());
        assert!(remaining_duration_at(
            control,
            budget.final_deadline_qpc_ns,
            budget.final_deadline_qpc_ns
        )
        .is_err());
    }

    #[test]
    fn owner_pipe_timeouts_never_exceed_the_injected_remaining_budget() {
        assert_eq!(
            owner_pipe_timeouts(Duration::from_secs(9)).unwrap(),
            (OWNER_PIPE_WAIT_MS, OWNER_PIPE_IO_MS)
        );
        assert_eq!(
            owner_pipe_timeouts(Duration::from_millis(1_200)).unwrap(),
            (500, 700)
        );
        assert_eq!(
            owner_pipe_timeouts(Duration::from_millis(1)).unwrap(),
            (0, 1)
        );
        assert!(owner_pipe_timeouts(Duration::ZERO).is_err());
        assert!(owner_pipe_timeouts(Duration::from_nanos(999_999)).is_err());
        for remaining_ms in [1_u64, 17, 499, 500, 501, 2_499, 2_500, 9_000] {
            let (wait, io) = owner_pipe_timeouts(Duration::from_millis(remaining_ms)).unwrap();
            assert!(u64::from(wait) + u64::from(io) <= remaining_ms);
            assert_ne!(io, 0);
        }
    }

    #[test]
    fn config_requires_existing_absolute_root_and_exact_options() {
        let root = std::env::temp_dir().join(format!(
            "forge-service-config-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let config = ServiceHostConfig::parse([
            OsString::from("--data-root"),
            root.clone().into_os_string(),
            OsString::from("--operator-sid"),
            OsString::from("S-1-5-21-1-2-3-1001"),
        ])
        .unwrap();
        assert_eq!(config.data_root, root);
        assert_eq!(config.pipe_name, crate::ipc::DEFAULT_PIPE_NAME);
        assert_eq!(config.hardware_pipe_name, DEFAULT_HARDWARE_PIPE_NAME);
        assert_eq!(config.analysis_worker_sid, None);
        assert_eq!(config.analysis_pipe_name, DEFAULT_ANALYSIS_PIPE_NAME);
        assert_eq!(config.direct_pod_policy, None);
        let manifest = root
            .join(".forge-deployment")
            .join("forge-acqd.deployment.v1.json");
        let with_manifest = ServiceDispatchConfig::parse([
            OsString::from("--data-root"),
            root.clone().into_os_string(),
            OsString::from("--operator-sid"),
            OsString::from("S-1-5-21-1-2-3-1001"),
            OsString::from("--deployment-manifest"),
            manifest.clone().into_os_string(),
        ])
        .unwrap();
        assert_eq!(with_manifest.deployment_manifest_path, manifest);
        let with_worker = ServiceHostConfig::parse([
            OsString::from("--data-root"),
            root.clone().into_os_string(),
            OsString::from("--operator-sid"),
            OsString::from("S-1-5-21-1-2-3-1001"),
            OsString::from("--analysis-worker-sid"),
            OsString::from("S-1-5-21-1-2-3-1002"),
        ])
        .unwrap();
        assert_eq!(
            with_worker.analysis_worker_sid.as_deref(),
            Some("S-1-5-21-1-2-3-1002")
        );
        assert!(ServiceHostConfig::parse([
            OsString::from("--data-root"),
            OsString::from("relative"),
            OsString::from("--operator-sid"),
            OsString::from("S-1-5-18"),
        ])
        .is_err());
        assert!(ServiceHostConfig::parse([
            OsString::from("--data-root"),
            root.clone().into_os_string(),
            OsString::from("--operator-sid"),
            OsString::from("S-1-5-18"),
            OsString::from("--pipe"),
            OsString::from(r"\\.\pipe\CaseAlias"),
            OsString::from("--hardware-pipe"),
            OsString::from(r"\\.\PIPE\CASEALIAS"),
        ])
        .is_err());
        assert!(ServiceHostConfig::parse([
            OsString::from("--data-root"),
            root.clone().into_os_string(),
            OsString::from("--operator-sid"),
            OsString::from("S-1-5-18"),
            OsString::from("--hardware-pipe"),
            OsString::from(crate::ipc::DEFAULT_PIPE_NAME),
        ])
        .is_err());
        assert!(ServiceHostConfig::parse([
            OsString::from("--data-root"),
            root.clone().into_os_string(),
            OsString::from("--operator-sid"),
            OsString::from("S-1-5-18"),
            OsString::from("--analysis-pipe"),
            OsString::from(DEFAULT_ANALYSIS_PIPE_NAME),
        ])
        .is_err());
        assert!(ServiceHostConfig::parse([
            OsString::from("--data-root"),
            root.clone().into_os_string(),
            OsString::from("--operator-sid"),
            OsString::from("S-1-5-18"),
            OsString::from("--extra"),
            OsString::from("x"),
        ])
        .is_err());
        let policy = root.join("direct-pod-policy.json");
        std::fs::write(&policy, b"test-only").unwrap();
        assert!(ServiceHostConfig::parse([
            OsString::from("--data-root"),
            root.clone().into_os_string(),
            OsString::from("--operator-sid"),
            OsString::from("S-1-5-18"),
            OsString::from("--direct-pod-policy"),
            policy.clone().into_os_string(),
        ])
        .is_err());
        let with_policy = ServiceHostConfig::parse([
            OsString::from("--data-root"),
            root.clone().into_os_string(),
            OsString::from("--operator-sid"),
            OsString::from("S-1-5-18"),
            OsString::from("--direct-pod-policy"),
            policy.into_os_string(),
            OsString::from("--direct-pod-policy-sha256"),
            OsString::from("11".repeat(32)),
            OsString::from("--internal-approval-authority-sha256"),
            OsString::from("22".repeat(32)),
        ])
        .unwrap();
        assert!(with_policy.direct_pod_policy.is_some());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dispatcher_refuses_unbound_runtime_configuration_before_scm() {
        let root = std::env::temp_dir().join(format!(
            "forge-service-dispatch-manifest-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let error = ServiceDispatchConfig::parse([
            OsString::from("--data-root"),
            root.clone().into_os_string(),
            OsString::from("--operator-sid"),
            OsString::from("S-1-5-21-1-2-3-1001"),
        ])
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn frozen_scm_command_is_identical_to_installer_command_and_binds_manifest() {
        let root = std::env::temp_dir().join(format!(
            "forge-scm-command-contract-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source.exe");
        std::fs::write(&source, b"test-only").unwrap();
        let sid = crate::ipc::current_process_user_sid().unwrap();
        let plan =
            crate::windows_service_install::ServiceInstallPlan::new(&source, &root, &sid).unwrap();
        let config = ServiceHostConfig::parse([
            OsString::from("--data-root"),
            plan.data_root.clone().into_os_string(),
            OsString::from("--operator-sid"),
            OsString::from(&sid),
            OsString::from("--pipe"),
            OsString::from(crate::ipc::DEFAULT_PIPE_NAME),
            OsString::from("--hardware-pipe"),
            OsString::from(DEFAULT_HARDWARE_PIPE_NAME),
        ])
        .unwrap();
        let expected = canonical_scm_launch_command(
            &plan.executable_path,
            &config,
            &plan.deployment_manifest_path,
        )
        .unwrap();
        assert_eq!(expected, plan.launch_command_line);
        let drifted = canonical_scm_launch_command(
            &plan.executable_path,
            &config,
            &root.join("wrong-manifest.json"),
        )
        .unwrap();
        assert_ne!(expected, drifted);
        std::fs::remove_file(source).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
