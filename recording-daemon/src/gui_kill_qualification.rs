//! Independent-owner, SCM-emulated qualification of GUI process loss.
//!
//! The retained `forge-acqd` executable is started as a distinct owner process.
//! Only that process owns the replay dispatcher, journal, ledger, and audit
//! writer. The supervisor owns process containment and independently reopens
//! every durable artifact before it can publish a receipt. This is deliberately
//! not evidence that an installed Windows service or hardware path is ready.

#![cfg(windows)]

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use forge_protocol_v1::{sha256, RunCommandV1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::Threading::GetProcessTimes;

use crate::gui_kill_audit::{
    verify_gui_kill_audit_v3, GuiKillAuditEvidenceV3 as InternalAuditEvidenceV3,
    GuiKillAuditIdentityV3,
};
use crate::gui_kill_control::{
    decode_response as decode_control_response, encode_request as encode_control_request,
    GuiKillAttemptModeV1, GuiKillContainmentEvidenceV2, GuiKillControlCommandV1,
    GuiKillControlRequestV1, GuiKillControlResponseV1, GuiKillReapEvidenceV2, GuiKillWaitMethodV2,
    GuiKillWaitResultV2, GUI_KILL_CONTROL_REQUEST_SCHEMA,
};
use crate::gui_kill_owner::{run_gui_kill_owner_v3, GuiKillOwnerOptions};
use crate::ipc::{call_secure_pipe_bounded, call_secure_pipe_bounded_hold_before_ack};
use crate::journal::{scan_journal, JournalScan};
use crate::run::{RunCommandKind, RunState};
use crate::run_ledger::{DurableRunService, DurableRunStatus};
use crate::service_protocol::{DaemonResponseV1, SERVICE_CONTRACT_HASH_HEX};
use crate::windows_contained_process::{
    ContainedProcess, ContainedProcessContainmentEvidence, ContainedProcessWaitEvidence,
    ContainedProcessWaitMethod,
};
use crate::windows_deployment_security::{
    copy_new_durable_from_proof, lock_qualification_file_proof,
};

pub const GUI_KILL_QUALIFICATION_SCHEMA: &str = "forge.gui-kill-qualification.v3";
pub const GUI_KILL_QUALIFICATION_V1_SCHEMA: &str = "forge.gui-kill-qualification.v1";
pub const GUI_KILL_QUALIFICATION_V2_SCHEMA: &str = "forge.gui-kill-qualification.v2";
const CHILD_STAGE_TIMEOUT: Duration = Duration::from_secs(3);
const CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(3);
const OWNER_REAP_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_WAIT_TIMEOUT_MS: u32 = 5_000;
const CLIENT_IO_TIMEOUT_MS: u32 = 5_000;
const FIRST_ATTEMPT_REQUEST_ID: u64 = 10_000;

fn qualification_timeouts() -> GuiKillTimeoutsV2 {
    GuiKillTimeoutsV2 {
        child_stage_timeout_ms: CHILD_STAGE_TIMEOUT.as_millis() as u64,
        child_reap_timeout_ms: CHILD_REAP_TIMEOUT.as_millis() as u64,
        owner_reap_timeout_ms: OWNER_REAP_TIMEOUT.as_millis() as u64,
        client_wait_timeout_ms: CLIENT_WAIT_TIMEOUT_MS,
        client_io_timeout_ms: CLIENT_IO_TIMEOUT_MS,
    }
}

fn qualification_open_gates() -> Vec<String> {
    vec![
        "installed SCM service identity, ACL, restart, and blocked-handler shutdown remain unqualified".to_owned(),
        "process-image/path-ancestor ABA, abnormal same-account early resume, qualification-root ACL/WDAC/Authenticode, and owner-independent Job queries remain open".to_owned(),
        "local audit and receipt hashes are integrity evidence, not a signature or attestation".to_owned(),
        "D3XX hardware, RHS safety, Aggregator, 24-hour endurance, and release gates remain open".to_owned(),
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuiKillInjectedFailure {
    Timeout,
    Exit,
}

#[derive(Clone, Debug)]
pub struct GuiKillQualificationOptions {
    pub root: PathBuf,
    pub receipt_path: PathBuf,
    pub executable_path: PathBuf,
    pub kill_count: u32,
    pub injected_failure: Option<GuiKillInjectedFailure>,
    pub inject_ack_read_failure: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuiKillTimeoutsV2 {
    pub child_stage_timeout_ms: u64,
    pub child_reap_timeout_ms: u64,
    pub owner_reap_timeout_ms: u64,
    pub client_wait_timeout_ms: u32,
    pub client_io_timeout_ms: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuiKillContainmentEvidenceV3 {
    pub created_suspended: bool,
    pub kill_on_job_close_configured: bool,
    pub job_assigned_before_resume: bool,
    pub executable_rehashed_before_resume: bool,
}

impl GuiKillContainmentEvidenceV3 {
    fn validate(&self) -> io::Result<()> {
        if self.created_suspended
            && self.kill_on_job_close_configured
            && self.job_assigned_before_resume
            && self.executable_rehashed_before_resume
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete v3 containment evidence",
            ))
        }
    }
}

impl From<ContainedProcessContainmentEvidence> for GuiKillContainmentEvidenceV3 {
    fn from(value: ContainedProcessContainmentEvidence) -> Self {
        Self {
            created_suspended: value.created_suspended,
            kill_on_job_close_configured: value.kill_on_job_close_configured,
            job_assigned_before_resume: value.job_assigned_before_resume,
            executable_rehashed_before_resume: value.executable_rehashed_before_resume,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuiKillReapEvidenceV3 {
    pub method: String,
    pub exit_code: u32,
    pub wait_deadline_ms: u32,
    pub wait_elapsed_ms: u32,
    pub wait_result: String,
    pub job_active_processes_after_wait: u32,
    pub job_empty_proven: bool,
}

impl From<GuiKillContainmentEvidenceV3> for GuiKillContainmentEvidenceV2 {
    fn from(value: GuiKillContainmentEvidenceV3) -> Self {
        Self {
            created_suspended: value.created_suspended,
            kill_on_job_close_configured: value.kill_on_job_close_configured,
            job_assigned_before_resume: value.job_assigned_before_resume,
            executable_rehashed_before_resume: value.executable_rehashed_before_resume,
        }
    }
}

impl GuiKillReapEvidenceV3 {
    fn to_control_evidence(&self) -> io::Result<GuiKillReapEvidenceV2> {
        self.validate()?;
        Ok(GuiKillReapEvidenceV2 {
            method: match self.method.as_str() {
                "graceful_wait" => GuiKillWaitMethodV2::GracefulWait,
                "job_object_termination" => GuiKillWaitMethodV2::JobObjectTermination,
                _ => unreachable!("validated above"),
            },
            exit_code: self.exit_code,
            wait_deadline_ms: self.wait_deadline_ms,
            wait_elapsed_ms: self.wait_elapsed_ms,
            wait_result: GuiKillWaitResultV2::SignaledReaped,
            job_active_processes_after_wait: self.job_active_processes_after_wait,
            job_empty_proven: self.job_empty_proven,
        })
    }
}

impl GuiKillReapEvidenceV3 {
    fn validate(&self) -> io::Result<()> {
        if (self.method == "job_object_termination" || self.method == "graceful_wait")
            && self.wait_result == "signaled_reaped"
            && self.exit_code != 259
            && self.wait_deadline_ms != 0
            && self.wait_elapsed_ms <= self.wait_deadline_ms
            && self.job_active_processes_after_wait == 0
            && self.job_empty_proven
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid v3 reap evidence",
            ))
        }
    }
}

impl From<ContainedProcessWaitEvidence> for GuiKillReapEvidenceV3 {
    fn from(value: ContainedProcessWaitEvidence) -> Self {
        Self {
            method: match value.method {
                ContainedProcessWaitMethod::GracefulWait => "graceful_wait",
                ContainedProcessWaitMethod::JobObjectTermination => "job_object_termination",
            }
            .to_owned(),
            exit_code: value.exit_code,
            wait_deadline_ms: value.wait_deadline_ms,
            wait_elapsed_ms: value.wait_elapsed_ms,
            wait_result: value.wait_result.to_owned(),
            job_active_processes_after_wait: value.job_active_processes_after_wait,
            job_empty_proven: value.job_empty_proven,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuiKillJournalEvidenceV2 {
    pub path: String,
    pub sha256_hex: String,
    pub bytes: u64,
    pub record_count: u64,
    pub first_journal_sequence: u64,
    pub last_journal_sequence: u64,
    pub durable_record_count: u64,
    pub durable_valid_len: u64,
    pub seal_expected_last_journal_sequence: u64,
    pub seal_record_count: u64,
    pub pod_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuiKillProgressEvidenceV2 {
    pub baseline_committed_record_count: u64,
    pub baseline_durable_record_count: u64,
    pub terminal_committed_record_count: u64,
    pub terminal_durable_record_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuiKillLedgerEvidenceV2 {
    pub state_wire: u8,
    pub active_epoch: Option<u64>,
    pub highest_epoch: u64,
    pub active_run_id_hex: Option<String>,
    pub ledger_events: u64,
    pub auto_failed_on_restart: bool,
    pub poisoned: bool,
    pub latest_sealed_run_id_hex: Option<String>,
    pub latest_published_run_id_hex: Option<String>,
}

impl From<&DurableRunStatus> for GuiKillLedgerEvidenceV2 {
    fn from(value: &DurableRunStatus) -> Self {
        Self {
            state_wire: value.state.wire_value(),
            active_epoch: value.active_epoch,
            highest_epoch: value.highest_epoch,
            active_run_id_hex: value.active_run_id_hex.clone(),
            ledger_events: value.ledger_events,
            auto_failed_on_restart: value.auto_failed_on_restart,
            poisoned: value.poisoned,
            latest_sealed_run_id_hex: value.latest_sealed_run_id_hex.clone(),
            latest_published_run_id_hex: value.latest_published_run_id_hex.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuiKillAuditEvidenceV3 {
    pub path: String,
    pub sha256_hex: String,
    pub bytes: u64,
    pub event_count: u64,
    pub first_event_hash_hex: String,
    pub last_event_hash_hex: String,
    pub durable_event_sequence: u64,
}

impl From<InternalAuditEvidenceV3> for GuiKillAuditEvidenceV3 {
    fn from(value: InternalAuditEvidenceV3) -> Self {
        Self {
            path: value.path,
            sha256_hex: value.sha256_hex,
            bytes: value.bytes,
            event_count: value.event_count,
            first_event_hash_hex: value.first_event_hash_hex,
            last_event_hash_hex: value.last_event_hash_hex,
            durable_event_sequence: value.durable_event_sequence,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuiKillQualificationReceiptV3 {
    pub schema: String,
    pub protocol_hash_hex: String,
    pub service_contract_hash_hex: String,
    pub executable_path: String,
    pub executable_sha256_hex: String,
    pub run_id_hex: String,
    pub supervisor_pid: u32,
    pub supervisor_creation_time_100ns: u64,
    pub owner_pid: u32,
    pub owner_creation_time_100ns: u64,
    pub gui_pipe_name: String,
    pub control_pipe_name: String,
    pub owner_job_assigned: bool,
    pub owner_containment: GuiKillContainmentEvidenceV3,
    pub owner_reap: GuiKillReapEvidenceV3,
    pub owner_exit_code: i32,
    pub requested_kill_count: u32,
    pub completed_kill_count: u32,
    pub response_consumed_then_killed_count: u32,
    pub transaction_inflight_then_killed_count: u32,
    pub hard_timeouts: GuiKillTimeoutsV2,
    pub progress: GuiKillProgressEvidenceV2,
    pub journal: GuiKillJournalEvidenceV2,
    pub ledger_final_status: GuiKillLedgerEvidenceV2,
    pub audit: GuiKillAuditEvidenceV3,
    pub service_deployed: bool,
    pub scm_emulated: bool,
    pub owner_process_isolated: bool,
    pub hardware_transport_available: bool,
    pub nwb_enabled: bool,
    pub raw_sample_bytes_entered_gui: u64,
    pub gui_stop_or_abort_commands: u32,
    pub supervisor_stop_commands: u32,
    pub passed: bool,
    pub open_gates: Vec<String>,
    pub evidence_sha256_hex: String,
    pub evidence_hash_is_signature_or_attestation: bool,
}

struct ContainedChild {
    process: Option<ContainedProcess>,
}

impl ContainedChild {
    fn new(process: ContainedProcess) -> Self {
        Self {
            process: Some(process),
        }
    }

    fn id(&self) -> io::Result<u32> {
        self.process
            .as_ref()
            .map(|process| process.identity().pid)
            .ok_or_else(|| io::Error::other("contained child was already reaped"))
    }

    fn creation_time_100ns(&self) -> io::Result<u64> {
        self.process
            .as_ref()
            .map(|process| process.identity().creation_time_100ns)
            .ok_or_else(|| io::Error::other("contained child was already reaped"))
    }

    fn containment_evidence(&self) -> io::Result<GuiKillContainmentEvidenceV3> {
        let evidence = self
            .process
            .as_ref()
            .ok_or_else(|| io::Error::other("contained child was already reaped"))?
            .containment_evidence();
        evidence.validate()?;
        Ok(evidence.into())
    }

    fn child_mut(&mut self) -> io::Result<&mut ContainedProcess> {
        self.process
            .as_mut()
            .ok_or_else(|| io::Error::other("contained child was already reaped"))
    }

    fn reap(&mut self, timeout: Duration) -> io::Result<ContainedProcessWaitEvidence> {
        let process = self
            .process
            .as_mut()
            .ok_or_else(|| io::Error::other("contained child was already reaped"))?;
        let evidence = if process.query_exit_code()?.is_some() {
            process.wait_for_exit(timeout)?
        } else {
            process.terminate_and_reap(timeout)?
        };
        self.process.take();
        Ok(evidence)
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> io::Result<ContainedProcessWaitEvidence> {
        let process = self
            .process
            .as_mut()
            .ok_or_else(|| io::Error::other("contained child was already reaped"))?;
        let evidence = process.wait_for_exit(timeout)?;
        self.process.take();
        Ok(evidence)
    }
}

impl Drop for ContainedChild {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            let _ = process.terminate_and_observe(CHILD_REAP_TIMEOUT);
        }
    }
}

struct OwnerControlClient {
    pipe_name: String,
    gui_pipe_name: String,
    run_id_hex: String,
    supervisor_pid: u32,
    supervisor_creation_time_100ns: u64,
    owner_pid: u32,
    owner_creation_time_100ns: u64,
    owner_executable_sha256_hex: String,
    next_sequence: u64,
}

impl OwnerControlClient {
    fn call(&mut self, command: GuiKillControlCommandV1) -> io::Result<GuiKillControlResponseV1> {
        let sequence = self.next_sequence;
        let request = GuiKillControlRequestV1 {
            schema: GUI_KILL_CONTROL_REQUEST_SCHEMA.to_owned(),
            command_sequence: sequence,
            supervisor_pid: self.supervisor_pid,
            supervisor_creation_time_100ns: self.supervisor_creation_time_100ns,
            run_id_hex: self.run_id_hex.clone(),
            command,
        };
        // This private control frame is itself the SecurePipe frame. It must
        // never be wrapped inside the frozen Host low-speed envelope.
        let response = decode_control_response(&call_secure_pipe_bounded(
            &self.pipe_name,
            &encode_control_request(&request)?,
            CLIENT_WAIT_TIMEOUT_MS,
            CLIENT_IO_TIMEOUT_MS,
        )?)?;
        if response.command_sequence != sequence
            || response.run_id_hex != self.run_id_hex
            || !response.accepted
            || response.error_code != "none"
            || response.owner_pid != self.owner_pid
            || response.owner_creation_time_100ns != self.owner_creation_time_100ns
            || response.owner_executable_sha256_hex != self.owner_executable_sha256_hex
            || response.gui_pipe_name != self.gui_pipe_name
            || response.control_pipe_name != self.pipe_name
            || response.supervisor_pid != self.supervisor_pid
            || response.supervisor_creation_time_100ns != self.supervisor_creation_time_100ns
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "owner-control response identity or command binding is invalid",
            ));
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("owner-control sequence overflow"))?;
        Ok(response)
    }
}

pub fn run_gui_kill_qualification(
    options: GuiKillQualificationOptions,
) -> io::Result<GuiKillQualificationReceiptV3> {
    validate_options(&options)?;
    fs::create_dir(&options.root)?;
    let root = fs::canonicalize(&options.root)?;
    run_gui_kill_qualification_inner(&options, &root)
}

fn run_gui_kill_qualification_inner(
    options: &GuiKillQualificationOptions,
    root: &Path,
) -> io::Result<GuiKillQualificationReceiptV3> {
    let run_id = fresh_run_id(root)?;
    let run_id_hex = hex(&run_id);
    let (qualified_executable, executable_sha256_hex) =
        retain_qualified_executable(root, &options.executable_path)?;
    let (gui_pipe_name, control_pipe_name) = fresh_pipe_names()?;
    let supervisor_pid = std::process::id();
    let supervisor_creation_time_100ns = current_process_creation_time_100ns()?;

    let mut owner = spawn_owner_child(
        &qualified_executable,
        root,
        &gui_pipe_name,
        &control_pipe_name,
        &run_id_hex,
        supervisor_pid,
        supervisor_creation_time_100ns,
        &executable_sha256_hex,
        options.kill_count,
    )?;
    let owner_containment = owner.containment_evidence()?;
    let owner_pid = owner.id()?;
    let owner_creation_time_100ns = owner.creation_time_100ns()?;
    if owner_pid == supervisor_pid || owner_creation_time_100ns == supervisor_creation_time_100ns {
        return Err(io::Error::other(
            "qualification owner is not an independent process instance",
        ));
    }
    let mut control = OwnerControlClient {
        pipe_name: control_pipe_name.clone(),
        gui_pipe_name: gui_pipe_name.clone(),
        run_id_hex: run_id_hex.clone(),
        supervisor_pid,
        supervisor_creation_time_100ns,
        owner_pid,
        owner_creation_time_100ns,
        owner_executable_sha256_hex: executable_sha256_hex.clone(),
        next_sequence: 1,
    };

    let work = (|| -> io::Result<SupervisorWork> {
        wait_for_pipe_creation(&control_pipe_name, owner.child_mut()?)?;
        let ready = control.call(GuiKillControlCommandV1::QueryReady)?;
        if ready.state_wire != RunState::New.wire_value() || ready.active_epoch.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "owner did not start at the New lifecycle boundary",
            ));
        }

        for (request_id, kind, expected_state) in [
            (1, RunCommandKind::Prepare, RunState::Prepared),
            (2, RunCommandKind::Arm, RunState::Armed),
            (3, RunCommandKind::Start, RunState::Recording),
        ] {
            let response = control.call(GuiKillControlCommandV1::Lifecycle {
                request_id,
                command_wire: kind.wire_value() as u8,
            })?;
            if response.state_wire != expected_state.wire_value() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "owner lifecycle response reached the wrong state",
                ));
            }
        }

        let baseline = wait_for_recording(&gui_pipe_name, 4)?;
        let baseline_control =
            control.call(GuiKillControlCommandV1::BaselineSnapshot { request_id: 4 })?;
        let baseline_committed = baseline.committed_record_count.unwrap_or(0);
        let baseline_durable = baseline.durable_record_count.unwrap_or(0);
        if baseline_control.state_wire != RunState::Recording.wire_value()
            || baseline_control.active_epoch != Some(1)
            || baseline_control.committed_record_count != baseline_committed
            || baseline_control.durable_record_count != baseline_durable
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "owner baseline does not match the supervisor FACK-completed snapshot",
            ));
        }

        let mut previous_committed = baseline_committed;
        let mut previous_durable = baseline_durable;
        let mut after_ack = 0_u32;
        let mut inflight = 0_u32;
        for attempt in 0..options.kill_count {
            let request_id = attempt_request_id(attempt)?;
            let is_after_ack = attempt % 2 == 0;
            let mode = if is_after_ack {
                GuiKillAttemptModeV1::AfterAck
            } else {
                GuiKillAttemptModeV1::Inflight
            };
            let injected = (attempt == 0).then_some(options.injected_failure).flatten();
            let stage = match (is_after_ack, injected) {
                (_, Some(GuiKillInjectedFailure::Timeout)) => "timeout",
                (_, Some(GuiKillInjectedFailure::Exit)) => "exit",
                (true, None) => "after-ack",
                (false, None) => "inflight",
            };
            let mut child = spawn_gui_child(
                &qualified_executable,
                &executable_sha256_hex,
                &gui_pipe_name,
                root,
                stage,
                u64::from(attempt),
                request_id,
            )?;
            let gui_containment = child.containment_evidence()?;
            let gui_pid = child.id()?;
            let gui_creation_time_100ns = child.creation_time_100ns()?;

            let attempt_result = (|| -> io::Result<()> {
                control.call(GuiKillControlCommandV1::AttemptStarted {
                    attempt,
                    mode,
                    gui_pid,
                    gui_creation_time_100ns,
                    request_id,
                    barrier_request_id: is_after_ack.then_some(request_id + 1),
                    post_kill_request_id: request_id + 2,
                    containment: gui_containment.into(),
                })?;

                let marker = if is_after_ack && injected.is_none() {
                    format!("after-ack-{attempt}")
                } else if !is_after_ack && injected.is_none() {
                    format!("inflight-ready-{attempt}")
                } else {
                    format!("never-written-{attempt}")
                };
                wait_for_marker_or_child_exit(root, &marker, child.child_mut()?)?;
                if !is_after_ack && options.inject_ack_read_failure {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "injected AckRead observation failure",
                    ));
                }
                control.call(GuiKillControlCommandV1::StageObserved { attempt })?;
                control.call(GuiKillControlCommandV1::KillRequested { attempt })?;
                let reap = child.reap(CHILD_REAP_TIMEOUT)?;
                if reap.method != ContainedProcessWaitMethod::JobObjectTermination
                    || !reap.job_empty_proven
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "GUI child reap lacks Job termination and empty-job proof",
                    ));
                }
                write_marker(root, &format!("reaped-{attempt}"))?;
                let reap_v3: GuiKillReapEvidenceV3 = reap.into();
                reap_v3.validate()?;
                control.call(GuiKillControlCommandV1::ReapProven {
                    attempt,
                    evidence: reap_v3.to_control_evidence()?,
                })?;

                let post = verify_recording_after_kill(
                    &gui_pipe_name,
                    request_id + 2,
                    &mut previous_committed,
                    &mut previous_durable,
                )?;
                let completed =
                    control.call(GuiKillControlCommandV1::CompleteAttempt { attempt })?;
                if completed.state_wire != RunState::Recording.wire_value()
                    || completed.active_epoch != Some(1)
                    || completed.committed_record_count != post.committed
                    || completed.durable_record_count != post.durable
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "owner post-kill evidence does not match supervisor snapshot",
                    ));
                }
                Ok(())
            })();
            if let Err(error) = attempt_result {
                let cleanup = if child.process.is_some() {
                    child.reap(CHILD_REAP_TIMEOUT).map(|_| ())
                } else {
                    Ok(())
                };
                if cleanup.is_ok() {
                    let _ = write_marker(root, &format!("reaped-{attempt}"));
                }
                return Err(combine_errors(
                    &format!("GUI child attempt {attempt} ({stage}) failed closed"),
                    error,
                    cleanup,
                ));
            }
            if is_after_ack {
                after_ack += 1;
            } else {
                inflight += 1;
            }
        }

        let stop_request_id = FIRST_ATTEMPT_REQUEST_ID
            .checked_add(u64::from(options.kill_count) * 3)
            .ok_or_else(|| io::Error::other("qualification Stop request ID overflow"))?;
        let stop = control.call(GuiKillControlCommandV1::Lifecycle {
            request_id: stop_request_id,
            command_wire: RunCommandKind::Stop.wire_value() as u8,
        })?;
        if stop.state_wire != RunState::JournalSealed.wire_value() || stop.active_epoch.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "owner Stop did not reach JournalSealed",
            ));
        }
        let exit = control.call(GuiKillControlCommandV1::Exit)?;
        if exit.state_wire != RunState::JournalSealed.wire_value() || exit.active_epoch.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "owner Exit was acknowledged before the sealed boundary",
            ));
        }
        Ok(SupervisorWork {
            after_ack,
            inflight,
            baseline_committed,
            baseline_durable,
        })
    })();

    let work = match work {
        Ok(value) => value,
        Err(error) => {
            let cleanup = owner.reap(OWNER_REAP_TIMEOUT).map(|_| ());
            return Err(combine_errors(
                "independent owner qualification",
                error,
                cleanup,
            ));
        }
    };
    let owner_status = owner.wait_for_exit(OWNER_REAP_TIMEOUT)?;
    if !owner_status.job_empty_proven {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner exit lacks an empty-job proof",
        ));
    }
    let owner_exit_code = i32::try_from(owner_status.exit_code).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "owner exit code does not fit the receipt representation",
        )
    })?;
    if owner_exit_code != 0 {
        return Err(io::Error::other(format!(
            "owner exited after seal with nonzero code {owner_exit_code}"
        )));
    }
    let owner_reap = GuiKillReapEvidenceV3::from(owner_status);
    if owner_reap.method != "graceful_wait"
        || owner_reap.wait_result != "signaled_reaped"
        || owner_reap.job_active_processes_after_wait != 0
        || !owner_reap.job_empty_proven
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner graceful exit lacks the required empty-job evidence",
        ));
    }

    let audit_identity = GuiKillAuditIdentityV3 {
        run_id_hex: run_id_hex.clone(),
        supervisor_pid,
        supervisor_creation_time_100ns,
        owner_pid,
        owner_creation_time_100ns,
    };
    let audit_path = root.join("gui-kill-audit-v3.jsonl");
    let audit = verify_gui_kill_audit_v3(
        &audit_path,
        &audit_identity,
        options.kill_count,
        RunState::Recording.wire_value(),
    )?;
    let journal_path = root.join(format!("run-{run_id_hex}.forgewal"));
    let scan = verify_reopened_journal(&journal_path, run_id, work.baseline_committed)?;
    let ledger_status = verify_reopened_ledger(root, &run_id_hex)?;
    let mut receipt = build_receipt(ReceiptInputs {
        executable: &qualified_executable,
        executable_sha256_hex,
        run_id_hex,
        supervisor_pid,
        supervisor_creation_time_100ns,
        owner_pid,
        owner_creation_time_100ns,
        gui_pipe_name,
        control_pipe_name,
        owner_exit_code,
        owner_containment,
        owner_reap,
        requested_kill_count: options.kill_count,
        work,
        journal_path: &journal_path,
        scan: &scan,
        ledger_status,
        audit: audit.into(),
    })?;
    receipt.evidence_sha256_hex = receipt_evidence_hash(&receipt)?;
    persist_receipt(&options.receipt_path, &receipt)?;
    verify_gui_kill_qualification_receipt(&options.receipt_path)
}

struct SupervisorWork {
    after_ack: u32,
    inflight: u32,
    baseline_committed: u64,
    baseline_durable: u64,
}

struct ReceiptInputs<'a> {
    executable: &'a Path,
    executable_sha256_hex: String,
    run_id_hex: String,
    supervisor_pid: u32,
    supervisor_creation_time_100ns: u64,
    owner_pid: u32,
    owner_creation_time_100ns: u64,
    gui_pipe_name: String,
    control_pipe_name: String,
    owner_exit_code: i32,
    owner_containment: GuiKillContainmentEvidenceV3,
    owner_reap: GuiKillReapEvidenceV3,
    requested_kill_count: u32,
    work: SupervisorWork,
    journal_path: &'a Path,
    scan: &'a JournalScan,
    ledger_status: DurableRunStatus,
    audit: GuiKillAuditEvidenceV3,
}

fn build_receipt(input: ReceiptInputs<'_>) -> io::Result<GuiKillQualificationReceiptV3> {
    let journal = journal_evidence(input.journal_path, input.scan)?;
    Ok(GuiKillQualificationReceiptV3 {
        schema: GUI_KILL_QUALIFICATION_SCHEMA.to_owned(),
        protocol_hash_hex: forge_protocol_v1::PROTOCOL_HASH_HEX.to_owned(),
        service_contract_hash_hex: SERVICE_CONTRACT_HASH_HEX.to_owned(),
        executable_path: input.executable.to_string_lossy().into_owned(),
        executable_sha256_hex: input.executable_sha256_hex,
        run_id_hex: input.run_id_hex,
        supervisor_pid: input.supervisor_pid,
        supervisor_creation_time_100ns: input.supervisor_creation_time_100ns,
        owner_pid: input.owner_pid,
        owner_creation_time_100ns: input.owner_creation_time_100ns,
        gui_pipe_name: input.gui_pipe_name,
        control_pipe_name: input.control_pipe_name,
        owner_job_assigned: input.owner_containment.job_assigned_before_resume,
        owner_containment: input.owner_containment,
        owner_reap: input.owner_reap,
        owner_exit_code: input.owner_exit_code,
        requested_kill_count: input.requested_kill_count,
        completed_kill_count: input.work.after_ack + input.work.inflight,
        response_consumed_then_killed_count: input.work.after_ack,
        transaction_inflight_then_killed_count: input.work.inflight,
        hard_timeouts: qualification_timeouts(),
        progress: GuiKillProgressEvidenceV2 {
            baseline_committed_record_count: input.work.baseline_committed,
            baseline_durable_record_count: input.work.baseline_durable,
            terminal_committed_record_count: input.scan.complete_chunks,
            terminal_durable_record_count: input.scan.durable.durable_record_count,
        },
        journal,
        ledger_final_status: GuiKillLedgerEvidenceV2::from(&input.ledger_status),
        audit: input.audit,
        service_deployed: false,
        scm_emulated: true,
        owner_process_isolated: true,
        hardware_transport_available: false,
        nwb_enabled: false,
        raw_sample_bytes_entered_gui: 0,
        gui_stop_or_abort_commands: 0,
        supervisor_stop_commands: 1,
        passed: true,
        open_gates: qualification_open_gates(),
        evidence_sha256_hex: String::new(),
        evidence_hash_is_signature_or_attestation: false,
    })
}

pub fn verify_gui_kill_qualification_receipt(
    path: &Path,
) -> io::Result<GuiKillQualificationReceiptV3> {
    let bytes = fs::read(path)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(json_error)?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "receipt schema is missing"))?;
    if schema == GUI_KILL_QUALIFICATION_V1_SCHEMA || schema == GUI_KILL_QUALIFICATION_V2_SCHEMA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "historical GUI-kill receipt is incomplete and cannot satisfy v3",
        ));
    }
    if schema != GUI_KILL_QUALIFICATION_SCHEMA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown GUI-kill qualification receipt schema",
        ));
    }
    let receipt: GuiKillQualificationReceiptV3 =
        serde_json::from_value(value).map_err(json_error)?;
    if receipt.evidence_sha256_hex != receipt_evidence_hash(&receipt)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GUI-kill receipt evidence hash mismatch",
        ));
    }
    verify_receipt_semantics(&receipt)?;
    Ok(receipt)
}

fn verify_receipt_semantics(receipt: &GuiKillQualificationReceiptV3) -> io::Result<()> {
    receipt.owner_containment.validate()?;
    receipt.owner_reap.validate()?;
    if receipt.owner_reap.method != "graceful_wait" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner receipt must carry a graceful process-handle wait",
        ));
    }
    if receipt.protocol_hash_hex != forge_protocol_v1::PROTOCOL_HASH_HEX
        || receipt.service_contract_hash_hex != SERVICE_CONTRACT_HASH_HEX
        || receipt.supervisor_pid == 0
        || receipt.supervisor_creation_time_100ns == 0
        || receipt.owner_pid == 0
        || receipt.owner_creation_time_100ns == 0
        || receipt.owner_pid == receipt.supervisor_pid
        || receipt.owner_creation_time_100ns == receipt.supervisor_creation_time_100ns
        || receipt.gui_pipe_name == receipt.control_pipe_name
        || !receipt
            .gui_pipe_name
            .starts_with(r"\\.\pipe\forge-acqd-gui-kill-v3-")
        || !receipt
            .control_pipe_name
            .starts_with(r"\\.\pipe\forge-acqd-gui-kill-v3-")
        || receipt.owner_job_assigned != receipt.owner_containment.job_assigned_before_resume
        || !receipt.owner_job_assigned
        || receipt.owner_exit_code != 0
        || receipt.owner_reap.exit_code != receipt.owner_exit_code as u32
        || u64::from(receipt.owner_reap.wait_deadline_ms)
            != receipt.hard_timeouts.owner_reap_timeout_ms
        || !(2..=1_000).contains(&receipt.requested_kill_count)
        || !receipt.requested_kill_count.is_multiple_of(2)
        || receipt.completed_kill_count != receipt.requested_kill_count
        || receipt.response_consumed_then_killed_count != receipt.requested_kill_count / 2
        || receipt.transaction_inflight_then_killed_count != receipt.requested_kill_count / 2
        || receipt.response_consumed_then_killed_count
            + receipt.transaction_inflight_then_killed_count
            != receipt.completed_kill_count
        || receipt.service_deployed
        || !receipt.scm_emulated
        || !receipt.owner_process_isolated
        || receipt.hardware_transport_available
        || receipt.nwb_enabled
        || receipt.raw_sample_bytes_entered_gui != 0
        || receipt.gui_stop_or_abort_commands != 0
        || receipt.supervisor_stop_commands != 1
        || !receipt.passed
        || receipt.evidence_hash_is_signature_or_attestation
        || receipt.hard_timeouts != qualification_timeouts()
        || receipt.open_gates != qualification_open_gates()
        || !is_hex_len(&receipt.run_id_hex, 32)
        || !is_hex_len(&receipt.executable_sha256_hex, 64)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GUI-kill receipt fixed invariants are invalid",
        ));
    }
    let executable = Path::new(&receipt.executable_path);
    let journal_path = Path::new(&receipt.journal.path);
    let audit_path = Path::new(&receipt.audit.path);
    if !executable.is_absolute()
        || !journal_path.is_absolute()
        || !audit_path.is_absolute()
        || sha256_file(executable)? != receipt.executable_sha256_hex
        || journal_path.parent() != audit_path.parent()
        || executable.parent() != journal_path.parent()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "receipt artifacts do not share the retained qualification root",
        ));
    }
    let audit_identity = GuiKillAuditIdentityV3 {
        run_id_hex: receipt.run_id_hex.clone(),
        supervisor_pid: receipt.supervisor_pid,
        supervisor_creation_time_100ns: receipt.supervisor_creation_time_100ns,
        owner_pid: receipt.owner_pid,
        owner_creation_time_100ns: receipt.owner_creation_time_100ns,
    };
    let verified_audit = verify_gui_kill_audit_v3(
        audit_path,
        &audit_identity,
        receipt.requested_kill_count,
        RunState::Recording.wire_value(),
    )?;
    if receipt.audit != GuiKillAuditEvidenceV3::from(verified_audit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "receipt audit evidence does not match independent replay",
        ));
    }
    let mut run_id = [0_u8; 16];
    decode_hex_into(&receipt.run_id_hex, &mut run_id)?;
    let scan = verify_reopened_journal(
        journal_path,
        run_id,
        receipt.progress.baseline_committed_record_count,
    )?;
    if receipt.journal != journal_evidence(journal_path, &scan)?
        || receipt.progress.terminal_committed_record_count != scan.complete_chunks
        || receipt.progress.terminal_durable_record_count != scan.durable.durable_record_count
        || receipt.progress.baseline_durable_record_count
            > receipt.progress.terminal_durable_record_count
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "receipt journal/progress evidence does not match reopen",
        ));
    }
    let root = journal_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "journal has no parent"))?;
    let ledger = verify_reopened_ledger(root, &receipt.run_id_hex)?;
    if receipt.ledger_final_status != GuiKillLedgerEvidenceV2::from(&ledger) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "receipt ledger evidence does not match reopen",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // stable CLI seam; internal owner uses a typed options object
pub fn run_gui_kill_owner(
    root: &Path,
    gui_pipe_name: &str,
    control_pipe_name: &str,
    run_id_hex: &str,
    supervisor_pid: u32,
    supervisor_creation_time_100ns: u64,
    owner_executable_sha256_hex: &str,
    expected_attempts: u32,
) -> io::Result<()> {
    let mut run_id = [0_u8; 16];
    decode_hex_into(run_id_hex, &mut run_id)?;
    run_gui_kill_owner_v3(GuiKillOwnerOptions {
        root: root.to_path_buf(),
        gui_pipe_name: gui_pipe_name.to_owned(),
        control_pipe_name: control_pipe_name.to_owned(),
        run_id,
        supervisor_pid,
        supervisor_creation_time_100ns,
        owner_executable_sha256_hex: owner_executable_sha256_hex.to_owned(),
        expected_attempts,
    })
}

pub fn run_gui_kill_client(
    pipe_name: &str,
    root: &Path,
    stage: &str,
    attempt: u64,
    request_id: u64,
) -> io::Result<()> {
    match stage {
        "after-ack" => {
            let first = call_gui_request(pipe_name, &snapshot_request(request_id)?, request_id)?;
            validate_gui_snapshot(&first)?;
            let barrier = request_id
                .checked_add(1)
                .ok_or_else(|| io::Error::other("GUI barrier request ID overflow"))?;
            let second = call_gui_request(pipe_name, &snapshot_request(barrier)?, barrier)?;
            validate_gui_snapshot(&second)?;
            write_marker(root, &format!("after-ack-{attempt}"))?;
            park_until_terminated();
        }
        "inflight" => {
            let request = snapshot_request(request_id)?;
            let hold = call_secure_pipe_bounded_hold_before_ack(
                pipe_name,
                &request,
                CLIENT_WAIT_TIMEOUT_MS,
                CLIENT_IO_TIMEOUT_MS,
            )?;
            let response = DaemonResponseV1::decode(hold.response())?;
            validate_gui_snapshot(&response)?;
            if response.receipt_hash != sha256(&request)
                || hold.challenge().iter().all(|byte| *byte == 0)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GUI inflight response/challenge binding is invalid",
                ));
            }
            write_marker(root, &format!("inflight-ready-{attempt}"))?;
            let _hold = hold;
            park_until_terminated();
        }
        "timeout" => park_until_terminated(),
        "exit" => Err(io::Error::other("injected GUI client abnormal exit")),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown GUI-kill client stage",
        )),
    }
}

struct PostKillSnapshot {
    committed: u64,
    durable: u64,
}

fn verify_recording_after_kill(
    pipe_name: &str,
    request_id: u64,
    previous_committed: &mut u64,
    previous_durable: &mut u64,
) -> io::Result<PostKillSnapshot> {
    let response = call_gui_request(pipe_name, &snapshot_request(request_id)?, request_id)?;
    validate_gui_snapshot(&response)?;
    let committed = response.committed_record_count.unwrap_or(0);
    let durable = response.durable_record_count.unwrap_or(0);
    if committed < *previous_committed || durable < *previous_durable {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "post-kill journal watermark regressed",
        ));
    }
    *previous_committed = committed;
    *previous_durable = durable;
    Ok(PostKillSnapshot { committed, durable })
}

fn wait_for_recording(pipe_name: &str, request_id: u64) -> io::Result<DaemonResponseV1> {
    let deadline = Instant::now() + CHILD_STAGE_TIMEOUT;
    while Instant::now() < deadline {
        let request = snapshot_request(request_id)?;
        let response = call_gui_request(pipe_name, &request, request_id)?;
        validate_gui_snapshot(&response)?;
        if response.generated_record_count.unwrap_or(0) > 0
            && response.committed_record_count.unwrap_or(0) > 0
        {
            return Ok(response);
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "independent owner did not make journal progress before qualification",
    ))
}

fn call_gui_request(
    pipe_name: &str,
    request: &[u8],
    request_id: u64,
) -> io::Result<DaemonResponseV1> {
    let response = DaemonResponseV1::decode(&call_secure_pipe_bounded(
        pipe_name,
        request,
        CLIENT_WAIT_TIMEOUT_MS,
        CLIENT_IO_TIMEOUT_MS,
    )?)?;
    if response.request_id != request_id
        || response.epoch != 1
        || response.receipt_hash != sha256(request)
        || !response.authenticated_pipe
        || response.scm_owned
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GUI-pipe response does not match the authenticated request",
        ));
    }
    Ok(response)
}

fn validate_gui_snapshot(response: &DaemonResponseV1) -> io::Result<()> {
    if !response.accepted
        || response.state != RunState::Recording
        || response.poisoned
        || response.active_epoch != Some(1)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GUI snapshot is not a healthy Recording response",
        ));
    }
    Ok(())
}

fn snapshot_request(request_id: u64) -> io::Result<Vec<u8>> {
    forge_protocol_v1::encode_low_speed(
        0,
        request_id,
        1,
        &RunCommandV1 {
            command: RunCommandKind::GetSnapshot.wire_value(),
            scope: 1,
            run_id: [0x51; 16],
            target_device_id: [0x52; 16],
            deadline_global_time_ns: u64::MAX,
            frozen_config_hash: crate::service_protocol::SERVICE_CONTRACT_HASH,
        },
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[allow(clippy::too_many_arguments)] // every value is frozen into the independent owner CLI
fn spawn_owner_child(
    executable: &Path,
    root: &Path,
    gui_pipe_name: &str,
    control_pipe_name: &str,
    run_id_hex: &str,
    supervisor_pid: u32,
    supervisor_creation_time_100ns: u64,
    executable_sha256_hex: &str,
    expected_attempts: u32,
) -> io::Result<ContainedChild> {
    let args = vec![
        OsString::from("gui-kill-owner"),
        OsString::from("--root"),
        utf8_path(root)?.to_owned().into(),
        OsString::from("--gui-pipe"),
        gui_pipe_name.to_owned().into(),
        OsString::from("--control-pipe"),
        control_pipe_name.to_owned().into(),
        OsString::from("--run-id"),
        run_id_hex.to_owned().into(),
        OsString::from("--supervisor-pid"),
        supervisor_pid.to_string().into(),
        OsString::from("--supervisor-creation-time"),
        supervisor_creation_time_100ns.to_string().into(),
        OsString::from("--executable-sha256"),
        executable_sha256_hex.to_owned().into(),
        OsString::from("--expected-attempts"),
        expected_attempts.to_string().into(),
    ];
    spawn_verified_child(executable, executable_sha256_hex, &args)
}

fn spawn_gui_child(
    executable: &Path,
    executable_sha256_hex: &str,
    pipe_name: &str,
    root: &Path,
    stage: &str,
    attempt: u64,
    request_id: u64,
) -> io::Result<ContainedChild> {
    let args = vec![
        OsString::from("gui-kill-client"),
        OsString::from("--pipe"),
        pipe_name.to_owned().into(),
        OsString::from("--root"),
        utf8_path(root)?.to_owned().into(),
        OsString::from("--stage"),
        stage.to_owned().into(),
        OsString::from("--attempt"),
        attempt.to_string().into(),
        OsString::from("--request-id"),
        request_id.to_string().into(),
    ];
    spawn_verified_child(executable, executable_sha256_hex, &args)
}

fn spawn_verified_child(
    executable: &Path,
    expected_sha256_hex: &str,
    args: &[OsString],
) -> io::Result<ContainedChild> {
    let mut proof = lock_qualification_file_proof(executable)?;
    proof.reverify()?;
    if proof.sha256_hex() != expected_sha256_hex {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "qualification executable proof hash differs from the retained receipt hash",
        ));
    }
    let process = ContainedProcess::spawn_verified(&mut proof, args)?;
    process.containment_evidence().validate()?;
    let identity = process.identity();
    if identity.executable_sha256 != proof.sha256_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "contained process identity is not bound to the stable executable proof",
        ));
    }
    Ok(ContainedChild::new(process))
}

fn wait_for_marker_or_child_exit(
    root: &Path,
    marker: &str,
    child: &mut ContainedProcess,
) -> io::Result<()> {
    let path = root.join(marker);
    let deadline = Instant::now() + CHILD_STAGE_TIMEOUT;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        if let Some(status) = child.query_exit_code()? {
            return Err(io::Error::other(format!(
                "GUI child exited before the timing hint {marker}: code {status}"
            )));
        }
        thread::sleep(Duration::from_millis(5));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "GUI child did not reach the timing hint before the hard deadline",
    ))
}

fn wait_for_pipe_creation(pipe_name: &str, owner: &mut ContainedProcess) -> io::Result<()> {
    let wide: Vec<u16> = std::ffi::OsStr::new(pipe_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let deadline = Instant::now() + CHILD_STAGE_TIMEOUT;
    while Instant::now() < deadline {
        if unsafe { WaitNamedPipeW(wide.as_ptr(), 25) } != 0 {
            return Ok(());
        }
        if let Some(status) = owner.query_exit_code()? {
            return Err(io::Error::other(format!(
                "owner exited before binding control pipe: code {status}"
            )));
        }
        thread::sleep(Duration::from_millis(5));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "owner did not bind the control pipe before the hard deadline",
    ))
}

fn park_until_terminated() -> ! {
    loop {
        thread::park_timeout(Duration::from_secs(60));
    }
}

fn write_marker(root: &Path, marker: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(marker))?;
    file.write_all(format!("{marker}\n").as_bytes())?;
    file.sync_all()
}

fn verify_reopened_journal(
    journal_path: &Path,
    run_id: [u8; 16],
    baseline_committed: u64,
) -> io::Result<JournalScan> {
    let scan = scan_journal(journal_path)?;
    let seal = scan
        .seal
        .as_ref()
        .ok_or_else(|| io::Error::other("qualification journal has no seal"))?;
    if scan.identity.run_id != run_id
        || scan.complete_chunks <= baseline_committed
        || scan.complete_chunks == 0
        || scan.complete_chunks != scan.durable.durable_record_count
        || scan.file_len != scan.durable.durable_valid_len
        || scan.last_journal_sequence != seal.expected_last_journal_sequence
        || seal.record_count != scan.complete_chunks
        || scan.content_profile.pods.len() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "qualification journal failed continuity/durability/seal reopen",
        ));
    }
    Ok(scan)
}

fn verify_reopened_ledger(root: &Path, run_id_hex: &str) -> io::Result<DurableRunStatus> {
    let status = DurableRunService::open(root.join("run-ledger"))?.status();
    if status.state != RunState::JournalSealed
        || status.latest_sealed_run_id_hex.as_deref() != Some(run_id_hex)
        || status.ledger_events != 5
        || status.highest_epoch != 1
        || status.active_epoch.is_some()
        || status.active_run_id_hex.is_some()
        || status.latest_published_run_id_hex.is_some()
        || status.auto_failed_on_restart
        || status.poisoned
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "qualification ledger failed JournalSealed reopen",
        ));
    }
    Ok(status)
}

fn journal_evidence(path: &Path, scan: &JournalScan) -> io::Result<GuiKillJournalEvidenceV2> {
    let seal = scan
        .seal
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "journal seal is missing"))?;
    Ok(GuiKillJournalEvidenceV2 {
        path: path.to_string_lossy().into_owned(),
        sha256_hex: sha256_file(path)?,
        bytes: scan.file_len,
        record_count: scan.complete_chunks,
        first_journal_sequence: 0,
        last_journal_sequence: scan.last_journal_sequence.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "journal last sequence is missing",
            )
        })?,
        durable_record_count: scan.durable.durable_record_count,
        durable_valid_len: scan.durable.durable_valid_len,
        seal_expected_last_journal_sequence: seal.expected_last_journal_sequence.ok_or_else(
            || {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "journal seal expected-last sequence is missing",
                )
            },
        )?,
        seal_record_count: seal.record_count,
        pod_count: scan.content_profile.pods.len(),
    })
}

fn validate_options(options: &GuiKillQualificationOptions) -> io::Result<()> {
    if !options.root.is_absolute()
        || !options.receipt_path.is_absolute()
        || !options.executable_path.is_absolute()
        || !(2..=1_000).contains(&options.kill_count)
        || !options.kill_count.is_multiple_of(2)
        || options.root.exists()
        || options.receipt_path.exists()
        || options.receipt_path.with_extension("pending").exists()
        || !options.executable_path.is_file()
        || options.root.parent().is_none_or(|parent| !parent.is_dir())
        || options
            .receipt_path
            .parent()
            .is_none_or(|parent| !parent.is_dir())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "GUI-kill qualification requires new absolute root/receipt paths, an existing absolute executable, and an even 2..=1000 kill count",
        ));
    }
    Ok(())
}

fn fresh_pipe_names() -> io::Result<(String, String)> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before the Unix epoch"))?
        .as_nanos();
    let base = format!(
        r"\\.\pipe\forge-acqd-gui-kill-v3-{}-{stamp}",
        std::process::id()
    );
    Ok((format!("{base}-gui"), format!("{base}-control")))
}

fn fresh_run_id(root: &Path) -> io::Result<[u8; 16]> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before the Unix epoch"))?
        .as_nanos();
    let mut source = root.to_string_lossy().as_bytes().to_vec();
    source.extend_from_slice(&std::process::id().to_le_bytes());
    source.extend_from_slice(&stamp.to_le_bytes());
    let hash = sha256(&source);
    let mut run_id = [0_u8; 16];
    run_id.copy_from_slice(&hash[..16]);
    if run_id == [0; 16] {
        return Err(io::Error::other("derived an all-zero qualification Run ID"));
    }
    Ok(run_id)
}

fn attempt_request_id(attempt: u32) -> io::Result<u64> {
    FIRST_ATTEMPT_REQUEST_ID
        .checked_add(u64::from(attempt) * 3)
        .ok_or_else(|| io::Error::other("attempt request ID overflow"))
}

fn retain_qualified_executable(root: &Path, source: &Path) -> io::Result<(PathBuf, String)> {
    let destination = root.join("qualified-forge-acqd.exe");
    let mut source_proof = lock_qualification_file_proof(source)?;
    source_proof.reverify()?;
    let source_hash = source_proof.sha256_hex().to_owned();
    let source_identity = source_proof.identity().clone();
    let artifact = copy_new_durable_from_proof(&mut source_proof, &destination)?;
    if artifact.destination_identity().bytes != source_identity.bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "retained executable size does not match the stable source proof",
        ));
    }
    drop(artifact);
    // Bind the receipt hash to a fresh handle-derived destination object
    // before any spawn; CREATE_NEW above prevents an existing destination.
    let mut destination_proof = lock_qualification_file_proof(&destination)?;
    destination_proof.reverify()?;
    if destination_proof.sha256_hex() != source_hash || destination_proof.identity().link_count != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "retained executable destination proof is not the copied single-link object",
        ));
    }
    Ok((destination, source_hash))
}

fn current_process_creation_time_100ns() -> io::Result<u64> {
    let handle = unsafe {
        windows_sys::Win32::System::Threading::OpenProcess(
            windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            std::process::id(),
        )
    };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    let result = process_creation_time_from_handle(handle);
    unsafe { CloseHandle(handle) };
    result
}

fn process_creation_time_from_handle(handle: HANDLE) -> io::Result<u64> {
    let mut creation: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
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

fn combine_errors(context: &str, primary: io::Error, cleanup: io::Result<()>) -> io::Error {
    match cleanup {
        Ok(()) => io::Error::new(primary.kind(), format!("{context}: {primary}")),
        Err(cleanup_error) => io::Error::other(format!(
            "{context}: {primary}; bounded cleanup also failed: {cleanup_error}"
        )),
    }
}

fn persist_receipt(path: &Path, receipt: &GuiKillQualificationReceiptV3) -> io::Result<()> {
    let pending = path.with_extension("pending");
    if path.exists() || pending.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "GUI-kill receipt or pending path already exists",
        ));
    }
    let bytes = serde_json::to_vec_pretty(receipt).map_err(json_error)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(pending, path)
}

pub fn receipt_evidence_hash(receipt: &GuiKillQualificationReceiptV3) -> io::Result<String> {
    let mut normalized = receipt.clone();
    normalized.evidence_sha256_hex.clear();
    Ok(hex(&sha256(
        &serde_json::to_vec(&normalized).map_err(json_error)?,
    )))
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

fn decode_hex_into(value: &str, output: &mut [u8]) -> io::Result<()> {
    if value.len() != output.len() * 2 || !value.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hex value has the wrong length",
        ));
    }
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "hex value is not canonical")
        })?;
    }
    if hex(output) != value {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hex value is not lowercase canonical encoding",
        ));
    }
    Ok(())
}

fn is_hex_len(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn utf8_path(path: &Path) -> io::Result<&str> {
    path.to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not UTF-8"))
}

fn json_error(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
