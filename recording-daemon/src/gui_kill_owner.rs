//! Isolated owner process for the private GUI-loss qualification harness.
//!
//! This module intentionally owns the replay dispatcher, journal/ledger and
//! audit writer.  The supervisor has no write handle for any of those objects.

#![cfg(windows)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use forge_protocol_v1::{
    decode_low_speed, encode_low_speed, sha256, MessageKind, RunCommandV1, WireBody,
};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, HANDLE, STILL_ACTIVE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess, WaitForSingleObject,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::gui_kill_audit::{
    GuiKillAuditAttemptModeV2, GuiKillAuditEventDataV2, GuiKillAuditIdentityV2,
    GuiKillAuditKillMethodV2, GuiKillAuditKindV2, GuiKillAuditWaitResultV2, GuiKillAuditWriterV2,
};
use crate::gui_kill_control::{
    decode_request, encode_response, GuiKillAttemptModeV1, GuiKillContainmentEvidenceV2,
    GuiKillControlCommandV1, GuiKillControlRequestV1, GuiKillControlResponseV1,
    GuiKillControlSequenceV1, GuiKillReapEvidenceV2, GuiKillWaitMethodV2, GuiKillWaitResultV2,
};
use crate::ipc::{
    current_process_user_sid, AuthenticatedPipeClient, CompletedTransactionObservation,
    PendingIoObservation, PendingIoStage, SecurePipeOptions, SecurePipeServer,
};
use crate::run::{RunCommandKind, RunState};
use crate::service_protocol::{DaemonResponseV1, ServiceDispatcher};

const FACT_TIMEOUT: Duration = Duration::from_secs(3);
const LISTENER_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const REAP_PROOF_DEADLINE_MS: u32 = 250;

#[derive(Clone, Debug)]
pub(crate) struct GuiKillOwnerOptions {
    pub root: PathBuf,
    pub gui_pipe_name: String,
    pub control_pipe_name: String,
    pub run_id: [u8; 16],
    pub supervisor_pid: u32,
    pub supervisor_creation_time_100ns: u64,
    pub owner_executable_sha256_hex: String,
    pub expected_attempts: u32,
}

struct OwnedProcess(HANDLE);
// A Windows process HANDLE is an owned kernel-object reference whose wait and
// query operations are thread-safe. Ownership remains unique and Drop closes
// it exactly once after the mutex-protected attempt is removed.
unsafe impl Send for OwnedProcess {}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

#[derive(Clone)]
struct GuiFact {
    response: DaemonResponseV1,
    request_bytes: Vec<u8>,
    response_bytes: Vec<u8>,
    handled: bool,
    completed: bool,
}

struct Attempt {
    mode: GuiKillAttemptModeV1,
    gui_pid: u32,
    gui_creation: u64,
    request_id: u64,
    barrier_request_id: Option<u64>,
    post_kill_request_id: u64,
    process: OwnedProcess,
    stage_observed: bool,
    killed: bool,
    reaped: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Lifecycle {
    New,
    Prepared,
    Armed,
    Recording,
    Sealed,
    ExitArmed,
}

struct OwnerState {
    options: GuiKillOwnerOptions,
    owner_pid: u32,
    owner_creation: u64,
    executable_hash: String,
    dispatcher: ServiceDispatcher,
    audit: Option<GuiKillAuditWriterV2>,
    audit_next: u64,
    sequence: GuiKillControlSequenceV1,
    lifecycle: Lifecycle,
    baseline: Option<DaemonResponseV1>,
    facts: BTreeMap<(u32, u64, u64), GuiFact>,
    pending: BTreeSet<(u32, u64)>,
    attempt: Option<Attempt>,
    completed_attempts: u32,
    exit_completion: bool,
}

pub(crate) fn run_gui_kill_owner_v3(options: GuiKillOwnerOptions) -> io::Result<()> {
    validate_options(&options)?;
    let executable_hash = sha256_current_exe()?;
    if executable_hash != options.owner_executable_sha256_hex {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner executable hash drifted",
        ));
    }
    let owner_pid = std::process::id();
    let owner_creation = current_process_creation_time()?;
    let identity = GuiKillAuditIdentityV2 {
        run_id_hex: hex(&options.run_id),
        supervisor_pid: options.supervisor_pid,
        supervisor_creation_time_100ns: options.supervisor_creation_time_100ns,
        owner_pid,
        owner_creation_time_100ns: owner_creation,
    };
    let mut audit =
        GuiKillAuditWriterV2::create(&options.root.join("gui-kill-audit-v3.jsonl"), identity)?;
    audit.append(GuiKillAuditEventDataV2::static_event(
        GuiKillAuditKindV2::AuditStarted,
    ))?;
    audit.append(GuiKillAuditEventDataV2::static_event(
        GuiKillAuditKindV2::OwnerReady,
    ))?;
    let audit_next = 2;
    let dispatcher = ServiceDispatcher::open_protected_replay(
        options.root.join("run-ledger"),
        &options.root,
        true,
        false,
    )?;
    let sid = current_process_user_sid()?;
    let mut gui_server = SecurePipeServer::bind_scm_emulation(&SecurePipeOptions {
        pipe_name: options.gui_pipe_name.clone(),
        service_sid: sid.clone(),
        allowed_client_sid: sid.clone(),
    })?;
    let mut control_server = SecurePipeServer::bind_scm_emulation(&SecurePipeOptions {
        pipe_name: options.control_pipe_name.clone(),
        service_sid: sid.clone(),
        allowed_client_sid: sid,
    })?;
    let gui_completions = gui_server.install_completion_observer();
    let gui_pending = gui_server.install_pending_observation_observer();
    let control_completions = control_server.install_completion_observer();
    let gui_stop = gui_server.stop_handle();
    let control_stop = control_server.stop_handle();
    let state = Arc::new(Mutex::new(OwnerState {
        options,
        owner_pid,
        owner_creation,
        executable_hash,
        dispatcher,
        audit: Some(audit),
        audit_next,
        sequence: GuiKillControlSequenceV1::default(),
        lifecycle: Lifecycle::New,
        baseline: None,
        facts: BTreeMap::new(),
        pending: BTreeSet::new(),
        attempt: None,
        completed_attempts: 0,
        exit_completion: false,
    }));
    let gui_facts = Arc::clone(&state);
    let gui_listener = spawn_listener(gui_server, move |client, request| {
        gui_request(&gui_facts, client, request)
    })?;
    let control_facts = Arc::clone(&state);
    let control_listener = spawn_listener(control_server, move |client, request| {
        control_request(&control_facts, client, request)
    })?;
    let _observers = spawn_observers(
        state.clone(),
        gui_completions,
        gui_pending,
        control_completions,
    )?;

    loop {
        if let Some(outcome) = listener_finished_early(&gui_listener, "GUI")?
            .or(listener_finished_early(&control_listener, "control")?)
        {
            let _ = gui_stop.request_stop();
            let _ = control_stop.request_stop();
            return Err(outcome);
        }
        if state
            .lock()
            .map_err(|_| io::Error::other("owner state mutex poisoned"))?
            .exit_completion
        {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    gui_stop.request_stop()?;
    control_stop.request_stop()?;
    stop_listener(gui_listener)?;
    stop_listener(control_listener)?;
    Ok(())
}

fn spawn_listener<F>(
    mut server: SecurePipeServer,
    mut handler: F,
) -> io::Result<mpsc::Receiver<io::Result<u64>>>
where
    F: FnMut(&AuthenticatedPipeClient, &[u8]) -> io::Result<Vec<u8>> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("forge-gui-kill-owner-pipe".to_owned())
        .spawn(move || {
            let _ = tx.send(
                server.run_until_stopped_authenticated(|client, request| handler(client, request)),
            );
        })?;
    Ok(rx)
}

fn stop_listener(rx: mpsc::Receiver<io::Result<u64>>) -> io::Result<()> {
    rx.recv_timeout(LISTENER_STOP_TIMEOUT).map_err(|error| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("owner listener did not terminate: {error}"),
        )
    })??;
    Ok(())
}

fn listener_finished_early(
    rx: &mpsc::Receiver<io::Result<u64>>,
    name: &str,
) -> io::Result<Option<io::Error>> {
    match rx.try_recv() {
        Ok(Ok(_)) => Ok(Some(io::Error::other(format!(
            "{name} owner listener stopped before Exit FACK"
        )))),
        Ok(Err(error)) => Ok(Some(io::Error::new(
            error.kind(),
            format!("{name} owner listener failed before Exit FACK: {error}"),
        ))),
        Err(mpsc::TryRecvError::Empty) => Ok(None),
        Err(mpsc::TryRecvError::Disconnected) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("{name} owner listener completion channel disconnected"),
        )),
    }
}

fn spawn_observers(
    state: Arc<Mutex<OwnerState>>,
    gui_completions: mpsc::Receiver<CompletedTransactionObservation>,
    gui_pending: mpsc::Receiver<PendingIoObservation>,
    control_completions: mpsc::Receiver<CompletedTransactionObservation>,
) -> io::Result<Vec<thread::JoinHandle<()>>> {
    let completed_state = Arc::clone(&state);
    let completed = thread::Builder::new()
        .name("forge-gui-kill-owner-gui-completion".to_owned())
        .spawn(move || {
            while let Ok(observation) = gui_completions.recv() {
                if let Ok(mut state) = completed_state.lock() {
                    if let Ok(request_id) = request_id(&observation.request) {
                        if let Some(fact) = state.facts.get_mut(&(
                            observation.client.process_id,
                            observation.client.process_creation_time_100ns,
                            request_id,
                        )) {
                            if fact.request_bytes == observation.request
                                && fact.response_bytes == observation.response
                            {
                                fact.completed = true;
                            }
                        }
                    }
                }
            }
        })?;
    let pending_state = Arc::clone(&state);
    let pending = thread::Builder::new()
        .name("forge-gui-kill-owner-pending".to_owned())
        .spawn(move || {
            while let Ok(observation) = gui_pending.recv() {
                if observation.stage == PendingIoStage::AckRead {
                    if let Some(pid) = observation.client_process_id {
                        if let Ok(mut state) = pending_state.lock() {
                            let pending = state
                                .facts
                                .iter()
                                .filter_map(|((fact_pid, creation, _), fact)| {
                                    if *fact_pid == pid && fact.handled && !fact.completed {
                                        Some((pid, *creation))
                                    } else {
                                        None
                                    }
                                })
                                .collect::<Vec<_>>();
                            state.pending.extend(pending);
                        }
                    }
                }
            }
        })?;
    let control_state = Arc::clone(&state);
    let control = thread::Builder::new()
        .name("forge-gui-kill-owner-control-completion".to_owned())
        .spawn(move || {
            while let Ok(observation) = control_completions.recv() {
                if let Ok(mut state) = control_state.lock() {
                    if observation.client.process_id == state.options.supervisor_pid
                        && observation.client.process_creation_time_100ns
                            == state.options.supervisor_creation_time_100ns
                        && decode_request(&observation.request)
                            .ok()
                            .is_some_and(|request| {
                                matches!(request.command, GuiKillControlCommandV1::Exit)
                            })
                    {
                        state.exit_completion = true;
                    }
                }
            }
        })?;
    Ok(vec![completed, pending, control])
}

fn gui_request(
    state: &Arc<Mutex<OwnerState>>,
    client: &AuthenticatedPipeClient,
    request: &[u8],
) -> io::Result<Vec<u8>> {
    let decoded = decode_low_speed(request).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "GUI request is not canonical low-speed",
        )
    })?;
    if decoded.kind != MessageKind::RunCommand {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GUI request kind is forbidden",
        ));
    }
    let command = RunCommandV1::decode_body(&decoded.body)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "GUI RunCommand body invalid"))?;
    if decoded.epoch != 1
        || RunCommandKind::from_wire(command.command)? != RunCommandKind::GetSnapshot
        || command.scope != 1
        || command.run_id != [0x51; 16]
        || command.target_device_id != [0x52; 16]
        || command.frozen_config_hash != crate::service_protocol::SERVICE_CONTRACT_HASH
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "GUI may only request snapshot",
        ));
    }
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("owner state mutex poisoned"))?;
    let response_bytes = state.dispatcher.handle(request)?;
    let response = DaemonResponseV1::decode(&response_bytes)?;
    state.facts.insert(
        (
            client.process_id,
            client.process_creation_time_100ns,
            decoded.request_id,
        ),
        GuiFact {
            response,
            request_bytes: request.to_vec(),
            response_bytes: response_bytes.clone(),
            handled: true,
            completed: false,
        },
    );
    Ok(response_bytes)
}

fn control_request(
    state: &Arc<Mutex<OwnerState>>,
    client: &AuthenticatedPipeClient,
    bytes: &[u8],
) -> io::Result<Vec<u8>> {
    let request = decode_request(bytes)?;
    {
        let mut state = state
            .lock()
            .map_err(|_| io::Error::other("owner state mutex poisoned"))?;
        if client.process_id != state.options.supervisor_pid
            || client.process_creation_time_100ns != state.options.supervisor_creation_time_100ns
            || request.supervisor_pid != client.process_id
            || request.supervisor_creation_time_100ns != client.process_creation_time_100ns
            || request.run_id_hex != hex(&state.options.run_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "control supervisor identity mismatch",
            ));
        }
        state.sequence.observe(&request)?;
        if request.command_sequence == 1
            && !matches!(request.command, GuiKillControlCommandV1::QueryReady)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "first control command must be QueryReady",
            ));
        }
    }
    wait_for_control_fact(state, &request)?;
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("owner state mutex poisoned"))?;
    apply_control(&mut state, request.clone())?;
    control_response(&state, request.command_sequence)
}

/// Control messages are sequenced by the authenticated supervisor, but GUI
/// FACK/PendingIo facts arrive through independent server threads.  Never
/// hold the owner state lock while waiting: doing so would prevent the
/// observers from establishing the very fact required to authorize a kill.
fn wait_for_control_fact(
    state: &Arc<Mutex<OwnerState>>,
    request: &GuiKillControlRequestV1,
) -> io::Result<()> {
    let (attempt, snapshot_request) = match &request.command {
        GuiKillControlCommandV1::StageObserved { attempt } => (Some(*attempt), None),
        GuiKillControlCommandV1::BaselineSnapshot { request_id } => (None, Some(*request_id)),
        GuiKillControlCommandV1::CompleteAttempt { .. } => {
            let post = state
                .lock()
                .map_err(|_| io::Error::other("owner state mutex poisoned"))?
                .attempt
                .as_ref()
                .ok_or_else(|| io::Error::other("owner has no active attempt"))?
                .post_kill_request_id;
            (None, Some(post))
        }
        _ => return Ok(()),
    };
    let deadline = Instant::now() + FACT_TIMEOUT;
    loop {
        let ready = {
            let state = state
                .lock()
                .map_err(|_| io::Error::other("owner state mutex poisoned"))?;
            if let Some(attempt) = attempt {
                stage_ready(&state, attempt)?
            } else {
                let request_id = snapshot_request.expect("snapshot request set");
                state
                    .facts
                    .get(&(
                        state.options.supervisor_pid,
                        state.options.supervisor_creation_time_100ns,
                        request_id,
                    ))
                    .is_some_and(|fact| fact.completed)
            }
        };
        if ready {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owner did not observe required GUI FACK/PendingIo stage",
            ));
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn apply_control(state: &mut OwnerState, request: GuiKillControlRequestV1) -> io::Result<()> {
    match request.command {
        GuiKillControlCommandV1::QueryReady => {
            if state.lifecycle != Lifecycle::New {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "QueryReady is only valid at owner start",
                ));
            }
        }
        GuiKillControlCommandV1::Lifecycle {
            request_id,
            command_wire,
        } => lifecycle(
            state,
            request_id,
            RunCommandKind::from_wire(u16::from(command_wire))?,
        )?,
        GuiKillControlCommandV1::BaselineSnapshot { request_id } => baseline(state, request_id)?,
        GuiKillControlCommandV1::AttemptStarted {
            attempt,
            mode,
            gui_pid,
            gui_creation_time_100ns,
            request_id,
            barrier_request_id,
            post_kill_request_id,
            containment,
        } => attempt_started(
            state,
            attempt,
            mode,
            gui_pid,
            gui_creation_time_100ns,
            request_id,
            barrier_request_id,
            post_kill_request_id,
            containment,
        )?,
        GuiKillControlCommandV1::StageObserved { attempt } => stage_observed(state, attempt)?,
        GuiKillControlCommandV1::KillRequested { attempt } => kill_requested(state, attempt)?,
        GuiKillControlCommandV1::ReapProven { attempt, evidence } => {
            reap_proven(state, attempt, evidence)?
        }
        GuiKillControlCommandV1::CompleteAttempt { attempt } => complete_attempt(state, attempt)?,
        GuiKillControlCommandV1::Exit => exit(state)?,
    }
    Ok(())
}

fn lifecycle(state: &mut OwnerState, request_id: u64, kind: RunCommandKind) -> io::Result<()> {
    let (expected_before, expected_after, audit_kind) = match kind {
        RunCommandKind::Prepare => (
            Lifecycle::New,
            Lifecycle::Prepared,
            GuiKillAuditKindV2::LifecyclePrepare,
        ),
        RunCommandKind::Arm => (
            Lifecycle::Prepared,
            Lifecycle::Armed,
            GuiKillAuditKindV2::LifecycleArm,
        ),
        RunCommandKind::Start => (
            Lifecycle::Armed,
            Lifecycle::Recording,
            GuiKillAuditKindV2::LifecycleStart,
        ),
        RunCommandKind::Stop => (
            Lifecycle::Recording,
            Lifecycle::Sealed,
            GuiKillAuditKindV2::SupervisorStop,
        ),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "forbidden owner lifecycle command",
            ))
        }
    };
    if state.lifecycle != expected_before
        || (kind == RunCommandKind::Stop
            && state.completed_attempts != state.options.expected_attempts)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner lifecycle order is invalid",
        ));
    }
    let request = encode_low_speed(
        0,
        request_id,
        1,
        &RunCommandV1 {
            command: kind.wire_value(),
            scope: 1,
            run_id: state.options.run_id,
            target_device_id: [0x71; 16],
            deadline_global_time_ns: u64::MAX,
            frozen_config_hash: sha256(b"forge-gui-kill-owner-v2"),
        },
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let response = DaemonResponseV1::decode(&state.dispatcher.handle(&request)?)?;
    let expected_state = match kind {
        RunCommandKind::Prepare => RunState::Prepared,
        RunCommandKind::Arm => RunState::Armed,
        RunCommandKind::Start => RunState::Recording,
        RunCommandKind::Stop => RunState::JournalSealed,
        _ => unreachable!(),
    };
    if !response.accepted
        || response.state != expected_state
        || response.poisoned
        || response.scm_owned
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner dispatcher lifecycle response invalid",
        ));
    }
    let mut data = GuiKillAuditEventDataV2::static_event(audit_kind);
    data.request_id = Some(request_id);
    append_audit(state, data)?;
    if kind == RunCommandKind::Stop {
        append_audit(
            state,
            GuiKillAuditEventDataV2::static_event(GuiKillAuditKindV2::OwnerSealed),
        )?;
    }
    state.lifecycle = expected_after;
    Ok(())
}

fn baseline(state: &mut OwnerState, request_id: u64) -> io::Result<()> {
    if state.lifecycle != Lifecycle::Recording || state.baseline.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "baseline state invalid",
        ));
    }
    let response = wait_completed_snapshot(
        state,
        state.options.supervisor_pid,
        state.options.supervisor_creation_time_100ns,
        request_id,
    )?;
    validate_recording_snapshot(&response, None)?;
    let mut data = GuiKillAuditEventDataV2::static_event(GuiKillAuditKindV2::BaselineSnapshot);
    data.request_id = Some(request_id);
    snapshot_fields(&mut data, &response)?;
    append_audit(state, data)?;
    state.baseline = Some(response);
    Ok(())
}

#[allow(clippy::too_many_arguments)] // mirrors the frozen AttemptStarted control payload
fn attempt_started(
    state: &mut OwnerState,
    attempt: u32,
    mode: GuiKillAttemptModeV1,
    gui_pid: u32,
    gui_creation: u64,
    request_id: u64,
    barrier: Option<u64>,
    post: u64,
    containment: GuiKillContainmentEvidenceV2,
) -> io::Result<()> {
    if state.lifecycle != Lifecycle::Recording
        || state.baseline.is_none()
        || state.attempt.is_some()
        || attempt != state.completed_attempts
        || attempt >= state.options.expected_attempts
        || attempt.is_multiple_of(2) != (mode == GuiKillAttemptModeV1::AfterAck)
        || request_id != 10_000 + u64::from(attempt) * 3
        || post != request_id + 2
        || (mode == GuiKillAttemptModeV1::AfterAck && barrier != Some(request_id + 1))
        || (mode == GuiKillAttemptModeV1::Inflight && barrier.is_some())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "attempt start contract invalid",
        ));
    }
    containment.validate()?;
    let process = open_verified_process(gui_pid, gui_creation)?;
    let data = attempt_data(
        GuiKillAuditKindV2::GuiSpawned,
        attempt,
        mode,
        gui_pid,
        gui_creation,
        request_id,
        barrier,
        post,
    );
    let mut data = data;
    data.containment = Some(containment);
    append_audit(state, data)?;
    state.attempt = Some(Attempt {
        mode,
        gui_pid,
        gui_creation,
        request_id,
        barrier_request_id: barrier,
        post_kill_request_id: post,
        process,
        stage_observed: false,
        killed: false,
        reaped: false,
    });
    Ok(())
}

fn stage_observed(state: &mut OwnerState, attempt: u32) -> io::Result<()> {
    let (mode, pid, creation, request, barrier, post) = attempt_values(state, attempt)?;
    if !stage_ready(state, attempt)? {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "owner did not observe required GUI stage",
        ));
    }
    let data = attempt_data(
        GuiKillAuditKindV2::StageConfirmed,
        attempt,
        mode,
        pid,
        creation,
        request,
        barrier,
        post,
    );
    append_audit(state, data)?;
    state
        .attempt
        .as_mut()
        .ok_or_else(|| io::Error::other("missing attempt"))?
        .stage_observed = true;
    Ok(())
}

fn stage_ready(state: &OwnerState, attempt: u32) -> io::Result<bool> {
    let (mode, pid, creation, request, barrier, _) = attempt_values(state, attempt)?;
    Ok(match mode {
        GuiKillAttemptModeV1::AfterAck => {
            state
                .facts
                .get(&(pid, creation, request))
                .is_some_and(|fact| fact.completed)
                && barrier.is_some_and(|id| {
                    state
                        .facts
                        .get(&(pid, creation, id))
                        .is_some_and(|fact| fact.completed)
                })
        }
        GuiKillAttemptModeV1::Inflight => {
            state
                .facts
                .get(&(pid, creation, request))
                .is_some_and(|fact| fact.handled && !fact.completed)
                && state.pending.contains(&(pid, creation))
        }
    })
}

fn kill_requested(state: &mut OwnerState, attempt: u32) -> io::Result<()> {
    let (mode, pid, creation, request, barrier, post) = attempt_values(state, attempt)?;
    if !state
        .attempt
        .as_ref()
        .is_some_and(|value| value.stage_observed && !value.killed)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kill not stage-gated",
        ));
    }
    append_audit(
        state,
        attempt_data(
            GuiKillAuditKindV2::KillRequested,
            attempt,
            mode,
            pid,
            creation,
            request,
            barrier,
            post,
        ),
    )?;
    state.attempt.as_mut().unwrap().killed = true;
    Ok(())
}

fn reap_proven(
    state: &mut OwnerState,
    attempt: u32,
    evidence: GuiKillReapEvidenceV2,
) -> io::Result<()> {
    let (mode, pid, creation, request, barrier, post) = attempt_values(state, attempt)?;
    let attempt_state = state
        .attempt
        .as_ref()
        .ok_or_else(|| io::Error::other("missing attempt"))?;
    if !attempt_state.killed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner cannot prove GUI reap before kill request",
        ));
    }
    if evidence.method != GuiKillWaitMethodV2::JobObjectTermination
        || evidence.wait_result != GuiKillWaitResultV2::SignaledReaped
        || evidence.wait_deadline_ms == 0
        || evidence.wait_elapsed_ms > evidence.wait_deadline_ms
        || evidence.job_active_processes_after_wait != 0
        || !evidence.job_empty_proven
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "supervisor reap evidence is not a signaled empty Job proof",
        ));
    }
    let wait_started = Instant::now();
    let wait = unsafe { WaitForSingleObject(attempt_state.process.0, REAP_PROOF_DEADLINE_MS) };
    let wait_elapsed_ms = u32::try_from(wait_started.elapsed().as_millis()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "owner reap wait elapsed duration exceeds audit representation",
        )
    })?;
    match wait {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owner bounded GUI reap wait timed out",
            ))
        }
        WAIT_FAILED => return Err(io::Error::last_os_error()),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "owner GUI reap wait returned an unexpected result",
            ))
        }
    }
    if wait_elapsed_ms > REAP_PROOF_DEADLINE_MS {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "owner GUI reap completed after its declared deadline",
        ));
    }
    let mut code = 0_u32;
    if unsafe { GetExitCodeProcess(attempt_state.process.0, &mut code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if code == STILL_ACTIVE as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner observed a signaled GUI handle but exit code remains STILL_ACTIVE",
        ));
    }
    if code != evidence.exit_code {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "supervisor/owner primary process exit codes differ",
        ));
    }
    let mut data = attempt_data(
        GuiKillAuditKindV2::ReapProven,
        attempt,
        mode,
        pid,
        creation,
        request,
        barrier,
        post,
    );
    data.exit_code = Some(evidence.exit_code);
    data.kill_method = Some(match evidence.method {
        GuiKillWaitMethodV2::JobObjectTermination => GuiKillAuditKillMethodV2::JobObjectTermination,
        GuiKillWaitMethodV2::GracefulWait => unreachable!("validated above"),
    });
    data.wait_deadline_ms = Some(evidence.wait_deadline_ms);
    data.wait_elapsed_ms = Some(evidence.wait_elapsed_ms);
    data.wait_result = Some(match evidence.wait_result {
        GuiKillWaitResultV2::SignaledReaped => GuiKillAuditWaitResultV2::SignaledReaped,
    });
    data.job_active_processes_after_wait = Some(evidence.job_active_processes_after_wait);
    data.job_empty_proven = Some(evidence.job_empty_proven);
    append_audit(state, data)?;
    state
        .attempt
        .as_mut()
        .ok_or_else(|| io::Error::other("owner lost active attempt before reap state update"))?
        .reaped = true;
    Ok(())
}

fn complete_attempt(state: &mut OwnerState, attempt: u32) -> io::Result<()> {
    let (mode, pid, creation, request, barrier, post) = attempt_values(state, attempt)?;
    if !state.attempt.as_ref().is_some_and(|value| value.reaped) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "complete attempt requires proven reap",
        ));
    }
    let response = wait_completed_snapshot(
        state,
        state.options.supervisor_pid,
        state.options.supervisor_creation_time_100ns,
        post,
    )?;
    let baseline = state
        .baseline
        .as_ref()
        .ok_or_else(|| io::Error::other("missing baseline"))?;
    validate_recording_snapshot(&response, Some(baseline))?;
    let mut data = attempt_data(
        GuiKillAuditKindV2::PostKillSnapshot,
        attempt,
        mode,
        pid,
        creation,
        request,
        barrier,
        post,
    );
    snapshot_fields(&mut data, &response)?;
    append_audit(state, data)?;
    state.baseline = Some(response);
    state.attempt.take();
    state.completed_attempts += 1;
    Ok(())
}

fn exit(state: &mut OwnerState) -> io::Result<()> {
    if state.lifecycle != Lifecycle::Sealed
        || state.completed_attempts != state.options.expected_attempts
        || state.attempt.is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner cannot exit before seal and attempts",
        ));
    }
    let audit = state
        .audit
        .take()
        .ok_or_else(|| io::Error::other("audit already finished"))?;
    let evidence = audit.finish()?;
    state.audit_next = evidence.event_count;
    state.lifecycle = Lifecycle::ExitArmed;
    Ok(())
}

fn wait_completed_snapshot(
    state: &OwnerState,
    pid: u32,
    creation: u64,
    request_id: u64,
) -> io::Result<DaemonResponseV1> {
    let fact = state
        .facts
        .get(&(pid, creation, request_id))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "required GUI snapshot has not been handled",
            )
        })?;
    if !fact.completed {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "required GUI snapshot FACK has not completed",
        ));
    }
    Ok(fact.response.clone())
}

fn validate_recording_snapshot(
    response: &DaemonResponseV1,
    baseline: Option<&DaemonResponseV1>,
) -> io::Result<()> {
    if !response.accepted
        || response.state != RunState::Recording
        || response.poisoned
        || response.scm_owned
        || response.active_epoch != Some(1)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot does not prove protected replay Recording",
        ));
    }
    if let Some(previous) = baseline {
        if response.committed_record_count.unwrap_or(0)
            < previous.committed_record_count.unwrap_or(0)
            || response.durable_record_count.unwrap_or(0)
                < previous.durable_record_count.unwrap_or(0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot watermark regressed",
            ));
        }
    }
    Ok(())
}

fn snapshot_fields(
    data: &mut GuiKillAuditEventDataV2,
    response: &DaemonResponseV1,
) -> io::Result<()> {
    data.state_wire = Some(response.state.wire_value());
    data.active_epoch = response.active_epoch;
    data.committed_record_count = response.committed_record_count;
    data.durable_record_count = response.durable_record_count;
    if data.active_epoch.is_none()
        || data.committed_record_count.is_none()
        || data.durable_record_count.is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot lacks required owner watermarks",
        ));
    }
    Ok(())
}

fn attempt_values(
    state: &OwnerState,
    attempt: u32,
) -> io::Result<(GuiKillAttemptModeV1, u32, u64, u64, Option<u64>, u64)> {
    let value = state
        .attempt
        .as_ref()
        .ok_or_else(|| io::Error::other("owner has no active attempt"))?;
    if attempt != state.completed_attempts {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "attempt index does not match owner state",
        ));
    }
    Ok((
        value.mode,
        value.gui_pid,
        value.gui_creation,
        value.request_id,
        value.barrier_request_id,
        value.post_kill_request_id,
    ))
}

#[allow(clippy::too_many_arguments)] // one audit context is repeated byte-for-byte across five phases
fn attempt_data(
    kind: GuiKillAuditKindV2,
    attempt: u32,
    mode: GuiKillAttemptModeV1,
    gui_pid: u32,
    gui_creation: u64,
    request: u64,
    barrier: Option<u64>,
    post: u64,
) -> GuiKillAuditEventDataV2 {
    GuiKillAuditEventDataV2 {
        kind,
        attempt: Some(attempt),
        mode: Some(match mode {
            GuiKillAttemptModeV1::AfterAck => GuiKillAuditAttemptModeV2::AfterAck,
            GuiKillAttemptModeV1::Inflight => GuiKillAuditAttemptModeV2::Inflight,
        }),
        gui_pid: Some(gui_pid),
        gui_creation_time_100ns: Some(gui_creation),
        request_id: Some(request),
        barrier_request_id: barrier,
        post_kill_request_id: Some(post),
        state_wire: None,
        active_epoch: None,
        committed_record_count: None,
        durable_record_count: None,
        exit_code: None,
        kill_method: None,
        wait_deadline_ms: None,
        wait_elapsed_ms: None,
        wait_result: None,
        containment: None,
        job_active_processes_after_wait: None,
        job_empty_proven: None,
    }
}

fn append_audit(state: &mut OwnerState, data: GuiKillAuditEventDataV2) -> io::Result<()> {
    let sequence = state
        .audit
        .as_mut()
        .ok_or_else(|| io::Error::other("owner audit was already finalized"))?
        .append(data)?;
    state.audit_next = sequence
        .checked_add(1)
        .ok_or_else(|| io::Error::other("audit sequence overflow"))?;
    Ok(())
}

fn control_response(state: &OwnerState, command_sequence: u64) -> io::Result<Vec<u8>> {
    let status = state.dispatcher.status();
    encode_response(&GuiKillControlResponseV1 {
        schema: crate::gui_kill_control::GUI_KILL_CONTROL_RESPONSE_SCHEMA.to_owned(),
        command_sequence,
        run_id_hex: hex(&state.options.run_id),
        accepted: true,
        error_code: "none".to_owned(),
        owner_pid: state.owner_pid,
        owner_creation_time_100ns: state.owner_creation,
        owner_executable_sha256_hex: state.executable_hash.clone(),
        gui_pipe_name: state.options.gui_pipe_name.clone(),
        control_pipe_name: state.options.control_pipe_name.clone(),
        supervisor_pid: state.options.supervisor_pid,
        supervisor_creation_time_100ns: state.options.supervisor_creation_time_100ns,
        state_wire: status.state.wire_value(),
        active_epoch: status.active_epoch,
        committed_record_count: state
            .baseline
            .as_ref()
            .and_then(|response| response.committed_record_count)
            .unwrap_or(0),
        durable_record_count: state
            .baseline
            .as_ref()
            .and_then(|response| response.durable_record_count)
            .unwrap_or(0),
        audit_event_sequence: state.audit_next,
    })
}

fn request_id(bytes: &[u8]) -> io::Result<u64> {
    Ok(decode_low_speed(bytes)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "completion request is not low-speed",
            )
        })?
        .request_id)
}

fn open_verified_process(pid: u32, expected_creation: u64) -> io::Result<OwnedProcess> {
    let handle = unsafe { OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    let owned = OwnedProcess(handle);
    if process_creation_time(handle)? != expected_creation {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GUI PID creation time mismatch",
        ));
    }
    Ok(owned)
}

fn current_process_creation_time() -> io::Result<u64> {
    process_creation_time(unsafe { GetCurrentProcess() })
}
fn process_creation_time(handle: HANDLE) -> io::Result<u64> {
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
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

fn sha256_current_exe() -> io::Result<String> {
    let path = std::env::current_exe()?;
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex(&hasher.finalize()))
}

fn validate_options(options: &GuiKillOwnerOptions) -> io::Result<()> {
    if !options.root.is_absolute()
        || !options.root.is_dir()
        || options.gui_pipe_name == options.control_pipe_name
        || options.supervisor_pid == 0
        || options.supervisor_creation_time_100ns == 0
        || !(2..=1_000).contains(&options.expected_attempts)
        || !options.expected_attempts.is_multiple_of(2)
        || options.owner_executable_sha256_hex.len() != 64
        || !options
            .owner_executable_sha256_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "owner options are invalid",
        ));
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
