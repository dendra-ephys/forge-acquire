//! Private business owner for the Windows SCM supervisor.
//!
//! The SCM-facing process must never own a journal writer, replay worker,
//! dispatcher, D3XX backend, or public pipe handler.  This child process owns
//! all of those potentially blocking objects and is expected to be placed in a
//! kill-on-close Job Object by its supervisor.  In particular, this module
//! does not claim that a Rust thread join can be forcibly interrupted.

#![cfg(windows)]

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use forge_protocol_v1::sha256;
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessTimes,
};

use crate::hardware_service::{
    HardwareOwnerShutdownSignal, HardwareServiceDispatcher, HardwareServiceOwner,
    HardwareServiceProxy, HostMonotonicClock, UnavailableHardwareBackend,
};
use crate::ipc::{
    canonical_sid_string, lookup_account_sid, AuthenticatedPipeClient, SecurePipeOptions,
    SecurePipeServer, SecurePipeStopHandle,
};
use crate::run::RunState;
use crate::scan_journal;
use crate::scm_owner_protocol::{
    decode_request, encode_response, qpc_now_ns, ExpectedOwnerControlPeer, ScmOwnerCommandV1,
    ScmOwnerErrorCodeV1, ScmOwnerPhaseV1, ScmOwnerRequestV1, ScmOwnerResponseV1, SequenceGuard,
    SCM_OWNER_RESPONSE_SCHEMA,
};
use crate::scm_stop_receipt::{
    bind_existing_evidence_file_v1, load_bound_stop_intent_v1, publish_owner_stop_outcome_v1,
    scm_stop_evidence_paths_v1, CaptureExitReasonV1, DurablePrefixV1, OwnerStopOutcomeV1,
    RunStopTruthV1, StableFileBindingV1, StopIntentKindV1, StopIntentV1, StopProcessIdentityV1,
    SCM_STOP_RECEIPT_SCHEMA,
};
use crate::service_protocol::{OwnerDispatcherSnapshot, ServiceDispatcher};
use crate::service_replay::ReplayOwnerShutdownSignal;
use crate::windows_service_host::{
    ServiceHostConfig, DEFAULT_ANALYSIS_PIPE_NAME, DEFAULT_HARDWARE_PIPE_NAME, SERVICE_ACCOUNT_NAME,
};
use crate::{ProtectedDirectPodPolicyReference, VerifiedDirectPodDeploymentPolicy};

const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
const HARDWARE_OWNER_QUEUE_CAPACITY: usize = 16;
const HARDWARE_OWNER_POLL_INTERVAL: Duration = Duration::from_millis(1);
const HARDWARE_OWNER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Compile-time authority for the optional NWB supervisor runtime. Only this
/// service-owner module can mint it in production; it is deliberately not a
/// proof of installed SCM identity, generation-root ACLs, or publication
/// authority. Those remain independent, fail-closed launch inputs.
pub(crate) struct NwbOwnerAuthorityV1 {
    _private: (),
}

impl NwbOwnerAuthorityV1 {
    fn mint_for_service_owner_runtime() -> Self {
        Self { _private: () }
    }
}

#[cfg(test)]
pub(crate) fn nwb_owner_authority_for_test() -> NwbOwnerAuthorityV1 {
    NwbOwnerAuthorityV1::mint_for_service_owner_runtime()
}

/// Immutable launch material supplied by the SCM supervisor.  These values are
/// identity bindings, not secrets: the owner verifies its own image and token
/// instead of trusting command-line text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceOwnerLaunchConfig {
    pub service_config: ServiceHostConfig,
    pub service_instance_id: [u8; 32],
    pub supervisor_pid: u32,
    pub supervisor_creation_time_100ns: u64,
    pub supervisor_executable_sha256: [u8; 32],
    pub expected_owner_executable_sha256: [u8; 32],
    pub owner_control_pipe: String,
}

/// Parses only the internal `service-owner` argument set.  The normal product
/// CLI must dispatch this only after creating a contained child process.
pub fn parse_service_owner_args(
    arguments: impl IntoIterator<Item = OsString>,
) -> io::Result<ServiceOwnerLaunchConfig> {
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
    let mut service_instance_id = None;
    let mut supervisor_pid = None;
    let mut supervisor_creation_time_100ns = None;
    let mut supervisor_executable_sha256 = None;
    let mut expected_owner_executable_sha256 = None;
    let mut owner_control_pipe = None;

    while let Some(argument) = arguments.next() {
        let argument = argument.into_string().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "service-owner argument is not Unicode",
            )
        })?;
        let value = arguments.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("missing value after {argument}"),
            )
        })?;
        let value = value.into_string().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "service-owner value is not Unicode",
            )
        })?;
        match argument.as_str() {
            "--data-root" if data_root.is_none() => data_root = Some(PathBuf::from(value)),
            "--operator-sid" if operator_sid.is_none() => operator_sid = Some(value),
            "--pipe" if pipe_name.is_none() => pipe_name = Some(value),
            "--hardware-pipe" if hardware_pipe_name.is_none() => hardware_pipe_name = Some(value),
            "--analysis-worker-sid" if analysis_worker_sid.is_none() => {
                analysis_worker_sid = Some(value)
            }
            "--analysis-pipe" if analysis_pipe_name.is_none() => analysis_pipe_name = Some(value),
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
            "--service-instance-id" if service_instance_id.is_none() => {
                service_instance_id = Some(parse_hex32(&value, "service instance ID")?)
            }
            "--supervisor-pid" if supervisor_pid.is_none() => {
                supervisor_pid = Some(parse_nonzero(&value, "supervisor PID")?)
            }
            "--supervisor-creation-time-100ns" if supervisor_creation_time_100ns.is_none() => {
                supervisor_creation_time_100ns =
                    Some(parse_nonzero(&value, "supervisor creation time")?)
            }
            "--supervisor-executable-sha256" if supervisor_executable_sha256.is_none() => {
                supervisor_executable_sha256 =
                    Some(parse_hex32(&value, "supervisor executable SHA-256")?)
            }
            "--owner-executable-sha256" if expected_owner_executable_sha256.is_none() => {
                expected_owner_executable_sha256 =
                    Some(parse_hex32(&value, "owner executable SHA-256")?)
            }
            "--owner-control-pipe" if owner_control_pipe.is_none() => {
                owner_control_pipe = Some(value)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown or duplicate service-owner option: {argument}"),
                ))
            }
        }
    }

    let data_root = data_root.ok_or_else(|| required("--data-root"))?;
    if !data_root.is_absolute() || !std::fs::metadata(&data_root)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service-owner data root must be an existing absolute directory",
        ));
    }
    let operator_sid =
        canonical_sid_string(&operator_sid.ok_or_else(|| required("--operator-sid"))?)?;
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
    let pipe_name = pipe_name.unwrap_or_else(|| crate::ipc::DEFAULT_PIPE_NAME.to_owned());
    let hardware_pipe_name =
        hardware_pipe_name.unwrap_or_else(|| DEFAULT_HARDWARE_PIPE_NAME.to_owned());
    let analysis_pipe_name =
        analysis_pipe_name.unwrap_or_else(|| DEFAULT_ANALYSIS_PIPE_NAME.to_owned());
    validate_local_pipe(&pipe_name, "public control pipe")?;
    validate_local_pipe(&hardware_pipe_name, "public hardware pipe")?;
    validate_local_pipe(&analysis_pipe_name, "public analysis pipe")?;
    if pipe_name.eq_ignore_ascii_case(&hardware_pipe_name)
        || (analysis_worker_sid.is_some()
            && (pipe_name.eq_ignore_ascii_case(&analysis_pipe_name)
                || hardware_pipe_name.eq_ignore_ascii_case(&analysis_pipe_name)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "enabled service-owner public pipes must be distinct",
        ));
    }
    let direct_pod_policy = match (
        direct_pod_policy_path,
        direct_pod_policy_sha256,
        internal_approval_authority_sha256,
    ) {
        (None, None, None) => None,
        (Some(path), Some(policy_hash), Some(authority_hash)) => {
            parse_hex32(&policy_hash, "direct-Pod policy SHA-256")?;
            parse_hex32(&authority_hash, "direct-Pod approval-authority SHA-256")?;
            Some(ProtectedDirectPodPolicyReference::from_hex(
                path,
                &policy_hash,
                &authority_hash,
            )?)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "direct-Pod policy path and both protected hashes are required together",
            ))
        }
    };
    let owner_control_pipe = owner_control_pipe.ok_or_else(|| required("--owner-control-pipe"))?;
    validate_local_pipe(&owner_control_pipe, "owner-control pipe")?;
    if owner_control_pipe.eq_ignore_ascii_case(&pipe_name)
        || owner_control_pipe.eq_ignore_ascii_case(&hardware_pipe_name)
        || owner_control_pipe.eq_ignore_ascii_case(&analysis_pipe_name)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "owner-control pipe must differ from every public pipe",
        ));
    }

    let launch = ServiceOwnerLaunchConfig {
        service_config: ServiceHostConfig {
            data_root,
            operator_sid,
            pipe_name,
            hardware_pipe_name,
            analysis_worker_sid,
            analysis_pipe_name,
            direct_pod_policy,
        },
        service_instance_id: service_instance_id
            .ok_or_else(|| required("--service-instance-id"))?,
        supervisor_pid: supervisor_pid.ok_or_else(|| required("--supervisor-pid"))?,
        supervisor_creation_time_100ns: supervisor_creation_time_100ns
            .ok_or_else(|| required("--supervisor-creation-time-100ns"))?,
        supervisor_executable_sha256: supervisor_executable_sha256
            .ok_or_else(|| required("--supervisor-executable-sha256"))?,
        expected_owner_executable_sha256: expected_owner_executable_sha256
            .ok_or_else(|| required("--owner-executable-sha256"))?,
        owner_control_pipe,
    };
    validate_launch_config(&launch)?;
    Ok(launch)
}

/// Produces the exact non-secret internal owner arguments for a contained
/// child. The caller provides the supervisor identity captured from a retained
/// process handle and the frozen executable hashes.
pub(crate) fn owner_launch_arguments(
    service_config: &ServiceHostConfig,
    service_instance_id: [u8; 32],
    supervisor_pid: u32,
    supervisor_creation_time_100ns: u64,
    supervisor_executable_sha256: [u8; 32],
    expected_owner_executable_sha256: [u8; 32],
    owner_control_pipe: &str,
) -> io::Result<Vec<OsString>> {
    let launch = ServiceOwnerLaunchConfig {
        service_config: service_config.clone(),
        service_instance_id,
        supervisor_pid,
        supervisor_creation_time_100ns,
        supervisor_executable_sha256,
        expected_owner_executable_sha256,
        owner_control_pipe: owner_control_pipe.to_owned(),
    };
    validate_launch_config(&launch)?;
    let mut args = vec![
        OsString::from("service-owner"),
        OsString::from("--data-root"),
        launch.service_config.data_root.clone().into_os_string(),
        OsString::from("--operator-sid"),
        OsString::from(&launch.service_config.operator_sid),
        OsString::from("--pipe"),
        OsString::from(&launch.service_config.pipe_name),
        OsString::from("--hardware-pipe"),
        OsString::from(&launch.service_config.hardware_pipe_name),
        OsString::from("--service-instance-id"),
        OsString::from(hex(&launch.service_instance_id)),
        OsString::from("--supervisor-pid"),
        OsString::from(launch.supervisor_pid.to_string()),
        OsString::from("--supervisor-creation-time-100ns"),
        OsString::from(launch.supervisor_creation_time_100ns.to_string()),
        OsString::from("--supervisor-executable-sha256"),
        OsString::from(hex(&launch.supervisor_executable_sha256)),
        OsString::from("--owner-executable-sha256"),
        OsString::from(hex(&launch.expected_owner_executable_sha256)),
        OsString::from("--owner-control-pipe"),
        OsString::from(&launch.owner_control_pipe),
    ];
    if let Some(worker_sid) = &launch.service_config.analysis_worker_sid {
        args.extend([
            OsString::from("--analysis-worker-sid"),
            OsString::from(worker_sid),
            OsString::from("--analysis-pipe"),
            OsString::from(&launch.service_config.analysis_pipe_name),
        ]);
    }
    if let Some(policy) = &launch.service_config.direct_pod_policy {
        args.extend([
            OsString::from("--direct-pod-policy"),
            policy.path().as_os_str().to_os_string(),
            OsString::from("--direct-pod-policy-sha256"),
            OsString::from(policy.expected_file_sha256_hex()),
            OsString::from("--internal-approval-authority-sha256"),
            OsString::from(policy.expected_approval_authority_sha256_hex()),
        ]);
    }
    Ok(args)
}

/// Runs the child owner. It only returns `Ok` after every public listener,
/// replay dispatcher, and hardware owner has shut down successfully. There is
/// deliberately no `ShutdownSealed` response here: a durable shutdown receipt
/// writer is a required later integration gate.
pub fn run_service_owner(launch: ServiceOwnerLaunchConfig) -> io::Result<()> {
    validate_launch_config(&launch)?;
    let owner_executable_sha256 = current_executable_sha256()?;
    if owner_executable_sha256 != launch.expected_owner_executable_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service-owner executable SHA-256 does not match the frozen launch identity",
        ));
    }
    let owner_pid = unsafe { GetCurrentProcessId() };
    let owner_creation_time_100ns = current_process_creation_time()?;
    if owner_pid == 0 || owner_creation_time_100ns == 0 {
        return Err(io::Error::other(
            "service-owner process identity is invalid",
        ));
    }

    let service_sid = lookup_account_sid(SERVICE_ACCOUNT_NAME)?;
    // Every public bind below verifies that the owner token actually contains
    // the configured NT SERVICE SID. The private pipe is intentionally not
    // created until the complete public runtime and all listener threads exist;
    // this prevents the supervisor's first non-idempotent QueryReady request
    // from entering a pipe whose business initialization is still in flight.
    let mut runtime = initialize_runtime(&launch.service_config, &service_sid)?;
    let dispatcher = Arc::new(Mutex::new(runtime.dispatcher));
    let initial_snapshot = dispatcher
        .lock()
        .map_err(|_| io::Error::other("owner dispatcher mutex poisoned during startup"))?
        .owner_snapshot();
    let replay_shutdown = dispatcher
        .lock()
        .map_err(|_| io::Error::other("owner dispatcher mutex poisoned during startup"))?
        .owner_shutdown_signal();
    let hardware_shutdown = runtime
        .hardware_owner
        .as_ref()
        .ok_or_else(|| io::Error::other("owner hardware service is unavailable during startup"))?
        .shutdown_signal();
    let snapshot = Arc::new(Mutex::new(initial_snapshot));

    let public_stops = OwnerPublicStops {
        control: runtime.control_server.stop_handle(),
        hardware: runtime.hardware_server.stop_handle(),
        analysis: runtime
            .analysis_server
            .as_ref()
            .map(SecurePipeServer::stop_handle),
    };
    let public_activation = PublicActivationGate::new();
    let stop_transition_gate = Arc::new(Mutex::new(()));
    let graceful_shutdown_requested = Arc::new(AtomicBool::new(false));
    let public_listener_failed = Arc::new(AtomicBool::new(false));
    let (event_tx, event_rx) = mpsc::channel();
    let hardware_join = spawn_hardware_listener(
        runtime.hardware_server,
        runtime.hardware_dispatcher,
        runtime.hardware_clock,
        Arc::clone(&stop_transition_gate),
        Arc::clone(&graceful_shutdown_requested),
        public_activation.clone(),
        public_stops.clone(),
        Arc::clone(&public_listener_failed),
        event_tx.clone(),
    )?;
    let analysis_join = spawn_analysis_listener(
        runtime.analysis_server.take(),
        Arc::clone(&dispatcher),
        Arc::clone(&snapshot),
        Arc::clone(&stop_transition_gate),
        Arc::clone(&graceful_shutdown_requested),
        public_activation.clone(),
        public_stops.clone(),
        Arc::clone(&public_listener_failed),
        event_tx.clone(),
    )?;
    let control_join = spawn_control_listener(
        runtime.control_server,
        PublicControlListenerContext {
            dispatcher: Arc::clone(&dispatcher),
            snapshot: Arc::clone(&snapshot),
            stop_transition_gate: Arc::clone(&stop_transition_gate),
            graceful_shutdown_requested: Arc::clone(&graceful_shutdown_requested),
            activation: public_activation.clone(),
            public_stops: public_stops.clone(),
            public_listener_failed: Arc::clone(&public_listener_failed),
            events: event_tx.clone(),
        },
    )?;

    let owner_control_server = SecurePipeServer::bind_service(&SecurePipeOptions {
        pipe_name: launch.owner_control_pipe.clone(),
        service_sid: service_sid.clone(),
        allowed_client_sid: LOCAL_SYSTEM_SID.to_owned(),
    })?;
    let owner_control_stop = owner_control_server.stop_handle();

    let expected_peer = ExpectedOwnerControlPeer {
        service_instance_id: launch.service_instance_id,
        supervisor_pid: launch.supervisor_pid,
        supervisor_creation_time_100ns: launch.supervisor_creation_time_100ns,
        supervisor_executable_sha256: launch.supervisor_executable_sha256,
        owner_pid,
        owner_creation_time_100ns,
        owner_executable_sha256,
    };
    let control_state = Arc::new(OwnerControlState {
        expected_peer: expected_peer.clone(),
        sequence: Mutex::new(SequenceGuard::new(expected_peer)?),
        phase: Mutex::new(ScmOwnerPhaseV1::Running),
        data_root: launch.service_config.data_root.clone(),
        dispatcher: Arc::clone(&dispatcher),
        snapshot,
        public_stops: public_stops.clone(),
        public_activation: public_activation.clone(),
        replay_shutdown,
        hardware_shutdown,
        public_listener_failed,
        public_control_pipe_name: launch.service_config.pipe_name.clone(),
        public_hardware_pipe_name: launch.service_config.hardware_pipe_name.clone(),
        public_analysis_pipe_name: launch
            .service_config
            .analysis_worker_sid
            .as_ref()
            .map(|_| launch.service_config.analysis_pipe_name.clone()),
        graceful_shutdown_requested,
        stop_transition_gate,
        graceful_shutdown_fack_pending: AtomicBool::new(false),
        graceful_shutdown_fack_observed: AtomicBool::new(false),
        graceful_stop_intent: Mutex::new(None),
        activation_pending_fack: AtomicBool::new(false),
    });
    let owner_control_join = spawn_owner_control_listener(
        owner_control_server,
        Arc::clone(&control_state),
        event_tx.clone(),
    )?;

    let first_event = event_rx.recv().map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "service-owner listener event channel disconnected",
        )
    })?;
    // Public listeners may finish after the handler latched shutdown but
    // before the private response/FACK completes. The immutable latch, not
    // cross-sender channel ordering, decides whether this is a graceful path.
    let graceful = matches!(&first_event, OwnerEvent::GracefulShutdown)
        || control_state
            .graceful_shutdown_requested
            .load(Ordering::Acquire);
    if !graceful {
        let _ = owner_control_stop.request_stop();
    }
    control_state.request_business_shutdown();
    public_activation.stop();
    public_stops.request_all();

    let control_result = join_listener(control_join, "public control listener");
    let hardware_result = join_listener(hardware_join, "public hardware listener");
    let analysis_result = join_optional_listener(analysis_join, "public analysis listener");
    let replay_shutdown_result = dispatcher
        .lock()
        .map_err(|_| io::Error::other("owner dispatcher mutex poisoned during shutdown"))
        .and_then(|mut dispatcher| dispatcher.shutdown());
    let hardware_shutdown_result = runtime
        .hardware_owner
        .take()
        .ok_or_else(|| io::Error::other("owner hardware service was already stopped"))
        .and_then(HardwareServiceOwner::shutdown);

    // In the graceful path the private listener emitted GracefulShutdown only
    // after the response/FACK transaction reached a terminal result and exits
    // itself. In a failure path it was stopped above without touching a live
    // shutdown response.
    let private_result = join_listener(owner_control_join, "owner-control listener");

    if !graceful {
        return Err(first_event.into_error());
    }
    let shutdown_result = control_result
        .and(hardware_result)
        .and(analysis_result)
        .and(replay_shutdown_result)
        .and(hardware_shutdown_result)
        .and(private_result);
    shutdown_result?;
    publish_graceful_stop_outcome(&launch, &control_state)
}

struct ServiceRuntime {
    control_server: SecurePipeServer,
    hardware_server: SecurePipeServer,
    analysis_server: Option<SecurePipeServer>,
    dispatcher: ServiceDispatcher,
    hardware_dispatcher: HardwareServiceDispatcher<HardwareServiceProxy>,
    hardware_owner: Option<HardwareServiceOwner>,
    hardware_clock: HostMonotonicClock,
}

fn initialize_runtime(config: &ServiceHostConfig, service_sid: &str) -> io::Result<ServiceRuntime> {
    let control_server = SecurePipeServer::bind_service(&SecurePipeOptions {
        pipe_name: config.pipe_name.clone(),
        service_sid: service_sid.to_owned(),
        allowed_client_sid: config.operator_sid.clone(),
    })?;
    let hardware_server = SecurePipeServer::bind_service(&SecurePipeOptions {
        pipe_name: config.hardware_pipe_name.clone(),
        service_sid: service_sid.to_owned(),
        allowed_client_sid: config.operator_sid.clone(),
    })?;
    let hardware_clock = HostMonotonicClock::new();
    let hardware_owner = if let Some(reference) = config.direct_pod_policy.as_ref() {
        let now_unix_ns = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| io::Error::other("system clock is before the Unix epoch"))?
                .as_nanos(),
        )
        .map_err(|_| io::Error::other("system wall-clock timestamp exceeds policy range"))?;
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(reference, &config.data_root, now_unix_ns)?;
        let recovery = verified.recover_prior_runs()?;
        let mut deployment_evidence_bytes = Vec::with_capacity(64);
        deployment_evidence_bytes.extend_from_slice(&verified.evidence_hash());
        deployment_evidence_bytes.extend_from_slice(&recovery.evidence_hash);
        let deployment_evidence = sha256(&deployment_evidence_bytes);
        HardwareServiceOwner::spawn(
            verified.into_reconnecting_owner_backend(
                deployment_evidence,
                fresh_hardware_service_instance_id()?,
                recovery.highest_transport_epoch,
            )?,
            hardware_clock.clone(),
            HARDWARE_OWNER_QUEUE_CAPACITY,
            HARDWARE_OWNER_POLL_INTERVAL,
            HARDWARE_OWNER_RESPONSE_TIMEOUT,
        )?
    } else {
        HardwareServiceOwner::spawn(
            UnavailableHardwareBackend::new(
                b"forge-acqd direct-Pod internal verification policy is not configured",
                1,
            )?,
            hardware_clock.clone(),
            HARDWARE_OWNER_QUEUE_CAPACITY,
            HARDWARE_OWNER_POLL_INTERVAL,
            HARDWARE_OWNER_RESPONSE_TIMEOUT,
        )?
    };
    let hardware_dispatcher = HardwareServiceDispatcher::new(hardware_owner.proxy(), true, true)?;
    let (analysis_server, dispatcher) =
        if let Some(worker_sid) = config.analysis_worker_sid.as_ref() {
            let server = SecurePipeServer::bind_service(&SecurePipeOptions {
                pipe_name: config.analysis_pipe_name.clone(),
                service_sid: service_sid.to_owned(),
                allowed_client_sid: worker_sid.clone(),
            })?;
            let dispatcher = ServiceDispatcher::open_protected_replay_with_analysis_worker(
                config.data_root.join("run-ledger"),
                &config.data_root,
                true,
                true,
                service_sid,
                worker_sid,
            )?;
            (Some(server), dispatcher)
        } else {
            let dispatcher = ServiceDispatcher::open_protected_replay(
                config.data_root.join("run-ledger"),
                &config.data_root,
                true,
                true,
            )?;
            (None, dispatcher)
        };
    Ok(ServiceRuntime {
        control_server,
        hardware_server,
        analysis_server,
        dispatcher,
        hardware_dispatcher,
        hardware_owner: Some(hardware_owner),
        hardware_clock,
    })
}

#[derive(Clone)]
struct OwnerPublicStops {
    control: SecurePipeStopHandle,
    hardware: SecurePipeStopHandle,
    analysis: Option<SecurePipeStopHandle>,
}

impl OwnerPublicStops {
    fn request_all(&self) {
        // request_stop stores the flag before its best-effort wake connection.
        // A wake error therefore does not mean the listener remains enabled.
        let _ = self.control.request_stop();
        let _ = self.hardware.request_stop();
        if let Some(analysis) = &self.analysis {
            let _ = analysis.request_stop();
        }
    }
}

enum OwnerEvent {
    GracefulShutdown,
    PublicListenerExited(&'static str, Result<(), String>),
    PrivateListenerExited(Result<(), String>),
}

impl OwnerEvent {
    fn into_error(self) -> io::Error {
        match self {
            Self::GracefulShutdown => {
                io::Error::other("unexpected graceful shutdown event conversion")
            }
            Self::PublicListenerExited(label, Ok(())) => {
                io::Error::other(format!("{label} exited before graceful shutdown"))
            }
            Self::PublicListenerExited(label, Err(error)) => {
                io::Error::other(format!("{label} failed: {error}"))
            }
            Self::PrivateListenerExited(Ok(())) => {
                io::Error::other("owner-control listener exited before graceful shutdown")
            }
            Self::PrivateListenerExited(Err(error)) => {
                io::Error::other(format!("owner-control listener failed: {error}"))
            }
        }
    }
}

struct OwnerControlState {
    expected_peer: ExpectedOwnerControlPeer,
    sequence: Mutex<SequenceGuard>,
    phase: Mutex<ScmOwnerPhaseV1>,
    data_root: PathBuf,
    dispatcher: Arc<Mutex<ServiceDispatcher>>,
    snapshot: Arc<Mutex<OwnerDispatcherSnapshot>>,
    public_stops: OwnerPublicStops,
    public_activation: PublicActivationGate,
    replay_shutdown: Option<ReplayOwnerShutdownSignal>,
    hardware_shutdown: HardwareOwnerShutdownSignal,
    public_listener_failed: Arc<AtomicBool>,
    public_control_pipe_name: String,
    public_hardware_pipe_name: String,
    public_analysis_pipe_name: Option<String>,
    graceful_shutdown_requested: Arc<AtomicBool>,
    stop_transition_gate: Arc<Mutex<()>>,
    graceful_shutdown_fack_pending: AtomicBool,
    graceful_shutdown_fack_observed: AtomicBool,
    graceful_stop_intent: Mutex<Option<GracefulStopIntent>>,
    activation_pending_fack: AtomicBool,
}

#[derive(Clone)]
struct GracefulStopIntent {
    binding: StableFileBindingV1,
    intent: StopIntentV1,
}

impl OwnerControlState {
    fn request_business_shutdown(&self) {
        if let Some(replay) = &self.replay_shutdown {
            replay.request_abort();
        }
        self.hardware_shutdown.request();
    }

    fn current_active_run_id(&self) -> io::Result<Option<[u8; 16]>> {
        let status = self
            .dispatcher
            .lock()
            .map_err(|_| io::Error::other("owner dispatcher mutex poisoned while reading Run"))?
            .status();
        status
            .active_run_id_hex
            .as_deref()
            .map(parse_hex16)
            .transpose()
    }

    fn current_run_context(&self) -> io::Result<(RunState, Option<u64>, Option<[u8; 16]>)> {
        let dispatcher = self
            .dispatcher
            .lock()
            .map_err(|_| io::Error::other("owner dispatcher mutex poisoned while reading Run"))?;
        let snapshot = dispatcher.owner_snapshot();
        let status = dispatcher.status();
        let active_run_id = status
            .active_run_id_hex
            .as_deref()
            .map(parse_hex16)
            .transpose()?;
        Ok((snapshot.state, snapshot.active_epoch, active_run_id))
    }
}

fn validate_graceful_stop_intent(
    state: &OwnerControlState,
    request: &ScmOwnerRequestV1,
    binding: &StableFileBindingV1,
) -> io::Result<StopIntentV1> {
    let intent = load_bound_stop_intent_v1(binding)?;
    let expected_paths =
        scm_stop_evidence_paths_v1(&state.data_root, &state.expected_peer.service_instance_id)?;
    let (run_state, active_epoch, active_run_id) = state.current_run_context()?;
    let active = active_epoch.is_some();
    if intent.service_name != crate::windows_service_host::SERVICE_NAME
        || intent.intent_kind != StopIntentKindV1::RuntimeGracefulShutdown
        || binding.path != path_string(&expected_paths.intent_path)?
        || intent.service_instance_id_hex != hex(&state.expected_peer.service_instance_id)
        || intent.owner_process
            != (StopProcessIdentityV1 {
                pid: state.expected_peer.owner_pid,
                creation_time_100ns: state.expected_peer.owner_creation_time_100ns,
            })
        || intent.private_request_sequence != Some(request.command_sequence)
        || intent.private_epoch != Some(request.request_id)
        || intent.deadline_monotonic_ns != request.deadline_qpc_ns
        || intent.run_state_wire != Some(run_state.wire_value())
        || intent.active_run_at_intent != active
        || intent.run_id_hex.as_deref()
            != active_run_id.as_ref().map(|run_id| hex(run_id)).as_deref()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private GracefulShutdown StopIntent does not match owner Run identity",
        ));
    }
    Ok(intent)
}

fn publish_graceful_stop_outcome(
    launch: &ServiceOwnerLaunchConfig,
    state: &OwnerControlState,
) -> io::Result<()> {
    if !state
        .graceful_shutdown_fack_observed
        .load(Ordering::Acquire)
    {
        return Err(io::Error::other(
            "owner graceful shutdown response FACK was not observed; outcome is withheld",
        ));
    }
    let stored = state
        .graceful_stop_intent
        .lock()
        .map_err(|_| io::Error::other("owner StopIntent mutex poisoned"))?
        .clone()
        .ok_or_else(|| io::Error::other("graceful shutdown lacks persisted StopIntent"))?;
    let paths = scm_stop_evidence_paths_v1(
        &launch.service_config.data_root,
        &launch.service_instance_id,
    )?;
    if stored.binding.path != path_string(&paths.intent_path)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "owner StopIntent path is outside the deterministic protected data root",
        ));
    }
    let completed_wall_time_unix_ns = unix_time_ns()?;
    let completed_monotonic_ns = qpc_now_ns()?;
    let final_status = state
        .dispatcher
        .lock()
        .map_err(|_| io::Error::other("owner dispatcher mutex poisoned after shutdown"))?
        .status();
    let frozen_run_state = RunState::from_wire(
        stored
            .intent
            .run_state_wire
            .ok_or_else(|| io::Error::other("runtime StopIntent lacks frozen Run state"))?,
    )?;
    let (final_run_truth, durable_prefix, capture_exit_reason) = match frozen_run_state {
        RunState::Failed => {
            if final_status.state != RunState::Failed {
                return Err(io::Error::other(
                    "preexisting Failed Run changed during owner shutdown",
                ));
            }
            (
                RunStopTruthV1::AlreadyFailed,
                None,
                CaptureExitReasonV1::PreexistingRunFailure,
            )
        }
        RunState::Prepared
        | RunState::Armed
        | RunState::Recording
        | RunState::Stopped
        | RunState::Aborted => {
            let expected_final_state = if frozen_run_state == RunState::Aborted {
                RunState::Aborted
            } else {
                RunState::Failed
            };
            if final_status.state != expected_final_state {
                return Err(io::Error::other(
                    "active Run did not enter the expected fail-closed shutdown state",
                ));
            }
            let run_id = stored
                .intent
                .run_id_hex
                .as_deref()
                .ok_or_else(|| io::Error::other("active StopIntent lacks Run ID"))?;
            let journal_path = launch
                .service_config
                .data_root
                .join(format!("run-{run_id}.forgewal"));
            let scan = scan_journal(&journal_path)?;
            if scan.seal.is_some()
                || scan.torn_tail
                || scan.file_len != scan.durable.durable_valid_len
            {
                return Err(io::Error::other(
                    "active SCM abort requires an unsealed journal with no bytes beyond the durable boundary",
                ));
            }
            let journal = bind_existing_evidence_file_v1(&journal_path)?;
            (
                RunStopTruthV1::ActiveRunAbortedWithDurablePrefix,
                Some(DurablePrefixV1 {
                    journal,
                    durable_watermark_journal_sequence: scan.durable.durable_journal_sequence,
                    durable_record_count: scan.durable.durable_record_count,
                    last_observed_record_sequence: None,
                    last_observed_sample_index: None,
                    journal_poisoned: false,
                    journal_fault: None,
                }),
                CaptureExitReasonV1::ExplicitScmStopAbort,
            )
        }
        RunState::New | RunState::JournalSealed | RunState::Finalized => {
            if final_status.state != frozen_run_state {
                return Err(io::Error::other(
                    "idle Run state changed during owner shutdown",
                ));
            }
            (
                RunStopTruthV1::IdleCleanStop,
                None,
                CaptureExitReasonV1::IdleOwnerShutdown,
            )
        }
    };
    let outcome = OwnerStopOutcomeV1 {
        schema: SCM_STOP_RECEIPT_SCHEMA.to_owned(),
        intent_sha256_hex: stored.intent.intent_sha256_hex,
        service_name: crate::windows_service_host::SERVICE_NAME.to_owned(),
        service_instance_id_hex: hex(&launch.service_instance_id),
        run_id_hex: stored.intent.run_id_hex,
        owner_process: StopProcessIdentityV1 {
            pid: state.expected_peer.owner_pid,
            creation_time_100ns: state.expected_peer.owner_creation_time_100ns,
        },
        private_fack_observed: true,
        private_request_sequence: stored
            .intent
            .private_request_sequence
            .ok_or_else(|| io::Error::other("runtime StopIntent lacks private sequence"))?,
        private_epoch: stored
            .intent
            .private_epoch
            .ok_or_else(|| io::Error::other("runtime StopIntent lacks private epoch"))?,
        completed_wall_time_unix_ns,
        completed_monotonic_ns,
        final_run_truth,
        durable_prefix,
        capture_exit_reason,
        outcome_sha256_hex: String::new(),
    };
    publish_owner_stop_outcome_v1(&paths.outcome_path, &outcome)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicActivationState {
    Blocked,
    Active,
    Stopping,
}

#[derive(Clone)]
struct PublicActivationGate {
    state: Arc<(Mutex<PublicActivationState>, Condvar)>,
}

impl PublicActivationGate {
    fn new() -> Self {
        Self {
            state: Arc::new((Mutex::new(PublicActivationState::Blocked), Condvar::new())),
        }
    }

    fn activate(&self) -> io::Result<()> {
        let (state, wake) = &*self.state;
        let mut state = state
            .lock()
            .map_err(|_| io::Error::other("public activation gate mutex poisoned"))?;
        if *state != PublicActivationState::Blocked {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "public activation gate is not blocked",
            ));
        }
        *state = PublicActivationState::Active;
        wake.notify_all();
        Ok(())
    }

    fn stop(&self) {
        let (state, wake) = &*self.state;
        if let Ok(mut state) = state.lock() {
            *state = PublicActivationState::Stopping;
            wake.notify_all();
        }
    }

    /// Returns false when shutdown wins before activation. Public listeners
    /// remain bound but cannot accept or execute a command while SCM is still
    /// StartPending.
    fn wait_until_active(&self) -> io::Result<bool> {
        let (state, wake) = &*self.state;
        let mut state = state
            .lock()
            .map_err(|_| io::Error::other("public activation gate mutex poisoned"))?;
        while *state == PublicActivationState::Blocked {
            state = wake
                .wait(state)
                .map_err(|_| io::Error::other("public activation gate mutex poisoned"))?;
        }
        Ok(*state == PublicActivationState::Active)
    }
}

struct PublicControlListenerContext {
    dispatcher: Arc<Mutex<ServiceDispatcher>>,
    snapshot: Arc<Mutex<OwnerDispatcherSnapshot>>,
    stop_transition_gate: Arc<Mutex<()>>,
    graceful_shutdown_requested: Arc<AtomicBool>,
    activation: PublicActivationGate,
    public_stops: OwnerPublicStops,
    public_listener_failed: Arc<AtomicBool>,
    events: mpsc::Sender<OwnerEvent>,
}

fn spawn_control_listener(
    mut server: SecurePipeServer,
    context: PublicControlListenerContext,
) -> io::Result<JoinHandle<io::Result<u64>>> {
    let PublicControlListenerContext {
        dispatcher,
        snapshot,
        stop_transition_gate,
        graceful_shutdown_requested,
        activation,
        public_stops,
        public_listener_failed,
        events,
    } = context;
    std::thread::Builder::new()
        .name("forge-owner-control-listener".to_owned())
        .spawn(move || {
            let result = if activation.wait_until_active()? {
                server.run_until_stopped(|request| {
                    with_public_command_admission(
                        &stop_transition_gate,
                        &graceful_shutdown_requested,
                        || {
                            let mut dispatcher = dispatcher
                                .lock()
                                .map_err(|_| io::Error::other("owner dispatcher mutex poisoned"))?;
                            let response = dispatcher.handle(request)?;
                            let current = dispatcher.owner_snapshot();
                            *snapshot
                                .lock()
                                .map_err(|_| io::Error::other("owner snapshot mutex poisoned"))? =
                                current;
                            Ok(response)
                        },
                    )
                })
            } else {
                Ok(0)
            };
            if result.is_err() {
                public_listener_failed.store(true, Ordering::Release);
                public_stops.request_all();
            }
            let observation = result.as_ref().map(|_| ()).map_err(ToString::to_string);
            let _ = events.send(OwnerEvent::PublicListenerExited(
                "public control listener",
                observation,
            ));
            result
        })
}

fn with_public_command_admission<T>(
    stop_transition_gate: &Mutex<()>,
    graceful_shutdown_requested: &AtomicBool,
    command: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let _transition = stop_transition_gate
        .lock()
        .map_err(|_| io::Error::other("owner stop-transition mutex poisoned"))?;
    if graceful_shutdown_requested.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "public Run command refused after SCM stop transition",
        ));
    }
    command()
}

#[allow(clippy::too_many_arguments)] // stop gate and latch are explicit listener inputs.
fn spawn_hardware_listener(
    mut server: SecurePipeServer,
    mut dispatcher: HardwareServiceDispatcher<HardwareServiceProxy>,
    clock: HostMonotonicClock,
    stop_transition_gate: Arc<Mutex<()>>,
    graceful_shutdown_requested: Arc<AtomicBool>,
    activation: PublicActivationGate,
    public_stops: OwnerPublicStops,
    public_listener_failed: Arc<AtomicBool>,
    events: mpsc::Sender<OwnerEvent>,
) -> io::Result<JoinHandle<io::Result<u64>>> {
    std::thread::Builder::new()
        .name("forge-owner-hardware-listener".to_owned())
        .spawn(move || {
            let result = if activation.wait_until_active()? {
                server.run_until_stopped(|request| {
                    with_public_command_admission(
                        &stop_transition_gate,
                        &graceful_shutdown_requested,
                        || dispatcher.handle(request, clock.now_ns()),
                    )
                })
            } else {
                Ok(0)
            };
            if result.is_err() {
                public_listener_failed.store(true, Ordering::Release);
                public_stops.request_all();
            }
            let observation = result.as_ref().map(|_| ()).map_err(ToString::to_string);
            let _ = events.send(OwnerEvent::PublicListenerExited(
                "public hardware listener",
                observation,
            ));
            result
        })
}

#[allow(clippy::too_many_arguments)] // stop gate and latch are explicit listener inputs.
fn spawn_analysis_listener(
    server: Option<SecurePipeServer>,
    dispatcher: Arc<Mutex<ServiceDispatcher>>,
    snapshot: Arc<Mutex<OwnerDispatcherSnapshot>>,
    stop_transition_gate: Arc<Mutex<()>>,
    graceful_shutdown_requested: Arc<AtomicBool>,
    activation: PublicActivationGate,
    public_stops: OwnerPublicStops,
    public_listener_failed: Arc<AtomicBool>,
    events: mpsc::Sender<OwnerEvent>,
) -> io::Result<Option<JoinHandle<io::Result<u64>>>> {
    let Some(mut server) = server else {
        return Ok(None);
    };
    std::thread::Builder::new()
        .name("forge-owner-analysis-listener".to_owned())
        .spawn(move || {
            let result = if activation.wait_until_active()? {
                server.run_until_stopped_authenticated(|client, request| {
                    with_public_command_admission(
                        &stop_transition_gate,
                        &graceful_shutdown_requested,
                        || {
                            let mut dispatcher = dispatcher
                                .lock()
                                .map_err(|_| io::Error::other("owner dispatcher mutex poisoned"))?;
                            let response = dispatcher.handle_analysis_worker(client, request)?;
                            let current = dispatcher.owner_snapshot();
                            *snapshot
                                .lock()
                                .map_err(|_| io::Error::other("owner snapshot mutex poisoned"))? =
                                current;
                            Ok(response)
                        },
                    )
                })
            } else {
                Ok(0)
            };
            if result.is_err() {
                public_listener_failed.store(true, Ordering::Release);
                public_stops.request_all();
            }
            let observation = result.as_ref().map(|_| ()).map_err(ToString::to_string);
            let _ = events.send(OwnerEvent::PublicListenerExited(
                "public analysis listener",
                observation,
            ));
            result
        })
        .map(Some)
}

fn spawn_owner_control_listener(
    mut server: SecurePipeServer,
    state: Arc<OwnerControlState>,
    events: mpsc::Sender<OwnerEvent>,
) -> io::Result<JoinHandle<io::Result<u64>>> {
    // The private server is moved to its own thread after every public listener
    // has been created; QueryReady therefore cannot acknowledge a partial
    // runtime.
    std::thread::Builder::new()
        .name("forge-owner-private-control".to_owned())
        .spawn(move || {
            let completion_state = Arc::clone(&state);
            let result = server.run_until_transaction_flag_authenticated_with_completion(
                &state.graceful_shutdown_requested,
                |client, request| handle_owner_control(&state, client, request),
                || {
                    if completion_state
                        .activation_pending_fack
                        .swap(false, Ordering::AcqRel)
                    {
                        completion_state.public_activation.activate()?;
                    }
                    if completion_state
                        .graceful_shutdown_fack_pending
                        .swap(false, Ordering::AcqRel)
                    {
                        completion_state
                            .graceful_shutdown_fack_observed
                            .store(true, Ordering::Release);
                    }
                    Ok(())
                },
            );
            if state.graceful_shutdown_requested.load(Ordering::Acquire) {
                // This event is emitted only after the transaction loop has
                // either observed the shutdown response FACK or returned the
                // exact lost-FACK error. It cannot race ahead and cancel its
                // own response.
                let _ = events.send(OwnerEvent::GracefulShutdown);
            }
            let observation = result.as_ref().map(|_| ()).map_err(ToString::to_string);
            let _ = events.send(OwnerEvent::PrivateListenerExited(observation));
            result
        })
}

fn handle_owner_control(
    state: &OwnerControlState,
    client: &AuthenticatedPipeClient,
    bytes: &[u8],
) -> io::Result<Vec<u8>> {
    let request = decode_request(bytes)?;
    state
        .sequence
        .lock()
        .map_err(|_| io::Error::other("owner-control sequence mutex poisoned"))?
        .observe(client, &request, qpc_now_ns()?)?;
    if state.public_listener_failed.load(Ordering::Acquire) {
        return Err(io::Error::other(
            "owner public listener failed before private control response",
        ));
    }

    let phase = match request.command {
        ScmOwnerCommandV1::QueryReady | ScmOwnerCommandV1::GetSnapshot => *state
            .phase
            .lock()
            .map_err(|_| io::Error::other("owner-control phase mutex poisoned"))?,
        ScmOwnerCommandV1::ActivatePublic => {
            if state.activation_pending_fack.swap(true, Ordering::AcqRel) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "public activation is already pending FACK",
                ));
            }
            ScmOwnerPhaseV1::Running
        }
        ScmOwnerCommandV1::GracefulShutdown => {
            let _transition = state
                .stop_transition_gate
                .lock()
                .map_err(|_| io::Error::other("owner stop-transition mutex poisoned"))?;
            if state
                .graceful_shutdown_requested
                .swap(true, Ordering::AcqRel)
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "owner graceful shutdown transition was already latched",
                ));
            }
            let binding = request
                .stop_intent
                .as_ref()
                .ok_or_else(|| io::Error::other("validated GracefulShutdown lacks StopIntent"))?;
            let intent = validate_graceful_stop_intent(state, &request, binding)?;
            {
                let mut stored = state
                    .graceful_stop_intent
                    .lock()
                    .map_err(|_| io::Error::other("owner StopIntent mutex poisoned"))?;
                if stored.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "owner already accepted a graceful StopIntent",
                    ));
                }
                *stored = Some(GracefulStopIntent {
                    binding: binding.clone(),
                    intent,
                });
            }
            if state
                .graceful_shutdown_fack_pending
                .swap(true, Ordering::AcqRel)
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "owner graceful shutdown FACK is already pending",
                ));
            }
            *state
                .phase
                .lock()
                .map_err(|_| io::Error::other("owner-control phase mutex poisoned"))? =
                ScmOwnerPhaseV1::Stopping;
            state.request_business_shutdown();
            state.public_activation.stop();
            // Public handlers are stopped before the response is constructed;
            // the private listener itself remains alive so its response/FACK is
            // not cancelled by its own stop handle.
            state.public_stops.request_all();
            ScmOwnerPhaseV1::Stopping
        }
    };
    let snapshot = *state
        .snapshot
        .lock()
        .map_err(|_| io::Error::other("owner snapshot mutex poisoned"))?;
    let active_run_id = state.current_active_run_id()?;
    encode_response(&response_for(
        &request,
        &state.expected_peer,
        phase,
        snapshot,
        state,
        active_run_id,
    ))
}

fn response_for(
    request: &ScmOwnerRequestV1,
    identity: &ExpectedOwnerControlPeer,
    phase: ScmOwnerPhaseV1,
    snapshot: OwnerDispatcherSnapshot,
    state: &OwnerControlState,
    active_run_id: Option<[u8; 16]>,
) -> ScmOwnerResponseV1 {
    ScmOwnerResponseV1 {
        schema: SCM_OWNER_RESPONSE_SCHEMA.to_owned(),
        service_instance_id: identity.service_instance_id,
        supervisor_pid: identity.supervisor_pid,
        supervisor_creation_time_100ns: identity.supervisor_creation_time_100ns,
        owner_pid: identity.owner_pid,
        owner_creation_time_100ns: identity.owner_creation_time_100ns,
        supervisor_executable_sha256: identity.supervisor_executable_sha256,
        owner_executable_sha256: identity.owner_executable_sha256,
        command_sequence: request.command_sequence,
        request_id: request.request_id,
        accepted: true,
        error_code: ScmOwnerErrorCodeV1::None,
        owner_phase: phase,
        public_control_pipe_name: state.public_control_pipe_name.clone(),
        public_hardware_pipe_name: state.public_hardware_pipe_name.clone(),
        public_analysis_pipe_name: state.public_analysis_pipe_name.clone(),
        run_state_wire: snapshot.state.wire_value(),
        active_epoch: snapshot.active_epoch,
        active_run_id,
        committed_record_count: snapshot.committed_record_count,
        durable_record_count: snapshot.durable_record_count,
        sealed_record_count: snapshot.sealed_record_count,
        hardware_available: snapshot.hardware_transport_available,
        // A `ShutdownSealed` response requires a durable receipt path/hash.
        // This first owner integration has no writer, so it may emit Stopping
        // only and the supervisor must not interpret child exit as publication.
        shutdown_receipt_path: None,
        shutdown_receipt_sha256: None,
    }
}

fn join_listener(join: JoinHandle<io::Result<u64>>, label: &'static str) -> io::Result<()> {
    join.join()
        .map_err(|_| io::Error::other(format!("{label} panicked")))??;
    Ok(())
}

fn join_optional_listener(
    join: Option<JoinHandle<io::Result<u64>>>,
    label: &'static str,
) -> io::Result<()> {
    match join {
        Some(join) => join_listener(join, label),
        None => Ok(()),
    }
}

fn fresh_hardware_service_instance_id() -> io::Result<[u8; 16]> {
    let mut value = [0_u8; 16];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            value.as_mut_ptr(),
            value.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 || value == [0; 16] {
        Err(io::Error::other(
            "failed to obtain nonzero hardware service instance ID",
        ))
    } else {
        Ok(value)
    }
}

fn current_executable_sha256() -> io::Result<[u8; 32]> {
    let executable = std::env::current_exe()?;
    let executable = std::fs::canonicalize(executable)?;
    let metadata = std::fs::metadata(&executable)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service-owner current executable is not a regular file",
        ));
    }
    Ok(sha256(&std::fs::read(executable)?))
}

fn current_process_creation_time() -> io::Result<u64> {
    let mut creation: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };
    if unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if value == 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "service-owner process creation time is zero",
        ))
    } else {
        Ok(value)
    }
}

fn validate_launch_config(launch: &ServiceOwnerLaunchConfig) -> io::Result<()> {
    if launch.service_instance_id == [0; 32]
        || launch.supervisor_pid == 0
        || launch.supervisor_creation_time_100ns == 0
        || launch.supervisor_executable_sha256 == [0; 32]
        || launch.expected_owner_executable_sha256 == [0; 32]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service-owner launch identity is invalid",
        ));
    }
    if !launch.service_config.data_root.is_absolute()
        || !std::fs::metadata(&launch.service_config.data_root)?.is_dir()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service-owner data root must be an existing absolute directory",
        ));
    }
    validate_local_pipe(&launch.service_config.pipe_name, "public control pipe")?;
    validate_local_pipe(
        &launch.service_config.hardware_pipe_name,
        "public hardware pipe",
    )?;
    validate_local_pipe(
        &launch.service_config.analysis_pipe_name,
        "public analysis pipe",
    )?;
    if launch
        .service_config
        .pipe_name
        .eq_ignore_ascii_case(&launch.service_config.hardware_pipe_name)
        || (launch.service_config.analysis_worker_sid.is_some()
            && (launch
                .service_config
                .pipe_name
                .eq_ignore_ascii_case(&launch.service_config.analysis_pipe_name)
                || launch
                    .service_config
                    .hardware_pipe_name
                    .eq_ignore_ascii_case(&launch.service_config.analysis_pipe_name)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "enabled service-owner public pipes must be distinct",
        ));
    }
    validate_local_pipe(&launch.owner_control_pipe, "owner-control pipe")?;
    if launch
        .owner_control_pipe
        .eq_ignore_ascii_case(&launch.service_config.pipe_name)
        || launch
            .owner_control_pipe
            .eq_ignore_ascii_case(&launch.service_config.hardware_pipe_name)
        || launch
            .owner_control_pipe
            .eq_ignore_ascii_case(&launch.service_config.analysis_pipe_name)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "owner-control pipe must differ from every public pipe",
        ));
    }
    Ok(())
}

fn validate_local_pipe(value: &str, label: &'static str) -> io::Result<()> {
    let suffix = value.strip_prefix(r"\\.\pipe\");
    if suffix.is_none()
        || suffix.is_some_and(|suffix| suffix.is_empty() || suffix.contains('\\'))
        || value.len() > 240
        || !value.is_ascii()
        || value.bytes().any(|byte| byte == b'\0')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be a bounded local named-pipe path"),
        ));
    }
    Ok(())
}

fn parse_nonzero<T>(value: &str, label: &'static str) -> io::Result<T>
where
    T: std::str::FromStr + PartialEq + Default,
{
    let parsed = value.parse::<T>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} is not a valid unsigned integer"),
        )
    })?;
    if parsed == T::default() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be nonzero"),
        ))
    } else {
        Ok(parsed)
    }
}

fn parse_hex32(value: &str, label: &'static str) -> io::Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be exactly 64 lowercase hexadecimal characters"),
        ));
    }
    let mut output = [0_u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{label} is not hexadecimal"),
            )
        })?;
    }
    if output == [0; 32] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be nonzero"),
        ));
    }
    Ok(output)
}

fn parse_hex16(value: &str) -> io::Result<[u8; 16]> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "active Run ID is not exactly 32 lowercase hexadecimal characters",
        ));
    }
    let mut output = [0_u8; 16];
    for (index, slot) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "active Run ID is not hexadecimal",
            )
        })?;
    }
    if output == [0; 16] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "active Run ID is zero",
        ));
    }
    Ok(output)
}

fn path_string(path: &Path) -> io::Result<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not UTF-8"))
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

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn required(name: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is required"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    fn test_config(root: PathBuf) -> ServiceHostConfig {
        ServiceHostConfig {
            data_root: root,
            operator_sid: LOCAL_SYSTEM_SID.to_owned(),
            pipe_name: format!(
                r"\\.\pipe\forge-owner-public-control-{}",
                std::process::id()
            ),
            hardware_pipe_name: format!(
                r"\\.\pipe\forge-owner-public-hardware-{}",
                std::process::id()
            ),
            analysis_worker_sid: None,
            analysis_pipe_name: format!(
                r"\\.\pipe\forge-owner-public-analysis-{}",
                std::process::id()
            ),
            direct_pod_policy: None,
        }
    }

    #[test]
    fn owner_launch_arguments_round_trip_exactly() {
        let root = std::env::temp_dir().join(format!(
            "forge-service-owner-args-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut config = test_config(root.clone());
        config.analysis_worker_sid = Some(LOCAL_SYSTEM_SID.to_owned());
        let private_pipe = format!(r"\\.\pipe\forge-owner-private-{}", std::process::id());
        let arguments =
            owner_launch_arguments(&config, [1; 32], 101, 102, [3; 32], [4; 32], &private_pipe)
                .unwrap();
        assert_eq!(arguments.first(), Some(&OsString::from("service-owner")));
        let parsed = parse_service_owner_args(arguments.into_iter().skip(1)).unwrap();
        assert_eq!(parsed.service_config, config);
        assert_eq!(parsed.service_instance_id, [1; 32]);
        assert_eq!(parsed.supervisor_pid, 101);
        assert_eq!(parsed.supervisor_creation_time_100ns, 102);
        assert_eq!(parsed.supervisor_executable_sha256, [3; 32]);
        assert_eq!(parsed.expected_owner_executable_sha256, [4; 32]);
        assert_eq!(parsed.owner_control_pipe, private_pipe);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_launch_rejects_case_aliases_nested_pipes_and_noncanonical_hashes() {
        let root = std::env::temp_dir().join(format!(
            "forge-service-owner-invalid-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut config = test_config(root.clone());
        config.hardware_pipe_name = config.pipe_name.to_ascii_uppercase();
        assert!(owner_launch_arguments(
            &config,
            [1; 32],
            101,
            102,
            [3; 32],
            [4; 32],
            r"\\.\pipe\owner-private"
        )
        .is_err());
        assert!(validate_local_pipe(r"\\.\pipe\nested\name", "nested").is_err());
        assert!(parse_hex32(&"AA".repeat(32), "uppercase").is_err());
        assert!(parse_hex32(&"00".repeat(32), "zero").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn public_activation_gate_blocks_until_fack_path_activates_or_stops() {
        let gate = PublicActivationGate::new();
        let waiter = gate.clone();
        let (sent, received) = mpsc::channel();
        let join = std::thread::spawn(move || sent.send(waiter.wait_until_active()).unwrap());
        assert!(matches!(
            received.recv_timeout(Duration::from_millis(25)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        gate.activate().unwrap();
        assert!(received
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap());
        join.join().unwrap();
        assert!(gate.activate().is_err());

        let stopped = PublicActivationGate::new();
        stopped.stop();
        assert!(!stopped.wait_until_active().unwrap());
        assert!(stopped.activate().is_err());
    }

    #[test]
    fn public_run_command_and_stop_transition_share_one_barrier() {
        let gate = Arc::new(Mutex::new(()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let committed_state = Arc::new(AtomicU64::new(0));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let public_gate = Arc::clone(&gate);
        let public_shutdown = Arc::clone(&shutdown);
        let public_state = Arc::clone(&committed_state);
        let public = std::thread::spawn(move || {
            with_public_command_admission(&public_gate, &public_shutdown, || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                public_state.store(1, Ordering::Release);
                Ok(())
            })
            .unwrap();
        });
        entered_rx.recv().unwrap();

        let stop_gate = Arc::clone(&gate);
        let stop_shutdown = Arc::clone(&shutdown);
        let stop_state = Arc::clone(&committed_state);
        let stop = std::thread::spawn(move || {
            let _transition = stop_gate.lock().unwrap();
            stop_shutdown.store(true, Ordering::Release);
            stop_state.load(Ordering::Acquire)
        });
        release_tx.send(()).unwrap();
        public.join().unwrap();
        assert_eq!(stop.join().unwrap(), 1);
        assert!(shutdown.load(Ordering::Acquire));

        let rejected = with_public_command_admission(&gate, &shutdown, || {
            committed_state.store(2, Ordering::Release);
            Ok(())
        });
        assert!(rejected.is_err());
        assert_eq!(committed_state.load(Ordering::Acquire), 1);
    }
}
