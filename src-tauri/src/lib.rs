use serde::{Deserialize, Serialize};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::{Child, Command, Stdio};
#[cfg(windows)]
use std::time::{Duration, Instant};
#[cfg(windows)]
use std::{fs, thread};

#[derive(Serialize)]
struct DaemonSnapshotResult {
    available: bool,
    reason: String,
    snapshot: Option<DaemonSnapshotView>,
}

/// JSON-safe view of the daemon's low-rate status. The binary service protocol
/// remains u64-based; only the WebView representation changes to decimal text.
#[derive(Serialize)]
struct DaemonSnapshotView {
    state: forge_acqd::run::RunState,
    accepted: bool,
    retryable: bool,
    poisoned: bool,
    auto_failed_on_restart: bool,
    hardware_transport_available: bool,
    authenticated_pipe: bool,
    scm_owned: bool,
    protected_replay_available: bool,
    request_id: String,
    epoch: String,
    ledger_events: String,
    active_run_id: [u8; 16],
    latest_published_run_id: [u8; 16],
    receipt_hash: [u8; 32],
    committed_record_count: Option<String>,
    durable_record_count: Option<String>,
    expected_last_journal_sequence: Option<String>,
    queue_used_slots: Option<String>,
    queue_capacity_slots: Option<String>,
    generated_record_count: Option<String>,
    active_epoch: Option<String>,
    highest_epoch: String,
    active_target_device_id: [u8; 16],
    active_frozen_config_hash: [u8; 32],
    latest_sealed_run_id: [u8; 16],
    error: forge_acqd::ServiceErrorV1,
    reason: String,
}

impl From<forge_acqd::DaemonResponseV1> for DaemonSnapshotView {
    fn from(value: forge_acqd::DaemonResponseV1) -> Self {
        Self {
            state: value.state,
            accepted: value.accepted,
            retryable: value.retryable,
            poisoned: value.poisoned,
            auto_failed_on_restart: value.auto_failed_on_restart,
            hardware_transport_available: value.hardware_transport_available,
            authenticated_pipe: value.authenticated_pipe,
            scm_owned: value.scm_owned,
            protected_replay_available: value.protected_replay_available,
            request_id: value.request_id.to_string(),
            epoch: value.epoch.to_string(),
            ledger_events: value.ledger_events.to_string(),
            active_run_id: value.active_run_id,
            latest_published_run_id: value.latest_published_run_id,
            receipt_hash: value.receipt_hash,
            committed_record_count: value.committed_record_count.map(|item| item.to_string()),
            durable_record_count: value.durable_record_count.map(|item| item.to_string()),
            expected_last_journal_sequence: value
                .expected_last_journal_sequence
                .map(|item| item.to_string()),
            queue_used_slots: value.queue_used_slots.map(|item| item.to_string()),
            queue_capacity_slots: value.queue_capacity_slots.map(|item| item.to_string()),
            generated_record_count: value.generated_record_count.map(|item| item.to_string()),
            active_epoch: value.active_epoch.map(|item| item.to_string()),
            highest_epoch: value.highest_epoch.to_string(),
            active_target_device_id: value.active_target_device_id,
            active_frozen_config_hash: value.active_frozen_config_hash,
            latest_sealed_run_id: value.latest_sealed_run_id,
            error: value.error,
            reason: value.reason,
        }
    }
}

#[derive(Serialize)]
struct HardwareSnapshotResult {
    reachable: bool,
    reason: String,
    snapshot: Option<HardwareSnapshotView>,
}

/// JSON-safe view of the frozen binary hardware snapshot.  Every u64 crosses
/// the WebView boundary as canonical decimal text so JavaScript never rounds a
/// hardware time, epoch, sequence, or counter above 2^53.
#[derive(Serialize)]
struct HardwareSnapshotView {
    request_id: String,
    service_state: forge_acqd::HardwareServiceState,
    error_code: forge_acqd::HardwareServiceError,
    availability_flags: u32,
    device_id: [u8; 16],
    transport_epoch: String,
    status_sequence: String,
    hardware_time_ns: String,
    sample_counter: String,
    frame_counter: String,
    runtime_flags: u32,
    hardware_state_hash: [u8; 32],
    active_run_id: [u8; 16],
    active_epoch: String,
    pending_request_id: String,
    first_journal_sequence: Option<String>,
    evidence_hash: [u8; 32],
    detail_code: u32,
}

impl From<forge_acqd::HardwareServiceSnapshotV1> for HardwareSnapshotView {
    fn from(value: forge_acqd::HardwareServiceSnapshotV1) -> Self {
        Self {
            request_id: value.request_id.to_string(),
            service_state: value.service_state,
            error_code: value.error_code,
            availability_flags: value.availability_flags,
            device_id: value.device_id,
            transport_epoch: value.transport_epoch.to_string(),
            status_sequence: value.status_sequence.to_string(),
            hardware_time_ns: value.hardware_time_ns.to_string(),
            sample_counter: value.sample_counter.to_string(),
            frame_counter: value.frame_counter.to_string(),
            runtime_flags: value.runtime_flags,
            hardware_state_hash: value.hardware_state_hash,
            active_run_id: value.active_run_id,
            active_epoch: value.active_epoch.to_string(),
            pending_request_id: value.pending_request_id.to_string(),
            first_journal_sequence: value.first_journal_sequence.map(|item| item.to_string()),
            evidence_hash: value.evidence_hash,
            detail_code: value.detail_code,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DaemonRunCommandInput {
    command: u16,
    request_id: u64,
    epoch: u64,
    run_id_hex: String,
    target_device_id_hex: String,
    frozen_config_hash_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HardwareRunCommandInput {
    command: u16,
    request_id: u64,
    epoch: u64,
    relative_deadline_ms: u32,
    run_id_hex: String,
    target_device_id_hex: String,
    frozen_config_hash_hex: String,
    expected_hardware_state_hash_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SoftwareReplayLaunchInput {
    requested_directory: String,
    base_name: String,
    run_id_hex: String,
    target_group_id_hex: String,
    frozen_config_hash_hex: String,
    selected_device_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SoftwareReplayReservationView {
    schema: &'static str,
    reservation_id: String,
    run_id_hex: String,
    pipe_name: String,
    requested_directory: String,
    allocated_leaf_name: String,
    resolved_run_directory: String,
    journal_file_name: &'static str,
    selected_device_ids: Vec<String>,
    directory_create_disposition: &'static str,
    journal_create_disposition: &'static str,
    overwrite_policy: &'static str,
    scope: &'static str,
    synthetic: bool,
    process_id: u32,
    evidence_hash: String,
}

#[tauri::command]
fn daemon_snapshot(request_id: u64, epoch: u64) -> DaemonSnapshotResult {
    #[cfg(windows)]
    {
        match forge_acqd::query_daemon_snapshot(
            forge_acqd::ipc::DEFAULT_PIPE_NAME,
            request_id,
            epoch,
            250,
            750,
        ) {
            Ok(snapshot) => DaemonSnapshotResult {
                available: true,
                reason: "authenticated SCM daemon snapshot".to_owned(),
                snapshot: Some(snapshot.into()),
            },
            Err(error) => DaemonSnapshotResult {
                available: false,
                reason: format!("Forge acquisition service unavailable: {error}"),
                snapshot: None,
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (request_id, epoch);
        DaemonSnapshotResult {
            available: false,
            reason: "Forge acquisition service requires Windows".to_owned(),
            snapshot: None,
        }
    }
}

#[tauri::command]
fn daemon_run_command(input: DaemonRunCommandInput) -> DaemonSnapshotResult {
    #[cfg(windows)]
    {
        let body = (|| {
            Ok(forge_protocol_v1::RunCommandV1 {
                command: input.command,
                scope: 1,
                run_id: decode_hex(&input.run_id_hex)?,
                target_device_id: decode_hex(&input.target_device_id_hex)?,
                deadline_global_time_ns: u64::MAX,
                frozen_config_hash: decode_hex(&input.frozen_config_hash_hex)?,
            })
        })();
        let body = match body {
            Ok(body) => body,
            Err(reason) => {
                return DaemonSnapshotResult {
                    available: false,
                    reason,
                    snapshot: None,
                }
            }
        };
        match forge_acqd::call_daemon_run_command(
            forge_acqd::ipc::DEFAULT_PIPE_NAME,
            input.request_id,
            input.epoch,
            &body,
            250,
            12_000,
        ) {
            Ok(snapshot) => DaemonSnapshotResult {
                available: true,
                reason: snapshot.reason.clone(),
                snapshot: Some(snapshot.into()),
            },
            Err(error) => DaemonSnapshotResult {
                available: false,
                reason: format!("Forge acquisition service unavailable: {error}"),
                snapshot: None,
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = input;
        DaemonSnapshotResult {
            available: false,
            reason: "Forge acquisition service requires Windows".to_owned(),
            snapshot: None,
        }
    }
}

#[tauri::command]
fn hardware_snapshot(request_id: u64) -> HardwareSnapshotResult {
    #[cfg(windows)]
    {
        match forge_acqd::query_hardware_service(
            forge_acqd::windows_service_host::DEFAULT_HARDWARE_PIPE_NAME,
            request_id,
            250,
            750,
        ) {
            Ok(snapshot) => HardwareSnapshotResult {
                reachable: true,
                reason: format!("hardware service responded: {:?}", snapshot.error_code),
                snapshot: Some(snapshot.into()),
            },
            Err(error) => HardwareSnapshotResult {
                reachable: false,
                reason: format!("Forge hardware service unavailable: {error}"),
                snapshot: None,
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = request_id;
        HardwareSnapshotResult {
            reachable: false,
            reason: "Forge hardware service requires Windows".to_owned(),
            snapshot: None,
        }
    }
}

#[tauri::command]
fn hardware_run_command(input: HardwareRunCommandInput) -> HardwareSnapshotResult {
    #[cfg(windows)]
    {
        let request = (|| {
            Ok(forge_acqd::OperatorRunRequestV1 {
                request_id: input.request_id,
                epoch: input.epoch,
                command: match input.command {
                    1 => forge_acqd::run::RunCommandKind::Prepare,
                    2 => forge_acqd::run::RunCommandKind::Arm,
                    3 => forge_acqd::run::RunCommandKind::Start,
                    4 => forge_acqd::run::RunCommandKind::Stop,
                    5 => forge_acqd::run::RunCommandKind::Abort,
                    _ => return Err("invalid hardware Run command".to_owned()),
                },
                relative_deadline_ms: input.relative_deadline_ms,
                run_id: decode_hex(&input.run_id_hex)?,
                target_device_id: decode_hex(&input.target_device_id_hex)?,
                frozen_config_hash: decode_hex(&input.frozen_config_hash_hex)?,
                expected_hardware_state_hash: decode_hex(&input.expected_hardware_state_hash_hex)?,
            })
        })();
        let request = match request {
            Ok(request) => request,
            Err(reason) => {
                return HardwareSnapshotResult {
                    reachable: false,
                    reason,
                    snapshot: None,
                }
            }
        };
        match forge_acqd::call_hardware_run_command(
            forge_acqd::windows_service_host::DEFAULT_HARDWARE_PIPE_NAME,
            request,
            250,
            12_000,
        ) {
            Ok(snapshot) => HardwareSnapshotResult {
                reachable: true,
                reason: format!("hardware service responded: {:?}", snapshot.error_code),
                snapshot: Some(snapshot.into()),
            },
            Err(error) => HardwareSnapshotResult {
                reachable: false,
                reason: format!("Forge hardware service unavailable: {error}"),
                snapshot: None,
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = input;
        HardwareSnapshotResult {
            reachable: false,
            reason: "Forge hardware service requires Windows".to_owned(),
            snapshot: None,
        }
    }
}

#[tauri::command]
async fn software_replay_launch(
    input: SoftwareReplayLaunchInput,
) -> Result<SoftwareReplayReservationView, String> {
    #[cfg(windows)]
    {
        tauri::async_runtime::spawn_blocking(move || launch_software_replay_blocking(input))
            .await
            .map_err(|error| format!("software replay launcher task failed: {error}"))?
    }
    #[cfg(not(windows))]
    {
        let _ = input;
        Err("software replay daemon requires Windows".to_owned())
    }
}

#[cfg(windows)]
fn launch_software_replay_blocking(
    input: SoftwareReplayLaunchInput,
) -> Result<SoftwareReplayReservationView, String> {
    let run_id = decode_hex::<16>(&input.run_id_hex)?;
    let target_group_id = decode_hex::<16>(&input.target_group_id_hex)?;
    let frozen_config_hash = decode_hex::<32>(&input.frozen_config_hash_hex)?;
    if run_id == [0; 16] || target_group_id == [0; 16] || frozen_config_hash == [0; 32] {
        return Err("software replay Run identities must be nonzero".to_owned());
    }
    if input.requested_directory.trim().is_empty()
        || input.base_name.trim() != input.base_name
        || input.base_name.is_empty()
        || input.selected_device_ids.is_empty()
        || input.selected_device_ids.len() > 8
        || input
            .selected_device_ids
            .iter()
            .any(|value| value.trim() != value || value.is_empty())
        || input
            .selected_device_ids
            .iter()
            .enumerate()
            .any(|(index, value)| input.selected_device_ids[..index].contains(value))
    {
        return Err("software replay launch plan is malformed".to_owned());
    }
    let requested_directory = PathBuf::from(&input.requested_directory);
    if !requested_directory.is_absolute() {
        return Err("software replay requested directory must be absolute".to_owned());
    }

    let pipe_name = format!(r"\\.\pipe\forge-acqd-software-replay-{}", input.run_id_hex);
    validate_software_pipe_name(&pipe_name)?;
    let operator_sid = forge_acqd::ipc::current_process_user_sid()
        .map_err(|error| format!("cannot read current operator SID: {error}"))?;
    let executable = locate_forge_acqd()?;
    let ready_receipt = std::env::temp_dir().join(format!(
        "forge-software-replay-ready-{}-{}.json",
        std::process::id(),
        input.run_id_hex
    ));
    if ready_receipt.exists() {
        return Err("software replay ready receipt path already exists".to_owned());
    }

    let mut command = Command::new(&executable);
    command
        .arg("software-replay-service")
        .arg("--requested-directory")
        .arg(&requested_directory)
        .arg("--base-name")
        .arg(&input.base_name)
        .arg("--run-id")
        .arg(&input.run_id_hex)
        .arg("--target-group-id")
        .arg(&input.target_group_id_hex)
        .arg("--frozen-config-hash")
        .arg(&input.frozen_config_hash_hex)
        .arg("--pipe")
        .arg(&pipe_name)
        .arg("--operator-sid")
        .arg(&operator_sid)
        .arg("--ready-receipt")
        .arg(&ready_receipt)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Windows child processes are not tied to the parent lifetime. A new
        // process group plus CREATE_NO_WINDOW keeps this independent recorder
        // alive without presenting a console when the GUI exits.
        .creation_flags(0x0000_0200 | 0x0800_0000);
    for device_id in &input.selected_device_ids {
        command.arg("--selected-device").arg(device_id);
    }
    let child = command.spawn().map_err(|error| {
        format!(
            "cannot start independent forge-acqd software process at {}: {error}",
            executable.display()
        )
    })?;
    let mut pending = PendingSoftwareReplayLaunch::new(child, ready_receipt);
    let process_id = pending.child_mut().id();
    if process_id == 0 {
        return Err("software replay child returned a zero process ID".to_owned());
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    let ready = loop {
        if pending.ready_receipt().is_file() {
            let bytes = fs::read(pending.ready_receipt())
                .map_err(|error| format!("cannot read software replay ready receipt: {error}"))?;
            break serde_json::from_slice::<
                forge_acqd::software_replay_service::SoftwareReplayReservationV1,
            >(&bytes)
            .map_err(|error| format!("software replay ready receipt is malformed: {error}"))?;
        }
        if let Some(status) = pending
            .child_mut()
            .try_wait()
            .map_err(|error| format!("cannot query software replay child: {error}"))?
        {
            return Err(format!(
                "forge-acqd software replay exited before readiness with {status}"
            ));
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for software replay readiness receipt".to_owned());
        }
        thread::sleep(Duration::from_millis(25));
    };

    validate_software_ready_receipt(
        &ready,
        &input,
        &requested_directory,
        &pipe_name,
        &operator_sid,
        process_id,
    )?;
    let view = SoftwareReplayReservationView {
        schema: "forge.software-replay-reservation.v1",
        reservation_id: format!("SOFTWARE-{}", &ready.evidence_hash_hex[..16]),
        run_id_hex: ready.run_id_hex,
        pipe_name: ready.pipe_name,
        requested_directory: input.requested_directory,
        allocated_leaf_name: ready.allocated_leaf,
        resolved_run_directory: display_path(&ready.resolved_run_directory)?,
        journal_file_name: "run.forgewal",
        selected_device_ids: ready.selected_device_ids,
        directory_create_disposition: "created_new",
        journal_create_disposition: "not_created",
        overwrite_policy: "forbid",
        scope: "software",
        synthetic: true,
        process_id,
        evidence_hash: ready.evidence_hash_hex,
    };
    pending.commit();
    Ok(view)
}

/// Owns only a launch that has not yet returned a validated reservation. Once
/// committed, dropping the Windows `Child` handle deliberately leaves the
/// independent recorder alive. Every earlier error terminates and reaps this
/// exact process and removes only this launch's temporary readiness handoff.
#[cfg(windows)]
struct PendingSoftwareReplayLaunch {
    child: Option<Child>,
    ready_receipt: PathBuf,
}

#[cfg(windows)]
impl PendingSoftwareReplayLaunch {
    fn new(child: Child, ready_receipt: PathBuf) -> Self {
        Self {
            child: Some(child),
            ready_receipt,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child
            .as_mut()
            .expect("pending software replay launch must own its child")
    }

    fn ready_receipt(&self) -> &Path {
        &self.ready_receipt
    }

    fn commit(mut self) {
        drop(self.child.take());
        let _ = fs::remove_file(&self.ready_receipt);
    }
}

#[cfg(windows)]
impl Drop for PendingSoftwareReplayLaunch {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_file(&self.ready_receipt);
    }
}

#[cfg(windows)]
fn locate_forge_acqd() -> Result<PathBuf, String> {
    let current = std::env::current_exe()
        .map_err(|error| format!("cannot locate Forge Acquire executable: {error}"))?;
    let sibling = current
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("forge-acqd.exe");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        sibling,
        manifest.join(r"..\recording-daemon\target\debug\forge-acqd.exe"),
        manifest.join(r"..\recording-daemon\target\release\forge-acqd.exe"),
    ];
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            "forge-acqd.exe is not built beside the app or in recording-daemon/target; run cargo build --locked --manifest-path recording-daemon/Cargo.toml".to_owned()
        })
}

#[cfg(windows)]
fn validate_software_ready_receipt(
    ready: &forge_acqd::software_replay_service::SoftwareReplayReservationV1,
    input: &SoftwareReplayLaunchInput,
    requested_directory: &Path,
    pipe_name: &str,
    operator_sid: &str,
    process_id: u32,
) -> Result<(), String> {
    forge_acqd::software_replay_service::verify_software_replay_reservation(ready)
        .map_err(|error| format!("software replay readiness evidence is invalid: {error}"))?;
    let canonical_requested = fs::canonicalize(requested_directory)
        .map_err(|error| format!("cannot canonicalize daemon-created Run root: {error}"))?;
    if ready.run_id_hex != input.run_id_hex
        || ready.target_group_id_hex != input.target_group_id_hex
        || ready.frozen_config_hash_hex != input.frozen_config_hash_hex
        || ready.pipe_name != pipe_name
        || ready.operator_sid != operator_sid
        || ready.process_id != process_id
        || ready.requested_directory != requested_directory
        || ready.resolved_run_directory.parent() != Some(canonical_requested.as_path())
        || ready.selected_device_ids != input.selected_device_ids
    {
        return Err(
            "software replay readiness receipt contradicted the requested boundary".to_owned(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn display_path(path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| "software replay path is not valid UTF-8".to_owned())?;
    if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        return Ok(format!(r"\\{rest}"));
    }
    Ok(value.strip_prefix(r"\\?\").unwrap_or(value).to_owned())
}

#[tauri::command]
fn software_replay_snapshot(
    pipe_name: String,
    request_id: u64,
    epoch: u64,
) -> DaemonSnapshotResult {
    #[cfg(windows)]
    {
        if let Err(reason) = validate_software_pipe_name(&pipe_name) {
            return DaemonSnapshotResult {
                available: false,
                reason,
                snapshot: None,
            };
        }
        match forge_acqd::query_software_replay_snapshot(&pipe_name, request_id, epoch, 250, 750) {
            Ok(snapshot) => DaemonSnapshotResult {
                available: true,
                reason: "authenticated current-user software replay snapshot".to_owned(),
                snapshot: Some(snapshot.into()),
            },
            Err(error) => DaemonSnapshotResult {
                available: false,
                reason: format!("software replay daemon unavailable: {error}"),
                snapshot: None,
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (pipe_name, request_id, epoch);
        DaemonSnapshotResult {
            available: false,
            reason: "software replay daemon requires Windows".to_owned(),
            snapshot: None,
        }
    }
}

#[tauri::command]
fn software_replay_run_command(
    pipe_name: String,
    input: DaemonRunCommandInput,
) -> DaemonSnapshotResult {
    #[cfg(windows)]
    {
        if let Err(reason) = validate_software_pipe_name(&pipe_name) {
            return DaemonSnapshotResult {
                available: false,
                reason,
                snapshot: None,
            };
        }
        let body = (|| {
            Ok(forge_protocol_v1::RunCommandV1 {
                command: input.command,
                scope: 1,
                run_id: decode_hex(&input.run_id_hex)?,
                target_device_id: decode_hex(&input.target_device_id_hex)?,
                deadline_global_time_ns: u64::MAX,
                frozen_config_hash: decode_hex(&input.frozen_config_hash_hex)?,
            })
        })();
        let body = match body {
            Ok(body) => body,
            Err(reason) => {
                return DaemonSnapshotResult {
                    available: false,
                    reason,
                    snapshot: None,
                }
            }
        };
        match forge_acqd::call_software_replay_run_command(
            &pipe_name,
            input.request_id,
            input.epoch,
            &body,
            250,
            12_000,
        ) {
            Ok(snapshot) => DaemonSnapshotResult {
                available: true,
                reason: snapshot.reason.clone(),
                snapshot: Some(snapshot.into()),
            },
            Err(error) => DaemonSnapshotResult {
                available: false,
                reason: format!("software replay daemon unavailable: {error}"),
                snapshot: None,
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (pipe_name, input);
        DaemonSnapshotResult {
            available: false,
            reason: "software replay daemon requires Windows".to_owned(),
            snapshot: None,
        }
    }
}

#[cfg(windows)]
fn validate_software_pipe_name(value: &str) -> Result<(), String> {
    const PREFIX: &str = r"\\.\pipe\forge-acqd-software-replay-";
    let suffix = value
        .strip_prefix(PREFIX)
        .ok_or_else(|| "software replay pipe is outside the dedicated namespace".to_owned())?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("software replay pipe suffix must be one lowercase 16-byte Run ID".to_owned());
    }
    Ok(())
}

#[cfg(windows)]
fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "expected {} lowercase hexadecimal characters",
            N * 2
        ));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "Run identity contains non-hexadecimal characters".to_owned())?;
    }
    Ok(output)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            daemon_snapshot,
            daemon_run_command,
            hardware_snapshot,
            hardware_run_command,
            software_replay_launch,
            software_replay_snapshot,
            software_replay_run_command
        ])
        .run(tauri::generate_context!())
        .expect("error while running Forge Acquire");
}
