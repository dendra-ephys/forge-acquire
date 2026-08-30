use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::process::{Child, Command, Stdio};
#[cfg(windows)]
use std::thread;
#[cfg(windows)]
use std::time::{Duration, Instant};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;

const RUN_DIRECTORY_SCHEMA: &str = "forge.run-directory-listing.v1";
const RUN_DIRECTORY_ERROR_SCHEMA: &str = "forge.run-directory-error.v1";
const RUN_DIRECTORY_ENTRY_LIMIT: usize = 128;
const RUN_DIRECTORY_SCAN_LIMIT: usize = 2_048;
const RUN_DIRECTORY_MAX_UTF16: usize = 32_767;

#[derive(Default)]
struct RunDirectoryBrowserState {
    busy: Arc<AtomicBool>,
}

#[derive(Debug)]
struct RunDirectoryPermit {
    busy: Arc<AtomicBool>,
}

impl Drop for RunDirectoryPermit {
    fn drop(&mut self) {
        self.busy.store(false, Ordering::Release);
    }
}

impl RunDirectoryBrowserState {
    fn try_enter(&self, request_id: u32) -> Result<RunDirectoryPermit, RunDirectoryErrorView> {
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                RunDirectoryErrorView::new(
                    request_id,
                    "busy",
                    "Another directory request is still running.",
                    true,
                    None,
                )
            })?;
        Ok(RunDirectoryPermit {
            busy: Arc::clone(&self.busy),
        })
    }
}

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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowseRunRootInput {
    request_id: u32,
    directory: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDirectoryRootView {
    label: String,
    path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDirectoryEntryView {
    name: String,
    path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDirectoryListingView {
    schema: &'static str,
    request_id: u32,
    current_directory: String,
    parent_directory: Option<String>,
    roots: Vec<RunDirectoryRootView>,
    directories: Vec<RunDirectoryEntryView>,
    truncated: bool,
    entry_limit: usize,
    scanned_entries: usize,
    omitted_entries: usize,
    validation_scope: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDirectoryErrorView {
    schema: &'static str,
    request_id: u32,
    code: &'static str,
    message: String,
    retryable: bool,
    os_code: Option<i32>,
}

impl RunDirectoryErrorView {
    fn new(
        request_id: u32,
        code: &'static str,
        message: impl Into<String>,
        retryable: bool,
        os_code: Option<i32>,
    ) -> Self {
        Self {
            schema: RUN_DIRECTORY_ERROR_SCHEMA,
            request_id,
            code,
            message: message.into(),
            retryable,
            os_code,
        }
    }
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
async fn browse_run_root(
    state: tauri::State<'_, RunDirectoryBrowserState>,
    input: BrowseRunRootInput,
) -> Result<RunDirectoryListingView, RunDirectoryErrorView> {
    let request_id = input.request_id;
    let permit = state.try_enter(request_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        list_run_directories(request_id, &input.directory)
    })
    .await
    .map_err(|error| {
        RunDirectoryErrorView::new(
            request_id,
            "internal_error",
            format!("Directory browser worker failed: {error}"),
            true,
            None,
        )
    })?
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

fn selected_directory_display(path: &Path) -> Result<String, String> {
    #[cfg(windows)]
    {
        display_path(path)
    }
    #[cfg(not(windows))]
    {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| "selected Run folder is not valid UTF-8".to_owned())
    }
}

fn run_directory_io_error(
    request_id: u32,
    action: &str,
    error: std::io::Error,
) -> RunDirectoryErrorView {
    let (code, retryable) = match error.kind() {
        std::io::ErrorKind::NotFound => ("not_found", false),
        std::io::ErrorKind::PermissionDenied => ("access_denied", false),
        std::io::ErrorKind::InvalidInput => ("invalid_input", false),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => ("io_error", true),
        _ => ("io_error", true),
    };
    RunDirectoryErrorView::new(
        request_id,
        code,
        format!("Cannot {action}: {error}"),
        retryable,
        error.raw_os_error(),
    )
}

fn run_directory_display(request_id: u32, path: &Path) -> Result<String, RunDirectoryErrorView> {
    selected_directory_display(path).map_err(|message| {
        RunDirectoryErrorView::new(request_id, "path_not_unicode", message, false, None)
    })
}

fn validate_run_directory_input(
    request_id: u32,
    value: &str,
) -> Result<PathBuf, RunDirectoryErrorView> {
    if value.trim().is_empty() || value.contains('\0') {
        return Err(RunDirectoryErrorView::new(
            request_id,
            "invalid_input",
            "Directory path is empty or contains a NUL character.",
            false,
            None,
        ));
    }
    if value.encode_utf16().count() > RUN_DIRECTORY_MAX_UTF16 {
        return Err(RunDirectoryErrorView::new(
            request_id,
            "invalid_input",
            "Directory path exceeds the platform path limit.",
            false,
            None,
        ));
    }
    #[cfg(windows)]
    {
        let normalized = value.replace('/', "\\").to_ascii_lowercase();
        if normalized.starts_with(r"\\.\")
            || normalized.starts_with(r"\\?\")
            || normalized.starts_with(r"\??\")
            || normalized.contains("globalroot")
        {
            return Err(RunDirectoryErrorView::new(
                request_id,
                "unsupported_namespace",
                "Windows device namespaces are not accepted as Run roots.",
                false,
                None,
            ));
        }
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(RunDirectoryErrorView::new(
            request_id,
            "not_absolute",
            "Run root must be an absolute filesystem path.",
            false,
            None,
        ));
    }
    Ok(path)
}

fn list_run_directories(
    request_id: u32,
    requested: &str,
) -> Result<RunDirectoryListingView, RunDirectoryErrorView> {
    let requested_path = validate_run_directory_input(request_id, requested)?;
    let canonical = fs::canonicalize(&requested_path)
        .map_err(|error| run_directory_io_error(request_id, "open this directory", error))?;
    let metadata = fs::metadata(&canonical)
        .map_err(|error| run_directory_io_error(request_id, "inspect this directory", error))?;
    if !metadata.is_dir() {
        return Err(RunDirectoryErrorView::new(
            request_id,
            "not_directory",
            "The requested path is not a directory.",
            false,
            None,
        ));
    }

    let current_directory = run_directory_display(request_id, &canonical)?;
    let parent_directory = canonical
        .parent()
        .map(|parent| run_directory_display(request_id, parent))
        .transpose()?;
    let entries = fs::read_dir(&canonical)
        .map_err(|error| run_directory_io_error(request_id, "enumerate this directory", error))?;
    let mut directories = Vec::with_capacity(RUN_DIRECTORY_ENTRY_LIMIT);
    let mut scanned_entries = 0_usize;
    let mut omitted_entries = 0_usize;
    let mut truncated = false;

    for entry_result in entries {
        if scanned_entries >= RUN_DIRECTORY_SCAN_LIMIT {
            truncated = true;
            break;
        }
        scanned_entries += 1;
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_) => {
                omitted_entries += 1;
                continue;
            }
        };
        let is_directory = match entry.metadata() {
            Ok(metadata) => metadata.is_dir(),
            Err(_) => {
                omitted_entries += 1;
                continue;
            }
        };
        if !is_directory {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            omitted_entries += 1;
            continue;
        };
        if directories.len() >= RUN_DIRECTORY_ENTRY_LIMIT {
            truncated = true;
            omitted_entries += 1;
            continue;
        }
        let path = run_directory_display(request_id, &entry.path())?;
        directories.push(RunDirectoryEntryView { name, path });
    }
    directories.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.name.cmp(&right.name))
    });

    Ok(RunDirectoryListingView {
        schema: RUN_DIRECTORY_SCHEMA,
        request_id,
        current_directory,
        parent_directory,
        roots: run_directory_roots(),
        directories,
        truncated,
        entry_limit: RUN_DIRECTORY_ENTRY_LIMIT,
        scanned_entries,
        omitted_entries,
        validation_scope: "browse_only",
    })
}

#[cfg(windows)]
fn logical_drive_roots(mask: u32) -> Vec<RunDirectoryRootView> {
    (0_u8..26)
        .filter(|index| mask & (1_u32 << index) != 0)
        .map(|index| {
            let letter = char::from(b'A' + index);
            RunDirectoryRootView {
                label: format!("{letter}:"),
                path: format!("{letter}:\\"),
            }
        })
        .collect()
}

#[cfg(windows)]
fn run_directory_roots() -> Vec<RunDirectoryRootView> {
    // GetLogicalDrives returns a bitmask only. It does not enumerate Explorer,
    // query volume labels, load thumbnails, or invoke Shell extensions.
    logical_drive_roots(unsafe { GetLogicalDrives() })
}

#[cfg(not(windows))]
fn run_directory_roots() -> Vec<RunDirectoryRootView> {
    vec![RunDirectoryRootView {
        label: "/".to_owned(),
        path: "/".to_owned(),
    }]
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
        .manage(RunDirectoryBrowserState::default())
        .invoke_handler(tauri::generate_handler![
            browse_run_root,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "forge-run-directory-browser-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn run_directory_input_rejects_empty_relative_and_files() {
        assert_eq!(
            validate_run_directory_input(7, "").unwrap_err().code,
            "invalid_input"
        );
        assert_eq!(
            validate_run_directory_input(8, "relative/path")
                .unwrap_err()
                .code,
            "not_absolute"
        );

        let root = TestDirectory::new("file");
        let file_path = root.0.join("not-a-directory.txt");
        fs::File::create(&file_path)
            .expect("create file")
            .write_all(b"test")
            .expect("write file");
        assert_eq!(
            list_run_directories(9, file_path.to_str().expect("unicode path"))
                .unwrap_err()
                .code,
            "not_directory"
        );
    }

    #[cfg(windows)]
    #[test]
    fn run_directory_input_rejects_windows_device_namespaces() {
        for path in [r"\\.\PhysicalDrive0", r"\\?\C:\", r"\??\C:\"] {
            assert_eq!(
                validate_run_directory_input(10, path).unwrap_err().code,
                "unsupported_namespace"
            );
        }
    }

    #[test]
    fn listing_returns_only_sorted_direct_children() {
        let root = TestDirectory::new("children");
        fs::create_dir(root.0.join("Zulu")).expect("create Zulu");
        fs::create_dir(root.0.join("alpha")).expect("create alpha");
        fs::create_dir_all(root.0.join("alpha").join("nested")).expect("create nested");
        fs::File::create(root.0.join("samples.bin")).expect("create file");

        let listing = list_run_directories(11, root.0.to_str().expect("unicode path"))
            .expect("list directory");
        assert_eq!(listing.request_id, 11);
        assert_eq!(listing.validation_scope, "browse_only");
        assert_eq!(listing.directories.len(), 2);
        assert_eq!(listing.directories[0].name, "alpha");
        assert_eq!(listing.directories[1].name, "Zulu");
        assert!(listing
            .directories
            .iter()
            .all(|entry| !entry.path.ends_with("nested")));
        assert!(!listing.truncated);
    }

    #[test]
    fn listing_is_hard_bounded_and_reports_truncation() {
        let root = TestDirectory::new("bounded");
        for index in 0..=RUN_DIRECTORY_ENTRY_LIMIT {
            fs::create_dir(root.0.join(format!("D{index:03}"))).expect("create child");
        }
        let listing = list_run_directories(12, root.0.to_str().expect("unicode path"))
            .expect("list directory");
        assert_eq!(listing.directories.len(), RUN_DIRECTORY_ENTRY_LIMIT);
        assert!(listing.truncated);
        assert!(listing.omitted_entries >= 1);
        assert!(listing.scanned_entries <= RUN_DIRECTORY_SCAN_LIMIT);
    }

    #[test]
    fn browser_permit_refuses_overlap_and_releases_on_drop() {
        let state = RunDirectoryBrowserState::default();
        let permit = state.try_enter(13).expect("first permit");
        let busy = state.try_enter(14).unwrap_err();
        assert_eq!(busy.code, "busy");
        assert!(busy.retryable);
        drop(permit);
        assert!(state.try_enter(15).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn logical_drive_bitmask_is_mapped_without_volume_queries() {
        let roots = logical_drive_roots((1 << 2) | (1 << 5));
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].label, "C:");
        assert_eq!(roots[0].path, "C:\\");
        assert_eq!(roots[1].label, "F:");
        assert_eq!(roots[1].path, "F:\\");
    }
}
