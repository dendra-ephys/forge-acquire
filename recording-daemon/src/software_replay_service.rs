//! Current-user operator service for real on-disk software/synthetic Runs.
//!
//! This is intentionally not the production SCM service and never exposes a
//! hardware claim. It exists so the GUI can exercise an independent process,
//! authenticated local IPC, create-new Run allocation, journal durability and
//! sealing before physical acquisition is qualified.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use forge_protocol_v1::{decode_low_speed, sha256, MessageKind, RunCommandV1, WireBody};
use serde::{Deserialize, Serialize};

use crate::ipc::{canonical_sid_string, current_process_user_sid, SecurePipeServer};
use crate::run::{RunCommandKind, RunState};
use crate::service_protocol::{DaemonResponseV1, ServiceDispatcher, ServiceErrorV1};

pub const SOFTWARE_REPLAY_RESERVATION_SCHEMA: &str = "forge.software-replay-reservation.v1";
pub const SOFTWARE_REPLAY_JOURNAL_FILENAME: &str = "run.forgewal";
pub const SOFTWARE_REPLAY_LEDGER_FILENAME: &str = "run.ledger";
pub const SOFTWARE_REPLAY_RESERVATION_FILENAME: &str = "software-replay-reservation.json";
const MAX_SELECTED_DEVICES: usize = 8;
const MAX_BASE_NAME_CHARS: usize = 80;
const MAX_DEVICE_ID_BYTES: usize = 256;
const MAX_ALLOCATION_ATTEMPTS: u32 = 999_999;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareReplayServiceOptions {
    pub requested_directory: PathBuf,
    pub base_name: String,
    pub run_id: [u8; 16],
    pub target_group_id: [u8; 16],
    pub frozen_config_hash: [u8; 32],
    pub pipe_name: String,
    pub operator_sid: String,
    pub selected_device_ids: Vec<String>,
    pub ready_receipt_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareReplayReservationV1 {
    pub schema: String,
    pub status: String,
    pub run_id_hex: String,
    pub target_group_id_hex: String,
    pub frozen_config_hash_hex: String,
    pub pipe_name: String,
    pub operator_sid: String,
    pub process_id: u32,
    pub created_unix_ms: u64,
    pub requested_directory: PathBuf,
    pub allocated_leaf: String,
    pub resolved_run_directory: PathBuf,
    pub journal_filename: String,
    pub ledger_filename: String,
    pub reservation_filename: String,
    pub selected_device_ids: Vec<String>,
    pub selected_pod_ids_hex: Vec<String>,
    pub channel_count_per_device: u16,
    pub samples_per_channel_per_block: u32,
    pub sample_rate_hz: u32,
    pub source_kind: String,
    pub synthetic: bool,
    pub software_only: bool,
    pub hardware_transport_available: bool,
    pub hardware_verified: bool,
    pub authenticated_pipe: bool,
    pub scm_owned: bool,
    pub protected_replay_available: bool,
    pub overwrite_policy: String,
    pub evidence_hash_hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReservationEvidence<'a> {
    schema: &'a str,
    run_id_hex: &'a str,
    target_group_id_hex: &'a str,
    frozen_config_hash_hex: &'a str,
    pipe_name: &'a str,
    operator_sid: &'a str,
    process_id: u32,
    created_unix_ms: u64,
    requested_directory: &'a Path,
    allocated_leaf: &'a str,
    resolved_run_directory: &'a Path,
    journal_filename: &'a str,
    ledger_filename: &'a str,
    selected_device_ids: &'a [String],
    selected_pod_ids_hex: &'a [String],
    channel_count_per_device: u16,
    samples_per_channel_per_block: u32,
    sample_rate_hz: u32,
    source_kind: &'a str,
    synthetic: bool,
    software_only: bool,
    hardware_transport_available: bool,
    hardware_verified: bool,
    authenticated_pipe: bool,
    scm_owned: bool,
    protected_replay_available: bool,
    overwrite_policy: &'a str,
}

pub struct PreparedSoftwareReplayService {
    reservation: SoftwareReplayReservationV1,
    pipe: SecurePipeServer,
    dispatcher: ServiceDispatcher,
}

impl PreparedSoftwareReplayService {
    pub fn reservation(&self) -> &SoftwareReplayReservationV1 {
        &self.reservation
    }

    /// Blocks in the independent daemon process. If the listener fails or is
    /// explicitly stopped, owner shutdown fail-closes any active unsealed Run.
    pub fn serve(mut self) -> io::Result<u64> {
        let exit_after_fack = AtomicBool::new(false);
        let transactions = self
            .pipe
            .run_until_acknowledged_transaction_flag_authenticated(
                &exit_after_fack,
                |_, request| {
                    let response = self.dispatcher.handle(request)?;
                    if accepted_terminal_response(request, &response) {
                        exit_after_fack.store(true, Ordering::Release);
                    }
                    Ok(response)
                },
            );
        let shutdown = self.dispatcher.shutdown();
        match (transactions, shutdown) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }
}

/// A software daemon exits only after the exact accepted Stop response reports
/// `JournalSealed`, an accepted cleanup Abort reports `Aborted`, or an accepted
/// failure acknowledgement reports the durably reset `New` state. The pipe
/// loop observes this flag only after its unpredictable response challenge has
/// been consumption-acknowledged by the client.
fn accepted_terminal_response(request: &[u8], response: &[u8]) -> bool {
    let Ok(decoded) = decode_low_speed(request) else {
        return false;
    };
    if decoded.kind != MessageKind::RunCommand {
        return false;
    }
    let Ok(command) = RunCommandV1::decode_body(&decoded.body) else {
        return false;
    };
    let terminal_state = if command.command == RunCommandKind::Stop.wire_value() {
        RunState::JournalSealed
    } else if command.command == RunCommandKind::Abort.wire_value() {
        RunState::Aborted
    } else if command.command == RunCommandKind::AcknowledgeFailure.wire_value() {
        RunState::New
    } else {
        return false;
    };
    let Ok(snapshot) = DaemonResponseV1::decode(response) else {
        return false;
    };
    snapshot.request_id == decoded.request_id
        && snapshot.epoch == decoded.epoch
        && snapshot.accepted
        && snapshot.error == ServiceErrorV1::None
        && snapshot.state == terminal_state
}

/// Reserves the Run namespace, opens the durable ledger and run-bound replay
/// session, binds the current-user-only pipe, and publishes both reservation
/// receipts. It does not create `run.forgewal`; the accepted Prepare command
/// owns that create-new transition.
pub fn prepare_software_replay_service(
    options: SoftwareReplayServiceOptions,
) -> io::Result<PreparedSoftwareReplayService> {
    validate_options(&options)?;
    let operator_sid = canonical_sid_string(&options.operator_sid)?;
    if operator_sid != current_process_user_sid()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "software replay operator SID is not the current process user",
        ));
    }

    let requested_directory_input = options.requested_directory.clone();
    fs::create_dir_all(&options.requested_directory)?;
    if !options.requested_directory.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "requested software replay directory is not a directory",
        ));
    }
    let requested_directory_root = fs::canonicalize(&options.requested_directory)?;
    let (allocated_leaf, run_directory) =
        allocate_run_directory(&requested_directory_root, &options.base_name)?;
    let resolved_run_directory = fs::canonicalize(&run_directory)?;

    let pod_ids = options
        .selected_device_ids
        .iter()
        .map(|device_id| pod_id_for_device(device_id))
        .collect::<Vec<_>>();
    let selected_pod_ids_hex = pod_ids.iter().map(|value| hex(value)).collect::<Vec<_>>();
    let ledger_path = resolved_run_directory.join(SOFTWARE_REPLAY_LEDGER_FILENAME);
    let dispatcher = ServiceDispatcher::open_operator_software_replay(
        &ledger_path,
        &resolved_run_directory,
        options.run_id,
        options.target_group_id,
        options.frozen_config_hash,
        pod_ids,
    )?;
    let pipe = SecurePipeServer::bind_software_replay(&options.pipe_name, &operator_sid)?;

    let created_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::Error::other("system clock predates Unix epoch"))?
            .as_millis(),
    )
    .map_err(|_| io::Error::other("software replay timestamp overflow"))?;
    let run_id_hex = hex(&options.run_id);
    let target_group_id_hex = hex(&options.target_group_id);
    let frozen_config_hash_hex = hex(&options.frozen_config_hash);
    let evidence = ReservationEvidence {
        schema: SOFTWARE_REPLAY_RESERVATION_SCHEMA,
        run_id_hex: &run_id_hex,
        target_group_id_hex: &target_group_id_hex,
        frozen_config_hash_hex: &frozen_config_hash_hex,
        pipe_name: &options.pipe_name,
        operator_sid: &operator_sid,
        process_id: std::process::id(),
        created_unix_ms,
        requested_directory: &requested_directory_input,
        allocated_leaf: &allocated_leaf,
        resolved_run_directory: &resolved_run_directory,
        journal_filename: SOFTWARE_REPLAY_JOURNAL_FILENAME,
        ledger_filename: SOFTWARE_REPLAY_LEDGER_FILENAME,
        selected_device_ids: &options.selected_device_ids,
        selected_pod_ids_hex: &selected_pod_ids_hex,
        channel_count_per_device: 32,
        samples_per_channel_per_block: 30,
        sample_rate_hz: 30_000,
        source_kind: "deterministic_synthetic_canonical_sample_block",
        synthetic: true,
        software_only: true,
        hardware_transport_available: false,
        hardware_verified: false,
        authenticated_pipe: true,
        scm_owned: false,
        protected_replay_available: true,
        overwrite_policy: "forbid",
    };
    let evidence_hash_hex = hex(&sha256(&serde_json::to_vec(&evidence).map_err(json_error)?));
    let reservation = SoftwareReplayReservationV1 {
        schema: SOFTWARE_REPLAY_RESERVATION_SCHEMA.to_owned(),
        status: "reserved_ready".to_owned(),
        run_id_hex,
        target_group_id_hex,
        frozen_config_hash_hex,
        pipe_name: options.pipe_name,
        operator_sid,
        process_id: std::process::id(),
        created_unix_ms,
        requested_directory: requested_directory_input,
        allocated_leaf,
        resolved_run_directory,
        journal_filename: SOFTWARE_REPLAY_JOURNAL_FILENAME.to_owned(),
        ledger_filename: SOFTWARE_REPLAY_LEDGER_FILENAME.to_owned(),
        reservation_filename: SOFTWARE_REPLAY_RESERVATION_FILENAME.to_owned(),
        selected_device_ids: options.selected_device_ids,
        selected_pod_ids_hex,
        channel_count_per_device: 32,
        samples_per_channel_per_block: 30,
        sample_rate_hz: 30_000,
        source_kind: "deterministic_synthetic_canonical_sample_block".to_owned(),
        synthetic: true,
        software_only: true,
        hardware_transport_available: false,
        hardware_verified: false,
        authenticated_pipe: true,
        scm_owned: false,
        protected_replay_available: true,
        overwrite_policy: "forbid".to_owned(),
        evidence_hash_hex,
    };
    let bytes = serde_json::to_vec_pretty(&reservation).map_err(json_error)?;
    write_new_durable(
        &reservation
            .resolved_run_directory
            .join(SOFTWARE_REPLAY_RESERVATION_FILENAME),
        &bytes,
    )?;
    publish_new_atomically(&options.ready_receipt_path, &bytes)?;

    Ok(PreparedSoftwareReplayService {
        reservation,
        pipe,
        dispatcher,
    })
}

/// Strictly validates an owned ready receipt before a Tauri caller trusts its
/// pipe or Run paths. The hash is an integrity/evidence digest, not a secret
/// signature; endpoint authenticity still comes from the current-user SID
/// DACL plus per-client TokenUser verification on every transaction.
pub fn verify_software_replay_reservation(
    reservation: &SoftwareReplayReservationV1,
) -> io::Result<()> {
    if reservation.schema != SOFTWARE_REPLAY_RESERVATION_SCHEMA
        || reservation.status != "reserved_ready"
        || reservation.journal_filename != SOFTWARE_REPLAY_JOURNAL_FILENAME
        || reservation.ledger_filename != SOFTWARE_REPLAY_LEDGER_FILENAME
        || reservation.reservation_filename != SOFTWARE_REPLAY_RESERVATION_FILENAME
        || reservation.source_kind != "deterministic_synthetic_canonical_sample_block"
        || reservation.overwrite_policy != "forbid"
        || !reservation.synthetic
        || !reservation.software_only
        || reservation.hardware_transport_available
        || reservation.hardware_verified
        || !reservation.authenticated_pipe
        || reservation.scm_owned
        || !reservation.protected_replay_available
        || reservation.channel_count_per_device != 32
        || reservation.samples_per_channel_per_block != 30
        || reservation.sample_rate_hz != 30_000
        || reservation.process_id == 0
        || reservation.created_unix_ms == 0
        || !reservation
            .pipe_name
            .starts_with(crate::ipc::SOFTWARE_REPLAY_PIPE_PREFIX)
        || !reservation.requested_directory.is_absolute()
        || !reservation.resolved_run_directory.is_absolute()
        || reservation
            .resolved_run_directory
            .file_name()
            .and_then(|value| value.to_str())
            != Some(reservation.allocated_leaf.as_str())
        || !valid_nonzero_hex(&reservation.run_id_hex, 16)
        || !valid_nonzero_hex(&reservation.target_group_id_hex, 16)
        || !valid_nonzero_hex(&reservation.frozen_config_hash_hex, 32)
        || reservation.selected_device_ids.is_empty()
        || reservation.selected_device_ids.len() > MAX_SELECTED_DEVICES
        || reservation.selected_device_ids.len() != reservation.selected_pod_ids_hex.len()
        || reservation
            .selected_device_ids
            .iter()
            .zip(&reservation.selected_pod_ids_hex)
            .any(|(device_id, pod_hex)| hex(&pod_id_for_device(device_id)) != *pod_hex)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "software replay reservation fields are contradictory or outside the operator contract",
        ));
    }
    let canonical_sid = canonical_sid_string(&reservation.operator_sid)?;
    if canonical_sid != reservation.operator_sid || canonical_sid != current_process_user_sid()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "software replay reservation operator SID is not the current user",
        ));
    }
    let evidence = ReservationEvidence {
        schema: &reservation.schema,
        run_id_hex: &reservation.run_id_hex,
        target_group_id_hex: &reservation.target_group_id_hex,
        frozen_config_hash_hex: &reservation.frozen_config_hash_hex,
        pipe_name: &reservation.pipe_name,
        operator_sid: &reservation.operator_sid,
        process_id: reservation.process_id,
        created_unix_ms: reservation.created_unix_ms,
        requested_directory: &reservation.requested_directory,
        allocated_leaf: &reservation.allocated_leaf,
        resolved_run_directory: &reservation.resolved_run_directory,
        journal_filename: &reservation.journal_filename,
        ledger_filename: &reservation.ledger_filename,
        selected_device_ids: &reservation.selected_device_ids,
        selected_pod_ids_hex: &reservation.selected_pod_ids_hex,
        channel_count_per_device: reservation.channel_count_per_device,
        samples_per_channel_per_block: reservation.samples_per_channel_per_block,
        sample_rate_hz: reservation.sample_rate_hz,
        source_kind: &reservation.source_kind,
        synthetic: reservation.synthetic,
        software_only: reservation.software_only,
        hardware_transport_available: reservation.hardware_transport_available,
        hardware_verified: reservation.hardware_verified,
        authenticated_pipe: reservation.authenticated_pipe,
        scm_owned: reservation.scm_owned,
        protected_replay_available: reservation.protected_replay_available,
        overwrite_policy: &reservation.overwrite_policy,
    };
    let expected = hex(&sha256(&serde_json::to_vec(&evidence).map_err(json_error)?));
    if reservation.evidence_hash_hex != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "software replay reservation evidence hash mismatch",
        ));
    }
    Ok(())
}

fn validate_options(options: &SoftwareReplayServiceOptions) -> io::Result<()> {
    if !options.requested_directory.is_absolute()
        || !options.ready_receipt_path.is_absolute()
        || options.run_id == [0; 16]
        || options.target_group_id == [0; 16]
        || options.frozen_config_hash == [0; 32]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "software replay paths and Run context must be absolute/nonzero",
        ));
    }
    validate_base_name(&options.base_name)?;
    if options.selected_device_ids.is_empty()
        || options.selected_device_ids.len() > MAX_SELECTED_DEVICES
        || options.selected_device_ids.iter().any(|value| {
            value.trim() != value
                || value.is_empty()
                || value.len() > MAX_DEVICE_ID_BYTES
                || value.chars().any(char::is_control)
        })
        || options
            .selected_device_ids
            .iter()
            .enumerate()
            .any(|(index, value)| options.selected_device_ids[..index].contains(value))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "software replay requires one to eight unique bounded device IDs",
        ));
    }
    let ready_parent = options.ready_receipt_path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "ready receipt has no parent")
    })?;
    if !ready_parent.is_dir() || options.ready_receipt_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "ready receipt parent must exist and the receipt must not already exist",
        ));
    }
    Ok(())
}

fn validate_base_name(value: &str) -> io::Result<()> {
    let mut components = Path::new(value).components();
    let single_normal =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    let upper_stem = value
        .trim_end_matches(['.', ' '])
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let windows_reserved = matches!(upper_stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper_stem.len() == 4
            && matches!(&upper_stem[..3], "COM" | "LPT")
            && matches!(upper_stem.as_bytes()[3], b'1'..=b'9'));
    if !single_normal
        || value == "."
        || value == ".."
        || value.chars().count() > MAX_BASE_NAME_CHARS
        || value.ends_with(['.', ' '])
        || value.chars().any(char::is_control)
        || windows_reserved
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "base name must be one safe, non-reserved Run-directory component",
        ));
    }
    Ok(())
}

fn allocate_run_directory(root: &Path, base_name: &str) -> io::Result<(String, PathBuf)> {
    for index in 1..=MAX_ALLOCATION_ATTEMPTS {
        let leaf = format!("{base_name}-{index:03}");
        let path = root.join(&leaf);
        match fs::create_dir(&path) {
            Ok(()) => return Ok((leaf, path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "software replay Run-directory sequence is exhausted",
    ))
}

fn pod_id_for_device(device_id: &str) -> [u8; 16] {
    let mut identity_material = b"forge.software-replay.pod.v1\0".to_vec();
    identity_material.extend_from_slice(device_id.as_bytes());
    let digest = sha256(&identity_material);
    let mut pod_id = [0_u8; 16];
    pod_id.copy_from_slice(&digest[..16]);
    pod_id
}

fn valid_nonzero_hex(value: &str, byte_len: usize) -> bool {
    value.len() == byte_len * 2
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0')
}

fn write_new_durable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn publish_new_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "receipt path has no parent"))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "receipt filename is not UTF-8")
        })?;
    let temp = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    write_new_durable(&temp, bytes)?;
    match fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temp);
            Err(error)
        }
    }
}

fn json_error(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "forge-software-replay-service-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn allocation_starts_at_one_and_never_reuses_an_existing_leaf() {
        let root = TempRoot::new();
        let first = allocate_run_directory(&root.0, "FORGE-RUN").unwrap();
        let second = allocate_run_directory(&root.0, "FORGE-RUN").unwrap();
        assert_eq!(first.0, "FORGE-RUN-001");
        assert_eq!(second.0, "FORGE-RUN-002");
        assert_ne!(first.1, second.1);
    }

    #[test]
    fn device_mapping_is_stable_and_separates_ids() {
        assert_eq!(pod_id_for_device("pod-a"), pod_id_for_device("pod-a"));
        assert_ne!(pod_id_for_device("pod-a"), pod_id_for_device("pod-b"));
    }

    #[test]
    fn unsafe_or_reserved_leaf_names_are_rejected() {
        for name in ["", ".", "..", "a/b", r"a\b", "CON", "com1.txt", "trail."] {
            assert!(validate_base_name(name).is_err(), "accepted {name:?}");
        }
        assert!(validate_base_name("FORGE-RUN").is_ok());
    }

    #[test]
    fn ready_receipt_round_trips_and_detects_tampering() {
        let root = TempRoot::new();
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let ready = root.0.join("ready.json");
        let service = prepare_software_replay_service(SoftwareReplayServiceOptions {
            requested_directory: root.0.join("runs"),
            base_name: "FORGE-RUN".to_owned(),
            run_id: [0x11; 16],
            target_group_id: [0x22; 16],
            frozen_config_hash: [0x33; 32],
            pipe_name: format!(
                "{}{}-{}",
                crate::ipc::SOFTWARE_REPLAY_PIPE_PREFIX,
                std::process::id(),
                sequence
            ),
            operator_sid: current_process_user_sid().unwrap(),
            selected_device_ids: vec!["direct-pod-a".to_owned(), "aggregated-pod-b".to_owned()],
            ready_receipt_path: ready.clone(),
        })
        .unwrap();
        let bytes = fs::read(&ready).unwrap();
        let mut decoded: SoftwareReplayReservationV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(&decoded, service.reservation());
        verify_software_replay_reservation(&decoded).unwrap();
        assert!(!decoded.resolved_run_directory.join("run.forgewal").exists());
        decoded.selected_device_ids[0].push_str("-tampered");
        assert!(verify_software_replay_reservation(&decoded).is_err());
    }
}
