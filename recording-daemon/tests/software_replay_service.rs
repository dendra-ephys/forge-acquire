#![cfg(windows)]

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use forge_acqd::ipc::{current_process_user_sid, SOFTWARE_REPLAY_PIPE_PREFIX};
use forge_acqd::journal::JournalReader;
use forge_acqd::run::RunState;
use forge_acqd::service_protocol::{DaemonResponseV1, ServiceErrorV1};
use forge_acqd::software_replay_service::{
    verify_software_replay_reservation, SoftwareReplayReservationV1,
};
use forge_acqd::{
    call_software_replay_control, call_software_replay_run_command, query_software_replay_snapshot,
    SoftwareReplayControlCommandV1, SoftwareReplayControlRequestV1,
};
use forge_protocol_v1::{
    encode_low_speed, RunCommandV1, SampleBlockV1, RECORD_FLAG_DISCONTINUITY_BEFORE,
};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "forge-software-replay-process-{}-{}",
            std::process::id(),
            monotonic_nonce()
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
fn independent_process_records_and_seals_two_software_devices() {
    let root = TempRoot::new();
    let runs = root.0.join("runs");
    let ready = root.0.join("ready.json");
    let pipe = format!(
        "{}{}-{}",
        SOFTWARE_REPLAY_PIPE_PREFIX,
        std::process::id(),
        monotonic_nonce()
    );
    let run_id = [0x11; 16];
    let target_group_id = [0x22; 16];
    let frozen_config_hash = [0x33; 32];
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_forge-acqd"))
            .args(["software-replay-service", "--requested-directory"])
            .arg(&runs)
            .args([
                "--base-name",
                "FORGE-RUN",
                "--run-id",
                &hex(&run_id),
                "--target-group-id",
                &hex(&target_group_id),
                "--frozen-config-hash",
                &hex(&frozen_config_hash),
                "--pipe",
                &pipe,
                "--operator-sid",
                &current_process_user_sid().unwrap(),
                "--selected-device",
                "direct-pod-a",
                "--selected-device",
                "aggregated-pod-b",
                "--ready-receipt",
            ])
            .arg(&ready)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );

    let reservation = wait_for_reservation(&ready, &mut child.0);
    verify_software_replay_reservation(&reservation).unwrap();
    assert_eq!(reservation.allocated_leaf, "FORGE-RUN-001");
    assert!(!reservation
        .resolved_run_directory
        .join("run.forgewal")
        .exists());

    let initial = query_software_replay_snapshot(&pipe, 1, 1, 5_000, 5_000).unwrap();
    assert_eq!(initial.state, RunState::New);
    for (request_id, command) in [(2, 1_u16), (3, 2), (4, 3)] {
        let response = call_software_replay_run_command(
            &pipe,
            request_id,
            1,
            &RunCommandV1 {
                command,
                scope: 1,
                run_id,
                target_device_id: target_group_id,
                deadline_global_time_ns: u64::MAX,
                frozen_config_hash,
            },
            5_000,
            5_000,
        )
        .unwrap();
        assert!(response.accepted, "{}", response.reason);
    }
    thread::sleep(Duration::from_millis(30));
    let recording = query_software_replay_snapshot(&pipe, 5, 1, 5_000, 5_000).unwrap();
    assert_eq!(recording.state, RunState::Recording);
    assert!(recording.generated_record_count.unwrap_or_default() > 0);
    assert!(child.0.try_wait().unwrap().is_none());

    let paused = call_software_replay_control(
        &pipe,
        &SoftwareReplayControlRequestV1::new(SoftwareReplayControlCommandV1::Pause, 6, 1, run_id)
            .unwrap(),
        5_000,
        5_000,
    )
    .unwrap();
    assert!(paused.accepted, "{}", paused.reason);
    assert!(paused.paused);
    let paused_snapshot = query_software_replay_snapshot(&pipe, 7, 1, 5_000, 5_000).unwrap();
    let committed_at_pause = paused_snapshot.committed_record_count.unwrap();
    thread::sleep(Duration::from_millis(20));
    let still_paused = query_software_replay_snapshot(&pipe, 8, 1, 5_000, 5_000).unwrap();
    assert_eq!(
        still_paused.committed_record_count,
        Some(committed_at_pause)
    );

    let resumed = call_software_replay_control(
        &pipe,
        &SoftwareReplayControlRequestV1::new(SoftwareReplayControlCommandV1::Resume, 9, 1, run_id)
            .unwrap(),
        5_000,
        5_000,
    )
    .unwrap();
    assert!(resumed.accepted, "{}", resumed.reason);
    assert!(!resumed.paused);
    assert!(resumed.discarded_record_count > 0);
    thread::sleep(Duration::from_millis(20));
    let after_resume = query_software_replay_snapshot(&pipe, 10, 1, 5_000, 5_000).unwrap();
    assert!(after_resume.committed_record_count.unwrap() > committed_at_pause);

    let stopped = call_software_replay_run_command(
        &pipe,
        11,
        1,
        &RunCommandV1 {
            command: 4,
            scope: 1,
            run_id,
            target_device_id: target_group_id,
            deadline_global_time_ns: u64::MAX,
            frozen_config_hash,
        },
        5_000,
        10_000,
    )
    .unwrap();
    assert!(stopped.accepted, "{}", stopped.reason);
    assert_eq!(stopped.state, RunState::JournalSealed);
    assert_eq!(stopped.committed_record_count, stopped.durable_record_count);
    assert!(stopped.committed_record_count.unwrap_or_default() > 0);
    let exit = wait_for_exit(&mut child.0);
    assert!(exit.success(), "software replay daemon exited with {exit}");

    let records =
        JournalReader::open_sealed(reservation.resolved_run_directory.join("run.forgewal"))
            .unwrap()
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
    assert!(!records.is_empty());
    let mut pod_ids = Vec::new();
    let mut saw_pause_gap = false;
    for record in records {
        let block = SampleBlockV1::decode(&record.canonical.payload).unwrap();
        assert_eq!(block.channel_count, 32);
        assert_eq!(block.samples_per_channel, 30);
        assert_eq!(block.sample_rate_numerator_hz, 30_000);
        if !pod_ids.contains(&record.canonical.envelope.pod_id) {
            pod_ids.push(record.canonical.envelope.pod_id);
        }
        saw_pause_gap |= record.canonical.envelope.flags & RECORD_FLAG_DISCONTINUITY_BEFORE != 0;
    }
    assert_eq!(pod_ids.len(), 2);
    assert!(saw_pause_gap);
}

#[test]
fn acknowledged_abort_exits_but_prepared_disconnect_does_not() {
    let root = TempRoot::new();
    let runs = root.0.join("runs");
    let ready = root.0.join("ready.json");
    let pipe = format!(
        "{}{}-{}",
        SOFTWARE_REPLAY_PIPE_PREFIX,
        std::process::id(),
        monotonic_nonce()
    );
    let run_id = [0x41; 16];
    let target_group_id = [0x42; 16];
    let frozen_config_hash = [0x43; 32];
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_forge-acqd"))
            .args(["software-replay-service", "--requested-directory"])
            .arg(&runs)
            .args([
                "--base-name",
                "FORGE-ABORT",
                "--run-id",
                &hex(&run_id),
                "--target-group-id",
                &hex(&target_group_id),
                "--frozen-config-hash",
                &hex(&frozen_config_hash),
                "--pipe",
                &pipe,
                "--operator-sid",
                &current_process_user_sid().unwrap(),
                "--selected-device",
                "direct-pod-abort",
                "--ready-receipt",
            ])
            .arg(&ready)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );

    let reservation = wait_for_reservation(&ready, &mut child.0);
    let prepared = call_software_replay_run_command(
        &pipe,
        1,
        1,
        &RunCommandV1 {
            command: 1,
            scope: 1,
            run_id,
            target_device_id: target_group_id,
            deadline_global_time_ns: u64::MAX,
            frozen_config_hash,
        },
        5_000,
        5_000,
    )
    .unwrap();
    assert!(prepared.accepted, "{}", prepared.reason);
    assert_eq!(prepared.state, RunState::Prepared);
    assert!(reservation
        .resolved_run_directory
        .join("run.forgewal")
        .is_file());

    // There is no persistent GUI connection. Remaining alive here proves that
    // a prepared Run is not implicitly aborted when the command client closes.
    thread::sleep(Duration::from_millis(30));
    assert!(child.0.try_wait().unwrap().is_none());
    let still_prepared = query_software_replay_snapshot(&pipe, 2, 1, 5_000, 5_000).unwrap();
    assert_eq!(still_prepared.state, RunState::Prepared);

    let aborted = call_software_replay_run_command(
        &pipe,
        3,
        1,
        &RunCommandV1 {
            command: 5,
            scope: 1,
            run_id,
            target_device_id: target_group_id,
            deadline_global_time_ns: u64::MAX,
            frozen_config_hash,
        },
        5_000,
        10_000,
    )
    .unwrap();
    assert!(aborted.accepted, "{}", aborted.reason);
    assert_eq!(aborted.state, RunState::Aborted);
    let exit = wait_for_exit(&mut child.0);
    assert!(exit.success(), "software replay daemon exited with {exit}");
    assert!(
        JournalReader::open_sealed(reservation.resolved_run_directory.join("run.forgewal"))
            .is_err()
    );
}

#[test]
fn acknowledged_failure_exits_only_after_exact_fack_and_preserves_partial_wal() {
    let root = TempRoot::new();
    let runs = root.0.join("runs");
    let ready = root.0.join("ready.json");
    let pipe = format!(
        "{}{}-{}",
        SOFTWARE_REPLAY_PIPE_PREFIX,
        std::process::id(),
        monotonic_nonce()
    );
    let run_id = [0x71; 16];
    let target_group_id = [0x72; 16];
    let frozen_config_hash = [0x73; 32];
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_forge-acqd"))
            .args(["software-replay-service", "--requested-directory"])
            .arg(&runs)
            .args([
                "--base-name",
                "FORGE-FAILED",
                "--run-id",
                &hex(&run_id),
                "--target-group-id",
                &hex(&target_group_id),
                "--frozen-config-hash",
                &hex(&frozen_config_hash),
                "--pipe",
                &pipe,
                "--operator-sid",
                &current_process_user_sid().unwrap(),
                "--selected-device",
                "direct-pod-failed",
                "--ready-receipt",
            ])
            .arg(&ready)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );

    let reservation = wait_for_reservation(&ready, &mut child.0);
    let journal = reservation.resolved_run_directory.join("run.forgewal");
    let mut seal_name = journal.as_os_str().to_owned();
    seal_name.push(".seal");
    let seal = PathBuf::from(seal_name);
    let partial_wal = b"FORGE-PARTIAL-WAL-SENTINEL";
    fs::write(&journal, partial_wal).unwrap();

    // AcknowledgeFailure is not terminal unless it is accepted from Failed.
    let rejected = call_software_replay_run_command(
        &pipe,
        1,
        1,
        &run_body(7, run_id, target_group_id, frozen_config_hash),
        5_000,
        5_000,
    )
    .unwrap();
    assert!(!rejected.accepted);
    assert_eq!(rejected.state, RunState::New);
    assert!(child.0.try_wait().unwrap().is_none());

    // Prepare owns create-new. The pre-existing partial artifact forces a
    // durable Failed state without overwriting or deleting that evidence.
    let failed = call_software_replay_run_command(
        &pipe,
        2,
        1,
        &run_body(1, run_id, target_group_id, frozen_config_hash),
        5_000,
        5_000,
    )
    .unwrap();
    assert!(!failed.accepted);
    assert_eq!(failed.error, ServiceErrorV1::PersistenceFailure);
    assert_eq!(failed.state, RunState::Failed);
    assert_eq!(fs::read(&journal).unwrap(), partial_wal);
    assert!(!seal.exists());
    assert!(child.0.try_wait().unwrap().is_none());

    let acknowledge = run_body(7, run_id, target_group_id, frozen_config_hash);
    let request = encode_low_speed(0, 3, 1, &acknowledge).unwrap();
    let lost_fack = abandon_response_before_fack(&pipe, &request);
    assert!(lost_fack.accepted, "{}", lost_fack.reason);
    assert_eq!(lost_fack.state, RunState::New);

    // The state transition is durable, but loss of the exact response FACK
    // must clear the exit request and leave the listener available for the
    // exact idempotent retry.
    thread::sleep(Duration::from_millis(50));
    assert!(child.0.try_wait().unwrap().is_none());
    let still_available = query_software_replay_snapshot(&pipe, 4, 1, 5_000, 5_000).unwrap();
    assert_eq!(still_available.state, RunState::New);
    let acknowledged =
        call_software_replay_run_command(&pipe, 3, 1, &acknowledge, 5_000, 5_000).unwrap();
    assert!(acknowledged.accepted, "{}", acknowledged.reason);
    assert_eq!(acknowledged.state, RunState::New);
    let exit = wait_for_exit(&mut child.0);
    assert!(exit.success(), "software replay daemon exited with {exit}");
    assert_eq!(fs::read(&journal).unwrap(), partial_wal);
    assert!(!seal.exists());
}

fn run_body(
    command: u16,
    run_id: [u8; 16],
    target_device_id: [u8; 16],
    frozen_config_hash: [u8; 32],
) -> RunCommandV1 {
    RunCommandV1 {
        command,
        scope: 1,
        run_id,
        target_device_id,
        deadline_global_time_ns: u64::MAX,
        frozen_config_hash,
    }
}

fn abandon_response_before_fack(pipe: &str, request: &[u8]) -> DaemonResponseV1 {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut connection = loop {
        match fs::OpenOptions::new().read(true).write(true).open(pipe) {
            Ok(connection) => break connection,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "software replay pipe did not accept lost-FACK client: {error}"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }
    };
    connection.write_all(request).unwrap();
    let mut prefix = [0_u8; 4];
    connection.read_exact(&mut prefix).unwrap();
    let response_len = u32::from_le_bytes(prefix) as usize;
    let mut response = vec![0_u8; response_len];
    response[..4].copy_from_slice(&prefix);
    connection.read_exact(&mut response[4..]).unwrap();
    let mut challenge = [0_u8; 16];
    connection.read_exact(&mut challenge).unwrap();
    drop(connection);
    DaemonResponseV1::decode(&response).unwrap()
}

fn wait_for_reservation(path: &PathBuf, child: &mut Child) -> SoftwareReplayReservationV1 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(bytes) = fs::read(path) {
            if let Ok(receipt) = serde_json::from_slice(&bytes) {
                return receipt;
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("software replay child exited before ready receipt: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "software replay ready receipt timed out"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "software replay daemon did not exit after acknowledged Stop seal"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn monotonic_nonce() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}
