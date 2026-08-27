use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use forge_acqd::journal::{CHUNK_HEADER_LEN, COMMIT_FOOTER_LEN, FILE_HEADER_LEN};
use forge_acqd::run::{RunCommand, RunCommandKind, RunState};
use forge_acqd::source::{DeterministicReplayConfig, DeterministicReplaySource};
use forge_acqd::{
    inspect_recovery, recover_to_durable, DurableRunService, JournalIdentity, JournalReader,
    JournalRecovery, JournalWriter,
};
use forge_protocol_v1::{RunCommandV1, RECORD_HEADER_LEN};

const CHILD_SCENARIO: &str = "FORGE_ACQD_CRASH_CHILD_SCENARIO";
const CHILD_ROOT: &str = "FORGE_ACQD_CRASH_CHILD_ROOT";
const RUN_ID: [u8; 16] = [0x11; 16];
const POD_ID: [u8; 16] = [0x22; 16];
const HEADSTAGE_ID: [u8; 16] = [0x33; 16];
const TARGET_ID: [u8; 16] = [0x44; 16];
const CONFIG_HASH: [u8; 32] = [0x55; 32];

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "forge-acqd-process-crash-{label}-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time must follow the Unix epoch")
                .as_nanos(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create isolated process-crash directory");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct KillGuard(Child);

impl KillGuard {
    fn kill_and_wait(&mut self) {
        self.0.kill().expect("terminate qualification child");
        let status = wait_for_reap(&mut self.0, Duration::from_secs(3))
            .expect("reap qualification child within hard deadline");
        assert!(!status.success(), "a killed child must not report success");
    }
}

impl Drop for KillGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = wait_for_reap(&mut self.0, Duration::from_secs(3));
        }
    }
}

fn wait_for_reap(
    child: &mut Child,
    timeout: Duration,
) -> std::io::Result<std::process::ExitStatus> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| std::io::Error::other("child reap deadline overflow"))?;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "qualification child could not be proven reaped within hard deadline",
    ))
}

fn spawn_until_ready(scenario: &str, root: &Path) -> KillGuard {
    let child = Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--exact", "crash_child_fixture", "--nocapture"])
        .env(CHILD_SCENARIO, scenario)
        .env(CHILD_ROOT, root)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn qualification child");
    let mut guarded = KillGuard(child);
    let ready_path = root.join(format!("ready-{scenario}"));
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if ready_path.exists() {
            return guarded;
        }
        if let Some(status) = guarded.0.try_wait().expect("poll qualification child") {
            panic!("qualification child exited before ready: {status}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("qualification child did not reach the ready boundary");
}

fn replay_source(records: u64) -> DeterministicReplaySource {
    DeterministicReplaySource::new(DeterministicReplayConfig {
        run_id: RUN_ID,
        pod_id: POD_ID,
        headstage_id: HEADSTAGE_ID,
        channel_layout_id: 1,
        channel_count: 1,
        samples_per_channel: 30,
        sample_rate_hz: 30_000,
        total_records: records,
        seed: 0x464f_5247_4543_5241,
    })
    .expect("valid deterministic source")
}

fn run_command(request_id: u64, kind: RunCommandKind) -> RunCommand {
    RunCommand {
        request_id,
        epoch: 1,
        body: RunCommandV1 {
            command: kind.wire_value(),
            scope: 1,
            run_id: RUN_ID,
            target_device_id: TARGET_ID,
            deadline_global_time_ns: u64::MAX,
            frozen_config_hash: CONFIG_HASH,
        },
    }
}

fn child_ready(root: &Path, scenario: &str) -> ! {
    let ready_path = root.join(format!("ready-{scenario}"));
    let mut ready = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(ready_path)
        .expect("create ready marker");
    ready
        .write_all(format!("FORGE_CRASH_READY {scenario}\n").as_bytes())
        .expect("write ready marker");
    ready.sync_all().expect("persist ready marker");
    drop(ready);
    loop {
        std::thread::park_timeout(Duration::from_secs(60));
    }
}

#[derive(Clone, Copy)]
enum JournalTailCut {
    Header,
    Payload,
    Footer,
    BeforeBarrier,
}

fn child_journal_cutpoint(root: &Path, scenario: &str, cut: JournalTailCut) -> ! {
    let path = root.join("run.forgewal");
    let identity = JournalIdentity::for_run(RUN_ID).expect("valid journal identity");
    let mut writer = JournalWriter::create(&path, identity).expect("create qualification journal");
    let mut source = replay_source(2);
    writer
        .append_record(&source.next_encoded_record().unwrap().unwrap())
        .expect("append durable record");
    let durable = writer
        .durability_barrier()
        .expect("persist first record boundary");
    let second = source.next_encoded_record().unwrap().unwrap();
    writer
        .append_record(&second)
        .expect("append second structural record");
    let full_tail_len = CHUNK_HEADER_LEN + second.len() + COMMIT_FOOTER_LEN;
    let retained_tail_len = match cut {
        JournalTailCut::Header => CHUNK_HEADER_LEN / 2,
        JournalTailCut::Payload => CHUNK_HEADER_LEN + second.len() / 2,
        JournalTailCut::Footer => CHUNK_HEADER_LEN + second.len() + COMMIT_FOOTER_LEN / 2,
        JournalTailCut::BeforeBarrier => full_tail_len,
    };
    drop(writer);
    if retained_tail_len < full_tail_len {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open journal for deterministic process cutpoint");
        file.set_len(durable.durable_valid_len + retained_tail_len as u64)
            .expect("truncate journal to deterministic process cutpoint");
        file.sync_all()
            .expect("persist deterministic process cutpoint");
    }
    child_ready(root, scenario);
}

fn child_corrupt_durable_record(root: &Path, scenario: &str) -> ! {
    let path = root.join("run.forgewal");
    let identity = JournalIdentity::for_run(RUN_ID).expect("valid journal identity");
    let mut writer = JournalWriter::create(&path, identity).expect("create qualification journal");
    let mut source = replay_source(1);
    writer
        .append_record(&source.next_encoded_record().unwrap().unwrap())
        .expect("append durable record");
    writer
        .durability_barrier()
        .expect("persist durable record boundary");
    drop(writer);

    let mut bytes = fs::read(&path).expect("read durable journal for corruption fixture");
    let corrupt_offset = FILE_HEADER_LEN + CHUNK_HEADER_LEN + RECORD_HEADER_LEN + 33;
    assert!(corrupt_offset < bytes.len());
    bytes[corrupt_offset] ^= 0x80;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("open durable journal for corruption fixture");
    file.write_all(&bytes)
        .expect("write durable corruption fixture");
    file.sync_all().expect("persist durable corruption fixture");
    drop(file);
    child_ready(root, scenario);
}

#[test]
fn crash_child_fixture() {
    let Ok(scenario) = std::env::var(CHILD_SCENARIO) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root is required"));
    match scenario.as_str() {
        "journal_header_cut" => child_journal_cutpoint(&root, &scenario, JournalTailCut::Header),
        "journal_payload_cut" => child_journal_cutpoint(&root, &scenario, JournalTailCut::Payload),
        "journal_footer_cut" => child_journal_cutpoint(&root, &scenario, JournalTailCut::Footer),
        "journal_before_barrier" => {
            child_journal_cutpoint(&root, &scenario, JournalTailCut::BeforeBarrier)
        }
        "journal_durable_crc_corruption" => child_corrupt_durable_record(&root, &scenario),
        "active_run" => {
            let mut service = DurableRunService::open(root.join("ledger"))
                .expect("open qualification Run ledger");
            for (request_id, kind) in [
                (1, RunCommandKind::Prepare),
                (2, RunCommandKind::Arm),
                (3, RunCommandKind::Start),
            ] {
                let receipt = service
                    .handle(run_command(request_id, kind), 1)
                    .expect("persist Run command");
                assert!(receipt.accepted);
            }
            child_ready(&root, &scenario);
        }
        other => panic!("unknown child scenario: {other}"),
    }
}

#[test]
fn killed_writer_cutpoint_matrix_recovers_only_the_proven_durable_prefix() {
    for scenario in [
        "journal_header_cut",
        "journal_payload_cut",
        "journal_footer_cut",
        "journal_before_barrier",
    ] {
        let root = TempDir::new(scenario);
        let journal = root.0.join("run.forgewal");
        let mut child = spawn_until_ready(scenario, &root.0);
        child.kill_and_wait();

        let recovery = inspect_recovery(&journal).expect("inspect killed journal");
        match recovery {
            JournalRecovery::RecoverableUnprovenTail { durable, .. } => {
                assert_eq!(durable.durable_record_count, 1, "{scenario}");
                assert_eq!(durable.durable_journal_sequence, Some(0), "{scenario}");
            }
            JournalRecovery::Clean(_) => {
                panic!("{scenario}: process cutpoint must not be reported clean")
            }
        }
        let durable_records = JournalReader::open_durable(&journal)
            .expect("open durable prefix")
            .collect::<Result<Vec<_>, _>>()
            .expect("read durable prefix");
        assert_eq!(durable_records.len(), 1, "{scenario}");
        assert_eq!(
            durable_records[0].metadata.journal_sequence, 0,
            "{scenario}"
        );

        let recovered = recover_to_durable(&journal).expect("truncate to durable prefix");
        assert_eq!(recovered.complete_chunks, 1, "{scenario}");
        assert_eq!(recovered.last_journal_sequence, Some(0), "{scenario}");
        assert!(matches!(
            inspect_recovery(&journal).expect("reinspect recovered journal"),
            JournalRecovery::Clean(_)
        ));
    }
}

#[test]
fn killed_active_run_reopens_failed_and_requires_explicit_acknowledgement() {
    let root = TempDir::new("run-ledger");
    let ledger = root.0.join("ledger");
    let mut child = spawn_until_ready("active_run", &root.0);
    child.kill_and_wait();

    let mut service = DurableRunService::open(&ledger).expect("reopen killed Run ledger");
    let failed = service.status();
    assert_eq!(failed.state, RunState::Failed);
    assert!(failed.auto_failed_on_restart);
    assert_eq!(failed.active_epoch, Some(1));
    let expected_run_id = "11".repeat(16);
    assert_eq!(
        failed.active_run_id_hex.as_deref(),
        Some(expected_run_id.as_str())
    );
    assert_eq!(failed.ledger_events, 4);

    let acknowledged = service
        .handle(run_command(4, RunCommandKind::AcknowledgeFailure), 1)
        .expect("persist failure acknowledgement");
    assert!(acknowledged.accepted);
    assert_eq!(acknowledged.current_state, RunState::New);
    drop(service);

    let reopened = DurableRunService::open(&ledger).expect("reopen acknowledged ledger");
    assert_eq!(reopened.status().state, RunState::New);
    assert_eq!(reopened.status().highest_epoch, 1);
    assert_eq!(reopened.status().ledger_events, 5);
}

#[test]
fn killed_process_with_durable_crc_corruption_fails_closed_without_truncation() {
    let root = TempDir::new("durable-crc-corruption");
    let journal = root.0.join("run.forgewal");
    let mut child = spawn_until_ready("journal_durable_crc_corruption", &root.0);
    child.kill_and_wait();

    let inspect_error = inspect_recovery(&journal).expect_err("durable corruption must be fatal");
    assert_eq!(inspect_error.kind(), std::io::ErrorKind::InvalidData);
    let recovery_error =
        recover_to_durable(&journal).expect_err("durable corruption cannot be truncated away");
    assert_eq!(recovery_error.kind(), std::io::ErrorKind::InvalidData);
    assert!(JournalReader::open_durable(&journal).is_err());
}
