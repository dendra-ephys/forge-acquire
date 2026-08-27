#![cfg(all(windows, feature = "qualification-harness"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use forge_acqd::{
    receipt_evidence_hash, verify_gui_kill_qualification_receipt, GuiKillQualificationReceiptV3,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

fn temp_base(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "forge-acqd-gui-kill-{label}-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must follow Unix epoch")
            .as_nanos(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).expect("create GUI-kill test base");
    path
}

fn reap_bounded(child: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child
            .try_wait()
            .expect("poll qualification process")
            .is_some()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let kill_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < kill_deadline {
        if child
            .try_wait()
            .expect("poll killed qualification process")
            .is_some()
        {
            panic!("qualification process exceeded its hard deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("qualification process could not be proven reaped after timeout");
}

fn run_cli(arguments: &[String], expect_success: bool) -> String {
    let executable = env!("CARGO_BIN_EXE_forge-acqd");
    let mut child = Command::new(executable)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn GUI-kill qualification executable");
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(status) = child.try_wait().expect("poll qualification executable") {
            let output = child
                .wait_with_output()
                .expect("collect completed qualification output");
            let text = format!(
                "stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(status.success(), expect_success, "{text}");
            return text;
        }
        if Instant::now() >= deadline {
            reap_bounded(&mut child, Duration::ZERO);
            panic!("qualification executable timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn prepare_build_artifact(base: &Path) -> PathBuf {
    let artifact = base.join("input-forge-acqd.exe");
    fs::copy(env!("CARGO_BIN_EXE_forge-acqd"), &artifact)
        .expect("copy immutable GUI-kill build artifact before the supervisor starts");
    artifact
}

fn qualification_args(root: &Path, receipt: &Path, artifact: &Path, count: u32) -> Vec<String> {
    vec![
        "gui-kill-qualification".to_owned(),
        "--root".to_owned(),
        root.to_string_lossy().into_owned(),
        "--receipt".to_owned(),
        receipt.to_string_lossy().into_owned(),
        "--build-artifact".to_owned(),
        artifact.to_string_lossy().into_owned(),
        "--kill-count".to_owned(),
        count.to_string(),
    ]
}

fn assert_rehashed_receipt_rejected(
    receipt_path: &Path,
    original: &str,
    mutate: impl FnOnce(&mut GuiKillQualificationReceiptV3),
) {
    let mut receipt: GuiKillQualificationReceiptV3 =
        serde_json::from_str(original).expect("parse valid v3 receipt for semantic mutation");
    mutate(&mut receipt);
    receipt.evidence_sha256_hex.clear();
    receipt.evidence_sha256_hex =
        receipt_evidence_hash(&receipt).expect("rehash semantic mutation");
    fs::write(
        receipt_path,
        serde_json::to_vec_pretty(&receipt).expect("encode semantic mutation"),
    )
    .expect("write semantic mutation");
    assert!(verify_gui_kill_qualification_receipt(receipt_path).is_err());
}

#[test]
fn gui_kill_smoke_receipt_is_no_overwrite_and_tamper_detecting() {
    let base = temp_base("smoke");
    let root = base.join("run");
    let receipt = base.join("receipt.json");
    let artifact = prepare_build_artifact(&base);
    let arguments = qualification_args(&root, &receipt, &artifact, 4);
    let output = run_cli(&arguments, true);
    assert!(output.contains("forge.gui-kill-qualification.v3"));
    let verified = verify_gui_kill_qualification_receipt(&receipt).expect("verify smoke receipt");
    assert_eq!(verified.completed_kill_count, 4);
    assert_eq!(verified.response_consumed_then_killed_count, 2);
    assert_eq!(verified.transaction_inflight_then_killed_count, 2);
    assert!(verified.scm_emulated);
    assert!(!verified.service_deployed);
    assert!(verified.owner_process_isolated);
    assert_ne!(verified.owner_pid, std::process::id());
    assert_eq!(verified.audit.event_count, 5 * 4 + 9);
    assert_eq!(verified.raw_sample_bytes_entered_gui, 0);

    // Root and receipt are no-overwrite outputs: rerunning the same command
    // must fail before it can overwrite either evidence path.
    let _ = run_cli(&arguments, false);
    let original = fs::read_to_string(&receipt).expect("read receipt for tamper test");
    for index in 0..4 {
        assert_rehashed_receipt_rejected(&receipt, &original, |candidate| match index {
            0 => candidate.owner_containment.created_suspended = false,
            1 => candidate.owner_containment.kill_on_job_close_configured = false,
            2 => candidate.owner_containment.job_assigned_before_resume = false,
            3 => {
                candidate
                    .owner_containment
                    .executable_rehashed_before_resume = false
            }
            _ => unreachable!(),
        });
    }
    assert_rehashed_receipt_rejected(&receipt, &original, |candidate| {
        candidate.owner_reap.exit_code = 42;
    });
    assert_rehashed_receipt_rejected(&receipt, &original, |candidate| {
        candidate.owner_reap.wait_deadline_ms += 1;
    });
    assert_rehashed_receipt_rejected(&receipt, &original, |candidate| {
        candidate.owner_reap.method = "job_object_termination".to_owned();
    });
    assert_rehashed_receipt_rejected(&receipt, &original, |candidate| {
        candidate.owner_reap.job_active_processes_after_wait = 1;
    });
    assert_rehashed_receipt_rejected(&receipt, &original, |candidate| {
        candidate.owner_reap.job_empty_proven = false;
    });
    assert_rehashed_receipt_rejected(&receipt, &original, |candidate| {
        candidate.open_gates = vec!["closed".to_owned(); 4];
    });
    fs::write(&receipt, &original).expect("restore receipt after containment mutation");
    let tampered = original.replacen("\"passed\": true", "\"passed\": false", 1);
    fs::write(&receipt, tampered).expect("write controlled receipt tamper");
    assert!(verify_gui_kill_qualification_receipt(&receipt).is_err());

    // The audit evidence is mandatory in v3, even if every other receipt
    // field is preserved byte-for-byte.
    let mut missing_audit: serde_json::Value =
        serde_json::from_str(&original).expect("parse original receipt");
    missing_audit
        .as_object_mut()
        .expect("receipt must be a JSON object")
        .remove("audit");
    fs::write(
        &receipt,
        serde_json::to_vec_pretty(&missing_audit).expect("encode missing-audit receipt"),
    )
    .expect("write controlled missing-audit receipt");
    assert!(verify_gui_kill_qualification_receipt(&receipt).is_err());

    // Restore the valid receipt, then prove that independently modifying the
    // append-only audit is also detected by the cross-artifact verifier.
    fs::write(&receipt, &original).expect("restore original receipt");
    let audit_path = PathBuf::from(&verified.audit.path);
    let mut audit_bytes = fs::read(&audit_path).expect("read audit for tamper test");
    audit_bytes.extend_from_slice(b" ");
    fs::write(&audit_path, audit_bytes).expect("write controlled audit tamper");
    assert!(verify_gui_kill_qualification_receipt(&receipt).is_err());
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn gui_kill_v1_receipt_is_rejected_before_field_validation() {
    let base = temp_base("v1-rejected");
    let receipt = base.join("receipt.json");
    fs::write(&receipt, br#"{"schema":"forge.gui-kill-qualification.v1"}"#)
        .expect("write controlled v1 receipt");
    let error = verify_gui_kill_qualification_receipt(&receipt)
        .expect_err("v1 evidence must never pass the v3 verifier");
    let error_text = error.to_string();
    assert!(
        error_text.contains("historical") && error_text.contains("v3"),
        "unexpected error: {error_text}"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn gui_kill_v2_receipt_is_rejected_before_field_validation() {
    let base = temp_base("v2-rejected");
    let receipt = base.join("receipt.json");
    fs::write(&receipt, br#"{"schema":"forge.gui-kill-qualification.v2"}"#)
        .expect("write controlled v2 receipt");
    assert!(verify_gui_kill_qualification_receipt(&receipt).is_err());
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn gui_kill_child_failures_and_ackread_observer_failure_reap_without_receipt() {
    for (label, injected) in [
        ("timeout", "--inject-child-timeout"),
        ("exit", "--inject-child-exit"),
        ("ackread", "--inject-ack-read-failure"),
    ] {
        let base = temp_base(label);
        let root = base.join("run");
        let receipt = base.join("receipt.json");
        let artifact = prepare_build_artifact(&base);
        let mut arguments = qualification_args(&root, &receipt, &artifact, 2);
        arguments.push(injected.to_owned());
        let output = run_cli(&arguments, false);
        assert!(output.contains("failed closed"));
        assert!(root.exists());
        assert!(!receipt.exists());
        let reaped_attempt = if label == "ackread" { 1 } else { 0 };
        assert!(
            root.join(format!("reaped-{reaped_attempt}")).exists(),
            "{label} failure must prove bounded child reap"
        );
        let _ = fs::remove_dir_all(&base);
    }
}

#[test]
#[ignore = "explicit 1000-real-child qualification; preserves receipt paths in environment-selected location"]
fn gui_kill_qualification_1000_real_children() {
    let base = std::env::var_os("FORGE_GUI_KILL_QUALIFICATION_BASE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temp_base("1000"));
    if !base.is_dir() {
        fs::create_dir_all(&base).expect("create requested 1000 qualification base");
    }
    let root = base.join("run");
    let receipt = base.join("receipt.json");
    let artifact = prepare_build_artifact(&base);
    let output = run_cli(&qualification_args(&root, &receipt, &artifact, 1_000), true);
    let verified = verify_gui_kill_qualification_receipt(&receipt).expect("verify 1000 receipt");
    assert_eq!(verified.completed_kill_count, 1_000);
    eprintln!(
        "1000 GUI-kill receipt retained at {} ({output})",
        receipt.display()
    );
}
