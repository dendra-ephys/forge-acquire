//! Three-stage evidence for an explicit Windows SCM stop.
//!
//! This is deliberately a data and verification layer.  It does not send an
//! SCM control, own a process, write a journal, or publish NWB.  In particular,
//! an active Run stopped by SCM is an abort with a proven durable prefix, never
//! a `ShutdownSealed` or an NWB-finalization claim.  SHA-256 here binds local
//! content; it is neither a signature nor remote authentication.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use forge_protocol_v1::{crc32c, sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::journal::{scan_journal, FILE_HEADER_LEN};
use crate::run::RunState;

// This v1 evidence shape has not been externally released. Its reset requires
// explicit `intent_kind`, `run_state_wire`, and terminal commit qualification
// fields; older JSON is rejected rather than inferred as a legacy form.
pub const SCM_STOP_RECEIPT_SCHEMA: &str = "forge.scm-stop-receipt.v1";
const LEDGER_EVENT_DOMAIN: &[u8] = b"forge.scm-stop-receipt.ledger-event.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmStopEvidenceSourceV1 {
    /// A runtime SCM host that has not completed the independent real-SCM
    /// qualification gate. It records local facts but cannot promote itself.
    UnqualifiedWindowsRuntime,
    /// A future supervisor observed Windows SCM and retained-handle facts.
    WindowsScmApi,
    /// Unit tests and emulation.  This can never satisfy a real-SCM pass.
    SyntheticTest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmTerminalCommitQualificationV1 {
    /// The service itself performs synchronous evidence publication. Its QPC
    /// timestamp is sampled before those writes complete, so this path can
    /// preserve useful failure evidence but can never prove a bounded commit.
    UnqualifiedSynchronousIo,
    /// A test-only injected commit boundary. It can exercise bounded-receipt
    /// semantics but can never qualify as real Windows SCM evidence.
    SyntheticBoundedCommit,
    /// A future external SCM watcher observed the final durable publication
    /// independently of the service process. The current service host has no
    /// construction path for this qualification.
    ExternalScmWatcherObserved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmStopReasonV1 {
    ServiceControlStop,
    ServiceControlShutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopIntentKindV1 {
    /// The owner answered an exact snapshot and the following private
    /// GracefulShutdown is bound to this intent.
    RuntimeGracefulShutdown,
    /// SCM Stop arrived after the contained owner existed but before its
    /// private endpoint was ready.  No private command was sent and no Run
    /// state is claimed.
    StartupBeforeOwnerReady,
    /// The private endpoint existed, but an exact Run snapshot could not be
    /// obtained.  The owner is reaped fail-closed without a private command.
    RuntimeSnapshotUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureExitReasonV1 {
    ExplicitScmStopAbort,
    IdleOwnerShutdown,
    PreexistingRunFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStopTruthV1 {
    /// No active Run existed, so no acquisition prefix needed preservation.
    IdleCleanStop,
    /// An active Run cannot continue.  A separately bound durable prefix exists.
    ActiveRunAbortedWithDurablePrefix,
    /// The Run was already failed before the SCM request; this is not a seal.
    AlreadyFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmFinalStatusV1 {
    Stopped,
    StopPending,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StopLedgerEventKindV1 {
    IntentPersisted,
    OwnerOutcomePersisted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopProcessIdentityV1 {
    pub pid: u32,
    pub creation_time_100ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableFileIdentityV1 {
    pub volume_serial_number: u64,
    pub file_index: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableFileBindingV1 {
    pub path: String,
    pub sha256_hex: String,
    pub file_identity: StableFileIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurablePrefixV1 {
    /// The journal artifact that contains the recoverable prefix.  It is not
    /// required to be sealed and does not imply that an NWB worker succeeded.
    pub journal: StableFileBindingV1,
    /// `None` is the only honest representation of an empty, header-only
    /// durable journal. It is never encoded as an integer sentinel.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub durable_watermark_journal_sequence: Option<u64>,
    pub durable_record_count: u64,
    pub last_observed_record_sequence: Option<u64>,
    pub last_observed_sample_index: Option<u64>,
    pub journal_poisoned: bool,
    pub journal_fault: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopIntentV1 {
    pub schema: String,
    pub service_name: String,
    pub service_instance_id_hex: String,
    pub run_id_hex: Option<String>,
    pub owner_process: StopProcessIdentityV1,
    pub reason: ScmStopReasonV1,
    pub intent_kind: StopIntentKindV1,
    pub scm_control_wall_time_unix_ns: u64,
    pub scm_control_monotonic_ns: u64,
    pub deadline_monotonic_ns: u64,
    pub private_request_sequence: Option<u64>,
    pub private_epoch: Option<u64>,
    /// Exact `RunState::wire_value()` observed in the supervisor snapshot.
    /// Startup/snapshot-unavailable evidence uses `None` instead of inventing
    /// an idle state.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub run_state_wire: Option<u8>,
    pub active_run_at_intent: bool,
    pub intent_sha256_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerStopOutcomeV1 {
    pub schema: String,
    pub intent_sha256_hex: String,
    pub service_name: String,
    pub service_instance_id_hex: String,
    pub run_id_hex: Option<String>,
    pub owner_process: StopProcessIdentityV1,
    /// This is the private protocol FACK for the exact graceful-shutdown
    /// transaction.  It does not prove process exit.
    pub private_fack_observed: bool,
    pub private_request_sequence: u64,
    pub private_epoch: u64,
    pub completed_wall_time_unix_ns: u64,
    pub completed_monotonic_ns: u64,
    pub final_run_truth: RunStopTruthV1,
    pub durable_prefix: Option<DurablePrefixV1>,
    pub capture_exit_reason: CaptureExitReasonV1,
    pub outcome_sha256_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmStopLedgerEvidenceV1 {
    pub ledger: StableFileBindingV1,
    pub event_count: u64,
    pub last_event_hash_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmStopReceiptV1 {
    pub schema: String,
    pub evidence_source: ScmStopEvidenceSourceV1,
    pub terminal_commit_qualification: ScmTerminalCommitQualificationV1,
    pub service_name: String,
    pub service_instance_id_hex: String,
    pub run_id_hex: Option<String>,
    pub owner_process: StopProcessIdentityV1,
    pub intent: StableFileBindingV1,
    pub outcome: Option<StableFileBindingV1>,
    pub ledger: ScmStopLedgerEvidenceV1,
    pub owner_exit_code: Option<u32>,
    pub forced_termination: bool,
    pub retained_process_exit_observed: bool,
    pub job_active_processes_after_wait: u32,
    pub job_empty_proven: bool,
    pub stop_completed_wall_time_unix_ns: u64,
    /// Time at which the service had prepared its terminal evidence before
    /// receipt publication. It is not the completion time of synchronous
    /// create-new, flush, verification, or publish I/O and cannot qualify a
    /// bounded terminal commit by itself.
    pub stop_completed_monotonic_ns: u64,
    pub elapsed_ns: u64,
    pub final_scm_status: ScmFinalStatusV1,
    /// Trusted bounded-terminal result. It is false if terminal commit is
    /// unqualified, an outcome is missing, an owner was forced, the Job is
    /// nonempty, the deadline is exceeded, or final SCM state is not Stopped.
    pub bounded_stop_complete: bool,
    pub receipt_sha256_hex: String,
}

/// Values supplied by the caller's trusted supervisor context, never copied
/// from the receipt.  The three expected hashes make a semantic forgery with a
/// recomputed self-hash fail even when all JSON remains structurally valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScmStopVerificationExpectationV1 {
    pub(crate) service_name: String,
    pub(crate) service_instance_id_hex: String,
    pub(crate) run_id_hex: Option<String>,
    pub(crate) owner_process: StopProcessIdentityV1,
    pub(crate) intent_path: PathBuf,
    pub(crate) outcome_path: Option<PathBuf>,
    pub(crate) receipt_path: PathBuf,
    pub(crate) ledger_path: PathBuf,
    pub(crate) expected_intent_sha256_hex: String,
    pub(crate) expected_outcome_sha256_hex: Option<String>,
    pub(crate) expected_receipt_sha256_hex: String,
    pub(crate) deadline_span_max_ns: u64,
    pub(crate) expected_evidence_source: ScmStopEvidenceSourceV1,
    pub(crate) expected_terminal_commit_qualification: ScmTerminalCommitQualificationV1,
    /// This is a fail-closed demand, not authority. Until an external watcher
    /// proof is integrated, setting it can only make verification return an
    /// error; it can never promote a receipt.
    pub(crate) require_real_scm: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScmStopVerificationReportV1 {
    pub(crate) bounded_stop_complete: bool,
    pub(crate) real_scm_pass: bool,
    pub(crate) real_scm_conclusion: ScmRealQualificationConclusionV1,
    pub(crate) forced_termination: bool,
    pub(crate) active_run_aborted_with_durable_prefix: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScmRealQualificationConclusionV1 {
    /// The A0 coordinator's unforgeable authority has not yet been connected
    /// to this receipt verifier. Receipt fields alone are never authority.
    ExternalWatcherNotIntegrated,
}

/// Deterministic evidence names under the already protected data root.  This
/// module never creates a directory for stop evidence: the caller must have
/// admitted and protected `data_root` before it can create any of these files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScmStopEvidencePathsV1 {
    pub intent_path: PathBuf,
    pub ledger_path: PathBuf,
    pub outcome_path: PathBuf,
    pub receipt_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedOwnerStopOutcomeV1 {
    pub intent: StopIntentV1,
    pub outcome: OwnerStopOutcomeV1,
    pub outcome_binding: StableFileBindingV1,
}

pub(crate) fn scm_stop_evidence_paths_v1(
    data_root: &Path,
    service_instance_id: &[u8; 32],
) -> io::Result<ScmStopEvidencePathsV1> {
    if *service_instance_id == [0; 32] {
        return Err(invalid_input("SCM service instance ID is zero"));
    }
    let root = std::fs::canonicalize(data_root)?;
    if !root.is_absolute() || !root.metadata()?.is_dir() {
        return Err(invalid_input(
            "SCM stop evidence root is not an existing absolute directory",
        ));
    }
    let stem = format!(".forge-acqd-scm-stop-{}", hex(service_instance_id));
    Ok(ScmStopEvidencePathsV1 {
        intent_path: root.join(format!("{stem}.intent.json")),
        ledger_path: root.join(format!("{stem}.ledger.jsonl")),
        outcome_path: root.join(format!("{stem}.outcome.json")),
        receipt_path: root.join(format!("{stem}.receipt.json")),
    })
}

/// Loads a supervisor-created intent through its exact, stable binding.  The
/// owner uses this only after independently proving that the path is the
/// deterministic name for its protected data root and service instance.
pub(crate) fn load_bound_stop_intent_v1(binding: &StableFileBindingV1) -> io::Result<StopIntentV1> {
    load_bound_stop_intent(binding)
}

/// Verifies an owner outcome before the supervisor appends it to its ledger.
/// The caller supplies the already persisted intent binding and deterministic
/// outcome path; the outcome is never trusted merely because the child named
/// that pathname in a response.
pub(crate) fn verify_owner_stop_outcome_for_intent_v1(
    intent_binding: &StableFileBindingV1,
    outcome_path: &Path,
) -> io::Result<VerifiedOwnerStopOutcomeV1> {
    let intent = load_bound_stop_intent(intent_binding)?;
    let mut file = open_stable_file(outcome_path)?;
    let (bytes, outcome_binding) = read_bound_open_file(outcome_path, &mut file)?;
    let outcome: OwnerStopOutcomeV1 = serde_json::from_slice(&bytes).map_err(json_error)?;
    validate_owner_outcome_shape(&outcome)?;
    verify_self_hash_outcome(&outcome)?;
    verify_intent_outcome_linkage(&intent, Some(&outcome))?;
    verify_durable_prefix_locked(Some(&intent), Some(&outcome))?;
    Ok(VerifiedOwnerStopOutcomeV1 {
        intent,
        outcome,
        outcome_binding,
    })
}

/// Takes a stable, read-only file binding after the owner has closed the
/// journal writer.  It is intentionally crate-private: callers still need the
/// StopIntent/Outcome verifier to interpret this local integrity evidence.
pub(crate) fn bind_existing_evidence_file_v1(path: &Path) -> io::Result<StableFileBindingV1> {
    let mut file = open_stable_file(path)?;
    bind_open_file(path, &mut file)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScmStopLedgerEventV1 {
    schema: String,
    event_sequence: u64,
    previous_event_hash_hex: String,
    kind: StopLedgerEventKindV1,
    artifact: StableFileBindingV1,
    event_crc32c: u32,
    event_hash_hex: String,
}

/// Append-only CRC32C + SHA-256 chain for the first two stop facts.  A receipt
/// references a finalized immutable snapshot of this ledger.
pub(crate) struct ScmStopLedgerWriterV1 {
    path: PathBuf,
    file: File,
    next_sequence: u64,
    previous_hash: [u8; 32],
    poisoned: bool,
    intent: Option<StableFileBindingV1>,
    outcome: Option<StableFileBindingV1>,
}

impl ScmStopLedgerWriterV1 {
    pub(crate) fn create_new(path: &Path) -> io::Result<Self> {
        validate_absolute_new_path(path, "SCM stop ledger")?;
        Ok(Self {
            path: path.to_path_buf(),
            file: create_exclusive_new(path)?,
            next_sequence: 0,
            previous_hash: [0; 32],
            poisoned: false,
            intent: None,
            outcome: None,
        })
    }

    pub(crate) fn append_intent(&mut self, artifact: StableFileBindingV1) -> io::Result<()> {
        if self.intent.is_some() {
            return Err(invalid_input("duplicate StopIntent ledger entry"));
        }
        self.append(StopLedgerEventKindV1::IntentPersisted, artifact.clone())?;
        self.intent = Some(artifact);
        Ok(())
    }

    pub(crate) fn append_owner_outcome(&mut self, artifact: StableFileBindingV1) -> io::Result<()> {
        if self.intent.is_none() || self.outcome.is_some() {
            return Err(invalid_input("OwnerStopOutcome ledger ordering is invalid"));
        }
        self.append(
            StopLedgerEventKindV1::OwnerOutcomePersisted,
            artifact.clone(),
        )?;
        self.outcome = Some(artifact);
        Ok(())
    }

    fn append(
        &mut self,
        kind: StopLedgerEventKindV1,
        artifact: StableFileBindingV1,
    ) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid_input("SCM stop ledger is poisoned"));
        }
        let mut event = ScmStopLedgerEventV1 {
            schema: SCM_STOP_RECEIPT_SCHEMA.to_owned(),
            event_sequence: self.next_sequence,
            previous_event_hash_hex: hex(&self.previous_hash),
            kind,
            artifact,
            event_crc32c: 0,
            event_hash_hex: String::new(),
        };
        let result = (|| {
            validate_ledger_event_shape(&event)?;
            let covered = canonical_ledger_covered_bytes(&event)?;
            event.event_crc32c = crc32c(&covered);
            let event_hash = hash_ledger_event(&covered, event.event_crc32c);
            event.event_hash_hex = hex(&event_hash);
            self.file
                .write_all(&serde_json::to_vec(&event).map_err(json_error)?)?;
            self.file.write_all(b"\n")?;
            self.file.flush()?;
            self.file.sync_data()?;
            self.previous_hash = event_hash;
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or_else(|| io::Error::other("SCM stop ledger sequence overflow"))?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(crate) fn finish(mut self) -> io::Result<ScmStopLedgerEvidenceV1> {
        if self.poisoned || self.intent.is_none() {
            return Err(invalid_input("SCM stop ledger has no durable StopIntent"));
        }
        self.file.sync_all()?;
        let binding = bind_open_file(&self.path, &mut self.file)?;
        let replay = replay_ledger_locked(&self.path, &mut self.file)?;
        if replay
            .events
            .first()
            .is_none_or(|event| event.kind != StopLedgerEventKindV1::IntentPersisted)
            || replay.events.len() > 2
            || replay
                .events
                .get(1)
                .is_some_and(|event| event.kind != StopLedgerEventKindV1::OwnerOutcomePersisted)
        {
            return Err(invalid_data("SCM stop ledger order is not canonical"));
        }
        Ok(ScmStopLedgerEvidenceV1 {
            ledger: binding,
            event_count: replay.events.len() as u64,
            last_event_hash_hex: hex(&replay.last_hash),
        })
    }
}

pub(crate) fn publish_stop_intent_v1(
    path: &Path,
    intent: &StopIntentV1,
) -> io::Result<StableFileBindingV1> {
    let mut normalized = intent.clone();
    normalized.intent_sha256_hex.clear();
    validate_stop_intent(&normalized)?;
    let expected = hex(&sha256(&canonical_json(&normalized)?));
    if !intent.intent_sha256_hex.is_empty() && intent.intent_sha256_hex != expected {
        return Err(invalid_input("StopIntent self hash is not canonical"));
    }
    normalized.intent_sha256_hex = expected;
    publish_json_no_replace(path, &normalized)
}

pub(crate) fn publish_owner_stop_outcome_v1(
    path: &Path,
    outcome: &OwnerStopOutcomeV1,
) -> io::Result<StableFileBindingV1> {
    let mut normalized = outcome.clone();
    normalized.outcome_sha256_hex.clear();
    validate_owner_outcome_shape(&normalized)?;
    let expected = hex(&sha256(&canonical_json(&normalized)?));
    if !outcome.outcome_sha256_hex.is_empty() && outcome.outcome_sha256_hex != expected {
        return Err(invalid_input("OwnerStopOutcome self hash is not canonical"));
    }
    normalized.outcome_sha256_hex = expected;
    publish_json_no_replace(path, &normalized)
}

pub(crate) fn publish_scm_stop_receipt_v1(
    path: &Path,
    receipt: &ScmStopReceiptV1,
) -> io::Result<StableFileBindingV1> {
    let mut normalized = receipt.clone();
    normalized.receipt_sha256_hex.clear();
    validate_receipt_shape(&normalized)?;
    let intent = load_bound_stop_intent(&normalized.intent)?;
    let outcome = match &normalized.outcome {
        Some(binding) => Some(load_bound_owner_stop_outcome(binding)?),
        None => None,
    };
    verify_intent_outcome_linkage(&intent, outcome.as_ref())?;
    verify_durable_prefix_locked(Some(&intent), outcome.as_ref())?;
    verify_ledger(
        &normalized.ledger,
        Path::new(&normalized.ledger.ledger.path),
        &normalized.intent,
        normalized.outcome.as_ref(),
    )?;
    normalized.bounded_stop_complete = receipt_bounded_stop_complete(&normalized, Some(&intent))?;
    let expected = hex(&sha256(&canonical_json(&normalized)?));
    if !receipt.receipt_sha256_hex.is_empty() && receipt.receipt_sha256_hex != expected {
        return Err(invalid_input("ScmStopReceipt self hash is not canonical"));
    }
    normalized.receipt_sha256_hex = expected;
    publish_json_no_replace(path, &normalized)
}

pub(crate) fn verify_scm_stop_receipt_v1(
    expected: &ScmStopVerificationExpectationV1,
) -> io::Result<ScmStopVerificationReportV1> {
    validate_expectation(expected)?;
    let mut receipt_file = open_stable_file(&expected.receipt_path)?;
    let (receipt_bytes, receipt_binding) =
        read_bound_open_file(&expected.receipt_path, &mut receipt_file)?;
    let receipt: ScmStopReceiptV1 = serde_json::from_slice(&receipt_bytes).map_err(json_error)?;
    validate_receipt_shape(&receipt)?;
    verify_self_hash_receipt(&receipt)?;
    if receipt_binding.sha256_hex != expected.expected_receipt_sha256_hex {
        return Err(invalid_data("trusted ScmStopReceipt hash mismatch"));
    }
    verify_receipt_expected_context(&receipt, expected)?;

    let mut intent_file = open_stable_file(&expected.intent_path)?;
    let (intent_bytes, intent_binding) =
        read_bound_open_file(&expected.intent_path, &mut intent_file)?;
    let intent: StopIntentV1 = serde_json::from_slice(&intent_bytes).map_err(json_error)?;
    validate_stop_intent(&intent)?;
    verify_self_hash_intent(&intent)?;
    if intent_binding != receipt.intent
        || intent_binding.sha256_hex != expected.expected_intent_sha256_hex
    {
        return Err(invalid_data("trusted StopIntent binding or hash mismatch"));
    }

    let outcome = match (
        &expected.outcome_path,
        &receipt.outcome,
        &expected.expected_outcome_sha256_hex,
    ) {
        (None, None, None) => None,
        (Some(path), Some(receipt_binding), Some(expected_hash)) => {
            let mut file = open_stable_file(path)?;
            let (bytes, binding) = read_bound_open_file(path, &mut file)?;
            let parsed: OwnerStopOutcomeV1 = serde_json::from_slice(&bytes).map_err(json_error)?;
            validate_owner_outcome_shape(&parsed)?;
            verify_self_hash_outcome(&parsed)?;
            if binding != *receipt_binding || binding.sha256_hex != *expected_hash {
                return Err(invalid_data(
                    "trusted OwnerStopOutcome binding or hash mismatch",
                ));
            }
            Some(parsed)
        }
        _ => {
            return Err(invalid_data(
                "outcome path/hash presence does not match receipt",
            ))
        }
    };
    verify_intent_outcome_linkage(&intent, outcome.as_ref())?;
    verify_ledger(
        &receipt.ledger,
        &expected.ledger_path,
        &intent_binding,
        receipt.outcome.as_ref(),
    )?;
    verify_durable_prefix_locked(Some(&intent), outcome.as_ref())?;
    verify_stop_timing(&intent, &receipt, expected)?;

    let bounded = receipt_bounded_stop_complete(&receipt, Some(&intent))?;
    if receipt.bounded_stop_complete != bounded {
        return Err(invalid_data("ScmStopReceipt bounded result is forged"));
    }
    // Receipt-controlled fields cannot mint the A0 coordinator's private
    // ExternalWatcherAuthority. Until that authority is explicitly threaded
    // into this verifier, even a structurally consistent Windows/external
    // receipt remains neutral evidence rather than a real SCM pass.
    let real_scm_pass = false;
    let real_scm_conclusion = ScmRealQualificationConclusionV1::ExternalWatcherNotIntegrated;
    if expected.require_real_scm {
        return Err(invalid_data(
            "real SCM gate requires bounded WindowsScmApi evidence with an external watcher commit",
        ));
    }
    let final_receipt_binding = bind_open_file(&expected.receipt_path, &mut receipt_file)?;
    if final_receipt_binding != receipt_binding {
        return Err(invalid_data(
            "ScmStopReceipt changed during locked verification",
        ));
    }
    Ok(ScmStopVerificationReportV1 {
        bounded_stop_complete: bounded,
        real_scm_pass,
        real_scm_conclusion,
        forced_termination: receipt.forced_termination,
        active_run_aborted_with_durable_prefix: outcome.as_ref().is_some_and(|value| {
            value.final_run_truth == RunStopTruthV1::ActiveRunAbortedWithDurablePrefix
        }),
    })
}

fn validate_stop_intent(intent: &StopIntentV1) -> io::Result<()> {
    if intent.schema != SCM_STOP_RECEIPT_SCHEMA
        || intent.service_name.trim().is_empty()
        || !is_hex(&intent.service_instance_id_hex, 64)
        || !valid_process(&intent.owner_process)
        || intent.scm_control_wall_time_unix_ns == 0
        || intent.scm_control_monotonic_ns == 0
        || intent.deadline_monotonic_ns <= intent.scm_control_monotonic_ns
        || intent.private_request_sequence == Some(0)
        || intent.private_epoch == Some(0)
        || intent
            .run_id_hex
            .as_deref()
            .is_some_and(|id| !is_hex(id, 32))
        || (!intent.intent_sha256_hex.is_empty() && !is_hex(&intent.intent_sha256_hex, 64))
    {
        return Err(invalid_data("StopIntent shape is invalid"));
    }
    match intent.intent_kind {
        StopIntentKindV1::RuntimeGracefulShutdown => {
            let run_state = RunState::from_wire(
                intent
                    .run_state_wire
                    .ok_or_else(|| invalid_data("runtime StopIntent lacks exact Run state"))?,
            )?;
            if intent.private_request_sequence.is_none()
                || intent.private_epoch.is_none()
                || intent.active_run_at_intent != intent.run_id_hex.is_some()
                || run_state_requires_identity(run_state) != intent.active_run_at_intent
            {
                return Err(invalid_data(
                    "runtime StopIntent request or Run context is contradictory",
                ));
            }
        }
        StopIntentKindV1::StartupBeforeOwnerReady
        | StopIntentKindV1::RuntimeSnapshotUnavailable => {
            if intent.private_request_sequence.is_some()
                || intent.private_epoch.is_some()
                || intent.run_state_wire.is_some()
                || intent.active_run_at_intent
                || intent.run_id_hex.is_some()
            {
                return Err(invalid_data(
                    "unknown-context StopIntent must not invent private or Run evidence",
                ));
            }
        }
    }
    Ok(())
}

fn validate_owner_outcome_shape(outcome: &OwnerStopOutcomeV1) -> io::Result<()> {
    if outcome.schema != SCM_STOP_RECEIPT_SCHEMA
        || !is_hex(&outcome.intent_sha256_hex, 64)
        || outcome.service_name.trim().is_empty()
        || !is_hex(&outcome.service_instance_id_hex, 64)
        || !valid_process(&outcome.owner_process)
        || !outcome.private_fack_observed
        || outcome.private_epoch == 0
        || outcome.completed_wall_time_unix_ns == 0
        || outcome.completed_monotonic_ns == 0
        || outcome
            .run_id_hex
            .as_deref()
            .is_some_and(|id| !is_hex(id, 32))
        || (!outcome.outcome_sha256_hex.is_empty() && !is_hex(&outcome.outcome_sha256_hex, 64))
    {
        return Err(invalid_data("OwnerStopOutcome shape is invalid"));
    }
    match outcome.final_run_truth {
        RunStopTruthV1::IdleCleanStop => {
            if outcome.run_id_hex.is_some()
                || outcome.durable_prefix.is_some()
                || outcome.capture_exit_reason != CaptureExitReasonV1::IdleOwnerShutdown
            {
                return Err(invalid_data("idle stop cannot claim a Run prefix"));
            }
        }
        RunStopTruthV1::ActiveRunAbortedWithDurablePrefix => {
            let prefix = outcome
                .durable_prefix
                .as_ref()
                .ok_or_else(|| invalid_data("active SCM stop lacks durable prefix"))?;
            if outcome.run_id_hex.is_none()
                || outcome.capture_exit_reason != CaptureExitReasonV1::ExplicitScmStopAbort
            {
                return Err(invalid_data(
                    "active SCM stop semantics are not fail-closed abort",
                ));
            }
            validate_durable_prefix(prefix)?;
        }
        RunStopTruthV1::AlreadyFailed => {
            if outcome.run_id_hex.is_none()
                || outcome.durable_prefix.is_some()
                || outcome.capture_exit_reason != CaptureExitReasonV1::PreexistingRunFailure
            {
                return Err(invalid_data("already-failed stop exit reason is invalid"));
            }
        }
    }
    Ok(())
}

fn validate_durable_prefix(prefix: &DurablePrefixV1) -> io::Result<()> {
    validate_file_binding(&prefix.journal)?;
    if (prefix.durable_record_count == 0) != prefix.durable_watermark_journal_sequence.is_none()
        || prefix
            .last_observed_record_sequence
            .is_some_and(|sequence| {
                prefix
                    .durable_watermark_journal_sequence
                    .is_none_or(|watermark| sequence < watermark)
            })
        || prefix.last_observed_record_sequence.is_some()
        || prefix.last_observed_sample_index.is_some()
        || prefix.journal_poisoned
        || prefix.journal_fault.is_some()
    {
        return Err(invalid_data("durable prefix is malformed"));
    }
    Ok(())
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn validate_receipt_shape(receipt: &ScmStopReceiptV1) -> io::Result<()> {
    if receipt.schema != SCM_STOP_RECEIPT_SCHEMA
        || receipt.service_name.trim().is_empty()
        || !is_hex(&receipt.service_instance_id_hex, 64)
        || receipt
            .run_id_hex
            .as_deref()
            .is_some_and(|id| !is_hex(id, 32))
        || !valid_process(&receipt.owner_process)
        || receipt.stop_completed_wall_time_unix_ns == 0
        || receipt.stop_completed_monotonic_ns == 0
        || receipt.elapsed_ns == 0
        || (!receipt.receipt_sha256_hex.is_empty() && !is_hex(&receipt.receipt_sha256_hex, 64))
    {
        return Err(invalid_data("ScmStopReceipt shape is invalid"));
    }
    validate_file_binding(&receipt.intent)?;
    if let Some(outcome) = &receipt.outcome {
        validate_file_binding(outcome)?;
    }
    validate_file_binding(&receipt.ledger.ledger)?;
    if receipt.ledger.event_count == 0 || !is_hex(&receipt.ledger.last_event_hash_hex, 64) {
        return Err(invalid_data("SCM stop ledger evidence is invalid"));
    }
    if receipt.job_empty_proven != (receipt.job_active_processes_after_wait == 0) {
        return Err(invalid_data("Job empty evidence is contradictory"));
    }
    if !terminal_commit_pair_is_valid(
        receipt.evidence_source,
        receipt.terminal_commit_qualification,
    ) {
        return Err(invalid_data(
            "SCM evidence source and terminal commit qualification contradict",
        ));
    }
    if receipt.forced_termination && receipt.outcome.is_some() && receipt.bounded_stop_complete {
        return Err(invalid_data(
            "forced owner termination cannot be graceful completion",
        ));
    }
    Ok(())
}

fn receipt_bounded_stop_complete(
    receipt: &ScmStopReceiptV1,
    intent: Option<&StopIntentV1>,
) -> io::Result<bool> {
    validate_receipt_shape(receipt)?;
    let terminal_commit_is_bounded = matches!(
        receipt.terminal_commit_qualification,
        ScmTerminalCommitQualificationV1::SyntheticBoundedCommit
            | ScmTerminalCommitQualificationV1::ExternalScmWatcherObserved
    );
    let complete_evidence = terminal_commit_is_bounded
        && receipt.outcome.is_some()
        && !receipt.forced_termination
        && receipt.retained_process_exit_observed
        && receipt.owner_exit_code == Some(0)
        && receipt.job_empty_proven
        && intent.is_some_and(|intent| {
            receipt.stop_completed_monotonic_ns <= intent.deadline_monotonic_ns
                && receipt.stop_completed_monotonic_ns >= intent.scm_control_monotonic_ns
                && receipt.elapsed_ns
                    == receipt.stop_completed_monotonic_ns - intent.scm_control_monotonic_ns
        });
    if !complete_evidence && receipt.final_scm_status != ScmFinalStatusV1::Failed {
        return Err(invalid_data(
            "fail-closed stop evidence must report final SCM status Failed",
        ));
    }
    if receipt.final_scm_status == ScmFinalStatusV1::StopPending {
        return Err(invalid_data(
            "published final stop receipt cannot remain StopPending",
        ));
    }
    Ok(complete_evidence && receipt.final_scm_status == ScmFinalStatusV1::Stopped)
}

fn verify_receipt_expected_context(
    receipt: &ScmStopReceiptV1,
    expected: &ScmStopVerificationExpectationV1,
) -> io::Result<()> {
    if receipt.service_name != expected.service_name
        || receipt.service_instance_id_hex != expected.service_instance_id_hex
        || receipt.run_id_hex != expected.run_id_hex
        || receipt.owner_process != expected.owner_process
        || receipt.evidence_source != expected.expected_evidence_source
        || receipt.terminal_commit_qualification != expected.expected_terminal_commit_qualification
        || receipt.intent.path != path_string(&expected.intent_path)?
        || receipt.outcome.as_ref().map(|value| value.path.as_str())
            != expected
                .outcome_path
                .as_ref()
                .map(|path| path_string(path))
                .transpose()?
                .as_deref()
        || receipt.ledger.ledger.path != path_string(&expected.ledger_path)?
    {
        return Err(invalid_data(
            "ScmStopReceipt does not match trusted context",
        ));
    }
    Ok(())
}

fn verify_intent_outcome_linkage(
    intent: &StopIntentV1,
    outcome: Option<&OwnerStopOutcomeV1>,
) -> io::Result<()> {
    let Some(outcome) = outcome else {
        return Ok(());
    };
    if outcome.intent_sha256_hex != intent.intent_sha256_hex
        || outcome.service_name != intent.service_name
        || outcome.service_instance_id_hex != intent.service_instance_id_hex
        || outcome.run_id_hex != intent.run_id_hex
        || outcome.owner_process != intent.owner_process
        || Some(outcome.private_request_sequence) != intent.private_request_sequence
        || Some(outcome.private_epoch) != intent.private_epoch
        || outcome.completed_monotonic_ns < intent.scm_control_monotonic_ns
        || outcome.completed_monotonic_ns > intent.deadline_monotonic_ns
    {
        return Err(invalid_data("OwnerStopOutcome does not link to StopIntent"));
    }
    if intent.intent_kind != StopIntentKindV1::RuntimeGracefulShutdown {
        return Err(invalid_data(
            "unknown-context StopIntent cannot have an owner outcome",
        ));
    }
    let run_state = RunState::from_wire(
        intent
            .run_state_wire
            .ok_or_else(|| invalid_data("owner outcome intent lacks Run state"))?,
    )?;
    match (run_state, outcome.final_run_truth) {
        (RunState::Failed, RunStopTruthV1::AlreadyFailed) => {}
        (
            RunState::Prepared
            | RunState::Armed
            | RunState::Recording
            | RunState::Stopped
            | RunState::Aborted,
            RunStopTruthV1::ActiveRunAbortedWithDurablePrefix,
        ) => {}
        (
            RunState::New | RunState::JournalSealed | RunState::Finalized,
            RunStopTruthV1::IdleCleanStop,
        ) => {}
        _ => return Err(invalid_data("owner final Run truth contradicts StopIntent")),
    }
    Ok(())
}

fn verify_durable_prefix_locked(
    intent: Option<&StopIntentV1>,
    outcome: Option<&OwnerStopOutcomeV1>,
) -> io::Result<()> {
    let Some(prefix) = outcome.and_then(|value| value.durable_prefix.as_ref()) else {
        return Ok(());
    };
    let intent = intent.ok_or_else(|| invalid_data("durable prefix lacks StopIntent"))?;
    let expected_run_id = intent
        .run_id_hex
        .as_deref()
        .ok_or_else(|| invalid_data("durable prefix intent lacks Run identity"))?;
    let path = Path::new(&prefix.journal.path);
    let mut file = open_stable_file(path)?;
    let before = bind_open_file(path, &mut file)?;
    if before != prefix.journal {
        return Err(invalid_data("durable journal evidence binding changed"));
    }
    let scan = scan_journal(path)?;
    if hex(&scan.identity.run_id) != expected_run_id
        || scan.seal.is_some()
        || scan.torn_tail
        || scan.file_len != scan.durable.durable_valid_len
        || scan.durable.durable_journal_sequence != prefix.durable_watermark_journal_sequence
        || scan.durable.durable_record_count != prefix.durable_record_count
        || (prefix.durable_record_count == 0
            && (scan.durable.durable_valid_len != FILE_HEADER_LEN as u64
                || scan.valid_len != FILE_HEADER_LEN as u64))
        || prefix.last_observed_record_sequence.is_some()
        || prefix.last_observed_sample_index.is_some()
        || prefix.journal_poisoned
        || prefix.journal_fault.is_some()
    {
        return Err(invalid_data(
            "durable prefix fields do not match the independently scanned checkpoint",
        ));
    }
    let after_retained = bind_open_file(path, &mut file)?;
    let after_path = bind_existing_evidence_file_v1(path)?;
    if after_retained != before || after_path != before {
        return Err(invalid_data(
            "durable journal changed or its pathname was substituted during scan",
        ));
    }
    Ok(())
}

fn run_state_requires_identity(state: RunState) -> bool {
    matches!(
        state,
        RunState::Prepared
            | RunState::Armed
            | RunState::Recording
            | RunState::Stopped
            | RunState::Aborted
            | RunState::Failed
    )
}

fn load_bound_stop_intent(binding: &StableFileBindingV1) -> io::Result<StopIntentV1> {
    let path = Path::new(&binding.path);
    let mut file = open_stable_file(path)?;
    let (bytes, actual) = read_bound_open_file(path, &mut file)?;
    if actual != *binding {
        return Err(invalid_data(
            "StopIntent file binding changed before receipt publication",
        ));
    }
    let intent: StopIntentV1 = serde_json::from_slice(&bytes).map_err(json_error)?;
    validate_stop_intent(&intent)?;
    verify_self_hash_intent(&intent)?;
    Ok(intent)
}

fn load_bound_owner_stop_outcome(binding: &StableFileBindingV1) -> io::Result<OwnerStopOutcomeV1> {
    let path = Path::new(&binding.path);
    let mut file = open_stable_file(path)?;
    let (bytes, actual) = read_bound_open_file(path, &mut file)?;
    if actual != *binding {
        return Err(invalid_data(
            "OwnerStopOutcome file binding changed before receipt publication",
        ));
    }
    let outcome: OwnerStopOutcomeV1 = serde_json::from_slice(&bytes).map_err(json_error)?;
    validate_owner_outcome_shape(&outcome)?;
    verify_self_hash_outcome(&outcome)?;
    Ok(outcome)
}

fn verify_stop_timing(
    intent: &StopIntentV1,
    receipt: &ScmStopReceiptV1,
    expected: &ScmStopVerificationExpectationV1,
) -> io::Result<()> {
    let span = intent
        .deadline_monotonic_ns
        .checked_sub(intent.scm_control_monotonic_ns)
        .ok_or_else(|| invalid_data("StopIntent deadline precedes control"))?;
    let elapsed = receipt
        .stop_completed_monotonic_ns
        .checked_sub(intent.scm_control_monotonic_ns)
        .ok_or_else(|| invalid_data("ScmStopReceipt precedes control intent"))?;
    if span > expected.deadline_span_max_ns || receipt.elapsed_ns != elapsed {
        return Err(invalid_data(
            "SCM stop timing contradicts trusted deadline policy",
        ));
    }
    Ok(())
}

fn verify_ledger(
    evidence: &ScmStopLedgerEvidenceV1,
    path: &Path,
    intent: &StableFileBindingV1,
    outcome: Option<&StableFileBindingV1>,
) -> io::Result<()> {
    let mut file = open_stable_file(path)?;
    let binding = bind_open_file(path, &mut file)?;
    if binding != evidence.ledger {
        return Err(invalid_data("SCM stop ledger binding changed"));
    }
    let replay = replay_ledger_locked(path, &mut file)?;
    if replay.events.len() as u64 != evidence.event_count
        || hex(&replay.last_hash) != evidence.last_event_hash_hex
        || replay.events.first().is_none_or(|event| {
            event.kind != StopLedgerEventKindV1::IntentPersisted || event.artifact != *intent
        })
        || (outcome.is_some()
            != (replay.events.len() == 2
                && replay.events.get(1).is_some_and(|event| {
                    event.kind == StopLedgerEventKindV1::OwnerOutcomePersisted
                        && Some(&event.artifact) == outcome
                })))
    {
        return Err(invalid_data(
            "SCM stop ledger is missing, reordered, or duplicated",
        ));
    }
    Ok(())
}

struct LedgerReplayV1 {
    events: Vec<ScmStopLedgerEventV1>,
    last_hash: [u8; 32],
}

fn replay_ledger_locked(path: &Path, file: &mut File) -> io::Result<LedgerReplayV1> {
    let (bytes, _) = read_bound_open_file(path, file)?;
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err(invalid_data(
            "SCM stop ledger is not a durable complete JSONL stream",
        ));
    }
    let mut previous = [0_u8; 32];
    let mut events = Vec::new();
    for (sequence, line) in bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        let event: ScmStopLedgerEventV1 = serde_json::from_slice(line).map_err(json_error)?;
        validate_ledger_event_shape(&event)?;
        if event.event_sequence != sequence as u64
            || event.previous_event_hash_hex != hex(&previous)
        {
            return Err(invalid_data("SCM stop ledger sequence or chain is invalid"));
        }
        let covered = canonical_ledger_covered_bytes(&event)?;
        if event.event_crc32c != crc32c(&covered) {
            return Err(invalid_data("SCM stop ledger CRC32C is invalid"));
        }
        previous = hash_ledger_event(&covered, event.event_crc32c);
        if event.event_hash_hex != hex(&previous) {
            return Err(invalid_data("SCM stop ledger SHA-256 chain is invalid"));
        }
        events.push(event);
    }
    Ok(LedgerReplayV1 {
        events,
        last_hash: previous,
    })
}

fn validate_ledger_event_shape(event: &ScmStopLedgerEventV1) -> io::Result<()> {
    if event.schema != SCM_STOP_RECEIPT_SCHEMA
        || !is_hex_exact(&event.previous_event_hash_hex, 64)
        || !event.event_hash_hex.is_empty() && !is_hex(&event.event_hash_hex, 64)
    {
        return Err(invalid_data("SCM stop ledger event shape is invalid"));
    }
    validate_file_binding(&event.artifact)
}

fn canonical_ledger_covered_bytes(event: &ScmStopLedgerEventV1) -> io::Result<Vec<u8>> {
    let mut normalized = event.clone();
    normalized.event_crc32c = 0;
    normalized.event_hash_hex.clear();
    canonical_json(&normalized)
}

fn hash_ledger_event(covered: &[u8], crc: u32) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(LEDGER_EVENT_DOMAIN.len() + covered.len() + 4);
    bytes.extend_from_slice(LEDGER_EVENT_DOMAIN);
    bytes.extend_from_slice(covered);
    bytes.extend_from_slice(&crc.to_le_bytes());
    sha256(&bytes)
}

fn verify_self_hash_intent(value: &StopIntentV1) -> io::Result<()> {
    let mut normalized = value.clone();
    let expected = std::mem::take(&mut normalized.intent_sha256_hex);
    if expected != hex(&sha256(&canonical_json(&normalized)?)) {
        return Err(invalid_data("StopIntent self hash is invalid"));
    }
    Ok(())
}

fn verify_self_hash_outcome(value: &OwnerStopOutcomeV1) -> io::Result<()> {
    let mut normalized = value.clone();
    let expected = std::mem::take(&mut normalized.outcome_sha256_hex);
    if expected != hex(&sha256(&canonical_json(&normalized)?)) {
        return Err(invalid_data("OwnerStopOutcome self hash is invalid"));
    }
    Ok(())
}

fn verify_self_hash_receipt(value: &ScmStopReceiptV1) -> io::Result<()> {
    let mut normalized = value.clone();
    let expected = std::mem::take(&mut normalized.receipt_sha256_hex);
    if expected != hex(&sha256(&canonical_json(&normalized)?)) {
        return Err(invalid_data("ScmStopReceipt self hash is invalid"));
    }
    Ok(())
}

fn validate_expectation(expected: &ScmStopVerificationExpectationV1) -> io::Result<()> {
    if expected.service_name.trim().is_empty()
        || !is_hex(&expected.service_instance_id_hex, 64)
        || expected
            .run_id_hex
            .as_deref()
            .is_some_and(|id| !is_hex(id, 32))
        || !valid_process(&expected.owner_process)
        || expected.deadline_span_max_ns == 0
        || !terminal_commit_pair_is_valid(
            expected.expected_evidence_source,
            expected.expected_terminal_commit_qualification,
        )
        || !is_hex(&expected.expected_intent_sha256_hex, 64)
        || !is_hex(&expected.expected_receipt_sha256_hex, 64)
        || expected
            .expected_outcome_sha256_hex
            .as_deref()
            .is_some_and(|hash| !is_hex(hash, 64))
        || [
            &expected.intent_path,
            &expected.receipt_path,
            &expected.ledger_path,
        ]
        .iter()
        .any(|path| !path.is_absolute())
        || expected
            .outcome_path
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        || (expected.outcome_path.is_some() != expected.expected_outcome_sha256_hex.is_some())
    {
        return Err(invalid_input(
            "trusted SCM stop verification expectation is malformed",
        ));
    }
    Ok(())
}

fn terminal_commit_pair_is_valid(
    evidence_source: ScmStopEvidenceSourceV1,
    qualification: ScmTerminalCommitQualificationV1,
) -> bool {
    matches!(
        (evidence_source, qualification),
        (
            ScmStopEvidenceSourceV1::UnqualifiedWindowsRuntime,
            ScmTerminalCommitQualificationV1::UnqualifiedSynchronousIo,
        ) | (
            ScmStopEvidenceSourceV1::SyntheticTest,
            ScmTerminalCommitQualificationV1::SyntheticBoundedCommit,
        ) | (
            ScmStopEvidenceSourceV1::WindowsScmApi,
            ScmTerminalCommitQualificationV1::ExternalScmWatcherObserved,
        )
    )
}

fn publish_json_no_replace<T: Serialize>(
    path: &Path,
    value: &T,
) -> io::Result<StableFileBindingV1> {
    validate_absolute_new_path(path, "SCM stop evidence")?;
    let bytes = canonical_json(value)?;
    let pending = pending_path(path)?;
    let mut file = create_exclusive_new(&pending)?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        rename_no_overwrite(&pending, path)?;
        let mut final_file = open_stable_file(path)?;
        let binding = bind_open_file(path, &mut final_file)?;
        if binding.sha256_hex != hex(&sha256(&bytes)) {
            return Err(invalid_data(
                "published evidence hash differs from canonical bytes",
            ));
        }
        Ok(binding)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&pending);
    }
    result
}

fn pending_path(path: &Path) -> io::Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_input("evidence path lacks parent"))?;
    for sequence in 0_u32..1024 {
        let candidate = parent.join(format!(
            ".{}.{}.{}.pending",
            path.file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| invalid_input("evidence filename is not UTF-8"))?,
            std::process::id(),
            sequence
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no unique pending evidence path",
    ))
}

fn validate_absolute_new_path(path: &Path, noun: &str) -> io::Result<()> {
    if !path.is_absolute() || path.parent().is_none_or(|parent| !parent.is_dir()) || path.exists() {
        return Err(invalid_input(format!(
            "{noun} path must be absolute, absent, and have an existing parent"
        )));
    }
    Ok(())
}

fn create_exclusive_new(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
    }
    #[cfg(not(windows))]
    {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
    }
}

#[cfg(windows)]
fn rename_no_overwrite(pending: &Path, final_path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
    let source: Vec<u16> = pending.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = final_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn rename_no_overwrite(pending: &Path, final_path: &Path) -> io::Result<()> {
    std::fs::hard_link(pending, final_path)?;
    let _ = std::fs::remove_file(pending);
    Ok(())
}

fn open_stable_file(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

fn bind_open_file(path: &Path, file: &mut File) -> io::Result<StableFileBindingV1> {
    file.seek(SeekFrom::Start(0))?;
    let before = stable_file_identity(file)?;
    let sha256_hex = sha256_reader(file)?;
    let after = stable_file_identity(file)?;
    if before != after {
        return Err(invalid_data(
            "evidence handle identity changed while hashing",
        ));
    }
    Ok(StableFileBindingV1 {
        path: path_string(path)?,
        sha256_hex,
        file_identity: after,
    })
}

fn read_bound_open_file(
    path: &Path,
    file: &mut File,
) -> io::Result<(Vec<u8>, StableFileBindingV1)> {
    file.seek(SeekFrom::Start(0))?;
    let before = stable_file_identity(file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let after = stable_file_identity(file)?;
    if before != after || bytes.len() as u64 != after.bytes {
        return Err(invalid_data(
            "evidence changed while read through retained handle",
        ));
    }
    let sha256_hex = hex(&sha256(&bytes));
    Ok((
        bytes,
        StableFileBindingV1 {
            path: path_string(path)?,
            sha256_hex,
            file_identity: after,
        },
    ))
}

#[cfg(windows)]
fn stable_file_identity(file: &File) -> io::Result<StableFileIdentityV1> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let identity = StableFileIdentityV1 {
        volume_serial_number: u64::from(information.dwVolumeSerialNumber),
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        bytes: (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow),
    };
    if !valid_file_identity(&identity) {
        return Err(invalid_data("invalid Windows evidence file identity"));
    }
    Ok(identity)
}

#[cfg(unix)]
fn stable_file_identity(file: &File) -> io::Result<StableFileIdentityV1> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(StableFileIdentityV1 {
        volume_serial_number: metadata.dev(),
        file_index: metadata.ino(),
        bytes: metadata.len(),
    })
}

#[cfg(not(any(windows, unix)))]
fn stable_file_identity(_: &File) -> io::Result<StableFileIdentityV1> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable file identity unsupported",
    ))
}

fn sha256_reader(file: &mut File) -> io::Result<String> {
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

fn validate_file_binding(value: &StableFileBindingV1) -> io::Result<()> {
    if !Path::new(&value.path).is_absolute()
        || !is_hex(&value.sha256_hex, 64)
        || !valid_file_identity(&value.file_identity)
    {
        return Err(invalid_data("evidence file binding is malformed"));
    }
    Ok(())
}

fn valid_file_identity(value: &StableFileIdentityV1) -> bool {
    value.volume_serial_number != 0 && value.file_index != 0
}

fn valid_process(value: &StopProcessIdentityV1) -> bool {
    value.pid != 0 && value.creation_time_100ns != 0
}

fn is_hex(value: &str, expected_len: usize) -> bool {
    is_hex_exact(value, expected_len) && value.bytes().any(|byte| byte != b'0')
}

fn is_hex_exact(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn path_string(path: &Path) -> io::Result<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid_input("path is not UTF-8"))
}

fn canonical_json<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(json_error)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn json_error(error: serde_json::Error) -> io::Error {
    invalid_data(error.to_string())
}
fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{JournalIdentity, JournalWriter};
    use forge_protocol_v1::{
        encode_record, CanonicalRecordEnvelopeV1, RecordKind, SampleBlockV1,
        SAMPLE_BLOCK_FLAG_COMPLETE, SAMPLE_BLOCK_FLAG_HARDWARE_TIMESTAMPED,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        intent_path: PathBuf,
        outcome_path: PathBuf,
        receipt_path: PathBuf,
        ledger_path: PathBuf,
        journal_path: PathBuf,
        service_name: String,
        instance: String,
        run: String,
        owner: StopProcessIdentityV1,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "forge-scm-stop-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&root).unwrap();
            let journal_path = root.join("prefix.journal");
            let run_id = [0x22; 16];
            let block = SampleBlockV1 {
                flags: SAMPLE_BLOCK_FLAG_COMPLETE | SAMPLE_BLOCK_FLAG_HARDWARE_TIMESTAMPED,
                samples_per_channel: 2,
                channel_count: 2,
                sample_format: 1,
                sample_rate_numerator_hz: 2_000,
                sample_rate_denominator: 1,
                first_sample_counter: 0,
                samples: vec![1, -1, 2, -2],
            };
            let record = encode_record(
                &CanonicalRecordEnvelopeV1 {
                    record_kind: RecordKind::SampleBlock,
                    flags: 0,
                    run_id,
                    pod_id: [0x11; 16],
                    headstage_id: [0x33; 16],
                    record_sequence: 0,
                    frame_start: 0,
                    frame_end_exclusive: 2,
                    sample_start: 0,
                    sample_end_exclusive: 2,
                    global_time_start_ns: 0,
                    global_time_end_exclusive_ns: 1_000_000,
                    channel_layout_id: 7,
                    channel_count: 2,
                    sample_format: 1,
                },
                &block.encode().unwrap(),
            )
            .unwrap();
            let mut journal =
                JournalWriter::create(&journal_path, JournalIdentity::for_run(run_id).unwrap())
                    .unwrap();
            journal.append_record(&record).unwrap();
            journal.durability_barrier().unwrap();
            drop(journal);
            Self {
                intent_path: root.join("intent.json"),
                outcome_path: root.join("outcome.json"),
                receipt_path: root.join("receipt.json"),
                ledger_path: root.join("stop.jsonl"),
                journal_path,
                service_name: "ForgeAcquire".to_owned(),
                instance: "11".repeat(32),
                run: "22".repeat(16),
                owner: StopProcessIdentityV1 {
                    pid: 42,
                    creation_time_100ns: 99,
                },
                root,
            }
        }
        fn intent(&self, active: bool) -> StopIntentV1 {
            StopIntentV1 {
                schema: SCM_STOP_RECEIPT_SCHEMA.to_owned(),
                service_name: self.service_name.clone(),
                service_instance_id_hex: self.instance.clone(),
                run_id_hex: active.then(|| self.run.clone()),
                owner_process: self.owner.clone(),
                reason: ScmStopReasonV1::ServiceControlStop,
                intent_kind: StopIntentKindV1::RuntimeGracefulShutdown,
                scm_control_wall_time_unix_ns: 10,
                scm_control_monotonic_ns: 100,
                deadline_monotonic_ns: 1_100,
                private_request_sequence: Some(7),
                private_epoch: Some(3),
                run_state_wire: Some(if active {
                    RunState::Recording.wire_value()
                } else {
                    RunState::New.wire_value()
                }),
                active_run_at_intent: active,
                intent_sha256_hex: String::new(),
            }
        }
        fn prefix(&self) -> DurablePrefixV1 {
            let scan = scan_journal(&self.journal_path).unwrap();
            let mut file = open_stable_file(&self.journal_path).unwrap();
            DurablePrefixV1 {
                journal: bind_open_file(&self.journal_path, &mut file).unwrap(),
                durable_watermark_journal_sequence: scan.durable.durable_journal_sequence,
                durable_record_count: scan.durable.durable_record_count,
                last_observed_record_sequence: None,
                last_observed_sample_index: None,
                journal_poisoned: false,
                journal_fault: None,
            }
        }
        fn header_only_prefix(&self) -> DurablePrefixV1 {
            let journal_path = self.root.join("header-only.journal");
            let mut journal =
                JournalWriter::create(&journal_path, JournalIdentity::for_run([0x22; 16]).unwrap())
                    .unwrap();
            journal.durability_barrier().unwrap();
            drop(journal);
            let scan = scan_journal(&journal_path).unwrap();
            assert_eq!(scan.file_len, FILE_HEADER_LEN as u64);
            assert_eq!(scan.durable.durable_valid_len, FILE_HEADER_LEN as u64);
            assert_eq!(scan.durable.durable_record_count, 0);
            assert_eq!(scan.durable.durable_journal_sequence, None);
            assert!(scan.seal.is_none());
            assert!(!scan.torn_tail);
            let mut file = open_stable_file(&journal_path).unwrap();
            DurablePrefixV1 {
                journal: bind_open_file(&journal_path, &mut file).unwrap(),
                durable_watermark_journal_sequence: None,
                durable_record_count: 0,
                last_observed_record_sequence: None,
                last_observed_sample_index: None,
                journal_poisoned: false,
                journal_fault: None,
            }
        }
        fn outcome(&self, intent_hash: String, active: bool) -> OwnerStopOutcomeV1 {
            OwnerStopOutcomeV1 {
                schema: SCM_STOP_RECEIPT_SCHEMA.to_owned(),
                intent_sha256_hex: intent_hash,
                service_name: self.service_name.clone(),
                service_instance_id_hex: self.instance.clone(),
                run_id_hex: active.then(|| self.run.clone()),
                owner_process: self.owner.clone(),
                private_fack_observed: true,
                private_request_sequence: 7,
                private_epoch: 3,
                completed_wall_time_unix_ns: 11,
                completed_monotonic_ns: 200,
                final_run_truth: if active {
                    RunStopTruthV1::ActiveRunAbortedWithDurablePrefix
                } else {
                    RunStopTruthV1::IdleCleanStop
                },
                durable_prefix: active.then(|| self.prefix()),
                capture_exit_reason: if active {
                    CaptureExitReasonV1::ExplicitScmStopAbort
                } else {
                    CaptureExitReasonV1::IdleOwnerShutdown
                },
                outcome_sha256_hex: String::new(),
            }
        }
        fn cleanup(self) {
            let _ = std::fs::remove_dir_all(self.root);
        }
    }

    fn hash_from_binding(binding: &StableFileBindingV1) -> String {
        binding.sha256_hex.clone()
    }

    fn publish_complete(
        f: &Fixture,
        active: bool,
        forced: bool,
        job_empty: bool,
        late: bool,
        source: ScmStopEvidenceSourceV1,
    ) -> (
        StopIntentV1,
        Option<OwnerStopOutcomeV1>,
        ScmStopReceiptV1,
        ScmStopVerificationExpectationV1,
    ) {
        let intent_binding = publish_stop_intent_v1(&f.intent_path, &f.intent(active)).unwrap();
        let intent: StopIntentV1 =
            serde_json::from_slice(&std::fs::read(&f.intent_path).unwrap()).unwrap();
        let mut ledger = ScmStopLedgerWriterV1::create_new(&f.ledger_path).unwrap();
        ledger.append_intent(intent_binding.clone()).unwrap();
        let (outcome, outcome_binding) = if forced {
            (None, None)
        } else {
            let binding = publish_owner_stop_outcome_v1(
                &f.outcome_path,
                &f.outcome(intent.intent_sha256_hex.clone(), active),
            )
            .unwrap();
            let outcome: OwnerStopOutcomeV1 =
                serde_json::from_slice(&std::fs::read(&f.outcome_path).unwrap()).unwrap();
            ledger.append_owner_outcome(binding.clone()).unwrap();
            (Some(outcome), Some(binding))
        };
        let ledger_evidence = ledger.finish().unwrap();
        let outcome_evidence_sha256 = outcome_binding.as_ref().map(hash_from_binding);
        let stop_ns = if late { 1_200 } else { 300 };
        let terminal_commit_qualification = match source {
            ScmStopEvidenceSourceV1::UnqualifiedWindowsRuntime => {
                ScmTerminalCommitQualificationV1::UnqualifiedSynchronousIo
            }
            ScmStopEvidenceSourceV1::WindowsScmApi => {
                ScmTerminalCommitQualificationV1::ExternalScmWatcherObserved
            }
            ScmStopEvidenceSourceV1::SyntheticTest => {
                ScmTerminalCommitQualificationV1::SyntheticBoundedCommit
            }
        };
        let receipt = ScmStopReceiptV1 {
            schema: SCM_STOP_RECEIPT_SCHEMA.to_owned(),
            evidence_source: source,
            terminal_commit_qualification,
            service_name: f.service_name.clone(),
            service_instance_id_hex: f.instance.clone(),
            run_id_hex: active.then(|| f.run.clone()),
            owner_process: f.owner.clone(),
            intent: intent_binding.clone(),
            outcome: outcome_binding,
            ledger: ledger_evidence,
            owner_exit_code: (!forced).then_some(0),
            forced_termination: forced,
            retained_process_exit_observed: true,
            job_active_processes_after_wait: if job_empty { 0 } else { 1 },
            job_empty_proven: job_empty,
            stop_completed_wall_time_unix_ns: 12,
            stop_completed_monotonic_ns: stop_ns,
            elapsed_ns: stop_ns - 100,
            final_scm_status: if forced || !job_empty || late {
                ScmFinalStatusV1::Failed
            } else {
                ScmFinalStatusV1::Stopped
            },
            bounded_stop_complete: false,
            receipt_sha256_hex: String::new(),
        };
        let receipt_binding = publish_scm_stop_receipt_v1(&f.receipt_path, &receipt).unwrap();
        let receipt: ScmStopReceiptV1 =
            serde_json::from_slice(&std::fs::read(&f.receipt_path).unwrap()).unwrap();
        let expected = ScmStopVerificationExpectationV1 {
            service_name: f.service_name.clone(),
            service_instance_id_hex: f.instance.clone(),
            run_id_hex: active.then(|| f.run.clone()),
            owner_process: f.owner.clone(),
            intent_path: f.intent_path.clone(),
            outcome_path: (!forced).then(|| f.outcome_path.clone()),
            receipt_path: f.receipt_path.clone(),
            ledger_path: f.ledger_path.clone(),
            expected_intent_sha256_hex: hash_from_binding(&intent_binding),
            expected_outcome_sha256_hex: outcome_evidence_sha256,
            expected_receipt_sha256_hex: hash_from_binding(&receipt_binding),
            deadline_span_max_ns: 1_000,
            expected_evidence_source: source,
            expected_terminal_commit_qualification: terminal_commit_qualification,
            require_real_scm: false,
        };
        (intent, outcome, receipt, expected)
    }

    #[test]
    fn idle_stop_is_bounded_but_synthetic_is_not_real_scm_pass() {
        let f = Fixture::new("idle");
        let (_, _, receipt, expected) = publish_complete(
            &f,
            false,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        assert_eq!(
            receipt.terminal_commit_qualification,
            ScmTerminalCommitQualificationV1::SyntheticBoundedCommit
        );
        assert!(receipt.bounded_stop_complete);
        let report = verify_scm_stop_receipt_v1(&expected).unwrap();
        assert!(report.bounded_stop_complete);
        assert!(!report.real_scm_pass);
        assert_eq!(
            report.real_scm_conclusion,
            ScmRealQualificationConclusionV1::ExternalWatcherNotIntegrated
        );
        f.cleanup();
    }

    #[test]
    fn windows_external_shape_remains_neutral_until_watcher_authority_is_integrated() {
        let f = Fixture::new("windows-neutral");
        let (_, _, receipt, mut expected) = publish_complete(
            &f,
            false,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::WindowsScmApi,
        );
        assert_eq!(
            receipt.terminal_commit_qualification,
            ScmTerminalCommitQualificationV1::ExternalScmWatcherObserved
        );
        let report = verify_scm_stop_receipt_v1(&expected).unwrap();
        assert!(report.bounded_stop_complete);
        assert!(!report.real_scm_pass);
        assert_eq!(
            report.real_scm_conclusion,
            ScmRealQualificationConclusionV1::ExternalWatcherNotIntegrated
        );

        // A caller-controlled demand cannot substitute for the coordinator's
        // private ExternalWatcherAuthority; it only makes this fail closed.
        expected.require_real_scm = true;
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());
        f.cleanup();
    }

    #[test]
    fn unqualified_sync_io_prepublication_timestamp_never_normalizes_to_success() {
        let f = Fixture::new("unqualified-commit");
        let (intent, _, mut receipt, mut expected) = publish_complete(
            &f,
            false,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        assert!(receipt.stop_completed_monotonic_ns < intent.deadline_monotonic_ns);
        receipt.evidence_source = ScmStopEvidenceSourceV1::UnqualifiedWindowsRuntime;
        receipt.terminal_commit_qualification =
            ScmTerminalCommitQualificationV1::UnqualifiedSynchronousIo;
        receipt.bounded_stop_complete = false;
        receipt.receipt_sha256_hex.clear();

        // This timestamp was sampled before receipt publication. Even if the
        // following synchronous I/O stalls beyond the deadline, no later clock
        // observation exists that could turn it into a bounded commit.
        receipt.final_scm_status = ScmFinalStatusV1::Stopped;
        let rejected_path = f.root.join("unqualified-stopped.receipt.json");
        assert!(publish_scm_stop_receipt_v1(&rejected_path, &receipt).is_err());
        assert!(!rejected_path.exists());

        receipt.final_scm_status = ScmFinalStatusV1::Failed;
        let failure_path = f.root.join("unqualified-failed.receipt.json");
        let failure_binding = publish_scm_stop_receipt_v1(&failure_path, &receipt).unwrap();
        let published: ScmStopReceiptV1 =
            serde_json::from_slice(&std::fs::read(&failure_path).unwrap()).unwrap();
        assert_eq!(published.final_scm_status, ScmFinalStatusV1::Failed);
        assert!(!published.bounded_stop_complete);

        expected.receipt_path = failure_path;
        expected.expected_receipt_sha256_hex = failure_binding.sha256_hex;
        expected.expected_evidence_source = ScmStopEvidenceSourceV1::UnqualifiedWindowsRuntime;
        expected.expected_terminal_commit_qualification =
            ScmTerminalCommitQualificationV1::UnqualifiedSynchronousIo;
        let report = verify_scm_stop_receipt_v1(&expected).unwrap();
        assert!(!report.bounded_stop_complete);
        assert!(!report.real_scm_pass);
        f.cleanup();
    }

    #[test]
    fn source_commit_mismatches_and_old_receipt_shape_are_rejected() {
        let f = Fixture::new("commit-shape");
        let (_, _, mut receipt, mut expected) = publish_complete(
            &f,
            false,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        let mut old_shape = serde_json::to_value(&receipt).unwrap();
        old_shape
            .as_object_mut()
            .unwrap()
            .remove("terminal_commit_qualification");
        assert!(serde_json::from_value::<ScmStopReceiptV1>(old_shape).is_err());

        expected.expected_terminal_commit_qualification =
            ScmTerminalCommitQualificationV1::ExternalScmWatcherObserved;
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());

        receipt.evidence_source = ScmStopEvidenceSourceV1::WindowsScmApi;
        receipt.terminal_commit_qualification =
            ScmTerminalCommitQualificationV1::SyntheticBoundedCommit;
        receipt.receipt_sha256_hex.clear();
        assert!(validate_receipt_shape(&receipt).is_err());
        let invalid_windows_path = f.root.join("windows-without-watcher.receipt.json");
        assert!(publish_scm_stop_receipt_v1(&invalid_windows_path, &receipt).is_err());
        assert!(!invalid_windows_path.exists());

        receipt.evidence_source = ScmStopEvidenceSourceV1::SyntheticTest;
        receipt.terminal_commit_qualification =
            ScmTerminalCommitQualificationV1::ExternalScmWatcherObserved;
        assert!(validate_receipt_shape(&receipt).is_err());
        f.cleanup();
    }

    #[test]
    fn active_run_is_abort_with_bound_durable_prefix_not_seal() {
        let f = Fixture::new("active");
        let (_, outcome, _, expected) = publish_complete(
            &f,
            true,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        let outcome = outcome.unwrap();
        assert_eq!(
            outcome.final_run_truth,
            RunStopTruthV1::ActiveRunAbortedWithDurablePrefix
        );
        assert!(outcome.durable_prefix.is_some());
        assert!(
            verify_scm_stop_receipt_v1(&expected)
                .unwrap()
                .active_run_aborted_with_durable_prefix
        );
        f.cleanup();
    }

    #[test]
    fn header_only_active_abort_has_an_honest_zero_record_prefix() {
        let f = Fixture::new("header-only-abort");
        let mut prepared_intent = f.intent(true);
        prepared_intent.run_state_wire = Some(RunState::Prepared.wire_value());
        let intent_binding = publish_stop_intent_v1(&f.intent_path, &prepared_intent).unwrap();
        let intent = load_bound_stop_intent_v1(&intent_binding).unwrap();
        let mut outcome = f.outcome(intent.intent_sha256_hex, true);
        outcome.durable_prefix = Some(f.header_only_prefix());
        publish_owner_stop_outcome_v1(&f.outcome_path, &outcome).unwrap();
        let verified =
            verify_owner_stop_outcome_for_intent_v1(&intent_binding, &f.outcome_path).unwrap();
        let prefix = verified.outcome.durable_prefix.unwrap();
        assert_eq!(prefix.durable_record_count, 0);
        assert_eq!(prefix.durable_watermark_journal_sequence, None);
        f.cleanup();
    }

    #[test]
    fn durable_prefix_rejects_empty_watermark_count_mismatches() {
        let f = Fixture::new("prefix-count-mismatch");
        let mut old_shape = serde_json::to_value(f.prefix()).unwrap();
        old_shape
            .as_object_mut()
            .unwrap()
            .remove("durable_watermark_journal_sequence");
        assert!(serde_json::from_value::<DurablePrefixV1>(old_shape).is_err());
        let mut malformed = f.prefix();
        malformed.durable_record_count = 0;
        assert!(validate_durable_prefix(&malformed).is_err());
        malformed.durable_watermark_journal_sequence = None;
        assert!(validate_durable_prefix(&malformed).is_ok());
        let intent_binding = publish_stop_intent_v1(&f.intent_path, &f.intent(true)).unwrap();
        let intent = load_bound_stop_intent_v1(&intent_binding).unwrap();
        let mut outcome = f.outcome(intent.intent_sha256_hex, true);
        outcome.durable_prefix = Some(malformed);
        publish_owner_stop_outcome_v1(&f.outcome_path, &outcome).unwrap();
        assert!(verify_owner_stop_outcome_for_intent_v1(&intent_binding, &f.outcome_path).is_err());
        f.cleanup();
    }

    #[test]
    fn unreleased_v1_old_stop_intent_shape_is_rejected() {
        let f = Fixture::new("old-intent-shape");
        for missing in ["intent_kind", "run_state_wire"] {
            let mut value = serde_json::to_value(f.intent(true)).unwrap();
            value.as_object_mut().unwrap().remove(missing);
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(serde_json::from_slice::<StopIntentV1>(&bytes).is_err());
        }
        f.cleanup();
    }

    #[test]
    fn independently_scanned_checkpoint_rejects_rehashed_semantic_forgery() {
        let f = Fixture::new("checkpoint-forgery");
        let intent_binding = publish_stop_intent_v1(&f.intent_path, &f.intent(true)).unwrap();
        let intent = load_bound_stop_intent_v1(&intent_binding).unwrap();
        let mut forged = f.outcome(intent.intent_sha256_hex, true);
        forged
            .durable_prefix
            .as_mut()
            .unwrap()
            .durable_watermark_journal_sequence = Some(
            forged
                .durable_prefix
                .as_ref()
                .unwrap()
                .durable_watermark_journal_sequence
                .unwrap()
                .saturating_add(1),
        );
        publish_owner_stop_outcome_v1(&f.outcome_path, &forged).unwrap();
        assert!(verify_owner_stop_outcome_for_intent_v1(&intent_binding, &f.outcome_path).is_err());
        f.cleanup();
    }

    #[test]
    fn preexisting_failed_run_is_not_relabelled_as_new_abort() {
        let f = Fixture::new("already-failed");
        let mut failed_intent = f.intent(true);
        failed_intent.run_state_wire = Some(RunState::Failed.wire_value());
        let intent_binding = publish_stop_intent_v1(&f.intent_path, &failed_intent).unwrap();
        let intent = load_bound_stop_intent_v1(&intent_binding).unwrap();
        let mut outcome = f.outcome(intent.intent_sha256_hex, true);
        outcome.final_run_truth = RunStopTruthV1::AlreadyFailed;
        outcome.durable_prefix = None;
        outcome.capture_exit_reason = CaptureExitReasonV1::PreexistingRunFailure;
        publish_owner_stop_outcome_v1(&f.outcome_path, &outcome).unwrap();
        let verified =
            verify_owner_stop_outcome_for_intent_v1(&intent_binding, &f.outcome_path).unwrap();
        assert_eq!(
            verified.outcome.final_run_truth,
            RunStopTruthV1::AlreadyFailed
        );
        assert!(verified.outcome.durable_prefix.is_none());
        f.cleanup();
    }

    #[test]
    fn startup_before_owner_ready_has_honest_failed_receipt() {
        let f = Fixture::new("startup-stop");
        let mut startup_intent = f.intent(false);
        startup_intent.intent_kind = StopIntentKindV1::StartupBeforeOwnerReady;
        startup_intent.private_request_sequence = None;
        startup_intent.private_epoch = None;
        startup_intent.run_state_wire = None;
        let intent_binding = publish_stop_intent_v1(&f.intent_path, &startup_intent).unwrap();
        let mut ledger = ScmStopLedgerWriterV1::create_new(&f.ledger_path).unwrap();
        ledger.append_intent(intent_binding.clone()).unwrap();
        let ledger = ledger.finish().unwrap();
        let receipt = ScmStopReceiptV1 {
            schema: SCM_STOP_RECEIPT_SCHEMA.to_owned(),
            evidence_source: ScmStopEvidenceSourceV1::SyntheticTest,
            terminal_commit_qualification: ScmTerminalCommitQualificationV1::SyntheticBoundedCommit,
            service_name: f.service_name.clone(),
            service_instance_id_hex: f.instance.clone(),
            run_id_hex: None,
            owner_process: f.owner.clone(),
            intent: intent_binding.clone(),
            outcome: None,
            ledger,
            owner_exit_code: Some(1),
            forced_termination: true,
            retained_process_exit_observed: true,
            job_active_processes_after_wait: 0,
            job_empty_proven: true,
            stop_completed_wall_time_unix_ns: 12,
            stop_completed_monotonic_ns: 300,
            elapsed_ns: 200,
            final_scm_status: ScmFinalStatusV1::Failed,
            bounded_stop_complete: false,
            receipt_sha256_hex: String::new(),
        };
        let receipt_binding = publish_scm_stop_receipt_v1(&f.receipt_path, &receipt).unwrap();
        let expected = ScmStopVerificationExpectationV1 {
            service_name: f.service_name.clone(),
            service_instance_id_hex: f.instance.clone(),
            run_id_hex: None,
            owner_process: f.owner.clone(),
            intent_path: f.intent_path.clone(),
            outcome_path: None,
            receipt_path: f.receipt_path.clone(),
            ledger_path: f.ledger_path.clone(),
            expected_intent_sha256_hex: intent_binding.sha256_hex,
            expected_outcome_sha256_hex: None,
            expected_receipt_sha256_hex: receipt_binding.sha256_hex,
            deadline_span_max_ns: 1_000,
            expected_evidence_source: ScmStopEvidenceSourceV1::SyntheticTest,
            expected_terminal_commit_qualification:
                ScmTerminalCommitQualificationV1::SyntheticBoundedCommit,
            require_real_scm: false,
        };
        let report = verify_scm_stop_receipt_v1(&expected).unwrap();
        assert!(!report.bounded_stop_complete);
        let published: ScmStopReceiptV1 =
            serde_json::from_slice(&std::fs::read(&f.receipt_path).unwrap()).unwrap();
        assert_eq!(published.final_scm_status, ScmFinalStatusV1::Failed);
        f.cleanup();
    }

    #[test]
    fn missing_intent_or_outcome_fails_closed() {
        let f = Fixture::new("missing");
        let (_, _, _, expected) = publish_complete(
            &f,
            true,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        std::fs::remove_file(&f.intent_path).unwrap();
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());
        f.cleanup();
        let f = Fixture::new("missing-outcome");
        let (_, _, _, expected) = publish_complete(
            &f,
            true,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        std::fs::remove_file(&f.outcome_path).unwrap();
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());
        f.cleanup();
    }

    #[test]
    fn forced_kill_job_nonempty_and_late_deadline_never_claim_bounded_completion() {
        for (label, forced, job_empty, late) in [
            ("forced", true, true, false),
            ("job", false, false, false),
            ("late", false, true, true),
        ] {
            let f = Fixture::new(label);
            let (_, _, receipt, expected) = publish_complete(
                &f,
                true,
                forced,
                job_empty,
                late,
                ScmStopEvidenceSourceV1::SyntheticTest,
            );
            assert!(!receipt.bounded_stop_complete);
            assert!(
                !verify_scm_stop_receipt_v1(&expected)
                    .unwrap()
                    .bounded_stop_complete
            );
            f.cleanup();
        }
    }

    #[test]
    fn duplicate_reordered_and_tampered_ledger_fails() {
        let f = Fixture::new("ledger");
        let (_, _, _, expected) = publish_complete(
            &f,
            false,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        let line = std::fs::read_to_string(&f.ledger_path).unwrap();
        std::fs::write(&f.ledger_path, format!("{line}{line}")).unwrap();
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());
        f.cleanup();

        let f = Fixture::new("ledger-reordered");
        let (_, _, _, expected) = publish_complete(
            &f,
            true,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        let mut lines: Vec<String> = std::fs::read_to_string(&f.ledger_path)
            .unwrap()
            .lines()
            .map(ToOwned::to_owned)
            .collect();
        lines.reverse();
        std::fs::write(&f.ledger_path, format!("{}\n", lines.join("\n"))).unwrap();
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());
        f.cleanup();

        let f = Fixture::new("ledger-tampered");
        let (_, _, _, expected) = publish_complete(
            &f,
            false,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        let mut bytes = std::fs::read(&f.ledger_path).unwrap();
        let offset = bytes.iter().position(|byte| *byte == b'f').unwrap();
        bytes[offset] = b'x';
        std::fs::write(&f.ledger_path, bytes).unwrap();
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());
        f.cleanup();
    }

    #[test]
    fn recomputed_self_hash_semantic_forgery_fails_trusted_hash() {
        let f = Fixture::new("forged");
        let (_, _, _, expected) = publish_complete(
            &f,
            false,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        let mut intent: StopIntentV1 =
            serde_json::from_slice(&std::fs::read(&f.intent_path).unwrap()).unwrap();
        intent.reason = ScmStopReasonV1::ServiceControlShutdown;
        intent.intent_sha256_hex.clear();
        intent.intent_sha256_hex = hex(&sha256(&canonical_json(&intent).unwrap()));
        std::fs::write(&f.intent_path, canonical_json(&intent).unwrap()).unwrap();
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());
        f.cleanup();
    }

    #[test]
    fn wrong_owner_run_or_service_is_rejected() {
        let f = Fixture::new("context");
        let (_, _, _, mut expected) = publish_complete(
            &f,
            true,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        expected.owner_process.pid += 1;
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());
        expected.owner_process = f.owner.clone();
        expected.run_id_hex = Some("33".repeat(16));
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());
        expected.run_id_hex = Some(f.run.clone());
        expected.service_name = "Other".to_owned();
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());
        f.cleanup();
    }

    #[test]
    fn pathname_replacement_and_no_overwrite_are_rejected() {
        let f = Fixture::new("replace");
        let (_, _, _, expected) = publish_complete(
            &f,
            false,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        let replacement = f.root.join("replacement.json");
        std::fs::write(&replacement, b"{}\n").unwrap();
        std::fs::remove_file(&f.intent_path).unwrap();
        std::fs::rename(&replacement, &f.intent_path).unwrap();
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());
        assert!(publish_scm_stop_receipt_v1(
            &f.receipt_path,
            &ScmStopReceiptV1 {
                receipt_sha256_hex: String::new(),
                ..serde_json::from_slice(&std::fs::read(&f.receipt_path).unwrap()).unwrap()
            }
        )
        .is_err());
        f.cleanup();
    }

    #[test]
    fn require_real_scm_refuses_synthetic_even_when_bounded() {
        let f = Fixture::new("real-gate");
        let (_, _, _, mut expected) = publish_complete(
            &f,
            false,
            false,
            true,
            false,
            ScmStopEvidenceSourceV1::SyntheticTest,
        );
        expected.require_real_scm = true;
        assert!(verify_scm_stop_receipt_v1(&expected).is_err());
        f.cleanup();
    }

    #[test]
    fn deterministic_runtime_paths_stay_inside_existing_data_root() {
        let f = Fixture::new("paths");
        let paths = scm_stop_evidence_paths_v1(&f.root, &[0xA5; 32]).unwrap();
        let canonical_root = std::fs::canonicalize(&f.root).unwrap();
        for path in [
            &paths.intent_path,
            &paths.ledger_path,
            &paths.outcome_path,
            &paths.receipt_path,
        ] {
            assert!(path.starts_with(&canonical_root));
            assert!(!path.exists());
        }
        assert!(scm_stop_evidence_paths_v1(&f.root, &[0; 32]).is_err());
        f.cleanup();
    }
}
