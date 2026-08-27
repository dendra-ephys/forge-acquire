//! Append-only evidence format for local Windows SCM engineering qualification.
//!
//! This module deliberately does not install, start, stop, or uninstall a
//! service.  A qualification supervisor which is distinct from the service
//! owner is the sole writer.  The resulting CRC/hash chain and receipt are
//! local integrity evidence; they are not a signature, attestation, M1 release
//! receipt, or substitute for hardware/NWB qualification.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use forge_protocol_v1::{crc32c, sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCM_QUALIFICATION_SCHEMA: &str = "forge.scm-qualification.v1";
pub const HARDWARE_OPEN_GATE: &str = "hardware_hil_not_qualified";
pub const NWB_OPEN_GATE: &str = "nwb_endurance_not_qualified";
pub const REAL_SCM_OPEN_GATE: &str = "real_windows_scm_not_qualified";

const AUDIT_HASH_DOMAIN: &[u8] = b"forge.scm-qualification.audit-event.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmQualificationEventKindV1 {
    Preflight,
    ArtifactRetained,
    InstallRequested,
    InstallReadback,
    ServiceSidVerified,
    ServiceObjectDaclVerified,
    DataRootDaclVerified,
    StartRequested,
    StartPending,
    Running,
    OwnerReady,
    StopRequested,
    StopPending,
    OwnerGracefulShutdownRequested,
    OwnerExitProven,
    ForcedOwnerTermination,
    JournalRecoveryVerified,
    ServiceStopped,
    RestartObserved,
    UninstallRequested,
    UninstallVerified,
    QualificationSealed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmServiceStateV1 {
    Absent,
    Stopped,
    StartPending,
    Running,
    StopPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmStartTypeV1 {
    Automatic,
    Demand,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmErrorControlV1 {
    Ignore,
    Normal,
    Severe,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmServiceSidTypeV1 {
    None,
    Unrestricted,
    Restricted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerStopMethodV1 {
    Graceful,
    Forced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmEvidenceSourceV1 {
    WindowsScmApi,
    SyntheticTest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentityV1 {
    pub pid: u32,
    pub creation_time_100ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmStatusSnapshotV1 {
    pub state: ScmServiceStateV1,
    pub checkpoint: u32,
    pub wait_hint_ms: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfigurationReadbackV1 {
    pub service_account_name: String,
    pub binary_path: String,
    pub start_type: ScmStartTypeV1,
    pub error_control: ScmErrorControlV1,
    pub service_sid_type: ScmServiceSidTypeV1,
    pub failure_actions_sha256_hex: String,
    pub failure_actions_on_non_crash_failures: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFileIdentityV1 {
    /// Windows volume serial number (or the platform device identifier in
    /// non-production portable tests).
    pub volume_serial_number: u64,
    /// Stable file index from the already-open evidence handle.
    pub file_index: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEvidenceSnapshotV1 {
    pub path: String,
    pub sha256_hex: String,
    pub file_identity: EvidenceFileIdentityV1,
    pub durable_record_count: u64,
    pub durable_valid_len: u64,
    pub last_journal_sequence: Option<u64>,
    pub seal_expected_last_journal_sequence: Option<u64>,
    pub sealed: bool,
    pub recovery_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEvidenceSnapshotV1 {
    pub path: String,
    pub sha256_hex: String,
    pub file_identity: EvidenceFileIdentityV1,
    pub state: String,
}

/// Values which the independent qualification supervisor observed for one
/// event.  Identity, sequence, previous hash, and integrity fields are always
/// supplied by `ScmQualificationAuditWriterV1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScmQualificationEventDataV1 {
    pub kind: ScmQualificationEventKindV1,
    pub owner_process: Option<ProcessIdentityV1>,
    pub scm: ScmStatusSnapshotV1,
    pub wall_time_unix_ns: u64,
    pub monotonic_time_ns: u64,
    pub win32_exit_code: Option<u32>,
    pub service_exit_code: Option<u32>,
    pub service_configuration: Option<ServiceConfigurationReadbackV1>,
    pub token_user_sid_verified: Option<bool>,
    pub pipe_dacl_sha256_hex: Option<String>,
    pub service_object_dacl_sha256_hex: Option<String>,
    pub data_root_dacl_sha256_hex: Option<String>,
    pub journal: Option<JournalEvidenceSnapshotV1>,
    pub ledger: Option<LedgerEvidenceSnapshotV1>,
}

impl ScmQualificationEventDataV1 {
    pub fn bare(
        kind: ScmQualificationEventKindV1,
        scm: ScmStatusSnapshotV1,
        wall_time_unix_ns: u64,
        monotonic_time_ns: u64,
    ) -> Self {
        Self {
            kind,
            owner_process: None,
            scm,
            wall_time_unix_ns,
            monotonic_time_ns,
            win32_exit_code: None,
            service_exit_code: None,
            service_configuration: None,
            token_user_sid_verified: None,
            pipe_dacl_sha256_hex: None,
            service_object_dacl_sha256_hex: None,
            data_root_dacl_sha256_hex: None,
            journal: None,
            ledger: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScmQualificationContextV1 {
    pub qualification_id_hex: String,
    pub service_name: String,
    pub service_executable_path: String,
    pub service_executable_sha256_hex: String,
    pub service_sid: String,
    pub qualification_supervisor: ProcessIdentityV1,
    pub service_supervisor: ProcessIdentityV1,
    pub evidence_source: ScmEvidenceSourceV1,
}

/// A complete JSONL line.  CRC32C and SHA-256 cover the canonical encoding of
/// this struct after normalizing `event_crc32c` to zero and
/// `event_hash_hex` to the empty string.  `previous_event_hash_hex` is covered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmQualificationAuditEventV1 {
    pub schema: String,
    pub qualification_id_hex: String,
    pub event_sequence: u64,
    pub previous_event_hash_hex: String,
    pub kind: ScmQualificationEventKindV1,
    pub service_name: String,
    pub service_executable_path: String,
    pub service_executable_sha256_hex: String,
    pub service_sid: String,
    pub qualification_supervisor: ProcessIdentityV1,
    pub service_supervisor: ProcessIdentityV1,
    pub evidence_source: ScmEvidenceSourceV1,
    pub owner_process: Option<ProcessIdentityV1>,
    pub scm: ScmStatusSnapshotV1,
    pub wall_time_unix_ns: u64,
    pub monotonic_time_ns: u64,
    pub win32_exit_code: Option<u32>,
    pub service_exit_code: Option<u32>,
    pub service_configuration: Option<ServiceConfigurationReadbackV1>,
    pub token_user_sid_verified: Option<bool>,
    pub pipe_dacl_sha256_hex: Option<String>,
    pub service_object_dacl_sha256_hex: Option<String>,
    pub data_root_dacl_sha256_hex: Option<String>,
    pub journal: Option<JournalEvidenceSnapshotV1>,
    pub ledger: Option<LedgerEvidenceSnapshotV1>,
    pub event_crc32c: u32,
    pub event_hash_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmAuditEvidenceV1 {
    pub path: String,
    pub sha256_hex: String,
    pub bytes: u64,
    pub file_identity: EvidenceFileIdentityV1,
    pub event_count: u64,
    pub first_event_hash_hex: String,
    pub last_event_hash_hex: String,
}

pub struct ScmQualificationAuditWriterV1 {
    path: PathBuf,
    file: File,
    context: ScmQualificationContextV1,
    next_sequence: u64,
    previous_hash: [u8; 32],
    replay: QualificationReplayMachineV1,
    poisoned: bool,
    sealed: bool,
}

impl ScmQualificationAuditWriterV1 {
    /// Creates a brand-new audit.  On Windows the handle denies all sharing so
    /// no owner/service process can concurrently open it as a second writer.
    pub fn create_new(path: &Path, context: ScmQualificationContextV1) -> io::Result<Self> {
        validate_context(&context, true)?;
        if current_process_identity()? != context.qualification_supervisor {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "audit writer process does not match the qualification supervisor identity",
            ));
        }
        if !path.is_absolute() || path.parent().is_none_or(|parent| !parent.is_dir()) {
            return Err(invalid_input(
                "SCM qualification audit path must be absolute with an existing parent",
            ));
        }
        let file = create_exclusive_new(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            context,
            next_sequence: 0,
            previous_hash: [0; 32],
            replay: QualificationReplayMachineV1::default(),
            poisoned: false,
            sealed: false,
        })
    }

    pub fn append(
        &mut self,
        data: ScmQualificationEventDataV1,
    ) -> io::Result<ScmQualificationAuditEventV1> {
        if self.poisoned || self.sealed {
            return Err(invalid_input("audit writer is poisoned or sealed"));
        }
        let mut event = ScmQualificationAuditEventV1 {
            schema: SCM_QUALIFICATION_SCHEMA.to_owned(),
            qualification_id_hex: self.context.qualification_id_hex.clone(),
            event_sequence: self.next_sequence,
            previous_event_hash_hex: hex(&self.previous_hash),
            kind: data.kind,
            service_name: self.context.service_name.clone(),
            service_executable_path: self.context.service_executable_path.clone(),
            service_executable_sha256_hex: self.context.service_executable_sha256_hex.clone(),
            service_sid: self.context.service_sid.clone(),
            qualification_supervisor: self.context.qualification_supervisor.clone(),
            service_supervisor: self.context.service_supervisor.clone(),
            evidence_source: self.context.evidence_source,
            owner_process: data.owner_process,
            scm: data.scm,
            wall_time_unix_ns: data.wall_time_unix_ns,
            monotonic_time_ns: data.monotonic_time_ns,
            win32_exit_code: data.win32_exit_code,
            service_exit_code: data.service_exit_code,
            service_configuration: data.service_configuration,
            token_user_sid_verified: data.token_user_sid_verified,
            pipe_dacl_sha256_hex: data.pipe_dacl_sha256_hex,
            service_object_dacl_sha256_hex: data.service_object_dacl_sha256_hex,
            data_root_dacl_sha256_hex: data.data_root_dacl_sha256_hex,
            journal: data.journal,
            ledger: data.ledger,
            event_crc32c: 0,
            event_hash_hex: String::new(),
        };
        let result = (|| {
            validate_event_shape(&event)?;
            // Freeze every journal/ledger path, filesystem identity, size, and
            // hash while the audit event itself becomes durable.  On Windows
            // these handles deny write/delete sharing until sync_data returns.
            let _external_evidence_locks = lock_and_verify_event_evidence(&event)?;
            let mut replay = self.replay.clone();
            replay.apply(&event)?;
            let covered = canonical_covered_event_bytes(&event)?;
            event.event_crc32c = crc32c(&covered);
            let event_hash = hash_audit_event(&covered, event.event_crc32c);
            event.event_hash_hex = hex(&event_hash);
            let bytes = serde_json::to_vec(&event).map_err(json_error)?;
            self.file.write_all(&bytes)?;
            self.file.write_all(b"\n")?;
            self.file.flush()?;
            self.file.sync_data()?;
            self.previous_hash = event_hash;
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or_else(|| io::Error::other("audit event sequence overflow"))?;
            self.replay = replay;
            self.sealed = event.kind == ScmQualificationEventKindV1::QualificationSealed;
            Ok(event.clone())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Completes only an audit whose last durable event is
    /// `qualification_sealed`.  Dropping an incomplete writer cannot yield
    /// formal audit evidence.
    pub fn finish(mut self) -> io::Result<ScmAuditEvidenceV1> {
        if self.poisoned || !self.sealed || !self.replay.is_sealed() {
            return Err(invalid_input(
                "audit cannot finish before a valid qualification_sealed event",
            ));
        }
        self.file.flush()?;
        self.file.sync_all()?;
        let (bytes, binding) = read_bound_open_evidence_file(&self.path, &mut self.file)?;
        let replay = replay_audit_snapshot(bytes, binding, Some(&self.context))?;
        if !replay.machine.is_sealed() {
            return Err(invalid_data("SCM qualification audit is not sealed"));
        }
        rehash_all_audited_external_files(&replay.events)?;
        let final_binding = bind_open_evidence_file(&self.path, &mut self.file)?;
        if !audit_evidence_matches_binding(&replay.evidence, &final_binding) {
            return Err(invalid_data(
                "audit changed during its final locked verification snapshot",
            ));
        }
        Ok(replay.evidence)
    }
}

pub fn verify_scm_qualification_audit_v1(
    path: &Path,
    expected_context: &ScmQualificationContextV1,
) -> io::Result<ScmAuditEvidenceV1> {
    validate_context(expected_context, true)?;
    if !path.is_absolute() {
        return Err(invalid_data("audit path is not absolute"));
    }
    let mut audit_lock = open_evidence_file(path)?;
    let (bytes, binding) = read_bound_open_evidence_file(path, &mut audit_lock)?;
    let replay = replay_audit_snapshot(bytes, binding, Some(expected_context))?;
    if !replay.machine.is_sealed() {
        return Err(invalid_data("SCM qualification audit is not sealed"));
    }
    rehash_all_audited_external_files(&replay.events)?;
    let final_binding = bind_open_evidence_file(path, &mut audit_lock)?;
    if !audit_evidence_matches_binding(&replay.evidence, &final_binding) {
        return Err(invalid_data(
            "audit changed during its final locked verification snapshot",
        ));
    }
    Ok(replay.evidence)
}

fn audit_evidence_matches_binding(
    evidence: &ScmAuditEvidenceV1,
    binding: &EvidenceFileBindingV1,
) -> bool {
    evidence.path == binding.path
        && evidence.sha256_hex == binding.sha256_hex
        && evidence.bytes == binding.bytes
        && evidence.file_identity == binding.file_identity
}

#[derive(Clone, Debug, Default)]
struct QualificationReplayMachineV1 {
    phase: ReplayPhaseV1,
    last_wall_time_unix_ns: Option<u64>,
    last_monotonic_time_ns: Option<u64>,
    active_owner: Option<ProcessIdentityV1>,
    stopped_owner: Option<ProcessIdentityV1>,
    seen_owners: BTreeSet<(u32, u64)>,
    pending_recovery: Option<(JournalEvidenceSnapshotV1, LedgerEvidenceSnapshotV1, bool)>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ReplayPhaseV1 {
    #[default]
    NeedPreflight,
    NeedArtifactRetained,
    NeedInstallRequested,
    NeedInstallReadback,
    NeedServiceSidVerified,
    NeedServiceObjectDaclVerified,
    NeedDataRootDaclVerified,
    NeedStartRequested,
    NeedStartPending,
    NeedRunning,
    NeedOwnerReadyEvent,
    OwnerReady,
    NeedRestartObserved,
    NeedForcedRecovery,
    NeedGracefulStopPending,
    NeedGracefulShutdownRequest,
    NeedGracefulExit,
    NeedGracefulRecovery,
    NeedServiceStopped,
    NeedUninstallRequested,
    NeedUninstallVerified,
    NeedQualificationSealed,
    Sealed,
}

impl QualificationReplayMachineV1 {
    fn is_sealed(&self) -> bool {
        self.phase == ReplayPhaseV1::Sealed
    }

    fn apply(&mut self, event: &ScmQualificationAuditEventV1) -> io::Result<()> {
        if self
            .last_wall_time_unix_ns
            .is_some_and(|previous| event.wall_time_unix_ns < previous)
            || self
                .last_monotonic_time_ns
                .is_some_and(|previous| event.monotonic_time_ns <= previous)
        {
            return Err(invalid_data(
                "audit wall time regressed or monotonic time did not advance",
            ));
        }
        self.last_wall_time_unix_ns = Some(event.wall_time_unix_ns);
        self.last_monotonic_time_ns = Some(event.monotonic_time_ns);

        use ReplayPhaseV1 as P;
        use ScmQualificationEventKindV1 as K;
        self.phase = match (self.phase, event.kind) {
            (P::NeedPreflight, K::Preflight) => P::NeedArtifactRetained,
            (P::NeedArtifactRetained, K::ArtifactRetained) => P::NeedInstallRequested,
            (P::NeedInstallRequested, K::InstallRequested) => P::NeedInstallReadback,
            (P::NeedInstallReadback, K::InstallReadback) => P::NeedServiceSidVerified,
            (P::NeedServiceSidVerified, K::ServiceSidVerified) => P::NeedServiceObjectDaclVerified,
            (P::NeedServiceObjectDaclVerified, K::ServiceObjectDaclVerified) => {
                P::NeedDataRootDaclVerified
            }
            (P::NeedDataRootDaclVerified, K::DataRootDaclVerified) => P::NeedStartRequested,
            (P::NeedStartRequested, K::StartRequested) => {
                if event.owner_process.is_some() {
                    return Err(invalid_data("start request must not claim a running owner"));
                }
                P::NeedStartPending
            }
            (P::NeedStartPending, K::StartPending) => P::NeedRunning,
            (P::NeedRunning, K::Running) => {
                let owner = required_owner(event)?;
                let identity = (owner.pid, owner.creation_time_100ns);
                if !self.seen_owners.insert(identity) {
                    return Err(invalid_data("SCM owner identity was reused"));
                }
                self.active_owner = Some(owner.clone());
                self.stopped_owner = None;
                P::NeedOwnerReadyEvent
            }
            (P::NeedOwnerReadyEvent, K::OwnerReady) => {
                require_active_owner(self, event)?;
                P::OwnerReady
            }
            (P::OwnerReady, K::StopRequested) => {
                require_active_owner(self, event)?;
                P::NeedGracefulStopPending
            }
            (P::OwnerReady, K::ForcedOwnerTermination) => {
                require_active_owner(self, event)?;
                self.pending_recovery = Some((
                    event
                        .journal
                        .clone()
                        .ok_or_else(|| invalid_data("forced termination lacks journal"))?,
                    event
                        .ledger
                        .clone()
                        .ok_or_else(|| invalid_data("forced termination lacks ledger"))?,
                    true,
                ));
                self.stopped_owner = self.active_owner.take();
                P::NeedRestartObserved
            }
            (P::NeedRestartObserved, K::RestartObserved) => {
                let owner = required_owner(event)?;
                let identity = (owner.pid, owner.creation_time_100ns);
                if self.stopped_owner.as_ref() == Some(owner) || !self.seen_owners.insert(identity)
                {
                    return Err(invalid_data(
                        "owner restart did not produce a new PID/creation identity",
                    ));
                }
                self.active_owner = Some(owner.clone());
                P::NeedForcedRecovery
            }
            (P::NeedForcedRecovery, K::JournalRecoveryVerified) => {
                require_active_owner(self, event)?;
                if event.scm.state != ScmServiceStateV1::Running {
                    return Err(invalid_data(
                        "owner restart recovery must keep the SCM service running",
                    ));
                }
                verify_recovery_binding(self, event, true)?;
                P::NeedOwnerReadyEvent
            }
            (P::NeedGracefulStopPending, K::StopPending) => {
                require_active_owner(self, event)?;
                P::NeedGracefulShutdownRequest
            }
            (P::NeedGracefulShutdownRequest, K::OwnerGracefulShutdownRequested) => {
                require_active_owner(self, event)?;
                P::NeedGracefulExit
            }
            (P::NeedGracefulExit, K::OwnerExitProven) => {
                require_active_owner(self, event)?;
                self.pending_recovery = Some((
                    event
                        .journal
                        .clone()
                        .ok_or_else(|| invalid_data("graceful exit lacks journal"))?,
                    event
                        .ledger
                        .clone()
                        .ok_or_else(|| invalid_data("graceful exit lacks ledger"))?,
                    false,
                ));
                P::NeedGracefulRecovery
            }
            (P::NeedGracefulRecovery, K::JournalRecoveryVerified) => {
                require_active_owner(self, event)?;
                if event.scm.state != ScmServiceStateV1::StopPending {
                    return Err(invalid_data(
                        "graceful journal recovery must remain in SCM stop-pending",
                    ));
                }
                verify_recovery_binding(self, event, false)?;
                P::NeedServiceStopped
            }
            (P::NeedServiceStopped, K::ServiceStopped) => {
                require_active_owner(self, event)?;
                if event.win32_exit_code != Some(0) || event.service_exit_code != Some(0) {
                    return Err(invalid_data(
                        "final SCM service stop must be the proven graceful branch",
                    ));
                }
                self.stopped_owner = self.active_owner.take();
                P::NeedUninstallRequested
            }
            (P::NeedUninstallRequested, K::UninstallRequested) => P::NeedUninstallVerified,
            (P::NeedUninstallVerified, K::UninstallVerified) => P::NeedQualificationSealed,
            (P::NeedQualificationSealed, K::QualificationSealed) => P::Sealed,
            _ => {
                return Err(invalid_data(
                    "SCM qualification event is duplicated, reordered, or on an invalid branch",
                ));
            }
        };
        Ok(())
    }
}

fn required_owner(event: &ScmQualificationAuditEventV1) -> io::Result<&ProcessIdentityV1> {
    event
        .owner_process
        .as_ref()
        .ok_or_else(|| invalid_data("SCM event requires an owner process identity"))
}

fn require_active_owner(
    replay: &QualificationReplayMachineV1,
    event: &ScmQualificationAuditEventV1,
) -> io::Result<()> {
    if event.owner_process.as_ref() != replay.active_owner.as_ref() {
        return Err(invalid_data("SCM event changed the active owner identity"));
    }
    Ok(())
}

fn verify_recovery_binding(
    replay: &mut QualificationReplayMachineV1,
    event: &ScmQualificationAuditEventV1,
    forced: bool,
) -> io::Result<()> {
    let (prior_journal, prior_ledger, prior_forced) = replay
        .pending_recovery
        .take()
        .ok_or_else(|| invalid_data("journal recovery lacks a preceding owner-exit event"))?;
    let recovered_journal = event
        .journal
        .as_ref()
        .ok_or_else(|| invalid_data("journal recovery event lacks journal evidence"))?;
    let recovered_ledger = event
        .ledger
        .as_ref()
        .ok_or_else(|| invalid_data("journal recovery event lacks ledger evidence"))?;
    let common_prefix_changed = prior_journal.durable_record_count
        != recovered_journal.durable_record_count
        || prior_journal.durable_valid_len != recovered_journal.durable_valid_len
        || prior_journal.last_journal_sequence != recovered_journal.last_journal_sequence;
    let graceful_artifact_changed = prior_journal.path != recovered_journal.path
        || prior_journal.file_identity != recovered_journal.file_identity
        || prior_journal.sha256_hex != recovered_journal.sha256_hex
        || prior_ledger.path != recovered_ledger.path
        || prior_ledger.file_identity != recovered_ledger.file_identity
        || prior_ledger.sha256_hex != recovered_ledger.sha256_hex;
    let forced_artifact_not_snapshotted = prior_journal.path == recovered_journal.path
        || prior_journal.file_identity == recovered_journal.file_identity
        || prior_ledger.path == recovered_ledger.path
        || prior_ledger.file_identity == recovered_ledger.file_identity;
    if prior_forced != forced
        || common_prefix_changed
        || (forced && forced_artifact_not_snapshotted)
        || (!forced && graceful_artifact_changed)
    {
        return Err(invalid_data(
            "journal/ledger recovery is not bound to immutable preceding and recovered artifacts",
        ));
    }
    Ok(())
}

struct LoadedAuditV1 {
    events: Vec<ScmQualificationAuditEventV1>,
    evidence: ScmAuditEvidenceV1,
    machine: QualificationReplayMachineV1,
}

fn load_and_replay_audit(
    path: &Path,
    expected_context: Option<&ScmQualificationContextV1>,
) -> io::Result<LoadedAuditV1> {
    if !path.is_absolute() {
        return Err(invalid_data("audit path is not absolute"));
    }
    let (bytes, audit_binding) = read_bound_evidence_file(path)?;
    replay_audit_snapshot(bytes, audit_binding, expected_context)
}

fn replay_audit_snapshot(
    bytes: Vec<u8>,
    audit_binding: EvidenceFileBindingV1,
    expected_context: Option<&ScmQualificationContextV1>,
) -> io::Result<LoadedAuditV1> {
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err(invalid_data(
            "audit must be nonempty and end with exactly a complete newline-terminated line",
        ));
    }
    let mut events = Vec::new();
    let mut previous_hash = [0_u8; 32];
    let mut machine = QualificationReplayMachineV1::default();
    let mut inferred_context: Option<ScmQualificationContextV1> = None;
    for (index, raw) in bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        if raw.is_empty() {
            return Err(invalid_data("audit contains an empty line"));
        }
        let value: serde_json::Value = serde_json::from_slice(raw).map_err(json_error)?;
        if value.get("schema").and_then(serde_json::Value::as_str) != Some(SCM_QUALIFICATION_SCHEMA)
        {
            return Err(invalid_data("old or unknown SCM qualification schema"));
        }
        let event: ScmQualificationAuditEventV1 =
            serde_json::from_value(value).map_err(json_error)?;
        if serde_json::to_vec(&event).map_err(json_error)? != raw {
            return Err(invalid_data("audit line is not canonical JSON"));
        }
        if event.event_sequence != index as u64
            || event.previous_event_hash_hex != hex(&previous_hash)
        {
            return Err(invalid_data("audit sequence or previous hash is invalid"));
        }
        let event_context = context_from_event(&event);
        validate_context(&event_context, false)?;
        if let Some(expected) = expected_context {
            if &event_context != expected {
                return Err(invalid_data("audit identity differs from expected context"));
            }
        }
        if let Some(inferred) = &inferred_context {
            if inferred != &event_context {
                return Err(invalid_data("audit common identity changed mid-stream"));
            }
        } else {
            inferred_context = Some(event_context);
        }
        validate_event_shape(&event)?;
        let covered = canonical_covered_event_bytes(&event)?;
        if event.event_crc32c != crc32c(&covered) {
            return Err(invalid_data("audit CRC32C mismatch"));
        }
        let expected_hash = hash_audit_event(&covered, event.event_crc32c);
        if event.event_hash_hex != hex(&expected_hash) {
            return Err(invalid_data("audit SHA-256 chain mismatch"));
        }
        machine.apply(&event)?;
        previous_hash = expected_hash;
        events.push(event);
    }
    let first_event_hash_hex = events
        .first()
        .map(|event| event.event_hash_hex.clone())
        .ok_or_else(|| invalid_data("audit contains no event"))?;
    let event_count = events.len() as u64;
    Ok(LoadedAuditV1 {
        events,
        evidence: ScmAuditEvidenceV1 {
            path: audit_binding.path,
            sha256_hex: audit_binding.sha256_hex,
            bytes: audit_binding.bytes,
            file_identity: audit_binding.file_identity,
            event_count,
            first_event_hash_hex,
            last_event_hash_hex: hex(&previous_hash),
        },
        machine,
    })
}

fn validate_context(
    context: &ScmQualificationContextV1,
    rehash_executable: bool,
) -> io::Result<()> {
    let executable = Path::new(&context.service_executable_path);
    if !is_nonzero_hex_len(&context.qualification_id_hex, 32)
        || context.service_name.trim().is_empty()
        || context.service_name.len() > 256
        || !executable.is_absolute()
        || !is_nonzero_hex_len(&context.service_executable_sha256_hex, 64)
        || !is_service_sid(&context.service_sid)
    {
        return Err(invalid_data("SCM qualification context is malformed"));
    }
    validate_process_identity(&context.qualification_supervisor)?;
    validate_process_identity(&context.service_supervisor)?;
    if context.qualification_supervisor == context.service_supervisor {
        return Err(invalid_data(
            "qualification supervisor must be distinct from the SCM service supervisor",
        ));
    }
    if rehash_executable && sha256_file(executable)? != context.service_executable_sha256_hex {
        return Err(invalid_data(
            "retained service executable does not match its context hash",
        ));
    }
    Ok(())
}

fn validate_event_shape(event: &ScmQualificationAuditEventV1) -> io::Result<()> {
    if event.schema != SCM_QUALIFICATION_SCHEMA
        || event.wall_time_unix_ns == 0
        || event.monotonic_time_ns == 0
        || !is_hex_len(&event.previous_event_hash_hex, 64)
        || (!event.event_hash_hex.is_empty() && !is_nonzero_hex_len(&event.event_hash_hex, 64))
    {
        return Err(invalid_data("SCM audit event fixed fields are malformed"));
    }
    validate_scm_snapshot(&event.scm)?;
    if let Some(owner) = &event.owner_process {
        validate_process_identity(owner)?;
        if owner == &event.qualification_supervisor || owner == &event.service_supervisor {
            return Err(invalid_data(
                "qualification/SCM supervisors and service owner must be distinct",
            ));
        }
    }
    if let Some(value) = &event.service_configuration {
        validate_service_configuration(value, event)?;
    }
    for value in [
        event.pipe_dacl_sha256_hex.as_deref(),
        event.service_object_dacl_sha256_hex.as_deref(),
        event.data_root_dacl_sha256_hex.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !is_nonzero_hex_len(value, 64) {
            return Err(invalid_data("DACL evidence hash is malformed"));
        }
    }
    if let Some(journal) = &event.journal {
        validate_journal_evidence(journal)?;
    }
    if let Some(ledger) = &event.ledger {
        validate_ledger_evidence(ledger)?;
    }

    use ScmQualificationEventKindV1 as K;
    use ScmServiceStateV1 as S;
    let no_specific = || {
        event.win32_exit_code.is_none()
            && event.service_exit_code.is_none()
            && event.service_configuration.is_none()
            && event.token_user_sid_verified.is_none()
            && event.pipe_dacl_sha256_hex.is_none()
            && event.service_object_dacl_sha256_hex.is_none()
            && event.data_root_dacl_sha256_hex.is_none()
            && event.journal.is_none()
            && event.ledger.is_none()
    };
    let state_is = |state| event.scm.state == state;
    let exact = match event.kind {
        K::Preflight | K::ArtifactRetained | K::InstallRequested => {
            event.owner_process.is_none() && state_is(S::Absent) && no_specific()
        }
        K::InstallReadback => {
            event.owner_process.is_none()
                && state_is(S::Stopped)
                && event.win32_exit_code == Some(0)
                && event.service_exit_code == Some(0)
                && event.service_configuration.is_some()
                && only_specific(event, SpecificFieldsV1::Configuration)
        }
        K::ServiceSidVerified => {
            event.owner_process.is_none()
                && state_is(S::Stopped)
                && event.token_user_sid_verified == Some(true)
                && only_specific(event, SpecificFieldsV1::Token)
        }
        K::ServiceObjectDaclVerified => {
            event.owner_process.is_none()
                && state_is(S::Stopped)
                && event.service_object_dacl_sha256_hex.is_some()
                && only_specific(event, SpecificFieldsV1::ServiceDacl)
        }
        K::DataRootDaclVerified => {
            event.owner_process.is_none()
                && state_is(S::Stopped)
                && event.data_root_dacl_sha256_hex.is_some()
                && only_specific(event, SpecificFieldsV1::DataRootDacl)
        }
        K::StartRequested => event.owner_process.is_none() && state_is(S::Stopped) && no_specific(),
        K::StartPending => {
            event.owner_process.is_none() && state_is(S::StartPending) && no_specific()
        }
        K::Running => {
            event.owner_process.is_some()
                && state_is(S::Running)
                && event.win32_exit_code == Some(0)
                && event.service_exit_code == Some(0)
                && only_specific(event, SpecificFieldsV1::ExitCodes)
        }
        K::OwnerReady => {
            event.owner_process.is_some()
                && state_is(S::Running)
                && event.pipe_dacl_sha256_hex.is_some()
                && only_specific(event, SpecificFieldsV1::PipeDacl)
        }
        K::StopRequested => event.owner_process.is_some() && state_is(S::Running) && no_specific(),
        K::StopPending | K::OwnerGracefulShutdownRequested => {
            event.owner_process.is_some() && state_is(S::StopPending) && no_specific()
        }
        K::OwnerExitProven => {
            event.owner_process.is_some()
                && state_is(S::StopPending)
                && event.win32_exit_code == Some(0)
                && event.service_exit_code == Some(0)
                && event
                    .journal
                    .as_ref()
                    .is_some_and(|journal| journal.sealed && !journal.recovery_verified)
                && event.ledger.is_some()
                && only_specific(event, SpecificFieldsV1::ExitJournalLedger)
        }
        K::ForcedOwnerTermination => {
            event.owner_process.is_some()
                && state_is(S::Running)
                && event.win32_exit_code.is_some_and(|value| value != 0)
                && event.service_exit_code == Some(0)
                && event
                    .journal
                    .as_ref()
                    .is_some_and(|journal| !journal.sealed && !journal.recovery_verified)
                && event.ledger.is_some()
                && only_specific(event, SpecificFieldsV1::ExitJournalLedger)
        }
        K::JournalRecoveryVerified => {
            event.owner_process.is_some()
                && matches!(event.scm.state, S::Running | S::StopPending)
                && event
                    .journal
                    .as_ref()
                    .is_some_and(|journal| journal.sealed && journal.recovery_verified)
                && event.ledger.is_some()
                && only_specific(event, SpecificFieldsV1::JournalLedger)
        }
        K::ServiceStopped => {
            event.owner_process.is_some()
                && state_is(S::Stopped)
                && event.win32_exit_code == Some(0)
                && event.service_exit_code == Some(0)
                && only_specific(event, SpecificFieldsV1::ExitCodes)
        }
        K::RestartObserved => {
            event.owner_process.is_some() && state_is(S::Running) && no_specific()
        }
        K::UninstallRequested => {
            event.owner_process.is_none() && state_is(S::Stopped) && no_specific()
        }
        K::UninstallVerified => {
            event.owner_process.is_none()
                && state_is(S::Absent)
                && event.win32_exit_code == Some(0)
                && event.service_exit_code == Some(0)
                && only_specific(event, SpecificFieldsV1::ExitCodes)
        }
        K::QualificationSealed => {
            event.owner_process.is_none() && state_is(S::Absent) && no_specific()
        }
    };
    if !exact {
        return Err(invalid_data(
            "SCM audit event has missing or non-null fields for its event kind",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SpecificFieldsV1 {
    Configuration,
    Token,
    PipeDacl,
    ServiceDacl,
    DataRootDacl,
    ExitCodes,
    JournalLedger,
    ExitJournalLedger,
}

fn only_specific(event: &ScmQualificationAuditEventV1, allowed: SpecificFieldsV1) -> bool {
    let exit = matches!(
        allowed,
        SpecificFieldsV1::Configuration
            | SpecificFieldsV1::ExitCodes
            | SpecificFieldsV1::ExitJournalLedger
    );
    let configuration = matches!(allowed, SpecificFieldsV1::Configuration);
    let token = matches!(allowed, SpecificFieldsV1::Token);
    let pipe = matches!(allowed, SpecificFieldsV1::PipeDacl);
    let service = matches!(allowed, SpecificFieldsV1::ServiceDacl);
    let data_root = matches!(allowed, SpecificFieldsV1::DataRootDacl);
    let journal = matches!(
        allowed,
        SpecificFieldsV1::JournalLedger | SpecificFieldsV1::ExitJournalLedger
    );
    let ledger = journal;
    (exit == (event.win32_exit_code.is_some() && event.service_exit_code.is_some()))
        && (!exit || (event.win32_exit_code.is_some() && event.service_exit_code.is_some()))
        && (configuration == event.service_configuration.is_some())
        && (token == event.token_user_sid_verified.is_some())
        && (pipe == event.pipe_dacl_sha256_hex.is_some())
        && (service == event.service_object_dacl_sha256_hex.is_some())
        && (data_root == event.data_root_dacl_sha256_hex.is_some())
        && (journal == event.journal.is_some())
        && (ledger == event.ledger.is_some())
}

fn validate_scm_snapshot(snapshot: &ScmStatusSnapshotV1) -> io::Result<()> {
    let valid = match snapshot.state {
        ScmServiceStateV1::StartPending | ScmServiceStateV1::StopPending => {
            snapshot.checkpoint > 0 && snapshot.wait_hint_ms > 0
        }
        _ => snapshot.checkpoint == 0 && snapshot.wait_hint_ms == 0,
    };
    if !valid {
        return Err(invalid_data("SCM checkpoint/wait-hint shape is invalid"));
    }
    Ok(())
}

fn validate_service_configuration(
    value: &ServiceConfigurationReadbackV1,
    event: &ScmQualificationAuditEventV1,
) -> io::Result<()> {
    if value.service_account_name.trim().is_empty()
        || value.binary_path != event.service_executable_path
        || value.start_type == ScmStartTypeV1::Disabled
        || value.service_sid_type == ScmServiceSidTypeV1::None
        || !is_nonzero_hex_len(&value.failure_actions_sha256_hex, 64)
    {
        return Err(invalid_data(
            "SCM service configuration readback is invalid",
        ));
    }
    Ok(())
}

fn validate_journal_evidence(value: &JournalEvidenceSnapshotV1) -> io::Result<()> {
    if !Path::new(&value.path).is_absolute()
        || !is_nonzero_hex_len(&value.sha256_hex, 64)
        || !valid_file_identity(&value.file_identity)
        || value.durable_valid_len == 0
        || value.durable_valid_len > value.file_identity.bytes
        || value.last_journal_sequence.is_none() != (value.durable_record_count == 0)
        || (value.sealed
            && (value.seal_expected_last_journal_sequence != value.last_journal_sequence
                || value.durable_record_count == 0))
        || (!value.sealed && value.seal_expected_last_journal_sequence.is_some())
        || (value.recovery_verified && !value.sealed)
    {
        return Err(invalid_data("journal evidence shape is invalid"));
    }
    Ok(())
}

fn validate_ledger_evidence(value: &LedgerEvidenceSnapshotV1) -> io::Result<()> {
    if !Path::new(&value.path).is_absolute()
        || !is_nonzero_hex_len(&value.sha256_hex, 64)
        || !valid_file_identity(&value.file_identity)
        || value.state.trim().is_empty()
    {
        return Err(invalid_data("ledger evidence shape is invalid"));
    }
    Ok(())
}

fn valid_file_identity(value: &EvidenceFileIdentityV1) -> bool {
    value.file_index != 0 && value.bytes != 0
}

fn validate_process_identity(value: &ProcessIdentityV1) -> io::Result<()> {
    if value.pid == 0 || value.creation_time_100ns == 0 {
        return Err(invalid_data(
            "process PID/creation-time identity is invalid",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn current_process_identity() -> io::Result<ProcessIdentityV1> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let pid = std::process::id();
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut creation: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };
    let called =
        unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    let call_error = (called == 0).then(io::Error::last_os_error);
    unsafe { CloseHandle(handle) };
    if let Some(error) = call_error {
        return Err(error);
    }
    let creation_time_100ns =
        (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    let identity = ProcessIdentityV1 {
        pid,
        creation_time_100ns,
    };
    validate_process_identity(&identity)?;
    Ok(identity)
}

#[cfg(not(windows))]
fn current_process_identity() -> io::Result<ProcessIdentityV1> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SCM qualification audit writers require Windows process identity",
    ))
}

fn context_from_event(event: &ScmQualificationAuditEventV1) -> ScmQualificationContextV1 {
    ScmQualificationContextV1 {
        qualification_id_hex: event.qualification_id_hex.clone(),
        service_name: event.service_name.clone(),
        service_executable_path: event.service_executable_path.clone(),
        service_executable_sha256_hex: event.service_executable_sha256_hex.clone(),
        service_sid: event.service_sid.clone(),
        qualification_supervisor: event.qualification_supervisor.clone(),
        service_supervisor: event.service_supervisor.clone(),
        evidence_source: event.evidence_source,
    }
}

fn canonical_covered_event_bytes(event: &ScmQualificationAuditEventV1) -> io::Result<Vec<u8>> {
    let mut covered = event.clone();
    covered.event_crc32c = 0;
    covered.event_hash_hex.clear();
    serde_json::to_vec(&covered).map_err(json_error)
}

fn hash_audit_event(covered: &[u8], crc: u32) -> [u8; 32] {
    let mut input = Vec::with_capacity(AUDIT_HASH_DOMAIN.len() + covered.len() + 4);
    input.extend_from_slice(AUDIT_HASH_DOMAIN);
    input.extend_from_slice(covered);
    input.extend_from_slice(&crc.to_le_bytes());
    sha256(&input)
}

#[cfg(windows)]
fn create_exclusive_new(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(path)
}

#[cfg(not(windows))]
fn create_exclusive_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFileBindingV1 {
    pub path: String,
    pub sha256_hex: String,
    pub bytes: u64,
    pub file_identity: EvidenceFileIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmAuditReceiptBindingV1 {
    pub path: String,
    pub sha256_hex: String,
    pub bytes: u64,
    pub file_identity: EvidenceFileIdentityV1,
    pub event_count: u64,
    pub first_event_hash_hex: String,
    pub last_event_hash_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmAclReceiptV1 {
    pub service_sid_verified: bool,
    pub token_user_sid_verified: bool,
    pub pipe_dacl_sha256_hex: String,
    pub service_object_dacl_sha256_hex: String,
    pub data_root_dacl_sha256_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTimeV1 {
    pub wall_time_unix_ns: u64,
    pub monotonic_time_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmStateTrackEntryV1 {
    pub event_sequence: u64,
    pub kind: ScmQualificationEventKindV1,
    pub owner_process: Option<ProcessIdentityV1>,
    pub scm: ScmStatusSnapshotV1,
    pub observed_at: EvidenceTimeV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerInstanceReceiptV1 {
    pub instance_index: u32,
    pub owner_process: ProcessIdentityV1,
    pub owner_started_at: EvidenceTimeV1,
    pub owner_ready_at: EvidenceTimeV1,
    pub stop_requested_at: Option<EvidenceTimeV1>,
    pub owner_exit_observed_at: EvidenceTimeV1,
    pub owner_stopped_at: EvidenceTimeV1,
    pub successor_restart_observed_at: Option<EvidenceTimeV1>,
    pub stop_method: OwnerStopMethodV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalReceiptV1 {
    pub path: String,
    pub sha256_hex: String,
    pub file_identity: EvidenceFileIdentityV1,
    pub durable_record_count: u64,
    pub durable_valid_len: u64,
    pub last_journal_sequence: u64,
    pub seal_expected_last_journal_sequence: u64,
    pub sealed: bool,
    pub recovery_verified: bool,
    pub ledger_path: String,
    pub ledger_sha256_hex: String,
    pub ledger_file_identity: EvidenceFileIdentityV1,
    pub ledger_state: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryBranchV1 {
    ForcedOwnerRestart,
    GracefulServiceStop,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryArtifactTrackV1 {
    pub branch: RecoveryBranchV1,
    pub preceding_event_sequence: u64,
    pub recovery_event_sequence: u64,
    pub preceding_owner: ProcessIdentityV1,
    pub recovered_owner: ProcessIdentityV1,
    pub prior_journal: JournalEvidenceSnapshotV1,
    pub recovered_journal: JournalEvidenceSnapshotV1,
    pub prior_ledger: LedgerEvidenceSnapshotV1,
    pub recovered_ledger: LedgerEvidenceSnapshotV1,
}

/// Caller-frozen path expectations prevent a valid, internally consistent
/// audit from being replayed against substituted recovery artifacts.  File
/// identity and hashes come from the audit writer's stable handles, not from
/// these caller-owned path declarations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPathExpectationV1 {
    pub branch: RecoveryBranchV1,
    pub prior_journal_path: PathBuf,
    pub recovered_journal_path: PathBuf,
    pub prior_ledger_path: PathBuf,
    pub recovered_ledger_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalServiceStateV1 {
    pub installed: bool,
    pub running: bool,
    pub stopped: bool,
    pub uninstalled: bool,
}

/// Independently collected SCM lifecycle evidence.  The qualification module
/// intentionally exposes no production builder for this object: the Windows
/// SCM supervisor/qualification harness must collect it from SCM API readback,
/// publish canonical JSON, and then pass its path to the receipt builder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalScmLifecycleEvidenceV1 {
    pub schema: String,
    pub qualification_id_hex: String,
    pub evidence_source: ScmEvidenceSourceV1,
    pub qualification_supervisor: ProcessIdentityV1,
    pub service_supervisor: ProcessIdentityV1,
    pub service_name: String,
    pub service_executable_path: String,
    pub service_executable_sha256_hex: String,
    pub service_sid: String,
    pub audit: ScmAuditReceiptBindingV1,
    pub service_configuration_readback: ServiceConfigurationReadbackV1,
    pub acl_evidence: ScmAclReceiptV1,
    pub owner_instances: Vec<OwnerInstanceReceiptV1>,
    pub state_track: Vec<ScmStateTrackEntryV1>,
    pub first_start_requested_at: EvidenceTimeV1,
    pub final_stop_requested_at: Option<EvidenceTimeV1>,
    pub final_service_stopped_at: EvidenceTimeV1,
    pub restart_observed_count: u32,
    pub owner_graceful_shutdown_count: u32,
    pub forced_owner_termination_count: u32,
    pub recovery_track: Vec<RecoveryArtifactTrackV1>,
    pub journal: JournalReceiptV1,
    pub final_service_state: FinalServiceStateV1,
    pub scm_api_readback_verified: bool,
    pub audit_replay_verified: bool,
    pub external_artifacts_rehashed: bool,
    pub service_deployed: bool,
    pub scm_emulated: bool,
    pub evidence_sha256_hex: String,
    pub evidence_hash_is_signature_or_attestation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmQualificationReceiptV1 {
    pub schema: String,
    pub qualification_id_hex: String,
    pub service_name: String,
    pub service_executable_path: String,
    pub service_executable_sha256_hex: String,
    pub service_sid: String,
    pub qualification_supervisor: ProcessIdentityV1,
    pub service_supervisor: ProcessIdentityV1,
    pub evidence_source: ScmEvidenceSourceV1,
    pub audit: ScmAuditReceiptBindingV1,
    pub scm_lifecycle_evidence: EvidenceFileBindingV1,
    pub retained_binary: EvidenceFileBindingV1,
    pub service_configuration_readback: ServiceConfigurationReadbackV1,
    pub acl_evidence: ScmAclReceiptV1,
    pub owner_instances: Vec<OwnerInstanceReceiptV1>,
    pub state_track: Vec<ScmStateTrackEntryV1>,
    pub first_start_requested_at: EvidenceTimeV1,
    pub final_stop_requested_at: Option<EvidenceTimeV1>,
    pub final_service_stopped_at: EvidenceTimeV1,
    pub restart_observed_count: u32,
    pub owner_graceful_shutdown_count: u32,
    pub forced_owner_termination_count: u32,
    pub recovery_track: Vec<RecoveryArtifactTrackV1>,
    pub journal: JournalReceiptV1,
    pub final_service_state: FinalServiceStateV1,
    pub service_deployed: bool,
    pub scm_emulated: bool,
    pub hardware_qualified: bool,
    pub nwb_qualified: bool,
    pub open_gates: Vec<String>,
    pub passed: bool,
    pub evidence_sha256_hex: String,
    pub evidence_hash_is_signature_or_attestation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScmQualificationReceiptOptionsV1 {
    pub open_gates: Vec<String>,
    pub scm_lifecycle_evidence_path: PathBuf,
    pub recovery_paths: Vec<RecoveryPathExpectationV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScmQualificationVerificationExpectationV1 {
    pub qualification_id_hex: String,
    pub service_name: String,
    pub service_sid: String,
    pub qualification_supervisor: ProcessIdentityV1,
    pub service_supervisor: ProcessIdentityV1,
    pub evidence_source: ScmEvidenceSourceV1,
    pub audit_path: PathBuf,
    pub scm_lifecycle_evidence_path: PathBuf,
    pub retained_binary_path: PathBuf,
    pub journal_path: PathBuf,
    pub ledger_path: PathBuf,
    pub recovery_paths: Vec<RecoveryPathExpectationV1>,
}

/// Builds a receipt from independently replayed audit evidence and freshly
/// rehashed external artifacts.  This function does not publish anything.
pub fn build_scm_qualification_receipt_v1(
    audit_path: &Path,
    retained_binary_path: &Path,
    options: ScmQualificationReceiptOptionsV1,
) -> io::Result<ScmQualificationReceiptV1> {
    if !audit_path.is_absolute()
        || !retained_binary_path.is_absolute()
        || !options.scm_lifecycle_evidence_path.is_absolute()
    {
        return Err(invalid_input(
            "receipt artifact paths must be absolute trusted paths",
        ));
    }
    validate_recovery_path_expectations(&options.recovery_paths)?;
    let loaded = load_and_replay_audit(audit_path, None)?;
    if !loaded.machine.is_sealed() {
        return Err(invalid_data("cannot receipt an unsealed audit"));
    }
    rehash_all_audited_external_files(&loaded.events)?;
    let first = loaded
        .events
        .first()
        .ok_or_else(|| invalid_data("audit has no first event"))?;
    if first.service_executable_path != utf8_path(retained_binary_path)? {
        return Err(invalid_data(
            "retained binary path differs from the audited service executable",
        ));
    }
    let binary = bind_file(retained_binary_path)?;
    if binary.sha256_hex != first.service_executable_sha256_hex {
        return Err(invalid_data(
            "retained binary hash differs from the audited executable hash",
        ));
    }
    let derived = derive_receipt_evidence(&loaded.events)?;
    verify_recovery_path_expectations(&derived.recovery_track, &options.recovery_paths)?;
    if sha256_file(Path::new(&derived.journal.path))? != derived.journal.sha256_hex
        || sha256_file(Path::new(&derived.journal.ledger_path))?
            != derived.journal.ledger_sha256_hex
    {
        return Err(invalid_data(
            "journal or ledger no longer matches the sealed audit evidence",
        ));
    }
    let audit_binding = ScmAuditReceiptBindingV1 {
        path: loaded.evidence.path.clone(),
        sha256_hex: loaded.evidence.sha256_hex.clone(),
        bytes: loaded.evidence.bytes,
        file_identity: loaded.evidence.file_identity.clone(),
        event_count: loaded.evidence.event_count,
        first_event_hash_hex: loaded.evidence.first_event_hash_hex.clone(),
        last_event_hash_hex: loaded.evidence.last_event_hash_hex.clone(),
    };
    let final_service_state = FinalServiceStateV1 {
        installed: false,
        running: false,
        stopped: true,
        uninstalled: true,
    };
    let (external_lifecycle, lifecycle_binding) = read_and_verify_external_scm_lifecycle_evidence(
        &options.scm_lifecycle_evidence_path,
        first,
        &audit_binding,
        &derived,
        &final_service_state,
    )?;

    // Deployment/emulation status comes only from independently collected
    // lifecycle evidence.  The receipt builder never promotes an audit source
    // enum into a real-SCM pass by itself.
    let service_deployed = external_lifecycle.service_deployed;
    let scm_emulated = external_lifecycle.scm_emulated;
    let hardware_qualified = false;
    let nwb_qualified = false;
    let open_gates = normalize_open_gates(options.open_gates, service_deployed, false, false)?;
    let passed = qualification_passes(
        service_deployed,
        scm_emulated,
        hardware_qualified,
        nwb_qualified,
        &open_gates,
        &derived,
        &final_service_state,
    );
    let mut receipt = ScmQualificationReceiptV1 {
        schema: SCM_QUALIFICATION_SCHEMA.to_owned(),
        qualification_id_hex: first.qualification_id_hex.clone(),
        service_name: first.service_name.clone(),
        service_executable_path: first.service_executable_path.clone(),
        service_executable_sha256_hex: first.service_executable_sha256_hex.clone(),
        service_sid: first.service_sid.clone(),
        qualification_supervisor: first.qualification_supervisor.clone(),
        service_supervisor: first.service_supervisor.clone(),
        evidence_source: first.evidence_source,
        audit: audit_binding,
        scm_lifecycle_evidence: lifecycle_binding,
        retained_binary: binary,
        service_configuration_readback: derived.configuration,
        acl_evidence: derived.acl,
        owner_instances: derived.owner_instances,
        state_track: derived.state_track,
        first_start_requested_at: derived.first_start_requested_at,
        final_stop_requested_at: derived.final_stop_requested_at,
        final_service_stopped_at: derived.final_service_stopped_at,
        restart_observed_count: derived.restart_observed_count,
        owner_graceful_shutdown_count: derived.owner_graceful_shutdown_count,
        forced_owner_termination_count: derived.forced_owner_termination_count,
        recovery_track: derived.recovery_track,
        journal: derived.journal,
        final_service_state,
        service_deployed,
        scm_emulated,
        hardware_qualified,
        nwb_qualified,
        open_gates,
        passed,
        evidence_sha256_hex: String::new(),
        evidence_hash_is_signature_or_attestation: false,
    };
    receipt.evidence_sha256_hex = receipt_evidence_hash(&receipt)?;
    validate_receipt_fixed_semantics(&receipt)?;
    Ok(receipt)
}

/// Publishes canonical JSON through a create-new pending file, durable flush,
/// and a Windows no-replace rename.  A failed publish can leave a forensic
/// pending file, but never deletes audit, journal, ledger, or binary evidence.
pub fn publish_scm_qualification_receipt_v1(
    path: &Path,
    receipt: &ScmQualificationReceiptV1,
    expected: &ScmQualificationVerificationExpectationV1,
) -> io::Result<()> {
    validate_expectation(expected)?;
    validate_receipt_fixed_semantics(receipt)?;
    if receipt.evidence_sha256_hex != receipt_evidence_hash(receipt)? {
        return Err(invalid_data("receipt evidence hash is invalid"));
    }
    // Keep read-only, delete/write-denying Windows handles open across the
    // final independent rebuild and rename.  This closes the publication
    // window in which a retained artifact could otherwise be replaced.
    let _evidence_locks = lock_all_receipted_evidence(receipt)?;
    let rebuilt = build_scm_qualification_receipt_v1(
        &expected.audit_path,
        &expected.retained_binary_path,
        ScmQualificationReceiptOptionsV1 {
            open_gates: receipt.open_gates.clone(),
            scm_lifecycle_evidence_path: expected.scm_lifecycle_evidence_path.clone(),
            recovery_paths: expected.recovery_paths.clone(),
        },
    )?;
    if &rebuilt != receipt {
        return Err(invalid_data(
            "formal receipt differs from independently rebuilt external evidence",
        ));
    }
    if !path.is_absolute() || path.parent().is_none_or(|parent| !parent.is_dir()) {
        return Err(invalid_input(
            "receipt path must be absolute with an existing parent",
        ));
    }
    let pending = path.with_extension("pending");
    let reserved_pending_extension = path.extension().is_some_and(|extension| {
        extension
            .to_string_lossy()
            .trim_end_matches(['.', ' '])
            .eq_ignore_ascii_case("pending")
    });
    if pending == path || reserved_pending_extension {
        return Err(invalid_input(
            "formal receipt path must not already use the reserved pending extension",
        ));
    }
    if path.exists() || pending.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "formal receipt or pending path already exists",
        ));
    }
    let bytes = serde_json::to_vec(receipt).map_err(json_error)?;
    let mut file = create_exclusive_new(&pending)?;
    (|| {
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()
    })()?;
    drop(file);
    // The pending receipt is durable, but is not formal yet.  Re-open every
    // caller-frozen pathname and independently re-hash/replay it one final
    // time while the original stable handles remain locked.  Any pathname
    // substitution or content/file-ID drift leaves only the forensic pending
    // file and cannot reach the formal name.
    let final_snapshot = build_scm_qualification_receipt_v1(
        &expected.audit_path,
        &expected.retained_binary_path,
        ScmQualificationReceiptOptionsV1 {
            open_gates: receipt.open_gates.clone(),
            scm_lifecycle_evidence_path: expected.scm_lifecycle_evidence_path.clone(),
            recovery_paths: expected.recovery_paths.clone(),
        },
    )?;
    if &final_snapshot != receipt {
        return Err(invalid_data(
            "final pre-publication evidence snapshot differs from the receipt",
        ));
    }
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "formal receipt appeared before no-overwrite rename",
        ));
    }
    rename_no_overwrite(&pending, path)
}

/// Verifies a canonical receipt against caller-owned expected paths and
/// identities, rehashes every external file, replays the audit state machine,
/// and reconstructs the expected receipt byte-for-byte.
pub fn verify_scm_qualification_receipt_v1(
    receipt_path: &Path,
    expected: &ScmQualificationVerificationExpectationV1,
) -> io::Result<ScmQualificationReceiptV1> {
    validate_expectation(expected)?;
    if !receipt_path.is_absolute() {
        return Err(invalid_input("formal receipt path must be absolute"));
    }
    // Keep the formal receipt path itself open without write/delete sharing
    // until every bound artifact has been replayed and rehashed.
    let mut receipt_lock = open_evidence_file(receipt_path)?;
    let (bytes, _receipt_snapshot) =
        read_bound_open_evidence_file(receipt_path, &mut receipt_lock)?;
    if bytes.is_empty() {
        return Err(invalid_data("SCM qualification receipt is empty"));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(json_error)?;
    if value.get("schema").and_then(serde_json::Value::as_str) != Some(SCM_QUALIFICATION_SCHEMA) {
        return Err(invalid_data(
            "old or unknown SCM qualification receipt schema",
        ));
    }
    let receipt: ScmQualificationReceiptV1 = serde_json::from_value(value).map_err(json_error)?;
    if serde_json::to_vec(&receipt).map_err(json_error)? != bytes {
        return Err(invalid_data(
            "SCM qualification receipt is not canonical JSON",
        ));
    }
    if receipt.evidence_sha256_hex != receipt_evidence_hash(&receipt)? {
        return Err(invalid_data("receipt evidence hash mismatch"));
    }
    if receipt.qualification_id_hex != expected.qualification_id_hex
        || receipt.service_name != expected.service_name
        || receipt.service_sid != expected.service_sid
        || receipt.qualification_supervisor != expected.qualification_supervisor
        || receipt.service_supervisor != expected.service_supervisor
        || receipt.evidence_source != expected.evidence_source
        || receipt.audit.path != utf8_path(&expected.audit_path)?
        || receipt.scm_lifecycle_evidence.path != utf8_path(&expected.scm_lifecycle_evidence_path)?
        || receipt.retained_binary.path != utf8_path(&expected.retained_binary_path)?
        || receipt.journal.path != utf8_path(&expected.journal_path)?
        || receipt.journal.ledger_path != utf8_path(&expected.ledger_path)?
    {
        return Err(invalid_data(
            "receipt identity or artifact path differs from the trusted expectation",
        ));
    }
    let _evidence_locks = lock_all_receipted_evidence(&receipt)?;
    let rebuilt = build_scm_qualification_receipt_v1(
        &expected.audit_path,
        &expected.retained_binary_path,
        ScmQualificationReceiptOptionsV1 {
            open_gates: receipt.open_gates.clone(),
            scm_lifecycle_evidence_path: expected.scm_lifecycle_evidence_path.clone(),
            recovery_paths: expected.recovery_paths.clone(),
        },
    )?;
    if rebuilt != receipt {
        return Err(invalid_data(
            "receipt does not match independently replayed and rehashed evidence",
        ));
    }
    Ok(receipt)
}

#[derive(Clone)]
struct DerivedReceiptEvidenceV1 {
    configuration: ServiceConfigurationReadbackV1,
    acl: ScmAclReceiptV1,
    owner_instances: Vec<OwnerInstanceReceiptV1>,
    state_track: Vec<ScmStateTrackEntryV1>,
    first_start_requested_at: EvidenceTimeV1,
    final_stop_requested_at: Option<EvidenceTimeV1>,
    final_service_stopped_at: EvidenceTimeV1,
    restart_observed_count: u32,
    owner_graceful_shutdown_count: u32,
    forced_owner_termination_count: u32,
    recovery_track: Vec<RecoveryArtifactTrackV1>,
    journal: JournalReceiptV1,
}

struct PendingRecoveryTrackV1 {
    branch: RecoveryBranchV1,
    preceding_event_sequence: u64,
    preceding_owner: ProcessIdentityV1,
    prior_journal: JournalEvidenceSnapshotV1,
    prior_ledger: LedgerEvidenceSnapshotV1,
}

struct InstanceBuilderV1 {
    instance_index: u32,
    owner_process: ProcessIdentityV1,
    owner_started_at: EvidenceTimeV1,
    owner_ready_at: Option<EvidenceTimeV1>,
    stop_requested_at: Option<EvidenceTimeV1>,
    owner_exit_observed_at: Option<EvidenceTimeV1>,
    owner_stopped_at: Option<EvidenceTimeV1>,
    successor_restart_observed_at: Option<EvidenceTimeV1>,
    stop_method: Option<OwnerStopMethodV1>,
}

impl InstanceBuilderV1 {
    fn finish(self) -> io::Result<OwnerInstanceReceiptV1> {
        Ok(OwnerInstanceReceiptV1 {
            instance_index: self.instance_index,
            owner_process: self.owner_process,
            owner_started_at: self.owner_started_at,
            owner_ready_at: self
                .owner_ready_at
                .ok_or_else(|| invalid_data("service instance never became owner-ready"))?,
            stop_requested_at: self.stop_requested_at,
            owner_exit_observed_at: self
                .owner_exit_observed_at
                .ok_or_else(|| invalid_data("service instance lacks owner-exit evidence"))?,
            owner_stopped_at: self
                .owner_stopped_at
                .ok_or_else(|| invalid_data("owner instance lacks stopped evidence"))?,
            successor_restart_observed_at: self.successor_restart_observed_at,
            stop_method: self
                .stop_method
                .ok_or_else(|| invalid_data("service instance lacks stop method"))?,
        })
    }
}

fn derive_receipt_evidence(
    events: &[ScmQualificationAuditEventV1],
) -> io::Result<DerivedReceiptEvidenceV1> {
    let configuration = exactly_one(events, |event| event.service_configuration.clone())?;
    let service_dacl = exactly_one(events, |event| event.service_object_dacl_sha256_hex.clone())?;
    let data_root_dacl = exactly_one(events, |event| event.data_root_dacl_sha256_hex.clone())?;
    let mut pipe_hash: Option<String> = None;
    let mut owner_instances = Vec::new();
    let mut current: Option<InstanceBuilderV1> = None;
    let mut first_start_requested_at = None;
    let mut final_stop_requested_at = None;
    let mut final_service_stopped_at = None;
    let mut restart_count = 0_u32;
    let mut graceful_count = 0_u32;
    let mut forced_count = 0_u32;
    let mut final_journal: Option<(JournalEvidenceSnapshotV1, LedgerEvidenceSnapshotV1)> = None;
    let mut pending_recovery: Option<PendingRecoveryTrackV1> = None;
    let mut recovery_track = Vec::new();
    let mut state_track = Vec::with_capacity(events.len());

    for event in events {
        let time = event_time(event);
        state_track.push(ScmStateTrackEntryV1 {
            event_sequence: event.event_sequence,
            kind: event.kind,
            owner_process: event.owner_process.clone(),
            scm: event.scm.clone(),
            observed_at: time.clone(),
        });
        match event.kind {
            ScmQualificationEventKindV1::StartRequested => {
                first_start_requested_at.get_or_insert_with(|| time.clone());
            }
            ScmQualificationEventKindV1::Running => {
                if current.is_some() {
                    return Err(invalid_data("new service instance overlaps prior instance"));
                }
                current = Some(InstanceBuilderV1 {
                    instance_index: owner_instances.len() as u32,
                    owner_process: required_owner(event)?.clone(),
                    owner_started_at: time,
                    owner_ready_at: None,
                    stop_requested_at: None,
                    owner_exit_observed_at: None,
                    owner_stopped_at: None,
                    successor_restart_observed_at: None,
                    stop_method: None,
                });
            }
            ScmQualificationEventKindV1::OwnerReady => {
                let value = event
                    .pipe_dacl_sha256_hex
                    .as_ref()
                    .ok_or_else(|| invalid_data("owner-ready event lacks pipe DACL"))?;
                if pipe_hash.as_ref().is_some_and(|prior| prior != value) {
                    return Err(invalid_data(
                        "pipe DACL hash changed across service restart",
                    ));
                }
                pipe_hash = Some(value.clone());
                current_instance_mut(&mut current)?.owner_ready_at = Some(time);
            }
            ScmQualificationEventKindV1::StopRequested => {
                final_stop_requested_at = Some(time.clone());
                current_instance_mut(&mut current)?.stop_requested_at = Some(time);
            }
            ScmQualificationEventKindV1::OwnerExitProven => {
                graceful_count = graceful_count
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("graceful count overflow"))?;
                let instance = current_instance_mut(&mut current)?;
                instance.owner_exit_observed_at = Some(time.clone());
                instance.owner_stopped_at = Some(time);
                instance.stop_method = Some(OwnerStopMethodV1::Graceful);
                pending_recovery = Some(pending_recovery_from_event(
                    event,
                    RecoveryBranchV1::GracefulServiceStop,
                )?);
            }
            ScmQualificationEventKindV1::ForcedOwnerTermination => {
                forced_count = forced_count
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("forced count overflow"))?;
                let instance = current_instance_mut(&mut current)?;
                instance.owner_exit_observed_at = Some(time.clone());
                instance.owner_stopped_at = Some(time);
                instance.stop_method = Some(OwnerStopMethodV1::Forced);
                pending_recovery = Some(pending_recovery_from_event(
                    event,
                    RecoveryBranchV1::ForcedOwnerRestart,
                )?);
            }
            ScmQualificationEventKindV1::JournalRecoveryVerified => {
                let recovered_journal = event
                    .journal
                    .clone()
                    .ok_or_else(|| invalid_data("recovery event lacks journal"))?;
                let recovered_ledger = event
                    .ledger
                    .clone()
                    .ok_or_else(|| invalid_data("recovery event lacks ledger"))?;
                let pending = pending_recovery
                    .take()
                    .ok_or_else(|| invalid_data("recovery event lacks a preceding owner exit"))?;
                recovery_track.push(RecoveryArtifactTrackV1 {
                    branch: pending.branch,
                    preceding_event_sequence: pending.preceding_event_sequence,
                    recovery_event_sequence: event.event_sequence,
                    preceding_owner: pending.preceding_owner,
                    recovered_owner: required_owner(event)?.clone(),
                    prior_journal: pending.prior_journal,
                    recovered_journal: recovered_journal.clone(),
                    prior_ledger: pending.prior_ledger,
                    recovered_ledger: recovered_ledger.clone(),
                });
                final_journal = Some((recovered_journal, recovered_ledger));
            }
            ScmQualificationEventKindV1::ServiceStopped => {
                final_service_stopped_at = Some(time);
            }
            ScmQualificationEventKindV1::RestartObserved => {
                restart_count = restart_count
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("restart count overflow"))?;
                let mut instance = current
                    .take()
                    .ok_or_else(|| invalid_data("restart has no stopped instance"))?;
                instance.successor_restart_observed_at = Some(time.clone());
                owner_instances.push(instance.finish()?);
                current = Some(InstanceBuilderV1 {
                    instance_index: owner_instances.len() as u32,
                    owner_process: required_owner(event)?.clone(),
                    owner_started_at: time,
                    owner_ready_at: None,
                    stop_requested_at: None,
                    owner_exit_observed_at: None,
                    owner_stopped_at: None,
                    successor_restart_observed_at: None,
                    stop_method: None,
                });
            }
            ScmQualificationEventKindV1::UninstallRequested => {
                let instance = current
                    .take()
                    .ok_or_else(|| invalid_data("uninstall has no stopped instance"))?;
                owner_instances.push(instance.finish()?);
            }
            _ => {}
        }
    }
    if current.is_some() {
        return Err(invalid_data(
            "sealed audit retained an unfinished service instance",
        ));
    }
    if pending_recovery.is_some() || recovery_track.is_empty() {
        return Err(invalid_data(
            "sealed audit has an incomplete or absent recovery evidence track",
        ));
    }
    if owner_instances.is_empty() || restart_count as usize + 1 != owner_instances.len() {
        return Err(invalid_data(
            "service instance/restart count is inconsistent",
        ));
    }
    let (journal, ledger) = final_journal
        .ok_or_else(|| invalid_data("sealed audit lacks recovered journal evidence"))?;
    Ok(DerivedReceiptEvidenceV1 {
        configuration,
        acl: ScmAclReceiptV1 {
            service_sid_verified: true,
            token_user_sid_verified: true,
            pipe_dacl_sha256_hex: pipe_hash
                .ok_or_else(|| invalid_data("sealed audit lacks pipe DACL evidence"))?,
            service_object_dacl_sha256_hex: service_dacl,
            data_root_dacl_sha256_hex: data_root_dacl,
        },
        owner_instances,
        state_track,
        first_start_requested_at: first_start_requested_at
            .ok_or_else(|| invalid_data("sealed audit lacks start time"))?,
        final_stop_requested_at,
        final_service_stopped_at: final_service_stopped_at
            .ok_or_else(|| invalid_data("sealed audit lacks service-stopped time"))?,
        restart_observed_count: restart_count,
        owner_graceful_shutdown_count: graceful_count,
        forced_owner_termination_count: forced_count,
        recovery_track,
        journal: JournalReceiptV1 {
            path: journal.path,
            sha256_hex: journal.sha256_hex,
            file_identity: journal.file_identity,
            durable_record_count: journal.durable_record_count,
            durable_valid_len: journal.durable_valid_len,
            last_journal_sequence: journal
                .last_journal_sequence
                .ok_or_else(|| invalid_data("recovered journal lacks last sequence"))?,
            seal_expected_last_journal_sequence: journal
                .seal_expected_last_journal_sequence
                .ok_or_else(|| invalid_data("recovered journal lacks seal expected-last"))?,
            sealed: journal.sealed,
            recovery_verified: journal.recovery_verified,
            ledger_path: ledger.path,
            ledger_sha256_hex: ledger.sha256_hex,
            ledger_file_identity: ledger.file_identity,
            ledger_state: ledger.state,
        },
    })
}

fn pending_recovery_from_event(
    event: &ScmQualificationAuditEventV1,
    branch: RecoveryBranchV1,
) -> io::Result<PendingRecoveryTrackV1> {
    Ok(PendingRecoveryTrackV1 {
        branch,
        preceding_event_sequence: event.event_sequence,
        preceding_owner: required_owner(event)?.clone(),
        prior_journal: event
            .journal
            .clone()
            .ok_or_else(|| invalid_data("owner exit lacks prior journal evidence"))?,
        prior_ledger: event
            .ledger
            .clone()
            .ok_or_else(|| invalid_data("owner exit lacks prior ledger evidence"))?,
    })
}

fn validate_recovery_path_expectations(expected: &[RecoveryPathExpectationV1]) -> io::Result<()> {
    if expected.is_empty() {
        return Err(invalid_input(
            "trusted recovery path expectations must not be empty",
        ));
    }
    let mut seen = BTreeSet::new();
    for item in expected {
        let paths = [
            &item.prior_journal_path,
            &item.recovered_journal_path,
            &item.prior_ledger_path,
            &item.recovered_ledger_path,
        ];
        if paths.iter().any(|path| !path.is_absolute()) {
            return Err(invalid_input(
                "trusted recovery artifact paths must be absolute",
            ));
        }
        let key = (
            item.branch as u8,
            item.prior_journal_path.clone(),
            item.recovered_journal_path.clone(),
            item.prior_ledger_path.clone(),
            item.recovered_ledger_path.clone(),
        );
        if !seen.insert(key) {
            return Err(invalid_input("duplicate trusted recovery path expectation"));
        }
        let same_artifacts = item.prior_journal_path == item.recovered_journal_path
            && item.prior_ledger_path == item.recovered_ledger_path;
        match item.branch {
            RecoveryBranchV1::ForcedOwnerRestart if same_artifacts => {
                return Err(invalid_input(
                    "forced recovery requires distinct immutable prior and recovered paths",
                ));
            }
            RecoveryBranchV1::GracefulServiceStop if !same_artifacts => {
                return Err(invalid_input(
                    "graceful recovery must retain the same sealed journal and ledger paths",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn verify_recovery_path_expectations(
    actual: &[RecoveryArtifactTrackV1],
    expected: &[RecoveryPathExpectationV1],
) -> io::Result<()> {
    if actual.len() != expected.len() {
        return Err(invalid_data(
            "audit recovery branch count differs from trusted path expectations",
        ));
    }
    for (actual, expected) in actual.iter().zip(expected) {
        if actual.branch != expected.branch
            || actual.prior_journal.path != utf8_path(&expected.prior_journal_path)?
            || actual.recovered_journal.path != utf8_path(&expected.recovered_journal_path)?
            || actual.prior_ledger.path != utf8_path(&expected.prior_ledger_path)?
            || actual.recovered_ledger.path != utf8_path(&expected.recovered_ledger_path)?
        {
            return Err(invalid_data(
                "audit recovery artifacts differ from caller-frozen trusted paths",
            ));
        }
    }
    Ok(())
}

fn read_and_verify_external_scm_lifecycle_evidence(
    path: &Path,
    first: &ScmQualificationAuditEventV1,
    audit: &ScmAuditReceiptBindingV1,
    derived: &DerivedReceiptEvidenceV1,
    final_service_state: &FinalServiceStateV1,
) -> io::Result<(ExternalScmLifecycleEvidenceV1, EvidenceFileBindingV1)> {
    let (bytes, binding) = read_bound_evidence_file(path)?;
    if bytes.is_empty() {
        return Err(invalid_data("external SCM lifecycle evidence is empty"));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(json_error)?;
    if value.get("schema").and_then(serde_json::Value::as_str) != Some(SCM_QUALIFICATION_SCHEMA) {
        return Err(invalid_data(
            "old or unknown external SCM lifecycle evidence schema",
        ));
    }
    let evidence: ExternalScmLifecycleEvidenceV1 =
        serde_json::from_value(value).map_err(json_error)?;
    if serde_json::to_vec(&evidence).map_err(json_error)? != bytes {
        return Err(invalid_data(
            "external SCM lifecycle evidence is not canonical JSON",
        ));
    }
    if evidence.evidence_sha256_hex != external_lifecycle_evidence_hash(&evidence)?
        || evidence.evidence_hash_is_signature_or_attestation
        || !evidence.audit_replay_verified
        || !evidence.external_artifacts_rehashed
    {
        return Err(invalid_data(
            "external SCM lifecycle evidence integrity or verification flags are invalid",
        ));
    }
    let source_shape_valid = match evidence.evidence_source {
        ScmEvidenceSourceV1::WindowsScmApi => {
            evidence.scm_api_readback_verified
                && evidence.service_deployed
                && !evidence.scm_emulated
        }
        ScmEvidenceSourceV1::SyntheticTest => {
            !evidence.scm_api_readback_verified
                && !evidence.service_deployed
                && evidence.scm_emulated
        }
    };
    if !source_shape_valid {
        return Err(invalid_data(
            "external SCM lifecycle source cannot support its deployment status",
        ));
    }
    if evidence.qualification_id_hex != first.qualification_id_hex
        || evidence.evidence_source != first.evidence_source
        || evidence.qualification_supervisor != first.qualification_supervisor
        || evidence.service_supervisor != first.service_supervisor
        || evidence.service_name != first.service_name
        || evidence.service_executable_path != first.service_executable_path
        || evidence.service_executable_sha256_hex != first.service_executable_sha256_hex
        || evidence.service_sid != first.service_sid
        || &evidence.audit != audit
        || evidence.service_configuration_readback != derived.configuration
        || evidence.acl_evidence != derived.acl
        || evidence.owner_instances != derived.owner_instances
        || evidence.state_track != derived.state_track
        || evidence.first_start_requested_at != derived.first_start_requested_at
        || evidence.final_stop_requested_at != derived.final_stop_requested_at
        || evidence.final_service_stopped_at != derived.final_service_stopped_at
        || evidence.restart_observed_count != derived.restart_observed_count
        || evidence.owner_graceful_shutdown_count != derived.owner_graceful_shutdown_count
        || evidence.forced_owner_termination_count != derived.forced_owner_termination_count
        || evidence.recovery_track != derived.recovery_track
        || evidence.journal != derived.journal
        || &evidence.final_service_state != final_service_state
    {
        return Err(invalid_data(
            "external SCM lifecycle evidence differs from the replayed audit",
        ));
    }
    Ok((evidence, binding))
}

fn external_lifecycle_evidence_hash(
    evidence: &ExternalScmLifecycleEvidenceV1,
) -> io::Result<String> {
    let mut normalized = evidence.clone();
    normalized.evidence_sha256_hex.clear();
    Ok(hex(&sha256(
        &serde_json::to_vec(&normalized).map_err(json_error)?,
    )))
}

fn rehash_all_audited_external_files(events: &[ScmQualificationAuditEventV1]) -> io::Result<()> {
    let first = events
        .first()
        .ok_or_else(|| invalid_data("audit contains no event"))?;
    let executable_binding = bind_file(Path::new(&first.service_executable_path))?;
    if executable_binding.sha256_hex != first.service_executable_sha256_hex {
        return Err(invalid_data(
            "audited service executable no longer matches its hash",
        ));
    }
    let mut expected = BTreeMap::new();
    for event in events {
        if let Some(journal) = &event.journal {
            insert_expected_file(
                &mut expected,
                &journal.path,
                &journal.sha256_hex,
                &journal.file_identity,
            )?;
        }
        if let Some(ledger) = &event.ledger {
            insert_expected_file(
                &mut expected,
                &ledger.path,
                &ledger.sha256_hex,
                &ledger.file_identity,
            )?;
        }
    }
    let _locks = lock_expected_files(&expected)?;
    Ok(())
}

fn lock_and_verify_event_evidence(event: &ScmQualificationAuditEventV1) -> io::Result<Vec<File>> {
    let mut expected = BTreeMap::new();
    if let Some(journal) = &event.journal {
        insert_expected_file(
            &mut expected,
            &journal.path,
            &journal.sha256_hex,
            &journal.file_identity,
        )?;
    }
    if let Some(ledger) = &event.ledger {
        insert_expected_file(
            &mut expected,
            &ledger.path,
            &ledger.sha256_hex,
            &ledger.file_identity,
        )?;
    }
    lock_expected_files(&expected)
}

fn insert_expected_file(
    files: &mut BTreeMap<String, (String, EvidenceFileIdentityV1)>,
    path: &str,
    sha256_hex: &str,
    identity: &EvidenceFileIdentityV1,
) -> io::Result<()> {
    let value = (sha256_hex.to_owned(), identity.clone());
    if files.get(path).is_some_and(|prior| prior != &value) {
        return Err(invalid_data(
            "one evidence path was bound to conflicting hash or file identity values",
        ));
    }
    files.insert(path.to_owned(), value);
    Ok(())
}

fn lock_expected_files(
    expected: &BTreeMap<String, (String, EvidenceFileIdentityV1)>,
) -> io::Result<Vec<File>> {
    let mut locks = Vec::with_capacity(expected.len());
    for (path, (sha256_hex, identity)) in expected {
        let mut file = open_evidence_file(Path::new(path))?;
        let actual = bind_open_evidence_file(Path::new(path), &mut file)?;
        if actual.sha256_hex != *sha256_hex || actual.file_identity != *identity {
            return Err(invalid_data(
                "evidence pathname now resolves to different content or filesystem identity",
            ));
        }
        locks.push(file);
    }
    Ok(locks)
}

fn lock_all_receipted_evidence(receipt: &ScmQualificationReceiptV1) -> io::Result<Vec<File>> {
    let audit_path = Path::new(&receipt.audit.path);
    let mut audit_lock = open_evidence_file(audit_path)?;
    let audit_binding = bind_open_evidence_file(audit_path, &mut audit_lock)?;
    if audit_binding.path != receipt.audit.path
        || audit_binding.sha256_hex != receipt.audit.sha256_hex
        || audit_binding.bytes != receipt.audit.bytes
        || audit_binding.file_identity != receipt.audit.file_identity
    {
        return Err(invalid_data(
            "audit path/content/filesystem identity changed before final snapshot",
        ));
    }
    let loaded = load_and_replay_audit(audit_path, None)?;
    let mut expected = BTreeMap::new();
    insert_expected_file(
        &mut expected,
        &receipt.retained_binary.path,
        &receipt.retained_binary.sha256_hex,
        &receipt.retained_binary.file_identity,
    )?;
    insert_expected_file(
        &mut expected,
        &receipt.scm_lifecycle_evidence.path,
        &receipt.scm_lifecycle_evidence.sha256_hex,
        &receipt.scm_lifecycle_evidence.file_identity,
    )?;
    insert_expected_file(
        &mut expected,
        &receipt.journal.path,
        &receipt.journal.sha256_hex,
        &receipt.journal.file_identity,
    )?;
    insert_expected_file(
        &mut expected,
        &receipt.journal.ledger_path,
        &receipt.journal.ledger_sha256_hex,
        &receipt.journal.ledger_file_identity,
    )?;
    for event in &loaded.events {
        if let Some(journal) = &event.journal {
            insert_expected_file(
                &mut expected,
                &journal.path,
                &journal.sha256_hex,
                &journal.file_identity,
            )?;
        }
        if let Some(ledger) = &event.ledger {
            insert_expected_file(
                &mut expected,
                &ledger.path,
                &ledger.sha256_hex,
                &ledger.file_identity,
            )?;
        }
    }
    let mut locks = Vec::with_capacity(expected.len() + 1);
    locks.push(audit_lock);
    locks.extend(lock_expected_files(&expected)?);
    Ok(locks)
}

fn current_instance_mut(
    current: &mut Option<InstanceBuilderV1>,
) -> io::Result<&mut InstanceBuilderV1> {
    current
        .as_mut()
        .ok_or_else(|| invalid_data("event lacks a current service instance"))
}

fn exactly_one<T>(
    events: &[ScmQualificationAuditEventV1],
    mut select: impl FnMut(&ScmQualificationAuditEventV1) -> Option<T>,
) -> io::Result<T> {
    let mut found = None;
    for event in events {
        if let Some(value) = select(event) {
            if found.is_some() {
                return Err(invalid_data("audit contains duplicate singleton evidence"));
            }
            found = Some(value);
        }
    }
    found.ok_or_else(|| invalid_data("audit lacks required singleton evidence"))
}

fn qualification_passes(
    service_deployed: bool,
    scm_emulated: bool,
    hardware_qualified: bool,
    nwb_qualified: bool,
    open_gates: &[String],
    derived: &DerivedReceiptEvidenceV1,
    final_state: &FinalServiceStateV1,
) -> bool {
    let allowed_open_gates: BTreeSet<&str> = [
        (!hardware_qualified).then_some(HARDWARE_OPEN_GATE),
        (!nwb_qualified).then_some(NWB_OPEN_GATE),
    ]
    .into_iter()
    .flatten()
    .collect();
    service_deployed
        && !scm_emulated
        && !derived.configuration.service_account_name.trim().is_empty()
        && derived.configuration.start_type != ScmStartTypeV1::Disabled
        && derived.configuration.service_sid_type != ScmServiceSidTypeV1::None
        && is_nonzero_hex_len(&derived.configuration.failure_actions_sha256_hex, 64)
        && derived.configuration.failure_actions_on_non_crash_failures
        && derived.acl.service_sid_verified
        && derived.acl.token_user_sid_verified
        && is_nonzero_hex_len(&derived.acl.pipe_dacl_sha256_hex, 64)
        && is_nonzero_hex_len(&derived.acl.service_object_dacl_sha256_hex, 64)
        && is_nonzero_hex_len(&derived.acl.data_root_dacl_sha256_hex, 64)
        && derived.journal.sealed
        && derived.journal.recovery_verified
        && valid_file_identity(&derived.journal.file_identity)
        && valid_file_identity(&derived.journal.ledger_file_identity)
        && !derived.recovery_track.is_empty()
        && !derived.owner_instances.is_empty()
        && final_state
            == &FinalServiceStateV1 {
                installed: false,
                running: false,
                stopped: true,
                uninstalled: true,
            }
        && open_gates
            .iter()
            .all(|gate| allowed_open_gates.contains(gate.as_str()))
}

fn normalize_open_gates(
    gates: Vec<String>,
    real_scm_qualified: bool,
    hardware_qualified: bool,
    nwb_qualified: bool,
) -> io::Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for gate in gates {
        if gate.trim().is_empty() || gate != gate.trim() || !normalized.insert(gate) {
            return Err(invalid_input(
                "open gates must be unique, nonempty canonical strings",
            ));
        }
    }
    if real_scm_qualified {
        normalized.remove(REAL_SCM_OPEN_GATE);
    } else {
        normalized.insert(REAL_SCM_OPEN_GATE.to_owned());
    }
    if hardware_qualified {
        normalized.remove(HARDWARE_OPEN_GATE);
    } else {
        normalized.insert(HARDWARE_OPEN_GATE.to_owned());
    }
    if nwb_qualified {
        normalized.remove(NWB_OPEN_GATE);
    } else {
        normalized.insert(NWB_OPEN_GATE.to_owned());
    }
    Ok(normalized.into_iter().collect())
}

fn validate_receipt_fixed_semantics(receipt: &ScmQualificationReceiptV1) -> io::Result<()> {
    validate_process_identity(&receipt.qualification_supervisor)?;
    validate_process_identity(&receipt.service_supervisor)?;
    validate_evidence_file_binding(&receipt.retained_binary)?;
    validate_evidence_file_binding(&receipt.scm_lifecycle_evidence)?;
    let real_scm = receipt.evidence_source == ScmEvidenceSourceV1::WindowsScmApi;
    if receipt.schema != SCM_QUALIFICATION_SCHEMA
        || receipt.evidence_hash_is_signature_or_attestation
        || !is_nonzero_hex_len(&receipt.evidence_sha256_hex, 64)
        || !is_nonzero_hex_len(&receipt.qualification_id_hex, 32)
        || !is_service_sid(&receipt.service_sid)
        || receipt.service_name.trim().is_empty()
        || !Path::new(&receipt.audit.path).is_absolute()
        || !is_nonzero_hex_len(&receipt.audit.sha256_hex, 64)
        || receipt.audit.bytes == 0
        || receipt.audit.bytes != receipt.audit.file_identity.bytes
        || !valid_file_identity(&receipt.audit.file_identity)
        || receipt.audit.event_count == 0
        || !is_nonzero_hex_len(&receipt.audit.first_event_hash_hex, 64)
        || !is_nonzero_hex_len(&receipt.audit.last_event_hash_hex, 64)
        || receipt.retained_binary.path != receipt.service_executable_path
        || receipt.retained_binary.sha256_hex != receipt.service_executable_sha256_hex
        || !Path::new(&receipt.journal.path).is_absolute()
        || !is_nonzero_hex_len(&receipt.journal.sha256_hex, 64)
        || !Path::new(&receipt.journal.ledger_path).is_absolute()
        || !is_nonzero_hex_len(&receipt.journal.ledger_sha256_hex, 64)
        || receipt.owner_instances.is_empty()
        || receipt.state_track.is_empty()
        || !receipt.final_service_state.uninstalled
        || receipt.final_service_state.installed
        || receipt.final_service_state.running
        || !receipt.final_service_state.stopped
        || receipt.service_deployed != real_scm
        || receipt.scm_emulated == real_scm
        || receipt.hardware_qualified
        || receipt.nwb_qualified
        || !receipt.journal.sealed
        || !receipt.journal.recovery_verified
        || !valid_file_identity(&receipt.journal.file_identity)
        || !valid_file_identity(&receipt.journal.ledger_file_identity)
        || receipt.restart_observed_count as usize + 1 != receipt.owner_instances.len()
        || receipt.owner_graceful_shutdown_count == 0
        || receipt.qualification_supervisor == receipt.service_supervisor
    {
        return Err(invalid_data(
            "SCM qualification receipt fixed semantics are invalid",
        ));
    }
    let mut instance_ids = BTreeSet::new();
    let mut counted_graceful = 0_u32;
    let mut counted_forced = 0_u32;
    for (index, instance) in receipt.owner_instances.iter().enumerate() {
        validate_process_identity(&instance.owner_process)?;
        match instance.stop_method {
            OwnerStopMethodV1::Graceful => counted_graceful += 1,
            OwnerStopMethodV1::Forced => counted_forced += 1,
        }
        if instance.instance_index != index as u32
            || !instance_ids.insert((
                instance.owner_process.pid,
                instance.owner_process.creation_time_100ns,
            ))
            || instance.owner_process == receipt.qualification_supervisor
            || instance.owner_process == receipt.service_supervisor
            || (instance.stop_method == OwnerStopMethodV1::Graceful
                && instance.stop_requested_at.is_none())
            || (instance.stop_method == OwnerStopMethodV1::Forced
                && instance.stop_requested_at.is_some())
            || (instance.successor_restart_observed_at.is_some()
                != (index + 1 < receipt.owner_instances.len()))
            || instance.owner_started_at.monotonic_time_ns
                > instance.owner_ready_at.monotonic_time_ns
            || instance.owner_ready_at.monotonic_time_ns
                > instance.owner_exit_observed_at.monotonic_time_ns
            || instance.owner_exit_observed_at != instance.owner_stopped_at
            || instance
                .successor_restart_observed_at
                .as_ref()
                .is_some_and(|time| {
                    time.monotonic_time_ns <= instance.owner_stopped_at.monotonic_time_ns
                })
        {
            return Err(invalid_data("receipt service instance timeline is invalid"));
        }
    }
    if counted_graceful != receipt.owner_graceful_shutdown_count
        || counted_forced != receipt.forced_owner_termination_count
        || receipt
            .owner_instances
            .last()
            .is_none_or(|instance| instance.stop_method != OwnerStopMethodV1::Graceful)
        || receipt.final_service_stopped_at.monotonic_time_ns
            <= receipt
                .owner_instances
                .last()
                .map(|instance| instance.owner_stopped_at.monotonic_time_ns)
                .unwrap_or(u64::MAX)
    {
        return Err(invalid_data(
            "receipt owner counts or final graceful service stop is inconsistent",
        ));
    }
    if receipt.recovery_track.len() != receipt.owner_instances.len() {
        return Err(invalid_data(
            "receipt recovery track does not cover every owner exit",
        ));
    }
    let mut recovery_forced = 0_u32;
    let mut recovery_graceful = 0_u32;
    let mut prior_recovery_sequence = None;
    for recovery in &receipt.recovery_track {
        validate_process_identity(&recovery.preceding_owner)?;
        validate_process_identity(&recovery.recovered_owner)?;
        validate_journal_evidence(&recovery.prior_journal)?;
        validate_journal_evidence(&recovery.recovered_journal)?;
        validate_ledger_evidence(&recovery.prior_ledger)?;
        validate_ledger_evidence(&recovery.recovered_ledger)?;
        if recovery.preceding_event_sequence >= recovery.recovery_event_sequence
            || prior_recovery_sequence
                .is_some_and(|prior| prior >= recovery.preceding_event_sequence)
        {
            return Err(invalid_data("receipt recovery sequence track is invalid"));
        }
        prior_recovery_sequence = Some(recovery.recovery_event_sequence);
        match recovery.branch {
            RecoveryBranchV1::ForcedOwnerRestart => {
                recovery_forced += 1;
                if recovery.preceding_owner == recovery.recovered_owner
                    || recovery.prior_journal.path == recovery.recovered_journal.path
                    || recovery.prior_journal.file_identity
                        == recovery.recovered_journal.file_identity
                    || recovery.prior_ledger.path == recovery.recovered_ledger.path
                    || recovery.prior_ledger.file_identity
                        == recovery.recovered_ledger.file_identity
                {
                    return Err(invalid_data(
                        "forced recovery lacks distinct owner and immutable artifact snapshots",
                    ));
                }
            }
            RecoveryBranchV1::GracefulServiceStop => {
                recovery_graceful += 1;
                if recovery.preceding_owner != recovery.recovered_owner
                    || recovery.prior_journal.path != recovery.recovered_journal.path
                    || recovery.prior_journal.file_identity
                        != recovery.recovered_journal.file_identity
                    || recovery.prior_journal.sha256_hex != recovery.recovered_journal.sha256_hex
                    || recovery.prior_ledger.path != recovery.recovered_ledger.path
                    || recovery.prior_ledger.file_identity
                        != recovery.recovered_ledger.file_identity
                    || recovery.prior_ledger.sha256_hex != recovery.recovered_ledger.sha256_hex
                {
                    return Err(invalid_data(
                        "graceful recovery changed its sealed artifact identity",
                    ));
                }
            }
        }
    }
    let last_recovery = receipt
        .recovery_track
        .last()
        .ok_or_else(|| invalid_data("receipt recovery track is empty"))?;
    if recovery_forced != receipt.forced_owner_termination_count
        || recovery_graceful != receipt.owner_graceful_shutdown_count
        || last_recovery.recovered_journal.path != receipt.journal.path
        || last_recovery.recovered_journal.sha256_hex != receipt.journal.sha256_hex
        || last_recovery.recovered_journal.file_identity != receipt.journal.file_identity
        || last_recovery.recovered_ledger.path != receipt.journal.ledger_path
        || last_recovery.recovered_ledger.sha256_hex != receipt.journal.ledger_sha256_hex
        || last_recovery.recovered_ledger.file_identity != receipt.journal.ledger_file_identity
    {
        return Err(invalid_data(
            "receipt recovery branch counts or final artifact snapshot are inconsistent",
        ));
    }
    let expected_gates = normalize_open_gates(
        receipt.open_gates.clone(),
        receipt.service_deployed && !receipt.scm_emulated,
        receipt.hardware_qualified,
        receipt.nwb_qualified,
    )?;
    if expected_gates != receipt.open_gates {
        return Err(invalid_data("receipt open gates are not canonical"));
    }
    let dummy = DerivedReceiptEvidenceV1 {
        configuration: receipt.service_configuration_readback.clone(),
        acl: receipt.acl_evidence.clone(),
        owner_instances: receipt.owner_instances.clone(),
        state_track: receipt.state_track.clone(),
        first_start_requested_at: receipt.first_start_requested_at.clone(),
        final_stop_requested_at: receipt.final_stop_requested_at.clone(),
        final_service_stopped_at: receipt.final_service_stopped_at.clone(),
        restart_observed_count: receipt.restart_observed_count,
        owner_graceful_shutdown_count: receipt.owner_graceful_shutdown_count,
        forced_owner_termination_count: receipt.forced_owner_termination_count,
        recovery_track: receipt.recovery_track.clone(),
        journal: receipt.journal.clone(),
    };
    let expected_passed = qualification_passes(
        receipt.service_deployed,
        receipt.scm_emulated,
        receipt.hardware_qualified,
        receipt.nwb_qualified,
        &receipt.open_gates,
        &dummy,
        &receipt.final_service_state,
    );
    if receipt.passed != expected_passed
        || (receipt.passed && (!receipt.service_deployed || receipt.scm_emulated))
    {
        return Err(invalid_data(
            "receipt passed result was forged or is inconsistent",
        ));
    }
    Ok(())
}

fn validate_evidence_file_binding(value: &EvidenceFileBindingV1) -> io::Result<()> {
    if !Path::new(&value.path).is_absolute()
        || !is_nonzero_hex_len(&value.sha256_hex, 64)
        || value.bytes == 0
        || value.bytes != value.file_identity.bytes
        || !valid_file_identity(&value.file_identity)
    {
        return Err(invalid_data("receipt evidence file binding is malformed"));
    }
    Ok(())
}

fn validate_expectation(expected: &ScmQualificationVerificationExpectationV1) -> io::Result<()> {
    validate_process_identity(&expected.qualification_supervisor)?;
    validate_process_identity(&expected.service_supervisor)?;
    if !is_nonzero_hex_len(&expected.qualification_id_hex, 32)
        || expected.service_name.trim().is_empty()
        || !is_service_sid(&expected.service_sid)
        || [
            &expected.audit_path,
            &expected.scm_lifecycle_evidence_path,
            &expected.retained_binary_path,
            &expected.journal_path,
            &expected.ledger_path,
        ]
        .iter()
        .any(|path| !path.is_absolute())
        || expected.qualification_supervisor == expected.service_supervisor
    {
        return Err(invalid_input(
            "trusted SCM verification expectation is malformed",
        ));
    }
    validate_recovery_path_expectations(&expected.recovery_paths)?;
    Ok(())
}

fn receipt_evidence_hash(receipt: &ScmQualificationReceiptV1) -> io::Result<String> {
    let mut normalized = receipt.clone();
    normalized.evidence_sha256_hex.clear();
    Ok(hex(&sha256(
        &serde_json::to_vec(&normalized).map_err(json_error)?,
    )))
}

fn bind_file(path: &Path) -> io::Result<EvidenceFileBindingV1> {
    let mut file = open_evidence_file(path)?;
    bind_open_evidence_file(path, &mut file)
}

fn bind_open_evidence_file(path: &Path, file: &mut File) -> io::Result<EvidenceFileBindingV1> {
    file.seek(SeekFrom::Start(0))?;
    let before = evidence_file_identity(file)?;
    let sha256_hex = sha256_reader(file)?;
    let after = evidence_file_identity(file)?;
    if before != after {
        return Err(invalid_data(
            "evidence file identity or size changed while it was hashed",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(EvidenceFileBindingV1 {
        path: utf8_path(path)?.to_owned(),
        sha256_hex,
        bytes: after.bytes,
        file_identity: after,
    })
}

fn event_time(event: &ScmQualificationAuditEventV1) -> EvidenceTimeV1 {
    EvidenceTimeV1 {
        wall_time_unix_ns: event.wall_time_unix_ns,
        monotonic_time_ns: event.monotonic_time_ns,
    }
}

#[cfg(windows)]
fn rename_no_overwrite(pending: &Path, final_path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let source: Vec<u16> = pending
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination: Vec<u16> = final_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // WRITE_THROUGH makes the rename durable while intentionally omitting
    // MOVEFILE_REPLACE_EXISTING, preserving atomic no-overwrite publication.
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
    // The format is Windows-only, but keeping tests portable must not weaken
    // no-overwrite semantics on platforms where rename replaces destinations.
    std::fs::hard_link(pending, final_path)?;
    // Once the no-replace link exists, publication succeeded.  Failure to
    // remove the private pending name must not turn that success into an error.
    let _ = std::fs::remove_file(pending);
    Ok(())
}

fn sha256_file(path: &Path) -> io::Result<String> {
    Ok(bind_file(path)?.sha256_hex)
}

fn sha256_reader(file: &mut File) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

fn read_bound_evidence_file(path: &Path) -> io::Result<(Vec<u8>, EvidenceFileBindingV1)> {
    let mut file = open_evidence_file(path)?;
    read_bound_open_evidence_file(path, &mut file)
}

fn read_bound_open_evidence_file(
    path: &Path,
    file: &mut File,
) -> io::Result<(Vec<u8>, EvidenceFileBindingV1)> {
    file.seek(SeekFrom::Start(0))?;
    let before = evidence_file_identity(file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let after = evidence_file_identity(file)?;
    if before != after || bytes.len() as u64 != after.bytes {
        return Err(invalid_data(
            "evidence file changed while its final snapshot was read",
        ));
    }
    let sha256_hex = hex(&sha256(&bytes));
    Ok((
        bytes,
        EvidenceFileBindingV1 {
            path: utf8_path(path)?.to_owned(),
            sha256_hex,
            bytes: after.bytes,
            file_identity: after,
        },
    ))
}

#[cfg(windows)]
fn evidence_file_identity(file: &File) -> io::Result<EvidenceFileIdentityV1> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let identity = EvidenceFileIdentityV1 {
        volume_serial_number: u64::from(information.dwVolumeSerialNumber),
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        bytes: (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow),
    };
    if !valid_file_identity(&identity) {
        return Err(invalid_data(
            "evidence handle has an invalid filesystem identity",
        ));
    }
    Ok(identity)
}

#[cfg(unix)]
fn evidence_file_identity(file: &File) -> io::Result<EvidenceFileIdentityV1> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    let identity = EvidenceFileIdentityV1 {
        volume_serial_number: metadata.dev(),
        file_index: metadata.ino(),
        bytes: metadata.len(),
    };
    if !valid_file_identity(&identity) {
        return Err(invalid_data(
            "evidence handle has an invalid filesystem identity",
        ));
    }
    Ok(identity)
}

#[cfg(not(any(windows, unix)))]
fn evidence_file_identity(_file: &File) -> io::Result<EvidenceFileIdentityV1> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable evidence file identity is unsupported on this platform",
    ))
}

#[cfg(windows)]
fn open_evidence_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    // Refuse to hash evidence while another handle can write or delete it.
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

#[cfg(not(windows))]
fn open_evidence_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn is_service_sid(value: &str) -> bool {
    let fields: Vec<&str> = value.split('-').collect();
    fields.len() == 9
        && fields[..4] == ["S", "1", "5", "80"]
        && fields[4..].iter().all(|field| {
            !field.is_empty()
                && (field.len() == 1 || !field.starts_with('0'))
                && field.bytes().all(|byte| byte.is_ascii_digit())
                && field.parse::<u32>().is_ok()
        })
}

fn is_hex_len(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_nonzero_hex_len(value: &str, len: usize) -> bool {
    is_hex_len(value, len) && value.bytes().any(|byte| byte != b'0')
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn utf8_path(path: &Path) -> io::Result<&str> {
    path.to_str()
        .ok_or_else(|| invalid_input("evidence path is not UTF-8"))
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
    use std::cell::Cell;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        executable: PathBuf,
        crash_journal: PathBuf,
        crash_ledger: PathBuf,
        journal: PathBuf,
        ledger: PathBuf,
        audit: PathBuf,
        lifecycle: PathBuf,
        receipt: PathBuf,
        context: ScmQualificationContextV1,
        forced_restart: Cell<Option<bool>>,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let serial = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "forge-scm-qualification-{label}-{}-{stamp}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            let executable = root.join("retained-forge-acqd.exe");
            let crash_journal = root.join("run.crash-snapshot.forge-journal");
            let crash_ledger = root.join("run-ledger.crash-snapshot.jsonl");
            let journal = root.join("run.forge-journal");
            let ledger = root.join("run-ledger.jsonl");
            let audit = root.join("scm-audit.jsonl");
            let lifecycle = root.join("scm-lifecycle-evidence.json");
            let receipt = root.join("scm-receipt.json");
            durable_test_file(&executable, b"retained test service binary\n");
            durable_test_file(
                &crash_journal,
                b"synthetic crash journal snapshot evidence\n",
            );
            durable_test_file(&crash_ledger, b"synthetic crash ledger snapshot evidence\n");
            durable_test_file(&journal, b"synthetic durable sealed journal evidence\n");
            durable_test_file(&ledger, b"synthetic sealed ledger evidence\n");
            let context = ScmQualificationContextV1 {
                qualification_id_hex: "11".repeat(16),
                service_name: "ForgeAcqdQualificationV2".to_owned(),
                service_executable_path: utf8_path(&executable).unwrap().to_owned(),
                service_executable_sha256_hex: sha256_file(&executable).unwrap(),
                service_sid: "S-1-5-80-1-2-3-4-5".to_owned(),
                qualification_supervisor: current_process_identity().unwrap(),
                service_supervisor: ProcessIdentityV1 {
                    pid: 151,
                    creation_time_100ns: 1_500_001,
                },
                evidence_source: ScmEvidenceSourceV1::SyntheticTest,
            };
            Self {
                root,
                executable,
                crash_journal,
                crash_ledger,
                journal,
                ledger,
                audit,
                lifecycle,
                receipt,
                context,
                forced_restart: Cell::new(None),
            }
        }

        fn recovery_paths(&self) -> Vec<RecoveryPathExpectationV1> {
            let mut paths = Vec::new();
            if self.forced_restart.get() == Some(true) {
                paths.push(RecoveryPathExpectationV1 {
                    branch: RecoveryBranchV1::ForcedOwnerRestart,
                    prior_journal_path: self.crash_journal.clone(),
                    recovered_journal_path: self.journal.clone(),
                    prior_ledger_path: self.crash_ledger.clone(),
                    recovered_ledger_path: self.ledger.clone(),
                });
            }
            paths.push(RecoveryPathExpectationV1 {
                branch: RecoveryBranchV1::GracefulServiceStop,
                prior_journal_path: self.journal.clone(),
                recovered_journal_path: self.journal.clone(),
                prior_ledger_path: self.ledger.clone(),
                recovered_ledger_path: self.ledger.clone(),
            });
            paths
        }

        fn expectation(&self) -> ScmQualificationVerificationExpectationV1 {
            ScmQualificationVerificationExpectationV1 {
                qualification_id_hex: self.context.qualification_id_hex.clone(),
                service_name: self.context.service_name.clone(),
                service_sid: self.context.service_sid.clone(),
                qualification_supervisor: self.context.qualification_supervisor.clone(),
                service_supervisor: self.context.service_supervisor.clone(),
                evidence_source: self.context.evidence_source,
                audit_path: self.audit.clone(),
                scm_lifecycle_evidence_path: self.lifecycle.clone(),
                retained_binary_path: self.executable.clone(),
                journal_path: self.journal.clone(),
                ledger_path: self.ledger.clone(),
                recovery_paths: self.recovery_paths(),
            }
        }

        fn build_audit(&self, forced_restart: bool) -> ScmAuditEvidenceV1 {
            assert_eq!(self.forced_restart.replace(Some(forced_restart)), None);
            let mut writer =
                ScmQualificationAuditWriterV1::create_new(&self.audit, self.context.clone())
                    .unwrap();
            let mut clock = TestClock::default();
            let owner_a = ProcessIdentityV1 {
                pid: 201,
                creation_time_100ns: 2_000_001,
            };
            let owner_b = ProcessIdentityV1 {
                pid: 202,
                creation_time_100ns: 2_000_002,
            };
            append_prefix(self, &mut writer, &mut clock, &owner_a);
            let final_owner = if forced_restart {
                let mut forced = clock.event(
                    ScmQualificationEventKindV1::ForcedOwnerTermination,
                    running(),
                );
                forced.owner_process = Some(owner_a.clone());
                forced.win32_exit_code = Some(1_067);
                forced.service_exit_code = Some(0);
                forced.journal = Some(self.journal_snapshot_at(&self.crash_journal, false, false));
                forced.ledger = Some(self.ledger_snapshot_at(&self.crash_ledger, "recording"));
                writer.append(forced).unwrap();

                let mut restart =
                    clock.event(ScmQualificationEventKindV1::RestartObserved, running());
                restart.owner_process = Some(owner_b.clone());
                writer.append(restart).unwrap();

                let mut recovery = clock.event(
                    ScmQualificationEventKindV1::JournalRecoveryVerified,
                    running(),
                );
                recovery.owner_process = Some(owner_b.clone());
                recovery.journal = Some(self.journal_snapshot_at(&self.journal, true, true));
                recovery.ledger = Some(self.ledger_snapshot_at(&self.ledger, "journal_recovered"));
                writer.append(recovery).unwrap();

                let mut owner_ready =
                    clock.event(ScmQualificationEventKindV1::OwnerReady, running());
                owner_ready.owner_process = Some(owner_b.clone());
                owner_ready.pipe_dacl_sha256_hex = Some("55".repeat(32));
                writer.append(owner_ready).unwrap();
                owner_b
            } else {
                owner_a
            };
            append_graceful_tail(self, &mut writer, &mut clock, &final_owner);
            writer.finish().unwrap()
        }

        fn journal_snapshot_at(
            &self,
            path: &Path,
            sealed: bool,
            recovered: bool,
        ) -> JournalEvidenceSnapshotV1 {
            let binding = bind_file(path).unwrap();
            JournalEvidenceSnapshotV1 {
                path: binding.path,
                sha256_hex: binding.sha256_hex,
                file_identity: binding.file_identity,
                durable_record_count: 1,
                durable_valid_len: 16,
                last_journal_sequence: Some(0),
                seal_expected_last_journal_sequence: sealed.then_some(0),
                sealed,
                recovery_verified: recovered,
            }
        }

        fn ledger_snapshot_at(&self, path: &Path, state: &str) -> LedgerEvidenceSnapshotV1 {
            let binding = bind_file(path).unwrap();
            LedgerEvidenceSnapshotV1 {
                path: binding.path,
                sha256_hex: binding.sha256_hex,
                file_identity: binding.file_identity,
                state: state.to_owned(),
            }
        }

        fn ensure_synthetic_lifecycle_evidence(&self) {
            if self.lifecycle.exists() {
                return;
            }
            let loaded = load_and_replay_audit(&self.audit, None).unwrap();
            let first = loaded.events.first().unwrap();
            let derived = derive_receipt_evidence(&loaded.events).unwrap();
            let mut evidence = ExternalScmLifecycleEvidenceV1 {
                schema: SCM_QUALIFICATION_SCHEMA.to_owned(),
                qualification_id_hex: first.qualification_id_hex.clone(),
                evidence_source: ScmEvidenceSourceV1::SyntheticTest,
                qualification_supervisor: first.qualification_supervisor.clone(),
                service_supervisor: first.service_supervisor.clone(),
                service_name: first.service_name.clone(),
                service_executable_path: first.service_executable_path.clone(),
                service_executable_sha256_hex: first.service_executable_sha256_hex.clone(),
                service_sid: first.service_sid.clone(),
                audit: ScmAuditReceiptBindingV1 {
                    path: loaded.evidence.path,
                    sha256_hex: loaded.evidence.sha256_hex,
                    bytes: loaded.evidence.bytes,
                    file_identity: loaded.evidence.file_identity,
                    event_count: loaded.evidence.event_count,
                    first_event_hash_hex: loaded.evidence.first_event_hash_hex,
                    last_event_hash_hex: loaded.evidence.last_event_hash_hex,
                },
                service_configuration_readback: derived.configuration,
                acl_evidence: derived.acl,
                owner_instances: derived.owner_instances,
                state_track: derived.state_track,
                first_start_requested_at: derived.first_start_requested_at,
                final_stop_requested_at: derived.final_stop_requested_at,
                final_service_stopped_at: derived.final_service_stopped_at,
                restart_observed_count: derived.restart_observed_count,
                owner_graceful_shutdown_count: derived.owner_graceful_shutdown_count,
                forced_owner_termination_count: derived.forced_owner_termination_count,
                recovery_track: derived.recovery_track,
                journal: derived.journal,
                final_service_state: FinalServiceStateV1 {
                    installed: false,
                    running: false,
                    stopped: true,
                    uninstalled: true,
                },
                scm_api_readback_verified: false,
                audit_replay_verified: true,
                external_artifacts_rehashed: true,
                service_deployed: false,
                scm_emulated: true,
                evidence_sha256_hex: String::new(),
                evidence_hash_is_signature_or_attestation: false,
            };
            evidence.evidence_sha256_hex = external_lifecycle_evidence_hash(&evidence).unwrap();
            durable_test_file(&self.lifecycle, &serde_json::to_vec(&evidence).unwrap());
        }

        fn build_receipt(&self) -> ScmQualificationReceiptV1 {
            self.ensure_synthetic_lifecycle_evidence();
            build_scm_qualification_receipt_v1(
                &self.audit,
                &self.executable,
                ScmQualificationReceiptOptionsV1 {
                    open_gates: Vec::new(),
                    scm_lifecycle_evidence_path: self.lifecycle.clone(),
                    recovery_paths: self.recovery_paths(),
                },
            )
            .unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Default)]
    struct TestClock {
        tick: u64,
    }

    impl TestClock {
        fn event(
            &mut self,
            kind: ScmQualificationEventKindV1,
            scm: ScmStatusSnapshotV1,
        ) -> ScmQualificationEventDataV1 {
            self.tick += 1;
            ScmQualificationEventDataV1::bare(
                kind,
                scm,
                1_800_000_000_000_000_000 + self.tick,
                10_000 + self.tick,
            )
        }
    }

    fn append_prefix(
        fixture: &Fixture,
        writer: &mut ScmQualificationAuditWriterV1,
        clock: &mut TestClock,
        owner: &ProcessIdentityV1,
    ) {
        for kind in [
            ScmQualificationEventKindV1::Preflight,
            ScmQualificationEventKindV1::ArtifactRetained,
            ScmQualificationEventKindV1::InstallRequested,
        ] {
            writer.append(clock.event(kind, absent())).unwrap();
        }
        let mut install = clock.event(ScmQualificationEventKindV1::InstallReadback, stopped());
        install.win32_exit_code = Some(0);
        install.service_exit_code = Some(0);
        install.service_configuration = Some(ServiceConfigurationReadbackV1 {
            service_account_name: r"NT SERVICE\ForgeAcqdQualificationV2".to_owned(),
            binary_path: fixture.context.service_executable_path.clone(),
            start_type: ScmStartTypeV1::Automatic,
            error_control: ScmErrorControlV1::Normal,
            service_sid_type: ScmServiceSidTypeV1::Unrestricted,
            failure_actions_sha256_hex: "44".repeat(32),
            failure_actions_on_non_crash_failures: true,
        });
        writer.append(install).unwrap();

        let mut sid = clock.event(ScmQualificationEventKindV1::ServiceSidVerified, stopped());
        sid.token_user_sid_verified = Some(true);
        writer.append(sid).unwrap();

        let mut service_dacl = clock.event(
            ScmQualificationEventKindV1::ServiceObjectDaclVerified,
            stopped(),
        );
        service_dacl.service_object_dacl_sha256_hex = Some("66".repeat(32));
        writer.append(service_dacl).unwrap();

        let mut data_dacl =
            clock.event(ScmQualificationEventKindV1::DataRootDaclVerified, stopped());
        data_dacl.data_root_dacl_sha256_hex = Some("77".repeat(32));
        writer.append(data_dacl).unwrap();
        writer
            .append(clock.event(ScmQualificationEventKindV1::StartRequested, stopped()))
            .unwrap();
        writer
            .append(clock.event(ScmQualificationEventKindV1::StartPending, start_pending()))
            .unwrap();
        let mut running_event = clock.event(ScmQualificationEventKindV1::Running, running());
        running_event.owner_process = Some(owner.clone());
        running_event.win32_exit_code = Some(0);
        running_event.service_exit_code = Some(0);
        writer.append(running_event).unwrap();
        let mut ready = clock.event(ScmQualificationEventKindV1::OwnerReady, running());
        ready.owner_process = Some(owner.clone());
        ready.pipe_dacl_sha256_hex = Some("55".repeat(32));
        writer.append(ready).unwrap();
    }

    fn append_graceful_tail(
        fixture: &Fixture,
        writer: &mut ScmQualificationAuditWriterV1,
        clock: &mut TestClock,
        owner: &ProcessIdentityV1,
    ) {
        let mut stop = clock.event(ScmQualificationEventKindV1::StopRequested, running());
        stop.owner_process = Some(owner.clone());
        writer.append(stop).unwrap();

        let mut pending = clock.event(ScmQualificationEventKindV1::StopPending, stop_pending());
        pending.owner_process = Some(owner.clone());
        writer.append(pending).unwrap();

        let mut graceful = clock.event(
            ScmQualificationEventKindV1::OwnerGracefulShutdownRequested,
            stop_pending(),
        );
        graceful.owner_process = Some(owner.clone());
        writer.append(graceful).unwrap();

        let mut exit = clock.event(ScmQualificationEventKindV1::OwnerExitProven, stop_pending());
        exit.owner_process = Some(owner.clone());
        exit.win32_exit_code = Some(0);
        exit.service_exit_code = Some(0);
        exit.journal = Some(fixture.journal_snapshot_at(&fixture.journal, true, false));
        exit.ledger = Some(fixture.ledger_snapshot_at(&fixture.ledger, "journal_sealed"));
        writer.append(exit).unwrap();

        let mut recovery = clock.event(
            ScmQualificationEventKindV1::JournalRecoveryVerified,
            stop_pending(),
        );
        recovery.owner_process = Some(owner.clone());
        recovery.journal = Some(fixture.journal_snapshot_at(&fixture.journal, true, true));
        recovery.ledger = Some(fixture.ledger_snapshot_at(&fixture.ledger, "journal_sealed"));
        writer.append(recovery).unwrap();

        let mut service_stopped =
            clock.event(ScmQualificationEventKindV1::ServiceStopped, stopped());
        service_stopped.owner_process = Some(owner.clone());
        service_stopped.win32_exit_code = Some(0);
        service_stopped.service_exit_code = Some(0);
        writer.append(service_stopped).unwrap();
        writer
            .append(clock.event(ScmQualificationEventKindV1::UninstallRequested, stopped()))
            .unwrap();
        let mut uninstall = clock.event(ScmQualificationEventKindV1::UninstallVerified, absent());
        uninstall.win32_exit_code = Some(0);
        uninstall.service_exit_code = Some(0);
        writer.append(uninstall).unwrap();
        writer
            .append(clock.event(ScmQualificationEventKindV1::QualificationSealed, absent()))
            .unwrap();
    }

    fn absent() -> ScmStatusSnapshotV1 {
        status(ScmServiceStateV1::Absent, 0, 0)
    }

    fn stopped() -> ScmStatusSnapshotV1 {
        status(ScmServiceStateV1::Stopped, 0, 0)
    }

    fn running() -> ScmStatusSnapshotV1 {
        status(ScmServiceStateV1::Running, 0, 0)
    }

    fn start_pending() -> ScmStatusSnapshotV1 {
        status(ScmServiceStateV1::StartPending, 1, 1_000)
    }

    fn stop_pending() -> ScmStatusSnapshotV1 {
        status(ScmServiceStateV1::StopPending, 1, 1_000)
    }

    fn status(state: ScmServiceStateV1, checkpoint: u32, wait_hint_ms: u32) -> ScmStatusSnapshotV1 {
        ScmStatusSnapshotV1 {
            state,
            checkpoint,
            wait_hint_ms,
        }
    }

    fn durable_test_file(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn read_audit_events(path: &Path) -> Vec<ScmQualificationAuditEventV1> {
        let bytes = fs::read(path).unwrap();
        bytes[..bytes.len() - 1]
            .split(|byte| *byte == b'\n')
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    fn write_rechained_audit(path: &Path, events: &mut [ScmQualificationAuditEventV1]) {
        let mut previous = [0_u8; 32];
        let mut output = Vec::new();
        for (index, event) in events.iter_mut().enumerate() {
            event.event_sequence = index as u64;
            event.previous_event_hash_hex = hex(&previous);
            event.event_crc32c = 0;
            event.event_hash_hex.clear();
            let covered = canonical_covered_event_bytes(event).unwrap();
            event.event_crc32c = crc32c(&covered);
            previous = hash_audit_event(&covered, event.event_crc32c);
            event.event_hash_hex = hex(&previous);
            output.extend_from_slice(&serde_json::to_vec(event).unwrap());
            output.push(b'\n');
        }
        durable_test_file(path, &output);
    }

    fn write_receipt(path: &Path, receipt: &ScmQualificationReceiptV1) {
        durable_test_file(path, &serde_json::to_vec(receipt).unwrap());
    }

    #[test]
    fn graceful_and_forced_restart_audits_and_receipts_verify() {
        let graceful = Fixture::new("graceful");
        let graceful_evidence = graceful.build_audit(false);
        assert_eq!(graceful_evidence.event_count, 20);
        assert_eq!(
            verify_scm_qualification_audit_v1(&graceful.audit, &graceful.context).unwrap(),
            graceful_evidence
        );
        let graceful_receipt = graceful.build_receipt();
        assert!(!graceful_receipt.passed);
        assert!(!graceful_receipt.service_deployed);
        assert!(graceful_receipt.scm_emulated);
        assert_eq!(graceful_receipt.owner_instances.len(), 1);
        assert_eq!(graceful_receipt.forced_owner_termination_count, 0);
        assert_eq!(graceful_receipt.owner_graceful_shutdown_count, 1);
        assert_eq!(
            graceful_receipt.open_gates,
            vec![
                HARDWARE_OPEN_GATE.to_owned(),
                NWB_OPEN_GATE.to_owned(),
                REAL_SCM_OPEN_GATE.to_owned(),
            ]
        );
        publish_scm_qualification_receipt_v1(
            &graceful.receipt,
            &graceful_receipt,
            &graceful.expectation(),
        )
        .unwrap();
        assert_eq!(
            verify_scm_qualification_receipt_v1(&graceful.receipt, &graceful.expectation())
                .unwrap(),
            graceful_receipt
        );

        let forced = Fixture::new("forced-restart");
        let forced_evidence = forced.build_audit(true);
        assert_eq!(forced_evidence.event_count, 24);
        let forced_receipt = forced.build_receipt();
        assert!(!forced_receipt.passed);
        assert_eq!(forced_receipt.owner_instances.len(), 2);
        assert_eq!(forced_receipt.restart_observed_count, 1);
        assert_eq!(forced_receipt.forced_owner_termination_count, 1);
        assert_eq!(forced_receipt.owner_graceful_shutdown_count, 1);
    }

    #[test]
    fn deletion_duplication_and_reordering_fail_even_after_rechaining() {
        let fixture = Fixture::new("sequence-tamper");
        fixture.build_audit(true);
        let original = read_audit_events(&fixture.audit);

        let deleted_path = fixture.root.join("deleted.jsonl");
        let mut deleted = original.clone();
        deleted.remove(8);
        write_rechained_audit(&deleted_path, &mut deleted);
        assert!(load_and_replay_audit(&deleted_path, None).is_err());

        let duplicate_path = fixture.root.join("duplicate.jsonl");
        let mut duplicated = original.clone();
        duplicated.insert(8, duplicated[8].clone());
        write_rechained_audit(&duplicate_path, &mut duplicated);
        assert!(load_and_replay_audit(&duplicate_path, None).is_err());

        let reordered_path = fixture.root.join("reordered.jsonl");
        let mut reordered = original;
        reordered.swap(7, 8);
        write_rechained_audit(&reordered_path, &mut reordered);
        assert!(load_and_replay_audit(&reordered_path, None).is_err());
    }

    #[test]
    fn semantic_tamper_with_recomputed_crc_and_hash_is_rejected() {
        let fixture = Fixture::new("semantic-tamper");
        fixture.build_audit(false);
        let mut events = read_audit_events(&fixture.audit);
        let stopped = events
            .iter_mut()
            .find(|event| event.kind == ScmQualificationEventKindV1::ServiceStopped)
            .unwrap();
        stopped.win32_exit_code = Some(1_067);
        stopped.service_exit_code = Some(1_067);
        let path = fixture.root.join("semantic-rechained.jsonl");
        write_rechained_audit(&path, &mut events);
        assert!(load_and_replay_audit(&path, None).is_err());
    }

    #[test]
    fn supervisor_recovery_binding_and_external_files_fail_closed() {
        let fixture = Fixture::new("identity-and-recovery");

        let mut wrong_writer = fixture.context.clone();
        wrong_writer.qualification_supervisor.creation_time_100ns += 1;
        let wrong_path = fixture.root.join("wrong-writer.jsonl");
        let error = match ScmQualificationAuditWriterV1::create_new(&wrong_path, wrong_writer) {
            Ok(_) => panic!("wrong qualification supervisor unexpectedly acquired audit writer"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!wrong_path.exists());

        assert!(!is_service_sid("S-1-5-80-S"));
        assert!(!is_service_sid("S-1-5-80-1--3-4-5"));
        assert!(!is_service_sid("S-1-5-80-01-2-3-4-5"));
        assert!(!is_service_sid("S-1-5-80-1-2-3-4"));

        fixture.build_audit(true);
        let mut events = read_audit_events(&fixture.audit);
        let forced_exit = events
            .iter()
            .find(|event| event.kind == ScmQualificationEventKindV1::ForcedOwnerTermination)
            .unwrap();
        let prior_journal = forced_exit.journal.clone().unwrap();
        let prior_ledger = forced_exit.ledger.clone().unwrap();
        let forced_recovery = events
            .iter_mut()
            .find(|event| {
                event.kind == ScmQualificationEventKindV1::JournalRecoveryVerified
                    && event.scm.state == ScmServiceStateV1::Running
            })
            .unwrap();
        let recovered_journal = forced_recovery.journal.as_mut().unwrap();
        recovered_journal.path = prior_journal.path;
        recovered_journal.sha256_hex = prior_journal.sha256_hex;
        recovered_journal.file_identity = prior_journal.file_identity;
        let recovered_ledger = forced_recovery.ledger.as_mut().unwrap();
        recovered_ledger.path = prior_ledger.path;
        recovered_ledger.sha256_hex = prior_ledger.sha256_hex;
        recovered_ledger.file_identity = prior_ledger.file_identity;
        let substituted = fixture.root.join("substituted-recovery.jsonl");
        write_rechained_audit(&substituted, &mut events);
        assert!(load_and_replay_audit(&substituted, None).is_err());

        fixture.ensure_synthetic_lifecycle_evidence();
        let mut wrong_recovery_paths = fixture.recovery_paths();
        wrong_recovery_paths[0].prior_journal_path = fixture.root.join("wrong-crash-snapshot");
        assert!(build_scm_qualification_receipt_v1(
            &fixture.audit,
            &fixture.executable,
            ScmQualificationReceiptOptionsV1 {
                open_gates: Vec::new(),
                scm_lifecycle_evidence_path: fixture.lifecycle.clone(),
                recovery_paths: wrong_recovery_paths,
            },
        )
        .is_err());

        let receipt = fixture.build_receipt();
        publish_scm_qualification_receipt_v1(&fixture.receipt, &receipt, &fixture.expectation())
            .unwrap();
        let original_bytes = fs::read(&fixture.journal).unwrap();
        let original_identity = bind_file(&fixture.journal).unwrap().file_identity;
        let displaced = fixture.root.join("displaced-original-journal.bin");
        fs::rename(&fixture.journal, &displaced).unwrap();
        durable_test_file(&fixture.journal, &original_bytes);
        assert_ne!(
            bind_file(&fixture.journal).unwrap().file_identity,
            original_identity
        );
        assert!(
            verify_scm_qualification_receipt_v1(&fixture.receipt, &fixture.expectation()).is_err()
        );
    }

    #[test]
    fn old_unknown_schema_and_unknown_fields_are_rejected() {
        let fixture = Fixture::new("schema");
        fixture.build_audit(false);
        let mut events = read_audit_events(&fixture.audit);
        events[0].schema = "forge.scm-qualification.v0".to_owned();
        let old_path = fixture.root.join("old.jsonl");
        write_rechained_audit(&old_path, &mut events);
        assert!(load_and_replay_audit(&old_path, None).is_err());

        let bytes = fs::read(&fixture.audit).unwrap();
        let first_end = bytes.iter().position(|byte| *byte == b'\n').unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes[..first_end]).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        let mut unknown = serde_json::to_vec(&value).unwrap();
        unknown.push(b'\n');
        unknown.extend_from_slice(&bytes[first_end + 1..]);
        let unknown_path = fixture.root.join("unknown.jsonl");
        durable_test_file(&unknown_path, &unknown);
        assert!(load_and_replay_audit(&unknown_path, None).is_err());
    }

    #[test]
    fn receipt_missing_tampered_replaced_and_passed_forgery_are_rejected() {
        let fixture = Fixture::new("receipt-tamper");
        fixture.build_audit(true);
        let receipt = fixture.build_receipt();

        let mut missing: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&receipt).unwrap()).unwrap();
        missing
            .as_object_mut()
            .unwrap()
            .remove("service_configuration_readback");
        let missing_path = fixture.root.join("missing.json");
        durable_test_file(&missing_path, &serde_json::to_vec(&missing).unwrap());
        assert!(
            verify_scm_qualification_receipt_v1(&missing_path, &fixture.expectation()).is_err()
        );

        let mut unknown: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&receipt).unwrap()).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        let unknown_path = fixture.root.join("unknown-receipt.json");
        durable_test_file(&unknown_path, &serde_json::to_vec(&unknown).unwrap());
        assert!(
            verify_scm_qualification_receipt_v1(&unknown_path, &fixture.expectation()).is_err()
        );

        let mut tampered = receipt.clone();
        tampered.service_configuration_readback.service_account_name = "LocalSystem".to_owned();
        tampered.evidence_sha256_hex = receipt_evidence_hash(&tampered).unwrap();
        let tampered_path = fixture.root.join("tampered.json");
        write_receipt(&tampered_path, &tampered);
        assert!(
            verify_scm_qualification_receipt_v1(&tampered_path, &fixture.expectation()).is_err()
        );

        let replacement_audit = fixture.root.join("replacement-audit.jsonl");
        durable_test_file(&replacement_audit, &fs::read(&fixture.audit).unwrap());
        let mut replaced = receipt.clone();
        replaced.audit.path = utf8_path(&replacement_audit).unwrap().to_owned();
        replaced.evidence_sha256_hex = receipt_evidence_hash(&replaced).unwrap();
        let replaced_path = fixture.root.join("replaced.json");
        write_receipt(&replaced_path, &replaced);
        assert!(
            verify_scm_qualification_receipt_v1(&replaced_path, &fixture.expectation()).is_err()
        );

        let mut forged = receipt.clone();
        forged.service_deployed = false;
        forged.scm_emulated = true;
        forged.passed = true;
        forged.evidence_sha256_hex = receipt_evidence_hash(&forged).unwrap();
        let forged_path = fixture.root.join("forged-pass.json");
        write_receipt(&forged_path, &forged);
        assert!(verify_scm_qualification_receipt_v1(&forged_path, &fixture.expectation()).is_err());

        let mut forged_promotions = receipt.clone();
        forged_promotions.hardware_qualified = true;
        forged_promotions.nwb_qualified = true;
        forged_promotions.open_gates.clear();
        forged_promotions.evidence_sha256_hex = receipt_evidence_hash(&forged_promotions).unwrap();
        let forged_promotions_path = fixture.root.join("forged-promotions.json");
        write_receipt(&forged_promotions_path, &forged_promotions);
        assert!(verify_scm_qualification_receipt_v1(
            &forged_promotions_path,
            &fixture.expectation()
        )
        .is_err());

        let mut old_receipt = receipt;
        old_receipt.schema = "forge.scm-qualification.v0".to_owned();
        old_receipt.evidence_sha256_hex = receipt_evidence_hash(&old_receipt).unwrap();
        let old_receipt_path = fixture.root.join("old-receipt.json");
        write_receipt(&old_receipt_path, &old_receipt);
        assert!(
            verify_scm_qualification_receipt_v1(&old_receipt_path, &fixture.expectation()).is_err()
        );
    }

    #[test]
    fn synthetic_lifecycle_evidence_cannot_be_promoted_to_real_scm() {
        let fixture = Fixture::new("synthetic-never-real");
        fixture.build_audit(false);

        let missing_lifecycle = fixture.root.join("missing-lifecycle.json");
        assert!(build_scm_qualification_receipt_v1(
            &fixture.audit,
            &fixture.executable,
            ScmQualificationReceiptOptionsV1 {
                open_gates: Vec::new(),
                scm_lifecycle_evidence_path: missing_lifecycle,
                recovery_paths: fixture.recovery_paths(),
            },
        )
        .is_err());

        let receipt = fixture.build_receipt();
        assert!(!receipt.passed);
        let lifecycle_bytes = fs::read(&fixture.lifecycle).unwrap();
        let substituted_lifecycle = fixture.root.join("substituted-lifecycle.json");
        durable_test_file(&substituted_lifecycle, &lifecycle_bytes);
        let substituted_receipt = build_scm_qualification_receipt_v1(
            &fixture.audit,
            &fixture.executable,
            ScmQualificationReceiptOptionsV1 {
                open_gates: Vec::new(),
                scm_lifecycle_evidence_path: substituted_lifecycle,
                recovery_paths: fixture.recovery_paths(),
            },
        )
        .unwrap();
        let substituted_receipt_path = fixture.root.join("substituted-lifecycle-receipt.json");
        write_receipt(&substituted_receipt_path, &substituted_receipt);
        assert!(verify_scm_qualification_receipt_v1(
            &substituted_receipt_path,
            &fixture.expectation(),
        )
        .is_err());

        let mut lifecycle: ExternalScmLifecycleEvidenceV1 =
            serde_json::from_slice(&lifecycle_bytes).unwrap();
        lifecycle.evidence_source = ScmEvidenceSourceV1::WindowsScmApi;
        lifecycle.scm_api_readback_verified = true;
        lifecycle.service_deployed = true;
        lifecycle.scm_emulated = false;
        lifecycle.evidence_sha256_hex = external_lifecycle_evidence_hash(&lifecycle).unwrap();
        let forged_lifecycle = fixture.root.join("forged-real-lifecycle.json");
        durable_test_file(&forged_lifecycle, &serde_json::to_vec(&lifecycle).unwrap());
        assert!(build_scm_qualification_receipt_v1(
            &fixture.audit,
            &fixture.executable,
            ScmQualificationReceiptOptionsV1 {
                open_gates: Vec::new(),
                scm_lifecycle_evidence_path: forged_lifecycle,
                recovery_paths: fixture.recovery_paths(),
            },
        )
        .is_err());

        let mut forged_receipt = receipt;
        forged_receipt.evidence_source = ScmEvidenceSourceV1::WindowsScmApi;
        forged_receipt.service_deployed = true;
        forged_receipt.scm_emulated = false;
        forged_receipt
            .open_gates
            .retain(|gate| gate != REAL_SCM_OPEN_GATE);
        forged_receipt.passed = true;
        forged_receipt.evidence_sha256_hex = receipt_evidence_hash(&forged_receipt).unwrap();
        let forged_receipt_path = fixture.root.join("forged-real-receipt.json");
        write_receipt(&forged_receipt_path, &forged_receipt);
        assert!(
            verify_scm_qualification_receipt_v1(&forged_receipt_path, &fixture.expectation(),)
                .is_err()
        );
    }

    #[test]
    fn second_audit_and_receipt_write_refuse_overwrite() {
        let fixture = Fixture::new("no-overwrite");
        fixture.build_audit(false);
        let audit_error = match ScmQualificationAuditWriterV1::create_new(
            &fixture.audit,
            fixture.context.clone(),
        ) {
            Ok(_) => panic!("second audit writer unexpectedly replaced evidence"),
            Err(error) => error,
        };
        assert_eq!(audit_error.kind(), io::ErrorKind::AlreadyExists);
        let receipt = fixture.build_receipt();
        for name in ["reserved.pending", "reserved.PENDING"] {
            let reserved_formal = fixture.root.join(name);
            let reserved_error = publish_scm_qualification_receipt_v1(
                &reserved_formal,
                &receipt,
                &fixture.expectation(),
            )
            .unwrap_err();
            assert_eq!(reserved_error.kind(), io::ErrorKind::InvalidInput);
            assert!(!reserved_formal.exists());
        }
        publish_scm_qualification_receipt_v1(&fixture.receipt, &receipt, &fixture.expectation())
            .unwrap();
        let before = fs::read(&fixture.receipt).unwrap();
        let error = publish_scm_qualification_receipt_v1(
            &fixture.receipt,
            &receipt,
            &fixture.expectation(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&fixture.receipt).unwrap(), before);
    }

    #[test]
    fn audit_rejects_missing_newline_and_empty_line() {
        let fixture = Fixture::new("line-shape");
        fixture.build_audit(false);
        let bytes = fs::read(&fixture.audit).unwrap();
        let no_newline = fixture.root.join("no-newline.jsonl");
        durable_test_file(&no_newline, &bytes[..bytes.len() - 1]);
        assert!(load_and_replay_audit(&no_newline, None).is_err());

        let empty_line = fixture.root.join("empty-line.jsonl");
        let first = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        let mut with_empty = bytes[..first].to_vec();
        with_empty.push(b'\n');
        with_empty.extend_from_slice(&bytes[first..]);
        durable_test_file(&empty_line, &with_empty);
        assert!(load_and_replay_audit(&empty_line, None).is_err());
    }
}
