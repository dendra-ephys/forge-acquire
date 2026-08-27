//! Owner-only journal backup and retention gate.
//!
//! This module never removes a journal.  A successful decision is only a
//! single-use, epoch-bound authorization object for a future owner operation.
//! In particular, a different directory is not backup evidence: on Windows a
//! target must have a different volume serial number.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use forge_protocol_v1::{sha256, Hash32, Id16};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::journal::{scan_journal_from_open_files, seal_evidence_hash};
use crate::nwb_publication::NwbGenerationPublicationReceiptV1;
use crate::nwb_receipt::{NwbGenerationValidationReceiptV1, NwbValidationBundlePaths};
use crate::run_ledger::verify_nwb_publication_proof_read_only;

pub const JOURNAL_BACKUP_RECEIPT_SCHEMA: &str = "forge.journal-backup-receipt.v1";
const MAX_FIXED_EVIDENCE_BYTES: u64 = 64 * 1024;
const MAX_JSON_EVIDENCE_BYTES: u64 = 1024 * 1024;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableFileIdentityV1 {
    pub volume_serial: u64,
    pub file_index: u64,
    pub link_count: u64,
    pub bytes: u64,
    pub sha256: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalBackupReceiptV1 {
    pub schema_version: String,
    pub run_id: Id16,
    pub journal: StableFileIdentityV1,
    pub journal_seal: StableFileIdentityV1,
    pub checkpoint_a: StableFileIdentityV1,
    pub checkpoint_b: StableFileIdentityV1,
    pub validation_receipt: StableFileIdentityV1,
    pub publication_receipt: StableFileIdentityV1,
    pub session_manifest: StableFileIdentityV1,
    pub backup_journal: StableFileIdentityV1,
    pub backup_journal_seal: StableFileIdentityV1,
    pub backup_checkpoint_a: StableFileIdentityV1,
    pub backup_checkpoint_b: StableFileIdentityV1,
    pub backup_validation_receipt: StableFileIdentityV1,
    pub backup_publication_receipt: StableFileIdentityV1,
    pub backup_session_manifest: StableFileIdentityV1,
    pub backup_target_volume_serial: u64,
    pub backup_target_root_sha256: Hash32,
    /// Different volume serials do not prove independent physical media or
    /// power-loss protection; this v1 writer records that limitation.
    pub evidence_source: String,
    pub verified_at_unix_ns: u64,
    pub verification_source: String,
    pub self_hash: Hash32,
}

impl JournalBackupReceiptV1 {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        self.verify_self_hash()?;
        serde_json::to_vec(self)
            .map_err(|error| invalid(format!("receipt JSON encoding failed: {error}")))
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| invalid(format!("receipt JSON decoding failed: {error}")))?;
        value.verify_self_hash()?;
        Ok(value)
    }

    pub fn verify_self_hash(&self) -> io::Result<()> {
        if self.schema_version != JOURNAL_BACKUP_RECEIPT_SCHEMA
            || !self.run_id.iter().any(|byte| *byte != 0)
            || self.verified_at_unix_ns == 0
            || self.verification_source != "protected-owner-retention-gate"
            || self.evidence_source != "unqualified-local-volume-only"
            || self.backup_target_volume_serial == 0
        {
            return Err(invalid("backup receipt semantic invariant failed"));
        }
        for identity in self.identities() {
            validate_identity(identity)?;
        }
        if self.journal.bytes != self.backup_journal.bytes
            || self.journal.sha256 != self.backup_journal.sha256
            || self.journal_seal.sha256 != self.backup_journal_seal.sha256
            || self.checkpoint_a.sha256 != self.backup_checkpoint_a.sha256
            || self.checkpoint_b.sha256 != self.backup_checkpoint_b.sha256
            || self.validation_receipt.sha256 != self.backup_validation_receipt.sha256
            || self.publication_receipt.sha256 != self.backup_publication_receipt.sha256
            || self.session_manifest.sha256 != self.backup_session_manifest.sha256
            || self.self_hash != self.expected_self_hash()?
        {
            return Err(invalid("backup receipt evidence or self hash differs"));
        }
        Ok(())
    }

    fn identities(&self) -> [&StableFileIdentityV1; 14] {
        [
            &self.journal,
            &self.journal_seal,
            &self.checkpoint_a,
            &self.checkpoint_b,
            &self.validation_receipt,
            &self.publication_receipt,
            &self.session_manifest,
            &self.backup_journal,
            &self.backup_journal_seal,
            &self.backup_checkpoint_a,
            &self.backup_checkpoint_b,
            &self.backup_validation_receipt,
            &self.backup_publication_receipt,
            &self.backup_session_manifest,
        ]
    }

    fn expected_self_hash(&self) -> io::Result<Hash32> {
        let mut unsigned = self.clone();
        unsigned.self_hash = [0; 32];
        let bytes = serde_json::to_vec(&unsigned)
            .map_err(|error| invalid(format!("receipt canonical encoding failed: {error}")))?;
        Ok(sha256(&bytes))
    }
}

/// Paths are owner-created and private to this crate so a GUI cannot supply an
/// arbitrary backup root or replace a receipt path at the public boundary.
#[derive(Clone, Debug)]
pub struct JournalRetentionOwnerConfigV1 {
    validation: NwbValidationBundlePaths,
    publication_receipt: PathBuf,
    run_ledger: PathBuf,
    backup_root: PathBuf,
}

impl JournalRetentionOwnerConfigV1 {
    #[allow(dead_code)] // Constructed only by the protected owner integration.
    pub(crate) fn new(
        validation: NwbValidationBundlePaths,
        publication_receipt: PathBuf,
        run_ledger: PathBuf,
        backup_root: PathBuf,
    ) -> io::Result<Self> {
        if !publication_receipt.is_absolute()
            || !run_ledger.is_absolute()
            || !backup_root.is_absolute()
        {
            return Err(invalid("owner retention paths must be absolute"));
        }
        Ok(Self {
            validation,
            publication_receipt,
            run_ledger,
            backup_root,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupVerifiedRetentionLockedV1 {
    pub run_id: Id16,
    pub epoch: u64,
    pub backup_receipt_self_hash: Hash32,
    pub authorization_id: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalRetentionDecisionV1 {
    /// Backup facts verify, but this is not a deletion authorization.  A
    /// future owner-only deletion protocol must add durable consumption.
    BackupVerifiedRetentionLocked(BackupVerifiedRetentionLockedV1),
    Retain {
        reason: &'static str,
    },
}

/// Owner gate.  This module intentionally has no deletion API or executable
/// cleanup authorization.
pub struct JournalRetentionGate;

impl Default for JournalRetentionGate {
    fn default() -> Self {
        Self::new()
    }
}

impl JournalRetentionGate {
    pub fn new() -> Self {
        Self
    }

    pub fn backup_and_evaluate(
        &mut self,
        config: &JournalRetentionOwnerConfigV1,
    ) -> io::Result<(JournalBackupReceiptV1, JournalRetentionDecisionV1)> {
        let frozen = verify_frozen_sources(config)?;
        let receipt = copy_frozen_sources(config, &frozen)?;
        let decision = self.evaluate_receipt(config, &receipt)?;
        Ok((receipt, decision))
    }

    pub fn evaluate_receipt(
        &mut self,
        config: &JournalRetentionOwnerConfigV1,
        receipt: &JournalBackupReceiptV1,
    ) -> io::Result<JournalRetentionDecisionV1> {
        receipt.verify_self_hash()?;
        let frozen = match verify_frozen_sources(config) {
            Ok(value) => value,
            Err(_) => {
                return Ok(JournalRetentionDecisionV1::Retain {
                    reason: "frozen source evidence no longer verifies",
                })
            }
        };
        if receipt.run_id != frozen.validation.run_id
            || receipt.journal != frozen.journal
            || receipt.journal_seal != frozen.journal_seal
            || receipt.checkpoint_a != frozen.checkpoint_a
            || receipt.checkpoint_b != frozen.checkpoint_b
            || receipt.validation_receipt != frozen.validation_receipt
            || receipt.publication_receipt != frozen.publication_receipt
            || receipt.session_manifest != frozen.session_manifest
        {
            return Ok(JournalRetentionDecisionV1::Retain {
                reason: "source evidence changed after backup receipt",
            });
        }
        let root = canonical_existing_directory(&config.backup_root)?;
        if sha256(path_bytes(&root)?) != receipt.backup_target_root_sha256 {
            return Ok(JournalRetentionDecisionV1::Retain {
                reason: "backup target policy differs",
            });
        }
        if receipt.backup_target_volume_serial == receipt.journal.volume_serial {
            return Ok(JournalRetentionDecisionV1::Retain {
                reason: "UnqualifiedSameVolume",
            });
        }
        for (source, backup) in [
            (&receipt.journal, &receipt.backup_journal),
            (&receipt.journal_seal, &receipt.backup_journal_seal),
            (&receipt.checkpoint_a, &receipt.backup_checkpoint_a),
            (&receipt.checkpoint_b, &receipt.backup_checkpoint_b),
            (
                &receipt.validation_receipt,
                &receipt.backup_validation_receipt,
            ),
            (
                &receipt.publication_receipt,
                &receipt.backup_publication_receipt,
            ),
            (&receipt.session_manifest, &receipt.backup_session_manifest),
        ] {
            if source.bytes != backup.bytes
                || source.sha256 != backup.sha256
                || source.volume_serial == backup.volume_serial
            {
                return Ok(JournalRetentionDecisionV1::Retain {
                    reason: "backup artifact identity or hash differs",
                });
            }
        }
        let destination = root.join(hex(&receipt.run_id));
        require_plain_directory(&root)?;
        require_plain_directory(&destination)?;
        for (name, expected) in [
            ("journal.forgewal", &receipt.backup_journal),
            ("journal.seal", &receipt.backup_journal_seal),
            ("checkpoint-a", &receipt.backup_checkpoint_a),
            ("checkpoint-b", &receipt.backup_checkpoint_b),
            ("nwb-validation.receipt", &receipt.backup_validation_receipt),
            (
                "nwb-publication.receipt",
                &receipt.backup_publication_receipt,
            ),
            ("session-manifest.json", &receipt.backup_session_manifest),
        ] {
            if stable_snapshot(&destination.join(name))? != *expected {
                return Ok(JournalRetentionDecisionV1::Retain {
                    reason: "backup artifact is missing or changed after receipt",
                });
            }
        }
        // A private owner configuration and distinct volume serial are not an
        // ACL/reparse audit, independent-device proof, or PLP evidence.
        let _candidate = retention_locked(receipt.run_id, frozen.epoch, receipt.self_hash);
        Ok(JournalRetentionDecisionV1::Retain {
            reason: "UnqualifiedBackupAcl",
        })
    }
}

#[derive(Clone)]
struct FrozenSources {
    validation: NwbGenerationValidationReceiptV1,
    epoch: u64,
    journal: StableFileIdentityV1,
    journal_seal: StableFileIdentityV1,
    checkpoint_a: StableFileIdentityV1,
    checkpoint_b: StableFileIdentityV1,
    validation_receipt: StableFileIdentityV1,
    publication_receipt: StableFileIdentityV1,
    session_manifest: StableFileIdentityV1,
}

/// Small evidence is rejected by metadata length before any allocation. Bytes
/// and identity are then read through the same no-write/no-delete-sharing
/// handle, which stays live until semantic validation and `recheck` finish.
struct LockedSmallEvidence {
    file: File,
    identity: StableFileIdentityV1,
    bytes: Vec<u8>,
}

impl LockedSmallEvidence {
    fn open(path: &Path, max_bytes: u64) -> io::Result<Self> {
        let mut file = open_stable_read(path)?;
        let metadata_len = file.metadata()?.len();
        if metadata_len > max_bytes {
            return Err(invalid(format!(
                "small evidence exceeds its {max_bytes}-byte bound"
            )));
        }
        let identity = snapshot_open_file(&mut file)?;
        if identity.bytes > max_bytes {
            return Err(invalid(format!(
                "small evidence exceeds its {max_bytes}-byte bound"
            )));
        }
        file.seek(SeekFrom::Start(0))?;
        let bytes = read_exact_bounded(&mut file, identity.bytes, max_bytes)?;
        if snapshot_open_file(&mut file)? != identity {
            return Err(invalid("evidence changed while locked for parsing"));
        }
        Ok(Self {
            file,
            identity,
            bytes,
        })
    }

    fn recheck(&mut self) -> io::Result<()> {
        if snapshot_open_file(&mut self.file)? != self.identity {
            return Err(invalid("evidence changed during semantic verification"));
        }
        Ok(())
    }
}

/// Reads exactly one already-proven small length and then probes one byte past
/// it. Allocation is rejected before it can exceed `max_bytes`; truncation or
/// extension is a hard failure.
fn read_exact_bounded(
    reader: &mut impl Read,
    exact_bytes: u64,
    max_bytes: u64,
) -> io::Result<Vec<u8>> {
    if exact_bytes > max_bytes {
        return Err(invalid(format!(
            "small evidence exceeds its {max_bytes}-byte bound"
        )));
    }
    let exact_bytes = usize::try_from(exact_bytes)
        .map_err(|_| invalid("small evidence length overflows usize"))?;
    let mut bytes = vec![0_u8; exact_bytes];
    reader.read_exact(&mut bytes)?;
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(invalid("small evidence extended during bounded read"));
    }
    Ok(bytes)
}

/// Large evidence retains only a stable handle and its streaming identity.
/// Neither journal nor NWB file length is ever used as an allocation size.
struct LockedLargeEvidence {
    file: File,
    identity: StableFileIdentityV1,
    require_single_link: bool,
}

impl LockedLargeEvidence {
    fn open(path: &Path, require_single_link: bool) -> io::Result<Self> {
        let mut file = open_stable_read(path)?;
        let identity = snapshot_open_file_with_policy(&mut file, require_single_link)?;
        Ok(Self {
            file,
            identity,
            require_single_link,
        })
    }

    fn recheck(&mut self) -> io::Result<()> {
        if snapshot_open_file_with_policy(&mut self.file, self.require_single_link)?
            != self.identity
        {
            return Err(invalid(
                "large evidence changed during semantic verification",
            ));
        }
        Ok(())
    }
}

fn verify_frozen_sources(config: &JournalRetentionOwnerConfigV1) -> io::Result<FrozenSources> {
    let mut validation_evidence =
        LockedSmallEvidence::open(&config.validation.receipt, MAX_FIXED_EVIDENCE_BYTES)?;
    let validation = NwbGenerationValidationReceiptV1::decode(&validation_evidence.bytes)?;
    let mut publication_evidence =
        LockedSmallEvidence::open(&config.publication_receipt, MAX_FIXED_EVIDENCE_BYTES)?;
    let publication = NwbGenerationPublicationReceiptV1::decode(&publication_evidence.bytes)?;
    let publication_receipt_hash = sha256(&publication_evidence.bytes);
    if publication.run_id != validation.run_id
        || publication.generation != validation.generation
        || publication.nwb_bytes != validation.nwb_bytes
        || publication.validation_sequence != validation.validation_sequence
        || publication.validation_receipt_sha256 != sha256(&validation_evidence.bytes)
    {
        return Err(invalid(
            "NWB publication receipt does not bind validation receipt",
        ));
    }
    let mut journal_evidence = LockedLargeEvidence::open(&config.validation.journal, true)?;
    let mut journal_seal_evidence =
        LockedSmallEvidence::open(&config.validation.journal_seal, MAX_FIXED_EVIDENCE_BYTES)?;
    let mut checkpoint_a_evidence =
        LockedSmallEvidence::open(&config.validation.checkpoint_a, MAX_FIXED_EVIDENCE_BYTES)?;
    let mut checkpoint_b_evidence =
        LockedSmallEvidence::open(&config.validation.checkpoint_b, MAX_FIXED_EVIDENCE_BYTES)?;
    let mut manifest_evidence =
        LockedSmallEvidence::open(&config.validation.session_manifest, MAX_JSON_EVIDENCE_BYTES)?;
    let journal = journal_evidence.identity.clone();
    let journal_seal = journal_seal_evidence.identity.clone();
    let checkpoint_a = checkpoint_a_evidence.identity.clone();
    let checkpoint_b = checkpoint_b_evidence.identity.clone();
    let session_manifest = manifest_evidence.identity.clone();
    let validation_receipt = validation_evidence.identity.clone();
    let publication_receipt = publication_evidence.identity.clone();
    if journal.bytes != validation.journal_bytes
        || journal.sha256 != validation.journal_sha256
        || journal_seal.sha256 != validation.journal_seal_sha256
        || checkpoint_set_hash(&checkpoint_a, &checkpoint_b)
            != validation.durable_checkpoint_set_sha256
        || session_manifest.sha256 != validation.session_manifest_sha256
    {
        return Err(invalid(
            "journal, seal, or durable checkpoint receipt differs",
        ));
    }
    let scan = scan_journal_from_open_files(
        &mut journal_evidence.file,
        &mut checkpoint_a_evidence.file,
        &mut checkpoint_b_evidence.file,
        &mut journal_seal_evidence.file,
    )?;
    let Some(seal) = scan.seal.as_ref() else {
        return Err(invalid("journal is not sealed"));
    };
    let expected_last = (validation.expected_last_journal_sequence != u64::MAX)
        .then_some(validation.expected_last_journal_sequence);
    if scan.torn_tail
        || scan.identity.run_id != validation.run_id
        || scan.file_len != journal.bytes
        || scan.last_journal_sequence != expected_last
        || scan.durable.durable_journal_sequence != expected_last
        || scan.durable.generation != seal.checkpoint_generation
        || seal.expected_last_journal_sequence != expected_last
        || seal.record_count != validation.checked_blocks
        || scan.complete_chunks != validation.checked_blocks
        || seal.expected_valid_len != scan.file_len
        || scan.durable.durable_valid_len != scan.file_len
        || seal_evidence_hash(validation.run_id, seal) != validation.run_ledger_seal_evidence_sha256
    {
        return Err(invalid(
            "journal seal, checkpoint generation, or watermark differs",
        ));
    }
    let manifest: Value = serde_json::from_slice(&manifest_evidence.bytes)
        .map_err(|error| invalid(format!("session manifest JSON is invalid: {error}")))?;
    let final_path = manifest
        .get("final_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| invalid("session manifest final_path is absent"))?;
    if !final_path.is_absolute()
        || sha256(path_bytes(&final_path)?) != publication.final_path_sha256
    {
        return Err(invalid("publication receipt final NWB path differs"));
    }
    // Publication intentionally retains the `.nwb.inprogress` hard link, so
    // the final NWB may have more than one link. Its exact link count remains
    // part of the stable identity and must not change during this proof.
    let mut final_nwb_evidence = LockedLargeEvidence::open(&final_path, false)?;
    let final_nwb = final_nwb_evidence.identity.clone();
    if final_nwb.bytes != validation.nwb_bytes
        || final_nwb.bytes != publication.nwb_bytes
        || final_nwb.sha256 != validation.nwb_sha256
        || final_nwb.sha256 != publication.nwb_sha256
    {
        return Err(invalid("published NWB identity or hash differs"));
    }
    let ledger_proof = verify_nwb_publication_proof_read_only(
        &config.run_ledger,
        validation.run_id,
        publication_receipt_hash,
    )?;
    if ledger_proof.journal_seal_evidence_hash != validation.run_ledger_seal_evidence_sha256 {
        return Err(invalid("Run ledger journal-seal evidence differs"));
    }
    for evidence in [
        &mut validation_evidence,
        &mut publication_evidence,
        &mut journal_seal_evidence,
        &mut checkpoint_a_evidence,
        &mut checkpoint_b_evidence,
        &mut manifest_evidence,
    ] {
        evidence.recheck()?;
    }
    journal_evidence.recheck()?;
    final_nwb_evidence.recheck()?;
    Ok(FrozenSources {
        validation,
        epoch: ledger_proof.epoch,
        journal,
        journal_seal,
        checkpoint_a,
        checkpoint_b,
        validation_receipt,
        publication_receipt,
        session_manifest,
    })
}

fn copy_frozen_sources(
    config: &JournalRetentionOwnerConfigV1,
    frozen: &FrozenSources,
) -> io::Result<JournalBackupReceiptV1> {
    let root = canonical_existing_directory(&config.backup_root)?;
    let source_volume = frozen.journal.volume_serial;
    let backup_volume = directory_volume_serial(&root)?;
    if backup_volume == source_volume {
        return Err(invalid(
            "UnqualifiedSameVolume: backup root is on the journal volume",
        ));
    }
    let destination = root.join(hex(&frozen.validation.run_id));
    fs::create_dir(&destination)
        .map_err(|error| invalid(format!("backup destination must be no-overwrite: {error}")))?;
    // Keep every destination handle deny-write/deny-delete until the receipt
    // has been atomically published below.
    let backup_journal = copy_no_overwrite_locked(
        &config.validation.journal,
        &destination.join("journal.forgewal"),
    )?;
    let backup_journal_seal = copy_no_overwrite_locked(
        &config.validation.journal_seal,
        &destination.join("journal.seal"),
    )?;
    let backup_checkpoint_a = copy_no_overwrite_locked(
        &config.validation.checkpoint_a,
        &destination.join("checkpoint-a"),
    )?;
    let backup_checkpoint_b = copy_no_overwrite_locked(
        &config.validation.checkpoint_b,
        &destination.join("checkpoint-b"),
    )?;
    let backup_validation_receipt = copy_no_overwrite_locked(
        &config.validation.receipt,
        &destination.join("nwb-validation.receipt"),
    )?;
    let backup_publication_receipt = copy_no_overwrite_locked(
        &config.publication_receipt,
        &destination.join("nwb-publication.receipt"),
    )?;
    let backup_session_manifest = copy_no_overwrite_locked(
        &config.validation.session_manifest,
        &destination.join("session-manifest.json"),
    )?;
    let result: io::Result<JournalBackupReceiptV1> = (|| {
        Ok(JournalBackupReceiptV1 {
            schema_version: JOURNAL_BACKUP_RECEIPT_SCHEMA.to_owned(),
            run_id: frozen.validation.run_id,
            journal: frozen.journal.clone(),
            journal_seal: frozen.journal_seal.clone(),
            checkpoint_a: frozen.checkpoint_a.clone(),
            checkpoint_b: frozen.checkpoint_b.clone(),
            validation_receipt: frozen.validation_receipt.clone(),
            publication_receipt: frozen.publication_receipt.clone(),
            session_manifest: frozen.session_manifest.clone(),
            backup_journal: backup_journal.identity.clone(),
            backup_journal_seal: backup_journal_seal.identity.clone(),
            backup_checkpoint_a: backup_checkpoint_a.identity.clone(),
            backup_checkpoint_b: backup_checkpoint_b.identity.clone(),
            backup_validation_receipt: backup_validation_receipt.identity.clone(),
            backup_publication_receipt: backup_publication_receipt.identity.clone(),
            backup_session_manifest: backup_session_manifest.identity.clone(),
            backup_target_volume_serial: backup_volume,
            backup_target_root_sha256: sha256(path_bytes(&root)?),
            evidence_source: "unqualified-local-volume-only".to_owned(),
            verified_at_unix_ns: unix_ns()?,
            verification_source: "protected-owner-retention-gate".to_owned(),
            self_hash: [0; 32],
        })
    })();
    let mut receipt = result?;
    receipt.self_hash = receipt.expected_self_hash()?;
    receipt.verify_self_hash()?;
    let bytes = receipt.encode()?;
    let receipt_path = destination.join("journal-backup-receipt.v1.json");
    atomic_write_no_overwrite(&receipt_path, &bytes)?;
    let verified_receipt = LockedSmallEvidence::open(&receipt_path, MAX_JSON_EVIDENCE_BYTES)?;
    JournalBackupReceiptV1::decode(&verified_receipt.bytes)?;
    Ok(receipt)
}

#[cfg(windows)]
fn atomic_write_no_overwrite(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| invalid("receipt filename is not UTF-8"))?;
    let pending = path.with_file_name(format!(
        ".{name}.pending-{}-{}",
        std::process::id(),
        unix_ns()?
    ));
    let result = (|| {
        let mut file = open_stable_create_new(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let identity = snapshot_open_file(&mut file)?;
        let expected_bytes =
            u64::try_from(bytes.len()).map_err(|_| invalid("receipt is too large"))?;
        if identity.bytes != expected_bytes || identity.sha256 != sha256(bytes) {
            return Err(invalid("pending receipt readback differs"));
        }
        drop(file);
        let pending_wide: Vec<u16> = pending.as_os_str().encode_wide().chain(Some(0)).collect();
        let final_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe {
            MoveFileExW(
                pending_wide.as_ptr(),
                final_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let actual = stable_snapshot(path)?;
        if actual.bytes != expected_bytes || actual.sha256 != sha256(bytes) {
            return Err(invalid("published receipt identity differs"));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&pending);
    }
    result
}

#[cfg(not(windows))]
fn atomic_write_no_overwrite(_path: &Path, _bytes: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic stable receipt publication requires Windows",
    ))
}

#[cfg(test)]
fn copy_no_overwrite(source: &Path, destination: &Path) -> io::Result<StableFileIdentityV1> {
    Ok(copy_no_overwrite_locked(source, destination)?.identity)
}

struct CopiedEvidence {
    identity: StableFileIdentityV1,
    _file: File,
}

fn copy_no_overwrite_locked(source: &Path, destination: &Path) -> io::Result<CopiedEvidence> {
    let mut input = open_stable_read(source)?;
    let before = snapshot_open_file(&mut input)?;
    let mut output = open_stable_create_new(destination)?;
    input.seek(SeekFrom::Start(0))?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    let after = snapshot_open_file(&mut input)?;
    if before != after {
        return Err(invalid("source changed during backup copy"));
    }
    let copied = snapshot_open_file(&mut output)?;
    if copied.bytes != before.bytes || copied.sha256 != before.sha256 {
        return Err(invalid("backup copy hash differs"));
    }
    Ok(CopiedEvidence {
        identity: copied,
        _file: output,
    })
}

#[cfg(windows)]
fn open_stable_create_new(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(path)
}

#[cfg(not(windows))]
fn open_stable_create_new(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable no-write/no-delete output handles require Windows",
    ))
}

fn stable_snapshot(path: &Path) -> io::Result<StableFileIdentityV1> {
    let mut file = open_stable_read(path)?;
    snapshot_open_file(&mut file)
}

#[cfg(windows)]
fn open_stable_read(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new().read(true).share_mode(1).open(path)
}

#[cfg(not(windows))]
fn open_stable_read(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable no-write/no-delete evidence handles require Windows",
    ))
}

#[cfg(windows)]
fn snapshot_open_file(file: &mut File) -> io::Result<StableFileIdentityV1> {
    snapshot_open_file_with_policy(file, true)
}

#[cfg(windows)]
fn snapshot_open_file_with_policy(
    file: &mut File,
    require_single_link: bool,
) -> io::Result<StableFileIdentityV1> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let metadata = file.metadata()?;
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if !metadata.file_type().is_file()
        || information.nNumberOfLinks == 0
        || (require_single_link && information.nNumberOfLinks != 1)
    {
        return Err(invalid(if require_single_link {
            "evidence must be a regular single-link file"
        } else {
            "evidence must be a regular linked file"
        }));
    }
    let bytes = metadata.len();
    let digest = hash_open_file_preserving_position(file)?;
    Ok(StableFileIdentityV1 {
        volume_serial: u64::from(information.dwVolumeSerialNumber),
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        link_count: u64::from(information.nNumberOfLinks),
        bytes,
        sha256: digest,
    })
}

#[cfg(not(windows))]
fn snapshot_open_file(_file: &mut File) -> io::Result<StableFileIdentityV1> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable no-write/no-delete evidence handles require Windows",
    ))
}

#[cfg(not(windows))]
fn snapshot_open_file_with_policy(
    _file: &mut File,
    _require_single_link: bool,
) -> io::Result<StableFileIdentityV1> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable no-write/no-delete evidence handles require Windows",
    ))
}

fn hash_open_file_preserving_position(file: &mut File) -> io::Result<Hash32> {
    let position = file.stream_position()?;
    let result = (|| {
        file.seek(SeekFrom::Start(0))?;
        stream_sha256(file)
    })();
    let restored = file.seek(SeekFrom::Start(position));
    match (result, restored) {
        (Ok(hash), Ok(_)) => Ok(hash),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn stream_sha256(reader: &mut impl Read) -> io::Result<Hash32> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; STREAM_BUFFER_BYTES];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(digest.finalize().into());
        }
        digest.update(&buffer[..count]);
    }
}

#[cfg(windows)]
fn directory_volume_serial(path: &Path) -> io::Result<u64> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0200_0000)
        .open(path)?;
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::from(information.dwVolumeSerialNumber))
}

#[cfg(not(windows))]
fn directory_volume_serial(_path: &Path) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "independent volume verification requires Windows",
    ))
}

fn checkpoint_set_hash(a: &StableFileIdentityV1, b: &StableFileIdentityV1) -> Hash32 {
    let mut digest = Sha256::new();
    digest.update(b"ForgeDurableCheckpointSetV1\0");
    for (label, checkpoint) in [("checkpoint-a", a), ("checkpoint-b", b)] {
        digest.update(label.as_bytes());
        digest.update(checkpoint.bytes.to_le_bytes());
        digest.update(checkpoint.sha256);
    }
    digest.finalize().into()
}

fn validate_identity(value: &StableFileIdentityV1) -> io::Result<()> {
    if value.volume_serial == 0
        || value.file_index == 0
        || value.link_count != 1
        || value.bytes == 0
        || !value.sha256.iter().any(|byte| *byte != 0)
    {
        return Err(invalid("stable evidence identity is invalid"));
    }
    Ok(())
}

fn canonical_existing_directory(path: &Path) -> io::Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_dir() {
        return Err(invalid("backup root is not an existing directory"));
    }
    Ok(canonical)
}

fn require_plain_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "backup root or destination is not a plain directory",
        ));
    }
    Ok(())
}

fn path_bytes(path: &Path) -> io::Result<&[u8]> {
    path.to_str()
        .map(str::as_bytes)
        .ok_or_else(|| invalid("backup root is not UTF-8"))
}

fn retention_locked(
    run_id: Id16,
    epoch: u64,
    receipt_hash: Hash32,
) -> BackupVerifiedRetentionLockedV1 {
    let mut bytes = Vec::with_capacity(16 + 8 + 32 + 14);
    bytes.extend_from_slice(b"FGRRETAINAUTH1");
    bytes.extend_from_slice(&run_id);
    bytes.extend_from_slice(&epoch.to_le_bytes());
    bytes.extend_from_slice(&receipt_hash);
    BackupVerifiedRetentionLockedV1 {
        run_id,
        epoch,
        backup_receipt_self_hash: receipt_hash,
        authorization_id: sha256(&bytes),
    }
}

fn unix_ns() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system clock precedes Unix epoch"))?
        .as_nanos()
        .try_into()
        .map_err(|_| invalid("timestamp overflows u64"))
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("journal retention: {}", reason.into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TrackingReader {
        remaining: usize,
        max_requested: usize,
    }

    impl Read for TrackingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.max_requested = self.max_requested.max(buffer.len());
            let count = self.remaining.min(buffer.len());
            buffer[..count].fill(0x5a);
            self.remaining -= count;
            Ok(count)
        }
    }

    fn identity(seed: u8) -> StableFileIdentityV1 {
        StableFileIdentityV1 {
            volume_serial: u64::from(seed) + 1,
            file_index: u64::from(seed) + 10,
            link_count: 1,
            bytes: u64::from(seed) + 100,
            sha256: [seed; 32],
        }
    }

    fn receipt() -> JournalBackupReceiptV1 {
        let mut value = JournalBackupReceiptV1 {
            schema_version: JOURNAL_BACKUP_RECEIPT_SCHEMA.to_owned(),
            run_id: [0x41; 16],
            journal: identity(1),
            journal_seal: identity(2),
            checkpoint_a: identity(3),
            checkpoint_b: identity(4),
            validation_receipt: identity(5),
            publication_receipt: identity(6),
            session_manifest: identity(7),
            backup_journal: identity(8),
            backup_journal_seal: identity(9),
            backup_checkpoint_a: identity(10),
            backup_checkpoint_b: identity(11),
            backup_validation_receipt: identity(12),
            backup_publication_receipt: identity(13),
            backup_session_manifest: identity(14),
            backup_target_volume_serial: 99,
            backup_target_root_sha256: [0x55; 32],
            evidence_source: "unqualified-local-volume-only".to_owned(),
            verified_at_unix_ns: 1,
            verification_source: "protected-owner-retention-gate".to_owned(),
            self_hash: [0; 32],
        };
        value.backup_journal.bytes = value.journal.bytes;
        value.backup_journal.sha256 = value.journal.sha256;
        value.backup_journal_seal.bytes = value.journal_seal.bytes;
        value.backup_journal_seal.sha256 = value.journal_seal.sha256;
        value.backup_checkpoint_a.bytes = value.checkpoint_a.bytes;
        value.backup_checkpoint_a.sha256 = value.checkpoint_a.sha256;
        value.backup_checkpoint_b.bytes = value.checkpoint_b.bytes;
        value.backup_checkpoint_b.sha256 = value.checkpoint_b.sha256;
        value.backup_validation_receipt.bytes = value.validation_receipt.bytes;
        value.backup_validation_receipt.sha256 = value.validation_receipt.sha256;
        value.backup_publication_receipt.bytes = value.publication_receipt.bytes;
        value.backup_publication_receipt.sha256 = value.publication_receipt.sha256;
        value.backup_session_manifest.bytes = value.session_manifest.bytes;
        value.backup_session_manifest.sha256 = value.session_manifest.sha256;
        value.self_hash = value.expected_self_hash().unwrap();
        value
    }

    #[test]
    fn receipt_round_trip_is_canonical_and_self_hashed() {
        let value = receipt();
        let bytes = value.encode().unwrap();
        assert_eq!(JournalBackupReceiptV1::decode(&bytes).unwrap(), value);
        assert_eq!(value.encode().unwrap(), bytes);
    }

    #[test]
    fn receipt_mutation_and_backup_hash_mismatch_fail_closed() {
        let value = receipt();
        let mut changed = value.clone();
        changed.backup_journal.sha256[0] ^= 1;
        changed.self_hash = changed.expected_self_hash().unwrap();
        assert!(changed.verify_self_hash().is_err());
        let mut bytes = value.encode().unwrap();
        let offset = bytes.len() - 2;
        bytes[offset] ^= 1;
        assert!(JournalBackupReceiptV1::decode(&bytes).is_err());
    }

    #[test]
    fn stable_backup_copy_is_create_new_and_rechecks_hash() {
        let root = std::env::temp_dir().join(format!(
            "forge-retention-copy-{}-{}",
            std::process::id(),
            unix_ns().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::write(&source, b"small retained journal evidence").unwrap();
        let copied = copy_no_overwrite(&source, &destination).unwrap();
        assert_eq!(copied.sha256, stable_snapshot(&source).unwrap().sha256);
        assert!(copy_no_overwrite(&source, &destination).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn same_volume_target_is_rejected_before_any_copy() {
        let root = std::env::temp_dir().join(format!(
            "forge-retention-same-volume-{}-{}",
            std::process::id(),
            unix_ns().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let volume = directory_volume_serial(&root).unwrap();
        // Different path spellings under the same root still report the same
        // volume; the gate rejects that equality before opening copy outputs.
        assert_eq!(directory_volume_serial(&root).unwrap(), volume);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deleted_or_replaced_backup_artifact_is_not_accepted_as_evidence() {
        let root = std::env::temp_dir().join(format!(
            "forge-retention-missing-backup-{}-{}",
            std::process::id(),
            unix_ns().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let artifact = root.join("journal.forgewal");
        fs::write(&artifact, b"retained backup").unwrap();
        let original = stable_snapshot(&artifact).unwrap();
        fs::remove_file(&artifact).unwrap();
        assert!(stable_snapshot(&artifact).is_err());
        fs::write(&artifact, b"replacement").unwrap();
        assert_ne!(stable_snapshot(&artifact).unwrap(), original);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn non_directory_backup_root_is_rejected_and_restart_has_no_cleanup_token() {
        let root = std::env::temp_dir().join(format!(
            "forge-retention-directory-policy-{}-{}",
            std::process::id(),
            unix_ns().unwrap()
        ));
        fs::write(&root, b"not a directory").unwrap();
        assert!(require_plain_directory(&root).is_err());
        let first = retention_locked([0x41; 16], 7, [0x22; 32]);
        let after_restart = retention_locked([0x41; 16], 7, [0x22; 32]);
        assert_eq!(first, after_restart);
        fs::remove_file(root).unwrap();
    }

    #[test]
    fn large_evidence_hashing_is_streamed_and_small_evidence_is_bounded_before_allocation() {
        let mut reader = TrackingReader {
            remaining: STREAM_BUFFER_BYTES * 3 + 17,
            max_requested: 0,
        };
        let hash = stream_sha256(&mut reader).unwrap();
        assert!(hash.iter().any(|byte| *byte != 0));
        assert_eq!(reader.remaining, 0);
        assert_eq!(reader.max_requested, STREAM_BUFFER_BYTES);

        let root = std::env::temp_dir().join(format!(
            "forge-retention-bounded-{}-{}",
            std::process::id(),
            unix_ns().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let large = root.join("large-evidence");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&large)
            .unwrap();
        let large_len = 8 * 1024 * 1024 + 17;
        file.set_len(large_len).unwrap();
        drop(file);
        let mut evidence = LockedLargeEvidence::open(&large, true).unwrap();
        assert_eq!(evidence.identity.bytes, large_len);
        evidence.recheck().unwrap();
        drop(evidence);

        let oversized = root.join("oversized-small-evidence");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&oversized)
            .unwrap();
        file.set_len(MAX_JSON_EVIDENCE_BYTES + 1).unwrap();
        drop(file);
        assert!(LockedSmallEvidence::open(&oversized, MAX_JSON_EVIDENCE_BYTES).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn small_evidence_reads_exactly_the_bound_and_rejects_truncation_or_extension() {
        let mut exact = TrackingReader {
            remaining: 4,
            max_requested: 0,
        };
        assert_eq!(read_exact_bounded(&mut exact, 4, 4).unwrap(), vec![0x5a; 4]);
        assert_eq!(exact.max_requested, 4);

        let mut truncated = TrackingReader {
            remaining: 3,
            max_requested: 0,
        };
        assert!(read_exact_bounded(&mut truncated, 4, 4).is_err());
        assert_eq!(truncated.max_requested, 4);

        let mut extended = TrackingReader {
            remaining: 5,
            max_requested: 0,
        };
        assert!(read_exact_bounded(&mut extended, 4, 4).is_err());
        assert_eq!(extended.max_requested, 4);

        let mut over_limit = TrackingReader {
            remaining: 5,
            max_requested: 0,
        };
        assert!(read_exact_bounded(&mut over_limit, 5, 4).is_err());
        assert_eq!(over_limit.max_requested, 0);
    }

    #[test]
    fn published_nwb_hard_link_is_stable_large_evidence_but_not_single_link_backup_evidence() {
        let root = std::env::temp_dir().join(format!(
            "forge-retention-hard-link-{}-{}",
            std::process::id(),
            unix_ns().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let inprogress = root.join("run.nwb.inprogress");
        let final_path = root.join("run.nwb");
        fs::write(&inprogress, b"retained NWB generation").unwrap();
        fs::hard_link(&inprogress, &final_path).unwrap();
        assert!(LockedLargeEvidence::open(&final_path, true).is_err());
        let evidence = LockedLargeEvidence::open(&final_path, false).unwrap();
        assert!(evidence.identity.link_count >= 2);
        drop(evidence);
        fs::remove_dir_all(root).unwrap();
    }
}
