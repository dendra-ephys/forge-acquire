//! Frozen parser for the Python materializer's NWB validation receipt.
//!
//! The receipt is an observation, not publication authority.  The Rust owner
//! must still independently verify every bound file hash and the Run ledger's
//! journal-seal evidence before it may publish an NWB artifact.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use forge_protocol_v1::{crc32c, Hash32, Id16, PROTOCOL_HASH};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::journal::{scan_journal, seal_evidence_hash};

pub const NWB_RECEIPT_LEN: usize = 544;
pub const NWB_RECEIPT_CONTRACT_HASH_HEX: &str =
    "6dfd2230e735b844c6d031aa9a19aa86a14efb98ec54e2076627a76eb4f72f93";
pub const NWB_RECEIPT_CONTRACT_HASH: Hash32 = [
    0x6d, 0xfd, 0x22, 0x30, 0xe7, 0x35, 0xb8, 0x44, 0xc6, 0xd0, 0x31, 0xaa, 0x9a, 0x19, 0xaa, 0x86,
    0xa1, 0x4e, 0xfb, 0x98, 0xec, 0x54, 0xe2, 0x07, 0x66, 0x27, 0xa7, 0x6e, 0xb4, 0xf7, 0x2f, 0x93,
];

pub const REQUIRED_VALIDATION_FLAGS: u32 = 0x0000_00ff;
pub const PUBLICATION_AUTHORIZED: u32 = 0x0000_0100;
pub const EMPTY_EXPECTED_LAST: u64 = u64::MAX;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NwbGenerationValidationReceiptV1 {
    pub validation_flags: u32,
    pub run_id: Id16,
    pub generation: u32,
    pub pod_count: u16,
    pub expected_last_journal_sequence: u64,
    pub checked_blocks: u64,
    pub total_samples: u64,
    pub validated_at_unix_ns: u64,
    pub journal_bytes: u64,
    pub nwb_bytes: u64,
    pub schema_error_count: u32,
    pub inspector_critical_count: u32,
    pub reconciliation_error_count: u32,
    pub host_protocol_hash: Hash32,
    pub receipt_contract_hash: Hash32,
    pub journal_sha256: Hash32,
    pub journal_seal_sha256: Hash32,
    pub durable_checkpoint_set_sha256: Hash32,
    pub nwb_sha256: Hash32,
    pub schema_plan_sha256: Hash32,
    pub dependency_lock_sha256: Hash32,
    pub materializer_build_sha256: Hash32,
    pub validation_report_sha256: Hash32,
    pub samples_manifest_sha256: Hash32,
    pub session_manifest_sha256: Hash32,
    pub run_ledger_seal_evidence_sha256: Hash32,
    pub validation_sequence: u64,
}

impl NwbGenerationValidationReceiptV1 {
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != NWB_RECEIPT_LEN
            || bytes.get(0..8) != Some(b"FGRNWB01")
            || le_u16(bytes, 8)? != 1
            || usize::from(le_u16(bytes, 10)?) != NWB_RECEIPT_LEN
            || le_u16(bytes, 38)? != 0
            || le_u32(bytes, 100)? != 0
            || bytes[528..540].iter().any(|byte| *byte != 0)
            || le_u32(bytes, 540)? != crc32c(&bytes[..540])
        {
            return Err(invalid_receipt("header, reserved bytes, or CRC is invalid"));
        }

        let value = Self {
            validation_flags: le_u32(bytes, 12)?,
            run_id: array(bytes, 16)?,
            generation: le_u32(bytes, 32)?,
            pod_count: le_u16(bytes, 36)?,
            expected_last_journal_sequence: le_u64(bytes, 40)?,
            checked_blocks: le_u64(bytes, 48)?,
            total_samples: le_u64(bytes, 56)?,
            validated_at_unix_ns: le_u64(bytes, 64)?,
            journal_bytes: le_u64(bytes, 72)?,
            nwb_bytes: le_u64(bytes, 80)?,
            schema_error_count: le_u32(bytes, 88)?,
            inspector_critical_count: le_u32(bytes, 92)?,
            reconciliation_error_count: le_u32(bytes, 96)?,
            host_protocol_hash: array(bytes, 104)?,
            receipt_contract_hash: array(bytes, 136)?,
            journal_sha256: array(bytes, 168)?,
            journal_seal_sha256: array(bytes, 200)?,
            durable_checkpoint_set_sha256: array(bytes, 232)?,
            nwb_sha256: array(bytes, 264)?,
            schema_plan_sha256: array(bytes, 296)?,
            dependency_lock_sha256: array(bytes, 328)?,
            materializer_build_sha256: array(bytes, 360)?,
            validation_report_sha256: array(bytes, 392)?,
            samples_manifest_sha256: array(bytes, 424)?,
            session_manifest_sha256: array(bytes, 456)?,
            run_ledger_seal_evidence_sha256: array(bytes, 488)?,
            validation_sequence: le_u64(bytes, 520)?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> io::Result<()> {
        let hashes = [
            self.host_protocol_hash,
            self.receipt_contract_hash,
            self.journal_sha256,
            self.journal_seal_sha256,
            self.durable_checkpoint_set_sha256,
            self.nwb_sha256,
            self.schema_plan_sha256,
            self.dependency_lock_sha256,
            self.materializer_build_sha256,
            self.validation_report_sha256,
            self.samples_manifest_sha256,
            self.session_manifest_sha256,
            self.run_ledger_seal_evidence_sha256,
        ];
        let expected_blocks = if self.expected_last_journal_sequence == EMPTY_EXPECTED_LAST {
            0
        } else {
            self.expected_last_journal_sequence
                .checked_add(1)
                .ok_or_else(|| invalid_receipt("expected-last overflows block count"))?
        };
        if !self.run_id.iter().any(|byte| *byte != 0)
            || hashes
                .iter()
                .any(|hash| !hash.iter().any(|byte| *byte != 0))
            || self.host_protocol_hash != PROTOCOL_HASH
            || self.receipt_contract_hash != NWB_RECEIPT_CONTRACT_HASH
            || self.validation_flags != REQUIRED_VALIDATION_FLAGS
            || self.validation_flags & PUBLICATION_AUTHORIZED != 0
            || !(1..=8).contains(&self.pod_count)
            || self.checked_blocks != expected_blocks
            || self.validated_at_unix_ns == 0
            || self.journal_bytes == 0
            || self.nwb_bytes == 0
            || self.validation_sequence == 0
            || self.schema_error_count != 0
            || self.inspector_critical_count != 0
            || self.reconciliation_error_count != 0
        {
            return Err(invalid_receipt("semantic invariant failed"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NwbValidationBundlePaths {
    pub receipt: PathBuf,
    pub journal: PathBuf,
    pub journal_seal: PathBuf,
    pub checkpoint_a: PathBuf,
    pub checkpoint_b: PathBuf,
    pub nwb_inprogress: PathBuf,
    pub session_manifest: PathBuf,
    pub validation_report: PathBuf,
}

impl NwbValidationBundlePaths {
    pub fn for_generation(
        receipt: impl Into<PathBuf>,
        journal: impl Into<PathBuf>,
        nwb_inprogress: impl Into<PathBuf>,
        session_manifest: impl Into<PathBuf>,
        validation_report: impl Into<PathBuf>,
    ) -> Self {
        let journal = journal.into();
        Self {
            receipt: receipt.into(),
            journal_seal: sidecar_path(&journal, ".seal"),
            checkpoint_a: sidecar_path(&journal, ".checkpoint-a"),
            checkpoint_b: sidecar_path(&journal, ".checkpoint-b"),
            journal,
            nwb_inprogress: nwb_inprogress.into(),
            session_manifest: session_manifest.into(),
            validation_report: validation_report.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedNwbGeneration {
    pub receipt: NwbGenerationValidationReceiptV1,
    pub final_path: PathBuf,
    pub publication_authorized: bool,
}

/// Independently verifies a worker-produced NWB validation bundle.
///
/// Success proves that the frozen receipt binds the supplied immutable files,
/// that the journal is durably sealed at the stated sequence, and that the
/// report/manifest identities agree. It deliberately does *not* publish or
/// rename the `.nwb.inprogress` artifact.
pub fn verify_nwb_validation_bundle(
    paths: &NwbValidationBundlePaths,
) -> io::Result<VerifiedNwbGeneration> {
    verify_nwb_validation_bundle_for_publication(paths, false)
}

pub(crate) fn verify_nwb_validation_bundle_for_publication(
    paths: &NwbValidationBundlePaths,
    allow_existing_final: bool,
) -> io::Result<VerifiedNwbGeneration> {
    require_expected_sidecars(paths)?;
    let receipt = NwbGenerationValidationReceiptV1::decode(&std::fs::read(&paths.receipt)?)?;
    let report = read_json(&paths.validation_report)?;
    let manifest = read_json(&paths.session_manifest)?;

    require_hash(
        "journal",
        sha256_file(&paths.journal)?,
        receipt.journal_sha256,
    )?;
    require_hash(
        "journal seal",
        sha256_file(&paths.journal_seal)?,
        receipt.journal_seal_sha256,
    )?;
    require_hash(
        "durable checkpoint set",
        checkpoint_set_hash(paths)?,
        receipt.durable_checkpoint_set_sha256,
    )?;
    require_hash(
        "NWB in-progress artifact",
        sha256_file(&paths.nwb_inprogress)?,
        receipt.nwb_sha256,
    )?;
    require_hash(
        "session manifest",
        sha256_file(&paths.session_manifest)?,
        receipt.session_manifest_sha256,
    )?;
    require_hash(
        "validation report",
        sha256_file(&paths.validation_report)?,
        receipt.validation_report_sha256,
    )?;

    let journal_len = std::fs::metadata(&paths.journal)?.len();
    let nwb_len = std::fs::metadata(&paths.nwb_inprogress)?.len();
    if journal_len != receipt.journal_bytes || nwb_len != receipt.nwb_bytes {
        return Err(invalid_bundle("artifact byte length differs from receipt"));
    }

    let scan = scan_journal(&paths.journal)?;
    let seal = scan
        .seal
        .as_ref()
        .ok_or_else(|| invalid_bundle("journal is not sealed"))?;
    let expected_last = if receipt.expected_last_journal_sequence == EMPTY_EXPECTED_LAST {
        None
    } else {
        Some(receipt.expected_last_journal_sequence)
    };
    if scan.torn_tail
        || scan.identity.run_id != receipt.run_id
        || scan.identity.protocol_contract_hash != PROTOCOL_HASH
        || scan.file_len != receipt.journal_bytes
        || scan.complete_chunks != receipt.checked_blocks
        || scan.last_journal_sequence != expected_last
        || scan.durable.durable_journal_sequence != expected_last
        || scan.durable.durable_valid_len != seal.expected_valid_len
        || seal.expected_last_journal_sequence != expected_last
        || seal.record_count != receipt.checked_blocks
    {
        return Err(invalid_bundle(
            "journal durability or seal identity differs from receipt",
        ));
    }
    require_hash(
        "Run-ledger seal evidence",
        seal_evidence_hash(receipt.run_id, seal),
        receipt.run_ledger_seal_evidence_sha256,
    )?;

    let (final_path, manifest_pod_channels) =
        validate_manifest(paths, &receipt, &manifest, allow_existing_final)?;
    validate_report(paths, &receipt, &report, &manifest_pod_channels)?;
    Ok(VerifiedNwbGeneration {
        receipt,
        final_path,
        publication_authorized: false,
    })
}

fn validate_manifest(
    paths: &NwbValidationBundlePaths,
    receipt: &NwbGenerationValidationReceiptV1,
    manifest: &Value,
    allow_existing_final: bool,
) -> io::Result<(PathBuf, BTreeMap<String, u64>)> {
    let final_path = PathBuf::from(json_str(manifest, "final_path")?);
    if json_str(manifest, "run_id")? != id_string(receipt.run_id)
        || json_u64(manifest, "generation")? != u64::from(receipt.generation)
        || json_str(manifest, "protocol_contract_hash")? != hex(&PROTOCOL_HASH)
        || !paths_equivalent(
            Path::new(json_str(manifest, "journal_path")?),
            &paths.journal,
        )?
        || !paths_equivalent(
            Path::new(json_str(manifest, "inprogress_path")?),
            &paths.nwb_inprogress,
        )?
        || final_path == paths.nwb_inprogress
        || (!allow_existing_final && final_path.exists())
    {
        return Err(invalid_bundle("session manifest identity is inconsistent"));
    }
    require_hash(
        "materializer build",
        parse_hash(json_str(manifest, "materializer_build_sha256")?)?,
        receipt.materializer_build_sha256,
    )?;
    Ok((final_path, manifest_pod_channel_counts(manifest, receipt)?))
}

/// Parse only the manifest facts needed to make the worker's raw-byte
/// observation quantitatively self-consistent.  This is deliberately not an
/// HDF5 decoder: the owner remains a hash-bound bundle verifier, and the
/// worker/ACL boundary remains the source of the raw-sample equality claim.
fn manifest_pod_channel_counts(
    manifest: &Value,
    receipt: &NwbGenerationValidationReceiptV1,
) -> io::Result<BTreeMap<String, u64>> {
    let pods = manifest
        .get("pods")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_bundle("session manifest has no Pod plans"))?;
    if pods.len() != usize::from(receipt.pod_count) {
        return Err(invalid_bundle(
            "session manifest Pod count differs from receipt",
        ));
    }
    let mut channels = BTreeMap::new();
    for pod in pods {
        let canonical_pod_id = json_str(pod, "canonical_pod_id")?;
        require_lower_hex(canonical_pod_id, 32, "manifest canonical Pod ID")?;
        let channel_count = json_u64(pod, "channel_count")?;
        if channel_count == 0 {
            return Err(invalid_bundle("manifest Pod channel count must be nonzero"));
        }
        if channels
            .insert(canonical_pod_id.to_owned(), channel_count)
            .is_some()
        {
            return Err(invalid_bundle(
                "session manifest duplicates a canonical Pod ID",
            ));
        }
    }
    Ok(channels)
}

// This owner-side verifier does not parse NWB/HDF5.  Raw-sample equality is a
// hash-bound worker validation-report claim and remains a worker/ACL trust
// boundary until an independent decoder is introduced.
fn validate_report(
    paths: &NwbValidationBundlePaths,
    receipt: &NwbGenerationValidationReceiptV1,
    report: &Value,
    manifest_pod_channels: &BTreeMap<String, u64>,
) -> io::Result<()> {
    let observation = report
        .get("observation")
        .ok_or_else(|| invalid_bundle("validation report has no observation"))?;
    let checks = [
        (
            "report schema",
            json_str(report, "schema")? == "forge.nwb-generation-validation-report.v1",
        ),
        (
            "receipt contract hash",
            json_str(report, "receipt_contract_hash")? == hex(&NWB_RECEIPT_CONTRACT_HASH),
        ),
        (
            "host protocol hash",
            json_str(report, "host_protocol_hash")? == hex(&PROTOCOL_HASH),
        ),
        (
            "report Run ID",
            json_str(report, "run_id")? == id_string(receipt.run_id),
        ),
        (
            "report generation",
            json_u64(report, "generation")? == u64::from(receipt.generation),
        ),
        (
            "validation sequence",
            json_u64(report, "validation_sequence")? == receipt.validation_sequence,
        ),
        (
            "manifest path",
            paths_equivalent(
                Path::new(json_str(report, "manifest_path")?),
                &paths.session_manifest,
            )?,
        ),
        (
            "journal path",
            paths_equivalent(Path::new(json_str(report, "journal_path")?), &paths.journal)?,
        ),
        (
            "NWB path",
            paths_equivalent(
                Path::new(json_str(report, "nwb_inprogress_path")?),
                &paths.nwb_inprogress,
            )?,
        ),
        (
            "materialized chunk count",
            json_u64(report, "materialized_chunks")? == receipt.checked_blocks,
        ),
        (
            "report publication authority",
            report
                .get("publication_authorized")
                .and_then(Value::as_bool)
                == Some(false),
        ),
        (
            "raw-sample equality claim",
            report
                .get("raw_sample_byte_equality_checked")
                .and_then(Value::as_bool)
                == Some(true),
        ),
        (
            "observation raw-sample equality",
            observation
                .get("raw_sample_byte_equality_checked")
                .and_then(Value::as_bool)
                == Some(true),
        ),
        (
            "observation Run ID",
            json_str(observation, "run_id")? == id_string(receipt.run_id),
        ),
        (
            "observation generation",
            json_u64(observation, "generation")? == u64::from(receipt.generation),
        ),
        (
            "observation block count",
            json_u64(observation, "checked_journal_records")? == receipt.checked_blocks,
        ),
        (
            "observation sample-block coverage",
            json_u64(observation, "checked_sample_blocks")? <= receipt.checked_blocks,
        ),
        (
            "observation passed",
            observation.get("passed").and_then(Value::as_bool) == Some(true),
        ),
        (
            "observation publication authority",
            observation
                .get("publication_authorized")
                .and_then(Value::as_bool)
                == Some(false),
        ),
        (
            "schema errors",
            json_array_empty(observation, "schema_errors"),
        ),
        (
            "Inspector critical errors",
            json_array_empty(observation, "inspector_critical"),
        ),
        (
            "reconciliation errors",
            json_array_empty(observation, "reconciliation_errors"),
        ),
    ];
    if let Some((label, _)) = checks.into_iter().find(|(_, passed)| !passed) {
        return Err(invalid_bundle(format!(
            "validation report check failed: {label}"
        )));
    }

    let expected_last = report.get("expected_last_journal_sequence");
    let expected_matches = if receipt.expected_last_journal_sequence == EMPTY_EXPECTED_LAST {
        expected_last == Some(&Value::Null)
    } else {
        expected_last.and_then(Value::as_u64) == Some(receipt.expected_last_journal_sequence)
    };
    if !expected_matches
        || json_str(report, "manifest_sha256")? != hex(&receipt.session_manifest_sha256)
        || json_str(report, "journal_sha256")? != hex(&receipt.journal_sha256)
        || json_str(report, "journal_seal_sha256")? != hex(&receipt.journal_seal_sha256)
        || json_str(observation, "nwb_sha256")? != hex(&receipt.nwb_sha256)
    {
        return Err(invalid_bundle(
            "validation report hashes or sequence are inconsistent",
        ));
    }

    require_hash(
        "schema plan",
        parse_hash(json_str(report, "schema_plan_sha256")?)?,
        receipt.schema_plan_sha256,
    )?;
    require_hash(
        "materializer build",
        parse_hash(json_str(report, "materializer_build_sha256")?)?,
        receipt.materializer_build_sha256,
    )?;
    require_hash(
        "dependency lock",
        canonical_json_hash(
            report
                .get("dependency_lock")
                .ok_or_else(|| invalid_bundle("validation report has no dependency lock"))?,
        )?,
        receipt.dependency_lock_sha256,
    )?;
    let samples = json_canonical_u64_map(observation, "samples_per_canonical_pod", "sample count")?;
    let blocks = json_canonical_u64_map(
        observation,
        "raw_sample_blocks_per_canonical_pod",
        "raw sample block count",
    )?;
    let digests = json_canonical_digest_map(observation, "raw_sample_sha256_per_canonical_pod")?;
    if samples.keys().ne(blocks.keys())
        || samples.keys().ne(digests.keys())
        || samples.keys().ne(manifest_pod_channels.keys())
        || samples.len() != usize::from(receipt.pod_count)
    {
        return Err(invalid_bundle(
            "per-Pod raw observation maps do not match the manifest",
        ));
    }
    let total_samples = checked_sum(samples.values(), "total sample count")?;
    if total_samples != receipt.total_samples {
        return Err(invalid_bundle("total sample count differs from receipt"));
    }
    let checked_sample_blocks = json_u64(observation, "checked_sample_blocks")?;
    if checked_sum(blocks.values(), "raw sample block count")? != checked_sample_blocks {
        return Err(invalid_bundle(
            "per-Pod raw sample block count differs from observation",
        ));
    }
    let raw_bytes = json_u64(observation, "raw_sample_bytes_checked")?;
    let expected_raw_bytes = samples.iter().try_fold(0_u64, |total, (pod_id, samples)| {
        let channels = manifest_pod_channels
            .get(*pod_id)
            .ok_or_else(|| invalid_bundle("per-Pod observation contains an unknown Pod"))?;
        let pod_bytes = samples
            .checked_mul(*channels)
            .and_then(|value| value.checked_mul(2))
            .ok_or_else(|| invalid_bundle("raw sample byte count overflows"))?;
        total
            .checked_add(pod_bytes)
            .ok_or_else(|| invalid_bundle("raw sample byte count overflows"))
    })?;
    if raw_bytes != expected_raw_bytes {
        return Err(invalid_bundle(
            "raw sample byte count differs from manifest geometry",
        ));
    }
    if total_samples > 0 && (checked_sample_blocks == 0 || raw_bytes == 0) {
        return Err(invalid_bundle(
            "nonempty sample observation has no raw-byte coverage",
        ));
    }
    require_hash(
        "sample manifest",
        canonical_json_hash(
            observation
                .get("samples_per_canonical_pod")
                .ok_or_else(|| invalid_bundle("validation report has no sample manifest"))?,
        )?,
        receipt.samples_manifest_sha256,
    )
}

fn json_canonical_u64_map<'a>(
    value: &'a Value,
    key: &str,
    value_label: &str,
) -> io::Result<BTreeMap<&'a str, u64>> {
    let map = value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_bundle(format!("validation report has no {key}")))?;
    let mut parsed = BTreeMap::new();
    for (pod_id, raw_value) in map {
        require_lower_hex(pod_id, 32, "canonical Pod ID")?;
        let number = raw_value
            .as_u64()
            .ok_or_else(|| invalid_bundle(format!("{value_label} is not an unsigned integer")))?;
        parsed.insert(pod_id.as_str(), number);
    }
    Ok(parsed)
}

fn json_canonical_digest_map<'a>(
    value: &'a Value,
    key: &str,
) -> io::Result<BTreeMap<&'a str, &'a str>> {
    let map = value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_bundle(format!("validation report has no {key}")))?;
    let mut parsed = BTreeMap::new();
    for (pod_id, raw_digest) in map {
        require_lower_hex(pod_id, 32, "canonical Pod ID")?;
        let digest = raw_digest
            .as_str()
            .ok_or_else(|| invalid_bundle("raw sample SHA-256 is not a string"))?;
        require_lower_hex(digest, 64, "raw sample SHA-256")?;
        parsed.insert(pod_id.as_str(), digest);
    }
    Ok(parsed)
}

fn checked_sum<'a>(values: impl IntoIterator<Item = &'a u64>, label: &str) -> io::Result<u64> {
    values.into_iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(*value)
            .ok_or_else(|| invalid_bundle(format!("{label} overflows")))
    })
}

fn require_lower_hex(value: &str, expected_len: usize, label: &str) -> io::Result<()> {
    if value.len() != expected_len
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_bundle(format!(
            "{label} is not lowercase hexadecimal"
        )));
    }
    Ok(())
}

fn require_expected_sidecars(paths: &NwbValidationBundlePaths) -> io::Result<()> {
    if paths.journal_seal != sidecar_path(&paths.journal, ".seal")
        || paths.checkpoint_a != sidecar_path(&paths.journal, ".checkpoint-a")
        || paths.checkpoint_b != sidecar_path(&paths.journal, ".checkpoint-b")
    {
        return Err(invalid_bundle("journal sidecar paths are not canonical"));
    }
    Ok(())
}

fn paths_equivalent(left: &Path, right: &Path) -> io::Result<bool> {
    Ok(std::fs::canonicalize(left)? == std::fs::canonicalize(right)?)
}

fn checkpoint_set_hash(paths: &NwbValidationBundlePaths) -> io::Result<Hash32> {
    let mut digest = Sha256::new();
    digest.update(b"ForgeDurableCheckpointSetV1\0");
    for (label, path) in [
        ("checkpoint-a", &paths.checkpoint_a),
        ("checkpoint-b", &paths.checkpoint_b),
    ] {
        digest.update(label.as_bytes());
        digest.update(std::fs::metadata(path)?.len().to_le_bytes());
        update_digest_from_file(&mut digest, path)?;
    }
    Ok(digest.finalize().into())
}

pub(crate) fn sha256_file(path: &Path) -> io::Result<Hash32> {
    let mut digest = Sha256::new();
    update_digest_from_file(&mut digest, path)?;
    Ok(digest.finalize().into())
}

fn update_digest_from_file(digest: &mut Sha256, path: &Path) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        digest.update(&buffer[..read]);
    }
}

fn read_json(path: &Path) -> io::Result<Value> {
    serde_json::from_reader(File::open(path)?)
        .map_err(|error| invalid_bundle(format!("invalid JSON in {}: {error}", path.display())))
}

fn canonical_json_hash(value: &Value) -> io::Result<Hash32> {
    let mut encoded = serde_json::to_vec(value)
        .map_err(|error| invalid_bundle(format!("cannot canonicalize JSON: {error}")))?;
    encoded.push(b'\n');
    Ok(forge_protocol_v1::sha256(&encoded))
}

fn json_str<'a>(value: &'a Value, key: &str) -> io::Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_bundle(format!("JSON field {key} is not a string")))
}

fn json_u64(value: &Value, key: &str) -> io::Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_bundle(format!("JSON field {key} is not an unsigned integer")))
}

fn json_array_empty(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
}

fn require_hash(label: &str, actual: Hash32, expected: Hash32) -> io::Result<()> {
    if actual != expected {
        return Err(invalid_bundle(format!(
            "{label} SHA-256 differs from receipt"
        )));
    }
    Ok(())
}

fn parse_hash(value: &str) -> io::Result<Hash32> {
    if value.len() != 64 {
        return Err(invalid_bundle("SHA-256 hex length is invalid"));
    }
    let mut hash = [0_u8; 32];
    for (index, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid_bundle("SHA-256 contains non-hexadecimal text"))?;
    }
    Ok(hash)
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn id_string(id: Id16) -> String {
    let raw = hex(&id);
    format!(
        "{}-{}-{}-{}-{}",
        &raw[0..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..32]
    )
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn invalid_bundle(reason: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("NWB validation bundle: {}", reason.into()),
    )
}

fn invalid_receipt(reason: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("NWB validation receipt: {reason}"),
    )
}

fn le_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(array(bytes, offset)?))
}

fn le_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(array(bytes, offset)?))
}

fn le_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(array(bytes, offset)?))
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(|| invalid_receipt("field is truncated"))?
        .try_into()
        .map_err(|_| invalid_receipt("field length is invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{JournalIdentity, JournalWriter};
    use crate::source::{DeterministicReplayConfig, DeterministicReplaySource};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn golden() -> Vec<u8> {
        let text = include_str!("../../workers/golden/nwb_generation_validation_receipt_v1.hex");
        let text = text.trim();
        assert!(text.len().is_multiple_of(2));
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let value = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(value, 16).unwrap()
            })
            .collect()
    }

    fn refresh_crc(bytes: &mut [u8]) {
        let crc = crc32c(&bytes[..540]);
        bytes[540..544].copy_from_slice(&crc.to_le_bytes());
    }

    fn encode_receipt(value: &NwbGenerationValidationReceiptV1) -> [u8; NWB_RECEIPT_LEN] {
        let mut bytes = [0_u8; NWB_RECEIPT_LEN];
        bytes[0..8].copy_from_slice(b"FGRNWB01");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&(NWB_RECEIPT_LEN as u16).to_le_bytes());
        bytes[12..16].copy_from_slice(&value.validation_flags.to_le_bytes());
        bytes[16..32].copy_from_slice(&value.run_id);
        bytes[32..36].copy_from_slice(&value.generation.to_le_bytes());
        bytes[36..38].copy_from_slice(&value.pod_count.to_le_bytes());
        bytes[40..48].copy_from_slice(&value.expected_last_journal_sequence.to_le_bytes());
        bytes[48..56].copy_from_slice(&value.checked_blocks.to_le_bytes());
        bytes[56..64].copy_from_slice(&value.total_samples.to_le_bytes());
        bytes[64..72].copy_from_slice(&value.validated_at_unix_ns.to_le_bytes());
        bytes[72..80].copy_from_slice(&value.journal_bytes.to_le_bytes());
        bytes[80..88].copy_from_slice(&value.nwb_bytes.to_le_bytes());
        bytes[88..92].copy_from_slice(&value.schema_error_count.to_le_bytes());
        bytes[92..96].copy_from_slice(&value.inspector_critical_count.to_le_bytes());
        bytes[96..100].copy_from_slice(&value.reconciliation_error_count.to_le_bytes());
        for (offset, hash) in [
            (104, value.host_protocol_hash),
            (136, value.receipt_contract_hash),
            (168, value.journal_sha256),
            (200, value.journal_seal_sha256),
            (232, value.durable_checkpoint_set_sha256),
            (264, value.nwb_sha256),
            (296, value.schema_plan_sha256),
            (328, value.dependency_lock_sha256),
            (360, value.materializer_build_sha256),
            (392, value.validation_report_sha256),
            (424, value.samples_manifest_sha256),
            (456, value.session_manifest_sha256),
            (488, value.run_ledger_seal_evidence_sha256),
        ] {
            bytes[offset..offset + 32].copy_from_slice(&hash);
        }
        bytes[520..528].copy_from_slice(&value.validation_sequence.to_le_bytes());
        refresh_crc(&mut bytes);
        bytes
    }

    fn unique_directory() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "forge-acqd-nwb-bundle-{}-{stamp}",
            std::process::id()
        ))
    }

    #[test]
    fn python_golden_receipt_decodes_exactly() {
        let value = NwbGenerationValidationReceiptV1::decode(&golden()).unwrap();
        assert_eq!(value.checked_blocks, 4);
        assert_eq!(value.total_samples, 240);
        assert_eq!(value.validation_flags, REQUIRED_VALIDATION_FLAGS);
        assert_eq!(value.host_protocol_hash, PROTOCOL_HASH);
        assert_eq!(value.receipt_contract_hash, NWB_RECEIPT_CONTRACT_HASH);
    }

    #[test]
    fn every_truncation_and_raw_byte_mutation_is_rejected() {
        let encoded = golden();
        for length in 0..encoded.len() {
            assert!(NwbGenerationValidationReceiptV1::decode(&encoded[..length]).is_err());
        }
        for offset in 0..encoded.len() {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 0x80;
            assert!(NwbGenerationValidationReceiptV1::decode(&mutated).is_err());
        }
    }

    #[test]
    fn crc_valid_semantic_mutations_are_rejected() {
        for offset in [12_usize, 88, 104, 136, 528] {
            let mut mutated = golden();
            mutated[offset] ^= 1;
            refresh_crc(&mut mutated);
            assert!(NwbGenerationValidationReceiptV1::decode(&mutated).is_err());
        }
    }

    #[test]
    fn independently_verifies_bound_files_and_rejects_artifact_tamper() {
        let directory = unique_directory();
        std::fs::create_dir(&directory).unwrap();
        let journal = directory.join("run.wal");
        let nwb = directory.join("run.g0001.nwb.inprogress");
        let manifest_path = directory.join("run.materialization.json");
        let report_path = directory.join("run.validation.json");
        let receipt_path = directory.join("run.validation.bin");
        let final_path = directory.join("run.nwb");
        let run_id = [0x41; 16];
        let pod_id = [0x22; 16];

        let mut source = DeterministicReplaySource::new(DeterministicReplayConfig {
            run_id,
            pod_id,
            headstage_id: [0x33; 16],
            channel_layout_id: 7,
            channel_count: 2,
            samples_per_channel: 2,
            sample_rate_hz: 30_000,
            total_records: 1,
            seed: 9,
        })
        .unwrap();
        let mut writer =
            JournalWriter::create(&journal, JournalIdentity::for_run(run_id).unwrap()).unwrap();
        writer
            .append_record(&source.next_encoded_record().unwrap().unwrap())
            .unwrap();
        let scan = writer.seal(Some(0)).unwrap();
        std::fs::write(&nwb, b"synthetic closed NWB generation").unwrap();

        let build_hash = [0x66; 32];
        let schema_hash = [0x55; 32];
        let manifest = serde_json::json!({
            "run_id": id_string(run_id),
            "generation": 1,
            "protocol_contract_hash": hex(&PROTOCOL_HASH),
            "journal_path": journal.to_string_lossy(),
            "inprogress_path": nwb.to_string_lossy(),
            "final_path": final_path.to_string_lossy(),
            "pods": [{"canonical_pod_id": hex(&pod_id), "channel_count": 2}],
            "materializer_build_sha256": hex(&build_hash),
        });
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let dependency_lock = serde_json::json!({
            "HDF5-runtime": "2.1.0",
            "PyNWB": "4.1.0"
        });
        let samples = serde_json::json!({hex(&pod_id): 2});
        let report = serde_json::json!({
            "schema": "forge.nwb-generation-validation-report.v1",
            "receipt_contract_hash": hex(&NWB_RECEIPT_CONTRACT_HASH),
            "host_protocol_hash": hex(&PROTOCOL_HASH),
            "run_id": id_string(run_id),
            "generation": 1,
            "validation_sequence": 1,
            "manifest_path": manifest_path.to_string_lossy(),
            "manifest_sha256": hex(&sha256_file(&manifest_path).unwrap()),
            "journal_path": journal.to_string_lossy(),
            "journal_sha256": hex(&sha256_file(&journal).unwrap()),
            "journal_seal_sha256": hex(&sha256_file(&sidecar_path(&journal, ".seal")).unwrap()),
            "nwb_inprogress_path": nwb.to_string_lossy(),
            "materialized_chunks": 1,
            "expected_last_journal_sequence": 0,
            "dependency_lock": dependency_lock,
            "materializer_build_sha256": hex(&build_hash),
            "schema_plan_sha256": hex(&schema_hash),
            "observation": {
                "run_id": id_string(run_id),
                "generation": 1,
                "nwb_sha256": hex(&sha256_file(&nwb).unwrap()),
                "checked_journal_records": 1,
                "checked_sample_blocks": 1,
                "samples_per_canonical_pod": samples,
                "raw_sample_bytes_checked": 8,
                "raw_sample_blocks_per_canonical_pod": {hex(&pod_id): 1},
                "raw_sample_sha256_per_canonical_pod": {
                    hex(&pod_id): "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                },
                "schema_errors": [],
                "inspector_critical": [],
                "reconciliation_errors": [],
                "raw_sample_byte_equality_checked": true,
                "passed": true,
                "publication_authorized": false
            },
            "raw_sample_byte_equality_checked": true,
            "publication_authorized": false
        });
        std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
        let paths = NwbValidationBundlePaths::for_generation(
            &receipt_path,
            &journal,
            &nwb,
            &manifest_path,
            &report_path,
        );
        let seal = scan.seal.as_ref().unwrap();
        let receipt = NwbGenerationValidationReceiptV1 {
            validation_flags: REQUIRED_VALIDATION_FLAGS,
            run_id,
            generation: 1,
            pod_count: 1,
            expected_last_journal_sequence: 0,
            checked_blocks: 1,
            total_samples: 2,
            validated_at_unix_ns: 1,
            journal_bytes: std::fs::metadata(&journal).unwrap().len(),
            nwb_bytes: std::fs::metadata(&nwb).unwrap().len(),
            schema_error_count: 0,
            inspector_critical_count: 0,
            reconciliation_error_count: 0,
            host_protocol_hash: PROTOCOL_HASH,
            receipt_contract_hash: NWB_RECEIPT_CONTRACT_HASH,
            journal_sha256: sha256_file(&journal).unwrap(),
            journal_seal_sha256: sha256_file(&paths.journal_seal).unwrap(),
            durable_checkpoint_set_sha256: checkpoint_set_hash(&paths).unwrap(),
            nwb_sha256: sha256_file(&nwb).unwrap(),
            schema_plan_sha256: schema_hash,
            dependency_lock_sha256: canonical_json_hash(report.get("dependency_lock").unwrap())
                .unwrap(),
            materializer_build_sha256: build_hash,
            validation_report_sha256: sha256_file(&report_path).unwrap(),
            samples_manifest_sha256: canonical_json_hash(
                report["observation"]
                    .get("samples_per_canonical_pod")
                    .unwrap(),
            )
            .unwrap(),
            session_manifest_sha256: sha256_file(&manifest_path).unwrap(),
            run_ledger_seal_evidence_sha256: seal_evidence_hash(run_id, seal),
            validation_sequence: 1,
        };
        std::fs::write(&receipt_path, encode_receipt(&receipt)).unwrap();

        let verified = verify_nwb_validation_bundle(&paths).unwrap();
        assert_eq!(verified.receipt, receipt);
        assert!(!verified.publication_authorized);
        assert!(!final_path.exists());

        // The receipt binds the report bytes; this focused suite additionally
        // proves that the owner's structural checks reject malformed
        // quantitative observations before a worker claim can be accepted.
        let manifest_pod_channels = manifest_pod_channel_counts(&manifest, &receipt).unwrap();
        assert!(validate_report(&paths, &receipt, &report, &manifest_pod_channels).is_ok());

        let mut missing_bytes = report.clone();
        missing_bytes["observation"]
            .as_object_mut()
            .unwrap()
            .remove("raw_sample_bytes_checked");
        assert!(
            validate_report(&paths, &receipt, &missing_bytes, &manifest_pod_channels,).is_err()
        );

        let mut wrong_key = report.clone();
        for field in [
            "samples_per_canonical_pod",
            "raw_sample_blocks_per_canonical_pod",
            "raw_sample_sha256_per_canonical_pod",
        ] {
            let values = wrong_key["observation"][field].as_object_mut().unwrap();
            let value = values.remove(&hex(&pod_id)).unwrap();
            values.insert("abababababababababababababababab".to_owned(), value);
        }
        assert!(validate_report(&paths, &receipt, &wrong_key, &manifest_pod_channels).is_err());

        let mut wrong_digest = report.clone();
        wrong_digest["observation"]["raw_sample_sha256_per_canonical_pod"][hex(&pod_id)] =
            Value::String("sha256:not-a-lowercase-hex-digest".to_owned());
        assert!(validate_report(&paths, &receipt, &wrong_digest, &manifest_pod_channels,).is_err());

        let mut wrong_sum = report.clone();
        wrong_sum["observation"]["raw_sample_blocks_per_canonical_pod"][hex(&pod_id)] =
            Value::from(0_u64);
        assert!(validate_report(&paths, &receipt, &wrong_sum, &manifest_pod_channels).is_err());

        let mut wrong_bytes = report.clone();
        wrong_bytes["observation"]["raw_sample_bytes_checked"] = Value::from(7_u64);
        assert!(validate_report(&paths, &receipt, &wrong_bytes, &manifest_pod_channels,).is_err());

        let mut overflow = report.clone();
        overflow["observation"]["samples_per_canonical_pod"][hex(&pod_id)] = Value::from(u64::MAX);
        let mut overflow_receipt = receipt.clone();
        overflow_receipt.total_samples = u64::MAX;
        assert!(
            validate_report(&paths, &overflow_receipt, &overflow, &manifest_pod_channels,).is_err()
        );

        let mut tampered = std::fs::read(&nwb).unwrap();
        tampered.push(0xff);
        std::fs::write(&nwb, tampered).unwrap();
        assert!(verify_nwb_validation_bundle(&paths).is_err());
        assert!(!final_path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
