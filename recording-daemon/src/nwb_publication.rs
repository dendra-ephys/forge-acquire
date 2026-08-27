//! Owner-only, same-directory NWB publication transaction.
//!
//! Publication uses a no-overwrite hard link so the final name appears
//! atomically and can be recovered idempotently if the process exits before
//! the publication receipt is committed. Publication has no authority to
//! delete or rename validation-bundle evidence, including `.nwb.inprogress`.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use forge_protocol_v1::{crc32c, sha256, Hash32, Id16, PROTOCOL_HASH};
use serde_json::Value;

use crate::nwb_receipt::{
    sha256_file, verify_nwb_validation_bundle_for_publication, NwbGenerationValidationReceiptV1,
    NwbValidationBundlePaths, NWB_RECEIPT_CONTRACT_HASH,
};
use crate::run_ledger::{DurableRunService, DurableRunStatus};

pub const NWB_PUBLICATION_RECEIPT_LEN: usize = 352;
pub const NWB_PUBLICATION_CONTRACT_HASH_HEX: &str =
    "1fdeeb7fc6fbae051954e5076f075f7d00279fec664b5262dba6f81ba11c236a";
pub const NWB_PUBLICATION_CONTRACT_HASH: Hash32 = [
    0x1f, 0xde, 0xeb, 0x7f, 0xc6, 0xfb, 0xae, 0x05, 0x19, 0x54, 0xe5, 0x07, 0x6f, 0x07, 0x5f, 0x7d,
    0x00, 0x27, 0x9f, 0xec, 0x66, 0x4b, 0x52, 0x62, 0xdb, 0xa6, 0xf8, 0x1b, 0xa1, 0x1c, 0x23, 0x6a,
];
pub const REQUIRED_PUBLICATION_FLAGS: u32 = 0x0000_0007;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NwbGenerationPublicationReceiptV1 {
    pub publication_flags: u32,
    pub run_id: Id16,
    pub generation: u32,
    pub published_at_unix_ns: u64,
    pub nwb_bytes: u64,
    pub validation_sequence: u64,
    pub host_protocol_hash: Hash32,
    pub validation_receipt_contract_hash: Hash32,
    pub validation_receipt_sha256: Hash32,
    pub nwb_sha256: Hash32,
    pub final_path_sha256: Hash32,
    pub publication_contract_hash: Hash32,
    pub owner_validation_evidence_sha256: Hash32,
}

impl NwbGenerationPublicationReceiptV1 {
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != NWB_PUBLICATION_RECEIPT_LEN
            || bytes.get(0..8) != Some(b"FGRPUB01")
            || le_u16(bytes, 8)? != 1
            || usize::from(le_u16(bytes, 10)?) != NWB_PUBLICATION_RECEIPT_LEN
            || le_u32(bytes, 36)? != 0
            || bytes[320..348].iter().any(|byte| *byte != 0)
            || le_u32(bytes, 348)? != crc32c(&bytes[..348])
        {
            return Err(invalid_receipt("header, reserved bytes, or CRC is invalid"));
        }
        let value = Self {
            publication_flags: le_u32(bytes, 12)?,
            run_id: array(bytes, 16)?,
            generation: le_u32(bytes, 32)?,
            published_at_unix_ns: le_u64(bytes, 40)?,
            nwb_bytes: le_u64(bytes, 48)?,
            validation_sequence: le_u64(bytes, 56)?,
            host_protocol_hash: array(bytes, 64)?,
            validation_receipt_contract_hash: array(bytes, 96)?,
            validation_receipt_sha256: array(bytes, 128)?,
            nwb_sha256: array(bytes, 160)?,
            final_path_sha256: array(bytes, 192)?,
            publication_contract_hash: array(bytes, 224)?,
            owner_validation_evidence_sha256: array(bytes, 256)?,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn encode(&self) -> io::Result<[u8; NWB_PUBLICATION_RECEIPT_LEN]> {
        self.validate()?;
        let mut bytes = [0_u8; NWB_PUBLICATION_RECEIPT_LEN];
        bytes[0..8].copy_from_slice(b"FGRPUB01");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&(NWB_PUBLICATION_RECEIPT_LEN as u16).to_le_bytes());
        bytes[12..16].copy_from_slice(&self.publication_flags.to_le_bytes());
        bytes[16..32].copy_from_slice(&self.run_id);
        bytes[32..36].copy_from_slice(&self.generation.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.published_at_unix_ns.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.nwb_bytes.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.validation_sequence.to_le_bytes());
        for (offset, hash) in [
            (64, self.host_protocol_hash),
            (96, self.validation_receipt_contract_hash),
            (128, self.validation_receipt_sha256),
            (160, self.nwb_sha256),
            (192, self.final_path_sha256),
            (224, self.publication_contract_hash),
            (256, self.owner_validation_evidence_sha256),
        ] {
            bytes[offset..offset + 32].copy_from_slice(&hash);
        }
        let checksum = crc32c(&bytes[..348]);
        bytes[348..352].copy_from_slice(&checksum.to_le_bytes());
        Ok(bytes)
    }

    fn validate(&self) -> io::Result<()> {
        let hashes = [
            self.host_protocol_hash,
            self.validation_receipt_contract_hash,
            self.validation_receipt_sha256,
            self.nwb_sha256,
            self.final_path_sha256,
            self.publication_contract_hash,
            self.owner_validation_evidence_sha256,
        ];
        if self.publication_flags != REQUIRED_PUBLICATION_FLAGS
            || !self.run_id.iter().any(|byte| *byte != 0)
            || self.generation == 0
            || self.published_at_unix_ns == 0
            || self.nwb_bytes == 0
            || self.validation_sequence == 0
            || hashes
                .iter()
                .any(|hash| !hash.iter().any(|byte| *byte != 0))
            || self.host_protocol_hash != PROTOCOL_HASH
            || self.validation_receipt_contract_hash != NWB_RECEIPT_CONTRACT_HASH
            || self.publication_contract_hash != NWB_PUBLICATION_CONTRACT_HASH
            || self.owner_validation_evidence_sha256
                != owner_evidence_hash(
                    self.validation_receipt_sha256,
                    self.nwb_sha256,
                    self.final_path_sha256,
                )
        {
            return Err(invalid_receipt("semantic invariant failed"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedNwbGeneration {
    pub receipt: NwbGenerationPublicationReceiptV1,
    pub final_path: PathBuf,
    pub publication_receipt_path: PathBuf,
    pub inprogress_retained: bool,
}

pub fn publish_nwb_generation(
    validation_paths: &NwbValidationBundlePaths,
    publication_receipt_path: impl AsRef<Path>,
) -> io::Result<PublishedNwbGeneration> {
    let validation =
        NwbGenerationValidationReceiptV1::decode(&std::fs::read(&validation_paths.receipt)?)?;
    let final_path = final_path_from_manifest(&validation_paths.session_manifest)?;
    let receipt_path = publication_receipt_path.as_ref().to_path_buf();
    require_publication_paths(validation_paths, &final_path, &receipt_path)?;

    if receipt_path.exists() {
        return verify_existing_publication(
            validation_paths,
            &final_path,
            &receipt_path,
            &validation,
        );
    }

    let verified = verify_nwb_validation_bundle_for_publication(validation_paths, true)?;
    if verified.final_path != final_path || verified.receipt != validation {
        return Err(invalid_publication(
            "manifest or validation receipt changed during publication preflight",
        ));
    }

    if final_path.exists() {
        require_final_matches(&final_path, &verified.receipt)?;
    } else {
        std::fs::hard_link(&validation_paths.nwb_inprogress, &final_path)?;
    }
    OpenOptions::new()
        .write(true)
        .open(&final_path)?
        .sync_all()?;
    require_final_matches(&final_path, &verified.receipt)?;

    let receipt = publication_receipt(validation_paths, &final_path, &verified.receipt)?;
    atomic_write_no_overwrite(&receipt_path, &receipt.encode()?)?;
    let published = verify_existing_publication(
        validation_paths,
        &final_path,
        &receipt_path,
        &verified.receipt,
    )?;
    Ok(published)
}

pub fn finalize_nwb_publication(
    run_ledger_path: impl AsRef<Path>,
    publication_receipt_path: impl AsRef<Path>,
) -> io::Result<DurableRunStatus> {
    let bytes = std::fs::read(publication_receipt_path)?;
    let receipt = NwbGenerationPublicationReceiptV1::decode(&bytes)?;
    let mut ledger = DurableRunService::open(run_ledger_path)?;
    ledger.mark_nwb_published(receipt.run_id, sha256(&bytes))?;
    Ok(ledger.status())
}

fn final_path_from_manifest(path: &Path) -> io::Result<PathBuf> {
    let manifest: Value = serde_json::from_reader(File::open(path)?)
        .map_err(|error| invalid_publication(format!("invalid manifest JSON: {error}")))?;
    manifest
        .get("final_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| invalid_publication("manifest final_path is missing or not a string"))
}

fn verify_existing_publication(
    validation_paths: &NwbValidationBundlePaths,
    final_path: &Path,
    receipt_path: &Path,
    validation: &NwbGenerationValidationReceiptV1,
) -> io::Result<PublishedNwbGeneration> {
    let receipt = NwbGenerationPublicationReceiptV1::decode(&std::fs::read(receipt_path)?)?;
    let expected_path_hash = final_path_hash(final_path)?;
    if receipt.run_id != validation.run_id
        || receipt.generation != validation.generation
        || receipt.nwb_bytes != validation.nwb_bytes
        || receipt.validation_sequence != validation.validation_sequence
        || receipt.validation_receipt_sha256 != sha256_file(&validation_paths.receipt)?
        || receipt.nwb_sha256 != validation.nwb_sha256
        || receipt.final_path_sha256 != expected_path_hash
    {
        return Err(invalid_publication("publication receipt identity differs"));
    }
    require_final_matches(final_path, validation)?;
    Ok(PublishedNwbGeneration {
        receipt,
        final_path: final_path.to_path_buf(),
        publication_receipt_path: receipt_path.to_path_buf(),
        inprogress_retained: validation_paths.nwb_inprogress.exists(),
    })
}

fn publication_receipt(
    validation_paths: &NwbValidationBundlePaths,
    final_path: &Path,
    validation: &NwbGenerationValidationReceiptV1,
) -> io::Result<NwbGenerationPublicationReceiptV1> {
    let validation_receipt_sha256 = sha256_file(&validation_paths.receipt)?;
    let final_path_sha256 = final_path_hash(final_path)?;
    Ok(NwbGenerationPublicationReceiptV1 {
        publication_flags: REQUIRED_PUBLICATION_FLAGS,
        run_id: validation.run_id,
        generation: validation.generation,
        published_at_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid_publication("system clock precedes Unix epoch"))?
            .as_nanos()
            .try_into()
            .map_err(|_| invalid_publication("publication timestamp overflows u64"))?,
        nwb_bytes: validation.nwb_bytes,
        validation_sequence: validation.validation_sequence,
        host_protocol_hash: PROTOCOL_HASH,
        validation_receipt_contract_hash: NWB_RECEIPT_CONTRACT_HASH,
        validation_receipt_sha256,
        nwb_sha256: validation.nwb_sha256,
        final_path_sha256,
        publication_contract_hash: NWB_PUBLICATION_CONTRACT_HASH,
        owner_validation_evidence_sha256: owner_evidence_hash(
            validation_receipt_sha256,
            validation.nwb_sha256,
            final_path_sha256,
        ),
    })
}

fn require_publication_paths(
    validation_paths: &NwbValidationBundlePaths,
    final_path: &Path,
    receipt_path: &Path,
) -> io::Result<()> {
    let inprogress = &validation_paths.nwb_inprogress;
    if !final_path.is_absolute()
        || !receipt_path.is_absolute()
        || final_path == inprogress
        || receipt_path == inprogress
        || receipt_path == final_path
    {
        return Err(invalid_publication(
            "publication paths are not distinct absolute paths",
        ));
    }
    let inprogress_parent = inprogress
        .parent()
        .ok_or_else(|| invalid_publication("in-progress path has no parent"))?;
    let final_parent = final_path
        .parent()
        .ok_or_else(|| invalid_publication("final path has no parent"))?;
    let receipt_parent = receipt_path
        .parent()
        .ok_or_else(|| invalid_publication("receipt path has no parent"))?;
    if std::fs::canonicalize(inprogress_parent)? != std::fs::canonicalize(final_parent)?
        || std::fs::canonicalize(final_parent)? != std::fs::canonicalize(receipt_parent)?
    {
        return Err(invalid_publication(
            "in-progress, final, and receipt paths must share one existing directory",
        ));
    }
    for (label, evidence_path) in [
        ("journal", &validation_paths.journal),
        ("journal seal", &validation_paths.journal_seal),
        ("checkpoint A", &validation_paths.checkpoint_a),
        ("checkpoint B", &validation_paths.checkpoint_b),
        ("validation receipt", &validation_paths.receipt),
        ("session manifest", &validation_paths.session_manifest),
        ("validation report", &validation_paths.validation_report),
    ] {
        if paths_alias(inprogress, evidence_path)? {
            return Err(invalid_publication(format!(
                "in-progress input aliases validation-bundle {label}"
            )));
        }
    }
    Ok(())
}

fn paths_alias(left: &Path, right: &Path) -> io::Result<bool> {
    if left == right {
        return Ok(true);
    }
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => Ok(left == right),
        // A historical idempotent retry may have no in-progress alias.  It is
        // not an evidence deletion operation, and a missing path cannot be a
        // canonical alias of an existing bundle file.
        (Err(_), _) | (_, Err(_)) => Ok(false),
    }
}

fn require_final_matches(
    final_path: &Path,
    validation: &NwbGenerationValidationReceiptV1,
) -> io::Result<()> {
    if std::fs::metadata(final_path)?.len() != validation.nwb_bytes
        || sha256_file(final_path)? != validation.nwb_sha256
    {
        return Err(invalid_publication(
            "existing final NWB differs from validated generation",
        ));
    }
    Ok(())
}

fn final_path_hash(path: &Path) -> io::Result<Hash32> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid_publication("final path is not UTF-8"))?;
    Ok(sha256(text.as_bytes()))
}

fn owner_evidence_hash(
    validation_receipt_sha256: Hash32,
    nwb_sha256: Hash32,
    final_path_sha256: Hash32,
) -> Hash32 {
    let mut evidence = Vec::with_capacity(12 + 96);
    evidence.extend_from_slice(b"FGRNWBOWNER1");
    evidence.extend_from_slice(&validation_receipt_sha256);
    evidence.extend_from_slice(&nwb_sha256);
    evidence.extend_from_slice(&final_path_sha256);
    sha256(&evidence)
}

fn atomic_write_no_overwrite(path: &Path, data: &[u8]) -> io::Result<()> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid_publication("system clock precedes Unix epoch"))?
        .as_nanos();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid_publication("publication receipt filename is not UTF-8"))?;
    let pending = path.with_file_name(format!(
        ".{file_name}.pending-{}-{stamp}",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&pending)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::hard_link(&pending, path)
    })();
    let _ = std::fs::remove_file(&pending);
    result
}

fn invalid_receipt(reason: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("NWB publication receipt: {reason}"),
    )
}

fn invalid_publication(reason: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("NWB publication: {}", reason.into()),
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
    use crate::journal::{seal_evidence_hash, JournalIdentity, JournalWriter};
    use crate::nwb_receipt::{
        NwbGenerationValidationReceiptV1, NWB_RECEIPT_LEN, REQUIRED_VALIDATION_FLAGS,
    };
    use crate::source::{DeterministicReplayConfig, DeterministicReplaySource};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestBundle {
        directory: PathBuf,
        paths: NwbValidationBundlePaths,
        publication_receipt: PathBuf,
        final_path: PathBuf,
    }

    impl Drop for TestBundle {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn canonical_json_hash(value: &Value) -> Hash32 {
        let mut encoded = serde_json::to_vec(value).unwrap();
        encoded.push(b'\n');
        sha256(&encoded)
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            text.push(char::from(DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        text
    }

    fn checkpoint_set_hash(paths: &NwbValidationBundlePaths) -> Hash32 {
        let mut digest = sha2::Sha256::new();
        use sha2::Digest as _;
        digest.update(b"ForgeDurableCheckpointSetV1\0");
        for (label, path) in [
            ("checkpoint-a", &paths.checkpoint_a),
            ("checkpoint-b", &paths.checkpoint_b),
        ] {
            digest.update(label.as_bytes());
            digest.update(std::fs::metadata(path).unwrap().len().to_le_bytes());
            digest.update(std::fs::read(path).unwrap());
        }
        digest.finalize().into()
    }

    fn encode_validation_receipt(
        value: &NwbGenerationValidationReceiptV1,
    ) -> [u8; NWB_RECEIPT_LEN] {
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
        let checksum = crc32c(&bytes[..540]);
        bytes[540..544].copy_from_slice(&checksum.to_le_bytes());
        bytes
    }

    fn valid_bundle() -> TestBundle {
        let directory = std::env::temp_dir().join(format!(
            "forge-nwb-publication-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let journal = directory.join("run.wal");
        let nwb = directory.join("run.g0001.nwb.inprogress");
        let manifest_path = directory.join("run.materialization.json");
        let report_path = directory.join("run.validation.json");
        let receipt_path = directory.join("run.validation.bin");
        let publication_receipt = directory.join("run.publication.bin");
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
            "run_id": "41414141-4141-4141-4141-414141414141",
            "generation": 1,
            "protocol_contract_hash": hex(&PROTOCOL_HASH),
            "journal_path": journal.to_string_lossy(),
            "inprogress_path": nwb.to_string_lossy(),
            "final_path": final_path.to_string_lossy(),
            "pods": [{"canonical_pod_id": hex(&pod_id), "channel_count": 2}],
            "materializer_build_sha256": hex(&build_hash),
        });
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let paths = NwbValidationBundlePaths::for_generation(
            &receipt_path,
            &journal,
            &nwb,
            &manifest_path,
            &report_path,
        );
        let dependency_lock = serde_json::json!({"HDF5-runtime": "2.1.0", "PyNWB": "4.1.0"});
        let samples = serde_json::json!({hex(&pod_id): 2});
        let report = serde_json::json!({
            "schema": "forge.nwb-generation-validation-report.v1",
            "receipt_contract_hash": hex(&NWB_RECEIPT_CONTRACT_HASH),
            "host_protocol_hash": hex(&PROTOCOL_HASH),
            "run_id": "41414141-4141-4141-4141-414141414141",
            "generation": 1,
            "validation_sequence": 1,
            "manifest_path": manifest_path.to_string_lossy(),
            "manifest_sha256": hex(&sha256_file(&manifest_path).unwrap()),
            "journal_path": journal.to_string_lossy(),
            "journal_sha256": hex(&sha256_file(&journal).unwrap()),
            "journal_seal_sha256": hex(&sha256_file(&paths.journal_seal).unwrap()),
            "nwb_inprogress_path": nwb.to_string_lossy(),
            "materialized_chunks": 1,
            "expected_last_journal_sequence": 0,
            "dependency_lock": dependency_lock,
            "materializer_build_sha256": hex(&build_hash),
            "schema_plan_sha256": hex(&schema_hash),
            "observation": {
                "run_id": "41414141-4141-4141-4141-414141414141",
                "generation": 1,
                "nwb_sha256": hex(&sha256_file(&nwb).unwrap()),
                "checked_journal_records": 1,
                "checked_sample_blocks": 1,
                "samples_per_canonical_pod": samples,
                "raw_sample_bytes_checked": 8,
                "raw_sample_blocks_per_canonical_pod": {hex(&pod_id): 1},
                "raw_sample_sha256_per_canonical_pod": {hex(&pod_id): "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                "schema_errors": [], "inspector_critical": [], "reconciliation_errors": [],
                "raw_sample_byte_equality_checked": true, "passed": true,
                "publication_authorized": false
            },
            "raw_sample_byte_equality_checked": true,
            "publication_authorized": false
        });
        std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
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
            durable_checkpoint_set_sha256: checkpoint_set_hash(&paths),
            nwb_sha256: sha256_file(&nwb).unwrap(),
            schema_plan_sha256: schema_hash,
            dependency_lock_sha256: canonical_json_hash(report.get("dependency_lock").unwrap()),
            materializer_build_sha256: build_hash,
            validation_report_sha256: sha256_file(&report_path).unwrap(),
            samples_manifest_sha256: canonical_json_hash(
                report["observation"]
                    .get("samples_per_canonical_pod")
                    .unwrap(),
            ),
            session_manifest_sha256: sha256_file(&manifest_path).unwrap(),
            run_ledger_seal_evidence_sha256: seal_evidence_hash(
                run_id,
                scan.seal.as_ref().unwrap(),
            ),
            validation_sequence: 1,
        };
        std::fs::write(&receipt_path, encode_validation_receipt(&receipt)).unwrap();
        TestBundle {
            directory,
            paths,
            publication_receipt,
            final_path,
        }
    }

    fn sample_receipt() -> NwbGenerationPublicationReceiptV1 {
        let validation_receipt_sha256 = [0x31; 32];
        let nwb_sha256 = [0x32; 32];
        let final_path_sha256 = [0x33; 32];
        NwbGenerationPublicationReceiptV1 {
            publication_flags: REQUIRED_PUBLICATION_FLAGS,
            run_id: [0x21; 16],
            generation: 1,
            published_at_unix_ns: 1,
            nwb_bytes: 4096,
            validation_sequence: 1,
            host_protocol_hash: PROTOCOL_HASH,
            validation_receipt_contract_hash: NWB_RECEIPT_CONTRACT_HASH,
            validation_receipt_sha256,
            nwb_sha256,
            final_path_sha256,
            publication_contract_hash: NWB_PUBLICATION_CONTRACT_HASH,
            owner_validation_evidence_sha256: owner_evidence_hash(
                validation_receipt_sha256,
                nwb_sha256,
                final_path_sha256,
            ),
        }
    }

    fn refresh_crc(bytes: &mut [u8]) {
        let checksum = crc32c(&bytes[..348]);
        bytes[348..352].copy_from_slice(&checksum.to_le_bytes());
    }

    #[test]
    fn frozen_contract_hash_and_receipt_round_trip() {
        let contract = include_str!("../schema/forge_nwb_publication_receipt_v1.idl")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert!(contract.ends_with('\n'));
        assert_eq!(sha256(contract.as_bytes()), NWB_PUBLICATION_CONTRACT_HASH);
        let value = sample_receipt();
        let encoded = value.encode().unwrap();
        assert_eq!(
            NwbGenerationPublicationReceiptV1::decode(&encoded).unwrap(),
            value
        );
    }

    #[test]
    fn every_truncation_and_raw_byte_mutation_is_rejected() {
        let encoded = sample_receipt().encode().unwrap();
        for length in 0..encoded.len() {
            assert!(NwbGenerationPublicationReceiptV1::decode(&encoded[..length]).is_err());
        }
        for offset in 0..encoded.len() {
            let mut mutated = encoded;
            mutated[offset] ^= 0x80;
            assert!(NwbGenerationPublicationReceiptV1::decode(&mutated).is_err());
        }
    }

    #[test]
    fn crc_valid_semantic_mutations_are_rejected() {
        for offset in [12_usize, 32, 64, 96, 224, 256, 320] {
            let mut mutated = sample_receipt().encode().unwrap();
            mutated[offset] ^= 1;
            refresh_crc(&mut mutated);
            assert!(NwbGenerationPublicationReceiptV1::decode(&mutated).is_err());
        }
    }

    #[test]
    fn fresh_and_idempotent_publication_retain_the_inprogress_input() {
        let bundle = valid_bundle();
        let before = sha256_file(&bundle.paths.nwb_inprogress).unwrap();
        let fresh = publish_nwb_generation(&bundle.paths, &bundle.publication_receipt).unwrap();
        assert!(fresh.inprogress_retained);
        assert!(bundle.paths.nwb_inprogress.exists());
        assert_eq!(sha256_file(&bundle.paths.nwb_inprogress).unwrap(), before);
        assert_eq!(sha256_file(&bundle.final_path).unwrap(), before);
        assert_eq!(
            NwbGenerationPublicationReceiptV1::decode(
                &std::fs::read(&bundle.publication_receipt).unwrap()
            )
            .unwrap(),
            fresh.receipt
        );

        let retry = publish_nwb_generation(&bundle.paths, &bundle.publication_receipt).unwrap();
        assert!(retry.inprogress_retained);
        assert!(bundle.paths.nwb_inprogress.exists());
        assert_eq!(sha256_file(&bundle.paths.nwb_inprogress).unwrap(), before);
    }

    #[test]
    fn publication_rejects_every_validation_bundle_evidence_alias_without_mutation() {
        let bundle = valid_bundle();
        publish_nwb_generation(&bundle.paths, &bundle.publication_receipt).unwrap();
        for (label, evidence_path) in [
            ("journal", &bundle.paths.journal),
            ("seal", &bundle.paths.journal_seal),
            ("checkpoint-a", &bundle.paths.checkpoint_a),
            ("checkpoint-b", &bundle.paths.checkpoint_b),
            ("validation-receipt", &bundle.paths.receipt),
            ("manifest", &bundle.paths.session_manifest),
            ("report", &bundle.paths.validation_report),
        ] {
            let bytes = std::fs::read(evidence_path).unwrap();
            let hash = sha256_file(evidence_path).unwrap();
            let mut retry_paths = bundle.paths.clone();
            retry_paths.nwb_inprogress = evidence_path.to_path_buf();
            assert!(
                publish_nwb_generation(&retry_paths, &bundle.publication_receipt).is_err(),
                "{label} alias was accepted"
            );
            assert!(evidence_path.exists(), "{label} was removed");
            assert_eq!(
                std::fs::read(evidence_path).unwrap(),
                bytes,
                "{label} changed"
            );
            assert_eq!(
                sha256_file(evidence_path).unwrap(),
                hash,
                "{label} hash changed"
            );
        }
    }

    #[test]
    fn publication_source_contains_no_inprogress_cleanup_operation() {
        let source = include_str!("nwb_publication.rs");
        assert!(!source.contains(&["remove_inprogress_", "alias"].concat()));
    }
}
