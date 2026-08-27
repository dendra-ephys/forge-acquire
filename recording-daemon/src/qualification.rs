//! Bounded journal-throughput qualification runner.
//!
//! This measures the canonical eight-Pod synthetic source through the journal
//! and stable-watermark path. It deliberately does not claim D3XX, 10GbE, NWB
//! dual-write, power-loss protection, or a hardware release gate.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use forge_protocol_v1::{sha256, RunCommandV1, PROTOCOL_HASH, PROTOCOL_HASH_HEX};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::buffer_pool::BoundedBufferPool;
use crate::journal::{
    scan_journal, seal_evidence_hash, JournalIdentity, JournalScan, JournalWriter,
};
use crate::run::{RunCommand, RunCommandKind, RunState};
use crate::run_ledger::{DurableRunService, FAULT_INTERNAL_PERSISTENCE};
use crate::source::{DeterministicReplayConfig, DeterministicReplaySource};

const JOURNAL_RECORD_OVERHEAD_BYTES: usize = 104;
const RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR: u64 = 190_080_000;
const ENGINEERING_GATE_SECONDS: u64 = 30 * 60;
const RELEASE_GATE_SECONDS: u64 = 24 * 60 * 60;
const RELEASE_GATE_MILLISECONDS: u64 = RELEASE_GATE_SECONDS * 1_000;
const LATENCY_BUCKET_US: u64 = 10;
const LATENCY_BUCKET_COUNT: usize = 4_097;

/// The synthetic source is deliberately explicit.  `active_receiver_pod_128`
/// models the current active-product catalog ceiling; `protocol_max_256` is
/// the conservative protocol envelope required for any journal release gate.
/// They are not interchangeable evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum JournalQualificationSourceProfile {
    #[serde(rename = "active_receiver_pod_128")]
    ActiveReceiverPod128,
    #[serde(rename = "protocol_max_256")]
    ProtocolMax256,
}

impl JournalQualificationSourceProfile {
    pub const fn id(self) -> &'static str {
        match self {
            Self::ActiveReceiverPod128 => "active_receiver_pod_128",
            Self::ProtocolMax256 => "protocol_max_256",
        }
    }

    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "active_receiver_pod_128" => Ok(Self::ActiveReceiverPod128),
            "protocol_max_256" => Ok(Self::ProtocolMax256),
            _ => invalid_input("unknown journal qualification source profile"),
        }
    }

    const fn definition(self) -> SourceProfileDefinition {
        match self {
            Self::ActiveReceiverPod128 => SourceProfileDefinition {
                pod_count: 8,
                channels_per_pod: 128,
                samples_per_block: 30,
                sample_rate_hz: 30_000,
                canonical_record_bytes: 7_888,
                journal_record_bytes: 7_888 + JOURNAL_RECORD_OVERHEAD_BYTES,
                class: "active_receiver_pod",
                target_floor_canonical_bytes_per_second: 63_104_000,
            },
            Self::ProtocolMax256 => SourceProfileDefinition {
                pod_count: 8,
                channels_per_pod: 256,
                samples_per_block: 30,
                sample_rate_hz: 30_000,
                canonical_record_bytes: 15_568,
                journal_record_bytes: 15_568 + JOURNAL_RECORD_OVERHEAD_BYTES,
                class: "protocol_conservative_stress",
                target_floor_canonical_bytes_per_second: RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceProfileDefinition {
    pod_count: usize,
    channels_per_pod: u16,
    samples_per_block: u32,
    sample_rate_hz: u32,
    canonical_record_bytes: usize,
    journal_record_bytes: usize,
    class: &'static str,
    target_floor_canonical_bytes_per_second: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalQualificationOptions {
    pub journal_path: PathBuf,
    pub receipt_path: PathBuf,
    pub duration: Duration,
    pub source_profile: JournalQualificationSourceProfile,
    pub target_canonical_bytes_per_second: u64,
    pub durability_batch_records: u64,
}

impl JournalQualificationOptions {
    fn validate(self) -> io::Result<Self> {
        if self.duration < Duration::from_millis(100)
            || self.duration > Duration::from_secs(RELEASE_GATE_SECONDS + 60)
            || self.target_canonical_bytes_per_second == 0
            || self.durability_batch_records == 0
            || self.journal_path == self.receipt_path
        {
            return invalid_input("invalid journal qualification options");
        }
        let journal_parent = self.journal_path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "journal path has no parent")
        })?;
        let receipt_parent = self.receipt_path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "receipt path has no parent")
        })?;
        if !journal_parent.is_dir() || !receipt_parent.is_dir() {
            return invalid_input("qualification output parents must already exist");
        }
        if self.journal_path.exists() || self.receipt_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "qualification journal or receipt already exists",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct VolumeIdentityV1 {
    pub root: String,
    pub filesystem: String,
    pub serial_hex: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct BuildIdentityV1 {
    pub daemon_version: String,
    pub build_profile: String,
    pub executable_sha256_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct LatencySummaryV1 {
    pub count: u64,
    pub p50_microseconds_upper_bound: u64,
    pub p99_microseconds_upper_bound: u64,
    pub max_microseconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct JournalQualificationEvidenceV2 {
    pub profile_hash_hex: String,
    pub protocol_hash_hex: String,
    pub run_id_hex: String,
    pub build: BuildIdentityV1,
    pub volume: VolumeIdentityV1,
    pub journal_path: String,
    pub journal_sha256_hex: String,
    pub source_profile_id: String,
    pub source_profile_class: String,
    pub source_profile_hash_hex: String,
    pub source_profile_target_floor_canonical_bytes_per_second: u64,
    pub pod_count: usize,
    pub channels_per_pod: u16,
    pub samples_per_block: u32,
    pub sample_rate_hz: u32,
    pub canonical_record_bytes: usize,
    pub journal_record_bytes: usize,
    pub requested_duration_milliseconds: u64,
    pub active_write_microseconds: u64,
    pub terminalization_microseconds: u64,
    pub wall_elapsed_microseconds: u64,
    pub target_canonical_bytes_per_second: u64,
    pub achieved_canonical_bytes_per_second: u64,
    pub achieved_journal_bytes_per_second: u64,
    pub generated_records: u64,
    pub committed_records: u64,
    pub durable_records: u64,
    pub journal_file_bytes: u64,
    pub durability_batch_records: u64,
    pub periodic_durability_barriers: u64,
    pub append_latency: LatencySummaryV1,
    pub periodic_barrier_latency: LatencySummaryV1,
    pub seal_latency_microseconds: u64,
    pub cpu_time_microseconds: Option<u64>,
    pub peak_working_set_bytes: Option<u64>,
    pub sealed: bool,
    pub restart_reopen_verified: bool,
    pub raw_sample_bytes_entered_webview: u64,
    pub hardware_transport_available: bool,
    pub nwb_dual_write_enabled: bool,
    pub release_build: bool,
    pub engineering_duration_gate_met: bool,
    pub release_duration_gate_met: bool,
    pub throughput_target_met: bool,
    pub release_throughput_floor_met: bool,
    pub engineering_journal_gate_passed: bool,
    pub release_journal_gate_passed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct JournalQualificationReceiptV2 {
    pub schema: String,
    pub status: String,
    pub evidence_sha256_hex: String,
    pub evidence: JournalQualificationEvidenceV2,
}

struct LatencyHistogram {
    buckets: [u64; LATENCY_BUCKET_COUNT],
    count: u64,
    max_microseconds: u64,
}

struct QualificationRunOutput {
    scan: JournalScan,
    active_elapsed: Duration,
    wall_elapsed: Duration,
    append_latency: LatencySummaryV1,
    periodic_barrier_latency: LatencySummaryV1,
    seal_latency_microseconds: u64,
    generated_records: u64,
    canonical_bytes: u64,
    durability_barriers: u64,
    process_before: Option<ProcessSample>,
    process_after: Option<ProcessSample>,
    canonical_record_bytes: usize,
}

impl LatencyHistogram {
    fn new() -> Self {
        Self {
            buckets: [0; LATENCY_BUCKET_COUNT],
            count: 0,
            max_microseconds: 0,
        }
    }

    fn observe(&mut self, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros())
            .unwrap_or(u64::MAX)
            .max(1);
        let bucket = usize::try_from(micros.div_ceil(LATENCY_BUCKET_US))
            .unwrap_or(usize::MAX)
            .min(LATENCY_BUCKET_COUNT - 1);
        self.buckets[bucket] = self.buckets[bucket].saturating_add(1);
        self.count = self.count.saturating_add(1);
        self.max_microseconds = self.max_microseconds.max(micros);
    }

    fn summary(&self) -> LatencySummaryV1 {
        LatencySummaryV1 {
            count: self.count,
            p50_microseconds_upper_bound: self.percentile_upper_bound(50, 100),
            p99_microseconds_upper_bound: self.percentile_upper_bound(99, 100),
            max_microseconds: self.max_microseconds,
        }
    }

    fn percentile_upper_bound(&self, numerator: u64, denominator: u64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let target = self.count.saturating_mul(numerator).div_ceil(denominator);
        let mut seen = 0_u64;
        for (index, count) in self.buckets.iter().enumerate() {
            seen = seen.saturating_add(*count);
            if seen >= target {
                return (index as u64).saturating_mul(LATENCY_BUCKET_US);
            }
        }
        self.max_microseconds
    }
}

pub fn run_journal_qualification(
    options: JournalQualificationOptions,
) -> io::Result<JournalQualificationReceiptV2> {
    let options = options.validate()?;
    let volume = volume_identity(&options.journal_path)?;
    let build = build_identity()?;
    let profile_hash = profile_hash(&options, &volume, &build);
    let run_id = fresh_run_id()?;
    let profile_hash_hex = hex(&profile_hash);
    let run_ledger_path = options.journal_path.with_extension("qualification-ledger");
    if run_ledger_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "qualification Run ledger already exists",
        ));
    }
    let mut lifecycle = DurableRunService::open(&run_ledger_path)?;
    for (request_id, kind) in [
        (1, RunCommandKind::Prepare),
        (2, RunCommandKind::Arm),
        (3, RunCommandKind::Start),
    ] {
        let receipt = lifecycle.handle(
            qualification_command(request_id, kind, run_id, profile_hash),
            1,
        )?;
        if !receipt.accepted {
            return Err(io::Error::other(format!(
                "qualification lifecycle rejected {kind:?}: {}",
                receipt.reason
            )));
        }
    }

    let run_result = (|| -> io::Result<QualificationRunOutput> {
        let source = options.source_profile.definition();
        let mut sources = qualification_sources(run_id, options.source_profile)?;
        let canonical_record_bytes = sources[0]
            .next_encoded_record()?
            .ok_or_else(|| io::Error::other("qualification source ended"))?
            .len();
        if canonical_record_bytes != source.canonical_record_bytes {
            return Err(io::Error::other(
                "qualification source profile record geometry mismatch",
            ));
        }
        sources = qualification_sources(run_id, options.source_profile)?;
        let pool = BoundedBufferPool::new(4, source.canonical_record_bytes)?;
        let mut writer =
            JournalWriter::create(&options.journal_path, JournalIdentity::for_run(run_id)?)?;
        let process_before = process_sample();
        let started = Instant::now();
        let mut append_latency = LatencyHistogram::new();
        let mut barrier_latency = LatencyHistogram::new();
        let mut generated_records = 0_u64;
        let mut committed_records = 0_u64;
        let mut canonical_bytes = 0_u64;
        let mut durability_barriers = 0_u64;
        let mut source_index = 0_usize;
        while started.elapsed() < options.duration {
            let encoded = sources[source_index]
                .next_encoded_record()?
                .ok_or_else(|| io::Error::other("qualification source ended unexpectedly"))?;
            source_index = (source_index + 1) % sources.len();
            generated_records = generated_records
                .checked_add(1)
                .ok_or_else(|| io::Error::other("qualification record count overflow"))?;
            canonical_bytes = canonical_bytes
                .checked_add(encoded.len() as u64)
                .ok_or_else(|| io::Error::other("qualification byte count overflow"))?;
            let mut buffer = pool.try_acquire()?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "bounded qualification buffer pool exhausted",
                )
            })?;
            buffer.try_extend_from_slice(&encoded)?;
            let append_started = Instant::now();
            writer.append_record(buffer.as_slice())?;
            append_latency.observe(append_started.elapsed());
            committed_records += 1;
            if committed_records.is_multiple_of(options.durability_batch_records) {
                let barrier_started = Instant::now();
                writer.durability_barrier()?;
                barrier_latency.observe(barrier_started.elapsed());
                durability_barriers += 1;
            }
        }
        let active_elapsed = started.elapsed();
        let stop = lifecycle.handle(
            qualification_command(4, RunCommandKind::Stop, run_id, profile_hash),
            1,
        )?;
        if !stop.accepted {
            return Err(io::Error::other(format!(
                "qualification Stop rejected: {}",
                stop.reason
            )));
        }
        let seal_started = Instant::now();
        let scan = writer.seal(committed_records.checked_sub(1))?;
        let seal_latency_microseconds = u64::try_from(seal_started.elapsed().as_micros())
            .unwrap_or(u64::MAX)
            .max(1);
        let seal = scan
            .seal
            .as_ref()
            .ok_or_else(|| io::Error::other("qualification journal did not seal"))?;
        lifecycle.mark_journal_sealed(seal_evidence_hash(run_id, seal))?;
        Ok(QualificationRunOutput {
            scan,
            active_elapsed,
            wall_elapsed: started.elapsed(),
            append_latency: append_latency.summary(),
            periodic_barrier_latency: barrier_latency.summary(),
            seal_latency_microseconds,
            generated_records,
            canonical_bytes,
            durability_barriers,
            process_before,
            process_after: process_sample(),
            canonical_record_bytes,
        })
    })();
    let output = match run_result {
        Ok(output) => output,
        Err(error) => {
            let evidence_hash =
                sha256(format!("forge-journal-qualification-failed-v1:{error}").as_bytes());
            if let Err(fail_error) =
                lifecycle.fail_closed(FAULT_INTERNAL_PERSISTENCE, evidence_hash)
            {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "qualification failed: {error}; durable fail-closed also failed: {fail_error}"
                    ),
                ));
            }
            return Err(error);
        }
    };
    drop(lifecycle);
    let reopened = DurableRunService::open(&run_ledger_path)?;
    let restart_reopen_verified = reopened.status().state == RunState::JournalSealed
        && !reopened.status().auto_failed_on_restart;
    if !restart_reopen_verified {
        return Err(io::Error::other(
            "qualification Run ledger did not reopen journal-sealed",
        ));
    }
    let active_write_microseconds = u64::try_from(output.active_elapsed.as_micros())
        .unwrap_or(u64::MAX)
        .max(1);
    let wall_elapsed_microseconds = u64::try_from(output.wall_elapsed.as_micros())
        .unwrap_or(u64::MAX)
        .max(active_write_microseconds);
    let terminalization_microseconds =
        wall_elapsed_microseconds.saturating_sub(active_write_microseconds);
    let achieved_canonical = rate_per_second(output.canonical_bytes, active_write_microseconds);
    let achieved_journal = rate_per_second(output.scan.file_len, active_write_microseconds);
    let requested_duration_milliseconds =
        u64::try_from(options.duration.as_millis()).unwrap_or(u64::MAX);
    let elapsed_seconds = output.active_elapsed.as_secs();
    let engineering_duration_gate_met = elapsed_seconds >= ENGINEERING_GATE_SECONDS;
    let release_duration_gate_met = elapsed_seconds >= RELEASE_GATE_SECONDS;
    let throughput_target_met = achieved_canonical
        >= options.target_canonical_bytes_per_second.max(
            options
                .source_profile
                .definition()
                .target_floor_canonical_bytes_per_second,
        );
    let release_build = !cfg!(debug_assertions);
    let source = options.source_profile.definition();
    let release_throughput_floor_met = achieved_canonical
        >= options
            .target_canonical_bytes_per_second
            .max(RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR);
    let evidence = JournalQualificationEvidenceV2 {
        profile_hash_hex,
        protocol_hash_hex: PROTOCOL_HASH_HEX.to_owned(),
        run_id_hex: hex(&run_id),
        build,
        volume,
        journal_path: options.journal_path.to_string_lossy().into_owned(),
        journal_sha256_hex: sha256_file(&options.journal_path)?,
        source_profile_id: options.source_profile.id().to_owned(),
        source_profile_class: source.class.to_owned(),
        source_profile_hash_hex: hex(&source_profile_hash(options.source_profile)),
        source_profile_target_floor_canonical_bytes_per_second: source
            .target_floor_canonical_bytes_per_second,
        pod_count: source.pod_count,
        channels_per_pod: source.channels_per_pod,
        samples_per_block: source.samples_per_block,
        sample_rate_hz: source.sample_rate_hz,
        canonical_record_bytes: output.canonical_record_bytes,
        journal_record_bytes: source.journal_record_bytes,
        requested_duration_milliseconds,
        active_write_microseconds,
        terminalization_microseconds,
        wall_elapsed_microseconds,
        target_canonical_bytes_per_second: options.target_canonical_bytes_per_second,
        achieved_canonical_bytes_per_second: achieved_canonical,
        achieved_journal_bytes_per_second: achieved_journal,
        generated_records: output.generated_records,
        committed_records: output.scan.complete_chunks,
        durable_records: output.scan.durable.durable_record_count,
        journal_file_bytes: output.scan.file_len,
        durability_batch_records: options.durability_batch_records,
        periodic_durability_barriers: output.durability_barriers,
        append_latency: output.append_latency,
        periodic_barrier_latency: output.periodic_barrier_latency,
        seal_latency_microseconds: output.seal_latency_microseconds,
        cpu_time_microseconds: process_delta_cpu(output.process_before, output.process_after),
        peak_working_set_bytes: output
            .process_after
            .and_then(|sample| sample.peak_working_set_bytes),
        sealed: output.scan.seal.is_some(),
        restart_reopen_verified,
        raw_sample_bytes_entered_webview: 0,
        hardware_transport_available: false,
        nwb_dual_write_enabled: false,
        release_build,
        engineering_duration_gate_met,
        release_duration_gate_met,
        throughput_target_met,
        release_throughput_floor_met,
        engineering_journal_gate_passed: engineering_duration_gate_met
            && throughput_target_met
            && release_build,
        release_journal_gate_passed: release_gate_passed(
            options.source_profile,
            requested_duration_milliseconds,
            elapsed_seconds,
            achieved_canonical,
            options.target_canonical_bytes_per_second,
            release_build,
        ),
    };
    if evidence.generated_records != evidence.committed_records
        || evidence.committed_records != evidence.durable_records
        || !evidence.sealed
    {
        return Err(io::Error::other(
            "qualification terminal watermarks do not reconcile",
        ));
    }
    let evidence_bytes = serde_json::to_vec(&evidence).map_err(io::Error::other)?;
    let receipt = JournalQualificationReceiptV2 {
        schema: "forge.journal-qualification-receipt.v2".to_owned(),
        status: if evidence.release_journal_gate_passed {
            "release_journal_gate_passed".to_owned()
        } else if evidence.engineering_journal_gate_passed {
            "engineering_journal_gate_passed".to_owned()
        } else {
            "smoke_only".to_owned()
        },
        evidence_sha256_hex: hex(&sha256(&evidence_bytes)),
        evidence,
    };
    persist_receipt(&options.receipt_path, &receipt)?;
    Ok(receipt)
}

/// Recomputes the immutable receipt binding and reopens the sealed journal.
/// A successful parse alone is never treated as qualification evidence.
pub fn verify_journal_qualification_receipt(
    receipt_path: impl AsRef<Path>,
) -> io::Result<JournalQualificationReceiptV2> {
    let receipt_path = receipt_path.as_ref();
    let bytes = fs::read(receipt_path)?;
    let receipt: JournalQualificationReceiptV2 = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let verifier_build = build_identity()?;
    if receipt.schema != "forge.journal-qualification-receipt.v2"
        || !matches!(
            receipt.status.as_str(),
            "smoke_only" | "engineering_journal_gate_passed" | "release_journal_gate_passed"
        )
        || receipt.evidence.protocol_hash_hex != PROTOCOL_HASH_HEX
        || receipt.evidence.raw_sample_bytes_entered_webview != 0
        || receipt.evidence.hardware_transport_available
        || receipt.evidence.nwb_dual_write_enabled
        || receipt.evidence.release_build != (receipt.evidence.build.build_profile == "release")
        || receipt.evidence.build != verifier_build
        || receipt.evidence.build.daemon_version.is_empty()
        || receipt.evidence.build.executable_sha256_hex.len() != 64
        || receipt.evidence.requested_duration_milliseconds < 100
        || receipt.evidence.requested_duration_milliseconds > (RELEASE_GATE_SECONDS + 60) * 1_000
        || receipt.evidence.target_canonical_bytes_per_second == 0
        || receipt.evidence.durability_batch_records == 0
    {
        return invalid_data("qualification receipt has invalid fixed semantics");
    }
    let source_profile = JournalQualificationSourceProfile::parse(
        &receipt.evidence.source_profile_id,
    )
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "qualification receipt source profile is invalid",
        )
    })?;
    let source = source_profile.definition();
    if receipt.evidence.source_profile_class != source.class
        || receipt.evidence.source_profile_hash_hex != hex(&source_profile_hash(source_profile))
        || receipt.evidence.pod_count != source.pod_count
        || receipt.evidence.channels_per_pod != source.channels_per_pod
        || receipt.evidence.samples_per_block != source.samples_per_block
        || receipt.evidence.sample_rate_hz != source.sample_rate_hz
        || receipt.evidence.canonical_record_bytes != source.canonical_record_bytes
        || receipt.evidence.journal_record_bytes != source.journal_record_bytes
        || receipt
            .evidence
            .source_profile_target_floor_canonical_bytes_per_second
            != source.target_floor_canonical_bytes_per_second
    {
        return invalid_data("qualification receipt source profile geometry mismatch");
    }
    let evidence_bytes = serde_json::to_vec(&receipt.evidence)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if receipt.evidence_sha256_hex != hex(&sha256(&evidence_bytes)) {
        return invalid_data("qualification receipt evidence hash mismatch");
    }
    let journal_path = PathBuf::from(&receipt.evidence.journal_path);
    if sha256_file(&journal_path)? != receipt.evidence.journal_sha256_hex {
        return invalid_data("qualification journal SHA-256 mismatch");
    }
    let scan = scan_journal(&journal_path)?;
    if scan.identity.protocol_contract_hash != PROTOCOL_HASH
        || hex(&scan.identity.run_id) != receipt.evidence.run_id_hex
        || scan.complete_chunks != receipt.evidence.committed_records
        || scan.durable.durable_record_count != receipt.evidence.durable_records
        || scan.file_len != receipt.evidence.journal_file_bytes
        || scan.seal.is_none()
        || scan.torn_tail
        || receipt.evidence.generated_records != receipt.evidence.committed_records
        || receipt.evidence.committed_records != receipt.evidence.durable_records
        || !receipt.evidence.sealed
        || !receipt.evidence.restart_reopen_verified
    {
        return invalid_data("qualification journal and receipt do not reconcile");
    }
    verify_qualification_content_profile(&scan, source)?;
    let current_volume = volume_identity(&journal_path)?;
    if current_volume != receipt.evidence.volume {
        return invalid_data("qualification journal volume identity changed");
    }
    let reconstructed = JournalQualificationOptions {
        journal_path,
        receipt_path: receipt_path.to_path_buf(),
        duration: Duration::from_millis(receipt.evidence.requested_duration_milliseconds),
        source_profile,
        target_canonical_bytes_per_second: receipt.evidence.target_canonical_bytes_per_second,
        durability_batch_records: receipt.evidence.durability_batch_records,
    };
    if hex(&profile_hash(
        &reconstructed,
        &receipt.evidence.volume,
        &receipt.evidence.build,
    )) != receipt.evidence.profile_hash_hex
    {
        return invalid_data("qualification profile hash mismatch");
    }
    if receipt.evidence.wall_elapsed_microseconds
        != receipt
            .evidence
            .active_write_microseconds
            .saturating_add(receipt.evidence.terminalization_microseconds)
    {
        return invalid_data("qualification elapsed-time accounting mismatch");
    }
    let canonical_bytes = receipt
        .evidence
        .committed_records
        .checked_mul(receipt.evidence.canonical_record_bytes as u64)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "qualification byte count overflow",
            )
        })?;
    let expected_canonical_rate =
        rate_per_second(canonical_bytes, receipt.evidence.active_write_microseconds);
    let expected_journal_rate = rate_per_second(
        receipt.evidence.journal_file_bytes,
        receipt.evidence.active_write_microseconds,
    );
    if receipt.evidence.achieved_canonical_bytes_per_second != expected_canonical_rate
        || receipt.evidence.achieved_journal_bytes_per_second != expected_journal_rate
    {
        return invalid_data("qualification derived throughput mismatch");
    }
    let elapsed_seconds = receipt.evidence.active_write_microseconds / 1_000_000;
    let engineering_duration = elapsed_seconds >= ENGINEERING_GATE_SECONDS;
    let release_duration = elapsed_seconds >= RELEASE_GATE_SECONDS;
    let throughput = receipt.evidence.achieved_canonical_bytes_per_second
        >= receipt
            .evidence
            .target_canonical_bytes_per_second
            .max(source.target_floor_canonical_bytes_per_second);
    let release_floor = receipt.evidence.achieved_canonical_bytes_per_second
        >= receipt
            .evidence
            .target_canonical_bytes_per_second
            .max(RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR);
    let expected_release_gate = release_gate_passed(
        source_profile,
        receipt.evidence.requested_duration_milliseconds,
        elapsed_seconds,
        receipt.evidence.achieved_canonical_bytes_per_second,
        receipt.evidence.target_canonical_bytes_per_second,
        receipt.evidence.release_build,
    );
    let expected_status = if expected_release_gate {
        "release_journal_gate_passed"
    } else if engineering_duration && throughput && receipt.evidence.release_build {
        "engineering_journal_gate_passed"
    } else {
        "smoke_only"
    };
    if receipt.evidence.engineering_duration_gate_met != engineering_duration
        || receipt.evidence.release_duration_gate_met != release_duration
        || receipt.evidence.throughput_target_met != throughput
        || receipt.evidence.release_throughput_floor_met != release_floor
        || receipt.evidence.engineering_journal_gate_passed
            != (engineering_duration && throughput && receipt.evidence.release_build)
        || receipt.evidence.release_journal_gate_passed != expected_release_gate
        || receipt.status != expected_status
        || receipt.evidence.append_latency.count != receipt.evidence.committed_records
        || receipt.evidence.periodic_barrier_latency.count
            != receipt.evidence.periodic_durability_barriers
        || receipt.evidence.seal_latency_microseconds == 0
    {
        return invalid_data("qualification receipt gate computation mismatch");
    }
    Ok(receipt)
}

fn verify_qualification_content_profile(
    scan: &JournalScan,
    source: SourceProfileDefinition,
) -> io::Result<()> {
    let profile = &scan.content_profile;
    if profile.non_sample_record_count != 0 || profile.pods.len() != source.pod_count {
        return invalid_data("qualification journal content profile does not match source");
    }
    let mut sample_records = 0_u64;
    let mut minimum_records = u64::MAX;
    let mut maximum_records = 0_u64;
    for (index, pod) in profile.pods.iter().enumerate() {
        let mut expected_pod_id = [0x50; 16];
        expected_pod_id[15] = u8::try_from(index + 1)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Pod index overflow"))?;
        if pod.pod_id != expected_pod_id
            || pod.sample_record_count == 0
            || pod.canonical_record_bytes_min != Some(source.canonical_record_bytes)
            || pod.canonical_record_bytes_max != Some(source.canonical_record_bytes)
            || pod.samples_per_block_min != Some(source.samples_per_block)
            || pod.samples_per_block_max != Some(source.samples_per_block)
            || pod.sample_rate_numerator_hz_min != Some(source.sample_rate_hz)
            || pod.sample_rate_numerator_hz_max != Some(source.sample_rate_hz)
            || pod.sample_rate_denominator_min != Some(1)
            || pod.sample_rate_denominator_max != Some(1)
            || pod.channel_count != Some(source.channels_per_pod)
            || pod.sample_format != Some(1)
        {
            return invalid_data("qualification journal Pod geometry does not match source");
        }
        sample_records = sample_records
            .checked_add(pod.sample_record_count)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "sample count overflow"))?;
        minimum_records = minimum_records.min(pod.sample_record_count);
        maximum_records = maximum_records.max(pod.sample_record_count);
    }
    if sample_records != scan.complete_chunks || maximum_records - minimum_records > 1 {
        return invalid_data("qualification journal Pod record distribution is invalid");
    }
    Ok(())
}

fn release_gate_passed(
    profile: JournalQualificationSourceProfile,
    requested_duration_milliseconds: u64,
    active_elapsed_seconds: u64,
    achieved_canonical_bytes_per_second: u64,
    caller_target_canonical_bytes_per_second: u64,
    release_build: bool,
) -> bool {
    profile == JournalQualificationSourceProfile::ProtocolMax256
        && requested_duration_milliseconds >= RELEASE_GATE_MILLISECONDS
        && active_elapsed_seconds >= RELEASE_GATE_SECONDS
        && achieved_canonical_bytes_per_second
            >= caller_target_canonical_bytes_per_second
                .max(RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR)
        && release_build
}

fn qualification_sources(
    run_id: [u8; 16],
    profile: JournalQualificationSourceProfile,
) -> io::Result<Vec<DeterministicReplaySource>> {
    let source = profile.definition();
    (0..source.pod_count)
        .map(|index| {
            let mut pod_id = [0x50; 16];
            pod_id[15] = u8::try_from(index + 1).expect("Pod count fits in u8");
            let mut headstage_id = [0x48; 16];
            headstage_id[15] = u8::try_from(index + 1).expect("Pod count fits in u8");
            DeterministicReplaySource::new(DeterministicReplayConfig {
                run_id,
                pod_id,
                headstage_id,
                channel_layout_id: 1,
                channel_count: source.channels_per_pod,
                samples_per_channel: source.samples_per_block,
                sample_rate_hz: source.sample_rate_hz,
                total_records: u64::MAX,
                seed: 0x464f_5247_4551_0000_u64 | index as u64,
            })
        })
        .collect()
}

fn qualification_command(
    request_id: u64,
    kind: RunCommandKind,
    run_id: [u8; 16],
    profile_hash: [u8; 32],
) -> RunCommand {
    RunCommand {
        request_id,
        epoch: 1,
        body: RunCommandV1 {
            command: kind.wire_value(),
            scope: 1,
            run_id,
            target_device_id: [0x44; 16],
            deadline_global_time_ns: u64::MAX,
            frozen_config_hash: profile_hash,
        },
    }
}

fn profile_hash(
    options: &JournalQualificationOptions,
    volume: &VolumeIdentityV1,
    build: &BuildIdentityV1,
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(b"FGQUALP2");
    bytes.extend_from_slice(&PROTOCOL_HASH);
    bytes.extend_from_slice(&source_profile_hash(options.source_profile));
    bytes.extend_from_slice(&options.duration.as_millis().to_le_bytes());
    bytes.extend_from_slice(&options.target_canonical_bytes_per_second.to_le_bytes());
    bytes.extend_from_slice(&options.durability_batch_records.to_le_bytes());
    bytes.extend_from_slice(&(volume.root.len() as u64).to_le_bytes());
    bytes.extend_from_slice(volume.root.as_bytes());
    bytes.extend_from_slice(&(volume.filesystem.len() as u64).to_le_bytes());
    bytes.extend_from_slice(volume.filesystem.as_bytes());
    if let Some(serial) = &volume.serial_hex {
        bytes.extend_from_slice(&(serial.len() as u64).to_le_bytes());
        bytes.extend_from_slice(serial.as_bytes());
    } else {
        bytes.extend_from_slice(&0_u64.to_le_bytes());
    }
    append_hash_string(&mut bytes, &build.daemon_version);
    append_hash_string(&mut bytes, &build.build_profile);
    append_hash_string(&mut bytes, &build.executable_sha256_hex);
    sha256(&bytes)
}

fn source_profile_hash(profile: JournalQualificationSourceProfile) -> [u8; 32] {
    let source = profile.definition();
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(b"FGQUALSOURCE2");
    bytes.extend_from_slice(profile.id().as_bytes());
    bytes.extend_from_slice(&(source.pod_count as u64).to_le_bytes());
    bytes.extend_from_slice(&source.channels_per_pod.to_le_bytes());
    bytes.extend_from_slice(&source.samples_per_block.to_le_bytes());
    bytes.extend_from_slice(&source.sample_rate_hz.to_le_bytes());
    bytes.extend_from_slice(&(source.canonical_record_bytes as u64).to_le_bytes());
    bytes.extend_from_slice(&(source.journal_record_bytes as u64).to_le_bytes());
    bytes.extend_from_slice(source.class.as_bytes());
    bytes.extend_from_slice(&source.target_floor_canonical_bytes_per_second.to_le_bytes());
    sha256(&bytes)
}

fn append_hash_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn build_identity() -> io::Result<BuildIdentityV1> {
    let executable = std::env::current_exe()?;
    Ok(BuildIdentityV1 {
        daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
        build_profile: if cfg!(debug_assertions) {
            "debug".to_owned()
        } else {
            "release".to_owned()
        },
        executable_sha256_hex: sha256_file(&executable)?,
    })
}

#[cfg(windows)]
fn fresh_run_id() -> io::Result<[u8; 16]> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };

    let mut run_id = [0_u8; 16];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            run_id.as_mut_ptr(),
            run_id.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "BCryptGenRandom failed with NTSTATUS 0x{:08x}",
            status as u32
        )));
    }
    if run_id == [0; 16] {
        return Err(io::Error::other(
            "operating-system RNG returned a zero Run ID",
        ));
    }
    Ok(run_id)
}

#[cfg(not(windows))]
fn fresh_run_id() -> io::Result<[u8; 16]> {
    let mut run_id = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut run_id)?;
    if run_id == [0; 16] {
        return Err(io::Error::other(
            "operating-system RNG returned a zero Run ID",
        ));
    }
    Ok(run_id)
}

fn persist_receipt(path: &Path, receipt: &JournalQualificationReceiptV2) -> io::Result<()> {
    let mut pending = path.as_os_str().to_owned();
    pending.push(".pending");
    let pending = PathBuf::from(pending);
    if pending.exists() || path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "qualification receipt or pending file already exists",
        ));
    }
    let mut bytes = serde_json::to_vec_pretty(receipt).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = fs::hard_link(&pending, path) {
        let _ = fs::remove_file(&pending);
        return Err(error);
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()?;
    fs::remove_file(pending)?;
    Ok(())
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex(&digest.finalize()))
}

fn rate_per_second(bytes: u64, elapsed_microseconds: u64) -> u64 {
    u64::try_from(
        u128::from(bytes)
            .saturating_mul(1_000_000)
            .checked_div(u128::from(elapsed_microseconds.max(1)))
            .unwrap_or(0),
    )
    .unwrap_or(u64::MAX)
}

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

#[derive(Clone, Copy)]
struct ProcessSample {
    cpu_100ns: u64,
    peak_working_set_bytes: Option<u64>,
}

fn process_delta_cpu(before: Option<ProcessSample>, after: Option<ProcessSample>) -> Option<u64> {
    let delta_100ns = after?.cpu_100ns.checked_sub(before?.cpu_100ns)?;
    Some(delta_100ns / 10)
}

#[cfg(windows)]
fn process_sample() -> Option<ProcessSample> {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    unsafe {
        let process = GetCurrentProcess();
        let mut creation: FILETIME = zeroed();
        let mut exit: FILETIME = zeroed();
        let mut kernel: FILETIME = zeroed();
        let mut user: FILETIME = zeroed();
        if GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) == 0 {
            return None;
        }
        let mut memory: PROCESS_MEMORY_COUNTERS = zeroed();
        memory.cb = u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS>()).ok()?;
        let peak = (GetProcessMemoryInfo(process, &mut memory, memory.cb) != 0)
            .then_some(memory.PeakWorkingSetSize as u64);
        Some(ProcessSample {
            cpu_100ns: filetime_value(kernel).saturating_add(filetime_value(user)),
            peak_working_set_bytes: peak,
        })
    }
}

#[cfg(windows)]
fn filetime_value(value: windows_sys::Win32::Foundation::FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

#[cfg(not(windows))]
fn process_sample() -> Option<ProcessSample> {
    None
}

#[cfg(windows)]
fn volume_identity(path: &Path) -> io::Result<VolumeIdentityV1> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::ptr::null_mut;
    use windows_sys::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};

    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?
        .canonicalize()?;
    let wide: Vec<u16> = parent
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut root = vec![0_u16; 32_768];
    if unsafe { GetVolumePathNameW(wide.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let root_len = root
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(root.len());
    root.truncate(root_len);
    let mut filesystem = vec![0_u16; 256];
    let mut serial = 0_u32;
    let mut max_component = 0_u32;
    let mut flags = 0_u32;
    let mut root_nul = root.clone();
    root_nul.push(0);
    if unsafe {
        GetVolumeInformationW(
            root_nul.as_ptr(),
            null_mut(),
            0,
            &mut serial,
            &mut max_component,
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let fs_len = filesystem
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(filesystem.len());
    filesystem.truncate(fs_len);
    Ok(VolumeIdentityV1 {
        root: OsString::from_wide(&root).to_string_lossy().into_owned(),
        filesystem: OsString::from_wide(&filesystem)
            .to_string_lossy()
            .into_owned(),
        serial_hex: Some(format!("{serial:08x}")),
    })
}

#[cfg(not(windows))]
fn volume_identity(path: &Path) -> io::Result<VolumeIdentityV1> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?
        .canonicalize()?;
    Ok(VolumeIdentityV1 {
        root: parent.to_string_lossy().into_owned(),
        filesystem: "unverified".to_owned(),
        serial_hex: None,
    })
}

fn invalid_input<T>(message: &str) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn invalid_data<T>(message: impl Into<String>) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempQualification {
        root: PathBuf,
    }

    impl TempQualification {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "forge-acqd-qualification-test-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            Self { root }
        }
    }

    impl Drop for TempQualification {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn latency_histogram_is_fixed_and_monotonic() {
        let mut histogram = LatencyHistogram::new();
        for micros in [1, 5, 10, 11, 100, 1_000, 100_000] {
            histogram.observe(Duration::from_micros(micros));
        }
        let summary = histogram.summary();
        assert_eq!(summary.count, 7);
        assert!(summary.p50_microseconds_upper_bound <= summary.p99_microseconds_upper_bound);
        assert!(summary.p99_microseconds_upper_bound <= summary.max_microseconds.max(40_960));
        assert_eq!(summary.max_microseconds, 100_000);
    }

    #[test]
    fn profile_hash_binds_target_duration_and_volume() {
        let options = JournalQualificationOptions {
            journal_path: PathBuf::from("journal"),
            receipt_path: PathBuf::from("receipt"),
            duration: Duration::from_secs(1),
            source_profile: JournalQualificationSourceProfile::ProtocolMax256,
            target_canonical_bytes_per_second: 190_080_000,
            durability_batch_records: 1_024,
        };
        let volume = VolumeIdentityV1 {
            root: "X:\\".to_owned(),
            filesystem: "NTFS".to_owned(),
            serial_hex: Some("12345678".to_owned()),
        };
        let build = BuildIdentityV1 {
            daemon_version: "0.1.0".to_owned(),
            build_profile: "release".to_owned(),
            executable_sha256_hex: "11".repeat(32),
        };
        let baseline = profile_hash(&options, &volume, &build);
        let mut changed = options.clone();
        changed.duration = Duration::from_secs(2);
        assert_ne!(baseline, profile_hash(&changed, &volume, &build));
        let mut changed_build = build.clone();
        changed_build.executable_sha256_hex = "22".repeat(32);
        assert_ne!(baseline, profile_hash(&options, &volume, &changed_build));
    }

    #[test]
    fn source_profiles_freeze_geometry_and_journal_loads() {
        let active = JournalQualificationSourceProfile::ActiveReceiverPod128.definition();
        assert_eq!(active.canonical_record_bytes, 7_888);
        assert_eq!(active.journal_record_bytes, 7_992);
        assert_eq!(active.target_floor_canonical_bytes_per_second, 63_104_000);
        assert_eq!(
            active.pod_count as u64
                * active.canonical_record_bytes as u64
                * active.sample_rate_hz as u64
                / active.samples_per_block as u64,
            63_104_000
        );
        assert_eq!(
            active.pod_count as u64
                * active.journal_record_bytes as u64
                * active.sample_rate_hz as u64
                / active.samples_per_block as u64,
            63_936_000
        );
        let conservative = JournalQualificationSourceProfile::ProtocolMax256.definition();
        assert_eq!(conservative.canonical_record_bytes, 15_568);
        assert_eq!(conservative.journal_record_bytes, 15_672);
        assert_eq!(
            conservative.target_floor_canonical_bytes_per_second,
            RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR
        );
        assert_ne!(
            source_profile_hash(JournalQualificationSourceProfile::ActiveReceiverPod128),
            source_profile_hash(JournalQualificationSourceProfile::ProtocolMax256)
        );
    }

    #[test]
    fn qualification_profiles_do_not_change_the_m0_protocol_hash() {
        assert_eq!(
            PROTOCOL_HASH_HEX,
            "4e3db23e15a1480707132d28bdc820f36fdabbb5d20d9d84850ae89166b3efa0"
        );
    }

    #[test]
    fn release_gate_is_conservative_and_caller_target_can_only_raise_it() {
        assert!(!release_gate_passed(
            JournalQualificationSourceProfile::ProtocolMax256,
            RELEASE_GATE_MILLISECONDS,
            RELEASE_GATE_SECONDS,
            RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR - 1,
            1,
            true,
        ));
        assert!(!release_gate_passed(
            JournalQualificationSourceProfile::ActiveReceiverPod128,
            RELEASE_GATE_MILLISECONDS,
            RELEASE_GATE_SECONDS,
            RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR + 1,
            1,
            true,
        ));
        assert!(!release_gate_passed(
            JournalQualificationSourceProfile::ProtocolMax256,
            RELEASE_GATE_MILLISECONDS,
            RELEASE_GATE_SECONDS - 1,
            RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR + 1,
            1,
            true,
        ));
        assert!(release_gate_passed(
            JournalQualificationSourceProfile::ProtocolMax256,
            RELEASE_GATE_MILLISECONDS,
            RELEASE_GATE_SECONDS,
            RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR,
            1,
            true,
        ));
        assert!(!release_gate_passed(
            JournalQualificationSourceProfile::ProtocolMax256,
            RELEASE_GATE_MILLISECONDS,
            RELEASE_GATE_SECONDS,
            RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR,
            RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR + 1,
            true,
        ));
        assert!(!release_gate_passed(
            JournalQualificationSourceProfile::ProtocolMax256,
            RELEASE_GATE_MILLISECONDS - 1,
            RELEASE_GATE_SECONDS,
            RELEASE_CANONICAL_BYTES_PER_SECOND_FLOOR,
            1,
            true,
        ));
    }

    #[test]
    fn qualification_run_ids_are_fresh_and_nonzero() {
        let first = fresh_run_id().unwrap();
        let second = fresh_run_id().unwrap();
        assert_ne!(first, [0; 16]);
        assert_ne!(second, [0; 16]);
        assert_ne!(first, second);
    }

    #[test]
    fn short_run_is_persisted_bounded_smoke_not_a_duration_gate() {
        let temp = TempQualification::new();
        let journal_path = temp.root.join("smoke.wal");
        let receipt_path = temp.root.join("smoke-receipt.json");
        let receipt = run_journal_qualification(JournalQualificationOptions {
            journal_path: journal_path.clone(),
            receipt_path: receipt_path.clone(),
            duration: Duration::from_millis(100),
            source_profile: JournalQualificationSourceProfile::ActiveReceiverPod128,
            target_canonical_bytes_per_second: 1,
            durability_batch_records: 16,
        })
        .unwrap();
        assert_eq!(receipt.schema, "forge.journal-qualification-receipt.v2");
        assert_eq!(receipt.status, "smoke_only");
        assert_eq!(receipt.evidence.pod_count, 8);
        assert!(receipt.evidence.generated_records > 0);
        assert_eq!(
            receipt.evidence.generated_records,
            receipt.evidence.committed_records
        );
        assert_eq!(
            receipt.evidence.committed_records,
            receipt.evidence.durable_records
        );
        // A 100 ms debug smoke checks sealing/reopen cheaply; it is not a
        // throughput qualification and may miss the profile's fixed floor.
        assert!(!receipt.evidence.engineering_duration_gate_met);
        assert!(!receipt.evidence.release_duration_gate_met);
        assert!(!receipt.evidence.engineering_journal_gate_passed);
        assert!(!receipt.evidence.release_journal_gate_passed);
        assert_eq!(receipt.evidence.raw_sample_bytes_entered_webview, 0);
        assert!(!receipt.evidence.hardware_transport_available);
        assert!(!receipt.evidence.nwb_dual_write_enabled);
        assert!(journal_path.is_file());
        assert!(receipt_path.is_file());
        let scan = scan_journal(&journal_path).unwrap();
        verify_qualification_content_profile(
            &scan,
            JournalQualificationSourceProfile::ActiveReceiverPod128.definition(),
        )
        .unwrap();
        let mut wrong_geometry = scan.clone();
        wrong_geometry.content_profile.pods[0].channel_count = Some(64);
        assert!(verify_qualification_content_profile(
            &wrong_geometry,
            JournalQualificationSourceProfile::ActiveReceiverPod128.definition(),
        )
        .is_err());
        assert_eq!(
            verify_journal_qualification_receipt(&receipt_path).unwrap(),
            receipt
        );

        // An unkeyed hash can be recomputed, so the verifier also binds the
        // receipt to the exact executable that is performing verification.
        let forged_build_receipt = temp.root.join("forged-build-receipt.json");
        let mut forged_build = receipt.clone();
        let original_executable_sha256_hex =
            forged_build.evidence.build.executable_sha256_hex.clone();
        let forged_first_nibble = if original_executable_sha256_hex.starts_with('0') {
            '1'
        } else {
            '0'
        };
        forged_build
            .evidence
            .build
            .executable_sha256_hex
            .replace_range(0..1, &forged_first_nibble.to_string());
        assert_ne!(
            forged_build.evidence.build.executable_sha256_hex,
            original_executable_sha256_hex
        );
        let forged_options = JournalQualificationOptions {
            journal_path: journal_path.clone(),
            receipt_path: forged_build_receipt.clone(),
            duration: Duration::from_millis(forged_build.evidence.requested_duration_milliseconds),
            source_profile: JournalQualificationSourceProfile::ActiveReceiverPod128,
            target_canonical_bytes_per_second: forged_build
                .evidence
                .target_canonical_bytes_per_second,
            durability_batch_records: forged_build.evidence.durability_batch_records,
        };
        forged_build.evidence.profile_hash_hex = hex(&profile_hash(
            &forged_options,
            &forged_build.evidence.volume,
            &forged_build.evidence.build,
        ));
        forged_build.evidence_sha256_hex = hex(&sha256(
            &serde_json::to_vec(&forged_build.evidence).unwrap(),
        ));
        fs::write(
            &forged_build_receipt,
            serde_json::to_vec_pretty(&forged_build).unwrap(),
        )
        .unwrap();
        assert!(verify_journal_qualification_receipt(&forged_build_receipt).is_err());

        let serialized = fs::read_to_string(&receipt_path).unwrap();
        let tampered = serialized.replace("\"pod_count\": 8", "\"pod_count\": 7");
        assert_ne!(serialized, tampered);
        fs::write(&receipt_path, tampered).unwrap();
        assert!(verify_journal_qualification_receipt(&receipt_path).is_err());

        // Even with a freshly recomputed unkeyed evidence hash, self-reported
        // throughput must reconcile with the rescanned journal and elapsed time.
        let forged_rate_receipt = temp.root.join("forged-rate-receipt.json");
        let mut forged = receipt.clone();
        forged.evidence.achieved_canonical_bytes_per_second = u64::MAX;
        forged.evidence.achieved_journal_bytes_per_second = u64::MAX;
        forged.evidence_sha256_hex = hex(&sha256(&serde_json::to_vec(&forged.evidence).unwrap()));
        fs::write(
            &forged_rate_receipt,
            serde_json::to_vec_pretty(&forged).unwrap(),
        )
        .unwrap();
        assert!(verify_journal_qualification_receipt(&forged_rate_receipt).is_err());

        // A source-profile substitution is not a compatible receipt edit.
        let profile_receipt = temp.root.join("profile-receipt.json");
        let profile_journal = temp.root.join("profile.wal");
        let receipt = run_journal_qualification(JournalQualificationOptions {
            journal_path: profile_journal,
            receipt_path: profile_receipt.clone(),
            duration: Duration::from_millis(100),
            source_profile: JournalQualificationSourceProfile::ActiveReceiverPod128,
            target_canonical_bytes_per_second: 1,
            durability_batch_records: 16,
        })
        .unwrap();
        let tampered = serde_json::to_string(&receipt)
            .unwrap()
            .replace("active_receiver_pod_128", "protocol_max_256");
        fs::write(&profile_receipt, tampered).unwrap();
        assert!(verify_journal_qualification_receipt(&profile_receipt).is_err());
    }
}
