use std::io;
use std::path::PathBuf;
use std::time::Instant;

use forge_protocol_v1::{sha256, RunCommandV1, PROTOCOL_HASH_HEX, RECORD_HEADER_LEN};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::buffer_pool::BoundedBufferPool;
use crate::ipc::ipc_boundary;
use crate::journal::{JournalIdentity, JournalWriter};
use crate::run::{RunCommand, RunCommandKind, RunState};
use crate::run_ledger::DurableRunService;
use crate::source::{DeterministicReplayConfig, DeterministicReplaySource, SYNTHETIC_SCENARIO_ID};

const PROTECTED_REPLAY_SEED: u64 = 0x464f_5247_4552_504c;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedReplayOptions {
    pub journal_path: PathBuf,
    pub chunks: u64,
    /// Exact encoded `SampleBlockV1` payload length (32-byte header + i16 data).
    pub sample_payload_bytes: usize,
    pub durability_batch_records: u64,
}

impl ProtectedReplayOptions {
    pub fn validate(self) -> io::Result<Self> {
        if self.chunks == 0 || self.durability_batch_records == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chunks and durability batch must be nonzero",
            ));
        }
        if self.sample_payload_bytes < 34 || !(self.sample_payload_bytes - 32).is_multiple_of(2) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload bytes must be 32 + an even, nonzero i16 sample byte count",
            ));
        }
        let samples = (self.sample_payload_bytes - 32) / 2;
        if samples > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sample payload exceeds SampleBlockV1 bounds",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProtectedReplayReceipt {
    pub schema: &'static str,
    pub status: &'static str,
    pub mode: &'static str,
    pub run_id_hex: String,
    pub protocol_hash_hex: &'static str,
    pub journal_path: String,
    pub run_ledger_path: String,
    pub source: &'static str,
    pub source_seed_hex: String,
    pub source_sample_rate_numerator_hz: u32,
    pub source_sample_rate_denominator: u32,
    pub source_channel_layout_id: u32,
    pub source_channel_count: u16,
    pub source_sample_start: u64,
    pub source_sample_end_exclusive: u64,
    pub source_config_sha256_hex: String,
    pub canonical_record_stream_sha256_hex: String,
    pub requested_chunks: u64,
    pub committed_chunks: u64,
    pub durable_chunks: u64,
    pub last_journal_sequence: Option<u64>,
    pub durable_checkpoint_generation: u64,
    pub durable_valid_bytes: u64,
    pub sample_payload_bytes: usize,
    pub canonical_record_bytes_per_chunk: usize,
    pub journal_file_bytes: u64,
    pub elapsed_microseconds: u64,
    pub effective_journal_bytes_per_second: u64,
    pub sealed: bool,
    pub durable_run_state: RunState,
    pub run_ledger_events: u64,
    pub restart_reopen_verified: bool,
    pub hardware_transport_available: bool,
    pub secure_ipc_available: bool,
    pub stimulation_available: bool,
}

pub fn run_protected_replay(options: ProtectedReplayOptions) -> io::Result<ProtectedReplayReceipt> {
    let options = options.validate()?;
    let started = Instant::now();
    // This ID is explicitly a deterministic protected-replay fixture identity,
    // not a device identity. create_new prevents accidental Run overwrite.
    let run_id = [0x52; 16];
    let samples_per_channel = u32::try_from((options.sample_payload_bytes - 32) / 2)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sample count overflow"))?;
    let source_config = DeterministicReplayConfig {
        run_id,
        pod_id: [0x50; 16],
        headstage_id: [0x48; 16],
        channel_layout_id: 1,
        channel_count: 1,
        samples_per_channel,
        sample_rate_hz: 30_000,
        total_records: options.chunks,
        seed: PROTECTED_REPLAY_SEED,
    };
    let source_sample_end_exclusive = u64::from(samples_per_channel)
        .checked_mul(options.chunks)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "source sample range overflow")
        })?;
    let source_config_sha256 = synthetic_source_config_sha256(source_config);
    let mut source = DeterministicReplaySource::new(source_config)?;
    let mut canonical_record_stream_hasher = Sha256::new();
    let pool = BoundedBufferPool::new(4, RECORD_HEADER_LEN + options.sample_payload_bytes)?;
    let run_ledger_path = options.journal_path.with_extension("run-ledger");
    let mut lifecycle = DurableRunService::open(&run_ledger_path)?;
    for (request_id, kind) in [
        (1, RunCommandKind::Prepare),
        (2, RunCommandKind::Arm),
        (3, RunCommandKind::Start),
    ] {
        let receipt = lifecycle.handle(replay_command(request_id, kind, run_id), 1)?;
        if !receipt.accepted {
            return Err(io::Error::other(format!(
                "protected replay lifecycle rejected {kind:?}: {}",
                receipt.reason
            )));
        }
    }

    let mut writer =
        JournalWriter::create(&options.journal_path, JournalIdentity::for_run(run_id)?)?;
    let mut committed = 0_u64;
    while let Some(encoded) = source.next_encoded_record()? {
        canonical_record_stream_hasher.update((encoded.len() as u64).to_le_bytes());
        canonical_record_stream_hasher.update(&encoded);
        let mut buffer = pool.try_acquire()?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "bounded replay buffer pool exhausted",
            )
        })?;
        buffer.try_extend_from_slice(&encoded)?;
        writer.append_record(buffer.as_slice())?;
        committed += 1;
        if committed.is_multiple_of(options.durability_batch_records) && committed < options.chunks
        {
            writer.durability_barrier()?;
        }
    }
    if committed != options.chunks {
        lifecycle.fail_closed(
            crate::run_ledger::FAULT_INTERNAL_PERSISTENCE,
            sha256(b"forge-protected-replay-source-ended-early-v1"),
        )?;
        return Err(io::Error::other(
            "deterministic source ended before requested chunk count",
        ));
    }
    let stop = lifecycle.handle(replay_command(4, RunCommandKind::Stop, run_id), 1)?;
    if !stop.accepted {
        return Err(io::Error::other(format!(
            "protected replay Stop rejected: {}",
            stop.reason
        )));
    }
    let scan = writer.seal(committed.checked_sub(1))?;
    let seal = scan
        .seal
        .as_ref()
        .ok_or_else(|| io::Error::other("sealed replay scan has no seal receipt"))?;
    lifecycle.mark_journal_sealed(crate::journal::seal_evidence_hash(run_id, seal))?;
    let final_status = lifecycle.status();
    drop(lifecycle);
    let reopened = DurableRunService::open(&run_ledger_path)?;
    let reopened_status = reopened.status();
    if reopened_status.state != RunState::JournalSealed || reopened_status.auto_failed_on_restart {
        return Err(io::Error::other(
            "durable Run ledger did not reopen in the journal-sealed state",
        ));
    }
    let elapsed_microseconds = u64::try_from(started.elapsed().as_micros())
        .unwrap_or(u64::MAX)
        .max(1);
    let boundary = ipc_boundary();
    let canonical_record_stream_sha256: [u8; 32] = canonical_record_stream_hasher.finalize().into();
    Ok(ProtectedReplayReceipt {
        schema: "forge.protected-replay-receipt.v1",
        status: "sealed",
        mode: "protected_replay",
        run_id_hex: hex(&run_id),
        protocol_hash_hex: PROTOCOL_HASH_HEX,
        journal_path: options.journal_path.to_string_lossy().into_owned(),
        run_ledger_path: run_ledger_path.to_string_lossy().into_owned(),
        source: SYNTHETIC_SCENARIO_ID,
        source_seed_hex: format!("{PROTECTED_REPLAY_SEED:016x}"),
        source_sample_rate_numerator_hz: source_config.sample_rate_hz,
        source_sample_rate_denominator: 1,
        source_channel_layout_id: source_config.channel_layout_id,
        source_channel_count: source_config.channel_count,
        source_sample_start: 0,
        source_sample_end_exclusive,
        source_config_sha256_hex: hex(&source_config_sha256),
        canonical_record_stream_sha256_hex: hex(&canonical_record_stream_sha256),
        requested_chunks: options.chunks,
        committed_chunks: scan.complete_chunks,
        durable_chunks: scan.durable.durable_record_count,
        last_journal_sequence: scan.last_journal_sequence,
        durable_checkpoint_generation: scan.durable.generation,
        durable_valid_bytes: scan.durable.durable_valid_len,
        sample_payload_bytes: options.sample_payload_bytes,
        canonical_record_bytes_per_chunk: RECORD_HEADER_LEN + options.sample_payload_bytes,
        journal_file_bytes: scan.file_len,
        elapsed_microseconds,
        effective_journal_bytes_per_second: rate_per_second(scan.file_len, elapsed_microseconds),
        sealed: scan.seal.is_some(),
        durable_run_state: reopened_status.state,
        run_ledger_events: final_status.ledger_events,
        restart_reopen_verified: true,
        hardware_transport_available: false,
        secure_ipc_available: boundary.available,
        stimulation_available: false,
    })
}

fn synthetic_source_config_sha256(config: DeterministicReplayConfig) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"forge.synthetic-neural-source-config.v1\0");
    hasher.update(SYNTHETIC_SCENARIO_ID.as_bytes());
    hasher.update(config.run_id);
    hasher.update(config.pod_id);
    hasher.update(config.headstage_id);
    hasher.update(config.channel_layout_id.to_le_bytes());
    hasher.update(config.channel_count.to_le_bytes());
    hasher.update(config.samples_per_channel.to_le_bytes());
    hasher.update(config.sample_rate_hz.to_le_bytes());
    hasher.update(config.total_records.to_le_bytes());
    hasher.update(config.seed.to_le_bytes());
    hasher.finalize().into()
}

fn rate_per_second(bytes: u64, elapsed_microseconds: u64) -> u64 {
    let rate = u128::from(bytes)
        .saturating_mul(1_000_000)
        .checked_div(u128::from(elapsed_microseconds.max(1)))
        .unwrap_or(0);
    u64::try_from(rate).unwrap_or(u64::MAX)
}

fn replay_command(request_id: u64, kind: RunCommandKind, run_id: [u8; 16]) -> RunCommand {
    RunCommand {
        request_id,
        epoch: 1,
        body: RunCommandV1 {
            command: kind.wire_value(),
            scope: 1,
            run_id,
            target_device_id: [0x44; 16],
            deadline_global_time_ns: u64::MAX,
            frozen_config_hash: [0x43; 32],
        },
    }
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
    use crate::journal::JournalReader;
    use forge_protocol_v1::SampleBlockV1;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "forge-protected-replay-{}-{}.wal",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn cleanup(path: &std::path::Path) {
        for suffix in ["", ".checkpoint-a", ".checkpoint-b", ".seal"] {
            let mut target = path.as_os_str().to_owned();
            target.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(target));
        }
    }

    #[test]
    fn protected_replay_produces_sealed_canonical_journal_receipt() {
        let journal_path = path();
        let receipt = run_protected_replay(ProtectedReplayOptions {
            journal_path: journal_path.clone(),
            chunks: 5,
            sample_payload_bytes: 92,
            durability_batch_records: 2,
        })
        .unwrap();
        assert_eq!(receipt.status, "sealed");
        assert_eq!(receipt.committed_chunks, 5);
        assert_eq!(receipt.durable_chunks, 5);
        assert!(receipt.sealed);
        assert_eq!(receipt.durable_run_state, RunState::JournalSealed);
        assert_eq!(receipt.run_ledger_events, 5);
        assert!(receipt.restart_reopen_verified);
        assert!(receipt.journal_file_bytes > 0);
        assert!(receipt.elapsed_microseconds > 0);
        assert!(!receipt.hardware_transport_available);
        assert!(!receipt.secure_ipc_available);
        assert_eq!(receipt.source, SYNTHETIC_SCENARIO_ID);
        assert_eq!(receipt.source_seed_hex, "464f52474552504c");
        assert_eq!(receipt.source_sample_rate_numerator_hz, 30_000);
        assert_eq!(receipt.source_sample_rate_denominator, 1);
        assert_eq!(receipt.source_channel_layout_id, 1);
        assert_eq!(receipt.source_channel_count, 1);
        assert_eq!(receipt.source_sample_start, 0);
        assert_eq!(receipt.source_sample_end_exclusive, 150);
        assert_eq!(receipt.source_config_sha256_hex.len(), 64);
        assert_eq!(receipt.canonical_record_stream_sha256_hex.len(), 64);
        let oracle = DeterministicReplaySource::new(DeterministicReplayConfig {
            run_id: [0x52; 16],
            pod_id: [0x50; 16],
            headstage_id: [0x48; 16],
            channel_layout_id: 1,
            channel_count: 1,
            samples_per_channel: 30,
            sample_rate_hz: 30_000,
            total_records: 5,
            seed: PROTECTED_REPLAY_SEED,
        })
        .unwrap();
        {
            let records = JournalReader::open_sealed(&journal_path)
                .unwrap()
                .collect::<io::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(records.len(), 5);
            let mut journal_stream_hasher = Sha256::new();
            for record in records {
                journal_stream_hasher.update((record.encoded_record.len() as u64).to_le_bytes());
                journal_stream_hasher.update(&record.encoded_record);
                let block = SampleBlockV1::decode(&record.canonical.payload).unwrap();
                for offset in 0..block.samples_per_channel as u64 {
                    let absolute_sample = block.first_sample_counter + offset;
                    assert_eq!(
                        block.samples[offset as usize],
                        oracle.sample_at(absolute_sample, 0).unwrap()
                    );
                }
            }
            let journal_stream_sha256: [u8; 32] = journal_stream_hasher.finalize().into();
            assert_eq!(
                receipt.canonical_record_stream_sha256_hex,
                hex(&journal_stream_sha256)
            );
        }
        cleanup(&journal_path);
        let _ = std::fs::remove_dir_all(journal_path.with_extension("run-ledger"));
    }
}
