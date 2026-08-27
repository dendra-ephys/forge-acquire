use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub use forge_protocol_v1::crc32c;
use forge_protocol_v1::{
    decode_event_payload, decode_record, CanonicalRecordEnvelopeV1, DecodedEventPayload,
    DecodedRecord, Id16, RecordKind, StimIntentV1, StimReceiptV1, WireBody,
    EVENT_FAULT_FLAG_RUN_LATCHED, EVENT_FAULT_FLAG_STIM_DISARMING, MAX_RECORD_PAYLOAD_LEN,
    PROTOCOL_HASH, RECORD_FLAG_DISCONTINUITY_BEFORE, RECORD_HEADER_LEN,
};

const FILE_MAGIC: [u8; 8] = *b"FORGEWAL";
const CHUNK_MAGIC: [u8; 8] = *b"FRGCHNK1";
const COMMIT_MAGIC: [u8; 8] = *b"FRGCMIT1";
const CHECKPOINT_MAGIC: [u8; 8] = *b"FRGCKP01";
const SEAL_MAGIC: [u8; 8] = *b"FRGSEAL1";
const FORMAT_VERSION: u16 = 1;
pub const FILE_HEADER_LEN: usize = 64;
pub const CHUNK_HEADER_LEN: usize = 80;
pub const COMMIT_FOOTER_LEN: usize = 24;
const CHECKPOINT_LEN: usize = 128;
const SEAL_LEN: usize = 128;
const MAX_ENCODED_RECORD_LEN: usize = MAX_RECORD_PAYLOAD_LEN + RECORD_HEADER_LEN;
const MAX_PODS_PER_RUN: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalIdentity {
    pub run_id: Id16,
    pub protocol_contract_hash: [u8; 32],
}

impl JournalIdentity {
    pub fn for_run(run_id: Id16) -> io::Result<Self> {
        if run_id == [0; 16] {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "journal run_id must not be zero",
            ));
        }
        Ok(Self {
            run_id,
            protocol_contract_hash: PROTOCOL_HASH,
        })
    }

    fn validate_for_create(self) -> io::Result<Self> {
        if self.run_id == [0; 16] {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "journal run_id must not be zero",
            ));
        }
        if self.protocol_contract_hash != PROTOCOL_HASH {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "journal protocol hash is not Forge host protocol v1",
            ));
        }
        Ok(self)
    }
}

/// Redundant, validated cache of the canonical envelope fields.
///
/// `journal_sequence` is the file append order. `record_sequence` is the
/// independent per-Pod sequence from `CanonicalRecordEnvelopeV1`. They are
/// deliberately named differently and are never assumed equal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkMetadata {
    pub journal_sequence: u64,
    pub pod_slot: u16,
    pub record_sequence: u64,
    pub frame_start: u64,
    pub frame_end_exclusive: u64,
    pub sample_start: u64,
    pub sample_end_exclusive: u64,
    pub global_time_start_ns: u64,
    pub global_time_end_exclusive_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppendReceipt {
    pub journal_sequence: u64,
    pub record_sequence: u64,
    pub pod_id: Id16,
    pub encoded_record_len: u32,
    pub encoded_record_crc32c: u32,
    /// Newly appended records are never called durable before a barrier.
    pub durable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableCheckpoint {
    pub generation: u64,
    pub durable_journal_sequence: Option<u64>,
    pub durable_valid_len: u64,
    pub durable_record_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealReceipt {
    pub expected_last_journal_sequence: Option<u64>,
    pub expected_valid_len: u64,
    pub checkpoint_generation: u64,
    pub record_count: u64,
}

/// Hashes the exact durable journal-seal evidence persisted in the Run ledger.
///
/// This excludes mutable paths and wall-clock time. The NWB validation
/// boundary recomputes the same value from the sealed journal instead of
/// trusting a worker-supplied claim.
pub fn seal_evidence_hash(run_id: Id16, seal: &SealReceipt) -> [u8; 32] {
    let mut evidence = Vec::with_capacity(56);
    evidence.extend_from_slice(b"FGRSEAL1");
    evidence.extend_from_slice(&run_id);
    evidence.extend_from_slice(
        &seal
            .expected_last_journal_sequence
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    evidence.extend_from_slice(&seal.expected_valid_len.to_le_bytes());
    evidence.extend_from_slice(&seal.checkpoint_generation.to_le_bytes());
    evidence.extend_from_slice(&seal.record_count.to_le_bytes());
    forge_protocol_v1::sha256(&evidence)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalScan {
    pub identity: JournalIdentity,
    pub complete_chunks: u64,
    pub last_journal_sequence: Option<u64>,
    pub valid_len: u64,
    pub file_len: u64,
    pub torn_tail: bool,
    pub durable: DurableCheckpoint,
    pub seal: Option<SealReceipt>,
    /// Profile facts derived while every canonical record is decoded during
    /// structural scanning. Consumers must still apply their own expected
    /// profile; these values are observations, not capability claims.
    pub content_profile: JournalContentProfile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalContentProfile {
    pub non_sample_record_count: u64,
    pub pods: Vec<JournalPodSampleProfile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalPodSampleProfile {
    pub pod_id: Id16,
    pub sample_record_count: u64,
    pub canonical_record_bytes_min: Option<usize>,
    pub canonical_record_bytes_max: Option<usize>,
    pub samples_per_block_min: Option<u32>,
    pub samples_per_block_max: Option<u32>,
    pub sample_rate_numerator_hz_min: Option<u32>,
    pub sample_rate_numerator_hz_max: Option<u32>,
    pub sample_rate_denominator_min: Option<u32>,
    pub sample_rate_denominator_max: Option<u32>,
    pub channel_count: Option<u16>,
    pub sample_format: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalRecovery {
    Clean(JournalScan),
    RecoverableUnprovenTail {
        identity: JournalIdentity,
        durable: DurableCheckpoint,
        file_len: u64,
        reason: String,
    },
}

#[derive(Debug)]
struct DecodedChunkHeader {
    journal_sequence: u64,
    pod_slot: u16,
    encoded_record_len: usize,
    frame_start: u64,
    frame_end_exclusive: u64,
    sample_start: u64,
    sample_end_exclusive: u64,
    global_time_start_ns: u64,
    global_time_end_exclusive_ns: u64,
    encoded_record_crc32c: u32,
}

#[derive(Clone, Debug)]
struct PodContinuity {
    last_record_sequence: u64,
    last_frame_end_exclusive: Option<u64>,
    last_sample_end_exclusive: Option<u64>,
    last_global_time_end_exclusive_ns: Option<u64>,
    channel_layout_id: Option<u32>,
    channel_count: Option<u16>,
    sample_format: Option<u16>,
    sample_rate_numerator_hz: Option<u32>,
    sample_rate_denominator: Option<u32>,
    sample_record_count: u64,
    canonical_record_bytes_min: Option<usize>,
    canonical_record_bytes_max: Option<usize>,
    samples_per_block_min: Option<u32>,
    samples_per_block_max: Option<u32>,
    sample_rate_numerator_hz_min: Option<u32>,
    sample_rate_numerator_hz_max: Option<u32>,
    sample_rate_denominator_min: Option<u32>,
    sample_rate_denominator_max: Option<u32>,
}

#[derive(Clone, Debug, Default)]
struct ContinuityTracker {
    pods: HashMap<Id16, PodContinuity>,
    slots: HashMap<u16, Id16>,
    non_sample_record_count: u64,
}

impl ContinuityTracker {
    fn ensure_pod_capacity(&self, pod_id: &Id16) -> io::Result<()> {
        if !self.pods.contains_key(pod_id) && self.pods.len() >= MAX_PODS_PER_RUN {
            return invalid_data("journal Run exceeds the eight-Pod product limit");
        }
        Ok(())
    }

    fn validate_and_advance(
        &mut self,
        identity: JournalIdentity,
        chunk: &DecodedChunkHeader,
        record: &DecodedRecord,
    ) -> io::Result<()> {
        validate_typed_record_payload(record)?;
        let envelope = &record.envelope;
        if envelope.run_id != identity.run_id {
            return invalid_data("canonical record run_id does not match journal run_id");
        }
        self.ensure_pod_capacity(&envelope.pod_id)?;
        let expected_slot = pod_slot(&envelope.pod_id);
        if chunk.pod_slot != expected_slot {
            return invalid_data("journal Pod projection does not match canonical record");
        }
        if let Some(existing) = self.slots.get(&expected_slot) {
            if existing != &envelope.pod_id {
                return invalid_data("16-bit Pod projection collision in one Run");
            }
        }
        if chunk.frame_start != envelope.frame_start
            || chunk.frame_end_exclusive != envelope.frame_end_exclusive
            || chunk.sample_start != envelope.sample_start
            || chunk.sample_end_exclusive != envelope.sample_end_exclusive
            || chunk.global_time_start_ns != envelope.global_time_start_ns
            || chunk.global_time_end_exclusive_ns != envelope.global_time_end_exclusive_ns
        {
            return invalid_data("journal range cache does not match canonical record envelope");
        }

        let prior = self.pods.get(&envelope.pod_id).cloned();
        match prior {
            None if envelope.record_sequence != 0 => {
                return invalid_data("first canonical record sequence for a Pod is not zero")
            }
            Some(ref state) => {
                let expected = state.last_record_sequence.checked_add(1).ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        "canonical per-Pod record sequence overflow",
                    )
                })?;
                if envelope.record_sequence != expected {
                    return invalid_data("canonical per-Pod record sequence is not contiguous");
                }
            }
            _ => {}
        }

        self.validate_sample_rate_rational(record)?;

        let mut state = prior.unwrap_or(PodContinuity {
            last_record_sequence: envelope.record_sequence,
            last_frame_end_exclusive: None,
            last_sample_end_exclusive: None,
            last_global_time_end_exclusive_ns: None,
            channel_layout_id: None,
            channel_count: None,
            sample_format: None,
            sample_rate_numerator_hz: None,
            sample_rate_denominator: None,
            sample_record_count: 0,
            canonical_record_bytes_min: None,
            canonical_record_bytes_max: None,
            samples_per_block_min: None,
            samples_per_block_max: None,
            sample_rate_numerator_hz_min: None,
            sample_rate_numerator_hz_max: None,
            sample_rate_denominator_min: None,
            sample_rate_denominator_max: None,
        });
        state.last_record_sequence = envelope.record_sequence;

        if envelope.record_kind == RecordKind::SampleBlock {
            let discontinuity = envelope.flags & RECORD_FLAG_DISCONTINUITY_BEFORE != 0;
            validate_contiguous_range(
                "frame",
                state.last_frame_end_exclusive,
                envelope.frame_start,
                discontinuity,
            )?;
            validate_contiguous_range(
                "sample",
                state.last_sample_end_exclusive,
                envelope.sample_start,
                discontinuity,
            )?;
            validate_contiguous_range(
                "global-time",
                state.last_global_time_end_exclusive_ns,
                envelope.global_time_start_ns,
                discontinuity,
            )?;
            for (name, previous, current) in [
                (
                    "channel layout",
                    state.channel_layout_id.map(u64::from),
                    u64::from(envelope.channel_layout_id),
                ),
                (
                    "channel count",
                    state.channel_count.map(u64::from),
                    u64::from(envelope.channel_count),
                ),
                (
                    "sample format",
                    state.sample_format.map(u64::from),
                    u64::from(envelope.sample_format),
                ),
            ] {
                if previous.is_some_and(|value| value != current) {
                    return invalid_data(&format!("{name} changed within an armed Pod stream"));
                }
            }
            let samples_per_block = payload_u32(&record.payload, 8)?;
            let sample_rate_numerator_hz = payload_u32(&record.payload, 16)?;
            let sample_rate_denominator = payload_u32(&record.payload, 20)?;
            state.last_frame_end_exclusive = Some(envelope.frame_end_exclusive);
            state.last_sample_end_exclusive = Some(envelope.sample_end_exclusive);
            state.last_global_time_end_exclusive_ns = Some(envelope.global_time_end_exclusive_ns);
            state.channel_layout_id = Some(envelope.channel_layout_id);
            state.channel_count = Some(envelope.channel_count);
            state.sample_format = Some(envelope.sample_format);
            state.sample_rate_numerator_hz = Some(sample_rate_numerator_hz);
            state.sample_rate_denominator = Some(sample_rate_denominator);
            state.sample_record_count =
                state.sample_record_count.checked_add(1).ok_or_else(|| {
                    io::Error::new(ErrorKind::InvalidData, "sample record count overflow")
                })?;
            update_min_max(
                &mut state.canonical_record_bytes_min,
                &mut state.canonical_record_bytes_max,
                chunk.encoded_record_len,
            );
            update_min_max(
                &mut state.samples_per_block_min,
                &mut state.samples_per_block_max,
                samples_per_block,
            );
            update_min_max(
                &mut state.sample_rate_numerator_hz_min,
                &mut state.sample_rate_numerator_hz_max,
                sample_rate_numerator_hz,
            );
            update_min_max(
                &mut state.sample_rate_denominator_min,
                &mut state.sample_rate_denominator_max,
                sample_rate_denominator,
            );
        } else {
            self.non_sample_record_count =
                self.non_sample_record_count.checked_add(1).ok_or_else(|| {
                    io::Error::new(ErrorKind::InvalidData, "event record count overflow")
                })?;
        }
        self.slots.entry(expected_slot).or_insert(envelope.pod_id);
        self.pods.insert(envelope.pod_id, state);
        Ok(())
    }

    /// Validates the exact rate representation against the first SampleBlock
    /// already observed for this Pod. This helper is shared by writer-side
    /// preflight and structural scanning, so a CRC/commit-valid forged record
    /// cannot bypass the same per-Pod freeze.
    fn validate_sample_rate_rational(&self, record: &DecodedRecord) -> io::Result<()> {
        if record.envelope.record_kind != RecordKind::SampleBlock {
            return Ok(());
        }
        let Some(previous) = self.pods.get(&record.envelope.pod_id) else {
            return Ok(());
        };
        let numerator = payload_u32(&record.payload, 16)?;
        let denominator = payload_u32(&record.payload, 20)?;
        if previous
            .sample_rate_numerator_hz
            .is_some_and(|value| value != numerator)
            || previous
                .sample_rate_denominator
                .is_some_and(|value| value != denominator)
        {
            return invalid_data("sample rate rational changed within an armed Pod stream");
        }
        Ok(())
    }

    fn content_profile(&self) -> JournalContentProfile {
        let mut pods: Vec<_> = self
            .pods
            .iter()
            .map(|(pod_id, state)| JournalPodSampleProfile {
                pod_id: *pod_id,
                sample_record_count: state.sample_record_count,
                canonical_record_bytes_min: state.canonical_record_bytes_min,
                canonical_record_bytes_max: state.canonical_record_bytes_max,
                samples_per_block_min: state.samples_per_block_min,
                samples_per_block_max: state.samples_per_block_max,
                sample_rate_numerator_hz_min: state.sample_rate_numerator_hz_min,
                sample_rate_numerator_hz_max: state.sample_rate_numerator_hz_max,
                sample_rate_denominator_min: state.sample_rate_denominator_min,
                sample_rate_denominator_max: state.sample_rate_denominator_max,
                channel_count: state.channel_count,
                sample_format: state.sample_format,
            })
            .collect();
        pods.sort_by_key(|profile| profile.pod_id);
        JournalContentProfile {
            non_sample_record_count: self.non_sample_record_count,
            pods,
        }
    }
}

fn payload_u32(payload: &[u8], offset: usize) -> io::Result<u32> {
    let bytes: [u8; 4] = payload
        .get(offset..offset + 4)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "sample block header is truncated"))?
        .try_into()
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "sample block header is invalid"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn update_min_max<T: Copy + Ord>(minimum: &mut Option<T>, maximum: &mut Option<T>, value: T) {
    *minimum = Some(minimum.map_or(value, |current| current.min(value)));
    *maximum = Some(maximum.map_or(value, |current| current.max(value)));
}

fn validate_typed_record_payload(record: &DecodedRecord) -> io::Result<()> {
    let envelope = &record.envelope;
    match envelope.record_kind {
        RecordKind::SampleBlock => Ok(()),
        RecordKind::Marker => match decode_event_payload(&record.payload) {
            Ok(DecodedEventPayload::Marker(_)) => Ok(()),
            Ok(_) => invalid_data("MARKER record contains the wrong event payload kind"),
            Err(error) => invalid_data(&format!("invalid MarkerPayloadV1: {error}")),
        },
        RecordKind::Fault => match decode_event_payload(&record.payload) {
            Ok(DecodedEventPayload::Fault(_)) => Ok(()),
            Ok(DecodedEventPayload::Gap(gap)) => {
                if gap.gap_flags != (EVENT_FAULT_FLAG_RUN_LATCHED | EVENT_FAULT_FLAG_STIM_DISARMING)
                {
                    return invalid_data(
                        "GapPayloadV1 must latch Run integrity and stimulation disarm",
                    );
                }
                let frame_count = envelope.frame_end_exclusive - envelope.frame_start;
                let sample_count = envelope.sample_end_exclusive - envelope.sample_start;
                if gap.missing_frame_count != 0 && gap.missing_frame_count != frame_count {
                    return invalid_data("GapPayloadV1 frame count disagrees with outer range");
                }
                if gap.missing_sample_count != 0 && gap.missing_sample_count != sample_count {
                    return invalid_data("GapPayloadV1 sample count disagrees with outer range");
                }
                Ok(())
            }
            Ok(_) => invalid_data("FAULT record contains the wrong event payload kind"),
            Err(error) => invalid_data(&format!("invalid Fault/Gap payload: {error}")),
        },
        RecordKind::OnlineAnalysis => match decode_event_payload(&record.payload) {
            Ok(DecodedEventPayload::OnlineAnalysis(analysis)) => {
                if analysis.source_record_sequence >= envelope.record_sequence {
                    return invalid_data(
                        "OnlineAnalysis source record must precede its event record",
                    );
                }
                Ok(())
            }
            Ok(_) => invalid_data("ONLINE_ANALYSIS record contains the wrong event payload kind"),
            Err(error) => invalid_data(&format!("invalid OnlineAnalysisPayloadV1: {error}")),
        },
        RecordKind::StimIntent => {
            let intent = StimIntentV1::decode_body(&record.payload).map_err(|error| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid StimIntentV1 record payload: {error}"),
                )
            })?;
            if intent.run_id != envelope.run_id
                || !(envelope.sample_start..envelope.sample_end_exclusive)
                    .contains(&intent.source_sample_counter)
                || !(envelope.global_time_start_ns..envelope.global_time_end_exclusive_ns)
                    .contains(&intent.source_global_time_ns)
                || intent.source_record_sequence >= envelope.record_sequence
            {
                return invalid_data("StimIntentV1 disagrees with outer canonical envelope");
            }
            Ok(())
        }
        RecordKind::StimReceipt => {
            let receipt = StimReceiptV1::decode_body(&record.payload).map_err(|error| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid StimReceiptV1 record payload: {error}"),
                )
            })?;
            if receipt.run_id != envelope.run_id {
                return invalid_data("StimReceiptV1 Run disagrees with outer envelope");
            }
            if receipt.result == 1
                && (receipt.actual_start_global_time_ns < envelope.global_time_start_ns
                    || receipt.actual_end_global_time_ns >= envelope.global_time_end_exclusive_ns)
            {
                return invalid_data("executed StimReceiptV1 time is outside the outer range");
            }
            Ok(())
        }
    }
}

fn validate_contiguous_range(
    name: &str,
    previous_end: Option<u64>,
    current_start: u64,
    discontinuity: bool,
) -> io::Result<()> {
    let Some(previous_end) = previous_end else {
        return Ok(());
    };
    if current_start < previous_end {
        return invalid_data(&format!(
            "canonical {name} range overlaps prior SampleBlock"
        ));
    }
    if !discontinuity && current_start != previous_end {
        return invalid_data(&format!("canonical {name} gap lacks DISCONTINUITY_BEFORE"));
    }
    Ok(())
}

fn pod_slot(pod_id: &Id16) -> u16 {
    (crc32c(pod_id) & 0xffff) as u16
}

fn invalid_data<T>(message: &str) -> io::Result<T> {
    Err(io::Error::new(ErrorKind::InvalidData, message.to_owned()))
}

fn invalid_input<T>(message: &str) -> io::Result<T> {
    Err(io::Error::new(ErrorKind::InvalidInput, message.to_owned()))
}

fn file_header(identity: JournalIdentity) -> [u8; FILE_HEADER_LEN] {
    let mut header = [0_u8; FILE_HEADER_LEN];
    header[0..8].copy_from_slice(&FILE_MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[10..12].copy_from_slice(&(FILE_HEADER_LEN as u16).to_le_bytes());
    header[12..28].copy_from_slice(&identity.run_id);
    header[28..60].copy_from_slice(&identity.protocol_contract_hash);
    let checksum = crc32c(&header[..60]);
    header[60..64].copy_from_slice(&checksum.to_le_bytes());
    header
}

fn decode_file_header(header: &[u8; FILE_HEADER_LEN]) -> io::Result<JournalIdentity> {
    if header[0..8] != FILE_MAGIC {
        return invalid_data("invalid Forge journal magic");
    }
    if u16::from_le_bytes(header[8..10].try_into().unwrap()) != FORMAT_VERSION {
        return invalid_data("unsupported Forge journal version");
    }
    if usize::from(u16::from_le_bytes(header[10..12].try_into().unwrap())) != FILE_HEADER_LEN {
        return invalid_data("invalid Forge journal header length");
    }
    let expected = u32::from_le_bytes(header[60..64].try_into().unwrap());
    if crc32c(&header[..60]) != expected {
        return invalid_data("Forge journal header CRC32C mismatch");
    }
    let identity = JournalIdentity {
        run_id: header[12..28].try_into().unwrap(),
        protocol_contract_hash: header[28..60].try_into().unwrap(),
    };
    if identity.run_id == [0; 16] {
        return invalid_data("Forge journal run_id is zero");
    }
    if identity.protocol_contract_hash != PROTOCOL_HASH {
        return invalid_data("Forge journal protocol hash is not host protocol v1");
    }
    Ok(identity)
}

fn chunk_header(
    journal_sequence: u64,
    envelope: &CanonicalRecordEnvelopeV1,
    encoded_record_len: u32,
    encoded_record_crc32c: u32,
) -> [u8; CHUNK_HEADER_LEN] {
    let mut header = [0_u8; CHUNK_HEADER_LEN];
    header[0..8].copy_from_slice(&CHUNK_MAGIC);
    header[8..16].copy_from_slice(&journal_sequence.to_le_bytes());
    header[16..18].copy_from_slice(&pod_slot(&envelope.pod_id).to_le_bytes());
    header[20..24].copy_from_slice(&encoded_record_len.to_le_bytes());
    header[24..32].copy_from_slice(&envelope.frame_start.to_le_bytes());
    header[32..40].copy_from_slice(&envelope.frame_end_exclusive.to_le_bytes());
    header[40..48].copy_from_slice(&envelope.sample_start.to_le_bytes());
    header[48..56].copy_from_slice(&envelope.sample_end_exclusive.to_le_bytes());
    header[56..64].copy_from_slice(&envelope.global_time_start_ns.to_le_bytes());
    header[64..72].copy_from_slice(&envelope.global_time_end_exclusive_ns.to_le_bytes());
    header[72..76].copy_from_slice(&encoded_record_crc32c.to_le_bytes());
    let checksum = crc32c(&header[..76]);
    header[76..80].copy_from_slice(&checksum.to_le_bytes());
    header
}

fn decode_chunk_header(header: &[u8; CHUNK_HEADER_LEN]) -> io::Result<DecodedChunkHeader> {
    if header[0..8] != CHUNK_MAGIC {
        return invalid_data("invalid journal chunk magic");
    }
    if header[18..20] != [0, 0] {
        return invalid_data("journal chunk reserved bytes are nonzero");
    }
    let expected = u32::from_le_bytes(header[76..80].try_into().unwrap());
    if crc32c(&header[..76]) != expected {
        return invalid_data("journal chunk header CRC32C mismatch");
    }
    let encoded_record_len = u32::from_le_bytes(header[20..24].try_into().unwrap()) as usize;
    if encoded_record_len == 0 || encoded_record_len > MAX_ENCODED_RECORD_LEN {
        return invalid_data("journal encoded record length exceeds safety bounds");
    }
    Ok(DecodedChunkHeader {
        journal_sequence: u64::from_le_bytes(header[8..16].try_into().unwrap()),
        pod_slot: u16::from_le_bytes(header[16..18].try_into().unwrap()),
        encoded_record_len,
        frame_start: u64::from_le_bytes(header[24..32].try_into().unwrap()),
        frame_end_exclusive: u64::from_le_bytes(header[32..40].try_into().unwrap()),
        sample_start: u64::from_le_bytes(header[40..48].try_into().unwrap()),
        sample_end_exclusive: u64::from_le_bytes(header[48..56].try_into().unwrap()),
        global_time_start_ns: u64::from_le_bytes(header[56..64].try_into().unwrap()),
        global_time_end_exclusive_ns: u64::from_le_bytes(header[64..72].try_into().unwrap()),
        encoded_record_crc32c: u32::from_le_bytes(header[72..76].try_into().unwrap()),
    })
}

fn commit_footer(journal_sequence: u64, record_crc32c: u32) -> [u8; COMMIT_FOOTER_LEN] {
    let mut footer = [0_u8; COMMIT_FOOTER_LEN];
    footer[0..8].copy_from_slice(&COMMIT_MAGIC);
    footer[8..16].copy_from_slice(&journal_sequence.to_le_bytes());
    footer[16..20].copy_from_slice(&record_crc32c.to_le_bytes());
    let checksum = crc32c(&footer[..20]);
    footer[20..24].copy_from_slice(&checksum.to_le_bytes());
    footer
}

fn validate_footer(
    footer: &[u8; COMMIT_FOOTER_LEN],
    journal_sequence: u64,
    encoded_record_crc32c: u32,
) -> io::Result<()> {
    if footer[0..8] != COMMIT_MAGIC {
        return invalid_data("invalid journal commit magic");
    }
    if u64::from_le_bytes(footer[8..16].try_into().unwrap()) != journal_sequence
        || u32::from_le_bytes(footer[16..20].try_into().unwrap()) != encoded_record_crc32c
    {
        return invalid_data("journal commit does not match chunk");
    }
    let expected = u32::from_le_bytes(footer[20..24].try_into().unwrap());
    if crc32c(&footer[..20]) != expected {
        return invalid_data("journal commit CRC32C mismatch");
    }
    Ok(())
}

fn checkpoint_bytes(
    identity: JournalIdentity,
    checkpoint: DurableCheckpoint,
) -> [u8; CHECKPOINT_LEN] {
    let mut bytes = [0_u8; CHECKPOINT_LEN];
    bytes[0..8].copy_from_slice(&CHECKPOINT_MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(CHECKPOINT_LEN as u16).to_le_bytes());
    bytes[12..20].copy_from_slice(&checkpoint.generation.to_le_bytes());
    bytes[20..36].copy_from_slice(&identity.run_id);
    bytes[36..68].copy_from_slice(&identity.protocol_contract_hash);
    bytes[68..76].copy_from_slice(&checkpoint.durable_valid_len.to_le_bytes());
    bytes[76..84].copy_from_slice(
        &checkpoint
            .durable_journal_sequence
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    bytes[84..92].copy_from_slice(&checkpoint.durable_record_count.to_le_bytes());
    let checksum = crc32c(&bytes[..124]);
    bytes[124..128].copy_from_slice(&checksum.to_le_bytes());
    bytes
}

fn decode_checkpoint(
    bytes: &[u8; CHECKPOINT_LEN],
    identity: JournalIdentity,
) -> io::Result<DurableCheckpoint> {
    if bytes[0..8] != CHECKPOINT_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != FORMAT_VERSION
        || usize::from(u16::from_le_bytes(bytes[10..12].try_into().unwrap())) != CHECKPOINT_LEN
    {
        return invalid_data("invalid durable checkpoint header");
    }
    if bytes[20..36] != identity.run_id || bytes[36..68] != identity.protocol_contract_hash {
        return invalid_data("durable checkpoint identity mismatch");
    }
    if bytes[92..124].iter().any(|byte| *byte != 0) {
        return invalid_data("durable checkpoint reserved bytes are nonzero");
    }
    if u32::from_le_bytes(bytes[124..128].try_into().unwrap()) != crc32c(&bytes[..124]) {
        return invalid_data("durable checkpoint CRC32C mismatch");
    }
    let raw_sequence = u64::from_le_bytes(bytes[76..84].try_into().unwrap());
    let checkpoint = DurableCheckpoint {
        generation: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
        durable_journal_sequence: (raw_sequence != u64::MAX).then_some(raw_sequence),
        durable_valid_len: u64::from_le_bytes(bytes[68..76].try_into().unwrap()),
        durable_record_count: u64::from_le_bytes(bytes[84..92].try_into().unwrap()),
    };
    if checkpoint.durable_valid_len < FILE_HEADER_LEN as u64
        || (checkpoint.durable_record_count == 0) != checkpoint.durable_journal_sequence.is_none()
        || checkpoint.durable_journal_sequence != checkpoint.durable_record_count.checked_sub(1)
    {
        return invalid_data("durable checkpoint invariants failed");
    }
    Ok(checkpoint)
}

fn seal_bytes(identity: JournalIdentity, seal: SealReceipt) -> [u8; SEAL_LEN] {
    let mut bytes = [0_u8; SEAL_LEN];
    bytes[0..8].copy_from_slice(&SEAL_MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(SEAL_LEN as u16).to_le_bytes());
    bytes[12..28].copy_from_slice(&identity.run_id);
    bytes[28..60].copy_from_slice(&identity.protocol_contract_hash);
    bytes[60..68].copy_from_slice(
        &seal
            .expected_last_journal_sequence
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    bytes[68..76].copy_from_slice(&seal.expected_valid_len.to_le_bytes());
    bytes[76..84].copy_from_slice(&seal.checkpoint_generation.to_le_bytes());
    bytes[84..92].copy_from_slice(&seal.record_count.to_le_bytes());
    let checksum = crc32c(&bytes[..124]);
    bytes[124..128].copy_from_slice(&checksum.to_le_bytes());
    bytes
}

fn decode_seal(bytes: &[u8; SEAL_LEN], identity: JournalIdentity) -> io::Result<SealReceipt> {
    if bytes[0..8] != SEAL_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != FORMAT_VERSION
        || usize::from(u16::from_le_bytes(bytes[10..12].try_into().unwrap())) != SEAL_LEN
    {
        return invalid_data("invalid journal seal header");
    }
    if bytes[12..28] != identity.run_id || bytes[28..60] != identity.protocol_contract_hash {
        return invalid_data("journal seal identity mismatch");
    }
    if bytes[92..124].iter().any(|byte| *byte != 0)
        || u32::from_le_bytes(bytes[124..128].try_into().unwrap()) != crc32c(&bytes[..124])
    {
        return invalid_data("journal seal CRC/reserved validation failed");
    }
    let raw_sequence = u64::from_le_bytes(bytes[60..68].try_into().unwrap());
    let seal = SealReceipt {
        expected_last_journal_sequence: (raw_sequence != u64::MAX).then_some(raw_sequence),
        expected_valid_len: u64::from_le_bytes(bytes[68..76].try_into().unwrap()),
        checkpoint_generation: u64::from_le_bytes(bytes[76..84].try_into().unwrap()),
        record_count: u64::from_le_bytes(bytes[84..92].try_into().unwrap()),
    };
    if (seal.record_count == 0) != seal.expected_last_journal_sequence.is_none()
        || seal.expected_last_journal_sequence != seal.record_count.checked_sub(1)
    {
        return invalid_data("journal seal sequence/count invariants failed");
    }
    Ok(seal)
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn read_fixed<const N: usize>(path: &Path) -> io::Result<[u8; N]> {
    let mut file = File::open(path)?;
    read_fixed_open(&mut file)
}

fn read_fixed_open<const N: usize>(file: &mut File) -> io::Result<[u8; N]> {
    preserve_file_position(file, |file| {
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = [0_u8; N];
        file.read_exact(&mut bytes)?;
        let mut trailing = [0_u8; 1];
        if file.read(&mut trailing)? != 0 {
            return invalid_data("sidecar has trailing bytes");
        }
        Ok(bytes)
    })
}

fn preserve_file_position<T>(
    file: &mut File,
    operation: impl FnOnce(&mut File) -> io::Result<T>,
) -> io::Result<T> {
    let position = file.stream_position()?;
    let result = operation(file);
    let restored = file.seek(SeekFrom::Start(position));
    match (result, restored) {
        (Ok(value), Ok(_)) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn load_checkpoint_from_open_slots(
    checkpoint_a: &mut File,
    checkpoint_b: &mut File,
    identity: JournalIdentity,
) -> io::Result<DurableCheckpoint> {
    let mut valid = Vec::with_capacity(2);
    for file in [checkpoint_a, checkpoint_b] {
        if let Ok(bytes) = read_fixed_open::<CHECKPOINT_LEN>(file) {
            if let Ok(checkpoint) = decode_checkpoint(&bytes, identity) {
                valid.push(checkpoint);
            }
        }
    }
    valid.sort_by_key(|checkpoint| checkpoint.generation);
    valid.pop().ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            "no valid A/B durable checkpoint remains",
        )
    })
}

fn load_seal_from_open(file: &mut File, identity: JournalIdentity) -> io::Result<SealReceipt> {
    let bytes = read_fixed_open::<SEAL_LEN>(file)?;
    decode_seal(&bytes, identity)
}

fn load_checkpoint(path: &Path, identity: JournalIdentity) -> io::Result<DurableCheckpoint> {
    let mut valid = Vec::new();
    let mut existed = false;
    for suffix in [".checkpoint-a", ".checkpoint-b"] {
        let slot = sidecar_path(path, suffix);
        if slot.exists() {
            existed = true;
            if let Ok(bytes) = read_fixed::<CHECKPOINT_LEN>(&slot) {
                if let Ok(checkpoint) = decode_checkpoint(&bytes, identity) {
                    valid.push(checkpoint);
                }
            }
        }
    }
    valid.sort_by_key(|checkpoint| checkpoint.generation);
    if let Some(checkpoint) = valid.pop() {
        return Ok(checkpoint);
    }
    if existed {
        return invalid_data("no valid A/B durable checkpoint remains");
    }
    // A crash immediately after the durably-created file header but before
    // either initial sidecar is safe to recover to the header boundary.
    Ok(DurableCheckpoint {
        generation: 0,
        durable_journal_sequence: None,
        durable_valid_len: FILE_HEADER_LEN as u64,
        durable_record_count: 0,
    })
}

fn load_seal(path: &Path, identity: JournalIdentity) -> io::Result<Option<SealReceipt>> {
    let path = sidecar_path(path, ".seal");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = read_fixed::<SEAL_LEN>(&path)?;
    decode_seal(&bytes, identity).map(Some)
}

fn write_checkpoint_slot(
    journal_path: &Path,
    identity: JournalIdentity,
    checkpoint: DurableCheckpoint,
    create_new: bool,
) -> io::Result<()> {
    let suffix = if checkpoint.generation.is_multiple_of(2) {
        ".checkpoint-a"
    } else {
        ".checkpoint-b"
    };
    let path = sidecar_path(journal_path, suffix);
    let mut options = OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.truncate(true);
    }
    let mut file = options.open(path)?;
    file.write_all(&checkpoint_bytes(identity, checkpoint))?;
    file.sync_all()
}

fn write_initial_checkpoints(path: &Path, identity: JournalIdentity) -> io::Result<()> {
    let initial = DurableCheckpoint {
        generation: 0,
        durable_journal_sequence: None,
        durable_valid_len: FILE_HEADER_LEN as u64,
        durable_record_count: 0,
    };
    write_checkpoint_slot(path, identity, initial, true)?;
    // The B slot starts at generation 1 but describes the same header-only
    // boundary. That makes both slots independently valid after create().
    let second = DurableCheckpoint {
        generation: 1,
        ..initial
    };
    write_checkpoint_slot(path, identity, second, true)
}

fn read_exact_or_torn<const N: usize>(file: &mut File) -> io::Result<Option<[u8; N]>> {
    let mut bytes = [0_u8; N];
    let mut read = 0;
    while read < N {
        match file.read(&mut bytes[read..])? {
            0 if read == 0 => return Ok(None),
            0 => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "torn journal tail",
                ))
            }
            count => read += count,
        }
    }
    Ok(Some(bytes))
}

#[derive(Debug)]
struct StructuralScan {
    identity: JournalIdentity,
    complete_chunks: u64,
    last_journal_sequence: Option<u64>,
    valid_len: u64,
    file_len: u64,
    torn_tail: bool,
    tracker: ContinuityTracker,
}

fn scan_structural(path: &Path, boundary: Option<u64>) -> io::Result<StructuralScan> {
    let mut file = File::open(path)?;
    scan_structural_open(&mut file, boundary)
}

/// Scans through an already-open journal while attempting to restore its
/// original cursor on every path. A successful return proves restoration. The
/// largest allocation remains one bounded canonical record, never the journal
/// file length.
fn scan_structural_open(file: &mut File, boundary: Option<u64>) -> io::Result<StructuralScan> {
    preserve_file_position(file, |file| {
        file.seek(SeekFrom::Start(0))?;
        let physical_len = file.metadata()?.len();
        let file_len = boundary.unwrap_or(physical_len);
        if file_len > physical_len || file_len < FILE_HEADER_LEN as u64 {
            return invalid_data("journal scan boundary is outside the file");
        }
        let header = read_exact_or_torn::<FILE_HEADER_LEN>(file)?
            .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "empty Forge journal"))?;
        let identity = decode_file_header(&header)?;
        let mut valid_len = FILE_HEADER_LEN as u64;
        let mut complete_chunks = 0_u64;
        let mut last_journal_sequence = None;
        let mut tracker = ContinuityTracker::default();

        loop {
            if valid_len == file_len {
                break;
            }
            let record_start = valid_len;
            if file_len - valid_len < CHUNK_HEADER_LEN as u64 {
                return Ok(StructuralScan {
                    identity,
                    complete_chunks,
                    last_journal_sequence,
                    valid_len: record_start,
                    file_len,
                    torn_tail: true,
                    tracker,
                });
            }
            let header = read_exact_or_torn::<CHUNK_HEADER_LEN>(file)?
                .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "missing chunk header"))?;
            let decoded = decode_chunk_header(&header)?;
            let expected_sequence = match last_journal_sequence {
                None => 0,
                Some(previous) => previous.checked_add(1).ok_or_else(|| {
                    io::Error::new(ErrorKind::InvalidData, "journal sequence overflow")
                })?,
            };
            if decoded.journal_sequence != expected_sequence {
                return invalid_data("non-monotonic journal append sequence");
            }
            let record_len = CHUNK_HEADER_LEN as u64
                + decoded.encoded_record_len as u64
                + COMMIT_FOOTER_LEN as u64;
            if record_start.checked_add(record_len).is_none()
                || record_start + record_len > file_len
            {
                return Ok(StructuralScan {
                    identity,
                    complete_chunks,
                    last_journal_sequence,
                    valid_len: record_start,
                    file_len,
                    torn_tail: true,
                    tracker,
                });
            }
            let mut encoded_record = vec![0_u8; decoded.encoded_record_len];
            file.read_exact(&mut encoded_record)?;
            if crc32c(&encoded_record) != decoded.encoded_record_crc32c {
                return invalid_data("journal encoded record CRC32C mismatch");
            }
            let canonical = decode_record(&encoded_record).map_err(|error| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid CanonicalRecordEnvelopeV1: {error}"),
                )
            })?;
            tracker.validate_and_advance(identity, &decoded, &canonical)?;
            let footer = read_exact_or_torn::<COMMIT_FOOTER_LEN>(file)?
                .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "missing commit footer"))?;
            validate_footer(
                &footer,
                decoded.journal_sequence,
                decoded.encoded_record_crc32c,
            )?;
            valid_len = file.stream_position()?;
            complete_chunks += 1;
            last_journal_sequence = Some(decoded.journal_sequence);
        }

        Ok(StructuralScan {
            identity,
            complete_chunks,
            last_journal_sequence,
            valid_len,
            file_len,
            torn_tail: false,
            tracker,
        })
    })
}

fn validate_checkpoint_prefix(
    path: &Path,
    identity: JournalIdentity,
    checkpoint: DurableCheckpoint,
) -> io::Result<StructuralScan> {
    let mut file = File::open(path)?;
    validate_checkpoint_prefix_open(&mut file, identity, checkpoint)
}

fn validate_checkpoint_prefix_open(
    journal: &mut File,
    identity: JournalIdentity,
    checkpoint: DurableCheckpoint,
) -> io::Result<StructuralScan> {
    let prefix = scan_structural_open(journal, Some(checkpoint.durable_valid_len))?;
    if prefix.identity != identity
        || prefix.torn_tail
        || prefix.valid_len != checkpoint.durable_valid_len
        || prefix.complete_chunks != checkpoint.durable_record_count
        || prefix.last_journal_sequence != checkpoint.durable_journal_sequence
    {
        return invalid_data("durable checkpoint does not name a validated record boundary");
    }
    Ok(prefix)
}

pub fn scan_journal(path: impl AsRef<Path>) -> io::Result<JournalScan> {
    let path = path.as_ref();
    let mut journal = File::open(path)?;
    let structural = scan_structural_open(&mut journal, None)?;
    let durable = load_checkpoint(path, structural.identity)?;
    let seal = load_seal(path, structural.identity)?;
    finish_journal_scan(&mut journal, structural, durable, seal)
}

/// Verifies one sealed journal entirely through caller-held stable handles.
/// Restoration is attempted for all four cursors on every path; a successful
/// return proves restoration. This avoids a pathname reopen between
/// stable-identity verification and semantic scanning at retention time.
pub(crate) fn scan_journal_from_open_files(
    journal: &mut File,
    checkpoint_a: &mut File,
    checkpoint_b: &mut File,
    seal: &mut File,
) -> io::Result<JournalScan> {
    let structural = scan_structural_open(journal, None)?;
    let durable = load_checkpoint_from_open_slots(checkpoint_a, checkpoint_b, structural.identity)?;
    let seal = load_seal_from_open(seal, structural.identity)?;
    finish_journal_scan(journal, structural, durable, Some(seal))
}

fn finish_journal_scan(
    journal: &mut File,
    structural: StructuralScan,
    durable: DurableCheckpoint,
    seal: Option<SealReceipt>,
) -> io::Result<JournalScan> {
    validate_checkpoint_prefix_open(journal, structural.identity, durable)?;
    if durable.durable_valid_len > structural.valid_len {
        return invalid_data("durable checkpoint extends beyond the structural journal");
    }
    if let Some(seal) = seal {
        if structural.torn_tail
            || structural.file_len != structural.valid_len
            || seal.expected_valid_len != structural.valid_len
            || seal.expected_last_journal_sequence != structural.last_journal_sequence
            || seal.record_count != structural.complete_chunks
            || seal.checkpoint_generation != durable.generation
            || durable.durable_valid_len != structural.valid_len
            || durable.durable_journal_sequence != structural.last_journal_sequence
        {
            return invalid_data("journal seal does not match durable journal contents");
        }
    }
    Ok(JournalScan {
        identity: structural.identity,
        complete_chunks: structural.complete_chunks,
        last_journal_sequence: structural.last_journal_sequence,
        valid_len: structural.valid_len,
        file_len: structural.file_len,
        torn_tail: structural.torn_tail,
        durable,
        seal,
        content_profile: structural.tracker.content_profile(),
    })
}

pub fn inspect_recovery(path: impl AsRef<Path>) -> io::Result<JournalRecovery> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let header = read_exact_or_torn::<FILE_HEADER_LEN>(&mut file)?
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "empty Forge journal"))?;
    let identity = decode_file_header(&header)?;
    let file_len = file.metadata()?.len();
    let durable = load_checkpoint(path, identity)?;
    validate_checkpoint_prefix(path, identity, durable)?;
    let seal = load_seal(path, identity)?;
    if seal.is_some() {
        // Once a seal exists, any mismatch is hard corruption; a sealed Run
        // must never be silently downgraded into a recoverable unproven tail.
        return scan_journal(path).map(JournalRecovery::Clean);
    }
    match scan_journal(path) {
        Ok(scan)
            if !scan.torn_tail
                && scan.file_len == scan.durable.durable_valid_len
                && scan.valid_len == scan.file_len =>
        {
            Ok(JournalRecovery::Clean(scan))
        }
        Ok(scan) => Ok(JournalRecovery::RecoverableUnprovenTail {
            identity,
            durable,
            file_len,
            reason: if scan.torn_tail {
                "torn bytes exist after the durable watermark".to_owned()
            } else {
                "structurally committed bytes exist after the durable watermark".to_owned()
            },
        }),
        Err(error) => Ok(JournalRecovery::RecoverableUnprovenTail {
            identity,
            durable,
            file_len,
            reason: format!("invalid bytes exist after the validated durable watermark: {error}"),
        }),
    }
}

/// Explicitly discards every byte beyond the last valid durable A/B checkpoint.
pub fn recover_to_durable(path: impl AsRef<Path>) -> io::Result<JournalScan> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let header = read_exact_or_torn::<FILE_HEADER_LEN>(&mut file)?
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "empty Forge journal"))?;
    let identity = decode_file_header(&header)?;
    if load_seal(path, identity)?.is_some() {
        return invalid_input("sealed journals cannot be recovered or truncated");
    }
    let durable = load_checkpoint(path, identity)?;
    validate_checkpoint_prefix(path, identity, durable)?;
    drop(file);
    let file = OpenOptions::new().write(true).open(path)?;
    if file.metadata()?.len() < durable.durable_valid_len {
        return invalid_data("journal is shorter than its durable watermark");
    }
    file.set_len(durable.durable_valid_len)?;
    file.sync_all()?;
    drop(file);
    scan_journal(path)
}

pub struct JournalWriter {
    file: File,
    path: PathBuf,
    identity: JournalIdentity,
    next_journal_sequence: u64,
    committed_journal_sequence: Option<u64>,
    committed_record_count: u64,
    committed_valid_len: u64,
    durable: DurableCheckpoint,
    continuity: ContinuityTracker,
    poisoned: bool,
    #[cfg(test)]
    fail_after_bytes: Option<usize>,
}

impl JournalWriter {
    /// Creates a new host-protocol-v1 journal and two durable checkpoint slots.
    /// Existing WAL or sidecars are never overwritten.
    pub fn create(path: impl AsRef<Path>, identity: JournalIdentity) -> io::Result<Self> {
        let identity = identity.validate_for_create()?;
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(&file_header(identity))?;
        file.sync_all()?;
        write_initial_checkpoints(&path, identity)?;
        file.seek(SeekFrom::Start(FILE_HEADER_LEN as u64))?;
        Ok(Self {
            file,
            path,
            identity,
            next_journal_sequence: 0,
            committed_journal_sequence: None,
            committed_record_count: 0,
            committed_valid_len: FILE_HEADER_LEN as u64,
            durable: DurableCheckpoint {
                generation: 1,
                durable_journal_sequence: None,
                durable_valid_len: FILE_HEADER_LEN as u64,
                durable_record_count: 0,
            },
            continuity: ContinuityTracker::default(),
            poisoned: false,
            #[cfg(test)]
            fail_after_bytes: None,
        })
    }

    /// Opens only a clean, unsealed journal whose file end equals its durable
    /// watermark. All other cases require explicit `recover_to_durable`.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let scan = scan_journal(&path)?;
        if scan.seal.is_some() {
            return invalid_input("sealed journal is read-only");
        }
        if scan.torn_tail
            || scan.valid_len != scan.file_len
            || scan.durable.durable_valid_len != scan.file_len
            || scan.durable.durable_journal_sequence != scan.last_journal_sequence
        {
            return invalid_data("journal has unproven tail; call recover_to_durable explicitly");
        }
        let structural = scan_structural(&path, Some(scan.file_len))?;
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        file.seek(SeekFrom::Start(scan.file_len))?;
        Ok(Self {
            file,
            path,
            identity: scan.identity,
            next_journal_sequence: scan
                .last_journal_sequence
                .map_or(0, |sequence| sequence + 1),
            committed_journal_sequence: scan.last_journal_sequence,
            committed_record_count: scan.complete_chunks,
            committed_valid_len: scan.valid_len,
            durable: scan.durable,
            continuity: structural.tracker,
            poisoned: false,
            #[cfg(test)]
            fail_after_bytes: None,
        })
    }

    pub fn append_record(&mut self, encoded_record: &[u8]) -> io::Result<AppendReceipt> {
        self.ensure_healthy()?;
        let encoded_record_len = u32::try_from(encoded_record.len())
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "encoded record is too large"))?;
        if encoded_record.is_empty() || encoded_record.len() > MAX_ENCODED_RECORD_LEN {
            return invalid_input("encoded canonical record exceeds journal safety bounds");
        }
        let canonical = decode_record(encoded_record).map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!("record is not a valid CanonicalRecordEnvelopeV1: {error}"),
            )
        })?;
        if let Err(error) = self
            .continuity
            .ensure_pod_capacity(&canonical.envelope.pod_id)
        {
            self.poisoned = true;
            return Err(error);
        }
        let following_sequence = self.next_journal_sequence.checked_add(1).ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidInput, "journal sequence space exhausted")
        })?;
        let following_count = self.committed_record_count.checked_add(1).ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidInput, "journal record count overflow")
        })?;
        let encoded_record_crc32c = crc32c(encoded_record);
        let header = chunk_header(
            self.next_journal_sequence,
            &canonical.envelope,
            encoded_record_len,
            encoded_record_crc32c,
        );
        let decoded_header = decode_chunk_header(&header)?;
        if let Err(error) = self.continuity.validate_sample_rate_rational(&canonical) {
            self.poisoned = true;
            return Err(error);
        }
        let mut next_continuity = self.continuity.clone();
        next_continuity.validate_and_advance(self.identity, &decoded_header, &canonical)?;
        let footer = commit_footer(self.next_journal_sequence, encoded_record_crc32c);

        self.write_all_checked(&header)?;
        self.write_all_checked(encoded_record)?;
        self.write_all_checked(&footer)?;
        self.committed_valid_len = self.file.stream_position().unwrap_or_else(|_| {
            self.poisoned = true;
            0
        });
        if self.poisoned {
            return Err(io::Error::other(
                "writer poisoned while obtaining committed position",
            ));
        }
        let journal_sequence = self.next_journal_sequence;
        self.next_journal_sequence = following_sequence;
        self.committed_journal_sequence = Some(journal_sequence);
        self.committed_record_count = following_count;
        self.continuity = next_continuity;
        Ok(AppendReceipt {
            journal_sequence,
            record_sequence: canonical.envelope.record_sequence,
            pod_id: canonical.envelope.pod_id,
            encoded_record_len,
            encoded_record_crc32c,
            durable: false,
        })
    }

    fn write_all_checked(&mut self, bytes: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        if let Some(remaining) = self.fail_after_bytes {
            if remaining < bytes.len() {
                if remaining > 0 {
                    self.file.write_all(&bytes[..remaining])?;
                }
                self.fail_after_bytes = Some(0);
                self.poisoned = true;
                return Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "injected short write after partial record",
                ));
            }
            self.fail_after_bytes = Some(remaining - bytes.len());
        }
        if let Err(error) = self.file.write_all(bytes) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    /// Persists the WAL first, then advances exactly one inactive A/B slot.
    pub fn durability_barrier(&mut self) -> io::Result<DurableCheckpoint> {
        self.ensure_healthy()?;
        if let Err(error) = self.file.sync_all() {
            self.poisoned = true;
            return Err(error);
        }
        let checkpoint = DurableCheckpoint {
            generation: self.durable.generation.checked_add(1).ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "checkpoint generation overflow")
            })?,
            durable_journal_sequence: self.committed_journal_sequence,
            durable_valid_len: self.committed_valid_len,
            durable_record_count: self.committed_record_count,
        };
        if let Err(error) = write_checkpoint_slot(&self.path, self.identity, checkpoint, false) {
            self.poisoned = true;
            return Err(error);
        }
        self.durable = checkpoint;
        Ok(checkpoint)
    }

    pub fn seal(mut self, expected_last_journal_sequence: Option<u64>) -> io::Result<JournalScan> {
        self.ensure_healthy()?;
        if expected_last_journal_sequence != self.committed_journal_sequence {
            return invalid_input("seal expected-last does not match committed journal");
        }
        let durable = self.durability_barrier()?;
        self.file.sync_all().inspect_err(|_| {
            self.poisoned = true;
        })?;
        let seal = SealReceipt {
            expected_last_journal_sequence,
            expected_valid_len: durable.durable_valid_len,
            checkpoint_generation: durable.generation,
            record_count: durable.durable_record_count,
        };
        let seal_path = sidecar_path(&self.path, ".seal");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(seal_path)?;
        file.write_all(&seal_bytes(self.identity, seal))?;
        file.sync_all()?;
        drop(file);
        drop(self.file);
        scan_journal(&self.path)
    }

    pub fn identity(&self) -> JournalIdentity {
        self.identity
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn ensure_healthy(&self) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "journal writer is poisoned after an earlier I/O failure",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn inject_write_failure_after(&mut self, bytes: usize) {
        self.fail_after_bytes = Some(bytes);
    }
}

pub struct JournalRecord {
    pub metadata: ChunkMetadata,
    pub canonical: DecodedRecord,
    pub encoded_record: Vec<u8>,
}

/// Read-only iterator bounded by a proven durable checkpoint or a seal.
pub struct JournalReader {
    file: File,
    identity: JournalIdentity,
    boundary: u64,
    offset: u64,
    next_journal_sequence: u64,
    continuity: ContinuityTracker,
}

impl JournalReader {
    pub fn open_durable(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let mut header_file = File::open(path)?;
        let header = read_exact_or_torn::<FILE_HEADER_LEN>(&mut header_file)?
            .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "empty Forge journal"))?;
        let identity = decode_file_header(&header)?;
        let durable = load_checkpoint(path, identity)?;
        validate_checkpoint_prefix(path, identity, durable)?;
        if load_seal(path, identity)?.is_some() {
            // A present seal is authoritative and must validate against the
            // entire file before exposing it as a sealed/durable Run.
            scan_journal(path)?;
        }
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(FILE_HEADER_LEN as u64))?;
        Ok(Self {
            file,
            identity,
            boundary: durable.durable_valid_len,
            offset: FILE_HEADER_LEN as u64,
            next_journal_sequence: 0,
            continuity: ContinuityTracker::default(),
        })
    }

    pub fn open_sealed(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let scan = scan_journal(path)?;
        if scan.seal.is_none() {
            return invalid_input("journal has no valid seal");
        }
        Self::open_durable(path)
    }
}

impl Iterator for JournalReader {
    type Item = io::Result<JournalRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.boundary {
            return None;
        }
        if self.offset > self.boundary {
            return Some(invalid_data("reader crossed its durable boundary"));
        }
        Some((|| {
            let header = read_exact_or_torn::<CHUNK_HEADER_LEN>(&mut self.file)?
                .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "missing chunk"))?;
            let decoded = decode_chunk_header(&header)?;
            if decoded.journal_sequence != self.next_journal_sequence {
                return invalid_data("reader encountered non-monotonic journal sequence");
            }
            let mut encoded_record = vec![0_u8; decoded.encoded_record_len];
            self.file.read_exact(&mut encoded_record)?;
            if crc32c(&encoded_record) != decoded.encoded_record_crc32c {
                return invalid_data("reader encoded record CRC32C mismatch");
            }
            let canonical = decode_record(&encoded_record).map_err(|error| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid CanonicalRecordEnvelopeV1: {error}"),
                )
            })?;
            self.continuity
                .validate_and_advance(self.identity, &decoded, &canonical)?;
            let footer = read_exact_or_torn::<COMMIT_FOOTER_LEN>(&mut self.file)?
                .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "missing footer"))?;
            validate_footer(
                &footer,
                decoded.journal_sequence,
                decoded.encoded_record_crc32c,
            )?;
            self.offset = self.file.stream_position()?;
            if self.offset > self.boundary {
                return invalid_data("record extends beyond durable reader boundary");
            }
            self.next_journal_sequence += 1;
            Ok(JournalRecord {
                metadata: ChunkMetadata {
                    journal_sequence: decoded.journal_sequence,
                    pod_slot: decoded.pod_slot,
                    record_sequence: canonical.envelope.record_sequence,
                    frame_start: decoded.frame_start,
                    frame_end_exclusive: decoded.frame_end_exclusive,
                    sample_start: decoded.sample_start,
                    sample_end_exclusive: decoded.sample_end_exclusive,
                    global_time_start_ns: decoded.global_time_start_ns,
                    global_time_end_exclusive_ns: decoded.global_time_end_exclusive_ns,
                },
                canonical,
                encoded_record,
            })
        })())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_protocol_v1::{
        encode_record, CanonicalRecordEnvelopeV1, FaultLayer, GapPayloadV1, GapReason,
        MarkerPayloadV1, OnlineAnalysisPayloadV1, SampleBlockV1, ANALYSIS_FLAG_REFERENCE_ONLY,
        MARKER_FLAG_OPERATOR, SAMPLE_BLOCK_FLAG_COMPLETE, SAMPLE_BLOCK_FLAG_HARDWARE_TIMESTAMPED,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "forge-acqd-{name}-{}-{stamp}.wal",
            std::process::id()
        ))
    }

    fn cleanup(path: &Path) {
        for suffix in ["", ".checkpoint-a", ".checkpoint-b", ".seal"] {
            let target = if suffix.is_empty() {
                path.to_path_buf()
            } else {
                sidecar_path(path, suffix)
            };
            let _ = std::fs::remove_file(target);
        }
    }

    fn identity() -> JournalIdentity {
        JournalIdentity::for_run([0x41; 16]).unwrap()
    }

    fn sample_record(pod: Id16, sequence: u64, sample_start: u64, flags: u32) -> Vec<u8> {
        sample_record_with_rate(pod, sequence, sample_start, flags, 2_000, 1)
    }

    fn sample_record_with_rate(
        pod: Id16,
        sequence: u64,
        sample_start: u64,
        flags: u32,
        sample_rate_numerator_hz: u32,
        sample_rate_denominator: u32,
    ) -> Vec<u8> {
        let samples_per_channel = 2;
        let block = SampleBlockV1 {
            flags: SAMPLE_BLOCK_FLAG_COMPLETE | SAMPLE_BLOCK_FLAG_HARDWARE_TIMESTAMPED,
            samples_per_channel,
            channel_count: 2,
            sample_format: 1,
            sample_rate_numerator_hz,
            sample_rate_denominator,
            first_sample_counter: sample_start,
            samples: vec![1, -1, 2, -2],
        };
        let payload = block.encode().unwrap();
        encode_record(
            &CanonicalRecordEnvelopeV1 {
                record_kind: RecordKind::SampleBlock,
                flags,
                run_id: identity().run_id,
                pod_id: pod,
                headstage_id: [0x33; 16],
                record_sequence: sequence,
                frame_start: sample_start,
                frame_end_exclusive: sample_start + samples_per_channel as u64,
                sample_start,
                sample_end_exclusive: sample_start + samples_per_channel as u64,
                global_time_start_ns: sample_start * 500_000,
                global_time_end_exclusive_ns: (sample_start + samples_per_channel as u64) * 500_000,
                channel_layout_id: 7,
                channel_count: 2,
                sample_format: 1,
            },
            &payload,
        )
        .unwrap()
    }

    fn distinct_pods(count: usize) -> Vec<Id16> {
        let mut pods = Vec::with_capacity(count);
        let mut slots = std::collections::HashSet::with_capacity(count);
        let mut seed = 1_u64;
        while pods.len() < count {
            let mut pod = [0_u8; 16];
            pod[..8].copy_from_slice(&seed.to_le_bytes());
            pod[8..].copy_from_slice(&(!seed).to_le_bytes());
            if slots.insert(pod_slot(&pod)) {
                pods.push(pod);
            }
            seed = seed.checked_add(1).unwrap();
        }
        pods
    }

    fn event_record(kind: RecordKind, sequence: u64, payload: &[u8]) -> Vec<u8> {
        encode_record(
            &CanonicalRecordEnvelopeV1 {
                record_kind: kind,
                flags: 0,
                run_id: identity().run_id,
                pod_id: [0x11; 16],
                headstage_id: [0x33; 16],
                record_sequence: sequence,
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
            payload,
        )
        .unwrap()
    }

    #[test]
    fn typed_event_payloads_are_required_before_journal_commit() {
        let path = unique_path("typed-events");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        let marker = MarkerPayloadV1 {
            event_id: [1; 16],
            marker_sequence: 0,
            marker_flags: MARKER_FLAG_OPERATOR,
            label: "baseline".into(),
            note: String::new(),
        }
        .encode()
        .unwrap();
        writer
            .append_record(&event_record(RecordKind::Marker, 1, &marker))
            .unwrap();
        let analysis = OnlineAnalysisPayloadV1 {
            event_id: [2; 16],
            worker_id: [3; 16],
            worker_build_hash: [4; 32],
            algorithm_hash: [5; 32],
            config_hash: [6; 32],
            result_schema_hash: [7; 32],
            source_record_sequence: 0,
            channel_id: 1,
            analysis_flags: ANALYSIS_FLAG_REFERENCE_ONLY,
            result: br#"{"value":9}"#.to_vec(),
        }
        .encode()
        .unwrap();
        writer
            .append_record(&event_record(RecordKind::OnlineAnalysis, 2, &analysis))
            .unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 3, 2, 0))
            .unwrap();
        writer.seal(Some(3)).unwrap();
        let records = JournalReader::open_sealed(&path)
            .unwrap()
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(records.len(), 4);
        cleanup(&path);
    }

    #[test]
    fn wrong_event_kind_and_contradictory_gap_fail_before_write() {
        let path = unique_path("bad-events");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        let marker = MarkerPayloadV1 {
            event_id: [1; 16],
            marker_sequence: 0,
            marker_flags: MARKER_FLAG_OPERATOR,
            label: "x".into(),
            note: String::new(),
        }
        .encode()
        .unwrap();
        assert!(writer
            .append_record(&event_record(RecordKind::Fault, 1, &marker))
            .is_err());
        let gap = GapPayloadV1 {
            event_id: [2; 16],
            reason: GapReason::CounterDiscontinuity,
            layer: FaultLayer::ReceiverCapture,
            gap_flags: EVENT_FAULT_FLAG_RUN_LATCHED | EVENT_FAULT_FLAG_STIM_DISARMING,
            missing_record_count: 1,
            missing_frame_count: 1,
            missing_sample_count: 99,
        }
        .encode()
        .unwrap();
        assert!(writer
            .append_record(&event_record(RecordKind::Fault, 1, &gap))
            .is_err());
        assert_eq!(writer.committed_record_count, 1);
        drop(writer);
        cleanup(&path);
    }

    #[test]
    fn rejects_arbitrary_protocol_hash_at_create() {
        let path = unique_path("bad-hash");
        let error = match JournalWriter::create(
            &path,
            JournalIdentity {
                run_id: [1; 16],
                protocol_contract_hash: [2; 32],
            },
        ) {
            Ok(_) => panic!("arbitrary protocol hash accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        cleanup(&path);
    }

    #[test]
    fn canonical_roundtrip_barrier_seal_and_read_only_iteration() {
        let path = unique_path("roundtrip");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        let first = writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        assert_eq!(first.journal_sequence, 0);
        assert!(!first.durable);
        let checkpoint = writer.durability_barrier().unwrap();
        assert_eq!(checkpoint.durable_journal_sequence, Some(0));
        writer
            .append_record(&sample_record([0x11; 16], 1, 2, 0))
            .unwrap();
        let scan = writer.seal(Some(1)).unwrap();
        assert_eq!(scan.complete_chunks, 2);
        assert_eq!(scan.last_journal_sequence, Some(1));
        assert_eq!(scan.durable.durable_journal_sequence, Some(1));
        assert!(scan.seal.is_some());
        let records: Vec<_> = JournalReader::open_sealed(&path)
            .unwrap()
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].canonical.envelope.record_sequence, 1);
        cleanup(&path);
    }

    #[test]
    fn stable_open_handle_scan_matches_path_scan_and_restores_every_cursor() {
        let path = unique_path("open-handle-scan");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 1, 2, 0))
            .unwrap();
        writer.seal(Some(1)).unwrap();
        let expected = scan_journal(&path).unwrap();

        let mut journal = File::open(&path).unwrap();
        let mut checkpoint_a = File::open(sidecar_path(&path, ".checkpoint-a")).unwrap();
        let mut checkpoint_b = File::open(sidecar_path(&path, ".checkpoint-b")).unwrap();
        let mut seal = File::open(sidecar_path(&path, ".seal")).unwrap();
        journal.seek(SeekFrom::Start(7)).unwrap();
        checkpoint_a.seek(SeekFrom::Start(3)).unwrap();
        checkpoint_b.seek(SeekFrom::Start(5)).unwrap();
        seal.seek(SeekFrom::Start(9)).unwrap();

        let actual = scan_journal_from_open_files(
            &mut journal,
            &mut checkpoint_a,
            &mut checkpoint_b,
            &mut seal,
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(journal.stream_position().unwrap(), 7);
        assert_eq!(checkpoint_a.stream_position().unwrap(), 3);
        assert_eq!(checkpoint_b.stream_position().unwrap(), 5);
        assert_eq!(seal.stream_position().unwrap(), 9);
        cleanup(&path);
    }

    #[test]
    fn complete_but_unbarriered_tail_requires_explicit_recovery() {
        let path = unique_path("unproven");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        drop(writer);
        assert!(matches!(
            inspect_recovery(&path).unwrap(),
            JournalRecovery::RecoverableUnprovenTail { .. }
        ));
        assert!(JournalWriter::open(&path).is_err());
        let recovered = recover_to_durable(&path).unwrap();
        assert_eq!(recovered.complete_chunks, 0);
        assert_eq!(recovered.file_len, FILE_HEADER_LEN as u64);
        cleanup(&path);
    }

    #[test]
    fn cutpoints_in_header_payload_and_footer_recover_only_to_watermark() {
        for (label, extra) in [("header", 3_usize), ("payload", 90), ("footer", 300)] {
            let path = unique_path(label);
            let mut writer = JournalWriter::create(&path, identity()).unwrap();
            writer
                .append_record(&sample_record([0x11; 16], 0, 0, 0))
                .unwrap();
            drop(writer);
            let full_len = std::fs::metadata(&path).unwrap().len();
            let cut = (FILE_HEADER_LEN + extra).min(full_len as usize - 1) as u64;
            let file = OpenOptions::new().write(true).open(&path).unwrap();
            file.set_len(cut).unwrap();
            file.sync_all().unwrap();
            drop(file);
            assert!(matches!(
                inspect_recovery(&path).unwrap(),
                JournalRecovery::RecoverableUnprovenTail { .. }
            ));
            let scan = recover_to_durable(&path).unwrap();
            assert_eq!(scan.complete_chunks, 0);
            cleanup(&path);
        }
    }

    #[test]
    fn one_corrupt_checkpoint_slot_falls_back_to_the_other() {
        let path = unique_path("ab-one");
        let writer = JournalWriter::create(&path, identity()).unwrap();
        drop(writer);
        let a = sidecar_path(&path, ".checkpoint-a");
        let mut bytes = std::fs::read(&a).unwrap();
        bytes[30] ^= 0xff;
        std::fs::write(&a, bytes).unwrap();
        let scan = scan_journal(&path).unwrap();
        assert_eq!(scan.durable.generation, 1);
        cleanup(&path);
    }

    #[test]
    fn both_corrupt_checkpoint_slots_fail_closed() {
        let path = unique_path("ab-both");
        let writer = JournalWriter::create(&path, identity()).unwrap();
        drop(writer);
        for suffix in [".checkpoint-a", ".checkpoint-b"] {
            let slot = sidecar_path(&path, suffix);
            let mut bytes = std::fs::read(&slot).unwrap();
            bytes[30] ^= 0xff;
            std::fs::write(slot, bytes).unwrap();
        }
        assert_eq!(
            scan_journal(&path).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        cleanup(&path);
    }

    #[test]
    fn partial_write_poisons_writer_until_process_recovery() {
        let path = unique_path("poison");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer.inject_write_failure_after(CHUNK_HEADER_LEN + 5);
        assert_eq!(
            writer
                .append_record(&sample_record([0x11; 16], 0, 0, 0))
                .unwrap_err()
                .kind(),
            ErrorKind::WriteZero
        );
        assert!(writer.is_poisoned());
        assert!(writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .is_err());
        assert!(writer.durability_barrier().is_err());
        drop(writer);
        let recovered = recover_to_durable(&path).unwrap();
        assert_eq!(recovered.complete_chunks, 0);
        cleanup(&path);
    }

    #[test]
    fn corruption_inside_durable_prefix_is_fatal() {
        let path = unique_path("durable-corrupt");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        writer.durability_barrier().unwrap();
        drop(writer);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(
            (FILE_HEADER_LEN + CHUNK_HEADER_LEN + 10) as u64,
        ))
        .unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(inspect_recovery(&path).is_err());
        assert!(recover_to_durable(&path).is_err());
        cleanup(&path);
    }

    #[test]
    fn per_pod_record_sequence_gap_is_rejected() {
        let path = unique_path("seq-gap");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        let error = writer
            .append_record(&sample_record([0x11; 16], 2, 2, 0))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        cleanup(&path);
    }

    #[test]
    fn sample_gap_requires_discontinuity_flag() {
        let path = unique_path("sample-gap");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        assert!(writer
            .append_record(&sample_record([0x11; 16], 1, 4, 0))
            .is_err());
        writer
            .append_record(&sample_record(
                [0x11; 16],
                1,
                4,
                RECORD_FLAG_DISCONTINUITY_BEFORE,
            ))
            .unwrap();
        cleanup(&path);
    }

    #[test]
    fn sample_rate_change_is_rejected_before_append_and_poisons_writer() {
        let path = unique_path("sample-rate-change");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        let before = writer.file.metadata().unwrap().len();
        let changed = sample_record_with_rate([0x11; 16], 1, 2, 0, 4_000, 2);
        let error = writer.append_record(&changed).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(writer.is_poisoned());
        assert_eq!(writer.committed_record_count, 1);
        assert_eq!(writer.file.metadata().unwrap().len(), before);
        assert!(writer
            .append_record(&sample_record([0x11; 16], 1, 2, 0))
            .is_err());
        drop(writer);
        cleanup(&path);
    }

    #[test]
    fn structural_scan_rejects_crc_valid_sample_rate_change() {
        let path = unique_path("sample-rate-scan-change");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        let next_sequence = writer.next_journal_sequence;
        drop(writer);

        let changed = sample_record_with_rate([0x11; 16], 1, 2, 0, 4_000, 2);
        let decoded = decode_record(&changed).unwrap();
        let encoded_len = u32::try_from(changed.len()).unwrap();
        let encoded_crc = crc32c(&changed);
        let header = chunk_header(next_sequence, &decoded.envelope, encoded_len, encoded_crc);
        let footer = commit_footer(next_sequence, encoded_crc);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&header).unwrap();
        file.write_all(&changed).unwrap();
        file.write_all(&footer).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let error = scan_journal(&path).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        cleanup(&path);
    }

    #[test]
    fn independent_pods_have_independent_record_sequences() {
        let path = unique_path("two-pods");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        writer
            .append_record(&sample_record([0x22; 16], 0, 0, 0))
            .unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 1, 2, 0))
            .unwrap();
        let scan = writer.seal(Some(2)).unwrap();
        assert_eq!(scan.complete_chunks, 3);
        cleanup(&path);
    }

    #[test]
    fn ninth_pod_is_rejected_before_append_poisons_writer_and_fails_scan() {
        let path = unique_path("nine-pods");
        let pods = distinct_pods(MAX_PODS_PER_RUN + 1);
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        for pod in &pods[..MAX_PODS_PER_RUN] {
            writer.append_record(&sample_record(*pod, 0, 0, 0)).unwrap();
        }
        // Reusing an admitted Pod at the product limit remains valid.
        writer
            .append_record(&sample_record(pods[0], 1, 2, 0))
            .unwrap();

        let rejected = sample_record(pods[MAX_PODS_PER_RUN], 0, 0, 0);
        let decoded = decode_record(&rejected).unwrap();
        let rejected_journal_sequence = writer.next_journal_sequence;
        let before = writer.file.metadata().unwrap().len();
        let error = writer.append_record(&rejected).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(writer.file.metadata().unwrap().len(), before);
        assert!(writer.poisoned);
        assert!(writer
            .append_record(&sample_record(pods[0], 2, 4, 0))
            .is_err());
        drop(writer);

        // Forge a structurally and CRC-valid ninth-Pod record after the
        // rejected append. Recovery scanning must enforce the same limit.
        let encoded_len = u32::try_from(rejected.len()).unwrap();
        let encoded_crc = crc32c(&rejected);
        let header = chunk_header(
            rejected_journal_sequence,
            &decoded.envelope,
            encoded_len,
            encoded_crc,
        );
        let footer = commit_footer(rejected_journal_sequence, encoded_crc);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&header).unwrap();
        file.write_all(&rejected).unwrap();
        file.write_all(&footer).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(scan_journal(&path).is_err());
        cleanup(&path);
    }

    #[test]
    fn wrong_expected_last_refuses_to_seal() {
        let path = unique_path("bad-seal");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        let error = writer.seal(Some(7)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(!sidecar_path(&path, ".seal").exists());
        cleanup(&path);
    }

    #[test]
    fn durable_reader_hides_structural_records_after_watermark() {
        let path = unique_path("reader-boundary");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        writer.durability_barrier().unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 1, 2, 0))
            .unwrap();
        let records = JournalReader::open_durable(&path)
            .unwrap()
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(records.len(), 1);
        drop(writer);
        cleanup(&path);
    }

    #[test]
    fn durable_reader_ignores_corrupt_unproven_tail() {
        let path = unique_path("reader-corrupt-tail");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        writer.durability_barrier().unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 1, 2, 0))
            .unwrap();
        drop(writer);
        let durable_len = load_checkpoint(&path, identity())
            .unwrap()
            .durable_valid_len;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(durable_len + CHUNK_HEADER_LEN as u64 + 10))
            .unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(scan_journal(&path).is_err());
        let records = JournalReader::open_durable(&path)
            .unwrap()
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(records.len(), 1);
        assert!(matches!(
            inspect_recovery(&path).unwrap(),
            JournalRecovery::RecoverableUnprovenTail { .. }
        ));
        cleanup(&path);
    }

    #[test]
    fn corrupted_seal_is_hard_failure_not_recoverable_tail() {
        let path = unique_path("seal-corrupt");
        let mut writer = JournalWriter::create(&path, identity()).unwrap();
        writer
            .append_record(&sample_record([0x11; 16], 0, 0, 0))
            .unwrap();
        writer.seal(Some(0)).unwrap();
        let seal_path = sidecar_path(&path, ".seal");
        let mut bytes = std::fs::read(&seal_path).unwrap();
        bytes[30] ^= 0xff;
        std::fs::write(seal_path, bytes).unwrap();
        assert!(inspect_recovery(&path).is_err());
        assert!(recover_to_durable(&path).is_err());
        cleanup(&path);
    }
}
