//! Frozen ForgeAnalysisRingV1 layout and bounded process-local reference core.
//!
//! The production Windows named mapping, its DACL, and live cross-process
//! acquire/release qualification are deliberately outside this module.  This
//! core owns aligned bytes with the exact frozen layout so Rust can generate
//! fixtures that the Python and C++ worker bindings validate independently.

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use forge_protocol_v1::{
    crc32c, decode_record, Id16, RecordKind, MAX_RECORD_PAYLOAD_LEN, PROTOCOL_HASH,
    RECORD_HEADER_LEN,
};

pub const ANALYSIS_RING_MAGIC: &[u8; 8] = b"FGRRNG01";
pub const ANALYSIS_RING_VERSION: u16 = 1;
pub const ANALYSIS_RING_HEADER_BYTES: usize = 256;
pub const ANALYSIS_RING_SLOT_HEADER_BYTES: usize = 64;
pub const ANALYSIS_RING_SCHEMA_HASH_HEX: &str =
    "96a5c4e07794b2ea7be3001e07436b5e3a3cd72d6e679098ba27771c640cb36e";
pub const ANALYSIS_RING_SCHEMA_HASH: [u8; 32] = [
    0x96, 0xa5, 0xc4, 0xe0, 0x77, 0x94, 0xb2, 0xea, 0x7b, 0xe3, 0x00, 0x1e, 0x07, 0x43, 0x6b, 0x5e,
    0x3a, 0x3c, 0xd7, 0x2d, 0x6e, 0x67, 0x90, 0x98, 0xba, 0x27, 0x77, 0x1c, 0x64, 0x0c, 0xb3, 0x6e,
];

const MIN_SLOT_COUNT: usize = 2;
const MAX_SLOT_COUNT: usize = 65_536;
const MIN_PAYLOAD_CAPACITY: usize = RECORD_HEADER_LEN;
const MAX_ENCODED_RECORD_BYTES: usize = RECORD_HEADER_LEN + MAX_RECORD_PAYLOAD_LEN;
const EMPTY_SLOT: u64 = u64::MAX;
const FAULT_RING_FULL: u64 = 1;
const FAULT_CONTRADICTION: u64 = 2;

const PUBLISHED_OFFSET: usize = 128;
const CONSUMED_OFFSET: usize = 136;
const DROPPED_OFFSET: usize = 144;
const PRODUCER_HEARTBEAT_OFFSET: usize = 152;
const CONSUMER_HEARTBEAT_OFFSET: usize = 160;
const FAULT_FLAGS_OFFSET: usize = 168;

/// Safety role of one independently bounded analysis consumer.
///
/// Live worker registration is observer-only today.  `Controller` is carried
/// here so an internally authenticated controller branch can be fenced by the
/// SafetyArbiter without treating every best-effort analysis consumer as a
/// stimulation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisConsumerRoleV1 {
    Observer,
    Controller,
}

/// Typed reasons by which an analysis branch becomes untrustworthy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisFaultV1 {
    RingFull,
    ConsumerLost,
    HeartbeatTimeout,
    DataGap,
    CrcFault,
    DeadlineMiss,
}

/// Immutable identity attached to every analysis fault route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisBranchIdentityV1 {
    run_id: Id16,
    consumer_id: Id16,
    producer_epoch: u64,
}

impl AnalysisBranchIdentityV1 {
    pub fn new(run_id: Id16, consumer_id: Id16, producer_epoch: u64) -> io::Result<Self> {
        if run_id == [0; 16] || consumer_id == [0; 16] || producer_epoch == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid analysis branch identity",
            ));
        }
        Ok(Self {
            run_id,
            consumer_id,
            producer_epoch,
        })
    }

    pub fn run_id(self) -> Id16 {
        self.run_id
    }

    pub fn consumer_id(self) -> Id16 {
        self.consumer_id
    }

    pub fn producer_epoch(self) -> u64 {
        self.producer_epoch
    }
}

/// Event offered to the bounded in-memory evidence queue only after the safety
/// transition is complete. Queueing does not mean durable persistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisFaultEventV1 {
    pub branch: AnalysisBranchIdentityV1,
    pub role: AnalysisConsumerRoleV1,
    pub fault: AnalysisFaultV1,
    pub observed_monotonic_ns: u64,
    pub expected_journal_sequence: Option<u64>,
    pub observed_journal_sequence: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisRingError {
    InvalidConfiguration,
    InvalidCanonicalRecord,
    NonSampleRecord,
    RecordTooLarge,
    Full,
    Contradiction,
}

impl fmt::Display for AnalysisRingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for AnalysisRingError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedAnalysisRecord {
    pub ring_sequence: u64,
    pub journal_sequence: u64,
    pub encoded_record: Vec<u8>,
}

#[repr(C, align(64))]
#[derive(Clone)]
struct CacheLine([u8; 64]);

/// Exact-layout, fixed-capacity reference ring.
///
/// The mutable API intentionally prevents this foundation from being mistaken
/// for a qualified live cross-process mapping.  The layout fields themselves
/// are atomics and use the frozen publication order.
pub struct AnalysisRing {
    storage: Box<[CacheLine]>,
    total_bytes: usize,
    slot_count: usize,
    payload_capacity: usize,
    slot_stride: usize,
    run_id: Id16,
}

impl AnalysisRing {
    pub fn new(
        slot_count: usize,
        payload_capacity: usize,
        run_id: Id16,
        consumer_id: Id16,
        producer_epoch: u64,
    ) -> Result<Self, AnalysisRingError> {
        if !(MIN_SLOT_COUNT..=MAX_SLOT_COUNT).contains(&slot_count)
            || !(MIN_PAYLOAD_CAPACITY..=MAX_ENCODED_RECORD_BYTES).contains(&payload_capacity)
            || run_id == [0; 16]
            || consumer_id == [0; 16]
            || producer_epoch == 0
        {
            return Err(AnalysisRingError::InvalidConfiguration);
        }
        let slot_stride = align64(
            ANALYSIS_RING_SLOT_HEADER_BYTES
                .checked_add(payload_capacity)
                .ok_or(AnalysisRingError::InvalidConfiguration)?,
        )
        .ok_or(AnalysisRingError::InvalidConfiguration)?;
        let total_bytes = ANALYSIS_RING_HEADER_BYTES
            .checked_add(
                slot_count
                    .checked_mul(slot_stride)
                    .ok_or(AnalysisRingError::InvalidConfiguration)?,
            )
            .ok_or(AnalysisRingError::InvalidConfiguration)?;
        let block_count = total_bytes
            .checked_add(63)
            .ok_or(AnalysisRingError::InvalidConfiguration)?
            / 64;
        let storage = vec![CacheLine([0; 64]); block_count].into_boxed_slice();
        let mut ring = Self {
            storage,
            total_bytes,
            slot_count,
            payload_capacity,
            slot_stride,
            run_id,
        };
        ring.initialize_header(consumer_id, producer_epoch);
        for index in 0..slot_count {
            ring.atomic_store(ring.slot_offset(index), EMPTY_SLOT, Ordering::Relaxed);
        }
        Ok(ring)
    }

    pub fn try_publish(
        &mut self,
        encoded_record: &[u8],
        journal_sequence: u64,
        producer_heartbeat_monotonic_ns: u64,
    ) -> Result<u64, AnalysisRingError> {
        let decoded =
            decode_record(encoded_record).map_err(|_| AnalysisRingError::InvalidCanonicalRecord)?;
        if decoded.envelope.record_kind != RecordKind::SampleBlock {
            return Err(AnalysisRingError::NonSampleRecord);
        }
        if decoded.envelope.run_id != self.run_id {
            return Err(AnalysisRingError::InvalidCanonicalRecord);
        }
        if encoded_record.len() > self.payload_capacity {
            return Err(AnalysisRingError::RecordTooLarge);
        }

        let published = self.atomic_load(PUBLISHED_OFFSET, Ordering::Relaxed);
        let consumed = self.atomic_load(CONSUMED_OFFSET, Ordering::Acquire);
        let outstanding = published
            .checked_sub(consumed)
            .ok_or_else(|| self.contradiction())?;
        if outstanding >= self.slot_count as u64 {
            self.atomic_fetch_add(DROPPED_OFFSET, 1, Ordering::Relaxed);
            self.atomic_fetch_or(FAULT_FLAGS_OFFSET, FAULT_RING_FULL, Ordering::Release);
            return Err(AnalysisRingError::Full);
        }

        let slot = published as usize % self.slot_count;
        let base = self.slot_offset(slot);
        if self.atomic_load(base, Ordering::Acquire) != EMPTY_SLOT {
            return Err(self.contradiction());
        }

        let previous_len = self.read_u32(base + 8) as usize;
        if previous_len > encoded_record.len() && previous_len <= self.payload_capacity {
            self.bytes_mut()[base + 64 + encoded_record.len()..base + 64 + previous_len].fill(0);
        }
        self.write_u32(base + 8, encoded_record.len() as u32);
        self.write_u32(base + 12, crc32c(encoded_record));
        self.write_u64(base + 16, journal_sequence);
        self.write_u64(base + 24, decoded.envelope.record_sequence);
        self.write_u64(base + 32, decoded.envelope.global_time_start_ns);
        self.write_u32(base + 40, decoded.envelope.flags);
        self.write_u32(base + 44, 0);
        self.write_u64(base + 48, !published);
        self.write_u64(base + 56, 0);
        self.bytes_mut()[base + 64..base + 64 + encoded_record.len()]
            .copy_from_slice(encoded_record);

        self.atomic_store(base, published, Ordering::Release);
        self.atomic_store(PUBLISHED_OFFSET, published + 1, Ordering::Release);
        self.atomic_store(
            PRODUCER_HEARTBEAT_OFFSET,
            producer_heartbeat_monotonic_ns,
            Ordering::Release,
        );
        Ok(published)
    }

    pub fn try_consume(
        &mut self,
        consumer_heartbeat_monotonic_ns: u64,
    ) -> Result<Option<ConsumedAnalysisRecord>, AnalysisRingError> {
        let published = self.atomic_load(PUBLISHED_OFFSET, Ordering::Acquire);
        let consumed = self.atomic_load(CONSUMED_OFFSET, Ordering::Relaxed);
        if published == consumed {
            self.atomic_store(
                CONSUMER_HEARTBEAT_OFFSET,
                consumer_heartbeat_monotonic_ns,
                Ordering::Release,
            );
            return Ok(None);
        }
        let outstanding = published
            .checked_sub(consumed)
            .ok_or_else(|| self.contradiction())?;
        if outstanding > self.slot_count as u64 {
            return Err(self.contradiction());
        }
        let slot = consumed as usize % self.slot_count;
        let base = self.slot_offset(slot);
        if self.atomic_load(base, Ordering::Acquire) != consumed
            || self.read_u64(base + 48) != !consumed
        {
            return Err(self.contradiction());
        }
        let encoded_len = self.read_u32(base + 8) as usize;
        if !(MIN_PAYLOAD_CAPACITY..=self.payload_capacity).contains(&encoded_len) {
            return Err(self.contradiction());
        }
        let encoded_record = self.bytes()[base + 64..base + 64 + encoded_len].to_vec();
        if crc32c(&encoded_record) != self.read_u32(base + 12) {
            return Err(self.contradiction());
        }
        let decoded = decode_record(&encoded_record).map_err(|_| self.contradiction())?;
        if decoded.envelope.record_kind != RecordKind::SampleBlock
            || decoded.envelope.run_id != self.run_id
            || decoded.envelope.record_sequence != self.read_u64(base + 24)
            || decoded.envelope.global_time_start_ns != self.read_u64(base + 32)
            || decoded.envelope.flags != self.read_u32(base + 40)
        {
            return Err(self.contradiction());
        }
        let journal_sequence = self.read_u64(base + 16);
        self.atomic_store(base, EMPTY_SLOT, Ordering::Release);
        self.atomic_store(CONSUMED_OFFSET, consumed + 1, Ordering::Release);
        self.atomic_store(
            CONSUMER_HEARTBEAT_OFFSET,
            consumer_heartbeat_monotonic_ns,
            Ordering::Release,
        );
        Ok(Some(ConsumedAnalysisRecord {
            ring_sequence: consumed,
            journal_sequence,
            encoded_record,
        }))
    }

    pub fn snapshot(&self) -> Vec<u8> {
        self.bytes()[..self.total_bytes].to_vec()
    }

    pub fn dropped_records(&self) -> u64 {
        self.atomic_load(DROPPED_OFFSET, Ordering::Acquire)
    }

    pub fn fault_flags(&self) -> u64 {
        self.atomic_load(FAULT_FLAGS_OFFSET, Ordering::Acquire)
    }

    fn initialize_header(&mut self, consumer_id: Id16, producer_epoch: u64) {
        let slot_count = self.slot_count as u32;
        let payload_capacity = self.payload_capacity as u32;
        let slot_stride = self.slot_stride as u64;
        let run_id = self.run_id;
        self.bytes_mut()[0..8].copy_from_slice(ANALYSIS_RING_MAGIC);
        self.write_u16(8, ANALYSIS_RING_VERSION);
        self.write_u16(10, ANALYSIS_RING_HEADER_BYTES as u16);
        self.write_u16(12, ANALYSIS_RING_SLOT_HEADER_BYTES as u16);
        self.write_u16(14, 0);
        self.write_u32(16, slot_count);
        self.write_u32(20, payload_capacity);
        self.write_u32(24, 0);
        self.write_u32(28, 0);
        self.bytes_mut()[32..64].copy_from_slice(&PROTOCOL_HASH);
        self.bytes_mut()[64..80].copy_from_slice(&run_id);
        self.bytes_mut()[80..96].copy_from_slice(&consumer_id);
        self.write_u64(96, producer_epoch);
        self.write_u64(104, slot_stride);
        let checksum = crc32c(&self.bytes()[..112]);
        self.write_u32(112, checksum);
    }

    fn slot_offset(&self, index: usize) -> usize {
        ANALYSIS_RING_HEADER_BYTES + index * self.slot_stride
    }

    fn contradiction(&self) -> AnalysisRingError {
        self.atomic_fetch_or(FAULT_FLAGS_OFFSET, FAULT_CONTRADICTION, Ordering::Release);
        AnalysisRingError::Contradiction
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: CacheLine is contiguous, contains only bytes, and total_bytes
        // never exceeds the allocated block count.
        unsafe {
            std::slice::from_raw_parts(self.storage.as_ptr().cast::<u8>(), self.storage.len() * 64)
        }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: &mut self provides unique access to the owned allocation.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.storage.as_mut_ptr().cast::<u8>(),
                self.storage.len() * 64,
            )
        }
    }

    fn atomic(&self, offset: usize) -> &AtomicU64 {
        debug_assert_eq!(offset % std::mem::align_of::<AtomicU64>(), 0);
        debug_assert!(offset + 8 <= self.total_bytes);
        // SAFETY: the allocation is 64-byte aligned, every atomic field is an
        // aligned 8-byte word, and all u64 bit patterns are valid atomics.
        unsafe {
            &*self
                .storage
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<AtomicU64>()
        }
    }

    fn atomic_load(&self, offset: usize, ordering: Ordering) -> u64 {
        self.atomic(offset).load(ordering)
    }

    fn atomic_store(&self, offset: usize, value: u64, ordering: Ordering) {
        self.atomic(offset).store(value, ordering);
    }

    fn atomic_fetch_add(&self, offset: usize, value: u64, ordering: Ordering) {
        self.atomic(offset).fetch_add(value, ordering);
    }

    fn atomic_fetch_or(&self, offset: usize, value: u64, ordering: Ordering) {
        self.atomic(offset).fetch_or(value, ordering);
    }

    fn read_u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes(
            self.bytes()[offset..offset + 4]
                .try_into()
                .expect("fixed slice"),
        )
    }

    fn read_u64(&self, offset: usize) -> u64 {
        u64::from_le_bytes(
            self.bytes()[offset..offset + 8]
                .try_into()
                .expect("fixed slice"),
        )
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        self.bytes_mut()[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        self.bytes_mut()[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(&mut self, offset: usize, value: u64) {
        self.bytes_mut()[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}

fn align64(value: usize) -> Option<usize> {
    value.checked_add(63).map(|rounded| rounded & !63)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{DeterministicReplayConfig, DeterministicReplaySource};

    fn source(total_records: u64) -> DeterministicReplaySource {
        DeterministicReplaySource::new(DeterministicReplayConfig {
            run_id: [1; 16],
            pod_id: [2; 16],
            headstage_id: [3; 16],
            channel_layout_id: 1,
            channel_count: 2,
            samples_per_channel: 30,
            sample_rate_hz: 30_000,
            total_records,
            seed: 9,
        })
        .unwrap()
    }

    fn ring(slot_count: usize) -> AnalysisRing {
        AnalysisRing::new(slot_count, 4_096, [1; 16], [4; 16], 7).unwrap()
    }

    #[test]
    fn exact_layout_round_trip_uses_canonical_record() {
        let mut source = source(1);
        let encoded = source.next_encoded_record().unwrap().unwrap();
        let mut ring = ring(2);
        assert_eq!(ring.try_publish(&encoded, 11, 100).unwrap(), 0);
        let consumed = ring.try_consume(200).unwrap().unwrap();
        assert_eq!(consumed.ring_sequence, 0);
        assert_eq!(consumed.journal_sequence, 11);
        assert_eq!(consumed.encoded_record, encoded);
        assert!(ring.try_consume(201).unwrap().is_none());
        assert_eq!(&ring.snapshot()[32..64], &PROTOCOL_HASH);
    }

    #[test]
    fn frozen_schema_hash_matches_lf_normalized_idl() {
        let normalized = include_str!("../../workers/schema/forge_analysis_ring_v1.idl")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(
            forge_protocol_v1::sha256(normalized.as_bytes()),
            ANALYSIS_RING_SCHEMA_HASH
        );
    }

    #[test]
    fn full_ring_rejects_newest_without_overwriting() {
        let mut source = source(3);
        let first = source.next_encoded_record().unwrap().unwrap();
        let second = source.next_encoded_record().unwrap().unwrap();
        let third = source.next_encoded_record().unwrap().unwrap();
        let mut ring = ring(2);
        ring.try_publish(&first, 0, 1).unwrap();
        ring.try_publish(&second, 1, 2).unwrap();
        assert_eq!(ring.try_publish(&third, 2, 3), Err(AnalysisRingError::Full));
        assert_eq!(ring.dropped_records(), 1);
        assert_eq!(ring.fault_flags(), FAULT_RING_FULL);
        assert_eq!(ring.try_consume(4).unwrap().unwrap().encoded_record, first);
        assert_eq!(ring.try_consume(5).unwrap().unwrap().encoded_record, second);
    }

    #[test]
    fn slot_crc_corruption_latches_contradiction() {
        let mut source = source(1);
        let encoded = source.next_encoded_record().unwrap().unwrap();
        let mut ring = ring(2);
        ring.try_publish(&encoded, 0, 1).unwrap();
        ring.bytes_mut()[ANALYSIS_RING_HEADER_BYTES + 64 + 180] ^= 1;
        assert_eq!(ring.try_consume(2), Err(AnalysisRingError::Contradiction));
        assert_eq!(ring.fault_flags(), FAULT_CONTRADICTION);
    }

    #[test]
    fn allocation_is_fixed_after_construction() {
        let mut source = source(10);
        let mut ring = ring(2);
        let allocation = ring.storage.as_ptr();
        for sequence in 0..10 {
            let encoded = source.next_encoded_record().unwrap().unwrap();
            ring.try_publish(&encoded, sequence, sequence).unwrap();
            ring.try_consume(sequence).unwrap().unwrap();
            assert_eq!(ring.storage.as_ptr(), allocation);
        }
    }
}
