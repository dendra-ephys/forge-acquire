//! Journal-bound Replay evidence for one direct Receiver Pod.
//!
//! A Replay ACK is not evidence that missing records reached durable storage.
//! This tracker binds the parent `ReplayRequestV1` to the exact active Run and
//! next journal record sequence, admits only a bounded contiguous sequence of
//! `REPLAYED` records, and accepts the ACK only after the final record has been
//! appended and crossed a journal durability barrier.

use std::io;

use forge_protocol_v1::{
    crc32c, decode_low_speed, decode_record, sha256, AckV1, Hash32, Id16, MessageKind,
    ReplayRequestV1, WireBody, PROTOCOL_HASH, RECORD_FLAG_REPLAYED,
};

use crate::journal::{AppendReceipt, DurableCheckpoint};

pub const DIRECT_POD_REPLAY_CONTEXT_LEN: usize = 280;
pub const DIRECT_POD_REPLAY_COMPLETION_LEN: usize = 296;
pub const DIRECT_POD_REPLAY_CONTRACT_HASH_HEX: &str =
    "f6efaca7514196deb3089aeca92752f11702c62050eb21f6b24a4019627eb8b2";
pub const DIRECT_POD_REPLAY_CONTRACT_HASH: Hash32 = [
    0xf6, 0xef, 0xac, 0xa7, 0x51, 0x41, 0x96, 0xde, 0xb3, 0x08, 0x9a, 0xec, 0xa9, 0x27, 0x52, 0xf1,
    0x17, 0x02, 0xc6, 0x20, 0x50, 0xeb, 0x21, 0xf6, 0xb2, 0x4a, 0x40, 0x19, 0x62, 0x7e, 0xb8, 0xb2,
];

pub const MAX_DIRECT_POD_REPLAY_RECORDS: u64 = 65_536;
pub const MAX_DIRECT_POD_REPLAY_ENCODED_BYTES: u64 = 256 * 1024 * 1024;
pub const REPLAY_ACK_CODE_APPLIED: u16 = 1;
pub const REPLAY_STATE_CODE_RECORDING: u16 = 3;

const CONTEXT_MAGIC: &[u8; 8] = b"FGRRCTX1";
const COMPLETION_MAGIC: &[u8; 8] = b"FGRRCMP1";
const ROLLING_RECORD_TAG: &[u8; 8] = b"FGRRREC1";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectPodReplayState {
    Receiving,
    Durable,
    Verified,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodReplayBoundarySnapshot {
    pub request_id: u64,
    pub first_record_sequence: u64,
    pub last_record_sequence_exclusive: u64,
    pub next_record_sequence: u64,
    pub replayed_record_count: u64,
    pub last_journal_sequence: Option<u64>,
    pub state: DirectPodReplayState,
    pub poisoned: bool,
}

#[derive(Clone, Debug)]
struct StagedRecord {
    record_sha256: Hash32,
    encoded_len: u32,
    encoded_crc32c: u32,
    record_sequence: u64,
    frame_end_exclusive: u64,
    sample_end_exclusive: u64,
    global_time_end_exclusive_ns: u64,
}

pub struct DirectPodReplayBoundaryTracker {
    run_id: Id16,
    device_id: Id16,
    pod_id: Id16,
    headstage_id: Id16,
    transport_epoch: u64,
    request_id: u64,
    request: ReplayRequestV1,
    context_hash: Hash32,
    rolling_record_hash: Hash32,
    next_record_sequence: u64,
    replayed_record_count: u64,
    replayed_encoded_bytes: u64,
    last_journal_sequence: Option<u64>,
    last_frame_end_exclusive: Option<u64>,
    last_sample_end_exclusive: Option<u64>,
    last_global_time_end_exclusive_ns: Option<u64>,
    staged: Option<StagedRecord>,
    state: DirectPodReplayState,
    poisoned: bool,
}

impl DirectPodReplayBoundaryTracker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: Id16,
        device_id: Id16,
        pod_id: Id16,
        headstage_id: Id16,
        transport_epoch: u64,
        request_id: u64,
        request: ReplayRequestV1,
        prior_record_sequence: Option<u64>,
        admission_receipt_file_sha256: Hash32,
        frozen_config_hash: Hash32,
    ) -> io::Result<Self> {
        if [run_id, device_id, pod_id, headstage_id].contains(&[0; 16])
            || transport_epoch == 0
            || request_id == 0
            || request.run_id != run_id
            || request.pod_id != pod_id
        {
            return Err(invalid_input(
                "direct-Pod Replay requires nonzero identities matching the active Run",
            ));
        }
        let expected_first = match prior_record_sequence {
            Some(prior) => prior
                .checked_add(1)
                .ok_or_else(|| invalid_input("direct-Pod Replay sequence overflow"))?,
            None => 0,
        };
        let requested_count = request
            .last_record_sequence_exclusive
            .checked_sub(request.first_record_sequence)
            .ok_or_else(|| invalid_input("direct-Pod Replay range is invalid"))?;
        if request.first_record_sequence != expected_first
            || requested_count == 0
            || requested_count > MAX_DIRECT_POD_REPLAY_RECORDS
        {
            return Err(invalid_input(
                "direct-Pod Replay must begin at the next journal sequence and stay within the bounded range",
            ));
        }
        let context = encode_request_context(
            run_id,
            device_id,
            pod_id,
            headstage_id,
            transport_epoch,
            request_id,
            &request,
            prior_record_sequence,
            admission_receipt_file_sha256,
            frozen_config_hash,
        )?;
        let context_hash = sha256(&context);
        if request.request_context_hash != context_hash {
            return Err(invalid_data(
                "ReplayRequestV1 context hash does not bind the active journal boundary",
            ));
        }
        Ok(Self {
            run_id,
            device_id,
            pod_id,
            headstage_id,
            transport_epoch,
            request_id,
            request,
            context_hash,
            rolling_record_hash: context_hash,
            next_record_sequence: expected_first,
            replayed_record_count: 0,
            replayed_encoded_bytes: 0,
            last_journal_sequence: None,
            last_frame_end_exclusive: None,
            last_sample_end_exclusive: None,
            last_global_time_end_exclusive_ns: None,
            staged: None,
            state: DirectPodReplayState::Receiving,
            poisoned: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn request_context_hash(
        run_id: Id16,
        device_id: Id16,
        pod_id: Id16,
        headstage_id: Id16,
        transport_epoch: u64,
        request_id: u64,
        first_record_sequence: u64,
        last_record_sequence_exclusive: u64,
        prior_record_sequence: Option<u64>,
        deadline_global_time_ns: u64,
        reason_code: u16,
        admission_receipt_file_sha256: Hash32,
        frozen_config_hash: Hash32,
    ) -> io::Result<Hash32> {
        let request = ReplayRequestV1 {
            run_id,
            pod_id,
            first_record_sequence,
            last_record_sequence_exclusive,
            deadline_global_time_ns,
            reason_code,
            request_context_hash: [1; 32],
        };
        Ok(sha256(&encode_request_context(
            run_id,
            device_id,
            pod_id,
            headstage_id,
            transport_epoch,
            request_id,
            &request,
            prior_record_sequence,
            admission_receipt_file_sha256,
            frozen_config_hash,
        )?))
    }

    pub fn verify_request_message(&self, message: &[u8]) -> io::Result<()> {
        self.require_healthy()?;
        let decoded = decode_low_speed(message)
            .map_err(|_| invalid_data("direct-Pod Replay request is not protocol v1"))?;
        let request = ReplayRequestV1::decode_body(&decoded.body)
            .map_err(|_| invalid_data("direct-Pod ReplayRequestV1 body is invalid"))?;
        if decoded.kind != MessageKind::ReplayRequest
            || decoded.request_id != self.request_id
            || decoded.epoch != self.transport_epoch
            || request != self.request
        {
            return Err(invalid_data(
                "direct-Pod Replay tracker does not match the outbound request",
            ));
        }
        Ok(())
    }

    /// Validates and stages the next replay record before journal append. A
    /// caller must immediately append these exact bytes and commit its receipt.
    pub fn stage_next_record(&mut self, encoded_record: &[u8]) -> io::Result<()> {
        self.require_receiving()?;
        if self.staged.is_some() {
            return Err(self.poison("a replay record is already staged for journal append"));
        }
        if self.next_record_sequence >= self.request.last_record_sequence_exclusive {
            return Err(self.poison("extra replay record arrived after the requested range"));
        }
        let encoded_len: u32 = encoded_record
            .len()
            .try_into()
            .map_err(|_| self.poison("Replay record length exceeds u32"))?;
        self.replayed_encoded_bytes
            .checked_add(encoded_len as u64)
            .filter(|total| *total <= MAX_DIRECT_POD_REPLAY_ENCODED_BYTES)
            .ok_or_else(|| {
                self.poison("Replay request would exceed its encoded-byte bound before append")
            })?;
        let decoded = decode_record(encoded_record)
            .map_err(|_| self.poison("Replay received an invalid canonical record"))?;
        let envelope = decoded.envelope;
        if envelope.run_id != self.run_id
            || envelope.pod_id != self.pod_id
            || envelope.headstage_id != self.headstage_id
            || envelope.record_sequence != self.next_record_sequence
            || envelope.flags & RECORD_FLAG_REPLAYED == 0
        {
            return Err(self.poison(
                "Replay record identity, sequence, or REPLAYED flag contradicts the request",
            ));
        }
        self.staged = Some(StagedRecord {
            record_sha256: sha256(encoded_record),
            encoded_len,
            encoded_crc32c: crc32c(encoded_record),
            record_sequence: envelope.record_sequence,
            frame_end_exclusive: envelope.frame_end_exclusive,
            sample_end_exclusive: envelope.sample_end_exclusive,
            global_time_end_exclusive_ns: envelope.global_time_end_exclusive_ns,
        });
        Ok(())
    }

    pub fn commit_journaled_record(&mut self, append: AppendReceipt) -> io::Result<()> {
        self.require_receiving()?;
        let staged = self
            .staged
            .take()
            .ok_or_else(|| self.poison("journal receipt arrived without a staged replay record"))?;
        if append.pod_id != self.pod_id
            || append.record_sequence != staged.record_sequence
            || append.encoded_record_len != staged.encoded_len
            || append.encoded_record_crc32c != staged.encoded_crc32c
            || append.durable
            || self
                .last_journal_sequence
                .is_some_and(|prior| append.journal_sequence <= prior)
        {
            return Err(self.poison("Replay record and journal append receipt disagree"));
        }
        let mut rolling = Vec::with_capacity(72);
        rolling.extend_from_slice(ROLLING_RECORD_TAG);
        rolling.extend_from_slice(&self.rolling_record_hash);
        rolling.extend_from_slice(&staged.record_sha256);
        self.rolling_record_hash = sha256(&rolling);
        self.replayed_record_count = self
            .replayed_record_count
            .checked_add(1)
            .ok_or_else(|| self.poison("Replay record counter overflow"))?;
        self.replayed_encoded_bytes = self
            .replayed_encoded_bytes
            .checked_add(staged.encoded_len as u64)
            .filter(|total| *total <= MAX_DIRECT_POD_REPLAY_ENCODED_BYTES)
            .ok_or_else(|| self.poison("Replay request exceeded its encoded-byte bound"))?;
        self.next_record_sequence = self
            .next_record_sequence
            .checked_add(1)
            .ok_or_else(|| self.poison("Replay record sequence overflow"))?;
        self.last_journal_sequence = Some(append.journal_sequence);
        self.last_frame_end_exclusive = Some(staged.frame_end_exclusive);
        self.last_sample_end_exclusive = Some(staged.sample_end_exclusive);
        self.last_global_time_end_exclusive_ns = Some(staged.global_time_end_exclusive_ns);
        Ok(())
    }

    pub fn mark_durable(&mut self, checkpoint: DurableCheckpoint) -> io::Result<()> {
        self.require_receiving()?;
        if self.staged.is_some()
            || self.next_record_sequence != self.request.last_record_sequence_exclusive
            || self.last_journal_sequence.is_none()
            || checkpoint
                .durable_journal_sequence
                .is_none_or(|durable| durable < self.last_journal_sequence.unwrap())
        {
            return Err(self.poison(
                "Replay cannot become durable before the complete requested range crosses the journal barrier",
            ));
        }
        self.state = DirectPodReplayState::Durable;
        Ok(())
    }

    pub fn verify_ack(&self, ack: &AckV1) -> io::Result<()> {
        self.require_healthy()?;
        if self.state != DirectPodReplayState::Durable
            || ack.acknowledged_request_id != self.request_id
            || ack.applied_epoch != self.transport_epoch
            || ack.ack_code != REPLAY_ACK_CODE_APPLIED
            || ack.state_code != REPLAY_STATE_CODE_RECORDING
            || ack.receipt_hash != self.receipt_hash()?
        {
            return Err(invalid_data(
                "Replay ACK does not bind the complete durable replay range",
            ));
        }
        Ok(())
    }

    pub fn mark_verified(&mut self) -> io::Result<()> {
        self.require_healthy()?;
        if self.state != DirectPodReplayState::Durable {
            return Err(self.poison("Replay cannot be verified before durability and ACK"));
        }
        self.state = DirectPodReplayState::Verified;
        Ok(())
    }

    pub fn reject_before_data(&mut self) -> io::Result<()> {
        self.require_healthy()?;
        if self.state != DirectPodReplayState::Receiving
            || self.replayed_record_count != 0
            || self.staged.is_some()
        {
            return Err(self.poison("Replay NACK arrived after replay data began"));
        }
        self.state = DirectPodReplayState::Rejected;
        Ok(())
    }

    pub fn encode_completion(&self) -> io::Result<Vec<u8>> {
        self.require_healthy()?;
        if !matches!(
            self.state,
            DirectPodReplayState::Durable | DirectPodReplayState::Verified
        ) || self.replayed_record_count == 0
            || self.next_record_sequence != self.request.last_record_sequence_exclusive
        {
            return Err(invalid_data(
                "Replay completion is unavailable before the full range is durable",
            ));
        }
        let mut bytes = Vec::with_capacity(DIRECT_POD_REPLAY_COMPLETION_LEN);
        bytes.extend_from_slice(COMPLETION_MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(DIRECT_POD_REPLAY_COMPLETION_LEN as u16).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&DIRECT_POD_REPLAY_CONTRACT_HASH);
        bytes.extend_from_slice(&self.context_hash);
        bytes.extend_from_slice(&self.run_id);
        bytes.extend_from_slice(&self.device_id);
        bytes.extend_from_slice(&self.pod_id);
        bytes.extend_from_slice(&self.headstage_id);
        for value in [
            self.transport_epoch,
            self.request_id,
            self.request.first_record_sequence,
            self.request.last_record_sequence_exclusive,
            self.replayed_record_count,
            self.next_record_sequence - 1,
            self.last_frame_end_exclusive.unwrap(),
            self.last_sample_end_exclusive.unwrap(),
            self.last_global_time_end_exclusive_ns.unwrap(),
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&self.rolling_record_hash);
        bytes.extend_from_slice(&PROTOCOL_HASH);
        bytes.extend_from_slice(&self.replayed_encoded_bytes.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        let checksum = crc32c(&bytes);
        bytes.extend_from_slice(&checksum.to_le_bytes());
        debug_assert_eq!(bytes.len(), DIRECT_POD_REPLAY_COMPLETION_LEN);
        Ok(bytes)
    }

    pub fn receipt_hash(&self) -> io::Result<Hash32> {
        Ok(sha256(&self.encode_completion()?))
    }

    pub fn is_receiving(&self) -> bool {
        self.state == DirectPodReplayState::Receiving && !self.poisoned
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            DirectPodReplayState::Verified | DirectPodReplayState::Rejected
        )
    }

    pub fn snapshot(&self) -> DirectPodReplayBoundarySnapshot {
        DirectPodReplayBoundarySnapshot {
            request_id: self.request_id,
            first_record_sequence: self.request.first_record_sequence,
            last_record_sequence_exclusive: self.request.last_record_sequence_exclusive,
            next_record_sequence: self.next_record_sequence,
            replayed_record_count: self.replayed_record_count,
            last_journal_sequence: self.last_journal_sequence,
            state: self.state,
            poisoned: self.poisoned,
        }
    }

    fn require_receiving(&mut self) -> io::Result<()> {
        self.require_healthy()?;
        if self.state != DirectPodReplayState::Receiving {
            Err(self.poison("direct-Pod Replay is not accepting records"))
        } else {
            Ok(())
        }
    }

    fn require_healthy(&self) -> io::Result<()> {
        if self.poisoned {
            Err(invalid_data("direct-Pod Replay boundary is poisoned"))
        } else {
            Ok(())
        }
    }

    fn poison(&mut self, message: &'static str) -> io::Error {
        self.poisoned = true;
        invalid_data(message)
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_request_context(
    run_id: Id16,
    device_id: Id16,
    pod_id: Id16,
    headstage_id: Id16,
    transport_epoch: u64,
    request_id: u64,
    request: &ReplayRequestV1,
    prior_record_sequence: Option<u64>,
    admission_receipt_file_sha256: Hash32,
    frozen_config_hash: Hash32,
) -> io::Result<Vec<u8>> {
    if [run_id, device_id, pod_id, headstage_id].contains(&[0; 16])
        || transport_epoch == 0
        || request_id == 0
        || request.run_id != run_id
        || request.pod_id != pod_id
        || request.first_record_sequence >= request.last_record_sequence_exclusive
        || request.deadline_global_time_ns == 0
        || request.reason_code == 0
        || admission_receipt_file_sha256 == [0; 32]
        || frozen_config_hash == [0; 32]
    {
        return Err(invalid_input("invalid direct-Pod Replay request context"));
    }
    let expected_first = match prior_record_sequence {
        Some(value) => value
            .checked_add(1)
            .ok_or_else(|| invalid_input("direct-Pod Replay prior sequence overflow"))?,
        None => 0,
    };
    let count = request.last_record_sequence_exclusive - request.first_record_sequence;
    if request.first_record_sequence != expected_first
        || count == 0
        || count > MAX_DIRECT_POD_REPLAY_RECORDS
    {
        return Err(invalid_input(
            "direct-Pod Replay context is not the bounded next journal range",
        ));
    }
    let mut bytes = Vec::with_capacity(DIRECT_POD_REPLAY_CONTEXT_LEN);
    bytes.extend_from_slice(CONTEXT_MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&(DIRECT_POD_REPLAY_CONTEXT_LEN as u16).to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&DIRECT_POD_REPLAY_CONTRACT_HASH);
    bytes.extend_from_slice(&PROTOCOL_HASH);
    bytes.extend_from_slice(&run_id);
    bytes.extend_from_slice(&device_id);
    bytes.extend_from_slice(&pod_id);
    bytes.extend_from_slice(&headstage_id);
    for value in [
        transport_epoch,
        request_id,
        request.first_record_sequence,
        request.last_record_sequence_exclusive,
        prior_record_sequence.unwrap_or(u64::MAX),
        request.deadline_global_time_ns,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&request.reason_code.to_le_bytes());
    bytes.extend_from_slice(&REPLAY_STATE_CODE_RECORDING.to_le_bytes());
    bytes.extend_from_slice(&admission_receipt_file_sha256);
    bytes.extend_from_slice(&frozen_config_hash);
    bytes.extend_from_slice(&MAX_DIRECT_POD_REPLAY_ENCODED_BYTES.to_le_bytes());
    bytes.extend_from_slice(&[0; 8]);
    let checksum = crc32c(&bytes);
    bytes.extend_from_slice(&checksum.to_le_bytes());
    debug_assert_eq!(bytes.len(), DIRECT_POD_REPLAY_CONTEXT_LEN);
    Ok(bytes)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_protocol_v1::{
        decode_record, encode_record, CanonicalRecordEnvelopeV1, RecordKind, SampleBlockV1,
        SAMPLE_BLOCK_FLAG_COMPLETE, SAMPLE_BLOCK_FLAG_HARDWARE_TIMESTAMPED,
    };
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    const RUN_ID: Id16 = [1; 16];
    const DEVICE_ID: Id16 = [2; 16];
    const POD_ID: Id16 = [3; 16];
    const HEADSTAGE_ID: Id16 = [4; 16];
    const EPOCH: u64 = 7;
    const REQUEST_ID: u64 = 9;
    const DEADLINE: u64 = 10_000;
    const REASON: u16 = 1;
    const ADMISSION_HASH: Hash32 = [5; 32];
    const FROZEN_CONFIG_HASH: Hash32 = [6; 32];

    struct JournalFiles(PathBuf);

    impl Drop for JournalFiles {
        fn drop(&mut self) {
            for suffix in ["", ".checkpoint-a", ".checkpoint-b", ".seal"] {
                let target = if suffix.is_empty() {
                    self.0.clone()
                } else {
                    PathBuf::from(format!("{}{suffix}", self.0.display()))
                };
                let _ = std::fs::remove_file(target);
            }
        }
    }

    fn journal_path(name: &str) -> JournalFiles {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        JournalFiles(std::env::temp_dir().join(format!(
            "forge-direct-pod-replay-{name}-{}-{stamp}.wal",
            std::process::id()
        )))
    }

    fn replay_record(sequence: u64) -> Vec<u8> {
        let sample_start = sequence * 3;
        let block = SampleBlockV1 {
            flags: SAMPLE_BLOCK_FLAG_COMPLETE | SAMPLE_BLOCK_FLAG_HARDWARE_TIMESTAMPED,
            samples_per_channel: 3,
            channel_count: 2,
            sample_format: 1,
            sample_rate_numerator_hz: 30_000,
            sample_rate_denominator: 1,
            first_sample_counter: sample_start,
            samples: vec![sequence as i16; 6],
        };
        let payload = block.encode().unwrap();
        encode_record(
            &CanonicalRecordEnvelopeV1 {
                record_kind: RecordKind::SampleBlock,
                flags: RECORD_FLAG_REPLAYED,
                run_id: RUN_ID,
                pod_id: POD_ID,
                headstage_id: HEADSTAGE_ID,
                record_sequence: sequence,
                frame_start: sample_start,
                frame_end_exclusive: sample_start + 3,
                sample_start,
                sample_end_exclusive: sample_start + 3,
                global_time_start_ns: sequence * 100_000,
                global_time_end_exclusive_ns: (sequence + 1) * 100_000,
                channel_layout_id: 1,
                channel_count: 2,
                sample_format: 1,
            },
            &payload,
        )
        .unwrap()
    }

    fn request(first: u64, last_exclusive: u64, prior: Option<u64>) -> ReplayRequestV1 {
        let context_hash = DirectPodReplayBoundaryTracker::request_context_hash(
            RUN_ID,
            DEVICE_ID,
            POD_ID,
            HEADSTAGE_ID,
            EPOCH,
            REQUEST_ID,
            first,
            last_exclusive,
            prior,
            DEADLINE,
            REASON,
            ADMISSION_HASH,
            FROZEN_CONFIG_HASH,
        )
        .unwrap();
        ReplayRequestV1 {
            run_id: RUN_ID,
            pod_id: POD_ID,
            first_record_sequence: first,
            last_record_sequence_exclusive: last_exclusive,
            deadline_global_time_ns: DEADLINE,
            reason_code: REASON,
            request_context_hash: context_hash,
        }
    }

    fn tracker(
        first: u64,
        last_exclusive: u64,
        prior: Option<u64>,
    ) -> DirectPodReplayBoundaryTracker {
        DirectPodReplayBoundaryTracker::new(
            RUN_ID,
            DEVICE_ID,
            POD_ID,
            HEADSTAGE_ID,
            EPOCH,
            REQUEST_ID,
            request(first, last_exclusive, prior),
            prior,
            ADMISSION_HASH,
            FROZEN_CONFIG_HASH,
        )
        .unwrap()
    }

    fn append_all(
        tracker: &mut DirectPodReplayBoundaryTracker,
        writer: &mut crate::journal::JournalWriter,
        records: &[Vec<u8>],
    ) {
        for record in records {
            tracker.stage_next_record(record).unwrap();
            let receipt = writer.append_record(record).unwrap();
            tracker.commit_journaled_record(receipt).unwrap();
        }
    }

    #[test]
    fn contract_hash_matches_lf_normalized_schema() {
        let normalized = include_str!("../schema/forge_direct_pod_replay_boundary_v1.idl")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(
            sha256(normalized.as_bytes()),
            DIRECT_POD_REPLAY_CONTRACT_HASH
        );
    }

    #[test]
    fn exact_context_binds_next_journal_range_and_all_identities() {
        let request = request(2, 4, Some(1));
        let tracker = DirectPodReplayBoundaryTracker::new(
            RUN_ID,
            DEVICE_ID,
            POD_ID,
            HEADSTAGE_ID,
            EPOCH,
            REQUEST_ID,
            request.clone(),
            Some(1),
            ADMISSION_HASH,
            FROZEN_CONFIG_HASH,
        )
        .unwrap();
        assert_eq!(tracker.context_hash, request.request_context_hash);
        assert_eq!(tracker.snapshot().next_record_sequence, 2);

        let mut wrong = request.clone();
        wrong.request_context_hash[0] ^= 1;
        assert!(DirectPodReplayBoundaryTracker::new(
            RUN_ID,
            DEVICE_ID,
            POD_ID,
            HEADSTAGE_ID,
            EPOCH,
            REQUEST_ID,
            wrong,
            Some(1),
            ADMISSION_HASH,
            FROZEN_CONFIG_HASH,
        )
        .is_err());
        assert!(DirectPodReplayBoundaryTracker::new(
            RUN_ID,
            DEVICE_ID,
            POD_ID,
            HEADSTAGE_ID,
            EPOCH,
            REQUEST_ID,
            request,
            Some(0),
            ADMISSION_HASH,
            FROZEN_CONFIG_HASH,
        )
        .is_err());
        assert!(tracker.receipt_hash().is_err());
    }

    #[test]
    fn independent_python_context_golden_matches_exact_bytes() {
        let request = request(0, 2, None);
        let bytes = encode_request_context(
            RUN_ID,
            DEVICE_ID,
            POD_ID,
            HEADSTAGE_ID,
            EPOCH,
            REQUEST_ID,
            &request,
            None,
            ADMISSION_HASH,
            FROZEN_CONFIG_HASH,
        )
        .unwrap();
        let actual = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            actual,
            include_str!("../golden/direct_pod_replay_context_v1.hex").trim()
        );
        assert_eq!(
            sha256(&bytes),
            [
                0xd7, 0xac, 0xc5, 0x75, 0xc1, 0x9d, 0x9f, 0x60, 0x68, 0xad, 0xdf, 0x4f, 0xe3, 0xac,
                0x1a, 0x8a, 0x69, 0x19, 0x2c, 0xc5, 0xfb, 0xbf, 0x15, 0x78, 0x1d, 0x10, 0x10, 0xa0,
                0x3c, 0x61, 0x2d, 0x22,
            ]
        );
    }

    #[test]
    fn replay_ack_requires_complete_durable_journaled_range() {
        let files = journal_path("durable");
        let mut writer = crate::journal::JournalWriter::create(
            Path::new(&files.0),
            crate::journal::JournalIdentity::for_run(RUN_ID).unwrap(),
        )
        .unwrap();
        let mut tracker = tracker(0, 2, None);
        let records = [replay_record(0), replay_record(1)];
        append_all(&mut tracker, &mut writer, &records);
        let early = AckV1 {
            acknowledged_request_id: REQUEST_ID,
            applied_epoch: EPOCH,
            ack_code: REPLAY_ACK_CODE_APPLIED,
            state_code: REPLAY_STATE_CODE_RECORDING,
            receipt_hash: [1; 32],
        };
        assert!(tracker.verify_ack(&early).is_err());
        let checkpoint = writer.durability_barrier().unwrap();
        tracker.mark_durable(checkpoint).unwrap();
        let completion = tracker.encode_completion().unwrap();
        assert_eq!(completion.len(), DIRECT_POD_REPLAY_COMPLETION_LEN);
        assert_eq!(&completion[..8], COMPLETION_MAGIC);
        assert_eq!(
            u32::from_le_bytes(completion[292..296].try_into().unwrap()),
            crc32c(&completion[..292])
        );
        let actual = completion
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            actual,
            include_str!("../golden/direct_pod_replay_completion_v1.hex").trim()
        );
        assert_eq!(
            sha256(&completion),
            [
                0xe5, 0x21, 0x93, 0x02, 0x5e, 0xa7, 0x5d, 0x31, 0xcb, 0xfe, 0x2b, 0xca, 0x48, 0xa8,
                0xfc, 0x05, 0x18, 0x40, 0x4e, 0x3a, 0xaf, 0x88, 0xf8, 0xbc, 0xc1, 0xf0, 0xec, 0xc9,
                0x68, 0x8b, 0xad, 0x89,
            ]
        );
        let ack = AckV1 {
            receipt_hash: sha256(&completion),
            ..early
        };
        tracker.verify_ack(&ack).unwrap();
        tracker.mark_verified().unwrap();
        assert_eq!(tracker.snapshot().state, DirectPodReplayState::Verified);
    }

    #[test]
    fn wrong_flag_order_identity_and_append_receipt_poison_before_completion() {
        let valid = replay_record(0);
        let decoded = decode_record(&valid).unwrap();
        let no_flag = encode_record(
            &CanonicalRecordEnvelopeV1 {
                flags: 0,
                ..decoded.envelope.clone()
            },
            &decoded.payload,
        )
        .unwrap();
        let mut missing_flag = tracker(0, 1, None);
        assert!(missing_flag.stage_next_record(&no_flag).is_err());
        assert!(missing_flag.snapshot().poisoned);

        let mut wrong_order = tracker(0, 2, None);
        assert!(wrong_order.stage_next_record(&replay_record(1)).is_err());

        let mut wrong_receipt = tracker(0, 1, None);
        wrong_receipt.stage_next_record(&valid).unwrap();
        let mut receipt = AppendReceipt {
            journal_sequence: 0,
            record_sequence: 0,
            pod_id: POD_ID,
            encoded_record_len: valid.len() as u32,
            encoded_record_crc32c: crc32c(&valid),
            durable: false,
        };
        receipt.encoded_record_crc32c ^= 1;
        assert!(wrong_receipt.commit_journaled_record(receipt).is_err());
    }

    #[test]
    fn nack_is_allowed_only_before_any_replay_data() {
        let mut before = tracker(0, 1, None);
        before.reject_before_data().unwrap();
        assert_eq!(before.snapshot().state, DirectPodReplayState::Rejected);

        let mut after = tracker(0, 1, None);
        after.stage_next_record(&replay_record(0)).unwrap();
        assert!(after.reject_before_data().is_err());
        assert!(after.snapshot().poisoned);
    }

    #[test]
    fn request_range_is_strictly_bounded() {
        assert!(DirectPodReplayBoundaryTracker::request_context_hash(
            RUN_ID,
            DEVICE_ID,
            POD_ID,
            HEADSTAGE_ID,
            EPOCH,
            REQUEST_ID,
            0,
            MAX_DIRECT_POD_REPLAY_RECORDS + 1,
            None,
            DEADLINE,
            REASON,
            ADMISSION_HASH,
            FROZEN_CONFIG_HASH,
        )
        .is_err());

        let mut encoded_bytes = tracker(0, 1, None);
        encoded_bytes.replayed_encoded_bytes = MAX_DIRECT_POD_REPLAY_ENCODED_BYTES;
        assert!(encoded_bytes.stage_next_record(&replay_record(0)).is_err());
        assert!(encoded_bytes.staged.is_none());
        assert!(encoded_bytes.snapshot().poisoned);
    }
}
