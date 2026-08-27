//! Journal-bound source Stop evidence for one direct Receiver Pod.
//!
//! A successful transport ACK is insufficient by itself. This module builds
//! the exact hash preimage that the Receiver Pod must acknowledge after every
//! final source record has appeared earlier on the same ordered IN stream and
//! has been appended to the host journal.

use std::io;

use forge_protocol_v1::{crc32c, decode_record, sha256, AckV1, Hash32, Id16, PROTOCOL_HASH};

use crate::journal::AppendReceipt;

pub const DIRECT_POD_STOP_BOUNDARY_LEN: usize = 208;
pub const DIRECT_POD_STOP_BOUNDARY_CONTRACT_HASH_HEX: &str =
    "231b5c78e39fb871119d96d5bc5fe8aa57803e211950785194244bba79c3c09c";
pub const DIRECT_POD_STOP_BOUNDARY_CONTRACT_HASH: Hash32 = [
    0x23, 0x1b, 0x5c, 0x78, 0xe3, 0x9f, 0xb8, 0x71, 0x11, 0x9d, 0x96, 0xd5, 0xbc, 0x5f, 0xe8, 0xaa,
    0x57, 0x80, 0x3e, 0x21, 0x19, 0x50, 0x78, 0x51, 0x94, 0x24, 0x4b, 0xba, 0x79, 0xc3, 0xc0, 0x9c,
];

const MAGIC: &[u8; 8] = b"FGRSTOP1";
const VERSION: u16 = 1;
pub const STOP_ACK_CODE_APPLIED: u16 = 1;
pub const STOP_STATE_CODE_STOPPED: u16 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodStopBoundarySnapshot {
    pub source_record_count: u64,
    pub last_record_sequence: Option<u64>,
    pub last_journal_sequence: Option<u64>,
    pub last_frame_end_exclusive: Option<u64>,
    pub last_sample_end_exclusive: Option<u64>,
    pub last_global_time_end_exclusive_ns: Option<u64>,
    pub poisoned: bool,
}

pub struct DirectPodStopBoundaryTracker {
    run_id: Id16,
    device_id: Id16,
    pod_id: Id16,
    headstage_id: Id16,
    source_record_count: u64,
    last_record_sequence: Option<u64>,
    last_journal_sequence: Option<u64>,
    last_frame_end_exclusive: Option<u64>,
    last_sample_end_exclusive: Option<u64>,
    last_global_time_end_exclusive_ns: Option<u64>,
    poisoned: bool,
}

impl DirectPodStopBoundaryTracker {
    pub fn new(
        run_id: Id16,
        device_id: Id16,
        pod_id: Id16,
        headstage_id: Id16,
    ) -> io::Result<Self> {
        if [run_id, device_id, pod_id, headstage_id].contains(&[0; 16]) {
            return Err(invalid_input("direct-Pod Stop identities must be nonzero"));
        }
        Ok(Self {
            run_id,
            device_id,
            pod_id,
            headstage_id,
            source_record_count: 0,
            last_record_sequence: None,
            last_journal_sequence: None,
            last_frame_end_exclusive: None,
            last_sample_end_exclusive: None,
            last_global_time_end_exclusive_ns: None,
            poisoned: false,
        })
    }

    /// Updates the boundary only from a record plus the exact receipt returned
    /// by `JournalWriter::append_record`. Callers must invoke this after append,
    /// in the same ordered stream callback that later handles the Stop ACK.
    pub fn observe_journaled_record(
        &mut self,
        encoded_record: &[u8],
        append: AppendReceipt,
    ) -> io::Result<()> {
        self.require_healthy()?;
        let decoded = decode_record(encoded_record)
            .map_err(|_| self.poison("source boundary received an invalid canonical record"))?;
        let envelope = decoded.envelope;
        if envelope.run_id != self.run_id
            || envelope.pod_id != self.pod_id
            || envelope.headstage_id != self.headstage_id
            || append.pod_id != self.pod_id
            || append.record_sequence != envelope.record_sequence
            || append.encoded_record_len as usize != encoded_record.len()
            || append.encoded_record_crc32c != crc32c(encoded_record)
            || append.durable
        {
            return Err(self.poison("source record and journal append receipt disagree"));
        }
        match self.last_record_sequence {
            None if envelope.record_sequence != 0 => {
                return Err(self.poison("first direct-Pod source record sequence must be zero"))
            }
            Some(previous)
                if previous
                    .checked_add(1)
                    .is_none_or(|expected| envelope.record_sequence != expected) =>
            {
                return Err(self.poison("direct-Pod source record sequence is not contiguous"))
            }
            _ => {}
        }
        if self
            .last_journal_sequence
            .is_some_and(|previous| append.journal_sequence <= previous)
            || self
                .last_frame_end_exclusive
                .is_some_and(|previous| envelope.frame_end_exclusive < previous)
            || self
                .last_sample_end_exclusive
                .is_some_and(|previous| envelope.sample_end_exclusive < previous)
            || self
                .last_global_time_end_exclusive_ns
                .is_some_and(|previous| envelope.global_time_end_exclusive_ns < previous)
        {
            return Err(self.poison("direct-Pod source boundary regressed"));
        }

        self.source_record_count = self
            .source_record_count
            .checked_add(1)
            .ok_or_else(|| self.poison("direct-Pod source record count overflow"))?;
        self.last_record_sequence = Some(envelope.record_sequence);
        self.last_journal_sequence = Some(append.journal_sequence);
        self.last_frame_end_exclusive = Some(envelope.frame_end_exclusive);
        self.last_sample_end_exclusive = Some(envelope.sample_end_exclusive);
        self.last_global_time_end_exclusive_ns = Some(envelope.global_time_end_exclusive_ns);
        Ok(())
    }

    pub fn encode_boundary(
        &self,
        transport_epoch: u64,
        stop_request_id: u64,
    ) -> io::Result<Vec<u8>> {
        self.require_healthy()?;
        if transport_epoch == 0 || stop_request_id == 0 || self.source_record_count == 0 {
            return Err(invalid_input(
                "a Stop boundary requires an epoch, request ID and at least one journaled source record",
            ));
        }
        let last_record_sequence = self
            .last_record_sequence
            .ok_or_else(|| invalid_data("missing final source record sequence"))?;
        let last_frame_end_exclusive = self
            .last_frame_end_exclusive
            .ok_or_else(|| invalid_data("missing final source frame boundary"))?;
        let last_sample_end_exclusive = self
            .last_sample_end_exclusive
            .ok_or_else(|| invalid_data("missing final source sample boundary"))?;
        let last_global_time_end_exclusive_ns = self
            .last_global_time_end_exclusive_ns
            .ok_or_else(|| invalid_data("missing final source time boundary"))?;

        let mut bytes = Vec::with_capacity(DIRECT_POD_STOP_BOUNDARY_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(DIRECT_POD_STOP_BOUNDARY_LEN as u16).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&DIRECT_POD_STOP_BOUNDARY_CONTRACT_HASH);
        bytes.extend_from_slice(&self.run_id);
        bytes.extend_from_slice(&self.device_id);
        bytes.extend_from_slice(&self.pod_id);
        bytes.extend_from_slice(&self.headstage_id);
        for value in [
            transport_epoch,
            stop_request_id,
            self.source_record_count,
            last_record_sequence,
            last_frame_end_exclusive,
            last_sample_end_exclusive,
            last_global_time_end_exclusive_ns,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&PROTOCOL_HASH);
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        let checksum = crc32c(&bytes);
        bytes.extend_from_slice(&checksum.to_le_bytes());
        debug_assert_eq!(bytes.len(), DIRECT_POD_STOP_BOUNDARY_LEN);
        Ok(bytes)
    }

    pub fn receipt_hash(&self, transport_epoch: u64, stop_request_id: u64) -> io::Result<Hash32> {
        Ok(sha256(
            &self.encode_boundary(transport_epoch, stop_request_id)?,
        ))
    }

    pub fn verify_stop_ack(
        &self,
        transport_epoch: u64,
        stop_request_id: u64,
        ack: &AckV1,
    ) -> io::Result<()> {
        if ack.acknowledged_request_id != stop_request_id
            || ack.applied_epoch != transport_epoch
            || ack.ack_code != STOP_ACK_CODE_APPLIED
            || ack.state_code != STOP_STATE_CODE_STOPPED
            || ack.receipt_hash != self.receipt_hash(transport_epoch, stop_request_id)?
        {
            return Err(invalid_data(
                "Stop ACK does not bind the journaled final source boundary",
            ));
        }
        Ok(())
    }

    pub fn snapshot(&self) -> DirectPodStopBoundarySnapshot {
        DirectPodStopBoundarySnapshot {
            source_record_count: self.source_record_count,
            last_record_sequence: self.last_record_sequence,
            last_journal_sequence: self.last_journal_sequence,
            last_frame_end_exclusive: self.last_frame_end_exclusive,
            last_sample_end_exclusive: self.last_sample_end_exclusive,
            last_global_time_end_exclusive_ns: self.last_global_time_end_exclusive_ns,
            poisoned: self.poisoned,
        }
    }

    fn require_healthy(&self) -> io::Result<()> {
        if self.poisoned {
            Err(invalid_data("direct-Pod Stop boundary is poisoned"))
        } else {
            Ok(())
        }
    }

    fn poison(&mut self, message: &'static str) -> io::Error {
        self.poisoned = true;
        invalid_data(message)
    }
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
    use crate::journal::{JournalIdentity, JournalWriter};
    use crate::source::{DeterministicReplayConfig, DeterministicReplaySource};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

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

    fn unique_journal_path(name: &str) -> JournalFiles {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        JournalFiles(std::env::temp_dir().join(format!(
            "forge-direct-pod-stop-{name}-{}-{stamp}.wal",
            std::process::id()
        )))
    }

    fn records(count: u64) -> Vec<Vec<u8>> {
        let mut source = DeterministicReplaySource::new(DeterministicReplayConfig {
            run_id: [1; 16],
            pod_id: [3; 16],
            headstage_id: [4; 16],
            channel_layout_id: 1,
            channel_count: 4,
            samples_per_channel: 3,
            sample_rate_hz: 30_000,
            total_records: count,
            seed: 1,
        })
        .unwrap();
        (0..count)
            .map(|_| source.next_encoded_record().unwrap().unwrap())
            .collect()
    }

    fn append_receipt(journal_sequence: u64, record: &[u8]) -> AppendReceipt {
        let decoded = decode_record(record).unwrap();
        AppendReceipt {
            journal_sequence,
            record_sequence: decoded.envelope.record_sequence,
            pod_id: decoded.envelope.pod_id,
            encoded_record_len: record.len() as u32,
            encoded_record_crc32c: crc32c(record),
            durable: false,
        }
    }

    fn tracker_with_two_records() -> DirectPodStopBoundaryTracker {
        let mut tracker =
            DirectPodStopBoundaryTracker::new([1; 16], [2; 16], [3; 16], [4; 16]).unwrap();
        for (journal_sequence, record) in records(2).iter().enumerate() {
            tracker
                .observe_journaled_record(record, append_receipt(journal_sequence as u64, record))
                .unwrap();
        }
        tracker
    }

    fn journal_path(files: &JournalFiles) -> &Path {
        &files.0
    }

    #[test]
    fn contract_hash_matches_lf_normalized_schema() {
        let normalized = include_str!("../schema/forge_direct_pod_stop_boundary_v1.idl")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(
            sha256(normalized.as_bytes()),
            DIRECT_POD_STOP_BOUNDARY_CONTRACT_HASH
        );
    }

    #[test]
    fn exact_boundary_layout_and_ack_hash_round_trip() {
        let tracker = tracker_with_two_records();
        let bytes = tracker.encode_boundary(7, 9).unwrap();
        assert_eq!(bytes.len(), DIRECT_POD_STOP_BOUNDARY_LEN);
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(&bytes[16..48], &DIRECT_POD_STOP_BOUNDARY_CONTRACT_HASH);
        assert_eq!(u64::from_le_bytes(bytes[128..136].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(bytes[136..144].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_le_bytes(bytes[204..208].try_into().unwrap()),
            crc32c(&bytes[..204])
        );
        let actual_hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            actual_hex,
            include_str!("../golden/direct_pod_stop_boundary_v1.hex").trim()
        );
        assert_eq!(
            sha256(&bytes),
            [
                0xe9, 0x2a, 0x60, 0x2e, 0x15, 0x39, 0xac, 0x62, 0x9d, 0xc2, 0x73, 0xdd, 0x0e, 0x22,
                0xfa, 0xc5, 0xbd, 0x1c, 0x8a, 0x3c, 0x2d, 0x46, 0xc8, 0xec, 0xe5, 0xfd, 0xe1, 0xc8,
                0xb6, 0xcb, 0x7c, 0x3a,
            ]
        );
        let ack = AckV1 {
            acknowledged_request_id: 9,
            applied_epoch: 7,
            ack_code: STOP_ACK_CODE_APPLIED,
            state_code: STOP_STATE_CODE_STOPPED,
            receipt_hash: sha256(&bytes),
        };
        tracker.verify_stop_ack(7, 9, &ack).unwrap();
    }

    #[test]
    fn boundary_advances_only_after_real_journal_append_receipts() {
        let files = unique_journal_path("append");
        let mut writer = JournalWriter::create(
            journal_path(&files),
            JournalIdentity::for_run([1; 16]).unwrap(),
        )
        .unwrap();
        let mut tracker =
            DirectPodStopBoundaryTracker::new([1; 16], [2; 16], [3; 16], [4; 16]).unwrap();
        for record in records(2) {
            let receipt = writer.append_record(&record).unwrap();
            tracker.observe_journaled_record(&record, receipt).unwrap();
        }
        assert_eq!(tracker.snapshot().source_record_count, 2);
        assert_eq!(tracker.snapshot().last_journal_sequence, Some(1));
        assert!(tracker.receipt_hash(7, 9).is_ok());
    }

    #[test]
    fn wrong_ack_identity_state_or_boundary_is_rejected() {
        let tracker = tracker_with_two_records();
        let mut ack = AckV1 {
            acknowledged_request_id: 9,
            applied_epoch: 7,
            ack_code: STOP_ACK_CODE_APPLIED,
            state_code: STOP_STATE_CODE_STOPPED,
            receipt_hash: tracker.receipt_hash(7, 9).unwrap(),
        };
        ack.receipt_hash[0] ^= 1;
        assert!(tracker.verify_stop_ack(7, 9, &ack).is_err());
        ack.receipt_hash = tracker.receipt_hash(7, 9).unwrap();
        ack.state_code = 3;
        assert!(tracker.verify_stop_ack(7, 9, &ack).is_err());
        ack.state_code = STOP_STATE_CODE_STOPPED;
        ack.applied_epoch = 8;
        assert!(tracker.verify_stop_ack(7, 9, &ack).is_err());
    }

    #[test]
    fn append_receipt_mismatch_or_sequence_gap_poisons_boundary() {
        let record = records(1).pop().unwrap();
        let mut tracker =
            DirectPodStopBoundaryTracker::new([1; 16], [2; 16], [3; 16], [4; 16]).unwrap();
        let mut receipt = append_receipt(0, &record);
        receipt.encoded_record_crc32c ^= 1;
        assert!(tracker.observe_journaled_record(&record, receipt).is_err());
        assert!(tracker.snapshot().poisoned);

        let mut tracker =
            DirectPodStopBoundaryTracker::new([1; 16], [2; 16], [3; 16], [4; 16]).unwrap();
        let mut second = record.clone();
        second[72..80].copy_from_slice(&1_u64.to_le_bytes());
        let header_crc = crc32c(&second[..172]);
        second[172..176].copy_from_slice(&header_crc.to_le_bytes());
        let receipt = append_receipt(0, &second);
        assert!(tracker.observe_journaled_record(&second, receipt).is_err());
        assert!(tracker.snapshot().poisoned);
    }

    #[test]
    fn empty_or_regressing_boundary_never_produces_a_receipt() {
        let tracker =
            DirectPodStopBoundaryTracker::new([1; 16], [2; 16], [3; 16], [4; 16]).unwrap();
        assert!(tracker.receipt_hash(7, 9).is_err());
        assert!(DirectPodStopBoundaryTracker::new([0; 16], [2; 16], [3; 16], [4; 16]).is_err());
    }
}
