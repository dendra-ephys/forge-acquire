//! Bounded, fail-closed reassembly of canonical records from arbitrary chunks.
//!
//! This is a host-side transport primitive, not a claim that Receiver-Pod
//! firmware already emits the M0 record format.  A malformed frame poisons the
//! current transport epoch; implicit byte scanning would hide corruption and is
//! therefore prohibited.

use std::io;

use forge_protocol_v1::{decode_record, MAX_RECORD_PAYLOAD_LEN, RECORD_HEADER_LEN};

const RECORD_MAGIC: &[u8; 8] = b"FGRREC01";
pub const MAX_CANONICAL_RECORD_BYTES: usize = RECORD_HEADER_LEN + MAX_RECORD_PAYLOAD_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalStreamStats {
    pub transport_epoch: u64,
    pub received_bytes: u64,
    pub emitted_records: u64,
    pub emitted_bytes: u64,
    pub pending_bytes: usize,
    pub poisoned: bool,
}

/// Holds at most one canonical record. Emitted slices are valid only during the
/// callback; a caller must synchronously copy them into its owned bounded pool
/// or append them to the journal before returning.
pub struct CanonicalStreamReassembler {
    transport_epoch: u64,
    pending: Vec<u8>,
    expected_len: Option<usize>,
    received_bytes: u64,
    emitted_records: u64,
    emitted_bytes: u64,
    poisoned: bool,
}

impl CanonicalStreamReassembler {
    pub fn new(transport_epoch: u64) -> io::Result<Self> {
        if transport_epoch == 0 {
            return Err(invalid_input("transport epoch must be nonzero"));
        }
        Ok(Self {
            transport_epoch,
            pending: Vec::with_capacity(MAX_CANONICAL_RECORD_BYTES),
            expected_len: None,
            received_bytes: 0,
            emitted_records: 0,
            emitted_bytes: 0,
            poisoned: false,
        })
    }

    pub fn push(
        &mut self,
        mut chunk: &[u8],
        mut emit: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid_data("canonical stream epoch is poisoned"));
        }
        self.received_bytes = self
            .received_bytes
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| self.poison("received-byte counter overflow"))?;
        while !chunk.is_empty() {
            if self.pending.len() < 24 {
                let take = (24 - self.pending.len()).min(chunk.len());
                self.pending.extend_from_slice(&chunk[..take]);
                chunk = &chunk[take..];
                if self.pending.len() < 24 {
                    continue;
                }
                self.inspect_prefix()?;
            }
            let expected = self
                .expected_len
                .ok_or_else(|| self.poison("missing canonical record length"))?;
            let take = (expected - self.pending.len()).min(chunk.len());
            self.pending.extend_from_slice(&chunk[..take]);
            chunk = &chunk[take..];
            if self.pending.len() != expected {
                continue;
            }
            if decode_record(&self.pending).is_err() {
                return Err(self.poison("canonical record validation failed"));
            }
            if let Err(error) = emit(&self.pending) {
                self.poisoned = true;
                return Err(error);
            }
            self.emitted_records = self
                .emitted_records
                .checked_add(1)
                .ok_or_else(|| self.poison("record counter overflow"))?;
            self.emitted_bytes = self
                .emitted_bytes
                .checked_add(expected as u64)
                .ok_or_else(|| self.poison("emitted-byte counter overflow"))?;
            self.pending.clear();
            self.expected_len = None;
        }
        Ok(())
    }

    /// Stop is valid only at a record boundary. A partial tail is not silently
    /// discarded and permanently degrades the current epoch.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid_data("canonical stream epoch is poisoned"));
        }
        if !self.pending.is_empty() {
            return Err(self.poison("transport stopped with a partial canonical record"));
        }
        Ok(())
    }

    /// Recovery always requires a strictly different nonzero epoch.
    pub fn reset(&mut self, transport_epoch: u64) -> io::Result<()> {
        if transport_epoch == 0 || transport_epoch == self.transport_epoch {
            return Err(invalid_input("recovery requires a fresh transport epoch"));
        }
        self.transport_epoch = transport_epoch;
        self.pending.clear();
        self.expected_len = None;
        self.received_bytes = 0;
        self.emitted_records = 0;
        self.emitted_bytes = 0;
        self.poisoned = false;
        Ok(())
    }

    pub fn stats(&self) -> CanonicalStreamStats {
        CanonicalStreamStats {
            transport_epoch: self.transport_epoch,
            received_bytes: self.received_bytes,
            emitted_records: self.emitted_records,
            emitted_bytes: self.emitted_bytes,
            pending_bytes: self.pending.len(),
            poisoned: self.poisoned,
        }
    }

    fn inspect_prefix(&mut self) -> io::Result<()> {
        let payload_len = u32::from_le_bytes(
            self.pending[20..24]
                .try_into()
                .map_err(|_| self.poison("truncated canonical payload length"))?,
        ) as usize;
        let declared = RECORD_HEADER_LEN
            .checked_add(payload_len)
            .ok_or_else(|| self.poison("canonical record length overflow"))?;
        if declared > MAX_CANONICAL_RECORD_BYTES || &self.pending[..8] != RECORD_MAGIC {
            return Err(self.poison("invalid canonical record prefix"));
        }
        self.expected_len = Some(declared);
        Ok(())
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
    use crate::source::{DeterministicReplayConfig, DeterministicReplaySource};

    fn records(count: u64) -> Vec<Vec<u8>> {
        let mut source = DeterministicReplaySource::new(DeterministicReplayConfig {
            run_id: [1; 16],
            pod_id: [2; 16],
            headstage_id: [3; 16],
            channel_layout_id: 1,
            channel_count: 4,
            samples_per_channel: 3,
            sample_rate_hz: 30_000,
            total_records: count,
            seed: 4,
        })
        .unwrap();
        (0..count)
            .map(|_| source.next_encoded_record().unwrap().unwrap())
            .collect()
    }

    #[test]
    fn every_single_split_reassembles_exactly() {
        let record = records(1).pop().unwrap();
        for split in 0..=record.len() {
            let mut parser = CanonicalStreamReassembler::new(1).unwrap();
            let mut output = Vec::new();
            parser
                .push(&record[..split], |value| {
                    output.push(value.to_vec());
                    Ok(())
                })
                .unwrap();
            parser
                .push(&record[split..], |value| {
                    output.push(value.to_vec());
                    Ok(())
                })
                .unwrap();
            parser.finish().unwrap();
            assert_eq!(output.as_slice(), std::slice::from_ref(&record));
        }
    }

    #[test]
    fn coalesced_and_bytewise_chunks_preserve_record_boundaries() {
        let records = records(3);
        let joined: Vec<u8> = records.iter().flatten().copied().collect();
        for chunk_size in [1, 7, 64, joined.len()] {
            let mut parser = CanonicalStreamReassembler::new(7).unwrap();
            let mut output = Vec::new();
            for chunk in joined.chunks(chunk_size) {
                parser
                    .push(chunk, |value| {
                        output.push(value.to_vec());
                        Ok(())
                    })
                    .unwrap();
            }
            parser.finish().unwrap();
            assert_eq!(output, records);
            assert_eq!(parser.stats().emitted_records, 3);
        }
    }

    #[test]
    fn malformed_length_magic_and_crc_poison_without_scanning() {
        let record = records(1).pop().unwrap();
        for offset in [0, 4, record.len() - 1] {
            let mut corrupted = record.clone();
            corrupted[offset] ^= 1;
            let mut parser = CanonicalStreamReassembler::new(1).unwrap();
            assert!(parser.push(&corrupted, |_| Ok(())).is_err());
            assert!(parser.stats().poisoned);
            assert!(parser.push(&record, |_| Ok(())).is_err());
        }
    }

    #[test]
    fn partial_stop_and_callback_error_latch_epoch() {
        let record = records(1).pop().unwrap();
        let mut parser = CanonicalStreamReassembler::new(1).unwrap();
        parser.push(&record[..20], |_| Ok(())).unwrap();
        assert!(parser.finish().is_err());
        assert!(parser.stats().poisoned);
        assert!(parser.reset(1).is_err());
        parser.reset(2).unwrap();
        let error = parser.push(&record, |_| Err(io::Error::other("journal failed")));
        assert_eq!(error.unwrap_err().to_string(), "journal failed");
        assert!(parser.stats().poisoned);
    }
}
