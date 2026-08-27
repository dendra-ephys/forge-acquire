//! Strict direct-Pod FT601 stream demultiplexer.
//!
//! The single FT601 IN channel may carry exact M0 canonical records and exact
//! M0 low-speed replies. There is no extra USB packet framing and no byte-scan
//! resynchronization: the next byte must begin one valid message. Any malformed
//! prefix/body, consumer failure, or partial terminal message poisons the
//! transport epoch and requires a fresh device/replay epoch.

use std::io;

use forge_protocol_v1::{
    decode_low_speed, decode_record, LOW_SPEED_HEADER_LEN, MAX_LOW_SPEED_MESSAGE_LEN,
    MAX_RECORD_PAYLOAD_LEN, RECORD_HEADER_LEN,
};

use crate::direct_pod_cabline::{DirectPodCablineStatusV1, DIRECT_POD_CABLINE_STATUS_LEN};
use crate::direct_pod_dhl_identity::{
    DirectPodDhlIdentityCapsuleV1, DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MAX_LEN,
    DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MIN_LEN,
};
use crate::direct_pod_replay_offer::{DirectPodReplayOfferV1, DIRECT_POD_REPLAY_OFFER_LEN};
use crate::direct_pod_time::{DirectPodTimeSnapshotV1, DIRECT_POD_TIME_SNAPSHOT_LEN};

const RECORD_MAGIC: &[u8; 8] = b"FGRREC01";
const CONTROL_MAGIC: &[u8; 8] = b"FGRCTL01";
const TIME_MAGIC: &[u8; 8] = b"FGRTIM01";
const REPLAY_OFFER_MAGIC: &[u8; 8] = b"FGRRPO01";
const CABLINE_STATUS_MAGIC: &[u8; 8] = b"FGRCAB01";
const DHL_IDENTITY_CAPSULE_MAGIC: &[u8; 8] = b"FGRDHI01";
const PREFIX_BYTES: usize = 12;
const RECORD_LENGTH_PREFIX_BYTES: usize = 24;
const MAX_DIRECT_POD_MESSAGE_BYTES: usize = {
    let record_max = RECORD_HEADER_LEN + MAX_RECORD_PAYLOAD_LEN;
    let control_or_record_max = if record_max > MAX_LOW_SPEED_MESSAGE_LEN {
        record_max
    } else {
        MAX_LOW_SPEED_MESSAGE_LEN
    };
    if control_or_record_max > DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MAX_LEN {
        control_or_record_max
    } else {
        DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MAX_LEN
    }
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectPodFrameKind {
    CanonicalRecord,
    LowSpeedMessage,
    TimeSnapshot,
    ReplayOffer,
}

/// Extended source-stream classification used while CABLINE status is staged
/// ahead of its journal/availability integration. The legacy `push` API stays
/// fail-closed for this new companion until its owner explicitly opts in via
/// `push_with_cabline`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectPodExtendedFrameKind {
    CanonicalRecord,
    LowSpeedMessage,
    TimeSnapshot,
    ReplayOffer,
    CablineStatus,
}

/// Widest Direct-Pod source-stream classification.  It deliberately leaves
/// [`DirectPodExtendedFrameKind`] unchanged so existing CABLINE consumers do
/// not need to acknowledge identity evidence until their preflight path opts
/// in through [`DirectPodStreamReassembler::push_with_identity`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectPodIdentityFrameKind {
    CanonicalRecord,
    LowSpeedMessage,
    TimeSnapshot,
    ReplayOffer,
    CablineStatus,
    DhlIdentityCapsule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodStreamStats {
    pub transport_epoch: u64,
    pub received_bytes: u64,
    pub canonical_records: u64,
    pub low_speed_messages: u64,
    pub time_snapshots: u64,
    pub replay_offers: u64,
    pub emitted_bytes: u64,
    pub pending_bytes: usize,
    pub poisoned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodExtendedStreamStats {
    pub base: DirectPodStreamStats,
    pub cabline_statuses: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodIdentityStreamStats {
    pub base: DirectPodExtendedStreamStats,
    pub dhl_identity_capsules: u64,
}

pub struct DirectPodStreamReassembler {
    transport_epoch: u64,
    pending: Vec<u8>,
    expected_len: Option<usize>,
    pending_kind: Option<DirectPodIdentityFrameKind>,
    received_bytes: u64,
    canonical_records: u64,
    low_speed_messages: u64,
    time_snapshots: u64,
    replay_offers: u64,
    cabline_statuses: u64,
    dhl_identity_capsules: u64,
    emitted_bytes: u64,
    poisoned: bool,
}

impl DirectPodStreamReassembler {
    pub fn new(transport_epoch: u64) -> io::Result<Self> {
        if transport_epoch == 0 {
            return Err(invalid_input("transport epoch must be nonzero"));
        }
        Ok(Self {
            transport_epoch,
            pending: Vec::with_capacity(MAX_DIRECT_POD_MESSAGE_BYTES),
            expected_len: None,
            pending_kind: None,
            received_bytes: 0,
            canonical_records: 0,
            low_speed_messages: 0,
            time_snapshots: 0,
            replay_offers: 0,
            cabline_statuses: 0,
            dhl_identity_capsules: 0,
            emitted_bytes: 0,
            poisoned: false,
        })
    }

    pub fn push(
        &mut self,
        chunk: &[u8],
        mut emit: impl FnMut(DirectPodFrameKind, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        self.push_with_identity(chunk, |kind, bytes| match kind {
            DirectPodIdentityFrameKind::CanonicalRecord => {
                emit(DirectPodFrameKind::CanonicalRecord, bytes)
            }
            DirectPodIdentityFrameKind::LowSpeedMessage => {
                emit(DirectPodFrameKind::LowSpeedMessage, bytes)
            }
            DirectPodIdentityFrameKind::TimeSnapshot => {
                emit(DirectPodFrameKind::TimeSnapshot, bytes)
            }
            DirectPodIdentityFrameKind::ReplayOffer => emit(DirectPodFrameKind::ReplayOffer, bytes),
            DirectPodIdentityFrameKind::CablineStatus => Err(invalid_data(
                "CABLINE status consumer is not bound to the legacy stream API",
            )),
            DirectPodIdentityFrameKind::DhlIdentityCapsule => Err(invalid_data(
                "DHL identity capsule consumer is not bound to the legacy stream API",
            )),
        })
    }

    pub fn push_with_cabline(
        &mut self,
        chunk: &[u8],
        mut emit: impl FnMut(DirectPodExtendedFrameKind, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        self.push_with_identity(chunk, |kind, bytes| match kind {
            DirectPodIdentityFrameKind::CanonicalRecord => {
                emit(DirectPodExtendedFrameKind::CanonicalRecord, bytes)
            }
            DirectPodIdentityFrameKind::LowSpeedMessage => {
                emit(DirectPodExtendedFrameKind::LowSpeedMessage, bytes)
            }
            DirectPodIdentityFrameKind::TimeSnapshot => {
                emit(DirectPodExtendedFrameKind::TimeSnapshot, bytes)
            }
            DirectPodIdentityFrameKind::ReplayOffer => {
                emit(DirectPodExtendedFrameKind::ReplayOffer, bytes)
            }
            DirectPodIdentityFrameKind::CablineStatus => {
                emit(DirectPodExtendedFrameKind::CablineStatus, bytes)
            }
            DirectPodIdentityFrameKind::DhlIdentityCapsule => Err(invalid_data(
                "DHL identity capsule consumer is not bound to the CABLINE stream API",
            )),
        })
    }

    /// Reassembles all currently defined source message kinds.  This only
    /// validates and classifies identity evidence; it does not admit policy,
    /// advance Ready, open D3XX, or authorize stimulation.
    pub fn push_with_identity(
        &mut self,
        mut chunk: &[u8],
        mut emit: impl FnMut(DirectPodIdentityFrameKind, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid_data("direct-Pod stream epoch is poisoned"));
        }
        self.received_bytes = self
            .received_bytes
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| self.poison("received-byte counter overflow"))?;

        while !chunk.is_empty() {
            if self.expected_len.is_none() {
                fill_to(&mut self.pending, PREFIX_BYTES, &mut chunk);
                if self.pending.len() < PREFIX_BYTES {
                    continue;
                }
                self.inspect_prefix(&mut chunk)?;
                if self.expected_len.is_none() {
                    continue;
                }
            }

            let expected = self
                .expected_len
                .ok_or_else(|| self.poison("missing direct-Pod message length"))?;
            fill_to(&mut self.pending, expected, &mut chunk);
            if self.pending.len() != expected {
                continue;
            }
            let kind = self
                .pending_kind
                .ok_or_else(|| self.poison("missing direct-Pod message kind"))?;
            let valid = match kind {
                DirectPodIdentityFrameKind::CanonicalRecord => decode_record(&self.pending).is_ok(),
                DirectPodIdentityFrameKind::LowSpeedMessage => {
                    decode_low_speed(&self.pending).is_ok()
                }
                DirectPodIdentityFrameKind::TimeSnapshot => {
                    DirectPodTimeSnapshotV1::decode(&self.pending).is_ok()
                }
                DirectPodIdentityFrameKind::ReplayOffer => {
                    DirectPodReplayOfferV1::decode(&self.pending).is_ok()
                }
                DirectPodIdentityFrameKind::CablineStatus => {
                    DirectPodCablineStatusV1::decode(&self.pending).is_ok()
                }
                DirectPodIdentityFrameKind::DhlIdentityCapsule => {
                    DirectPodDhlIdentityCapsuleV1::decode(&self.pending).is_ok()
                }
            };
            if !valid {
                return Err(self.poison("direct-Pod message validation failed"));
            }
            if let Err(error) = emit(kind, &self.pending) {
                self.poisoned = true;
                return Err(error);
            }
            match kind {
                DirectPodIdentityFrameKind::CanonicalRecord => {
                    self.canonical_records = self
                        .canonical_records
                        .checked_add(1)
                        .ok_or_else(|| self.poison("record counter overflow"))?;
                }
                DirectPodIdentityFrameKind::LowSpeedMessage => {
                    self.low_speed_messages = self
                        .low_speed_messages
                        .checked_add(1)
                        .ok_or_else(|| self.poison("control counter overflow"))?;
                }
                DirectPodIdentityFrameKind::TimeSnapshot => {
                    self.time_snapshots = self
                        .time_snapshots
                        .checked_add(1)
                        .ok_or_else(|| self.poison("time-snapshot counter overflow"))?;
                }
                DirectPodIdentityFrameKind::ReplayOffer => {
                    self.replay_offers = self
                        .replay_offers
                        .checked_add(1)
                        .ok_or_else(|| self.poison("Replay-offer counter overflow"))?;
                }
                DirectPodIdentityFrameKind::CablineStatus => {
                    self.cabline_statuses = self
                        .cabline_statuses
                        .checked_add(1)
                        .ok_or_else(|| self.poison("CABLINE-status counter overflow"))?;
                }
                DirectPodIdentityFrameKind::DhlIdentityCapsule => {
                    self.dhl_identity_capsules = self
                        .dhl_identity_capsules
                        .checked_add(1)
                        .ok_or_else(|| self.poison("DHL-identity-capsule counter overflow"))?;
                }
            }
            self.emitted_bytes = self
                .emitted_bytes
                .checked_add(expected as u64)
                .ok_or_else(|| self.poison("emitted-byte counter overflow"))?;
            self.pending.clear();
            self.expected_len = None;
            self.pending_kind = None;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid_data("direct-Pod stream epoch is poisoned"));
        }
        if !self.pending.is_empty() {
            return Err(self.poison("transport stopped with a partial direct-Pod message"));
        }
        Ok(())
    }

    pub fn reset(&mut self, transport_epoch: u64) -> io::Result<()> {
        if transport_epoch == 0 || transport_epoch == self.transport_epoch {
            return Err(invalid_input("recovery requires a fresh transport epoch"));
        }
        self.transport_epoch = transport_epoch;
        self.pending.clear();
        self.expected_len = None;
        self.pending_kind = None;
        self.received_bytes = 0;
        self.canonical_records = 0;
        self.low_speed_messages = 0;
        self.time_snapshots = 0;
        self.replay_offers = 0;
        self.cabline_statuses = 0;
        self.dhl_identity_capsules = 0;
        self.emitted_bytes = 0;
        self.poisoned = false;
        Ok(())
    }

    pub fn stats(&self) -> DirectPodStreamStats {
        DirectPodStreamStats {
            transport_epoch: self.transport_epoch,
            received_bytes: self.received_bytes,
            canonical_records: self.canonical_records,
            low_speed_messages: self.low_speed_messages,
            time_snapshots: self.time_snapshots,
            replay_offers: self.replay_offers,
            emitted_bytes: self.emitted_bytes,
            pending_bytes: self.pending.len(),
            poisoned: self.poisoned,
        }
    }

    pub fn extended_stats(&self) -> DirectPodExtendedStreamStats {
        DirectPodExtendedStreamStats {
            base: self.stats(),
            cabline_statuses: self.cabline_statuses,
        }
    }

    pub fn identity_stats(&self) -> DirectPodIdentityStreamStats {
        DirectPodIdentityStreamStats {
            base: self.extended_stats(),
            dhl_identity_capsules: self.dhl_identity_capsules,
        }
    }

    fn inspect_prefix(&mut self, chunk: &mut &[u8]) -> io::Result<()> {
        if self.pending.get(..8) == Some(DHL_IDENTITY_CAPSULE_MAGIC) {
            // The first twelve bytes contain the complete capsule length.  Do
            // not retain more bytes for this message until its bounded range
            // is accepted; there is deliberately no resynchronization path.
            let total_len = usize::from(u16::from_le_bytes(
                self.pending[10..12]
                    .try_into()
                    .map_err(|_| self.poison("truncated DHL identity capsule length"))?,
            ));
            if !(DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MIN_LEN
                ..=DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MAX_LEN)
                .contains(&total_len)
            {
                return Err(self.poison("DHL identity capsule exceeds bounded length"));
            }
            self.pending_kind = Some(DirectPodIdentityFrameKind::DhlIdentityCapsule);
            self.expected_len = Some(total_len);
            return Ok(());
        }

        if self.pending.get(..8) == Some(CABLINE_STATUS_MAGIC) {
            self.pending_kind = Some(DirectPodIdentityFrameKind::CablineStatus);
            self.expected_len = Some(DIRECT_POD_CABLINE_STATUS_LEN);
            return Ok(());
        }

        if self.pending.get(..8) == Some(TIME_MAGIC) {
            self.pending_kind = Some(DirectPodIdentityFrameKind::TimeSnapshot);
            self.expected_len = Some(DIRECT_POD_TIME_SNAPSHOT_LEN);
            return Ok(());
        }

        if self.pending.get(..8) == Some(REPLAY_OFFER_MAGIC) {
            self.pending_kind = Some(DirectPodIdentityFrameKind::ReplayOffer);
            self.expected_len = Some(DIRECT_POD_REPLAY_OFFER_LEN);
            return Ok(());
        }

        if self.pending.get(..8) == Some(RECORD_MAGIC) {
            fill_to(&mut self.pending, RECORD_LENGTH_PREFIX_BYTES, chunk);
            if self.pending.len() < RECORD_LENGTH_PREFIX_BYTES {
                return Ok(());
            }
            let payload_len = u32::from_le_bytes(
                self.pending[20..24]
                    .try_into()
                    .map_err(|_| self.poison("truncated canonical payload length"))?,
            ) as usize;
            let total_len = RECORD_HEADER_LEN
                .checked_add(payload_len)
                .ok_or_else(|| self.poison("canonical record length overflow"))?;
            if payload_len > MAX_RECORD_PAYLOAD_LEN {
                return Err(self.poison("canonical record exceeds bounded length"));
            }
            self.pending_kind = Some(DirectPodIdentityFrameKind::CanonicalRecord);
            self.expected_len = Some(total_len);
            return Ok(());
        }

        if self.pending.get(4..12) == Some(CONTROL_MAGIC) {
            let total_len = u32::from_le_bytes(
                self.pending[0..4]
                    .try_into()
                    .map_err(|_| self.poison("truncated low-speed message length"))?,
            ) as usize;
            if !(LOW_SPEED_HEADER_LEN..=MAX_LOW_SPEED_MESSAGE_LEN).contains(&total_len) {
                return Err(self.poison("low-speed message exceeds bounded length"));
            }
            self.pending_kind = Some(DirectPodIdentityFrameKind::LowSpeedMessage);
            self.expected_len = Some(total_len);
            return Ok(());
        }

        Err(self.poison("invalid direct-Pod message prefix"))
    }

    fn poison(&mut self, message: &'static str) -> io::Error {
        self.poisoned = true;
        invalid_data(message)
    }
}

fn fill_to(pending: &mut Vec<u8>, target: usize, chunk: &mut &[u8]) {
    if pending.len() >= target || chunk.is_empty() {
        return;
    }
    let take = (target - pending.len()).min(chunk.len());
    pending.extend_from_slice(&chunk[..take]);
    *chunk = &chunk[take..];
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
    use crate::direct_pod_dhl_identity::DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_HEADER_LEN;
    use crate::source::{DeterministicReplayConfig, DeterministicReplaySource};
    use forge_protocol_v1::{crc32c, encode_low_speed, sha256, AckV1};

    use crate::direct_pod_cabline::{DirectPodCablineStatusV1, CABLINE_REQUIRED_READY_FLAGS};
    use crate::direct_pod_replay_offer::{DirectPodReplayOfferV1, REPLAY_OFFER_REQUIRED_FLAGS};
    use crate::direct_pod_time::{
        DirectPodTimeSnapshotV1, TIME_FLAG_GLOBAL_TIME_VALID, TIME_FLAG_POD_READY,
    };

    fn record() -> Vec<u8> {
        let mut source = DeterministicReplaySource::new(DeterministicReplayConfig {
            run_id: [1; 16],
            pod_id: [2; 16],
            headstage_id: [3; 16],
            channel_layout_id: 1,
            channel_count: 4,
            samples_per_channel: 3,
            sample_rate_hz: 30_000,
            total_records: 1,
            seed: 4,
        })
        .unwrap();
        source.next_encoded_record().unwrap().unwrap()
    }

    fn control() -> Vec<u8> {
        encode_low_speed(
            0,
            7,
            11,
            &AckV1 {
                acknowledged_request_id: 7,
                applied_epoch: 11,
                ack_code: 1,
                state_code: 2,
                receipt_hash: [9; 32],
            },
        )
        .unwrap()
    }

    fn time_snapshot() -> Vec<u8> {
        DirectPodTimeSnapshotV1 {
            device_id: [4; 16],
            transport_epoch: 11,
            status_sequence: 1,
            global_time_ns: 1_000,
            sample_counter: 0,
            frame_counter: 0,
            runtime_flags: TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY,
            hardware_state_hash: sha256(b"state"),
        }
        .encode()
        .unwrap()
        .to_vec()
    }

    fn replay_offer() -> Vec<u8> {
        DirectPodReplayOfferV1 {
            flags: REPLAY_OFFER_REQUIRED_FLAGS,
            device_id: [4; 16],
            run_id: [1; 16],
            pod_id: [2; 16],
            headstage_id: [3; 16],
            transport_epoch: 11,
            offer_sequence: 1,
            first_missing_record_sequence: 0,
            last_missing_record_sequence_exclusive: 1,
            oldest_replayable_record_sequence: 0,
            newest_replayable_record_sequence_exclusive: 1,
            source_next_live_record_sequence: 1,
            last_produced_record_sequence_exclusive: 1,
            prior_record_sequence: None,
            offer_global_time_ns: 1_000,
            deadline_global_time_ns: 2_000,
            reason_code: 1,
            hardware_state_hash: sha256(b"state"),
        }
        .encode()
        .unwrap()
        .to_vec()
    }

    fn cabline_status() -> Vec<u8> {
        DirectPodCablineStatusV1 {
            device_id: [4; 16],
            pod_id: [2; 16],
            headstage_id: [3; 16],
            transport_epoch: 11,
            status_sequence: 1,
            global_time_ns: 1_000,
            headstage_boot_id: 5,
            next_dhl_sequence: 3,
            source_id: 6,
            state_flags: CABLINE_REQUIRED_READY_FLAGS,
            symbol_error_count: 0,
            crc_error_count: 0,
            sequence_error_count: 0,
            packet_drop_count: 0,
            receiver_overflow_count: 0,
            relock_count: 0,
            headstage_config_hash: sha256(b"headstage-config"),
            descriptor_hash: sha256(b"descriptor"),
            inventory_hash: sha256(b"inventory"),
            assembly_manifest_hash: sha256(b"assembly-manifest"),
            channel_map_hash: sha256(b"channel-map"),
        }
        .encode()
        .unwrap()
        .to_vec()
    }

    fn identity_capsule() -> Vec<u8> {
        let mut descriptor_payload = vec![0_u8; 96];
        descriptor_payload[0..2].copy_from_slice(&1_u16.to_le_bytes());
        descriptor_payload[2..4].copy_from_slice(&96_u16.to_le_bytes());
        descriptor_payload[4] = 1;
        descriptor_payload[5] = 1;
        descriptor_payload[8..10].copy_from_slice(&16_u16.to_le_bytes());
        descriptor_payload[10..12].copy_from_slice(&1_u16.to_le_bytes());
        descriptor_payload[12..16].copy_from_slice(&30_000_u32.to_le_bytes());
        descriptor_payload[16..20].copy_from_slice(&1_u32.to_le_bytes());
        descriptor_payload[20..24].copy_from_slice(&25_000_000_u32.to_le_bytes());
        descriptor_payload[28..44].copy_from_slice(&[0x11; 16]);
        descriptor_payload[44..76].copy_from_slice(&[0x22; 32]);
        descriptor_payload[76..92].copy_from_slice(&[0x33; 16]);

        let mut inventory_payload = vec![0_u8; 108];
        inventory_payload[0..2].copy_from_slice(&1_u16.to_le_bytes());
        inventory_payload[2..4].copy_from_slice(&76_u16.to_le_bytes());
        inventory_payload[4..6].copy_from_slice(&32_u16.to_le_bytes());
        inventory_payload[6..8].copy_from_slice(&1_u16.to_le_bytes());
        inventory_payload[8..12].copy_from_slice(&1_u32.to_le_bytes());
        inventory_payload[12..44].copy_from_slice(&[0x44; 32]);
        inventory_payload[44..76].copy_from_slice(&[0x55; 32]);

        DirectPodDhlIdentityCapsuleV1 {
            device_id: [0x11; 16],
            pod_id: [0x66; 16],
            headstage_id: [0x11; 16],
            transport_epoch: 1,
            descriptor_wire: dhl_wire(1, 1, &descriptor_payload),
            inventory_wire: dhl_wire(9, 2, &inventory_payload),
        }
        .encode()
        .unwrap()
    }

    fn dhl_wire(packet_type: u8, sequence: u64, payload: &[u8]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(40 + payload.len() + 4);
        wire.push(1);
        wire.push(packet_type);
        wire.extend_from_slice(&0_u16.to_le_bytes());
        wire.extend_from_slice(&40_u16.to_le_bytes());
        wire.extend_from_slice(&0_u16.to_le_bytes());
        wire.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        wire.extend_from_slice(&7_u32.to_le_bytes());
        wire.extend_from_slice(&8_u64.to_le_bytes());
        wire.extend_from_slice(&sequence.to_le_bytes());
        wire.extend_from_slice(&9_u64.to_le_bytes());
        wire.extend_from_slice(payload);
        wire.extend_from_slice(&crc32c(&wire).to_le_bytes());
        wire
    }

    fn refresh_capsule_crc(wire: &mut [u8]) {
        let footer_offset = wire.len() - 4;
        let crc = crc32c(&wire[..footer_offset]);
        wire[footer_offset..].copy_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn every_record_and_control_split_round_trips() {
        for (kind, message) in [
            (DirectPodExtendedFrameKind::CanonicalRecord, record()),
            (DirectPodExtendedFrameKind::LowSpeedMessage, control()),
            (DirectPodExtendedFrameKind::TimeSnapshot, time_snapshot()),
            (DirectPodExtendedFrameKind::ReplayOffer, replay_offer()),
            (DirectPodExtendedFrameKind::CablineStatus, cabline_status()),
        ] {
            for split in 0..=message.len() {
                let mut parser = DirectPodStreamReassembler::new(1).unwrap();
                let mut output = Vec::new();
                parser
                    .push_with_cabline(&message[..split], |actual_kind, bytes| {
                        output.push((actual_kind, bytes.to_vec()));
                        Ok(())
                    })
                    .unwrap();
                parser
                    .push_with_cabline(&message[split..], |actual_kind, bytes| {
                        output.push((actual_kind, bytes.to_vec()));
                        Ok(())
                    })
                    .unwrap();
                parser.finish().unwrap();
                assert_eq!(output, vec![(kind, message.clone())]);
            }
        }
    }

    #[test]
    fn interleaved_messages_survive_bytewise_and_coalesced_chunks() {
        let expected = vec![
            (DirectPodExtendedFrameKind::CanonicalRecord, record()),
            (DirectPodExtendedFrameKind::CablineStatus, cabline_status()),
            (DirectPodExtendedFrameKind::TimeSnapshot, time_snapshot()),
            (DirectPodExtendedFrameKind::LowSpeedMessage, control()),
            (DirectPodExtendedFrameKind::CanonicalRecord, record()),
        ];
        let joined: Vec<u8> = expected
            .iter()
            .flat_map(|(_, message)| message.iter().copied())
            .collect();
        for chunk_size in [1, 7, 64, joined.len()] {
            let mut parser = DirectPodStreamReassembler::new(5).unwrap();
            let mut output = Vec::new();
            for chunk in joined.chunks(chunk_size) {
                parser
                    .push_with_cabline(chunk, |kind, bytes| {
                        output.push((kind, bytes.to_vec()));
                        Ok(())
                    })
                    .unwrap();
            }
            parser.finish().unwrap();
            assert_eq!(output, expected);
            assert_eq!(parser.stats().canonical_records, 2);
            assert_eq!(parser.stats().low_speed_messages, 1);
            assert_eq!(parser.stats().time_snapshots, 1);
            assert_eq!(parser.extended_stats().cabline_statuses, 1);
        }
    }

    #[test]
    fn invalid_prefix_crc_and_junk_never_resynchronize() {
        for mut message in [record(), control(), cabline_status()] {
            let last = message.len() - 1;
            message[last] ^= 1;
            let mut parser = DirectPodStreamReassembler::new(1).unwrap();
            assert!(parser.push_with_cabline(&message, |_, _| Ok(())).is_err());
            assert!(parser.stats().poisoned);
            assert!(parser.push(&record(), |_, _| Ok(())).is_err());
        }
        let mut parser = DirectPodStreamReassembler::new(1).unwrap();
        let mut junk_then_record = b"bad-prefix!!".to_vec();
        junk_then_record.extend_from_slice(&record());
        assert!(parser.push(&junk_then_record, |_, _| Ok(())).is_err());
        assert_eq!(parser.stats().canonical_records, 0);
    }

    #[test]
    fn legacy_consumer_fails_closed_on_unintegrated_cabline_status() {
        let mut parser = DirectPodStreamReassembler::new(1).unwrap();
        assert!(parser.push(&cabline_status(), |_, _| Ok(())).is_err());
        assert!(parser.stats().poisoned);
        assert_eq!(parser.extended_stats().cabline_statuses, 0);
    }

    #[test]
    fn legacy_consumer_still_accepts_every_original_frame_kind() {
        for (kind, message) in [
            (DirectPodFrameKind::CanonicalRecord, record()),
            (DirectPodFrameKind::LowSpeedMessage, control()),
            (DirectPodFrameKind::TimeSnapshot, time_snapshot()),
            (DirectPodFrameKind::ReplayOffer, replay_offer()),
        ] {
            let mut parser = DirectPodStreamReassembler::new(1).unwrap();
            let mut output = Vec::new();
            parser
                .push(&message, |actual_kind, bytes| {
                    output.push((actual_kind, bytes.to_vec()));
                    Ok(())
                })
                .unwrap();
            parser.finish().unwrap();
            assert_eq!(output, vec![(kind, message)]);
        }
    }

    #[test]
    fn partial_stop_and_consumer_failure_require_a_fresh_epoch() {
        let message = control();
        let mut parser = DirectPodStreamReassembler::new(1).unwrap();
        parser.push(&message[..12], |_, _| Ok(())).unwrap();
        assert!(parser.finish().is_err());
        assert!(parser.reset(1).is_err());
        parser.reset(2).unwrap();
        let error = parser.push(&message, |_, _| Err(io::Error::other("journal failed")));
        assert_eq!(error.unwrap_err().to_string(), "journal failed");
        assert!(parser.stats().poisoned);
    }

    #[test]
    fn identity_capsule_every_split_round_trips_only_with_identity_api() {
        let capsule = identity_capsule();
        assert_eq!(capsule.len(), DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MIN_LEN);
        for split in 0..=capsule.len() {
            let mut parser = DirectPodStreamReassembler::new(1).unwrap();
            let mut output = Vec::new();
            parser
                .push_with_identity(&capsule[..split], |kind, bytes| {
                    output.push((kind, bytes.to_vec()));
                    Ok(())
                })
                .unwrap();
            parser
                .push_with_identity(&capsule[split..], |kind, bytes| {
                    output.push((kind, bytes.to_vec()));
                    Ok(())
                })
                .unwrap();
            parser.finish().unwrap();
            assert_eq!(
                output,
                vec![(
                    DirectPodIdentityFrameKind::DhlIdentityCapsule,
                    capsule.clone()
                )]
            );
            assert_eq!(parser.identity_stats().dhl_identity_capsules, 1);
        }
    }

    #[test]
    fn identity_api_preserves_all_message_kinds_bytewise_and_coalesced() {
        let expected = vec![
            (DirectPodIdentityFrameKind::CanonicalRecord, record()),
            (
                DirectPodIdentityFrameKind::DhlIdentityCapsule,
                identity_capsule(),
            ),
            (DirectPodIdentityFrameKind::LowSpeedMessage, control()),
            (DirectPodIdentityFrameKind::TimeSnapshot, time_snapshot()),
            (DirectPodIdentityFrameKind::ReplayOffer, replay_offer()),
            (DirectPodIdentityFrameKind::CablineStatus, cabline_status()),
        ];
        let joined: Vec<u8> = expected
            .iter()
            .flat_map(|(_, message)| message.iter().copied())
            .collect();
        for chunk_size in [1, 7, 64, joined.len()] {
            let mut parser = DirectPodStreamReassembler::new(5).unwrap();
            let mut output = Vec::new();
            for chunk in joined.chunks(chunk_size) {
                parser
                    .push_with_identity(chunk, |kind, bytes| {
                        output.push((kind, bytes.to_vec()));
                        Ok(())
                    })
                    .unwrap();
            }
            parser.finish().unwrap();
            assert_eq!(output, expected);
            let stats = parser.identity_stats();
            assert_eq!(stats.dhl_identity_capsules, 1);
            assert_eq!(stats.base.base.canonical_records, 1);
            assert_eq!(stats.base.base.low_speed_messages, 1);
            assert_eq!(stats.base.base.time_snapshots, 1);
            assert_eq!(stats.base.base.replay_offers, 1);
            assert_eq!(stats.base.cabline_statuses, 1);
        }
    }

    #[test]
    fn legacy_apis_reject_identity_capsules_and_poison() {
        let capsule = identity_capsule();
        let mut legacy = DirectPodStreamReassembler::new(1).unwrap();
        assert!(legacy.push(&capsule, |_, _| Ok(())).is_err());
        assert!(legacy.stats().poisoned);

        let mut cabline = DirectPodStreamReassembler::new(1).unwrap();
        assert!(cabline.push_with_cabline(&capsule, |_, _| Ok(())).is_err());
        assert!(cabline.stats().poisoned);
    }

    #[test]
    fn identity_length_crc_wire_and_terminal_failures_poison_without_resync() {
        let capsule = identity_capsule();

        let mut below_min = capsule.clone();
        below_min[10..12].copy_from_slice(
            &u16::try_from(DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MIN_LEN - 1)
                .unwrap()
                .to_le_bytes(),
        );
        let mut parser = DirectPodStreamReassembler::new(1).unwrap();
        assert!(parser
            .push_with_identity(&below_min, |_, _| Ok(()))
            .is_err());
        assert!(parser.stats().poisoned);

        let mut above_max = capsule.clone();
        above_max[10..12].copy_from_slice(
            &u16::try_from(DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MAX_LEN + 1)
                .unwrap()
                .to_le_bytes(),
        );
        let mut parser = DirectPodStreamReassembler::new(1).unwrap();
        assert!(parser
            .push_with_identity(&above_max, |_, _| Ok(()))
            .is_err());
        assert!(parser.stats().poisoned);

        let mut length_mismatch = capsule.clone();
        length_mismatch[10..12]
            .copy_from_slice(&u16::try_from(capsule.len() + 1).unwrap().to_le_bytes());
        length_mismatch.push(0);
        let mut parser = DirectPodStreamReassembler::new(1).unwrap();
        assert!(parser
            .push_with_identity(&length_mismatch, |_, _| Ok(()))
            .is_err());
        assert!(parser.stats().poisoned);

        let mut bad_capsule_crc = capsule.clone();
        let last = bad_capsule_crc.len() - 1;
        bad_capsule_crc[last] ^= 1;
        let mut parser = DirectPodStreamReassembler::new(1).unwrap();
        assert!(parser
            .push_with_identity(&bad_capsule_crc, |_, _| Ok(()))
            .is_err());
        assert!(parser.stats().poisoned);

        let mut bad_inner_wire = capsule.clone();
        let descriptor_offset = DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_HEADER_LEN;
        bad_inner_wire[descriptor_offset + 40] ^= 1;
        let descriptor_hash = sha256(&bad_inner_wire[descriptor_offset..descriptor_offset + 140]);
        bad_inner_wire[112..144].copy_from_slice(&descriptor_hash);
        refresh_capsule_crc(&mut bad_inner_wire);
        let mut parser = DirectPodStreamReassembler::new(1).unwrap();
        assert!(parser
            .push_with_identity(&bad_inner_wire, |_, _| Ok(()))
            .is_err());
        assert!(parser.stats().poisoned);

        let mut parser = DirectPodStreamReassembler::new(1).unwrap();
        parser
            .push_with_identity(&capsule[..capsule.len() - 1], |_, _| Ok(()))
            .unwrap();
        assert!(parser.finish().is_err());
        assert!(parser.stats().poisoned);

        let mut joined = bad_capsule_crc;
        joined.extend_from_slice(&record());
        let mut parser = DirectPodStreamReassembler::new(1).unwrap();
        assert!(parser.push_with_identity(&joined, |_, _| Ok(())).is_err());
        assert_eq!(parser.stats().canonical_records, 0);
    }

    #[test]
    fn identity_consumer_error_and_fresh_epoch_reset_are_fail_closed() {
        let capsule = identity_capsule();
        let mut parser = DirectPodStreamReassembler::new(1).unwrap();
        let error =
            parser.push_with_identity(&capsule, |_, _| Err(io::Error::other("preflight failed")));
        assert_eq!(error.unwrap_err().to_string(), "preflight failed");
        assert!(parser.stats().poisoned);
        assert!(parser.push_with_identity(&capsule, |_, _| Ok(())).is_err());

        parser.reset(2).unwrap();
        let mut output = Vec::new();
        parser
            .push_with_identity(&capsule, |kind, bytes| {
                output.push((kind, bytes.to_vec()));
                Ok(())
            })
            .unwrap();
        parser.finish().unwrap();
        assert_eq!(
            output,
            vec![(DirectPodIdentityFrameKind::DhlIdentityCapsule, capsule)]
        );
        assert_eq!(parser.identity_stats().dhl_identity_capsules, 1);
    }
}
