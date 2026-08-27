//! Source-authored evidence that a direct Pod has quiesced its live stream and
//! can replay one exact missing suffix without changing transport epoch.
//!
//! The host never infers this offer from USB arrival time or from a future
//! record. The companion is accepted only when it begins at the host's next
//! journal sequence and binds the latest admitted Pod hardware-state hash.

use std::io;

use forge_protocol_v1::{crc32c, Hash32, Id16, PROTOCOL_HASH};

use crate::direct_pod_replay::MAX_DIRECT_POD_REPLAY_RECORDS;

pub const DIRECT_POD_REPLAY_OFFER_LEN: usize = 280;
pub const DIRECT_POD_REPLAY_OFFER_CONTRACT_HASH_HEX: &str =
    "01f5c69d43623d746b76b0bd04873b03d0870b8ce2e42bb4153e3c9d3bdd55b5";
pub const DIRECT_POD_REPLAY_OFFER_CONTRACT_HASH: Hash32 = [
    0x01, 0xf5, 0xc6, 0x9d, 0x43, 0x62, 0x3d, 0x74, 0x6b, 0x76, 0xb0, 0xbd, 0x04, 0x87, 0x3b, 0x03,
    0xd0, 0x87, 0x0b, 0x8c, 0xe2, 0xe4, 0x2b, 0xb4, 0x15, 0x3e, 0x3c, 0x9d, 0x3b, 0xdd, 0x55, 0xb5,
];

pub const REPLAY_OFFER_FLAG_LIVE_STREAM_QUIESCED: u32 = 1 << 0;
pub const REPLAY_OFFER_FLAG_RANGE_REPLAYABLE: u32 = 1 << 1;
pub const REPLAY_OFFER_FLAG_HOLD_UNTIL_DEADLINE: u32 = 1 << 2;
pub const REPLAY_OFFER_REQUIRED_FLAGS: u32 = REPLAY_OFFER_FLAG_LIVE_STREAM_QUIESCED
    | REPLAY_OFFER_FLAG_RANGE_REPLAYABLE
    | REPLAY_OFFER_FLAG_HOLD_UNTIL_DEADLINE;

const MAGIC: &[u8; 8] = b"FGRRPO01";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodReplayOfferV1 {
    pub flags: u32,
    pub device_id: Id16,
    pub run_id: Id16,
    pub pod_id: Id16,
    pub headstage_id: Id16,
    pub transport_epoch: u64,
    pub offer_sequence: u64,
    pub first_missing_record_sequence: u64,
    pub last_missing_record_sequence_exclusive: u64,
    pub oldest_replayable_record_sequence: u64,
    pub newest_replayable_record_sequence_exclusive: u64,
    pub source_next_live_record_sequence: u64,
    pub last_produced_record_sequence_exclusive: u64,
    pub prior_record_sequence: Option<u64>,
    pub offer_global_time_ns: u64,
    pub deadline_global_time_ns: u64,
    pub reason_code: u16,
    pub hardware_state_hash: Hash32,
}

impl DirectPodReplayOfferV1 {
    pub fn encode(self) -> io::Result<[u8; DIRECT_POD_REPLAY_OFFER_LEN]> {
        validate_semantics(&self)?;
        let mut bytes = [0_u8; DIRECT_POD_REPLAY_OFFER_LEN];
        bytes[0..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(DIRECT_POD_REPLAY_OFFER_LEN as u16).to_le_bytes());
        bytes[12..16].copy_from_slice(&self.flags.to_le_bytes());
        bytes[16..48].copy_from_slice(&DIRECT_POD_REPLAY_OFFER_CONTRACT_HASH);
        bytes[48..64].copy_from_slice(&self.device_id);
        bytes[64..80].copy_from_slice(&self.run_id);
        bytes[80..96].copy_from_slice(&self.pod_id);
        bytes[96..112].copy_from_slice(&self.headstage_id);
        bytes[112..120].copy_from_slice(&self.transport_epoch.to_le_bytes());
        bytes[120..128].copy_from_slice(&self.offer_sequence.to_le_bytes());
        bytes[128..136].copy_from_slice(&self.first_missing_record_sequence.to_le_bytes());
        bytes[136..144].copy_from_slice(&self.last_missing_record_sequence_exclusive.to_le_bytes());
        bytes[144..152].copy_from_slice(&self.oldest_replayable_record_sequence.to_le_bytes());
        bytes[152..160].copy_from_slice(
            &self
                .newest_replayable_record_sequence_exclusive
                .to_le_bytes(),
        );
        bytes[160..168].copy_from_slice(&self.source_next_live_record_sequence.to_le_bytes());
        bytes[168..176]
            .copy_from_slice(&self.last_produced_record_sequence_exclusive.to_le_bytes());
        bytes[176..184]
            .copy_from_slice(&self.prior_record_sequence.unwrap_or(u64::MAX).to_le_bytes());
        bytes[184..192].copy_from_slice(&self.offer_global_time_ns.to_le_bytes());
        bytes[192..200].copy_from_slice(&self.deadline_global_time_ns.to_le_bytes());
        bytes[200..202].copy_from_slice(&self.reason_code.to_le_bytes());
        bytes[208..240].copy_from_slice(&self.hardware_state_hash);
        bytes[240..272].copy_from_slice(&PROTOCOL_HASH);
        let checksum = crc32c(&bytes[..276]);
        bytes[276..280].copy_from_slice(&checksum.to_le_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != DIRECT_POD_REPLAY_OFFER_LEN
            || bytes.get(0..8) != Some(MAGIC)
            || le_u16(bytes, 8)? != VERSION
            || le_u16(bytes, 10)? as usize != DIRECT_POD_REPLAY_OFFER_LEN
            || array::<32>(bytes, 16)? != DIRECT_POD_REPLAY_OFFER_CONTRACT_HASH
            || le_u16(bytes, 202)? != 0
            || le_u32(bytes, 204)? != 0
            || array::<32>(bytes, 240)? != PROTOCOL_HASH
            || le_u32(bytes, 272)? != 0
            || crc32c(&bytes[..276]) != le_u32(bytes, 276)?
        {
            return Err(invalid_data("direct-Pod Replay offer framing is invalid"));
        }
        let prior = le_u64(bytes, 176)?;
        let value = Self {
            flags: le_u32(bytes, 12)?,
            device_id: array(bytes, 48)?,
            run_id: array(bytes, 64)?,
            pod_id: array(bytes, 80)?,
            headstage_id: array(bytes, 96)?,
            transport_epoch: le_u64(bytes, 112)?,
            offer_sequence: le_u64(bytes, 120)?,
            first_missing_record_sequence: le_u64(bytes, 128)?,
            last_missing_record_sequence_exclusive: le_u64(bytes, 136)?,
            oldest_replayable_record_sequence: le_u64(bytes, 144)?,
            newest_replayable_record_sequence_exclusive: le_u64(bytes, 152)?,
            source_next_live_record_sequence: le_u64(bytes, 160)?,
            last_produced_record_sequence_exclusive: le_u64(bytes, 168)?,
            prior_record_sequence: (prior != u64::MAX).then_some(prior),
            offer_global_time_ns: le_u64(bytes, 184)?,
            deadline_global_time_ns: le_u64(bytes, 192)?,
            reason_code: le_u16(bytes, 200)?,
            hardware_state_hash: array(bytes, 208)?,
        };
        validate_semantics(&value)
            .map_err(|_| invalid_data("direct-Pod Replay offer violates semantic invariants"))?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_active_boundary(
        &self,
        run_id: Id16,
        device_id: Id16,
        pod_id: Id16,
        headstage_id: Id16,
        transport_epoch: u64,
        prior_record_sequence: Option<u64>,
        latest_hardware_state_hash: Hash32,
        latest_offer_sequence: Option<u64>,
    ) -> io::Result<()> {
        let expected_first = prior_record_sequence.map_or(Ok(0), |prior| {
            prior
                .checked_add(1)
                .ok_or_else(|| invalid_data("direct-Pod Replay offer sequence overflow"))
        })?;
        if self.run_id != run_id
            || self.device_id != device_id
            || self.pod_id != pod_id
            || self.headstage_id != headstage_id
            || self.transport_epoch != transport_epoch
            || self.first_missing_record_sequence != expected_first
            || self.prior_record_sequence != prior_record_sequence
            || self.hardware_state_hash != latest_hardware_state_hash
            || latest_offer_sequence.is_some_and(|prior| self.offer_sequence <= prior)
        {
            return Err(invalid_data(
                "direct-Pod Replay offer contradicts the active journal or hardware boundary",
            ));
        }
        Ok(())
    }
}

fn validate_semantics(value: &DirectPodReplayOfferV1) -> io::Result<()> {
    let count = value
        .last_missing_record_sequence_exclusive
        .checked_sub(value.first_missing_record_sequence)
        .ok_or_else(|| invalid_input("direct-Pod Replay offer range is invalid"))?;
    let expected_prior = value
        .first_missing_record_sequence
        .checked_sub(1)
        .map_or(u64::MAX, |prior| prior);
    if value.flags != REPLAY_OFFER_REQUIRED_FLAGS
        || [
            value.device_id,
            value.run_id,
            value.pod_id,
            value.headstage_id,
        ]
        .contains(&[0; 16])
        || value.transport_epoch == 0
        || value.offer_sequence == 0
        || count == 0
        || count > MAX_DIRECT_POD_REPLAY_RECORDS
        || value.oldest_replayable_record_sequence > value.first_missing_record_sequence
        || value.last_missing_record_sequence_exclusive
            > value.newest_replayable_record_sequence_exclusive
        || value.newest_replayable_record_sequence_exclusive
            > value.last_produced_record_sequence_exclusive
        || value.source_next_live_record_sequence != value.last_missing_record_sequence_exclusive
        || value.prior_record_sequence.unwrap_or(u64::MAX) != expected_prior
        || value.offer_global_time_ns == 0
        || value.deadline_global_time_ns <= value.offer_global_time_ns
        || value.reason_code == 0
        || value.hardware_state_hash == [0; 32]
    {
        return Err(invalid_input(
            "direct-Pod Replay offer semantic policy is invalid",
        ));
    }
    Ok(())
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| invalid_data("truncated direct-Pod Replay offer"))
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

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_protocol_v1::sha256;

    const RUN_ID: Id16 = [0x11; 16];
    const DEVICE_ID: Id16 = [0x22; 16];
    const POD_ID: Id16 = [0x33; 16];
    const HEADSTAGE_ID: Id16 = [0x44; 16];
    const STATE_HASH: Hash32 = [0x55; 32];

    fn offer() -> DirectPodReplayOfferV1 {
        DirectPodReplayOfferV1 {
            flags: REPLAY_OFFER_REQUIRED_FLAGS,
            device_id: DEVICE_ID,
            run_id: RUN_ID,
            pod_id: POD_ID,
            headstage_id: HEADSTAGE_ID,
            transport_epoch: 7,
            offer_sequence: 9,
            first_missing_record_sequence: 3,
            last_missing_record_sequence_exclusive: 5,
            oldest_replayable_record_sequence: 1,
            newest_replayable_record_sequence_exclusive: 8,
            source_next_live_record_sequence: 5,
            last_produced_record_sequence_exclusive: 8,
            prior_record_sequence: Some(2),
            offer_global_time_ns: 1_000,
            deadline_global_time_ns: 2_000,
            reason_code: 1,
            hardware_state_hash: STATE_HASH,
        }
    }

    #[test]
    fn contract_hash_matches_lf_normalized_schema() {
        let schema = include_str!("../schema/forge_direct_pod_replay_offer_v1.idl")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(
            sha256(schema.as_bytes()),
            DIRECT_POD_REPLAY_OFFER_CONTRACT_HASH
        );
    }

    #[test]
    fn exact_round_trip_and_every_mutation_fail_closed() {
        let bytes = offer().encode().unwrap();
        assert_eq!(DirectPodReplayOfferV1::decode(&bytes).unwrap(), offer());
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(
                DirectPodReplayOfferV1::decode(&changed).is_err(),
                "byte {index}"
            );
        }
        for length in 0..bytes.len() {
            assert!(DirectPodReplayOfferV1::decode(&bytes[..length]).is_err());
        }
    }

    #[test]
    fn independent_python_golden_matches_exact_offer_bytes() {
        let text = include_str!("../golden/direct_pod_replay_offer_v1.hex").trim();
        assert_eq!(text.len(), DIRECT_POD_REPLAY_OFFER_LEN * 2);
        let expected = (0..DIRECT_POD_REPLAY_OFFER_LEN)
            .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(expected.len(), DIRECT_POD_REPLAY_OFFER_LEN);
        assert_eq!(offer().encode().unwrap().as_slice(), expected.as_slice());
        assert_eq!(DirectPodReplayOfferV1::decode(&expected).unwrap(), offer());
    }

    #[test]
    fn active_boundary_requires_exact_next_sequence_state_and_monotonic_offer() {
        let value = offer();
        value
            .validate_active_boundary(
                RUN_ID,
                DEVICE_ID,
                POD_ID,
                HEADSTAGE_ID,
                7,
                Some(2),
                STATE_HASH,
                Some(8),
            )
            .unwrap();
        assert!(value
            .validate_active_boundary(
                RUN_ID,
                DEVICE_ID,
                POD_ID,
                HEADSTAGE_ID,
                7,
                Some(1),
                STATE_HASH,
                Some(8),
            )
            .is_err());
        assert!(value
            .validate_active_boundary(
                RUN_ID,
                DEVICE_ID,
                POD_ID,
                HEADSTAGE_ID,
                7,
                Some(2),
                [0x66; 32],
                Some(9),
            )
            .is_err());
    }
}
