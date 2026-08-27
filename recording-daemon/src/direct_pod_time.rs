//! Authenticated hardware-time snapshots for pre-recording direct-Pod control.
//!
//! Host monotonic time is used only to reject stale snapshots.  It is never
//! converted into a sample or hardware-global timestamp.

use std::io;

use forge_protocol_v1::{crc32c, Hash32, Id16};

pub const DIRECT_POD_TIME_SNAPSHOT_LEN: usize = 152;
pub const DIRECT_POD_TIME_SNAPSHOT_CONTRACT_HASH_HEX: &str =
    "32c7f4a546b19c3de9eeff4444c95579eebff31b879a2967d9d77d25f4e4706d";
pub const DIRECT_POD_TIME_SNAPSHOT_CONTRACT_HASH: Hash32 = [
    0x32, 0xc7, 0xf4, 0xa5, 0x46, 0xb1, 0x9c, 0x3d, 0xe9, 0xee, 0xff, 0x44, 0x44, 0xc9, 0x55, 0x79,
    0xee, 0xbf, 0xf3, 0x1b, 0x87, 0x9a, 0x29, 0x67, 0xd9, 0xd7, 0x7d, 0x25, 0xf4, 0xe4, 0x70, 0x6d,
];

pub const TIME_FLAG_GLOBAL_TIME_VALID: u32 = 1 << 0;
pub const TIME_FLAG_POD_READY: u32 = 1 << 1;
pub const TIME_FLAG_POD_FAULT: u32 = 1 << 2;
pub const TIME_FLAG_SYNCHRONIZED: u32 = 1 << 3;
const TIME_FLAG_KNOWN: u32 = TIME_FLAG_GLOBAL_TIME_VALID
    | TIME_FLAG_POD_READY
    | TIME_FLAG_POD_FAULT
    | TIME_FLAG_SYNCHRONIZED;
const MAGIC: &[u8; 8] = b"FGRTIM01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodTimeSnapshotV1 {
    pub device_id: Id16,
    pub transport_epoch: u64,
    pub status_sequence: u64,
    pub global_time_ns: u64,
    pub sample_counter: u64,
    pub frame_counter: u64,
    pub runtime_flags: u32,
    pub hardware_state_hash: Hash32,
}

impl DirectPodTimeSnapshotV1 {
    pub fn encode(self) -> io::Result<[u8; DIRECT_POD_TIME_SNAPSHOT_LEN]> {
        validate_snapshot(&self)?;
        let mut bytes = [0_u8; DIRECT_POD_TIME_SNAPSHOT_LEN];
        bytes[0..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&(DIRECT_POD_TIME_SNAPSHOT_LEN as u16).to_le_bytes());
        bytes[16..48].copy_from_slice(&DIRECT_POD_TIME_SNAPSHOT_CONTRACT_HASH);
        bytes[48..64].copy_from_slice(&self.device_id);
        bytes[64..72].copy_from_slice(&self.transport_epoch.to_le_bytes());
        bytes[72..80].copy_from_slice(&self.status_sequence.to_le_bytes());
        bytes[80..88].copy_from_slice(&self.global_time_ns.to_le_bytes());
        bytes[88..96].copy_from_slice(&self.sample_counter.to_le_bytes());
        bytes[96..104].copy_from_slice(&self.frame_counter.to_le_bytes());
        bytes[104..108].copy_from_slice(&self.runtime_flags.to_le_bytes());
        bytes[112..144].copy_from_slice(&self.hardware_state_hash);
        let checksum = crc32c(&bytes[..148]);
        bytes[148..152].copy_from_slice(&checksum.to_le_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != DIRECT_POD_TIME_SNAPSHOT_LEN
            || bytes.get(0..8) != Some(MAGIC)
            || le_u16(bytes, 8)? != 1
            || le_u16(bytes, 10)? as usize != DIRECT_POD_TIME_SNAPSHOT_LEN
            || le_u32(bytes, 12)? != 0
            || array::<32>(bytes, 16)? != DIRECT_POD_TIME_SNAPSHOT_CONTRACT_HASH
            || le_u32(bytes, 108)? != 0
            || le_u32(bytes, 144)? != 0
            || crc32c(&bytes[..148]) != le_u32(bytes, 148)?
        {
            return Err(invalid_data("direct-Pod time snapshot framing is invalid"));
        }
        let value = Self {
            device_id: array(bytes, 48)?,
            transport_epoch: le_u64(bytes, 64)?,
            status_sequence: le_u64(bytes, 72)?,
            global_time_ns: le_u64(bytes, 80)?,
            sample_counter: le_u64(bytes, 88)?,
            frame_counter: le_u64(bytes, 96)?,
            runtime_flags: le_u32(bytes, 104)?,
            hardware_state_hash: array(bytes, 112)?,
        };
        validate_snapshot(&value)
            .map_err(|_| invalid_data("direct-Pod time snapshot violates semantic invariants"))?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodTimeTrackerSnapshot {
    pub transport_epoch: u64,
    pub status_count: u64,
    pub latest: Option<DirectPodTimeSnapshotV1>,
    pub latest_host_monotonic_ns: Option<u64>,
    pub max_host_age_ns: u64,
    pub poisoned: bool,
}

pub struct DirectPodTimeTracker {
    device_id: Id16,
    transport_epoch: u64,
    max_host_age_ns: u64,
    latest: Option<DirectPodTimeSnapshotV1>,
    latest_host_monotonic_ns: Option<u64>,
    status_count: u64,
    poisoned: bool,
}

impl DirectPodTimeTracker {
    pub fn new(device_id: Id16, transport_epoch: u64, max_host_age_ns: u64) -> io::Result<Self> {
        if !device_id.iter().any(|byte| *byte != 0)
            || transport_epoch == 0
            || max_host_age_ns == 0
            || max_host_age_ns > 10_000_000_000
        {
            return Err(invalid_input("direct-Pod time tracker policy is invalid"));
        }
        Ok(Self {
            device_id,
            transport_epoch,
            max_host_age_ns,
            latest: None,
            latest_host_monotonic_ns: None,
            status_count: 0,
            poisoned: false,
        })
    }

    pub fn observe(&mut self, bytes: &[u8], host_monotonic_ns: u64) -> io::Result<()> {
        self.require_healthy()?;
        if host_monotonic_ns == 0
            || self
                .latest_host_monotonic_ns
                .is_some_and(|prior| host_monotonic_ns < prior)
        {
            return Err(self.poison("host freshness clock is zero or regressed"));
        }
        let value = DirectPodTimeSnapshotV1::decode(bytes)
            .map_err(|_| self.poison("direct-Pod time snapshot is invalid"))?;
        if value.device_id != self.device_id || value.transport_epoch != self.transport_epoch {
            return Err(self.poison("direct-Pod time snapshot identity is wrong"));
        }
        if let Some(prior) = self.latest {
            if value.status_sequence <= prior.status_sequence
                || value.global_time_ns <= prior.global_time_ns
                || value.sample_counter < prior.sample_counter
                || value.frame_counter < prior.frame_counter
            {
                return Err(self.poison("direct-Pod hardware time or counters regressed"));
            }
        }
        self.latest = Some(value);
        self.latest_host_monotonic_ns = Some(host_monotonic_ns);
        self.status_count = self
            .status_count
            .checked_add(1)
            .ok_or_else(|| self.poison("direct-Pod time status counter overflow"))?;
        Ok(())
    }

    /// Returns the last explicit hardware time only when the status is fresh,
    /// ready and fault-free. No host-clock interpolation is performed.
    pub fn require_fresh_ready_time(&mut self, host_monotonic_ns: u64) -> io::Result<u64> {
        self.require_healthy()?;
        let observed_at = self
            .latest_host_monotonic_ns
            .ok_or_else(|| invalid_data("no direct-Pod hardware-time snapshot is available"))?;
        let age = host_monotonic_ns
            .checked_sub(observed_at)
            .ok_or_else(|| self.poison("host freshness clock regressed"))?;
        if age > self.max_host_age_ns {
            return Err(self.poison("direct-Pod hardware-time snapshot is stale"));
        }
        let value = self.latest.unwrap();
        let required = TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY;
        if value.runtime_flags & required != required
            || value.runtime_flags & TIME_FLAG_POD_FAULT != 0
        {
            return Err(self.poison("direct-Pod time status is not ready and fault-free"));
        }
        Ok(value.global_time_ns)
    }

    pub fn snapshot(&self) -> DirectPodTimeTrackerSnapshot {
        DirectPodTimeTrackerSnapshot {
            transport_epoch: self.transport_epoch,
            status_count: self.status_count,
            latest: self.latest,
            latest_host_monotonic_ns: self.latest_host_monotonic_ns,
            max_host_age_ns: self.max_host_age_ns,
            poisoned: self.poisoned,
        }
    }

    fn require_healthy(&self) -> io::Result<()> {
        if self.poisoned {
            Err(invalid_data("direct-Pod time tracker is poisoned"))
        } else {
            Ok(())
        }
    }

    fn poison(&mut self, message: &'static str) -> io::Error {
        self.poisoned = true;
        invalid_data(message)
    }
}

fn validate_snapshot(value: &DirectPodTimeSnapshotV1) -> io::Result<()> {
    if !value.device_id.iter().any(|byte| *byte != 0)
        || value.transport_epoch == 0
        || value.global_time_ns == 0
        || value.runtime_flags & !TIME_FLAG_KNOWN != 0
        || !value.hardware_state_hash.iter().any(|byte| *byte != 0)
    {
        Err(invalid_input("direct-Pod time snapshot values are invalid"))
    } else {
        Ok(())
    }
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
        .ok_or_else(|| invalid_data("direct-Pod time snapshot is truncated"))?
        .try_into()
        .map_err(|_| invalid_data("direct-Pod time snapshot field length is invalid"))
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

    fn snapshot(sequence: u64, time: u64) -> DirectPodTimeSnapshotV1 {
        DirectPodTimeSnapshotV1 {
            device_id: [2; 16],
            transport_epoch: 7,
            status_sequence: sequence,
            global_time_ns: time,
            sample_counter: sequence * 30,
            frame_counter: sequence,
            runtime_flags: TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY,
            hardware_state_hash: sha256(&sequence.to_le_bytes()),
        }
    }

    #[test]
    fn contract_hash_matches_lf_normalized_schema() {
        let normalized = include_str!("../schema/forge_direct_pod_time_snapshot_v1.idl")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(
            sha256(normalized.as_bytes()),
            DIRECT_POD_TIME_SNAPSHOT_CONTRACT_HASH
        );
    }

    #[test]
    fn exact_layout_round_trip_and_every_mutation_fail_closed() {
        let bytes = snapshot(1, 1_000).encode().unwrap();
        assert_eq!(
            DirectPodTimeSnapshotV1::decode(&bytes).unwrap(),
            snapshot(1, 1_000)
        );
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(
                DirectPodTimeSnapshotV1::decode(&changed).is_err(),
                "byte {index}"
            );
        }
    }

    #[test]
    fn freshness_uses_host_clock_without_inventing_hardware_time() {
        let mut tracker = DirectPodTimeTracker::new([2; 16], 7, 100).unwrap();
        tracker
            .observe(&snapshot(1, 1_000).encode().unwrap(), 500)
            .unwrap();
        assert_eq!(tracker.require_fresh_ready_time(600).unwrap(), 1_000);
        assert!(tracker.require_fresh_ready_time(601).is_err());
        assert!(tracker.snapshot().poisoned);
    }

    #[test]
    fn coalesced_statuses_may_share_one_usb_completion_timestamp() {
        let mut tracker = DirectPodTimeTracker::new([2; 16], 7, 100).unwrap();
        tracker
            .observe(&snapshot(1, 1_000).encode().unwrap(), 500)
            .unwrap();
        tracker
            .observe(&snapshot(2, 2_000).encode().unwrap(), 500)
            .unwrap();
        assert_eq!(tracker.snapshot().status_count, 2);
        assert_eq!(tracker.require_fresh_ready_time(600).unwrap(), 2_000);
    }

    #[test]
    fn identity_counter_fault_and_clock_contradictions_poison() {
        let mut tracker = DirectPodTimeTracker::new([2; 16], 7, 100).unwrap();
        tracker
            .observe(&snapshot(2, 2_000).encode().unwrap(), 500)
            .unwrap();
        assert!(tracker
            .observe(&snapshot(1, 2_001).encode().unwrap(), 501)
            .is_err());

        let mut tracker = DirectPodTimeTracker::new([2; 16], 7, 100).unwrap();
        let mut fault = snapshot(1, 1_000);
        fault.runtime_flags |= TIME_FLAG_POD_FAULT;
        tracker.observe(&fault.encode().unwrap(), 500).unwrap();
        assert!(tracker.require_fresh_ready_time(501).is_err());
    }
}
