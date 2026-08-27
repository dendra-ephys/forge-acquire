//! Exact CABLINE source-status evidence for one admitted direct Pod.
//!
//! The companion binds the active Pod and Headstage identities, admitted DHL
//! Descriptor/Inventory evidence and fault-free receiver state. Host monotonic
//! time is used only for the fixed 100-ms freshness gate and is never converted
//! into source or hardware-global time.

use std::io;

use forge_protocol_v1::{crc32c, sha256, Hash32, Id16};

pub const DIRECT_POD_CABLINE_STATUS_LEN: usize = 360;
pub const DIRECT_POD_CABLINE_MAX_HOST_AGE_NS: u64 = 100_000_000;
pub const DIRECT_POD_CABLINE_STATUS_CONTRACT_HASH_HEX: &str =
    "40670b2feff4580e96a475c8f0aad83eab8bc3b267b19dc380d3dd1bf372cad0";
pub const DIRECT_POD_CABLINE_STATUS_CONTRACT_HASH: Hash32 = [
    0x40, 0x67, 0x0b, 0x2f, 0xef, 0xf4, 0x58, 0x0e, 0x96, 0xa4, 0x75, 0xc8, 0xf0, 0xaa, 0xd8, 0x3e,
    0xab, 0x8b, 0xc3, 0xb2, 0x67, 0xb1, 0x9d, 0xc3, 0x80, 0xd3, 0xdd, 0x1b, 0xf3, 0x72, 0xca, 0xd0,
];

pub const CABLINE_FLAG_LINK_LOCKED: u32 = 1 << 0;
pub const CABLINE_FLAG_DESCRIPTOR_ADMITTED: u32 = 1 << 1;
pub const CABLINE_FLAG_INVENTORY_ADMITTED: u32 = 1 << 2;
pub const CABLINE_FLAG_CTRL_READY: u32 = 1 << 3;
pub const CABLINE_FLAG_SOURCE_FAULT: u32 = 1 << 4;
pub const CABLINE_FLAG_RECEIVER_OVERFLOW: u32 = 1 << 5;
pub const CABLINE_REQUIRED_READY_FLAGS: u32 = CABLINE_FLAG_LINK_LOCKED
    | CABLINE_FLAG_DESCRIPTOR_ADMITTED
    | CABLINE_FLAG_INVENTORY_ADMITTED
    | CABLINE_FLAG_CTRL_READY;
const CABLINE_FAULT_FLAGS: u32 = CABLINE_FLAG_SOURCE_FAULT | CABLINE_FLAG_RECEIVER_OVERFLOW;
const CABLINE_KNOWN_FLAGS: u32 = CABLINE_REQUIRED_READY_FLAGS | CABLINE_FAULT_FLAGS;
const MAGIC: &[u8; 8] = b"FGRCAB01";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodCablineStatusV1 {
    pub device_id: Id16,
    pub pod_id: Id16,
    pub headstage_id: Id16,
    pub transport_epoch: u64,
    pub status_sequence: u64,
    pub global_time_ns: u64,
    pub headstage_boot_id: u64,
    pub next_dhl_sequence: u64,
    pub source_id: u32,
    pub state_flags: u32,
    pub symbol_error_count: u64,
    pub crc_error_count: u64,
    pub sequence_error_count: u64,
    pub packet_drop_count: u64,
    pub receiver_overflow_count: u64,
    pub relock_count: u64,
    pub headstage_config_hash: Hash32,
    pub descriptor_hash: Hash32,
    pub inventory_hash: Hash32,
    pub assembly_manifest_hash: Hash32,
    pub channel_map_hash: Hash32,
}

impl DirectPodCablineStatusV1 {
    pub fn configuration_binding_hash(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(40 + 32 * 6);
        bytes.extend_from_slice(b"FORGE-DIRECT-POD-CABLINE-BINDING-V1\0");
        bytes.extend_from_slice(&DIRECT_POD_CABLINE_STATUS_CONTRACT_HASH);
        bytes.extend_from_slice(&self.headstage_config_hash);
        bytes.extend_from_slice(&self.descriptor_hash);
        bytes.extend_from_slice(&self.inventory_hash);
        bytes.extend_from_slice(&self.assembly_manifest_hash);
        bytes.extend_from_slice(&self.channel_map_hash);
        sha256(&bytes)
    }

    pub fn encode(self) -> io::Result<[u8; DIRECT_POD_CABLINE_STATUS_LEN]> {
        validate_status(&self)?;
        let mut bytes = [0_u8; DIRECT_POD_CABLINE_STATUS_LEN];
        bytes[0..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(DIRECT_POD_CABLINE_STATUS_LEN as u16).to_le_bytes());
        bytes[16..48].copy_from_slice(&DIRECT_POD_CABLINE_STATUS_CONTRACT_HASH);
        bytes[48..64].copy_from_slice(&self.device_id);
        bytes[64..80].copy_from_slice(&self.pod_id);
        bytes[80..96].copy_from_slice(&self.headstage_id);
        bytes[96..104].copy_from_slice(&self.transport_epoch.to_le_bytes());
        bytes[104..112].copy_from_slice(&self.status_sequence.to_le_bytes());
        bytes[112..120].copy_from_slice(&self.global_time_ns.to_le_bytes());
        bytes[120..128].copy_from_slice(&self.headstage_boot_id.to_le_bytes());
        bytes[128..136].copy_from_slice(&self.next_dhl_sequence.to_le_bytes());
        bytes[136..140].copy_from_slice(&self.source_id.to_le_bytes());
        bytes[140..144].copy_from_slice(&self.state_flags.to_le_bytes());
        bytes[144..152].copy_from_slice(&self.symbol_error_count.to_le_bytes());
        bytes[152..160].copy_from_slice(&self.crc_error_count.to_le_bytes());
        bytes[160..168].copy_from_slice(&self.sequence_error_count.to_le_bytes());
        bytes[168..176].copy_from_slice(&self.packet_drop_count.to_le_bytes());
        bytes[176..184].copy_from_slice(&self.receiver_overflow_count.to_le_bytes());
        bytes[184..192].copy_from_slice(&self.relock_count.to_le_bytes());
        bytes[192..224].copy_from_slice(&self.headstage_config_hash);
        bytes[224..256].copy_from_slice(&self.descriptor_hash);
        bytes[256..288].copy_from_slice(&self.inventory_hash);
        bytes[288..320].copy_from_slice(&self.assembly_manifest_hash);
        bytes[320..352].copy_from_slice(&self.channel_map_hash);
        let checksum = crc32c(&bytes[..356]);
        bytes[356..360].copy_from_slice(&checksum.to_le_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != DIRECT_POD_CABLINE_STATUS_LEN
            || bytes.get(0..8) != Some(MAGIC)
            || le_u16(bytes, 8)? != VERSION
            || le_u16(bytes, 10)? as usize != DIRECT_POD_CABLINE_STATUS_LEN
            || le_u32(bytes, 12)? != 0
            || array::<32>(bytes, 16)? != DIRECT_POD_CABLINE_STATUS_CONTRACT_HASH
            || le_u32(bytes, 352)? != 0
            || crc32c(&bytes[..356]) != le_u32(bytes, 356)?
        {
            return Err(invalid_data("direct-Pod CABLINE status framing is invalid"));
        }
        let value = Self {
            device_id: array(bytes, 48)?,
            pod_id: array(bytes, 64)?,
            headstage_id: array(bytes, 80)?,
            transport_epoch: le_u64(bytes, 96)?,
            status_sequence: le_u64(bytes, 104)?,
            global_time_ns: le_u64(bytes, 112)?,
            headstage_boot_id: le_u64(bytes, 120)?,
            next_dhl_sequence: le_u64(bytes, 128)?,
            source_id: le_u32(bytes, 136)?,
            state_flags: le_u32(bytes, 140)?,
            symbol_error_count: le_u64(bytes, 144)?,
            crc_error_count: le_u64(bytes, 152)?,
            sequence_error_count: le_u64(bytes, 160)?,
            packet_drop_count: le_u64(bytes, 168)?,
            receiver_overflow_count: le_u64(bytes, 176)?,
            relock_count: le_u64(bytes, 184)?,
            headstage_config_hash: array(bytes, 192)?,
            descriptor_hash: array(bytes, 224)?,
            inventory_hash: array(bytes, 256)?,
            assembly_manifest_hash: array(bytes, 288)?,
            channel_map_hash: array(bytes, 320)?,
        };
        validate_status(&value)
            .map_err(|_| invalid_data("direct-Pod CABLINE status violates semantic invariants"))?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodCablineTrackerSnapshot {
    pub transport_epoch: u64,
    pub status_count: u64,
    pub latest: Option<DirectPodCablineStatusV1>,
    pub latest_host_monotonic_ns: Option<u64>,
    pub max_host_age_ns: u64,
    pub poisoned: bool,
}

pub struct DirectPodCablineTracker {
    device_id: Id16,
    expected_pod_id: Option<Id16>,
    expected_headstage_id: Option<Id16>,
    transport_epoch: u64,
    latest: Option<DirectPodCablineStatusV1>,
    latest_host_monotonic_ns: Option<u64>,
    status_count: u64,
    poisoned: bool,
}

impl DirectPodCablineTracker {
    pub fn new(
        device_id: Id16,
        pod_id: Id16,
        headstage_id: Id16,
        transport_epoch: u64,
    ) -> io::Result<Self> {
        if !nonzero(&pod_id) || !nonzero(&headstage_id) {
            return Err(invalid_input(
                "direct-Pod CABLINE tracker policy is invalid",
            ));
        }
        let mut tracker = Self::new_unbound(device_id, transport_epoch)?;
        tracker.expected_pod_id = Some(pod_id);
        tracker.expected_headstage_id = Some(headstage_id);
        Ok(tracker)
    }

    /// Creates the pre-Run tracker before a protected Run plan supplies the
    /// Pod and Headstage identities. The first valid source status becomes the
    /// stable observed identity, but it is not authorized for a Run until
    /// `require_fresh_ready_status_for` matches it to that plan.
    pub fn new_unbound(device_id: Id16, transport_epoch: u64) -> io::Result<Self> {
        if !nonzero(&device_id) || transport_epoch == 0 {
            return Err(invalid_input(
                "direct-Pod CABLINE tracker policy is invalid",
            ));
        }
        Ok(Self {
            device_id,
            expected_pod_id: None,
            expected_headstage_id: None,
            transport_epoch,
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
            return Err(self.poison("CABLINE freshness clock is zero or regressed"));
        }
        let value = DirectPodCablineStatusV1::decode(bytes)
            .map_err(|_| self.poison("direct-Pod CABLINE status is invalid"))?;
        if value.device_id != self.device_id
            || self
                .expected_pod_id
                .is_some_and(|expected| value.pod_id != expected)
            || self
                .expected_headstage_id
                .is_some_and(|expected| value.headstage_id != expected)
            || value.transport_epoch != self.transport_epoch
        {
            return Err(self.poison("direct-Pod CABLINE status identity is wrong"));
        }
        if let Some(prior) = self.latest {
            if value.pod_id != prior.pod_id
                || value.headstage_id != prior.headstage_id
                || value.headstage_boot_id != prior.headstage_boot_id
                || value.source_id != prior.source_id
                || value.headstage_config_hash != prior.headstage_config_hash
                || value.descriptor_hash != prior.descriptor_hash
                || value.inventory_hash != prior.inventory_hash
                || value.assembly_manifest_hash != prior.assembly_manifest_hash
                || value.channel_map_hash != prior.channel_map_hash
            {
                return Err(self.poison("CABLINE source identity or admitted hashes changed"));
            }
            if value.status_sequence <= prior.status_sequence
                || value.global_time_ns < prior.global_time_ns
                || value.next_dhl_sequence < prior.next_dhl_sequence
                || value.symbol_error_count < prior.symbol_error_count
                || value.crc_error_count < prior.crc_error_count
                || value.sequence_error_count < prior.sequence_error_count
                || value.packet_drop_count < prior.packet_drop_count
                || value.receiver_overflow_count < prior.receiver_overflow_count
                || value.relock_count < prior.relock_count
            {
                return Err(self.poison("CABLINE status sequence, time or counters regressed"));
            }
        }
        self.expected_pod_id.get_or_insert(value.pod_id);
        self.expected_headstage_id.get_or_insert(value.headstage_id);
        self.latest = Some(value);
        self.latest_host_monotonic_ns = Some(host_monotonic_ns);
        self.status_count = self
            .status_count
            .checked_add(1)
            .ok_or_else(|| self.poison("CABLINE status counter overflow"))?;
        Ok(())
    }

    pub fn require_fresh_ready_status(
        &mut self,
        host_monotonic_ns: u64,
    ) -> io::Result<DirectPodCablineStatusV1> {
        self.require_healthy()?;
        let observed_at = self
            .latest_host_monotonic_ns
            .ok_or_else(|| invalid_data("no direct-Pod CABLINE status is available"))?;
        let age = host_monotonic_ns
            .checked_sub(observed_at)
            .ok_or_else(|| self.poison("CABLINE freshness clock regressed"))?;
        if age > DIRECT_POD_CABLINE_MAX_HOST_AGE_NS {
            return Err(self.poison("direct-Pod CABLINE status is stale"));
        }
        let value = self
            .latest
            .ok_or_else(|| invalid_data("no direct-Pod CABLINE status is available"))?;
        validate_status(&value)
            .map_err(|_| self.poison("direct-Pod CABLINE status is not ready and fault-free"))?;
        Ok(value)
    }

    pub fn require_fresh_ready_status_for(
        &mut self,
        host_monotonic_ns: u64,
        pod_id: Id16,
        headstage_id: Id16,
        approved_binding_sha256: Hash32,
    ) -> io::Result<DirectPodCablineStatusV1> {
        if !nonzero(&pod_id) || !nonzero(&headstage_id) || !nonzero(&approved_binding_sha256) {
            return Err(self.poison("CABLINE Run identity or approved binding is zero"));
        }
        let value = self.require_fresh_ready_status(host_monotonic_ns)?;
        if value.pod_id != pod_id || value.headstage_id != headstage_id {
            return Err(self.poison("CABLINE source identity does not match the protected Run"));
        }
        if value.configuration_binding_hash() != approved_binding_sha256 {
            return Err(self.poison("CABLINE configuration is not approved for the protected Run"));
        }
        Ok(value)
    }

    pub fn snapshot(&self) -> DirectPodCablineTrackerSnapshot {
        DirectPodCablineTrackerSnapshot {
            transport_epoch: self.transport_epoch,
            status_count: self.status_count,
            latest: self.latest,
            latest_host_monotonic_ns: self.latest_host_monotonic_ns,
            max_host_age_ns: DIRECT_POD_CABLINE_MAX_HOST_AGE_NS,
            poisoned: self.poisoned,
        }
    }

    fn require_healthy(&self) -> io::Result<()> {
        if self.poisoned {
            Err(invalid_data("direct-Pod CABLINE tracker is poisoned"))
        } else {
            Ok(())
        }
    }

    fn poison(&mut self, message: &'static str) -> io::Error {
        self.poisoned = true;
        invalid_data(message)
    }
}

fn validate_status(value: &DirectPodCablineStatusV1) -> io::Result<()> {
    let counters = [
        value.symbol_error_count,
        value.crc_error_count,
        value.sequence_error_count,
        value.packet_drop_count,
        value.receiver_overflow_count,
        value.relock_count,
    ];
    let hashes = [
        value.headstage_config_hash,
        value.descriptor_hash,
        value.inventory_hash,
        value.assembly_manifest_hash,
        value.channel_map_hash,
    ];
    if !nonzero(&value.device_id)
        || !nonzero(&value.pod_id)
        || !nonzero(&value.headstage_id)
        || value.transport_epoch == 0
        || value.status_sequence == 0
        || value.global_time_ns == 0
        || value.headstage_boot_id == 0
        || value.next_dhl_sequence == 0
        || value.source_id == 0
        || hashes.iter().any(|hash| !nonzero(hash))
        || value.state_flags & !CABLINE_KNOWN_FLAGS != 0
        || value.state_flags & CABLINE_REQUIRED_READY_FLAGS != CABLINE_REQUIRED_READY_FLAGS
        || value.state_flags & CABLINE_FAULT_FLAGS != 0
        || counters.iter().any(|count| *count != 0)
    {
        Err(invalid_input(
            "direct-Pod CABLINE status values are invalid",
        ))
    } else {
        Ok(())
    }
}

fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
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
        .ok_or_else(|| invalid_data("direct-Pod CABLINE status is truncated"))?
        .try_into()
        .map_err(|_| invalid_data("direct-Pod CABLINE status field length is invalid"))
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

    fn status(sequence: u64, time_ns: u64, next_dhl_sequence: u64) -> DirectPodCablineStatusV1 {
        DirectPodCablineStatusV1 {
            device_id: [1; 16],
            pod_id: [2; 16],
            headstage_id: [3; 16],
            transport_epoch: 7,
            status_sequence: sequence,
            global_time_ns: time_ns,
            headstage_boot_id: 0x1122_3344_5566_7788,
            next_dhl_sequence,
            source_id: 0x1234_5678,
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
    }

    fn tracker() -> DirectPodCablineTracker {
        DirectPodCablineTracker::new([1; 16], [2; 16], [3; 16], 7).unwrap()
    }

    fn rewrite_crc(bytes: &mut [u8; DIRECT_POD_CABLINE_STATUS_LEN]) {
        let checksum = crc32c(&bytes[..356]);
        bytes[356..360].copy_from_slice(&checksum.to_le_bytes());
    }

    #[test]
    fn contract_hash_matches_lf_normalized_schema() {
        let normalized = include_str!("../schema/forge_direct_pod_cabline_status_v1.idl")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(
            sha256(normalized.as_bytes()),
            DIRECT_POD_CABLINE_STATUS_CONTRACT_HASH
        );
    }

    #[test]
    fn exact_layout_round_trip_truncation_and_every_mutation_fail_closed() {
        let expected = status(1, 1_000, 3);
        let bytes = expected.encode().unwrap();
        assert_eq!(bytes.len(), DIRECT_POD_CABLINE_STATUS_LEN);
        assert_eq!(DirectPodCablineStatusV1::decode(&bytes).unwrap(), expected);
        for length in 0..bytes.len() {
            assert!(DirectPodCablineStatusV1::decode(&bytes[..length]).is_err());
        }
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(
                DirectPodCablineStatusV1::decode(&changed).is_err(),
                "byte {index}"
            );
        }
    }

    #[test]
    fn semantic_fault_flags_counters_reserved_and_zero_values_fail_closed() {
        let original = status(1, 1_000, 3).encode().unwrap();
        for (offset, width) in [
            (48, 16),
            (64, 16),
            (80, 16),
            (96, 8),
            (104, 8),
            (112, 8),
            (120, 8),
            (128, 8),
            (136, 4),
            (192, 32),
            (224, 32),
            (256, 32),
            (288, 32),
            (320, 32),
        ] {
            let mut changed = original;
            changed[offset..offset + width].fill(0);
            rewrite_crc(&mut changed);
            assert!(
                DirectPodCablineStatusV1::decode(&changed).is_err(),
                "offset {offset}"
            );
        }
        for offset in [12, 144, 152, 160, 168, 176, 184, 352] {
            let mut changed = original;
            changed[offset] = 1;
            rewrite_crc(&mut changed);
            assert!(
                DirectPodCablineStatusV1::decode(&changed).is_err(),
                "offset {offset}"
            );
        }
        for flags in [
            CABLINE_REQUIRED_READY_FLAGS & !CABLINE_FLAG_CTRL_READY,
            CABLINE_REQUIRED_READY_FLAGS | CABLINE_FLAG_SOURCE_FAULT,
            CABLINE_REQUIRED_READY_FLAGS | CABLINE_FLAG_RECEIVER_OVERFLOW,
            CABLINE_REQUIRED_READY_FLAGS | (1 << 31),
        ] {
            let mut changed = original;
            changed[140..144].copy_from_slice(&flags.to_le_bytes());
            rewrite_crc(&mut changed);
            assert!(DirectPodCablineStatusV1::decode(&changed).is_err());
        }
    }

    #[test]
    fn tracker_requires_stable_identity_hash_boot_and_source() {
        let first = status(1, 1_000, 3);
        for changed in [
            DirectPodCablineStatusV1 {
                device_id: [9; 16],
                status_sequence: 2,
                global_time_ns: 2_000,
                next_dhl_sequence: 4,
                ..first
            },
            DirectPodCablineStatusV1 {
                pod_id: [9; 16],
                status_sequence: 2,
                global_time_ns: 2_000,
                next_dhl_sequence: 4,
                ..first
            },
            DirectPodCablineStatusV1 {
                descriptor_hash: sha256(b"changed-descriptor"),
                status_sequence: 2,
                global_time_ns: 2_000,
                next_dhl_sequence: 4,
                ..first
            },
            DirectPodCablineStatusV1 {
                headstage_boot_id: first.headstage_boot_id + 1,
                status_sequence: 2,
                global_time_ns: 2_000,
                next_dhl_sequence: 4,
                ..first
            },
            DirectPodCablineStatusV1 {
                source_id: first.source_id + 1,
                status_sequence: 2,
                global_time_ns: 2_000,
                next_dhl_sequence: 4,
                ..first
            },
        ] {
            let mut value = tracker();
            value.observe(&first.encode().unwrap(), 1_000).unwrap();
            assert!(value.observe(&changed.encode().unwrap(), 1_001).is_err());
            assert!(value.snapshot().poisoned);
        }
    }

    #[test]
    fn unbound_pre_run_tracker_requires_the_protected_run_identity() {
        let encoded = status(1, 1_000, 3).encode().unwrap();
        let approved = status(1, 1_000, 3).configuration_binding_hash();
        let mut matching = DirectPodCablineTracker::new_unbound([1; 16], 7).unwrap();
        matching.observe(&encoded, 100).unwrap();
        assert_eq!(
            matching
                .require_fresh_ready_status_for(101, [2; 16], [3; 16], approved)
                .unwrap()
                .source_id,
            0x1234_5678
        );

        let mut wrong_plan = DirectPodCablineTracker::new_unbound([1; 16], 7).unwrap();
        wrong_plan.observe(&encoded, 100).unwrap();
        assert!(wrong_plan
            .require_fresh_ready_status_for(101, [9; 16], [3; 16], approved)
            .is_err());
        assert!(wrong_plan.snapshot().poisoned);
    }

    #[test]
    fn configuration_binding_is_ordered_and_every_source_hash_is_authoritative() {
        let original = status(1, 1_000, 3);
        let approved = original.configuration_binding_hash();
        assert_eq!(
            approved,
            [
                0x4e, 0x28, 0x19, 0xbb, 0x9b, 0x37, 0xcf, 0xf7, 0xe2, 0x76, 0x10, 0x70, 0xe8, 0x21,
                0x9c, 0xc4, 0x7c, 0xe3, 0x38, 0xdc, 0x72, 0xc7, 0x6e, 0x30, 0x4f, 0x6a, 0xc7, 0xd6,
                0x33, 0x0b, 0x66, 0xdf,
            ]
        );
        for changed in [
            DirectPodCablineStatusV1 {
                headstage_config_hash: sha256(b"changed-headstage-config"),
                ..original
            },
            DirectPodCablineStatusV1 {
                descriptor_hash: sha256(b"changed-descriptor"),
                ..original
            },
            DirectPodCablineStatusV1 {
                inventory_hash: sha256(b"changed-inventory"),
                ..original
            },
            DirectPodCablineStatusV1 {
                assembly_manifest_hash: sha256(b"changed-assembly"),
                ..original
            },
            DirectPodCablineStatusV1 {
                channel_map_hash: sha256(b"changed-channel-map"),
                ..original
            },
        ] {
            assert_ne!(changed.configuration_binding_hash(), approved);
            let mut value = DirectPodCablineTracker::new_unbound([1; 16], 7).unwrap();
            value.observe(&changed.encode().unwrap(), 100).unwrap();
            assert!(value
                .require_fresh_ready_status_for(101, [2; 16], [3; 16], approved)
                .is_err());
            assert!(value.snapshot().poisoned);
        }
    }

    #[test]
    fn tracker_rejects_sequence_time_and_dhl_regression() {
        let first = status(2, 2_000, 4);
        for changed in [
            status(2, 2_001, 5),
            status(3, 1_999, 5),
            status(3, 2_001, 3),
        ] {
            let mut value = tracker();
            value.observe(&first.encode().unwrap(), 1_000).unwrap();
            assert!(value.observe(&changed.encode().unwrap(), 1_001).is_err());
            assert!(value.snapshot().poisoned);
        }
    }

    #[test]
    fn tracker_uses_fixed_100ms_freshness_and_faults_poison() {
        let mut value = tracker();
        let encoded = status(1, 1_000, 3).encode().unwrap();
        value.observe(&encoded, 500_000_000).unwrap();
        assert_eq!(
            value
                .require_fresh_ready_status(600_000_000)
                .unwrap()
                .global_time_ns,
            1_000
        );
        assert!(value.require_fresh_ready_status(600_000_001).is_err());
        assert!(value.snapshot().poisoned);

        let mut fault = encoded;
        fault[140..144].copy_from_slice(
            &(CABLINE_REQUIRED_READY_FLAGS | CABLINE_FLAG_SOURCE_FAULT).to_le_bytes(),
        );
        rewrite_crc(&mut fault);
        let mut value = tracker();
        assert!(value.observe(&fault, 1).is_err());
        assert!(value.snapshot().poisoned);
    }
}
