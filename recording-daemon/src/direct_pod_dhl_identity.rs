//! Direct-Pod DHL Descriptor/Inventory evidence capsule v1.
//!
//! This module is deliberately a standalone byte-level evidence boundary.  It
//! does not consume a stream, advance bootstrap, assert Ready, start a Run,
//! open D3XX/FT601, or grant RHS/stimulation authority.

use std::error::Error;
use std::fmt;

use forge_protocol_v1::{crc32c, sha256, Hash32, Id16};

use crate::dhl_identity_admission::{
    admit_new_run_dhl_identity_v1, decode_descriptor_payload_v1, decode_inventory_payload_v1,
    AdmittedDhlIdentityV1, DhlIdentityAdmissionError, DhlIdentityAdmissionPolicyV1,
};
use crate::dhl_identity_catalog::DhlIdentityCatalog;

const CAPSULE_MAGIC: &[u8; 8] = b"FGRDHI01";
pub const DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_HEADER_LEN: usize = 176;
pub const DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_DESCRIPTOR_WIRE_LEN: usize = 140;
pub const DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_INVENTORY_WIRE_MIN_LEN: usize = 152;
pub const DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_INVENTORY_WIRE_MAX_LEN: usize = 632;
pub const DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MIN_LEN: usize = 472;
pub const DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MAX_LEN: usize = 952;
pub const DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_CONTRACT_HASH_HEX: &str =
    "346b02777e0813ef8339abf9f54a63f6e1cc539e111a2e4864eaaa9c7efa3ae8";
pub const DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_CONTRACT_HASH: Hash32 = [
    0x34, 0x6b, 0x02, 0x77, 0x7e, 0x08, 0x13, 0xef, 0x83, 0x39, 0xab, 0xf9, 0xf5, 0x4a, 0x63, 0xf6,
    0xe1, 0xcc, 0x53, 0x9e, 0x11, 0x1a, 0x2e, 0x48, 0x64, 0xea, 0xaa, 0x9c, 0x7e, 0xfa, 0x3a, 0xe8,
];

const DHL_HEADER_LEN: usize = 40;
const DHL_DESCRIPTOR_TYPE: u8 = 1;
const DHL_INVENTORY_TYPE: u8 = 9;
const DHL_DESCRIPTOR_PAYLOAD_LEN: usize = 96;
const DHL_INVENTORY_PAYLOAD_MIN_LEN: usize = 108;
const DHL_INVENTORY_PAYLOAD_MAX_LEN: usize = 588;

/// Owned decoded (or to-be-encoded) evidence.  It carries no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectPodDhlIdentityCapsuleV1 {
    pub device_id: Id16,
    pub pod_id: Id16,
    pub headstage_id: Id16,
    pub transport_epoch: u64,
    pub descriptor_wire: Vec<u8>,
    pub inventory_wire: Vec<u8>,
}

/// Protected caller context.  The capsule cannot self-authorize these values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectPodDhlIdentityContextV1 {
    pub(crate) device_id: Id16,
    pub(crate) pod_id: Id16,
    pub(crate) headstage_id: Id16,
    pub(crate) transport_epoch: u64,
}

/// Strictly decoded DHL v1 outer packet retained as evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhlOuterPacketEvidenceV1 {
    pub packet_type: u8,
    pub source_id: u32,
    pub boot_id: u64,
    pub sequence: u64,
    pub timestamp_25mhz: u64,
    pub payload: Vec<u8>,
}

/// Successful capsule admission.  This is identity evidence only, never
/// Ready/Run/stimulation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmittedDirectPodDhlIdentityCapsuleV1 {
    pub(crate) admitted_identity: AdmittedDhlIdentityV1,
    pub(crate) source_id: u32,
    pub(crate) boot_id: u64,
    pub(crate) descriptor_sequence: u64,
    pub(crate) inventory_sequence: u64,
    pub(crate) next_sequence: u64,
    pub(crate) descriptor_timestamp_25mhz: u64,
    pub(crate) inventory_timestamp_25mhz: u64,
    pub(crate) descriptor_wire_sha256: Hash32,
    pub(crate) inventory_wire_sha256: Hash32,
    pub(crate) device_id: Id16,
    pub(crate) pod_id: Id16,
    pub(crate) headstage_id: Id16,
    pub(crate) transport_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectPodDhlIdentityCapsuleError(String);

impl DirectPodDhlIdentityCapsuleError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for DirectPodDhlIdentityCapsuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for DirectPodDhlIdentityCapsuleError {}

impl From<DhlIdentityAdmissionError> for DirectPodDhlIdentityCapsuleError {
    fn from(value: DhlIdentityAdmissionError) -> Self {
        Self::new(format!("DHL identity policy admission rejected: {value}"))
    }
}

impl DirectPodDhlIdentityCapsuleV1 {
    /// Encodes an evidence capsule after applying the same structural checks as
    /// decode.  The caller must still perform protected-context/policy admission.
    pub fn encode(&self) -> Result<Vec<u8>, DirectPodDhlIdentityCapsuleError> {
        validate_capsule_fields(self)?;
        let descriptor_wire_sha256 = sha256(&self.descriptor_wire);
        let inventory_wire_sha256 = sha256(&self.inventory_wire);
        let total_len = capsule_total_len(self.descriptor_wire.len(), self.inventory_wire.len())?;
        let total_len_u16 = u16::try_from(total_len).map_err(|_| {
            DirectPodDhlIdentityCapsuleError::new("capsule total length exceeds u16")
        })?;
        let inventory_len_u16 = u16::try_from(self.inventory_wire.len()).map_err(|_| {
            DirectPodDhlIdentityCapsuleError::new("inventory wire length exceeds u16")
        })?;
        let mut encoded = Vec::with_capacity(total_len);
        encoded.extend_from_slice(CAPSULE_MAGIC);
        put_u16(&mut encoded, 1);
        put_u16(&mut encoded, total_len_u16);
        put_u32(&mut encoded, 0);
        encoded.extend_from_slice(&DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_CONTRACT_HASH);
        encoded.extend_from_slice(&self.device_id);
        encoded.extend_from_slice(&self.pod_id);
        encoded.extend_from_slice(&self.headstage_id);
        put_u64(&mut encoded, self.transport_epoch);
        put_u16(
            &mut encoded,
            DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_DESCRIPTOR_WIRE_LEN as u16,
        );
        put_u16(&mut encoded, inventory_len_u16);
        put_u32(&mut encoded, 0);
        encoded.extend_from_slice(&descriptor_wire_sha256);
        encoded.extend_from_slice(&inventory_wire_sha256);
        debug_assert_eq!(encoded.len(), DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_HEADER_LEN);
        encoded.extend_from_slice(&self.descriptor_wire);
        encoded.extend_from_slice(&self.inventory_wire);
        let capsule_crc = crc32c(&encoded);
        put_u32(&mut encoded, capsule_crc);
        debug_assert_eq!(encoded.len(), total_len);
        Ok(encoded)
    }

    /// Decodes bounded evidence.  It validates all header fields and CRC/hash
    /// bindings before allocating either embedded DHL wire.
    pub fn decode(encoded: &[u8]) -> Result<Self, DirectPodDhlIdentityCapsuleError> {
        if encoded.len() < DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_HEADER_LEN {
            return Err(DirectPodDhlIdentityCapsuleError::new(
                "capsule is shorter than its header",
            ));
        }
        if encoded.len() > DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MAX_LEN {
            return Err(DirectPodDhlIdentityCapsuleError::new(
                "capsule exceeds maximum length",
            ));
        }
        if encoded[..8] != *CAPSULE_MAGIC
            || le_u16(encoded, 8)? != 1
            || le_u32(encoded, 12)? != 0
            || le_u32(encoded, 108)? != 0
            || array32(encoded, 16)? != DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_CONTRACT_HASH
        {
            return Err(DirectPodDhlIdentityCapsuleError::new(
                "capsule magic/version/flags/reserved/contract hash is non-canonical",
            ));
        }
        let total_len = usize::from(le_u16(encoded, 10)?);
        let descriptor_len = usize::from(le_u16(encoded, 104)?);
        let inventory_len = usize::from(le_u16(encoded, 106)?);
        if total_len != encoded.len()
            || !(DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MIN_LEN
                ..=DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MAX_LEN)
                .contains(&total_len)
            || descriptor_len != DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_DESCRIPTOR_WIRE_LEN
            || !(DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_INVENTORY_WIRE_MIN_LEN
                ..=DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_INVENTORY_WIRE_MAX_LEN)
                .contains(&inventory_len)
            || capsule_total_len(descriptor_len, inventory_len)? != total_len
        {
            return Err(DirectPodDhlIdentityCapsuleError::new(
                "capsule total or embedded DHL wire length is invalid",
            ));
        }
        if le_u32(
            encoded,
            total_len.checked_sub(4).ok_or_else(|| {
                DirectPodDhlIdentityCapsuleError::new("capsule footer offset underflow")
            })?,
        )? != crc32c(&encoded[..total_len - 4])
        {
            return Err(DirectPodDhlIdentityCapsuleError::new(
                "capsule CRC32C mismatch",
            ));
        }
        let descriptor_end = DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_HEADER_LEN
            .checked_add(descriptor_len)
            .ok_or_else(|| DirectPodDhlIdentityCapsuleError::new("Descriptor offset overflow"))?;
        let inventory_end = descriptor_end
            .checked_add(inventory_len)
            .ok_or_else(|| DirectPodDhlIdentityCapsuleError::new("Inventory offset overflow"))?;
        if inventory_end.checked_add(4) != Some(total_len) {
            return Err(DirectPodDhlIdentityCapsuleError::new(
                "capsule embedded range mismatch",
            ));
        }
        let descriptor_wire =
            &encoded[DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_HEADER_LEN..descriptor_end];
        let inventory_wire = &encoded[descriptor_end..inventory_end];
        if sha256(descriptor_wire) != array32(encoded, 112)?
            || sha256(inventory_wire) != array32(encoded, 144)?
        {
            return Err(DirectPodDhlIdentityCapsuleError::new(
                "capsule full DHL wire SHA-256 mismatch",
            ));
        }
        let capsule = Self {
            device_id: array16(encoded, 48)?,
            pod_id: array16(encoded, 64)?,
            headstage_id: array16(encoded, 80)?,
            transport_epoch: le_u64(encoded, 96)?,
            descriptor_wire: descriptor_wire.to_vec(),
            inventory_wire: inventory_wire.to_vec(),
        };
        validate_capsule_fields(&capsule)?;
        Ok(capsule)
    }
}

/// Strict, independently bounded outer DHL decoder for capsule Descriptor or
/// Inventory evidence.  It accepts no other DHL packet type.
pub fn decode_dhl_outer_packet_v1(
    wire: &[u8],
    expected_packet_type: u8,
) -> Result<DhlOuterPacketEvidenceV1, DirectPodDhlIdentityCapsuleError> {
    if !matches!(
        expected_packet_type,
        DHL_DESCRIPTOR_TYPE | DHL_INVENTORY_TYPE
    ) {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "DHL identity outer decoder accepts only Descriptor or Inventory",
        ));
    }
    if wire.len() < DHL_HEADER_LEN + 4 {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "DHL wire shorter than header and CRC",
        ));
    }
    let version = wire[0];
    let packet_type = wire[1];
    let flags = le_u16(wire, 2)?;
    let header_len = usize::from(le_u16(wire, 4)?);
    let reserved = le_u16(wire, 6)?;
    let payload_len = usize::try_from(le_u32(wire, 8)?).map_err(|_| {
        DirectPodDhlIdentityCapsuleError::new("DHL payload length does not fit usize")
    })?;
    let total_len = DHL_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| DirectPodDhlIdentityCapsuleError::new("DHL wire length overflow"))?;
    let identity_payload_len_is_exact = match expected_packet_type {
        DHL_DESCRIPTOR_TYPE => {
            wire.len() == DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_DESCRIPTOR_WIRE_LEN
                && payload_len == DHL_DESCRIPTOR_PAYLOAD_LEN
        }
        DHL_INVENTORY_TYPE => {
            wire.len() >= DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_INVENTORY_WIRE_MIN_LEN
                && wire.len() <= DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_INVENTORY_WIRE_MAX_LEN
                && (DHL_INVENTORY_PAYLOAD_MIN_LEN..=DHL_INVENTORY_PAYLOAD_MAX_LEN)
                    .contains(&payload_len)
                && (payload_len - DHL_INVENTORY_PAYLOAD_MIN_LEN).is_multiple_of(32)
        }
        _ => unreachable!("expected type is checked above"),
    };
    if version != 1
        || packet_type != expected_packet_type
        || flags != 0
        || header_len != DHL_HEADER_LEN
        || reserved != 0
        || total_len != wire.len()
        || !identity_payload_len_is_exact
    {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "DHL outer version/type/flags/header/reserved/length is non-canonical",
        ));
    }
    let source_id = le_u32(wire, 12)?;
    let boot_id = le_u64(wire, 16)?;
    let sequence = le_u64(wire, 24)?;
    if source_id == 0 || boot_id == 0 || sequence == u64::MAX {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "DHL outer source/boot is zero or sequence cannot advance",
        ));
    }
    let payload_end = DHL_HEADER_LEN
        .checked_add(payload_len)
        .ok_or_else(|| DirectPodDhlIdentityCapsuleError::new("DHL payload end overflow"))?;
    if le_u32(wire, payload_end)? != crc32c(&wire[..payload_end]) {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "DHL outer CRC32C mismatch",
        ));
    }
    Ok(DhlOuterPacketEvidenceV1 {
        packet_type,
        source_id,
        boot_id,
        sequence,
        timestamp_25mhz: le_u64(wire, 32)?,
        payload: wire[DHL_HEADER_LEN..payload_end].to_vec(),
    })
}

/// Binds capsule evidence to protected context and the existing byte-level DHL
/// identity policy.  A successful result is not Ready/Run/stimulation authority.
pub(crate) fn admit_new_run_dhl_identity_capsule_v1(
    capsule: &DirectPodDhlIdentityCapsuleV1,
    context: &DirectPodDhlIdentityContextV1,
    catalog: &DhlIdentityCatalog,
    policy: &DhlIdentityAdmissionPolicyV1,
) -> Result<AdmittedDirectPodDhlIdentityCapsuleV1, DirectPodDhlIdentityCapsuleError> {
    let packet_pair = validate_capsule_fields(capsule)?;
    validate_context(context)?;
    if capsule.device_id != context.device_id
        || capsule.pod_id != context.pod_id
        || capsule.headstage_id != context.headstage_id
        || capsule.transport_epoch != context.transport_epoch
    {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "capsule identity or transport epoch differs from protected context",
        ));
    }
    if capsule.headstage_id != policy.expected_device_id
        || context.headstage_id != policy.expected_device_id
    {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "capsule/context Headstage ID differs from protected policy device ID",
        ));
    }
    let descriptor = packet_pair.descriptor;
    let inventory = packet_pair.inventory;
    // These public decoders additionally enforce exact internal Descriptor and
    // Inventory layouts before policy admission/hashing.
    let decoded_descriptor = decode_descriptor_payload_v1(&descriptor.payload)?;
    decode_inventory_payload_v1(&inventory.payload)?;
    if decoded_descriptor.device_id != capsule.headstage_id
        || decoded_descriptor.device_id != context.headstage_id
        || decoded_descriptor.device_id != policy.expected_device_id
    {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "Descriptor immutable device ID does not equal capsule/context/policy Headstage ID",
        ));
    }
    let next_sequence = packet_pair.next_sequence;
    let admitted_identity =
        admit_new_run_dhl_identity_v1(&descriptor.payload, &inventory.payload, catalog, policy)?;
    Ok(AdmittedDirectPodDhlIdentityCapsuleV1 {
        admitted_identity,
        source_id: descriptor.source_id,
        boot_id: descriptor.boot_id,
        descriptor_sequence: descriptor.sequence,
        inventory_sequence: inventory.sequence,
        next_sequence,
        descriptor_timestamp_25mhz: descriptor.timestamp_25mhz,
        inventory_timestamp_25mhz: inventory.timestamp_25mhz,
        descriptor_wire_sha256: sha256(&capsule.descriptor_wire),
        inventory_wire_sha256: sha256(&capsule.inventory_wire),
        device_id: capsule.device_id,
        pod_id: capsule.pod_id,
        headstage_id: capsule.headstage_id,
        transport_epoch: capsule.transport_epoch,
    })
}

fn validate_capsule_fields(
    capsule: &DirectPodDhlIdentityCapsuleV1,
) -> Result<DhlIdentityPacketPairV1, DirectPodDhlIdentityCapsuleError> {
    if is_zero(&capsule.device_id)
        || is_zero(&capsule.pod_id)
        || is_zero(&capsule.headstage_id)
        || capsule.transport_epoch == 0
    {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "capsule has zero identity or epoch",
        ));
    }
    if capsule.descriptor_wire.len() != DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_DESCRIPTOR_WIRE_LEN
        || !(DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_INVENTORY_WIRE_MIN_LEN
            ..=DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_INVENTORY_WIRE_MAX_LEN)
            .contains(&capsule.inventory_wire.len())
    {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "capsule embedded wire lengths are invalid",
        ));
    }
    capsule_total_len(capsule.descriptor_wire.len(), capsule.inventory_wire.len())?;
    let descriptor = decode_dhl_outer_packet_v1(&capsule.descriptor_wire, DHL_DESCRIPTOR_TYPE)?;
    let inventory = decode_dhl_outer_packet_v1(&capsule.inventory_wire, DHL_INVENTORY_TYPE)?;
    decode_descriptor_payload_v1(&descriptor.payload)?;
    decode_inventory_payload_v1(&inventory.payload)?;
    let next_sequence = validate_dhl_identity_packet_pair(&descriptor, &inventory)?;
    Ok(DhlIdentityPacketPairV1 {
        descriptor,
        inventory,
        next_sequence,
    })
}

struct DhlIdentityPacketPairV1 {
    descriptor: DhlOuterPacketEvidenceV1,
    inventory: DhlOuterPacketEvidenceV1,
    next_sequence: u64,
}

fn validate_dhl_identity_packet_pair(
    descriptor: &DhlOuterPacketEvidenceV1,
    inventory: &DhlOuterPacketEvidenceV1,
) -> Result<u64, DirectPodDhlIdentityCapsuleError> {
    if descriptor.source_id != inventory.source_id || descriptor.boot_id != inventory.boot_id {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "DHL Descriptor and Inventory source/boot differ",
        ));
    }
    let expected_inventory_sequence = descriptor.sequence.checked_add(1).ok_or_else(|| {
        DirectPodDhlIdentityCapsuleError::new("Descriptor sequence cannot advance to Inventory")
    })?;
    if inventory.sequence != expected_inventory_sequence {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "DHL Inventory sequence is not Descriptor+1",
        ));
    }
    inventory
        .sequence
        .checked_add(1)
        .ok_or_else(|| DirectPodDhlIdentityCapsuleError::new("Inventory sequence cannot advance"))
}

fn validate_context(
    context: &DirectPodDhlIdentityContextV1,
) -> Result<(), DirectPodDhlIdentityCapsuleError> {
    if is_zero(&context.device_id)
        || is_zero(&context.pod_id)
        || is_zero(&context.headstage_id)
        || context.transport_epoch == 0
    {
        return Err(DirectPodDhlIdentityCapsuleError::new(
            "protected context has zero identity or epoch",
        ));
    }
    Ok(())
}

fn capsule_total_len(
    descriptor_len: usize,
    inventory_len: usize,
) -> Result<usize, DirectPodDhlIdentityCapsuleError> {
    DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_HEADER_LEN
        .checked_add(descriptor_len)
        .and_then(|value| value.checked_add(inventory_len))
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| DirectPodDhlIdentityCapsuleError::new("capsule length arithmetic overflow"))
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn array16(bytes: &[u8], offset: usize) -> Result<Id16, DirectPodDhlIdentityCapsuleError> {
    bytes
        .get(
            offset
                ..offset.checked_add(16).ok_or_else(|| {
                    DirectPodDhlIdentityCapsuleError::new("array offset overflow")
                })?,
        )
        .ok_or_else(|| DirectPodDhlIdentityCapsuleError::new("truncated u8[16]"))?
        .try_into()
        .map_err(|_| DirectPodDhlIdentityCapsuleError::new("invalid u8[16]"))
}

fn array32(bytes: &[u8], offset: usize) -> Result<Hash32, DirectPodDhlIdentityCapsuleError> {
    bytes
        .get(
            offset
                ..offset.checked_add(32).ok_or_else(|| {
                    DirectPodDhlIdentityCapsuleError::new("array offset overflow")
                })?,
        )
        .ok_or_else(|| DirectPodDhlIdentityCapsuleError::new("truncated u8[32]"))?
        .try_into()
        .map_err(|_| DirectPodDhlIdentityCapsuleError::new("invalid u8[32]"))
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, DirectPodDhlIdentityCapsuleError> {
    Ok(u16::from_le_bytes(array2(bytes, offset)?))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, DirectPodDhlIdentityCapsuleError> {
    Ok(u32::from_le_bytes(array4(bytes, offset)?))
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64, DirectPodDhlIdentityCapsuleError> {
    Ok(u64::from_le_bytes(array8(bytes, offset)?))
}

fn array2(bytes: &[u8], offset: usize) -> Result<[u8; 2], DirectPodDhlIdentityCapsuleError> {
    read_array(bytes, offset, "u16")
}
fn array4(bytes: &[u8], offset: usize) -> Result<[u8; 4], DirectPodDhlIdentityCapsuleError> {
    read_array(bytes, offset, "u32")
}
fn array8(bytes: &[u8], offset: usize) -> Result<[u8; 8], DirectPodDhlIdentityCapsuleError> {
    read_array(bytes, offset, "u64")
}
fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
    name: &str,
) -> Result<[u8; N], DirectPodDhlIdentityCapsuleError> {
    bytes
        .get(
            offset
                ..offset.checked_add(N).ok_or_else(|| {
                    DirectPodDhlIdentityCapsuleError::new("integer offset overflow")
                })?,
        )
        .ok_or_else(|| DirectPodDhlIdentityCapsuleError::new(format!("truncated {name}")))?
        .try_into()
        .map_err(|_| DirectPodDhlIdentityCapsuleError::new(format!("invalid {name}")))
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhl_identity_admission::{
        sha256_payload, DhlExpectedInstancePolicyV1, DHL_CAP_ELECTRODE_IMPEDANCE,
        DHL_CAP_STREAM_NEURAL,
    };
    use crate::dhl_identity_catalog::{DhlExpectedComponentKind, DhlIdentity};

    const IDL: &str = include_str!("../schema/forge_direct_pod_dhl_identity_capsule_v1.idl");
    const GOLDEN: &str = include_str!("../../protocol/dhl/golden/dhl_v1_vectors.json");

    #[test]
    fn idl_lf_hash_is_frozen_constant() {
        assert!(!IDL.contains('\r'));
        assert_eq!(
            sha256(IDL.as_bytes()),
            DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_CONTRACT_HASH
        );
        assert_eq!(
            hex(&sha256(IDL.as_bytes())),
            DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_CONTRACT_HASH_HEX
        );
    }

    #[test]
    fn checked_in_python_descriptor_golden_decodes_as_complete_outer_packet() {
        let value: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
        let wire = decode_hex(value["descriptor_hex"].as_str().unwrap());
        assert_eq!(wire.len(), 140);
        let packet = decode_dhl_outer_packet_v1(&wire, DHL_DESCRIPTOR_TYPE).unwrap();
        assert_eq!(packet.payload.len(), 96);
        assert_eq!(packet.source_id, 0x1122_3344);
    }

    #[test]
    fn active_capsule_round_trips_and_admits_but_decode_only_rejects() {
        let (catalog, policy, capsule, context) = fixture("rhd2132x1", 7, 8);
        let encoded = capsule.encode().unwrap();
        assert_eq!(encoded.len(), 472);
        let decoded = DirectPodDhlIdentityCapsuleV1::decode(&encoded).unwrap();
        let admitted =
            admit_new_run_dhl_identity_capsule_v1(&decoded, &context, &catalog, &policy).unwrap();
        assert_eq!(admitted.next_sequence, 9);
        assert_eq!(admitted.admitted_identity.profile_id, "rhd2132x1");
        let (catalog, policy, capsule, context) = fixture("rhd2132x2", 7, 8);
        assert!(
            admit_new_run_dhl_identity_capsule_v1(&capsule, &context, &catalog, &policy).is_err()
        );
    }

    #[test]
    fn capsule_and_outer_mutations_fail_closed() {
        let (_catalog, _policy, capsule, _context) = fixture("rhd2132x1", 7, 8);
        let encoded = capsule.encode().unwrap();
        for malformed in [
            encoded[..175].to_vec(),
            {
                let mut v = encoded.clone();
                v[8] = 2;
                v
            },
            {
                let mut v = encoded.clone();
                v[12] = 1;
                v
            },
            {
                let mut v = encoded.clone();
                v[108] = 1;
                v
            },
            {
                let mut v = encoded.clone();
                v[10] = 1;
                v
            },
            {
                let mut v = encoded.clone();
                v[112] ^= 1;
                refresh_capsule_crc(&mut v);
                v
            },
            {
                let mut v = encoded.clone();
                let x = 176 + 140;
                v[x] ^= 1;
                refresh_capsule_crc(&mut v);
                v
            },
            {
                let mut v = encoded.clone();
                let last = v.len() - 1;
                v[last] ^= 1;
                v
            },
        ] {
            assert!(DirectPodDhlIdentityCapsuleV1::decode(&malformed).is_err());
        }
        let mut bad_outer = capsule.descriptor_wire.clone();
        bad_outer[2] = 1;
        refresh_dhl_crc(&mut bad_outer);
        assert!(decode_dhl_outer_packet_v1(&bad_outer, DHL_DESCRIPTOR_TYPE).is_err());
        for offset in [0_usize, 1, 6] {
            let mut malformed = capsule.descriptor_wire.clone();
            malformed[offset] ^= 1;
            refresh_dhl_crc(&mut malformed);
            assert!(decode_dhl_outer_packet_v1(&malformed, DHL_DESCRIPTOR_TYPE).is_err());
        }
        let mut oversized_descriptor = capsule.descriptor_wire.clone();
        oversized_descriptor.push(0);
        assert!(decode_dhl_outer_packet_v1(&oversized_descriptor, DHL_DESCRIPTOR_TYPE).is_err());
        let oversized_inventory =
            vec![0_u8; DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_INVENTORY_WIRE_MAX_LEN + 1];
        assert!(decode_dhl_outer_packet_v1(&oversized_inventory, DHL_INVENTORY_TYPE).is_err());
        let bad_stride = dhl_wire(DHL_INVENTORY_TYPE, 1, 2, 2, 0, &[0; 109]);
        assert!(decode_dhl_outer_packet_v1(&bad_stride, DHL_INVENTORY_TYPE).is_err());
        assert!(decode_dhl_outer_packet_v1(&capsule.descriptor_wire, 2).is_err());
        let mut bad_inner_crc = capsule.inventory_wire.clone();
        let last = bad_inner_crc.len() - 1;
        bad_inner_crc[last] ^= 1;
        assert!(decode_dhl_outer_packet_v1(&bad_inner_crc, DHL_INVENTORY_TYPE).is_err());
    }

    #[test]
    fn context_source_boot_sequence_and_structural_mutations_fail_closed() {
        let (catalog, policy, capsule, context) = fixture("rhd2132x1", 7, 8);
        let mut mismatched_context = context;
        mismatched_context.pod_id[0] ^= 1;
        assert!(admit_new_run_dhl_identity_capsule_v1(
            &capsule,
            &mismatched_context,
            &catalog,
            &policy
        )
        .is_err());
        let mut zero_capsule = capsule.clone();
        zero_capsule.pod_id = [0; 16];
        assert!(
            admit_new_run_dhl_identity_capsule_v1(&zero_capsule, &context, &catalog, &policy)
                .is_err()
        );
        let mut zero_epoch = context;
        zero_epoch.transport_epoch = 0;
        assert!(
            admit_new_run_dhl_identity_capsule_v1(&capsule, &zero_epoch, &catalog, &policy)
                .is_err()
        );
        let mut bad_source = capsule.clone();
        bad_source.inventory_wire[12] ^= 1;
        refresh_dhl_crc(&mut bad_source.inventory_wire);
        assert!(bad_source.encode().is_err());
        assert!(
            admit_new_run_dhl_identity_capsule_v1(&bad_source, &context, &catalog, &policy)
                .is_err()
        );
        let mut bad_boot = capsule.clone();
        bad_boot.inventory_wire[16] ^= 1;
        refresh_dhl_crc(&mut bad_boot.inventory_wire);
        assert!(bad_boot.encode().is_err());
        assert!(
            admit_new_run_dhl_identity_capsule_v1(&bad_boot, &context, &catalog, &policy).is_err()
        );
        let mut gap = capsule.clone();
        gap.inventory_wire[24..32].copy_from_slice(&10_u64.to_le_bytes());
        refresh_dhl_crc(&mut gap.inventory_wire);
        assert!(gap.encode().is_err());
        assert!(admit_new_run_dhl_identity_capsule_v1(&gap, &context, &catalog, &policy).is_err());
        let mut overflow = capsule.clone();
        overflow.descriptor_wire[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        refresh_dhl_crc(&mut overflow.descriptor_wire);
        assert!(overflow.encode().is_err());
        assert!(
            admit_new_run_dhl_identity_capsule_v1(&overflow, &context, &catalog, &policy).is_err()
        );
        // Semantic descriptor mutation with an updated inner CRC is still bound
        // by the protected payload hash policy.
        let mut semantic = capsule.clone();
        semantic.descriptor_wire[116] ^= 1;
        refresh_dhl_crc(&mut semantic.descriptor_wire);
        assert!(
            admit_new_run_dhl_identity_capsule_v1(&semantic, &context, &catalog, &policy).is_err()
        );
    }

    #[test]
    fn inventory_min_and_max_outer_boundaries_are_enforced() {
        let (_, _, min, _) = fixture("rhd2132x1", 1, 2);
        assert_eq!(min.inventory_wire.len(), 152);
        let packet = decode_dhl_outer_packet_v1(&min.inventory_wire, DHL_INVENTORY_TYPE).unwrap();
        assert_eq!(packet.payload.len(), 108);
        let mut payload = packet.payload;
        payload[6..8].copy_from_slice(&16_u16.to_le_bytes());
        payload.resize(588, 0);
        let max = dhl_wire(DHL_INVENTORY_TYPE, 1, 2, 2, 0, &payload);
        assert_eq!(max.len(), 632);
        assert!(decode_dhl_outer_packet_v1(&max, DHL_INVENTORY_TYPE).is_ok());
    }

    fn fixture(
        profile: &str,
        descriptor_sequence: u64,
        inventory_sequence: u64,
    ) -> (
        DhlIdentityCatalog,
        DhlIdentityAdmissionPolicyV1,
        DirectPodDhlIdentityCapsuleV1,
        DirectPodDhlIdentityContextV1,
    ) {
        let catalog = DhlIdentityCatalog::load_embedded().unwrap();
        let identity = catalog.by_profile_id(profile).unwrap();
        let mut policy = policy_for(identity);
        let descriptor_payload = descriptor_payload(identity, &policy);
        let inventory_payload = inventory_payload(identity, &policy);
        policy.expected_descriptor_payload_sha256 = sha256_payload(&descriptor_payload);
        policy.expected_inventory_payload_sha256 = sha256_payload(&inventory_payload);
        let device_id = policy.expected_device_id;
        let capsule = DirectPodDhlIdentityCapsuleV1 {
            device_id,
            pod_id: [0x55; 16],
            headstage_id: device_id,
            transport_epoch: 9,
            descriptor_wire: dhl_wire(
                DHL_DESCRIPTOR_TYPE,
                0x1122_3344,
                77,
                descriptor_sequence,
                1,
                &descriptor_payload,
            ),
            inventory_wire: dhl_wire(
                DHL_INVENTORY_TYPE,
                0x1122_3344,
                77,
                inventory_sequence,
                2,
                &inventory_payload,
            ),
        };
        let context = DirectPodDhlIdentityContextV1 {
            device_id,
            pod_id: [0x55; 16],
            headstage_id: device_id,
            transport_epoch: 9,
        };
        (catalog, policy, capsule, context)
    }

    fn policy_for(identity: &DhlIdentity) -> DhlIdentityAdmissionPolicyV1 {
        let ordered_expected_instances = identity
            .ordered_expected_components
            .iter()
            .map(|component| {
                let exact_capability_flags = match component.kind {
                    DhlExpectedComponentKind::NeuralAfe => match component.model_id {
                        0x0001_0001 | 0x0001_0002 => {
                            DHL_CAP_STREAM_NEURAL | DHL_CAP_ELECTRODE_IMPEDANCE
                        }
                        _ => DHL_CAP_STREAM_NEURAL | (1 << 4),
                    },
                    DhlExpectedComponentKind::Imu => 1 << 1,
                    DhlExpectedComponentKind::ElectrochemAfe => (1 << 2) | (1 << 3),
                };
                DhlExpectedInstancePolicyV1 {
                    instance_id: component.instance_id,
                    exact_driver_abi: 1,
                    exact_capability_flags,
                    config_hash_prefix: [0x44; 12],
                }
            })
            .collect();
        DhlIdentityAdmissionPolicyV1 {
            profile_id: identity.profile_id.clone(),
            expected_descriptor_payload_sha256: [1; 32],
            expected_inventory_payload_sha256: [1; 32],
            expected_device_id: [0x11; 16],
            expected_config_hash: [0x22; 32],
            sample_rate_numerator_hz: 30_000,
            sample_rate_denominator: 1,
            approved_channel_layout_id: 0x1020_3040,
            assembly_manifest_hash: [0x66; 32],
            channel_map_hash: [0x77; 32],
            ordered_expected_instances,
        }
    }

    fn descriptor_payload(
        identity: &DhlIdentity,
        policy: &DhlIdentityAdmissionPolicyV1,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_u16(&mut bytes, 1);
        put_u16(&mut bytes, 96);
        bytes.push(identity.variant);
        bytes.push(identity.chip_count);
        put_u16(&mut bytes, identity.descriptor_feature_flags);
        put_u16(&mut bytes, identity.acquisition_channel_count);
        put_u16(&mut bytes, 1);
        put_u32(&mut bytes, policy.sample_rate_numerator_hz);
        put_u32(&mut bytes, policy.sample_rate_denominator);
        put_u32(&mut bytes, 25_000_000);
        put_u32(&mut bytes, 0);
        bytes.extend_from_slice(&policy.expected_device_id);
        bytes.extend_from_slice(&policy.expected_config_hash);
        bytes.extend_from_slice(&[0x33; 16]);
        put_u32(&mut bytes, 0);
        bytes
    }
    fn inventory_payload(identity: &DhlIdentity, policy: &DhlIdentityAdmissionPolicyV1) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_u16(&mut bytes, 1);
        put_u16(&mut bytes, 76);
        put_u16(&mut bytes, 32);
        put_u16(
            &mut bytes,
            u16::try_from(identity.ordered_expected_components.len()).unwrap(),
        );
        put_u32(&mut bytes, u32::from(identity.board_profile_id));
        bytes.extend_from_slice(&policy.assembly_manifest_hash);
        bytes.extend_from_slice(&policy.channel_map_hash);
        for (component, approved) in identity
            .ordered_expected_components
            .iter()
            .zip(&policy.ordered_expected_instances)
        {
            put_u16(&mut bytes, component.instance_id);
            let class = match component.kind {
                DhlExpectedComponentKind::NeuralAfe => 1,
                DhlExpectedComponentKind::Imu => 2,
                DhlExpectedComponentKind::ElectrochemAfe => 3,
            };
            bytes.push(class);
            bytes.push(2);
            put_u32(&mut bytes, component.model_id);
            if component.kind == DhlExpectedComponentKind::NeuralAfe {
                put_u16(&mut bytes, component.first_global_channel.unwrap());
                put_u16(&mut bytes, component.channel_count);
                put_u16(&mut bytes, component.native_first_channel.unwrap());
            } else {
                put_u16(&mut bytes, u16::MAX);
                put_u16(&mut bytes, 0);
                put_u16(&mut bytes, 0);
            }
            put_u16(&mut bytes, approved.exact_driver_abi);
            put_u32(&mut bytes, approved.exact_capability_flags);
            bytes.extend_from_slice(&approved.config_hash_prefix);
        }
        bytes
    }
    fn dhl_wire(
        packet_type: u8,
        source: u32,
        boot: u64,
        sequence: u64,
        timestamp: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.push(1);
        wire.push(packet_type);
        put_u16(&mut wire, 0);
        put_u16(&mut wire, 40);
        put_u16(&mut wire, 0);
        put_u32(&mut wire, u32::try_from(payload.len()).unwrap());
        put_u32(&mut wire, source);
        put_u64(&mut wire, boot);
        put_u64(&mut wire, sequence);
        put_u64(&mut wire, timestamp);
        wire.extend_from_slice(payload);
        let wire_crc = crc32c(&wire);
        put_u32(&mut wire, wire_crc);
        wire
    }
    fn refresh_dhl_crc(wire: &mut [u8]) {
        let crc_offset = wire.len() - 4;
        let crc = crc32c(&wire[..crc_offset]);
        wire[crc_offset..].copy_from_slice(&crc.to_le_bytes());
    }
    fn refresh_capsule_crc(wire: &mut [u8]) {
        let crc_offset = wire.len() - 4;
        let crc = crc32c(&wire[..crc_offset]);
        wire[crc_offset..].copy_from_slice(&crc.to_le_bytes());
    }
    fn decode_hex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
            .collect()
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
