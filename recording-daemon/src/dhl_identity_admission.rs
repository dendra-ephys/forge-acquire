//! Byte-level DHL Descriptor and Inventory identity admission.
//!
//! This is a pure, fail-closed identity boundary.  It deliberately does not
//! consume a Direct-Pod byte stream, assert Ready, open a D3XX device, or grant
//! Run/stimulation authority.  A future protected deployment/Arm layer must
//! supply [`DhlIdentityAdmissionPolicyV1`] from an authenticated source.

use std::error::Error;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::dhl_identity_catalog::{
    DhlExpectedComponent, DhlExpectedComponentKind, DhlIdentity, DhlIdentityCatalog,
};

const DESCRIPTOR_LEN: usize = 96;
const INVENTORY_HEADER_LEN: usize = 76;
const INVENTORY_ENTRY_LEN: usize = 32;
const INVENTORY_MIN_ENTRIES: usize = 1;
const INVENTORY_MAX_ENTRIES: usize = 16;

const DESCRIPTOR_VERSION: u16 = 1;
const INVENTORY_VERSION: u16 = 1;
const SAMPLE_FORMAT_SIGNED_I16_LE: u16 = 1;
const TIMEBASE_HZ: u32 = 25_000_000;

const COMPONENT_CLASS_NEURAL_AFE: u8 = 1;
const COMPONENT_CLASS_IMU: u8 = 2;
const COMPONENT_CLASS_ELECTROCHEM_AFE: u8 = 3;
const COMPONENT_STATUS_DETECTED_READY: u8 = 2;
const NON_NEURAL_FIRST_GLOBAL: u16 = u16::MAX;

const MODEL_RHD2132: u32 = 0x0001_0001;
const MODEL_RHD2164: u32 = 0x0001_0002;
const MODEL_RHS2116: u32 = 0x0001_0003;

/// Component capability: continuous Neural sample stream.
pub const DHL_CAP_STREAM_NEURAL: u32 = 1 << 0;
/// Component capability: IMU stream.
pub const DHL_CAP_STREAM_IMU: u32 = 1 << 1;
/// Component capability: amperometry.
pub const DHL_CAP_AMPEROMETRY: u32 = 1 << 2;
/// Component capability: FSCV.
pub const DHL_CAP_FSCV: u32 = 1 << 3;
/// Component capability: stimulation.
pub const DHL_CAP_STIMULATION: u32 = 1 << 4;
/// Component capability: RHD electrode impedance diagnostic.
pub const DHL_CAP_ELECTRODE_IMPEDANCE: u32 = 1 << 5;

const DHL_CAPABILITY_MASK: u32 = DHL_CAP_STREAM_NEURAL
    | DHL_CAP_STREAM_IMU
    | DHL_CAP_AMPEROMETRY
    | DHL_CAP_FSCV
    | DHL_CAP_STIMULATION
    | DHL_CAP_ELECTRODE_IMPEDANCE;

const FEATURE_ELECTROCHEM: u16 = 1;
const FEATURE_IMU: u16 = 2;
const FEATURE_RHS_STIMULATION: u16 = 4;
const FEATURE_MASK: u16 = FEATURE_ELECTROCHEM | FEATURE_IMU | FEATURE_RHS_STIMULATION;

/// The four catalog-bound Descriptor fields which identify a DHL assembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DhlDescriptorTupleV1 {
    pub variant: u8,
    pub chip_count: u8,
    pub feature_flags: u16,
    pub channel_count: u16,
}

/// Strictly decoded Descriptor payload fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhlDescriptorPayloadV1 {
    pub tuple: DhlDescriptorTupleV1,
    pub sample_format: u16,
    pub sample_rate_numerator_hz: u32,
    pub sample_rate_denominator: u32,
    pub timestamp_frequency_hz: u32,
    pub device_id: [u8; 16],
    pub config_hash: [u8; 32],
    pub firmware_hash_prefix: [u8; 16],
}

/// One strictly decoded Inventory component entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhlInventoryEntryV1 {
    pub instance_id: u16,
    pub component_class: u8,
    pub status: u8,
    pub model_id: u32,
    pub first_global_channel: u16,
    pub channel_count: u16,
    pub native_channel_base: u16,
    pub driver_abi: u16,
    pub capability_flags: u32,
    pub config_hash_prefix: [u8; 12],
}

/// Strictly decoded Inventory header and its ordered entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhlInventoryPayloadV1 {
    pub board_profile_id: u32,
    pub assembly_manifest_hash: [u8; 32],
    pub channel_map_hash: [u8; 32],
    pub entries: Vec<DhlInventoryEntryV1>,
}

/// Per-instance approval fields that intentionally do not belong in the decode catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhlExpectedInstancePolicyV1 {
    pub instance_id: u16,
    pub exact_driver_abi: u16,
    pub exact_capability_flags: u32,
    pub config_hash_prefix: [u8; 12],
}

/// Protected input required before a decoded DHL identity may be used for a new Run.
///
/// `instance_id == 0` is deliberately legal: the checked-in catalog assigns it
/// to U300.  Every nonzero/opaque identity and every hash/rate/layout below is
/// checked explicitly rather than inferred from a first device observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhlIdentityAdmissionPolicyV1 {
    pub profile_id: String,
    pub expected_descriptor_payload_sha256: [u8; 32],
    pub expected_inventory_payload_sha256: [u8; 32],
    pub expected_device_id: [u8; 16],
    pub expected_config_hash: [u8; 32],
    pub sample_rate_numerator_hz: u32,
    pub sample_rate_denominator: u32,
    /// Protected Host layout identity. This is deliberately independent of
    /// the DHL board profile ID and must never be derived from it.
    pub approved_channel_layout_id: u32,
    pub assembly_manifest_hash: [u8; 32],
    pub channel_map_hash: [u8; 32],
    pub ordered_expected_instances: Vec<DhlExpectedInstancePolicyV1>,
}

/// Owned identity result.  Admission means exact byte-level identity/policy
/// matching only; it must never be displayed as hardware Ready.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedDhlIdentityV1 {
    /// Normalized catalog identity retained at admission time; consumers must
    /// not need to re-query a potentially different catalog view.
    pub identity: DhlIdentity,
    pub profile_id: String,
    pub descriptor: DhlDescriptorPayloadV1,
    pub inventory: DhlInventoryPayloadV1,
    pub descriptor_payload_sha256: [u8; 32],
    pub inventory_payload_sha256: [u8; 32],
    pub assembly_manifest_hash: [u8; 32],
    pub channel_map_hash: [u8; 32],
    pub approved_device_id: [u8; 16],
    pub approved_config_hash: [u8; 32],
    pub approved_sample_rate_numerator_hz: u32,
    pub approved_sample_rate_denominator: u32,
    pub approved_channel_layout_id: u32,
    pub parsed_entries: Vec<DhlInventoryEntryV1>,
}

/// Contextual, fail-closed admission error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhlIdentityAdmissionError(String);

impl DhlIdentityAdmissionError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for DhlIdentityAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for DhlIdentityAdmissionError {}

/// Decodes the exact 96-byte little-endian Descriptor payload.
pub fn decode_descriptor_payload_v1(
    payload: &[u8],
) -> Result<DhlDescriptorPayloadV1, DhlIdentityAdmissionError> {
    if payload.len() != DESCRIPTOR_LEN {
        return Err(DhlIdentityAdmissionError::new(format!(
            "Descriptor payload length is {}, expected {DESCRIPTOR_LEN}",
            payload.len()
        )));
    }
    let version = read_u16(payload, 0, "Descriptor version")?;
    let length = read_u16(payload, 2, "Descriptor length")?;
    let sample_format = read_u16(payload, 10, "Descriptor sample format")?;
    let timestamp_frequency_hz = read_u32(payload, 20, "Descriptor timestamp frequency")?;
    let reserved0 = read_u32(payload, 24, "Descriptor reserved0")?;
    let reserved1 = read_u32(payload, 92, "Descriptor reserved1")?;
    if version != DESCRIPTOR_VERSION
        || length != DESCRIPTOR_LEN as u16
        || sample_format != SAMPLE_FORMAT_SIGNED_I16_LE
        || timestamp_frequency_hz != TIMEBASE_HZ
        || reserved0 != 0
        || reserved1 != 0
    {
        return Err(DhlIdentityAdmissionError::new(format!(
            "non-canonical Descriptor header: version={version}, length={length}, format={sample_format}, timebase={timestamp_frequency_hz}, reserved0={reserved0}, reserved1={reserved1}"
        )));
    }
    Ok(DhlDescriptorPayloadV1 {
        tuple: DhlDescriptorTupleV1 {
            variant: read_u8(payload, 4, "Descriptor variant")?,
            chip_count: read_u8(payload, 5, "Descriptor chip count")?,
            feature_flags: read_u16(payload, 6, "Descriptor feature flags")?,
            channel_count: read_u16(payload, 8, "Descriptor channel count")?,
        },
        sample_format,
        sample_rate_numerator_hz: read_u32(payload, 12, "Descriptor rate numerator")?,
        sample_rate_denominator: read_u32(payload, 16, "Descriptor rate denominator")?,
        timestamp_frequency_hz,
        device_id: read_array(payload, 28, "Descriptor device ID")?,
        config_hash: read_array(payload, 44, "Descriptor config hash")?,
        firmware_hash_prefix: read_array(payload, 76, "Descriptor firmware hash prefix")?,
    })
}

/// Decodes the exact `76 + 32*n` little-endian Inventory payload, for `n=1..16`.
pub fn decode_inventory_payload_v1(
    payload: &[u8],
) -> Result<DhlInventoryPayloadV1, DhlIdentityAdmissionError> {
    if payload.len() < INVENTORY_HEADER_LEN {
        return Err(DhlIdentityAdmissionError::new(format!(
            "Inventory payload length is {}, below header length {INVENTORY_HEADER_LEN}",
            payload.len()
        )));
    }
    let version = read_u16(payload, 0, "Inventory version")?;
    let header_length = read_u16(payload, 2, "Inventory header length")?;
    let entry_size = read_u16(payload, 4, "Inventory entry size")?;
    let entry_count = usize::from(read_u16(payload, 6, "Inventory entry count")?);
    let expected_length = INVENTORY_ENTRY_LEN
        .checked_mul(entry_count)
        .and_then(|entries_len| INVENTORY_HEADER_LEN.checked_add(entries_len))
        .ok_or_else(|| DhlIdentityAdmissionError::new("Inventory length arithmetic overflow"))?;
    if version != INVENTORY_VERSION
        || header_length != INVENTORY_HEADER_LEN as u16
        || entry_size != INVENTORY_ENTRY_LEN as u16
        || !(INVENTORY_MIN_ENTRIES..=INVENTORY_MAX_ENTRIES).contains(&entry_count)
        || payload.len() != expected_length
    {
        return Err(DhlIdentityAdmissionError::new(format!(
            "non-canonical Inventory header or length: version={version}, header_length={header_length}, entry_size={entry_size}, entry_count={entry_count}, payload_length={}, expected_length={expected_length}",
            payload.len()
        )));
    }
    let mut entries = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let offset =
            INVENTORY_HEADER_LEN
                .checked_add(index.checked_mul(INVENTORY_ENTRY_LEN).ok_or_else(|| {
                    DhlIdentityAdmissionError::new("Inventory entry offset overflow")
                })?)
                .ok_or_else(|| DhlIdentityAdmissionError::new("Inventory entry offset overflow"))?;
        entries.push(DhlInventoryEntryV1 {
            instance_id: read_u16(payload, offset, "Inventory instance ID")?,
            component_class: read_u8(payload, offset + 2, "Inventory component class")?,
            status: read_u8(payload, offset + 3, "Inventory component status")?,
            model_id: read_u32(payload, offset + 4, "Inventory model ID")?,
            first_global_channel: read_u16(payload, offset + 8, "Inventory first global channel")?,
            channel_count: read_u16(payload, offset + 10, "Inventory channel count")?,
            native_channel_base: read_u16(payload, offset + 12, "Inventory native channel base")?,
            driver_abi: read_u16(payload, offset + 14, "Inventory driver ABI")?,
            capability_flags: read_u32(payload, offset + 16, "Inventory capabilities")?,
            config_hash_prefix: read_array(payload, offset + 20, "Inventory config hash prefix")?,
        });
    }
    Ok(DhlInventoryPayloadV1 {
        board_profile_id: read_u32(payload, 8, "Inventory board profile")?,
        assembly_manifest_hash: read_array(payload, 12, "Inventory assembly manifest hash")?,
        channel_map_hash: read_array(payload, 44, "Inventory channel map hash")?,
        entries,
    })
}

/// SHA-256 of the raw payload bytes, never of a reconstructed DHL packet.
pub fn sha256_payload(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

/// Validates protected policy values against the embedded-catalog view without
/// reading any untrusted Descriptor or Inventory payload bytes.
///
/// The returned owned identity is a catalog classification only.  It is not a
/// wire admission, transport Ready state, D3XX receipt, or stimulation grant.
pub fn validate_dhl_identity_admission_policy_v1(
    catalog: &DhlIdentityCatalog,
    policy: &DhlIdentityAdmissionPolicyV1,
) -> Result<DhlIdentity, DhlIdentityAdmissionError> {
    let identity = catalog.by_profile_id(&policy.profile_id).ok_or_else(|| {
        DhlIdentityAdmissionError::new(format!(
            "policy profile_id {:?} is absent from the validated DHL catalog",
            policy.profile_id
        ))
    })?;
    validate_policy(policy, identity)?;
    if identity.catalog_status == crate::dhl_identity_catalog::CatalogStatus::DecodeOnly {
        return Err(DhlIdentityAdmissionError::new(format!(
            "catalog profile {} is decode-only and cannot admit a new Run",
            identity.profile_id
        )));
    }
    if !identity.graph_closed {
        return Err(DhlIdentityAdmissionError::new(format!(
            "catalog profile {} has graph_closed=false and cannot admit a new Run",
            identity.profile_id
        )));
    }
    if !identity.is_new_run_catalog_eligible() {
        return Err(DhlIdentityAdmissionError::new(format!(
            "catalog profile {} is not eligible for a new Run",
            identity.profile_id
        )));
    }
    Ok(identity.clone())
}

/// Admits a new-run DHL identity against a validated catalog and protected policy.
pub fn admit_new_run_dhl_identity_v1(
    raw_descriptor_payload: &[u8],
    raw_inventory_payload: &[u8],
    catalog: &DhlIdentityCatalog,
    policy: &DhlIdentityAdmissionPolicyV1,
) -> Result<AdmittedDhlIdentityV1, DhlIdentityAdmissionError> {
    let descriptor = decode_descriptor_payload_v1(raw_descriptor_payload)?;
    let inventory = decode_inventory_payload_v1(raw_inventory_payload)?;
    // Decode first so the fixed 96-byte Descriptor and bounded 1..16-entry
    // Inventory limits reject oversized untrusted inputs before hashing them.
    let descriptor_payload_sha256 = sha256_payload(raw_descriptor_payload);
    let inventory_payload_sha256 = sha256_payload(raw_inventory_payload);

    let identity = validate_dhl_identity_admission_policy_v1(catalog, policy)?;
    if descriptor_payload_sha256 != policy.expected_descriptor_payload_sha256
        || inventory_payload_sha256 != policy.expected_inventory_payload_sha256
    {
        return Err(DhlIdentityAdmissionError::new(
            "raw Descriptor or Inventory payload SHA-256 differs from protected policy",
        ));
    }
    validate_descriptor(&descriptor, &identity, policy)?;
    validate_inventory(&inventory, &descriptor, &identity, policy)?;

    Ok(AdmittedDhlIdentityV1 {
        identity: identity.clone(),
        profile_id: identity.profile_id.clone(),
        descriptor: descriptor.clone(),
        inventory: inventory.clone(),
        descriptor_payload_sha256,
        inventory_payload_sha256,
        assembly_manifest_hash: inventory.assembly_manifest_hash,
        channel_map_hash: inventory.channel_map_hash,
        approved_device_id: policy.expected_device_id,
        approved_config_hash: policy.expected_config_hash,
        approved_sample_rate_numerator_hz: policy.sample_rate_numerator_hz,
        approved_sample_rate_denominator: policy.sample_rate_denominator,
        approved_channel_layout_id: policy.approved_channel_layout_id,
        parsed_entries: inventory.entries,
    })
}

fn validate_policy(
    policy: &DhlIdentityAdmissionPolicyV1,
    identity: &DhlIdentity,
) -> Result<(), DhlIdentityAdmissionError> {
    if policy.profile_id.is_empty()
        || !nonzero(&policy.expected_descriptor_payload_sha256)
        || !nonzero(&policy.expected_inventory_payload_sha256)
        || !nonzero(&policy.expected_device_id)
        || !nonzero(&policy.expected_config_hash)
        || policy.sample_rate_numerator_hz == 0
        || policy.sample_rate_denominator == 0
        || policy.approved_channel_layout_id == 0
        || !nonzero(&policy.assembly_manifest_hash)
        || !nonzero(&policy.channel_map_hash)
    {
        return Err(DhlIdentityAdmissionError::new(
            "policy has an empty profile ID or a zero identity/hash/rate/layout field",
        ));
    }
    if policy.ordered_expected_instances.len() != identity.ordered_expected_components.len() {
        return Err(DhlIdentityAdmissionError::new(format!(
            "policy has {} instance approvals, catalog profile {} requires {}",
            policy.ordered_expected_instances.len(),
            identity.profile_id,
            identity.ordered_expected_components.len()
        )));
    }
    let expected_ids = identity
        .ordered_expected_components
        .iter()
        .map(|component| component.instance_id);
    if policy
        .ordered_expected_instances
        .iter()
        .map(|instance| instance.instance_id)
        .ne(expected_ids)
    {
        return Err(DhlIdentityAdmissionError::new(format!(
            "policy instance IDs do not exactly equal catalog profile {}",
            identity.profile_id
        )));
    }
    if policy
        .ordered_expected_instances
        .windows(2)
        .any(|pair| pair[0].instance_id >= pair[1].instance_id)
    {
        return Err(DhlIdentityAdmissionError::new(
            "policy instance IDs are not strictly ascending",
        ));
    }
    for (component, instance) in identity
        .ordered_expected_components
        .iter()
        .zip(&policy.ordered_expected_instances)
    {
        if instance.exact_driver_abi != 1 || !nonzero(&instance.config_hash_prefix) {
            return Err(DhlIdentityAdmissionError::new(format!(
                "policy instance {} has non-v1 driver ABI or a zero config-hash prefix",
                instance.instance_id
            )));
        }
        validate_capability_semantics(component, instance.exact_capability_flags).map_err(
            |message| {
                DhlIdentityAdmissionError::new(format!(
                    "policy instance {}: {message}",
                    instance.instance_id
                ))
            },
        )?;
    }
    Ok(())
}

fn validate_descriptor(
    descriptor: &DhlDescriptorPayloadV1,
    identity: &DhlIdentity,
    policy: &DhlIdentityAdmissionPolicyV1,
) -> Result<(), DhlIdentityAdmissionError> {
    if descriptor.tuple.variant != identity.variant
        || descriptor.tuple.chip_count != identity.chip_count
        || descriptor.tuple.feature_flags != identity.descriptor_feature_flags
        || descriptor.tuple.channel_count != identity.acquisition_channel_count
        || descriptor.tuple.feature_flags & !FEATURE_MASK != 0
    {
        return Err(DhlIdentityAdmissionError::new(format!(
            "Descriptor tuple {:?} does not exactly select catalog profile {}",
            descriptor.tuple, identity.profile_id
        )));
    }
    if descriptor.sample_rate_numerator_hz == 0
        || descriptor.sample_rate_denominator == 0
        || descriptor.sample_rate_numerator_hz != policy.sample_rate_numerator_hz
        || descriptor.sample_rate_denominator != policy.sample_rate_denominator
    {
        return Err(DhlIdentityAdmissionError::new(
            "Descriptor rational sample rate differs from protected policy",
        ));
    }
    if !nonzero(&descriptor.device_id)
        || descriptor.device_id != policy.expected_device_id
        || !nonzero(&descriptor.config_hash)
        || descriptor.config_hash != policy.expected_config_hash
        || !nonzero(&descriptor.firmware_hash_prefix)
    {
        return Err(DhlIdentityAdmissionError::new(
            "Descriptor device/config/firmware identity differs from protected policy or is zero",
        ));
    }
    Ok(())
}

fn validate_inventory(
    inventory: &DhlInventoryPayloadV1,
    descriptor: &DhlDescriptorPayloadV1,
    identity: &DhlIdentity,
    policy: &DhlIdentityAdmissionPolicyV1,
) -> Result<(), DhlIdentityAdmissionError> {
    if inventory.board_profile_id != u32::from(identity.board_profile_id)
        || !nonzero(&inventory.assembly_manifest_hash)
        || inventory.assembly_manifest_hash != policy.assembly_manifest_hash
        || !nonzero(&inventory.channel_map_hash)
        || inventory.channel_map_hash != policy.channel_map_hash
    {
        return Err(DhlIdentityAdmissionError::new(
            "Inventory board ID or assembly/channel-map hash differs from protected policy",
        ));
    }
    if inventory.entries.len() != identity.ordered_expected_components.len()
        || inventory.entries.len() != policy.ordered_expected_instances.len()
    {
        return Err(DhlIdentityAdmissionError::new(
            "Inventory entry count differs from the catalog/policy exact set",
        ));
    }
    let mut previous_id = None;
    let mut feature_flags = 0_u16;
    for ((entry, component), approved) in inventory
        .entries
        .iter()
        .zip(&identity.ordered_expected_components)
        .zip(&policy.ordered_expected_instances)
    {
        if previous_id.is_some_and(|previous| previous >= entry.instance_id) {
            return Err(DhlIdentityAdmissionError::new(
                "Inventory instance IDs are not strictly ordered and unique",
            ));
        }
        previous_id = Some(entry.instance_id);
        validate_entry(entry, component, approved)?;
        if entry.component_class == COMPONENT_CLASS_IMU {
            feature_flags |= FEATURE_IMU;
        } else if entry.component_class == COMPONENT_CLASS_ELECTROCHEM_AFE {
            feature_flags |= FEATURE_ELECTROCHEM;
        } else if entry.model_id == MODEL_RHS2116 {
            feature_flags |= FEATURE_RHS_STIMULATION;
        }
    }
    if feature_flags != descriptor.tuple.feature_flags
        || feature_flags != identity.descriptor_feature_flags
    {
        return Err(DhlIdentityAdmissionError::new(format!(
            "Inventory-derived feature flags {feature_flags:#x} differ from Descriptor/catalog"
        )));
    }
    Ok(())
}

fn validate_entry(
    entry: &DhlInventoryEntryV1,
    component: &DhlExpectedComponent,
    approved: &DhlExpectedInstancePolicyV1,
) -> Result<(), DhlIdentityAdmissionError> {
    let expected_class = class_for_kind(component.kind);
    if entry.instance_id != component.instance_id
        || entry.instance_id != approved.instance_id
        || entry.component_class != expected_class
        || entry.model_id != component.model_id
        || entry.status != COMPONENT_STATUS_DETECTED_READY
    {
        return Err(DhlIdentityAdmissionError::new(format!(
            "Inventory entry {} differs from required ID/class/model/status",
            entry.instance_id
        )));
    }
    match component.kind {
        DhlExpectedComponentKind::NeuralAfe => {
            if entry.first_global_channel != component.first_global_channel.unwrap_or(u16::MAX)
                || entry.channel_count != component.channel_count
                || entry.native_channel_base != component.native_first_channel.unwrap_or(u16::MAX)
            {
                return Err(DhlIdentityAdmissionError::new(format!(
                    "Inventory neural entry {} has wrong channel range",
                    entry.instance_id
                )));
            }
        }
        DhlExpectedComponentKind::Imu | DhlExpectedComponentKind::ElectrochemAfe => {
            if entry.first_global_channel != NON_NEURAL_FIRST_GLOBAL
                || entry.channel_count != 0
                || entry.native_channel_base != 0
            {
                return Err(DhlIdentityAdmissionError::new(format!(
                    "Inventory optional entry {} has a Neural channel range",
                    entry.instance_id
                )));
            }
        }
    }
    if entry.driver_abi != approved.exact_driver_abi
        || entry.capability_flags != approved.exact_capability_flags
        || entry.config_hash_prefix != approved.config_hash_prefix
        || !nonzero(&entry.config_hash_prefix)
    {
        return Err(DhlIdentityAdmissionError::new(format!(
            "Inventory entry {} ABI/capabilities/config prefix differs from policy",
            entry.instance_id
        )));
    }
    validate_capability_semantics(component, entry.capability_flags).map_err(|message| {
        DhlIdentityAdmissionError::new(format!("Inventory entry {}: {message}", entry.instance_id))
    })
}

fn validate_capability_semantics(
    component: &DhlExpectedComponent,
    capabilities: u32,
) -> Result<(), &'static str> {
    if capabilities & !DHL_CAPABILITY_MASK != 0 {
        return Err("capabilities contain reserved bits");
    }
    match component.kind {
        DhlExpectedComponentKind::NeuralAfe => {
            if capabilities & DHL_CAP_STREAM_NEURAL == 0 {
                return Err("Neural AFE lacks STREAM_NEURAL");
            }
            match component.model_id {
                MODEL_RHD2132 | MODEL_RHD2164 => {
                    if capabilities & DHL_CAP_STIMULATION != 0 {
                        return Err("RHD AFE advertises forbidden STIMULATION");
                    }
                    if capabilities & DHL_CAP_ELECTRODE_IMPEDANCE == 0 {
                        return Err("RHD AFE lacks ELECTRODE_IMPEDANCE");
                    }
                }
                MODEL_RHS2116 => {
                    // Match the Python codec's minimum/forbidden semantics:
                    // RHS requires STIMULATION but may carry other known bits.
                    if capabilities & DHL_CAP_STIMULATION == 0 {
                        return Err("RHS2116 lacks STIMULATION");
                    }
                }
                _ => return Err("Neural AFE has an unknown model"),
            }
        }
        DhlExpectedComponentKind::Imu => {
            if capabilities != DHL_CAP_STREAM_IMU {
                return Err("IMU capabilities are not exactly STREAM_IMU");
            }
        }
        DhlExpectedComponentKind::ElectrochemAfe => {
            if capabilities != DHL_CAP_AMPEROMETRY | DHL_CAP_FSCV {
                return Err("electrochem capabilities are not exactly AMPEROMETRY|FSCV");
            }
        }
    }
    Ok(())
}

fn class_for_kind(kind: DhlExpectedComponentKind) -> u8 {
    match kind {
        DhlExpectedComponentKind::NeuralAfe => COMPONENT_CLASS_NEURAL_AFE,
        DhlExpectedComponentKind::Imu => COMPONENT_CLASS_IMU,
        DhlExpectedComponentKind::ElectrochemAfe => COMPONENT_CLASS_ELECTROCHEM_AFE,
    }
}

fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

fn read_u8(payload: &[u8], offset: usize, field: &str) -> Result<u8, DhlIdentityAdmissionError> {
    payload
        .get(offset)
        .copied()
        .ok_or_else(|| DhlIdentityAdmissionError::new(format!("{field} is truncated")))
}

fn read_u16(payload: &[u8], offset: usize, field: &str) -> Result<u16, DhlIdentityAdmissionError> {
    Ok(u16::from_le_bytes(read_array(payload, offset, field)?))
}

fn read_u32(payload: &[u8], offset: usize, field: &str) -> Result<u32, DhlIdentityAdmissionError> {
    Ok(u32::from_le_bytes(read_array(payload, offset, field)?))
}

fn read_array<const N: usize>(
    payload: &[u8],
    offset: usize,
    field: &str,
) -> Result<[u8; N], DhlIdentityAdmissionError> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| DhlIdentityAdmissionError::new(format!("{field} offset overflow")))?;
    let bytes = payload
        .get(offset..end)
        .ok_or_else(|| DhlIdentityAdmissionError::new(format!("{field} is truncated")))?;
    bytes
        .try_into()
        .map_err(|_| DhlIdentityAdmissionError::new(format!("{field} has wrong width")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DHL_V1_VECTORS_JSON: &str =
        include_str!("../../protocol/dhl/golden/dhl_v1_vectors.json");

    fn policy_for(identity: &DhlIdentity) -> DhlIdentityAdmissionPolicyV1 {
        DhlIdentityAdmissionPolicyV1 {
            profile_id: identity.profile_id.clone(),
            expected_descriptor_payload_sha256: [0; 32],
            expected_inventory_payload_sha256: [0; 32],
            expected_device_id: [0x11; 16],
            expected_config_hash: [0x22; 32],
            sample_rate_numerator_hz: 30_000,
            sample_rate_denominator: 1,
            approved_channel_layout_id: 0x1020_3040,
            assembly_manifest_hash: [0x44; 32],
            channel_map_hash: [0x55; 32],
            ordered_expected_instances: identity
                .ordered_expected_components
                .iter()
                .map(|component| DhlExpectedInstancePolicyV1 {
                    instance_id: component.instance_id,
                    exact_driver_abi: 1,
                    exact_capability_flags: capability_for(component),
                    config_hash_prefix: [component.instance_id as u8 + 1; 12],
                })
                .collect(),
        }
    }

    fn capability_for(component: &DhlExpectedComponent) -> u32 {
        match component.kind {
            DhlExpectedComponentKind::Imu => DHL_CAP_STREAM_IMU,
            DhlExpectedComponentKind::ElectrochemAfe => DHL_CAP_AMPEROMETRY | DHL_CAP_FSCV,
            DhlExpectedComponentKind::NeuralAfe => match component.model_id {
                MODEL_RHD2132 | MODEL_RHD2164 => {
                    DHL_CAP_STREAM_NEURAL | DHL_CAP_ELECTRODE_IMPEDANCE
                }
                MODEL_RHS2116 => DHL_CAP_STREAM_NEURAL | DHL_CAP_STIMULATION,
                _ => unreachable!("catalog only exposes known Neural models"),
            },
        }
    }

    fn descriptor_bytes(identity: &DhlIdentity, policy: &DhlIdentityAdmissionPolicyV1) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DESCRIPTOR_LEN);
        push_u16(&mut bytes, 1);
        push_u16(&mut bytes, DESCRIPTOR_LEN as u16);
        bytes.push(identity.variant);
        bytes.push(identity.chip_count);
        push_u16(&mut bytes, identity.descriptor_feature_flags);
        push_u16(&mut bytes, identity.acquisition_channel_count);
        push_u16(&mut bytes, SAMPLE_FORMAT_SIGNED_I16_LE);
        push_u32(&mut bytes, policy.sample_rate_numerator_hz);
        push_u32(&mut bytes, policy.sample_rate_denominator);
        push_u32(&mut bytes, TIMEBASE_HZ);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(&policy.expected_device_id);
        bytes.extend_from_slice(&policy.expected_config_hash);
        bytes.extend_from_slice(&[0x33; 16]);
        push_u32(&mut bytes, 0);
        assert_eq!(bytes.len(), DESCRIPTOR_LEN);
        bytes
    }

    fn inventory_bytes(identity: &DhlIdentity, policy: &DhlIdentityAdmissionPolicyV1) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            INVENTORY_HEADER_LEN + INVENTORY_ENTRY_LEN * identity.ordered_expected_components.len(),
        );
        push_u16(&mut bytes, INVENTORY_VERSION);
        push_u16(&mut bytes, INVENTORY_HEADER_LEN as u16);
        push_u16(&mut bytes, INVENTORY_ENTRY_LEN as u16);
        push_u16(
            &mut bytes,
            u16::try_from(identity.ordered_expected_components.len()).unwrap(),
        );
        push_u32(&mut bytes, u32::from(identity.board_profile_id));
        bytes.extend_from_slice(&policy.assembly_manifest_hash);
        bytes.extend_from_slice(&policy.channel_map_hash);
        for (component, approved) in identity
            .ordered_expected_components
            .iter()
            .zip(&policy.ordered_expected_instances)
        {
            push_u16(&mut bytes, component.instance_id);
            bytes.push(class_for_kind(component.kind));
            bytes.push(COMPONENT_STATUS_DETECTED_READY);
            push_u32(&mut bytes, component.model_id);
            match component.kind {
                DhlExpectedComponentKind::NeuralAfe => {
                    push_u16(&mut bytes, component.first_global_channel.unwrap());
                    push_u16(&mut bytes, component.channel_count);
                    push_u16(&mut bytes, component.native_first_channel.unwrap());
                }
                DhlExpectedComponentKind::Imu | DhlExpectedComponentKind::ElectrochemAfe => {
                    push_u16(&mut bytes, NON_NEURAL_FIRST_GLOBAL);
                    push_u16(&mut bytes, 0);
                    push_u16(&mut bytes, 0);
                }
            }
            push_u16(&mut bytes, approved.exact_driver_abi);
            push_u32(&mut bytes, approved.exact_capability_flags);
            bytes.extend_from_slice(&approved.config_hash_prefix);
        }
        bytes
    }

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn exact_inputs(
        profile_id: &str,
    ) -> (
        DhlIdentityCatalog,
        DhlIdentityAdmissionPolicyV1,
        Vec<u8>,
        Vec<u8>,
    ) {
        let catalog = DhlIdentityCatalog::load_embedded().unwrap();
        let identity = catalog.by_profile_id(profile_id).unwrap();
        let (policy, descriptor, inventory) = bound_policy_and_payload(identity);
        (catalog, policy, descriptor, inventory)
    }

    fn bound_policy_and_payload(
        identity: &DhlIdentity,
    ) -> (DhlIdentityAdmissionPolicyV1, Vec<u8>, Vec<u8>) {
        let mut policy = policy_for(identity);
        let descriptor = descriptor_bytes(identity, &policy);
        let inventory = inventory_bytes(identity, &policy);
        policy.expected_descriptor_payload_sha256 = sha256_payload(&descriptor);
        policy.expected_inventory_payload_sha256 = sha256_payload(&inventory);
        (policy, descriptor, inventory)
    }

    #[test]
    fn admits_only_closed_non_decode_catalog_identities() {
        let catalog = DhlIdentityCatalog::load_embedded().unwrap();
        assert_eq!(catalog.identities().len(), 14);
        for identity in catalog.identities() {
            let (policy, descriptor, inventory) = bound_policy_and_payload(identity);
            let decoded = decode_descriptor_payload_v1(&descriptor).unwrap();
            assert_eq!(decoded.tuple.variant, identity.variant);
            let admission =
                admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy);
            if identity.is_new_run_catalog_eligible() {
                let admitted =
                    admission.unwrap_or_else(|error| panic!("{}: {error}", identity.profile_id));
                assert_eq!(admitted.identity, *identity);
                assert_eq!(admitted.approved_channel_layout_id, 0x1020_3040);
                assert_ne!(
                    admitted.approved_channel_layout_id,
                    u32::from(identity.board_profile_id)
                );
                assert_eq!(
                    admitted.identity.ordered_expected_components,
                    identity.ordered_expected_components
                );
            } else if identity.catalog_status
                == crate::dhl_identity_catalog::CatalogStatus::DecodeOnly
            {
                assert_eq!(identity.profile_id, "rhd2132x2");
                assert!(admission.unwrap_err().to_string().contains("decode-only"));
            } else {
                assert!(!identity.graph_closed);
                assert!(admission
                    .unwrap_err()
                    .to_string()
                    .contains("graph_closed=false"));
            }
        }
    }

    #[test]
    fn decodes_checked_in_descriptor_packet_payload_fixture() {
        let vectors: serde_json::Value = serde_json::from_str(DHL_V1_VECTORS_JSON).unwrap();
        let packet = decode_hex(vectors["descriptor_hex"].as_str().unwrap());
        assert_eq!(packet.len(), 140);
        let descriptor = decode_descriptor_payload_v1(&packet[40..136]).unwrap();
        assert_eq!(descriptor.sample_format, SAMPLE_FORMAT_SIGNED_I16_LE);
        assert_eq!(descriptor.timestamp_frequency_hz, TIMEBASE_HZ);
    }

    #[test]
    fn decoders_reject_all_fixed_layout_mismatches() {
        let (_catalog, _policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        for malformed in [
            descriptor[..95].to_vec(),
            {
                let mut value = descriptor.clone();
                value.push(0);
                value
            },
            mutate(&descriptor, 0, 2),
            mutate(&descriptor, 2, 95),
            mutate(&descriptor, 10, 2),
            mutate(&descriptor, 20, 1),
            mutate(&descriptor, 24, 1),
            mutate(&descriptor, 92, 1),
        ] {
            assert!(decode_descriptor_payload_v1(&malformed).is_err());
        }
        for malformed in [
            inventory[..75].to_vec(),
            mutate(&inventory, 0, 2),
            mutate(&inventory, 2, 75),
            mutate(&inventory, 4, 31),
            mutate(&inventory, 6, 0),
            {
                let mut value = inventory.clone();
                value[6..8].copy_from_slice(&17_u16.to_le_bytes());
                value.resize(INVENTORY_HEADER_LEN + INVENTORY_ENTRY_LEN * 17, 0);
                value
            },
        ] {
            assert!(decode_inventory_payload_v1(&malformed).is_err());
        }
    }

    #[test]
    fn admission_rejects_descriptor_identity_and_rate_mutations() {
        let (catalog, policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        for malformed in [
            mutate(&descriptor, 4, 9),
            mutate(&descriptor, 6, 0x80),
            mutate(&descriptor, 12, 1),
            zero_range(&descriptor, 28, 16),
            mutate(&descriptor, 28, 0x99),
            zero_range(&descriptor, 44, 32),
            mutate(&descriptor, 44, 0x99),
            zero_range(&descriptor, 76, 16),
        ] {
            assert!(
                admit_new_run_dhl_identity_v1(&malformed, &inventory, &catalog, &policy).is_err()
            );
        }
        let mut unknown_policy = policy.clone();
        unknown_policy.profile_id = "unknown-profile".into();
        assert!(
            admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &unknown_policy)
                .is_err()
        );
    }

    #[test]
    fn rhs2116x2_imu_tuple_is_admitted_but_an_adjacent_tuple_is_not() {
        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhs2116x2_imu");
        let admitted =
            admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).unwrap();
        assert_eq!(
            (
                admitted.descriptor.tuple.variant,
                admitted.descriptor.tuple.chip_count,
                admitted.descriptor.tuple.feature_flags,
                admitted.descriptor.tuple.channel_count,
            ),
            (3, 2, 6, 32)
        );
        assert_eq!(admitted.identity.profile_id, "rhs2116x2_imu");

        let mut adjacent = descriptor;
        adjacent[6..8].copy_from_slice(&2_u16.to_le_bytes());
        policy.expected_descriptor_payload_sha256 = sha256_payload(&adjacent);
        let error = admit_new_run_dhl_identity_v1(&adjacent, &inventory, &catalog, &policy)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Descriptor tuple"), "{error}");
    }

    #[test]
    fn admission_rejects_inventory_policy_and_entry_mutations() {
        let (catalog, policy, descriptor, inventory) = exact_inputs("rhd2132x1_imu_echem");
        let entry0 = INVENTORY_HEADER_LEN;
        let entry1 = entry0 + INVENTORY_ENTRY_LEN;
        let entry2 = entry1 + INVENTORY_ENTRY_LEN;
        let malformed_cases = [
            mutate(&inventory, 8, 9),
            zero_range(&inventory, 12, 32),
            mutate(&inventory, 44, 0x88),
            mutate(&inventory, entry0 + 2, COMPONENT_CLASS_IMU),
            mutate(&inventory, entry0 + 4, 0x99),
            mutate(&inventory, entry0 + 8, 1),
            mutate(&inventory, entry0 + 12, 1),
            mutate(&inventory, entry0 + 3, 3),
            mutate(&inventory, entry0 + 14, 2),
            mutate(&inventory, entry0 + 16, 0x80),
            zero_range(&inventory, entry0 + 20, 12),
            {
                let mut value = inventory.clone();
                value[entry1..entry1 + 2].copy_from_slice(&0_u16.to_le_bytes());
                value
            },
            {
                let mut value = inventory.clone();
                value[entry1..entry1 + 2].copy_from_slice(&1_u16.to_le_bytes());
                value
            },
            {
                let mut value = inventory.clone();
                value[entry1..entry1 + INVENTORY_ENTRY_LEN]
                    .copy_from_slice(&inventory[entry2..entry2 + INVENTORY_ENTRY_LEN]);
                value
            },
            {
                let mut value = inventory.clone();
                value.truncate(INVENTORY_HEADER_LEN + 2 * INVENTORY_ENTRY_LEN);
                value[6..8].copy_from_slice(&2_u16.to_le_bytes());
                value
            },
        ];
        for malformed in malformed_cases {
            assert!(
                admit_new_run_dhl_identity_v1(&descriptor, &malformed, &catalog, &policy).is_err()
            );
        }
    }

    #[test]
    fn mixed_order_optional_geometry_and_payload_hashes_are_bound() {
        let (catalog, policy, descriptor, inventory) = exact_inputs("rhd2132x1_imu_echem");
        let admitted =
            admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).unwrap();
        let mut descriptor_mutation = descriptor.clone();
        descriptor_mutation[28] ^= 1;
        let mut inventory_mutation = inventory.clone();
        inventory_mutation[INVENTORY_HEADER_LEN + 4] ^= 1;
        assert_ne!(
            admitted.descriptor_payload_sha256,
            sha256_payload(&descriptor_mutation)
        );
        assert_ne!(
            admitted.inventory_payload_sha256,
            sha256_payload(&inventory_mutation)
        );
        assert!(
            admit_new_run_dhl_identity_v1(&descriptor_mutation, &inventory, &catalog, &policy)
                .is_err()
        );
        assert!(
            admit_new_run_dhl_identity_v1(&descriptor, &inventory_mutation, &catalog, &policy)
                .is_err()
        );
        let mut wrong_mixed_model_order = inventory.clone();
        let first_model =
            wrong_mixed_model_order[INVENTORY_HEADER_LEN + 4..INVENTORY_HEADER_LEN + 8].to_vec();
        let second_entry = INVENTORY_HEADER_LEN + INVENTORY_ENTRY_LEN;
        let second_model = wrong_mixed_model_order[second_entry + 4..second_entry + 8].to_vec();
        wrong_mixed_model_order[INVENTORY_HEADER_LEN + 4..INVENTORY_HEADER_LEN + 8]
            .copy_from_slice(&second_model);
        wrong_mixed_model_order[second_entry + 4..second_entry + 8].copy_from_slice(&first_model);
        assert!(admit_new_run_dhl_identity_v1(
            &descriptor,
            &wrong_mixed_model_order,
            &catalog,
            &policy
        )
        .is_err());

        let (catalog, policy, descriptor, inventory) = exact_inputs("rhd2132x1_imu");
        let optional = INVENTORY_HEADER_LEN + INVENTORY_ENTRY_LEN;
        let mut optional_range = inventory.clone();
        optional_range[optional + 8..optional + 10].copy_from_slice(&0_u16.to_le_bytes());
        assert!(
            admit_new_run_dhl_identity_v1(&descriptor, &optional_range, &catalog, &policy).is_err()
        );
    }

    #[test]
    fn policy_capability_semantics_are_fail_closed() {
        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        policy.ordered_expected_instances[0].exact_capability_flags = DHL_CAP_STREAM_NEURAL;
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());

        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhs2116x1");
        policy.ordered_expected_instances[0].exact_capability_flags = DHL_CAP_STREAM_NEURAL;
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());

        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhd2132x1_imu");
        policy.ordered_expected_instances[1].exact_capability_flags =
            DHL_CAP_STREAM_IMU | DHL_CAP_FSCV;
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());
    }

    #[test]
    fn policy_requires_exact_nonzero_approved_values() {
        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        policy.approved_channel_layout_id = 0;
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());

        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        policy.ordered_expected_instances[0].exact_driver_abi = 2;
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());

        let (catalog, mut policy, descriptor, mut inventory) = exact_inputs("rhd2132x1");
        policy.ordered_expected_instances[0].exact_driver_abi = 2;
        inventory[INVENTORY_HEADER_LEN + 14..INVENTORY_HEADER_LEN + 16]
            .copy_from_slice(&2_u16.to_le_bytes());
        policy.expected_inventory_payload_sha256 = sha256_payload(&inventory);
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());

        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        policy.ordered_expected_instances[0].exact_capability_flags =
            DHL_CAP_STREAM_NEURAL | DHL_CAP_STREAM_IMU | DHL_CAP_ELECTRODE_IMPEDANCE;
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());

        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        policy.expected_device_id = [0x66; 16];
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());

        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        policy.ordered_expected_instances[0].config_hash_prefix = [0x77; 12];
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());

        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        policy.ordered_expected_instances[0].instance_id = 1;
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());

        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        policy.expected_descriptor_payload_sha256 = [0; 32];
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());

        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        policy.expected_descriptor_payload_sha256 = [0x88; 32];
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());

        let (catalog, mut policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        policy.expected_inventory_payload_sha256 = [0x99; 32];
        assert!(admit_new_run_dhl_identity_v1(&descriptor, &inventory, &catalog, &policy).is_err());
    }

    #[test]
    fn raw_payload_hash_binding_rejects_a_semantically_valid_firmware_mutation() {
        let (catalog, policy, descriptor, inventory) = exact_inputs("rhd2132x1");
        let mut mutated_descriptor = descriptor.clone();
        mutated_descriptor[76] ^= 1;
        assert!(nonzero(&mutated_descriptor[76..92]));
        let error =
            admit_new_run_dhl_identity_v1(&mutated_descriptor, &inventory, &catalog, &policy)
                .unwrap_err()
                .to_string();
        assert!(error.contains("raw Descriptor or Inventory payload SHA-256"));
    }

    fn mutate(bytes: &[u8], offset: usize, replacement: u8) -> Vec<u8> {
        let mut value = bytes.to_vec();
        value[offset] = replacement;
        value
    }

    fn zero_range(bytes: &[u8], offset: usize, len: usize) -> Vec<u8> {
        let mut value = bytes.to_vec();
        value[offset..offset + len].fill(0);
        value
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
            .collect()
    }
}
