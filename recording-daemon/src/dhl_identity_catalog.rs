//! Fail-closed DHL Headstage identity catalog.
//!
//! This module validates the checked-in machine-readable component inventory and
//! channel geometry before exposing a normalized identity.  It intentionally
//! does not decode Descriptor or Inventory wire bytes, bind bootstrap admission,
//! or make any FT601/D3XX/HIL readiness claim.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const COMPONENT_INVENTORY_PROFILES_JSON: &str =
    include_str!("../../../headstage/firmware/component_inventory_profiles.json");
const CHANNEL_MAPS_V1_JSON: &str = include_str!("../../../protocol/channel_maps_v1.json");
const HEADSTAGE_PRODUCT_MATRIX_JSON: &str =
    include_str!("../../../headstage/docs/headstage_product_matrix_v1.json");

/// Domain separation for the exact three checked-in catalog source files.
///
/// The byte lengths and labels make this a structured hash, rather than an
/// ambiguous hash of concatenated JSON text.
const CATALOG_SOURCE_BUNDLE_DOMAIN: &[u8] = b"FORGE-DHL-IDENTITY-CATALOG-SOURCES-V1\0";
const CATALOG_SOURCE_COMPONENT_INVENTORY_LABEL: &[u8] = b"component_inventory_profiles\0";
const CATALOG_SOURCE_CHANNEL_MAPS_LABEL: &[u8] = b"channel_maps_v1\0";
const CATALOG_SOURCE_PRODUCT_MATRIX_LABEL: &[u8] = b"headstage_product_matrix_v1\0";

/// Frozen SHA-256 of the embedded-source bundle.  Update only together with a
/// reviewed change to one of the three authoritative source files and its
/// protected deployment policy.
pub const DHL_IDENTITY_CATALOG_SOURCE_BUNDLE_SHA256_HEX: &str =
    "70ea69199e9ee5b8850c3261432b3b27cd3b1f7b764b13528845230ae08a1ea0";

/// SHA-256 evidence for the three exact `include_str!` source byte strings.
///
/// This binds the deployed catalog policy to source text; it is not a signing,
/// hardware-attestation, asset, or physical-readiness claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DhlIdentityCatalogSourceHashesV1 {
    pub component_inventory_sha256: [u8; 32],
    pub channel_maps_sha256: [u8; 32],
    pub product_matrix_sha256: [u8; 32],
    pub bundle_sha256: [u8; 32],
}

/// Hashes the exact checked-in source bytes compiled into `load_embedded()`.
pub fn embedded_source_hashes_v1() -> DhlIdentityCatalogSourceHashesV1 {
    source_hashes_v1(
        COMPONENT_INVENTORY_PROFILES_JSON.as_bytes(),
        CHANNEL_MAPS_V1_JSON.as_bytes(),
        HEADSTAGE_PRODUCT_MATRIX_JSON.as_bytes(),
    )
}

fn source_hashes_v1(
    component_inventory: &[u8],
    channel_maps: &[u8],
    product_matrix: &[u8],
) -> DhlIdentityCatalogSourceHashesV1 {
    let component_inventory_sha256 = Sha256::digest(component_inventory).into();
    let channel_maps_sha256 = Sha256::digest(channel_maps).into();
    let product_matrix_sha256 = Sha256::digest(product_matrix).into();
    let mut bundle = Sha256::new();
    bundle.update(CATALOG_SOURCE_BUNDLE_DOMAIN);
    for (label, bytes) in [
        (
            CATALOG_SOURCE_COMPONENT_INVENTORY_LABEL,
            component_inventory,
        ),
        (CATALOG_SOURCE_CHANNEL_MAPS_LABEL, channel_maps),
        (CATALOG_SOURCE_PRODUCT_MATRIX_LABEL, product_matrix),
    ] {
        bundle.update(label);
        bundle.update((bytes.len() as u64).to_le_bytes());
        bundle.update(bytes);
    }
    DhlIdentityCatalogSourceHashesV1 {
        component_inventory_sha256,
        channel_maps_sha256,
        product_matrix_sha256,
        bundle_sha256: bundle.finalize().into(),
    }
}

const FEATURE_ELECTROCHEM: u16 = 1;
const FEATURE_IMU: u16 = 2;
const FEATURE_RHS_STIMULATION: u16 = 4;
const FEATURE_MASK: u16 = FEATURE_ELECTROCHEM | FEATURE_IMU | FEATURE_RHS_STIMULATION;

/// The catalog classification; this is not an admission or hardware receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum CatalogStatus {
    ActiveProduct,
    ActiveOption,
    DecodeOnly,
}

/// Whether a catalog identity may be selected for a new Run.
///
/// This deliberately says nothing about deployment, device, transport, safety,
/// or stimulation authorization; those remain separate fail-closed gates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NewRunCatalogAvailability {
    Eligible,
    GraphOpen,
    DecodeOnly,
}

/// Component class relevant to identity matching, not a runtime capability grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DhlExpectedComponentKind {
    NeuralAfe,
    Imu,
    ElectrochemAfe,
}

/// One expected component for a normalized DHL identity.
///
/// Optional components have no Neural channel range, so their global/native
/// first-channel fields are `None` and their `channel_count` is zero. This
/// intentionally omits driver ABI, capabilities, status, and sample rate: the
/// three catalog inputs do not establish those wire-level values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhlExpectedComponent {
    pub instance_id: u16,
    pub reference: String,
    pub model_id: u32,
    pub kind: DhlExpectedComponentKind,
    pub first_global_channel: Option<u16>,
    pub channel_count: u16,
    pub native_first_channel: Option<u16>,
}

/// Stable, cross-language-checker-friendly identity view derived from three
/// authoritative machine-readable JSON files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhlIdentity {
    pub profile_id: String,
    pub board_profile_id: u16,
    pub variant: u8,
    pub chip_count: u8,
    pub acquisition_channel_count: u16,
    pub descriptor_feature_flags: u16,
    pub ordered_expected_instance_ids: Vec<u16>,
    pub ordered_expected_components: Vec<DhlExpectedComponent>,
    pub catalog_status: CatalogStatus,
    /// Electrical graph status only; it is not a device, transport, Run, or
    /// stimulation receipt.
    pub graph_closed: bool,
    pub new_run_catalog_availability: NewRunCatalogAvailability,
}

impl DhlIdentity {
    pub fn is_new_run_catalog_eligible(&self) -> bool {
        self.new_run_catalog_availability == NewRunCatalogAvailability::Eligible
    }
}

/// Validated DHL identities and the reusable eight-profile board geometry.
#[derive(Clone, Debug)]
pub struct DhlIdentityCatalog {
    identities_by_profile_id: BTreeMap<String, DhlIdentity>,
    identities_by_board_profile_id: BTreeMap<u16, Vec<DhlIdentity>>,
}

impl DhlIdentityCatalog {
    /// Loads the checked-in JSON inputs compiled into this crate.
    pub fn load_embedded() -> Result<Self, DhlIdentityCatalogError> {
        Self::from_json(
            COMPONENT_INVENTORY_PROFILES_JSON,
            CHANNEL_MAPS_V1_JSON,
            HEADSTAGE_PRODUCT_MATRIX_JSON,
        )
    }

    /// Strictly parses and cross-validates external copies of the authoritative
    /// JSON schemas. This is public so a future cross-language checker can use
    /// the same normalization without depending on fragile TypeScript parsing.
    pub fn from_json(
        component_inventory_profiles_json: &str,
        channel_maps_json: &str,
        headstage_product_matrix_json: &str,
    ) -> Result<Self, DhlIdentityCatalogError> {
        let inventory: ComponentInventoryProfiles =
            serde_json::from_str(component_inventory_profiles_json).map_err(|error| {
                DhlIdentityCatalogError::new(format!(
                    "component inventory profiles JSON is invalid or has an unknown field: {error}"
                ))
            })?;
        let channel_maps: ChannelMaps =
            serde_json::from_str(channel_maps_json).map_err(|error| {
                DhlIdentityCatalogError::new(format!(
                    "channel maps JSON is invalid or has an unknown field: {error}"
                ))
            })?;
        let product_matrix: HeadstageProductMatrix =
            serde_json::from_str(headstage_product_matrix_json).map_err(|error| {
                DhlIdentityCatalogError::new(format!(
                    "headstage product matrix JSON is invalid or has an unknown field: {error}"
                ))
            })?;
        validate_catalog(inventory, channel_maps, product_matrix)
    }

    pub fn by_profile_id(&self, profile_id: &str) -> Option<&DhlIdentity> {
        self.identities_by_profile_id.get(profile_id)
    }

    /// Returns every product/option/decode-only identity sharing a base board geometry.
    pub fn by_board_profile_id(&self, board_profile_id: u16) -> Option<&[DhlIdentity]> {
        self.identities_by_board_profile_id
            .get(&board_profile_id)
            .map(Vec::as_slice)
    }

    pub fn identities(&self) -> impl ExactSizeIterator<Item = &DhlIdentity> {
        self.identities_by_profile_id.values()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhlIdentityCatalogError(String);

impl DhlIdentityCatalogError {
    fn new(message: String) -> Self {
        Self(message)
    }
}

impl fmt::Display for DhlIdentityCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for DhlIdentityCatalogError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentInventoryProfiles {
    schema_version: u16,
    contract: String,
    channel_contract: String,
    instance_order: String,
    vstim_profile_contract: VstimProfileContract,
    profiles: Vec<BaseProfile>,
    assemblies: Vec<Assembly>,
    optional_components: Vec<OptionalComponent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VstimProfileContract {
    none: u8,
    bipolar_7v: u8,
    bipolar_22v5: u8,
    reserved_unassigned: Vec<VstimProfile>,
    admission: String,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
enum VstimProfile {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "bipolar_7v")]
    Bipolar7v,
    #[serde(rename = "bipolar_22v5")]
    Bipolar22v5,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseProfile {
    id: u16,
    name: String,
    variant: u8,
    components: Vec<InventoryComponent>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryComponent {
    instance_id: u16,
    reference: String,
    model_id: u32,
    first_global_channel: u16,
    channel_count: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assembly {
    name: String,
    board_profile_id: u16,
    descriptor_feature_flags: u16,
    vstim_profile: VstimProfile,
    expected_instance_ids: Vec<u16>,
    #[serde(default)]
    status: Option<AssemblyStatus>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum AssemblyStatus {
    DecodeOnly,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionalComponent {
    instance_id: u16,
    reference: String,
    model_id: u32,
    class: String,
    neural_channels: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelMaps {
    schema_version: u16,
    neural_vector_order: String,
    profiles: BTreeMap<String, ChannelMapProfile>,
    physical_connector_maps: BTreeMap<String, PhysicalConnectorMap>,
    physical_maps_open_for: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelMapProfile {
    board_profile_id: u16,
    instances: Vec<ChannelMapInstance>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelMapInstance {
    instance_id: u16,
    reference: String,
    model: String,
    global_first: u16,
    native_first: u16,
    count: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhysicalConnectorMap {
    profile: String,
    global_channel_to_contact: Vec<u16>,
    reference_contact: u16,
    ground_contacts: Vec<u16>,
    #[serde(default)]
    electrochem_contacts: Option<BTreeMap<String, u16>>,
    #[serde(default)]
    reserved_contacts: Option<Vec<u16>>,
    #[serde(default)]
    activation_status: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadstageProductMatrix {
    schema_version: u16,
    decision: String,
    status: String,
    imu_policy: String,
    decode_only_profiles: Vec<String>,
    products: Vec<ProductMatrixProduct>,
    mixed_50p_contract: Mixed50pContract,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductMatrixProduct {
    name: String,
    neural: Vec<String>,
    channels: u16,
    echem: bool,
    stim: bool,
    connector: Option<String>,
    #[serde(default)]
    minimum_signal_contacts: Option<u16>,
    graph_closed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mixed50pContract {
    mpn: String,
    contacts: u16,
    rhd2132_channels: [u16; 2],
    rhs2116_channels: [u16; 2],
    shared_reference_contact: u16,
    ground_contact: u16,
    exact_ecad_status: String,
    mechanical_note: String,
}

fn validate_catalog(
    inventory: ComponentInventoryProfiles,
    channel_maps: ChannelMaps,
    product_matrix: HeadstageProductMatrix,
) -> Result<DhlIdentityCatalog, DhlIdentityCatalogError> {
    if inventory.schema_version != 1
        || inventory.contract != "Forge/protocol/DHL_V1.md#component-inventory-payload"
        || inventory.channel_contract != "Forge/protocol/CHANNEL_MAP_V1.md"
        || inventory.instance_order != "formal SKiDL reference order: U300, then U301"
    {
        return Err(DhlIdentityCatalogError::new(
            "component inventory profiles has an unsupported schema or contract".into(),
        ));
    }
    let vstim = &inventory.vstim_profile_contract;
    if vstim.none != 0
        || vstim.bipolar_7v != 1
        || vstim.bipolar_22v5 != 2
        || vstim.reserved_unassigned.as_slice() != [VstimProfile::Bipolar22v5]
        || vstim.admission
            != "exact assembly name, board profile, and admitted manifest; descriptor stimulation bit alone is insufficient"
    {
        return Err(DhlIdentityCatalogError::new(
            "component inventory VSTIM profile contract is unsupported".into(),
        ));
    }
    if channel_maps.schema_version != 1
        || channel_maps.neural_vector_order != "sample-major; global channel ascending"
    {
        return Err(DhlIdentityCatalogError::new(
            "channel maps has an unsupported schema or vector order".into(),
        ));
    }
    if inventory.profiles.len() != 8 || inventory.assemblies.len() != 14 {
        return Err(DhlIdentityCatalogError::new(format!(
            "expected exactly 8 base profiles and 14 assemblies, got {} and {}",
            inventory.profiles.len(),
            inventory.assemblies.len()
        )));
    }

    validate_optional_components(&inventory.optional_components)?;
    validate_physical_map_references(&channel_maps, &inventory.profiles)?;

    let mut profiles_by_id = BTreeMap::new();
    let mut profile_names = BTreeSet::new();
    for profile in &inventory.profiles {
        if !(1..=8).contains(&profile.id) {
            return Err(DhlIdentityCatalogError::new(format!(
                "base profile {} has invalid board_profile_id {}",
                profile.name, profile.id
            )));
        }
        if profile.name.is_empty() || !profile_names.insert(profile.name.as_str()) {
            return Err(DhlIdentityCatalogError::new(format!(
                "base profile name is empty or duplicated: {:?}",
                profile.name
            )));
        }
        if profiles_by_id.insert(profile.id, profile).is_some() {
            return Err(DhlIdentityCatalogError::new(format!(
                "duplicate base board_profile_id {}",
                profile.id
            )));
        }
        validate_base_profile(profile)?;
    }
    if profiles_by_id.len() != 8 || channel_maps.profiles.len() != 8 {
        return Err(DhlIdentityCatalogError::new(format!(
            "expected 8 unique base profiles and 8 channel maps, got {} and {}",
            profiles_by_id.len(),
            channel_maps.profiles.len()
        )));
    }
    for profile in profiles_by_id.values() {
        let map = channel_maps.profiles.get(&profile.name).ok_or_else(|| {
            DhlIdentityCatalogError::new(format!(
                "missing channel map for base profile {}",
                profile.name
            ))
        })?;
        validate_geometry(profile, map)?;
    }
    for map_name in channel_maps.profiles.keys() {
        if !profile_names.contains(map_name.as_str()) {
            return Err(DhlIdentityCatalogError::new(format!(
                "channel map {} has no component inventory base profile",
                map_name
            )));
        }
    }
    let catalog_state_by_profile_id =
        validate_product_matrix(&product_matrix, &inventory.assemblies, &profiles_by_id)?;

    let mut identities_by_profile_id = BTreeMap::new();
    let mut identities_by_board_profile_id: BTreeMap<u16, Vec<DhlIdentity>> = BTreeMap::new();
    let mut active_product_count = 0;
    let mut active_option_count = 0;
    let mut decode_only_count = 0;
    for assembly in inventory.assemblies {
        if assembly.name.is_empty() {
            return Err(DhlIdentityCatalogError::new(
                "assembly profile_id is empty".into(),
            ));
        }
        let base = *profiles_by_id
            .get(&assembly.board_profile_id)
            .ok_or_else(|| {
                DhlIdentityCatalogError::new(format!(
                    "assembly {} references invalid board_profile_id {}",
                    assembly.name, assembly.board_profile_id
                ))
            })?;
        validate_assembly(&assembly, base, &inventory.optional_components)?;
        let channel_map = channel_maps.profiles.get(&base.name).ok_or_else(|| {
            DhlIdentityCatalogError::new(format!(
                "assembly {} has no validated channel map for base profile {}",
                assembly.name, base.name
            ))
        })?;
        let ordered_expected_components = normalized_expected_components(
            &assembly,
            base,
            channel_map,
            &inventory.optional_components,
        )?;
        if ordered_expected_components
            .iter()
            .map(|component| component.instance_id)
            .collect::<Vec<_>>()
            != assembly.expected_instance_ids
        {
            return Err(DhlIdentityCatalogError::new(format!(
                "assembly {} expected component view does not match expected instance IDs",
                assembly.name
            )));
        }
        let catalog_state = catalog_state_by_profile_id
            .get(&assembly.name)
            .expect("product-matrix validation covers every assembly");
        let new_run_catalog_availability = match catalog_state.status {
            CatalogStatus::DecodeOnly => NewRunCatalogAvailability::DecodeOnly,
            CatalogStatus::ActiveProduct | CatalogStatus::ActiveOption => {
                if catalog_state.graph_closed {
                    NewRunCatalogAvailability::Eligible
                } else {
                    NewRunCatalogAvailability::GraphOpen
                }
            }
        };
        match catalog_state.status {
            CatalogStatus::ActiveProduct => active_product_count += 1,
            CatalogStatus::ActiveOption => active_option_count += 1,
            CatalogStatus::DecodeOnly => decode_only_count += 1,
        }
        let identity = DhlIdentity {
            profile_id: assembly.name.clone(),
            board_profile_id: assembly.board_profile_id,
            variant: base.variant,
            chip_count: u8::try_from(base.components.len()).map_err(|_| {
                DhlIdentityCatalogError::new(format!(
                    "assembly {} chip count does not fit u8",
                    assembly.name
                ))
            })?,
            acquisition_channel_count: total_channels(&base.components, &base.name)?,
            descriptor_feature_flags: assembly.descriptor_feature_flags,
            ordered_expected_instance_ids: assembly.expected_instance_ids,
            ordered_expected_components,
            catalog_status: catalog_state.status,
            graph_closed: catalog_state.graph_closed,
            new_run_catalog_availability,
        };
        if identities_by_profile_id
            .insert(identity.profile_id.clone(), identity.clone())
            .is_some()
        {
            return Err(DhlIdentityCatalogError::new(format!(
                "duplicate assembly profile_id {}",
                identity.profile_id
            )));
        }
        identities_by_board_profile_id
            .entry(identity.board_profile_id)
            .or_default()
            .push(identity);
    }
    if active_product_count != 10 || active_option_count != 3 || decode_only_count != 1 {
        return Err(DhlIdentityCatalogError::new(format!(
            "catalog status distribution must be 10 active_product, 3 active_option, 1 decode_only; got {active_product_count}, {active_option_count}, {decode_only_count}"
        )));
    }
    for identities in identities_by_board_profile_id.values_mut() {
        identities.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
    }
    Ok(DhlIdentityCatalog {
        identities_by_profile_id,
        identities_by_board_profile_id,
    })
}

fn validate_optional_components(
    optional_components: &[OptionalComponent],
) -> Result<(), DhlIdentityCatalogError> {
    if optional_components.len() != 2 {
        return Err(DhlIdentityCatalogError::new(format!(
            "expected exactly 2 optional components, got {}",
            optional_components.len()
        )));
    }
    let expected = [
        (100, "U500", 131_073, "imu"),
        (101, "U600", 196_609, "electrochem_afe"),
    ];
    for (component, (instance_id, reference, model_id, class)) in
        optional_components.iter().zip(expected)
    {
        if component.instance_id != instance_id
            || component.reference != reference
            || component.model_id != model_id
            || component.class != class
            || component.neural_channels != 0
        {
            return Err(DhlIdentityCatalogError::new(format!(
                "optional component {} is not the canonical {} {} identity",
                component.instance_id, instance_id, reference
            )));
        }
    }
    Ok(())
}

fn validate_physical_map_references(
    channel_maps: &ChannelMaps,
    base_profiles: &[BaseProfile],
) -> Result<(), DhlIdentityCatalogError> {
    let base_names: BTreeSet<&str> = base_profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect();
    for (map_name, map) in &channel_maps.physical_connector_maps {
        if !base_names.contains(map.profile.as_str())
            || map.global_channel_to_contact.is_empty()
            || map.reference_contact == 0
            || map.ground_contacts.is_empty()
            || map.global_channel_to_contact.contains(&0)
            || map.ground_contacts.contains(&0)
        {
            return Err(DhlIdentityCatalogError::new(format!(
                "physical connector map {map_name} is malformed or references an unknown profile"
            )));
        }
        if let Some(contacts) = &map.electrochem_contacts {
            if contacts.is_empty() || contacts.values().any(|contact| *contact == 0) {
                return Err(DhlIdentityCatalogError::new(format!(
                    "physical connector map {map_name} has invalid electrochem contacts"
                )));
            }
        }
        if let Some(contacts) = &map.reserved_contacts {
            if contacts.contains(&0) {
                return Err(DhlIdentityCatalogError::new(format!(
                    "physical connector map {map_name} has invalid reserved contacts"
                )));
            }
        }
        if let Some(status) = &map.activation_status {
            if status.is_empty() {
                return Err(DhlIdentityCatalogError::new(format!(
                    "physical connector map {map_name} has an empty activation status"
                )));
            }
        }
    }
    for profile_name in &channel_maps.physical_maps_open_for {
        if !base_names.contains(profile_name.as_str()) {
            return Err(DhlIdentityCatalogError::new(format!(
                "physical_maps_open_for references unknown profile {profile_name}"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CatalogAssemblyState {
    status: CatalogStatus,
    graph_closed: bool,
}

fn validate_product_matrix(
    matrix: &HeadstageProductMatrix,
    assemblies: &[Assembly],
    profiles_by_id: &BTreeMap<u16, &BaseProfile>,
) -> Result<BTreeMap<String, CatalogAssemblyState>, DhlIdentityCatalogError> {
    if matrix.schema_version != 1
        || matrix.decision != "DEC-HEADSTAGE-003"
        || matrix.status != "ten_product_identities_frozen_individual_release_gates_open"
        || matrix.imu_policy != "orthogonal_dnp_option_not_a_neural_profile"
        || matrix.products.len() != 10
        || matrix.decode_only_profiles.len() != 1
    {
        return Err(DhlIdentityCatalogError::new(
            "headstage product matrix has an unsupported schema or catalog contract".into(),
        ));
    }
    let contract = &matrix.mixed_50p_contract;
    if contract.mpn != "5033765020"
        || contract.contacts != 50
        || contract.rhd2132_channels != [1, 32]
        || contract.rhs2116_channels != [33, 48]
        || contract.shared_reference_contact != 49
        || contract.ground_contact != 50
        || contract.exact_ecad_status != "manual_import_required"
        || contract.mechanical_note.is_empty()
    {
        return Err(DhlIdentityCatalogError::new(
            "headstage product matrix mixed_50p_contract is not canonical".into(),
        ));
    }
    let assemblies_by_name: BTreeMap<&str, &Assembly> = assemblies
        .iter()
        .map(|assembly| (assembly.name.as_str(), assembly))
        .collect();
    if assemblies_by_name.len() != assemblies.len() {
        return Err(DhlIdentityCatalogError::new(
            "component inventory contains duplicate assembly profile_id".into(),
        ));
    }

    let mut statuses = BTreeMap::new();
    for product in &matrix.products {
        if product.name.is_empty() || statuses.contains_key(&product.name) {
            return Err(DhlIdentityCatalogError::new(format!(
                "headstage product matrix has an empty or duplicate product {}",
                product.name
            )));
        }
        if product.connector.as_deref().is_some_and(str::is_empty)
            || (product.graph_closed && product.connector.is_none())
            || product
                .minimum_signal_contacts
                .is_some_and(|contacts| contacts == 0)
        {
            return Err(DhlIdentityCatalogError::new(format!(
                "headstage product {} has invalid connector metadata",
                product.name
            )));
        }
        let assembly = assemblies_by_name
            .get(product.name.as_str())
            .ok_or_else(|| {
                DhlIdentityCatalogError::new(format!(
                    "headstage product {} is absent from component inventory",
                    product.name
                ))
            })?;
        let base = profiles_by_id
            .get(&assembly.board_profile_id)
            .ok_or_else(|| {
                DhlIdentityCatalogError::new(format!(
                    "headstage product {} references unknown board profile {}",
                    product.name, assembly.board_profile_id
                ))
            })?;
        let expected_neural: Result<Vec<&str>, DhlIdentityCatalogError> = base
            .components
            .iter()
            .map(|component| {
                model_name(component.model_id).ok_or_else(|| {
                    DhlIdentityCatalogError::new(format!(
                        "headstage product {} contains unknown neural model {}",
                        product.name, component.model_id
                    ))
                })
            })
            .collect();
        let expected_neural = expected_neural?;
        let has_echem = assembly.descriptor_feature_flags & FEATURE_ELECTROCHEM != 0;
        let has_rhs = assembly.descriptor_feature_flags & FEATURE_RHS_STIMULATION != 0;
        let expected_vstim_profile = if has_rhs {
            VstimProfile::Bipolar7v
        } else {
            VstimProfile::None
        };
        if product
            .neural
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected_neural
            || product.channels != total_channels(&base.components, &base.name)?
            || product.echem != has_echem
            || product.stim != has_rhs
            || assembly.vstim_profile != expected_vstim_profile
            || assembly.status.is_some()
        {
            return Err(DhlIdentityCatalogError::new(format!(
                "headstage product {} disagrees with component inventory identity",
                product.name
            )));
        }
        statuses.insert(
            product.name.clone(),
            CatalogAssemblyState {
                status: CatalogStatus::ActiveProduct,
                graph_closed: product.graph_closed,
            },
        );
    }
    for profile_id in &matrix.decode_only_profiles {
        if profile_id.is_empty() || statuses.contains_key(profile_id) {
            return Err(DhlIdentityCatalogError::new(format!(
                "decode-only profile {} is empty, duplicated, or listed as a product",
                profile_id
            )));
        }
        let assembly = assemblies_by_name.get(profile_id.as_str()).ok_or_else(|| {
            DhlIdentityCatalogError::new(format!(
                "decode-only profile {} is absent from component inventory",
                profile_id
            ))
        })?;
        if !matches!(assembly.status.as_ref(), Some(AssemblyStatus::DecodeOnly)) {
            return Err(DhlIdentityCatalogError::new(format!(
                "decode-only profile {} is not marked decode_only in component inventory",
                profile_id
            )));
        }
        // This historical graph is retained for decode/diagnostics but remains
        // categorically unavailable for new Runs.
        statuses.insert(
            profile_id.clone(),
            CatalogAssemblyState {
                status: CatalogStatus::DecodeOnly,
                graph_closed: true,
            },
        );
    }
    for assembly in assemblies {
        if statuses.contains_key(&assembly.name) {
            continue;
        }
        validate_closed_active_option(assembly, profiles_by_id, &statuses)?;
        if statuses
            .insert(
                assembly.name.clone(),
                CatalogAssemblyState {
                    status: CatalogStatus::ActiveOption,
                    // Current generated SKiDL summaries explicitly close these three
                    // options; no unspecified assembly defaults to closed.
                    graph_closed: true,
                },
            )
            .is_some()
        {
            return Err(DhlIdentityCatalogError::new(format!(
                "assembly {} has duplicate catalog state",
                assembly.name
            )));
        }
    }
    if statuses.len() != assemblies.len() {
        return Err(DhlIdentityCatalogError::new(
            "product matrix status classes do not cover every component inventory assembly".into(),
        ));
    }
    Ok(statuses)
}

fn validate_closed_active_option(
    assembly: &Assembly,
    profiles_by_id: &BTreeMap<u16, &BaseProfile>,
    states: &BTreeMap<String, CatalogAssemblyState>,
) -> Result<(), DhlIdentityCatalogError> {
    if assembly.status.is_some() {
        return Err(DhlIdentityCatalogError::new(format!(
            "assembly {} is not an active option",
            assembly.name
        )));
    }
    let base = profiles_by_id
        .get(&assembly.board_profile_id)
        .ok_or_else(|| {
            DhlIdentityCatalogError::new(format!(
                "active option {} references unknown board profile {}",
                assembly.name, assembly.board_profile_id
            ))
        })?;
    let base_closed = states
        .get("rhd2132x1")
        .is_some_and(|state| state.status == CatalogStatus::ActiveProduct && state.graph_closed);
    let echem_closed = states
        .get("rhd2132x1_echem")
        .is_some_and(|state| state.status == CatalogStatus::ActiveProduct && state.graph_closed);
    let rhs2116x2_closed = states
        .get("rhs2116x2")
        .is_some_and(|state| state.status == CatalogStatus::ActiveProduct && state.graph_closed);
    let valid = match assembly.name.as_str() {
        "rhd2132x1_imu" => {
            base.name == "rhd2132x1"
                && assembly.descriptor_feature_flags == FEATURE_IMU
                && assembly.expected_instance_ids == [0, 100]
                && base_closed
        }
        "rhd2132x1_imu_echem" => {
            base.name == "rhd2132x1"
                && assembly.descriptor_feature_flags == FEATURE_IMU | FEATURE_ELECTROCHEM
                && assembly.expected_instance_ids == [0, 100, 101]
                && base_closed
                && echem_closed
        }
        "rhs2116x2_imu" => {
            base.name == "rhs2116x2"
                && assembly.descriptor_feature_flags == FEATURE_RHS_STIMULATION | FEATURE_IMU
                && assembly.expected_instance_ids == [0, 1, 100]
                && rhs2116x2_closed
        }
        _ => false,
    };
    if !valid {
        return Err(DhlIdentityCatalogError::new(format!(
            "assembly {} is not one of the three explicitly graph-closed IMU options",
            assembly.name
        )));
    }
    Ok(())
}

fn validate_base_profile(profile: &BaseProfile) -> Result<(), DhlIdentityCatalogError> {
    if profile.components.is_empty() || profile.components.len() > 2 {
        return Err(DhlIdentityCatalogError::new(format!(
            "base profile {} must contain one or two neural components",
            profile.name
        )));
    }
    let derived_variant = derived_variant(&profile.components, &profile.name)?;
    if profile.variant != derived_variant {
        return Err(DhlIdentityCatalogError::new(format!(
            "base profile {} variant {} disagrees with component order variant {}",
            profile.name, profile.variant, derived_variant
        )));
    }
    let mut expected_instance_id = 0_u16;
    let mut next_channel = 0_u16;
    for component in &profile.components {
        if component.instance_id != expected_instance_id
            || component.reference != format!("U{}", 300 + expected_instance_id)
            || component.channel_count
                != model_channel_count(component.model_id).ok_or_else(|| {
                    DhlIdentityCatalogError::new(format!(
                        "base profile {} contains unknown model_id {}",
                        profile.name, component.model_id
                    ))
                })?
            || component.first_global_channel != next_channel
        {
            return Err(DhlIdentityCatalogError::new(format!(
                "base profile {} has non-canonical component order or channel geometry",
                profile.name
            )));
        }
        expected_instance_id = expected_instance_id.checked_add(1).ok_or_else(|| {
            DhlIdentityCatalogError::new(format!(
                "base profile {} instance_id overflow",
                profile.name
            ))
        })?;
        next_channel = next_channel
            .checked_add(component.channel_count)
            .ok_or_else(|| {
                DhlIdentityCatalogError::new(format!(
                    "base profile {} channel count overflow",
                    profile.name
                ))
            })?;
    }
    Ok(())
}

fn validate_geometry(
    base: &BaseProfile,
    channel_map: &ChannelMapProfile,
) -> Result<(), DhlIdentityCatalogError> {
    if channel_map.board_profile_id != base.id
        || channel_map.instances.len() != base.components.len()
    {
        return Err(DhlIdentityCatalogError::new(format!(
            "channel map {} board id or component count differs from component inventory",
            base.name
        )));
    }
    let mut next_global = 0_u16;
    for (component, mapped) in base.components.iter().zip(&channel_map.instances) {
        if mapped.instance_id != component.instance_id
            || mapped.reference != component.reference
            || mapped.model
                != model_name(component.model_id).ok_or_else(|| {
                    DhlIdentityCatalogError::new(format!(
                        "channel map {} has unknown component model {}",
                        base.name, component.model_id
                    ))
                })?
            || mapped.global_first != component.first_global_channel
            || mapped.global_first != next_global
            || mapped.native_first != 0
            || mapped.count != component.channel_count
        {
            return Err(DhlIdentityCatalogError::new(format!(
                "channel map {} has component order mismatch or non-contiguous geometry",
                base.name
            )));
        }
        next_global = next_global.checked_add(mapped.count).ok_or_else(|| {
            DhlIdentityCatalogError::new(format!(
                "channel map {} channel count overflow",
                base.name
            ))
        })?;
    }
    if next_global != total_channels(&base.components, &base.name)? {
        return Err(DhlIdentityCatalogError::new(format!(
            "channel map {} total channel count mismatch",
            base.name
        )));
    }
    Ok(())
}

fn validate_assembly(
    assembly: &Assembly,
    base: &BaseProfile,
    optional_components: &[OptionalComponent],
) -> Result<(), DhlIdentityCatalogError> {
    if assembly.descriptor_feature_flags & !FEATURE_MASK != 0 {
        return Err(DhlIdentityCatalogError::new(format!(
            "assembly {} has reserved descriptor feature flags {:#x}",
            assembly.name, assembly.descriptor_feature_flags
        )));
    }
    let has_rhs = base
        .components
        .iter()
        .any(|component| component.model_id == 65_539);
    if has_rhs != (assembly.descriptor_feature_flags & FEATURE_RHS_STIMULATION != 0) {
        return Err(DhlIdentityCatalogError::new(format!(
            "assembly {} RHS capability does not match its base geometry",
            assembly.name
        )));
    }
    let mut expected_ids: Vec<u16> = base
        .components
        .iter()
        .map(|component| component.instance_id)
        .collect();
    for optional in optional_components {
        let expected_flag = match optional.class.as_str() {
            "imu" => FEATURE_IMU,
            "electrochem_afe" => FEATURE_ELECTROCHEM,
            _ => unreachable!("validated optional component class"),
        };
        if assembly.descriptor_feature_flags & expected_flag != 0 {
            expected_ids.push(optional.instance_id);
        }
    }
    expected_ids.sort_unstable();
    if assembly.expected_instance_ids.is_empty()
        || assembly
            .expected_instance_ids
            .windows(2)
            .any(|window| window[0] >= window[1])
        || assembly.expected_instance_ids != expected_ids
    {
        return Err(DhlIdentityCatalogError::new(format!(
            "assembly {} expected instance IDs are duplicated, out of order, or incomplete",
            assembly.name
        )));
    }
    Ok(())
}

fn normalized_expected_components(
    assembly: &Assembly,
    base: &BaseProfile,
    channel_map: &ChannelMapProfile,
    optional_components: &[OptionalComponent],
) -> Result<Vec<DhlExpectedComponent>, DhlIdentityCatalogError> {
    let neural_components: BTreeMap<u16, (&InventoryComponent, &ChannelMapInstance)> = base
        .components
        .iter()
        .zip(&channel_map.instances)
        .map(|(component, mapped)| (component.instance_id, (component, mapped)))
        .collect();
    let optional_components: BTreeMap<u16, &OptionalComponent> = optional_components
        .iter()
        .map(|component| (component.instance_id, component))
        .collect();
    assembly
        .expected_instance_ids
        .iter()
        .map(|instance_id| {
            if let Some((component, mapped)) = neural_components.get(instance_id) {
                return Ok(DhlExpectedComponent {
                    instance_id: *instance_id,
                    reference: component.reference.clone(),
                    model_id: component.model_id,
                    kind: DhlExpectedComponentKind::NeuralAfe,
                    first_global_channel: Some(mapped.global_first),
                    channel_count: mapped.count,
                    native_first_channel: Some(mapped.native_first),
                });
            }
            let component = optional_components.get(instance_id).ok_or_else(|| {
                DhlIdentityCatalogError::new(format!(
                    "assembly {} expected unknown component instance {}",
                    assembly.name, instance_id
                ))
            })?;
            let kind = match component.class.as_str() {
                "imu" => DhlExpectedComponentKind::Imu,
                "electrochem_afe" => DhlExpectedComponentKind::ElectrochemAfe,
                _ => {
                    return Err(DhlIdentityCatalogError::new(format!(
                        "assembly {} optional component {} has unknown class {}",
                        assembly.name, instance_id, component.class
                    )))
                }
            };
            Ok(DhlExpectedComponent {
                instance_id: *instance_id,
                reference: component.reference.clone(),
                model_id: component.model_id,
                kind,
                first_global_channel: None,
                channel_count: component.neural_channels,
                native_first_channel: None,
            })
        })
        .collect()
}

fn derived_variant(
    components: &[InventoryComponent],
    profile_name: &str,
) -> Result<u8, DhlIdentityCatalogError> {
    let models: Vec<u32> = components
        .iter()
        .map(|component| component.model_id)
        .collect();
    match models.as_slice() {
        [65_537] | [65_537, 65_537] => Ok(1),
        [65_538] | [65_538, 65_538] => Ok(2),
        [65_539] | [65_539, 65_539] => Ok(3),
        [65_537, 65_539] => Ok(4),
        [65_538, 65_539] => Ok(5),
        _ => Err(DhlIdentityCatalogError::new(format!(
            "base profile {profile_name} has unsupported neural model order {models:?}"
        ))),
    }
}

fn model_name(model_id: u32) -> Option<&'static str> {
    match model_id {
        65_537 => Some("RHD2132"),
        65_538 => Some("RHD2164"),
        65_539 => Some("RHS2116"),
        _ => None,
    }
}

fn model_channel_count(model_id: u32) -> Option<u16> {
    match model_id {
        65_537 => Some(32),
        65_538 => Some(64),
        65_539 => Some(16),
        _ => None,
    }
}

fn total_channels(
    components: &[InventoryComponent],
    profile_name: &str,
) -> Result<u16, DhlIdentityCatalogError> {
    components.iter().try_fold(0_u16, |total, component| {
        total.checked_add(component.channel_count).ok_or_else(|| {
            DhlIdentityCatalogError::new(format!(
                "base profile {profile_name} channel total overflow"
            ))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }

    type CanonicalProfileGolden = (
        &'static str,
        u16,
        u8,
        u8,
        u16,
        u16,
        CatalogStatus,
        &'static [u16],
    );

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ExpectedComponentGolden {
        instance_id: u16,
        reference: &'static str,
        model_id: u32,
        kind: DhlExpectedComponentKind,
        first_global_channel: Option<u16>,
        channel_count: u16,
        native_first_channel: Option<u16>,
    }

    const fn neural(
        instance_id: u16,
        reference: &'static str,
        model_id: u32,
        first_global_channel: u16,
        channel_count: u16,
    ) -> ExpectedComponentGolden {
        ExpectedComponentGolden {
            instance_id,
            reference,
            model_id,
            kind: DhlExpectedComponentKind::NeuralAfe,
            first_global_channel: Some(first_global_channel),
            channel_count,
            native_first_channel: Some(0),
        }
    }

    const fn optional(
        instance_id: u16,
        reference: &'static str,
        model_id: u32,
        kind: DhlExpectedComponentKind,
    ) -> ExpectedComponentGolden {
        ExpectedComponentGolden {
            instance_id,
            reference,
            model_id,
            kind,
            first_global_channel: None,
            channel_count: 0,
            native_first_channel: None,
        }
    }

    const RHD2132_X1_COMPONENTS: &[ExpectedComponentGolden] = &[neural(0, "U300", 65_537, 0, 32)];
    const RHD2132_X1_ECHEM_COMPONENTS: &[ExpectedComponentGolden] = &[
        neural(0, "U300", 65_537, 0, 32),
        optional(
            101,
            "U600",
            196_609,
            DhlExpectedComponentKind::ElectrochemAfe,
        ),
    ];
    const RHD2132_X1_IMU_COMPONENTS: &[ExpectedComponentGolden] = &[
        neural(0, "U300", 65_537, 0, 32),
        optional(100, "U500", 131_073, DhlExpectedComponentKind::Imu),
    ];
    const RHD2132_X1_IMU_ECHEM_COMPONENTS: &[ExpectedComponentGolden] = &[
        neural(0, "U300", 65_537, 0, 32),
        optional(100, "U500", 131_073, DhlExpectedComponentKind::Imu),
        optional(
            101,
            "U600",
            196_609,
            DhlExpectedComponentKind::ElectrochemAfe,
        ),
    ];
    const RHD2132_X2_COMPONENTS: &[ExpectedComponentGolden] = &[
        neural(0, "U300", 65_537, 0, 32),
        neural(1, "U301", 65_537, 32, 32),
    ];
    const RHD2164_X1_COMPONENTS: &[ExpectedComponentGolden] = &[neural(0, "U300", 65_538, 0, 64)];
    const RHD2164_X1_ECHEM_COMPONENTS: &[ExpectedComponentGolden] = &[
        neural(0, "U300", 65_538, 0, 64),
        optional(
            101,
            "U600",
            196_609,
            DhlExpectedComponentKind::ElectrochemAfe,
        ),
    ];
    const RHD2164_X2_COMPONENTS: &[ExpectedComponentGolden] = &[
        neural(0, "U300", 65_538, 0, 64),
        neural(1, "U301", 65_538, 64, 64),
    ];
    const RHS2116_X1_COMPONENTS: &[ExpectedComponentGolden] = &[neural(0, "U300", 65_539, 0, 16)];
    const RHS2116_X1_ECHEM_COMPONENTS: &[ExpectedComponentGolden] = &[
        neural(0, "U300", 65_539, 0, 16),
        optional(
            101,
            "U600",
            196_609,
            DhlExpectedComponentKind::ElectrochemAfe,
        ),
    ];
    const RHS2116_X2_COMPONENTS: &[ExpectedComponentGolden] = &[
        neural(0, "U300", 65_539, 0, 16),
        neural(1, "U301", 65_539, 16, 16),
    ];
    const RHS2116_X2_IMU_COMPONENTS: &[ExpectedComponentGolden] = &[
        neural(0, "U300", 65_539, 0, 16),
        neural(1, "U301", 65_539, 16, 16),
        optional(100, "U500", 131_073, DhlExpectedComponentKind::Imu),
    ];
    const RHD2132_RHS2116_COMPONENTS: &[ExpectedComponentGolden] = &[
        neural(0, "U300", 65_537, 0, 32),
        neural(1, "U301", 65_539, 32, 16),
    ];
    const RHD2164_RHS2116_COMPONENTS: &[ExpectedComponentGolden] = &[
        neural(0, "U300", 65_538, 0, 64),
        neural(1, "U301", 65_539, 64, 16),
    ];

    fn canonical_expected_components(profile_id: &str) -> &'static [ExpectedComponentGolden] {
        match profile_id {
            "rhd2132x1" => RHD2132_X1_COMPONENTS,
            "rhd2132x1_echem" => RHD2132_X1_ECHEM_COMPONENTS,
            "rhd2132x1_imu" => RHD2132_X1_IMU_COMPONENTS,
            "rhd2132x1_imu_echem" => RHD2132_X1_IMU_ECHEM_COMPONENTS,
            "rhd2132x1_rhs2116x1" => RHD2132_RHS2116_COMPONENTS,
            "rhd2132x2" => RHD2132_X2_COMPONENTS,
            "rhd2164x1" => RHD2164_X1_COMPONENTS,
            "rhd2164x1_echem" => RHD2164_X1_ECHEM_COMPONENTS,
            "rhd2164x1_rhs2116x1" => RHD2164_RHS2116_COMPONENTS,
            "rhd2164x2" => RHD2164_X2_COMPONENTS,
            "rhs2116x1" => RHS2116_X1_COMPONENTS,
            "rhs2116x1_echem" => RHS2116_X1_ECHEM_COMPONENTS,
            "rhs2116x2" => RHS2116_X2_COMPONENTS,
            "rhs2116x2_imu" => RHS2116_X2_IMU_COMPONENTS,
            _ => panic!("canonical profile {profile_id} is missing expected components"),
        }
    }

    // Auditable golden derived from the Python wire-profile tuples, checked-in
    // component/channel JSON, and product-matrix status semantics. Production
    // loading is driven solely by the three JSON catalogs and never parses TS.
    const CANONICAL_14_PROFILE_GOLDEN: &[CanonicalProfileGolden] = &[
        (
            "rhd2132x1",
            1,
            1,
            1,
            32,
            0,
            CatalogStatus::ActiveProduct,
            &[0],
        ),
        (
            "rhd2132x1_echem",
            1,
            1,
            1,
            32,
            1,
            CatalogStatus::ActiveProduct,
            &[0, 101],
        ),
        (
            "rhd2132x1_imu",
            1,
            1,
            1,
            32,
            2,
            CatalogStatus::ActiveOption,
            &[0, 100],
        ),
        (
            "rhd2132x1_imu_echem",
            1,
            1,
            1,
            32,
            3,
            CatalogStatus::ActiveOption,
            &[0, 100, 101],
        ),
        (
            "rhd2132x1_rhs2116x1",
            7,
            4,
            2,
            48,
            4,
            CatalogStatus::ActiveProduct,
            &[0, 1],
        ),
        (
            "rhd2132x2",
            2,
            1,
            2,
            64,
            0,
            CatalogStatus::DecodeOnly,
            &[0, 1],
        ),
        (
            "rhd2164x1",
            3,
            2,
            1,
            64,
            0,
            CatalogStatus::ActiveProduct,
            &[0],
        ),
        (
            "rhd2164x1_echem",
            3,
            2,
            1,
            64,
            1,
            CatalogStatus::ActiveProduct,
            &[0, 101],
        ),
        (
            "rhd2164x1_rhs2116x1",
            8,
            5,
            2,
            80,
            4,
            CatalogStatus::ActiveProduct,
            &[0, 1],
        ),
        (
            "rhd2164x2",
            4,
            2,
            2,
            128,
            0,
            CatalogStatus::ActiveProduct,
            &[0, 1],
        ),
        (
            "rhs2116x1",
            5,
            3,
            1,
            16,
            4,
            CatalogStatus::ActiveProduct,
            &[0],
        ),
        (
            "rhs2116x1_echem",
            5,
            3,
            1,
            16,
            5,
            CatalogStatus::ActiveProduct,
            &[0, 101],
        ),
        (
            "rhs2116x2",
            6,
            3,
            2,
            32,
            4,
            CatalogStatus::ActiveProduct,
            &[0, 1],
        ),
        (
            "rhs2116x2_imu",
            6,
            3,
            2,
            32,
            6,
            CatalogStatus::ActiveOption,
            &[0, 1, 100],
        ),
    ];

    #[test]
    fn embedded_catalog_matches_canonical_fourteen_profile_golden() {
        let catalog = DhlIdentityCatalog::load_embedded().unwrap();
        assert_eq!(catalog.identities().len(), 14);
        for (id, board_id, variant, chips, channels, flags, status, instances) in
            CANONICAL_14_PROFILE_GOLDEN
        {
            let identity = catalog.by_profile_id(id).unwrap();
            assert_eq!(identity.board_profile_id, *board_id, "{id}");
            assert_eq!(identity.variant, *variant, "{id}");
            assert_eq!(identity.chip_count, *chips, "{id}");
            assert_eq!(identity.acquisition_channel_count, *channels, "{id}");
            assert_eq!(identity.descriptor_feature_flags, *flags, "{id}");
            assert_eq!(identity.catalog_status, *status, "{id}");
            assert_eq!(identity.ordered_expected_instance_ids, *instances, "{id}");
            let expected_components = canonical_expected_components(id);
            assert_eq!(
                identity.ordered_expected_components.len(),
                expected_components.len(),
                "{id}"
            );
            assert_eq!(
                identity
                    .ordered_expected_components
                    .iter()
                    .map(|component| component.instance_id)
                    .collect::<Vec<_>>(),
                *instances,
                "{id}"
            );
            for (actual, expected) in identity
                .ordered_expected_components
                .iter()
                .zip(expected_components)
            {
                assert_eq!(actual.instance_id, expected.instance_id, "{id}");
                assert_eq!(actual.reference, expected.reference, "{id}");
                assert_eq!(actual.model_id, expected.model_id, "{id}");
                assert_eq!(actual.kind, expected.kind, "{id}");
                assert_eq!(
                    actual.first_global_channel, expected.first_global_channel,
                    "{id}"
                );
                assert_eq!(actual.channel_count, expected.channel_count, "{id}");
                assert_eq!(
                    actual.native_first_channel, expected.native_first_channel,
                    "{id}"
                );
            }
        }
        assert!(!catalog
            .by_profile_id("rhd2132x2")
            .unwrap()
            .is_new_run_catalog_eligible());
        assert!(catalog
            .by_profile_id("rhs2116x1")
            .unwrap()
            .is_new_run_catalog_eligible());
        assert_eq!(catalog.by_board_profile_id(1).unwrap().len(), 4);
        assert_eq!(catalog.by_board_profile_id(8).unwrap().len(), 1);
    }

    #[test]
    fn graph_closed_is_explicit_for_every_assembly_and_only_eight_are_new_run_eligible() {
        let catalog = DhlIdentityCatalog::load_embedded().unwrap();
        let expected_graph_closed = [
            ("rhd2132x1", true),
            // Closed legacy graph is preserved for diagnostics, not new Runs.
            ("rhd2132x2", true),
            ("rhd2164x1", false),
            ("rhd2164x2", false),
            ("rhs2116x1", true),
            ("rhs2116x2", true),
            // These three values are explicit generated-SKiDL-summary facts.
            ("rhs2116x2_imu", true),
            ("rhd2132x1_imu", true),
            ("rhd2132x1_echem", true),
            ("rhd2132x1_imu_echem", true),
            ("rhd2164x1_echem", false),
            ("rhs2116x1_echem", true),
            ("rhd2132x1_rhs2116x1", false),
            ("rhd2164x1_rhs2116x1", false),
        ];
        for (profile_id, graph_closed) in expected_graph_closed {
            assert_eq!(
                catalog.by_profile_id(profile_id).unwrap().graph_closed,
                graph_closed,
                "{profile_id}"
            );
        }
        let eligible = catalog
            .identities()
            .filter(|identity| identity.is_new_run_catalog_eligible())
            .map(|identity| identity.profile_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            eligible,
            [
                "rhd2132x1",
                "rhd2132x1_echem",
                "rhd2132x1_imu",
                "rhd2132x1_imu_echem",
                "rhs2116x1",
                "rhs2116x1_echem",
                "rhs2116x2",
                "rhs2116x2_imu",
            ]
        );
    }

    #[test]
    fn embedded_source_hashes_are_structured_and_bundle_is_frozen() {
        let actual = embedded_source_hashes_v1();
        assert_eq!(
            hex(&actual.bundle_sha256),
            DHL_IDENTITY_CATALOG_SOURCE_BUNDLE_SHA256_HEX
        );

        let mut inventory = COMPONENT_INVENTORY_PROFILES_JSON.as_bytes().to_vec();
        inventory[0] ^= 1;
        let changed_inventory = source_hashes_v1(
            &inventory,
            CHANNEL_MAPS_V1_JSON.as_bytes(),
            HEADSTAGE_PRODUCT_MATRIX_JSON.as_bytes(),
        );
        assert_ne!(
            changed_inventory.component_inventory_sha256,
            actual.component_inventory_sha256
        );
        assert_ne!(changed_inventory.bundle_sha256, actual.bundle_sha256);

        let mut maps = CHANNEL_MAPS_V1_JSON.as_bytes().to_vec();
        maps[0] ^= 1;
        let changed_maps = source_hashes_v1(
            COMPONENT_INVENTORY_PROFILES_JSON.as_bytes(),
            &maps,
            HEADSTAGE_PRODUCT_MATRIX_JSON.as_bytes(),
        );
        assert_ne!(changed_maps.channel_maps_sha256, actual.channel_maps_sha256);
        assert_ne!(changed_maps.bundle_sha256, actual.bundle_sha256);

        let mut matrix = HEADSTAGE_PRODUCT_MATRIX_JSON.as_bytes().to_vec();
        matrix[0] ^= 1;
        let changed_matrix = source_hashes_v1(
            COMPONENT_INVENTORY_PROFILES_JSON.as_bytes(),
            CHANNEL_MAPS_V1_JSON.as_bytes(),
            &matrix,
        );
        assert_ne!(
            changed_matrix.product_matrix_sha256,
            actual.product_matrix_sha256
        );
        assert_ne!(changed_matrix.bundle_sha256, actual.bundle_sha256);
    }

    #[test]
    fn rejects_unknown_schema_field_and_duplicate_expected_instance() {
        let unknown = COMPONENT_INVENTORY_PROFILES_JSON.replacen(
            "\n}",
            ",\n  \"unexpected_hash\": \"not-a-sha256\"\n}",
            1,
        );
        let error = DhlIdentityCatalog::from_json(
            &unknown,
            CHANNEL_MAPS_V1_JSON,
            HEADSTAGE_PRODUCT_MATRIX_JSON,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown field"), "{error}");

        let duplicate = COMPONENT_INVENTORY_PROFILES_JSON.replacen("[0, 100]", "[0, 0]", 1);
        let error = DhlIdentityCatalog::from_json(
            &duplicate,
            CHANNEL_MAPS_V1_JSON,
            HEADSTAGE_PRODUCT_MATRIX_JSON,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("expected instance IDs")
                || error.contains("three explicitly graph-closed"),
            "{error}"
        );
    }

    #[test]
    fn rejects_geometry_component_order_mismatch() {
        let malformed = CHANNEL_MAPS_V1_JSON.replacen(
            "\"global_first\": 32, \"native_first\": 0, \"count\": 32",
            "\"global_first\": 31, \"native_first\": 0, \"count\": 32",
            1,
        );
        let error = DhlIdentityCatalog::from_json(
            COMPONENT_INVENTORY_PROFILES_JSON,
            &malformed,
            HEADSTAGE_PRODUCT_MATRIX_JSON,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("component order mismatch or non-contiguous geometry"),
            "{error}"
        );
    }

    #[test]
    fn rejects_optional_component_model_or_class_mutation() {
        for malformed in [
            COMPONENT_INVENTORY_PROFILES_JSON.replacen("131073", "131074", 1),
            COMPONENT_INVENTORY_PROFILES_JSON.replacen(
                "\"class\": \"imu\"",
                "\"class\": \"bad\"",
                1,
            ),
        ] {
            let error = DhlIdentityCatalog::from_json(
                &malformed,
                CHANNEL_MAPS_V1_JSON,
                HEADSTAGE_PRODUCT_MATRIX_JSON,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("optional component"), "{error}");
        }
    }

    #[test]
    fn product_matrix_must_cover_the_same_fourteen_identities() {
        let missing_product = HEADSTAGE_PRODUCT_MATRIX_JSON.replacen(
            "\"name\":\"rhd2132x1\"",
            "\"name\":\"missing_from_inventory\"",
            1,
        );
        let error = DhlIdentityCatalog::from_json(
            COMPONENT_INVENTORY_PROFILES_JSON,
            CHANNEL_MAPS_V1_JSON,
            &missing_product,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("absent from component inventory"), "{error}");
    }

    #[test]
    fn rejects_an_unlisted_or_semantically_wrong_active_option_as_graph_closed() {
        let unknown_option = COMPONENT_INVENTORY_PROFILES_JSON.replacen(
            "\"name\": \"rhd2132x1_imu\"",
            "\"name\": \"rhd2132x1_future_imu\"",
            1,
        );
        let error = DhlIdentityCatalog::from_json(
            &unknown_option,
            CHANNEL_MAPS_V1_JSON,
            HEADSTAGE_PRODUCT_MATRIX_JSON,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("three explicitly graph-closed"), "{error}");

        let bad_option = COMPONENT_INVENTORY_PROFILES_JSON.replacen(
            "\"name\": \"rhd2132x1_imu\", \"board_profile_id\": 1, \"descriptor_feature_flags\": 2, \"vstim_profile\": \"none\", \"expected_instance_ids\": [0, 100]",
            "\"name\": \"rhd2132x1_imu\", \"board_profile_id\": 1, \"descriptor_feature_flags\": 2, \"vstim_profile\": \"none\", \"expected_instance_ids\": [0, 101]",
            1,
        );
        let error = DhlIdentityCatalog::from_json(
            &bad_option,
            CHANNEL_MAPS_V1_JSON,
            HEADSTAGE_PRODUCT_MATRIX_JSON,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("three explicitly graph-closed"), "{error}");
    }
}
