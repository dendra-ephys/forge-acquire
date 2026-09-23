//! Protected Windows deployment policy for one direct Receiver Pod.
//!
//! The policy is an exact-hash-bound local file referenced by SCM-protected
//! service arguments.  Loading it verifies the data-root binding and the
//! independently verified FT601 admission receipt.  Loading the policy alone
//! performs no hardware I/O.  Only an explicitly configured SCM service start
//! may call `open_d3xx_bootstrap`, which loads the protected D3XX source, opens
//! the one admitted FT601 and waits for the Pod-originated capability/epoch
//! bytes.  No production receipt, Pod firmware or HIL evidence exists yet, so
//! product-facing hardware availability remains fail-closed.

#![cfg(windows)]

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use forge_protocol_v1::{
    decode_low_speed, sha256, DeviceCapabilitiesV1, Hash32, Id16, MessageKind, WireBody,
    LOW_SPEED_HEADER_LEN,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::d3xx::{
    D3xxDevice, D3xxLibrary, Ft601ConfigurationEvidence, Ft601UsbDescriptorEvidence,
    MAX_D3XX_STREAM_PIPE_BYTES, MIN_D3XX_STREAM_PIPE_BYTES,
};
use crate::d3xx_admission::VerifiedFt601Admission;
use crate::dhl_identity_admission::{
    validate_dhl_identity_admission_policy_v1, DhlExpectedInstancePolicyV1,
    DhlIdentityAdmissionPolicyV1,
};
use crate::dhl_identity_catalog::{
    embedded_source_hashes_v1, DhlIdentityCatalog, DhlIdentityCatalogSourceHashesV1,
};
use crate::direct_pod_ingest::{
    DirectPodByteTransport, DirectPodProtectedPreflightV1, DirectPodRunPlan,
    DirectPodRuntimeConfig, DirectPodTransportRead, PreRunDirectPodConnection,
};
use crate::direct_pod_reconnect::{DirectPodReconnectEventKind, DirectPodReconnectLedger};
use crate::hardware_run::{HardwareRunCoordinator, HardwareRunPhase};
use crate::hardware_service::{
    DirectPodRunPlanProvider, OwnedHardwareServiceBackend, PromotableDirectPodBackend,
};
use crate::hardware_service_protocol::{
    HardwareServiceBackend, HardwareServiceSnapshotV1, OperatorRunRequestV1,
};
use crate::journal::{inspect_recovery, JournalRecovery};
use crate::receiver_pod_v2_session::Rps2SessionRuntime;

pub const DIRECT_POD_DEPLOYMENT_POLICY_SCHEMA: &str = "forge.direct-pod-deployment-policy.v4";
const CONTROL_MAGIC: &[u8; 8] = b"FGRCTL01";
const DEVICE_CAPABILITIES_MESSAGE_LEN: usize = LOW_SPEED_HEADER_LEN + 84;
// Bootstrap accepts only nonempty completions until the fixed first capability
// frame is complete, so it can need at most one completion per frame byte.
const MAX_BOOTSTRAP_COMPLETION_COUNT: usize = DEVICE_CAPABILITIES_MESSAGE_LEN;
const MAX_RECOVERY_RUN_ROOTS: usize = 4_096;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodRecoveryReport {
    pub inspected_run_roots: u32,
    pub failed_on_recovery: u32,
    pub terminal_run_roots: u32,
    pub unstarted_run_roots: u32,
    pub highest_transport_epoch: u64,
    pub evidence_hash: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedDirectPodPolicyReference {
    path: PathBuf,
    expected_file_sha256: Hash32,
    expected_approval_authority_sha256: Hash32,
}

impl ProtectedDirectPodPolicyReference {
    pub fn new(
        path: impl AsRef<Path>,
        expected_file_sha256: Hash32,
        expected_approval_authority_sha256: Hash32,
    ) -> io::Result<Self> {
        let path = path.as_ref();
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || !path.is_file()
            || expected_file_sha256 == [0; 32]
            || expected_approval_authority_sha256 == [0; 32]
        {
            return Err(invalid_input(
                "hardware policy reference requires an existing normalized absolute file and nonzero protected hashes",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            expected_file_sha256,
            expected_approval_authority_sha256,
        })
    }

    pub fn from_hex(
        path: impl AsRef<Path>,
        expected_file_sha256_hex: &str,
        expected_approval_authority_sha256_hex: &str,
    ) -> io::Result<Self> {
        Self::new(
            path,
            parse_hash32(expected_file_sha256_hex)?,
            parse_hash32(expected_approval_authority_sha256_hex)?,
        )
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn expected_file_sha256(&self) -> Hash32 {
        self.expected_file_sha256
    }

    pub fn expected_approval_authority_sha256(&self) -> Hash32 {
        self.expected_approval_authority_sha256
    }

    pub fn expected_file_sha256_hex(&self) -> String {
        hex(&self.expected_file_sha256)
    }

    pub fn expected_approval_authority_sha256_hex(&self) -> String {
        hex(&self.expected_approval_authority_sha256)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum D3xxLibraryPolicy {
    System32,
    Absolute(PathBuf),
}

#[derive(Debug)]
pub struct VerifiedDirectPodDeploymentPolicy {
    canonical_data_root: PathBuf,
    policy_file_sha256: Hash32,
    admission: VerifiedFt601Admission,
    d3xx_library: D3xxLibraryPolicy,
    pod_id: Id16,
    headstage_id: Id16,
    frozen_config_sha256: Hash32,
    approved_cabline_binding_sha256: Hash32,
    dhl_identity_policy: DhlIdentityAdmissionPolicyV1,
    dhl_catalog_source_hashes: DhlIdentityCatalogSourceHashesV1,
    runtime_config: DirectPodRuntimeConfig,
    stream_pipe_bytes: u32,
    pipe_timeout_ms: u32,
}

impl VerifiedDirectPodDeploymentPolicy {
    pub fn load(
        reference: &ProtectedDirectPodPolicyReference,
        data_root: impl AsRef<Path>,
        now_unix_ns: u64,
    ) -> io::Result<Self> {
        if now_unix_ns == 0 {
            return Err(permission_denied(
                "current wall-clock time is required to verify hardware admission",
            ));
        }
        let canonical_data_root = canonical_data_root(data_root.as_ref())?;
        let bytes = std::fs::read(reference.path())?;
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(invalid_data("hardware deployment policy size is invalid"));
        }
        let policy_file_sha256: Hash32 = Sha256::digest(&bytes).into();
        if policy_file_sha256 != reference.expected_file_sha256() {
            return Err(permission_denied(
                "hardware deployment policy file hash is not approved",
            ));
        }
        let raw: RawDeploymentPolicy = serde_json::from_slice(&bytes)
            .map_err(|_| invalid_data("hardware deployment policy JSON is not exact schema v4"))?;
        if raw.schema != DIRECT_POD_DEPLOYMENT_POLICY_SCHEMA
            || parse_hash32(&raw.data_root_sha256)?
                != windows_data_root_sha256(&canonical_data_root)?
        {
            return Err(permission_denied(
                "hardware deployment policy is not bound to this canonical data root",
            ));
        }

        let admission_path =
            normalized_absolute_file(&raw.admission_receipt_path, "admission receipt")?;
        let admission = VerifiedFt601Admission::load(
            admission_path,
            parse_hash32(&raw.admission_receipt_sha256)?,
            reference.expected_approval_authority_sha256(),
            now_unix_ns,
        )?;
        let pod_id = parse_id16(&raw.pod_id)?;
        let headstage_id = parse_id16(&raw.headstage_id)?;
        let frozen_config_sha256 = parse_hash32(&raw.frozen_config_sha256)?;
        let approved_cabline_binding_sha256 = parse_hash32(&raw.approved_cabline_binding_sha256)?;
        if pod_id == [0; 16]
            || headstage_id == [0; 16]
            || frozen_config_sha256 == [0; 32]
            || approved_cabline_binding_sha256 == [0; 32]
        {
            return Err(invalid_data(
                "hardware deployment policy identities and approved hashes must be nonzero",
            ));
        }
        let dhl_catalog = DhlIdentityCatalog::load_embedded()
            .map_err(|_| invalid_data("embedded DHL identity catalog is invalid"))?;
        let dhl_catalog_source_hashes = embedded_source_hashes_v1();
        if parse_hash32(&raw.dhl_catalog_component_inventory_sha256)?
            != dhl_catalog_source_hashes.component_inventory_sha256
            || parse_hash32(&raw.dhl_catalog_channel_maps_sha256)?
                != dhl_catalog_source_hashes.channel_maps_sha256
            || parse_hash32(&raw.dhl_catalog_product_matrix_sha256)?
                != dhl_catalog_source_hashes.product_matrix_sha256
            || parse_hash32(&raw.dhl_catalog_source_bundle_sha256)?
                != dhl_catalog_source_hashes.bundle_sha256
        {
            return Err(permission_denied(
                "hardware deployment policy DHL catalog source hashes do not match embedded sources",
            ));
        }
        let dhl_identity_policy = DhlIdentityAdmissionPolicyV1 {
            profile_id: raw.dhl_profile_id,
            expected_descriptor_payload_sha256: parse_hash32(&raw.dhl_descriptor_payload_sha256)?,
            expected_inventory_payload_sha256: parse_hash32(&raw.dhl_inventory_payload_sha256)?,
            // Descriptor identity intentionally reuses protected headstage_id;
            // it is distinct from the FT601 receipt device_id and Host Run config.
            expected_device_id: headstage_id,
            expected_config_hash: parse_hash32(&raw.dhl_expected_config_hash)?,
            sample_rate_numerator_hz: raw.dhl_sample_rate_numerator_hz,
            sample_rate_denominator: raw.dhl_sample_rate_denominator,
            approved_channel_layout_id: raw.dhl_channel_layout_id,
            assembly_manifest_hash: parse_hash32(&raw.dhl_assembly_manifest_hash)?,
            channel_map_hash: parse_hash32(&raw.dhl_channel_map_hash)?,
            ordered_expected_instances: raw
                .dhl_ordered_expected_instances
                .into_iter()
                .map(|instance| {
                    Ok(DhlExpectedInstancePolicyV1 {
                        instance_id: instance.instance_id,
                        exact_driver_abi: instance.exact_driver_abi,
                        exact_capability_flags: instance.exact_capability_flags,
                        config_hash_prefix: parse_hex::<12>(
                            &instance.config_hash_prefix,
                            "DHL instance config hash prefix",
                        )?,
                    })
                })
                .collect::<io::Result<Vec<_>>>()?,
        };
        validate_dhl_identity_admission_policy_v1(&dhl_catalog, &dhl_identity_policy).map_err(
            |_| invalid_data("hardware deployment DHL identity policy is not admissible"),
        )?;
        let runtime_config = DirectPodRuntimeConfig {
            read_buffer_bytes: raw.read_buffer_bytes,
            read_depth: raw.read_depth,
        }
        .validate()?;
        let queued_bytes = runtime_config
            .read_buffer_bytes
            .checked_mul(runtime_config.read_depth)
            .ok_or_else(|| invalid_data("hardware policy queue size overflow"))?;
        if raw.stream_pipe_bytes as usize != queued_bytes
            || !(MIN_D3XX_STREAM_PIPE_BYTES..=MAX_D3XX_STREAM_PIPE_BYTES)
                .contains(&raw.stream_pipe_bytes)
            || raw.pipe_timeout_ms == 0
            || raw.pipe_timeout_ms > 60_000
        {
            return Err(invalid_data(
                "D3XX stream size must equal the bounded queue and timeout must be within policy",
            ));
        }
        let d3xx_library = match raw.d3xx_library {
            RawD3xxLibraryPolicy::System32 => D3xxLibraryPolicy::System32,
            RawD3xxLibraryPolicy::Absolute { path } => {
                D3xxLibraryPolicy::Absolute(normalized_absolute_file(&path, "D3XX library")?)
            }
        };

        Ok(Self {
            canonical_data_root,
            policy_file_sha256,
            admission,
            d3xx_library,
            pod_id,
            headstage_id,
            frozen_config_sha256,
            approved_cabline_binding_sha256,
            dhl_identity_policy,
            dhl_catalog_source_hashes,
            runtime_config,
            stream_pipe_bytes: raw.stream_pipe_bytes,
            pipe_timeout_ms: raw.pipe_timeout_ms,
        })
    }

    pub fn policy_file_sha256(&self) -> Hash32 {
        self.policy_file_sha256
    }

    pub fn admission(&self) -> &VerifiedFt601Admission {
        &self.admission
    }

    pub fn d3xx_library(&self) -> &D3xxLibraryPolicy {
        &self.d3xx_library
    }

    pub fn runtime_config(&self) -> DirectPodRuntimeConfig {
        self.runtime_config
    }

    pub fn stream_pipe_bytes(&self) -> u32 {
        self.stream_pipe_bytes
    }

    pub fn pipe_timeout_ms(&self) -> u32 {
        self.pipe_timeout_ms
    }

    pub fn approved_cabline_binding_sha256(&self) -> Hash32 {
        self.approved_cabline_binding_sha256
    }

    /// Protected identity policy for a later byte-level DHL admission step.
    /// Loading this deployment policy does not itself consume a capsule or assert Ready.
    pub fn dhl_identity_policy(&self) -> &DhlIdentityAdmissionPolicyV1 {
        &self.dhl_identity_policy
    }

    pub fn dhl_catalog_source_hashes(&self) -> DhlIdentityCatalogSourceHashesV1 {
        self.dhl_catalog_source_hashes
    }

    pub fn evidence_hash(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(324);
        bytes.extend_from_slice(b"FORGE-DIRECT-POD-DEPLOYMENT-EVIDENCE-V4");
        bytes.extend_from_slice(&self.policy_file_sha256);
        bytes.extend_from_slice(&self.admission.receipt_file_sha256());
        bytes.extend_from_slice(&self.admission.device_id());
        bytes.extend_from_slice(&self.pod_id);
        bytes.extend_from_slice(&self.headstage_id);
        bytes.extend_from_slice(&self.frozen_config_sha256);
        bytes.extend_from_slice(&self.approved_cabline_binding_sha256);
        bytes.extend_from_slice(&self.dhl_catalog_source_hashes.bundle_sha256);
        bytes.extend_from_slice(&self.dhl_identity_policy.expected_descriptor_payload_sha256);
        bytes.extend_from_slice(&self.dhl_identity_policy.expected_inventory_payload_sha256);
        bytes.extend_from_slice(&self.dhl_identity_policy.expected_config_hash);
        bytes.extend_from_slice(
            &self
                .dhl_identity_policy
                .approved_channel_layout_id
                .to_le_bytes(),
        );
        sha256(&bytes)
    }

    pub(crate) fn run_plan_provider(&self) -> ProtectedDirectPodRunPlanProvider {
        ProtectedDirectPodRunPlanProvider {
            canonical_data_root: self.canonical_data_root.clone(),
            device_id: self.admission.device_id(),
            pod_id: self.pod_id,
            headstage_id: self.headstage_id,
            frozen_config_sha256: self.frozen_config_sha256,
            approved_cabline_binding_sha256: self.approved_cabline_binding_sha256,
        }
    }

    /// Reconciles every policy-owned historical Run before this service start
    /// is allowed to open D3XX. Unfinished hardware lifecycles are failed by
    /// `HardwareRunCoordinator::open`; no journal is truncated, resumed or
    /// sealed here.
    pub fn recover_prior_runs(&self) -> io::Result<DirectPodRecoveryReport> {
        let mut roots = Vec::new();
        for entry in std::fs::read_dir(&self.canonical_data_root)? {
            let entry = entry?;
            let name = match entry.file_name().into_string() {
                Ok(value) => value,
                Err(_) => continue,
            };
            if !name.starts_with("hardware-run-") {
                continue;
            }
            if roots.len() >= MAX_RECOVERY_RUN_ROOTS {
                return Err(invalid_data(
                    "direct-Pod recovery root count exceeds the fixed bound",
                ));
            }
            let suffix = name
                .strip_prefix("hardware-run-")
                .ok_or_else(|| invalid_data("hardware Run root prefix is invalid"))?;
            if suffix.len() != 32 || !suffix.bytes().all(|value| value.is_ascii_hexdigit()) {
                return Err(invalid_data(
                    "hardware Run root name does not contain one exact Run ID",
                ));
            }
            let run_id = parse_id16(suffix)?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(permission_denied(
                    "hardware Run recovery refuses files, links, and reparse points",
                ));
            }
            let canonical = path.canonicalize()?;
            if canonical.parent() != Some(self.canonical_data_root.as_path()) {
                return Err(permission_denied(
                    "hardware Run recovery root escaped the protected data root",
                ));
            }
            roots.push((name, run_id, canonical));
        }
        roots.sort_by(|left, right| left.0.cmp(&right.0));

        let mut failed_on_recovery = 0_u32;
        let mut terminal_run_roots = 0_u32;
        let mut unstarted_run_roots = 0_u32;
        let mut highest_transport_epoch = 0_u64;
        let mut evidence = Vec::new();
        evidence.extend_from_slice(b"FORGE-DIRECT-POD-RECOVERY-REPORT-V1");
        evidence.extend_from_slice(&self.policy_file_sha256);
        evidence.extend_from_slice(&self.admission.device_id());
        for (_, run_id, root) in &roots {
            let journal_path = root.join("run.forgewal");
            let hardware_ledger_path = root.join("hardware-ledger");
            validate_recovery_tree(root)?;
            if !journal_path.is_file() || !hardware_ledger_path.is_dir() {
                return Err(invalid_data(
                    "hardware Run recovery root is missing journal or lifecycle evidence",
                ));
            }
            let journal_identity = match inspect_recovery(&journal_path)? {
                JournalRecovery::Clean(scan) => scan.identity,
                JournalRecovery::RecoverableUnprovenTail { identity, .. } => identity,
            };
            if journal_identity.run_id != *run_id {
                return Err(invalid_data(
                    "hardware Run directory identity contradicts its journal",
                ));
            }

            let coordinator = HardwareRunCoordinator::open(&hardware_ledger_path)?;
            let status = coordinator.status();
            highest_transport_epoch = highest_transport_epoch.max(status.highest_epoch);
            if status.auto_failed_on_restart {
                failed_on_recovery = failed_on_recovery
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("recovered Run counter overflow"))?;
            } else if status.phase == HardwareRunPhase::New {
                unstarted_run_roots = unstarted_run_roots
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("unstarted Run counter overflow"))?;
            } else if matches!(
                status.phase,
                HardwareRunPhase::Sealed | HardwareRunPhase::Aborted | HardwareRunPhase::Failed
            ) {
                terminal_run_roots = terminal_run_roots
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("terminal Run counter overflow"))?;
            } else {
                return Err(invalid_data(
                    "hardware Run remained nonterminal after restart reconciliation",
                ));
            }
            if let Some(active_run_id) = status.active_run_id_hex.as_deref() {
                if active_run_id != hex(run_id) {
                    return Err(invalid_data(
                        "hardware lifecycle Run identity contradicts its directory",
                    ));
                }
            }
            evidence.extend_from_slice(run_id);
            evidence.extend_from_slice(&(status.phase as u16).to_le_bytes());
            evidence.extend_from_slice(&status.highest_epoch.to_le_bytes());
            evidence.extend_from_slice(&status.ledger_events.to_le_bytes());
            evidence.push(u8::from(status.auto_failed_on_restart));
        }
        let inspected_run_roots = u32::try_from(roots.len())
            .map_err(|_| invalid_data("inspected Run root count exceeds u32"))?;
        evidence.extend_from_slice(&inspected_run_roots.to_le_bytes());
        evidence.extend_from_slice(&failed_on_recovery.to_le_bytes());
        evidence.extend_from_slice(&terminal_run_roots.to_le_bytes());
        evidence.extend_from_slice(&unstarted_run_roots.to_le_bytes());
        evidence.extend_from_slice(&highest_transport_epoch.to_le_bytes());
        Ok(DirectPodRecoveryReport {
            inspected_run_roots,
            failed_on_recovery,
            terminal_run_roots,
            unstarted_run_roots,
            highest_transport_epoch,
            evidence_hash: sha256(&evidence),
        })
    }

    /// Explicitly opens the internally admitted FT601 and configures its duplex
    /// pipes, but does not yet expose a hardware-service backend. The caller
    /// must complete the exact capability bootstrap and obtain the Pod-supplied
    /// transport epoch first.
    pub fn open_d3xx_bootstrap(&self) -> io::Result<DirectPodD3xxBootstrap> {
        self.admission.require_valid_at(current_unix_ns()?)?;
        let library = match &self.d3xx_library {
            D3xxLibraryPolicy::System32 => D3xxLibrary::load_system32()?,
            D3xxLibraryPolicy::Absolute(path) => D3xxLibrary::load_absolute(path)?,
        };
        let (mut device, configuration, descriptors) =
            library.open_admitted_ft600(&self.admission)?;
        device.prepare_duplex_pipes(self.stream_pipe_bytes, self.pipe_timeout_ms)?;
        let plan_provider = self.run_plan_provider();
        let protected_preflight = DirectPodProtectedPreflightV1::new(
            self.dhl_identity_policy.clone(),
            self.pod_id,
            self.headstage_id,
            self.approved_cabline_binding_sha256,
        )?;
        let bootstrap = DirectPodTransportBootstrap::new(
            self.admission.clone(),
            device,
            self.runtime_config,
            protected_preflight,
        )?;
        Ok(DirectPodD3xxBootstrap {
            bootstrap,
            plan_provider,
            configuration,
            descriptors,
            library_path: library.source_path().to_path_buf(),
            library_sha256: library.library_sha256(),
            policy_file_sha256: self.policy_file_sha256,
        })
    }

    /// Opens the exact admitted FT600 transport for the V2 RPS2 session
    /// lifecycle.  This deliberately does not start the historical M0
    /// capability bootstrap: a V2 Pod consumes RPS2 frames rather than its
    /// old low-speed control wire.
    ///
    /// The caller must establish `BEGIN` with the current admitted startup
    /// ticket before issuing experiment commands.  This is still a software
    /// path only; successful construction does not provide USB/HIL evidence.
    pub fn open_d3xx_rps2_session(&self) -> io::Result<Rps2SessionRuntime<D3xxDevice>> {
        self.admission.require_valid_at(current_unix_ns()?)?;
        let library = match &self.d3xx_library {
            D3xxLibraryPolicy::System32 => D3xxLibrary::load_system32()?,
            D3xxLibraryPolicy::Absolute(path) => D3xxLibrary::load_absolute(path)?,
        };
        let (mut device, _configuration, _descriptors) =
            library.open_admitted_ft600(&self.admission)?;
        device.prepare_duplex_pipes(self.stream_pipe_bytes, self.pipe_timeout_ms)?;
        Ok(Rps2SessionRuntime::new(device))
    }
}

pub(crate) trait DirectPodReconnectFactory<T, P>: Send + 'static
where
    T: DirectPodByteTransport,
    P: DirectPodRunPlanProvider,
{
    fn open_fresh(&mut self) -> io::Result<(DirectPodTransportBootstrap<T>, P)>;
}

pub(crate) struct VerifiedDirectPodReconnectFactory {
    policy: VerifiedDirectPodDeploymentPolicy,
}

pub struct ProductionDirectPodReconnectBackend {
    inner: ReconnectingDirectPodBackend<
        D3xxDevice,
        ProtectedDirectPodRunPlanProvider,
        VerifiedDirectPodReconnectFactory,
    >,
}

impl VerifiedDirectPodDeploymentPolicy {
    pub fn into_reconnecting_owner_backend(
        self,
        deployment_evidence_hash: Hash32,
        service_instance_id: Id16,
        minimum_transport_epoch: u64,
    ) -> io::Result<ProductionDirectPodReconnectBackend> {
        let stable_policy_evidence_hash = self.evidence_hash();
        let ledger = DirectPodReconnectLedger::open(
            self.canonical_data_root.join("direct-pod-reconnect-ledger"),
            self.admission.device_id(),
            stable_policy_evidence_hash,
        )?;
        Ok(ProductionDirectPodReconnectBackend {
            inner: ReconnectingDirectPodBackend::new_waiting(
                VerifiedDirectPodReconnectFactory::new(self),
                ledger,
                DirectPodReconnectPolicy::PRODUCTION,
                deployment_evidence_hash,
                service_instance_id,
                minimum_transport_epoch,
            )?,
        })
    }
}

impl VerifiedDirectPodReconnectFactory {
    pub(crate) fn new(policy: VerifiedDirectPodDeploymentPolicy) -> Self {
        Self { policy }
    }
}

impl DirectPodReconnectFactory<D3xxDevice, ProtectedDirectPodRunPlanProvider>
    for VerifiedDirectPodReconnectFactory
{
    fn open_fresh(
        &mut self,
    ) -> io::Result<(
        DirectPodTransportBootstrap<D3xxDevice>,
        ProtectedDirectPodRunPlanProvider,
    )> {
        let opened = self.policy.open_d3xx_bootstrap()?;
        Ok((opened.bootstrap, opened.plan_provider))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectPodReconnectPolicy {
    pub max_attempts: u32,
    pub initial_backoff_ns: u64,
    pub max_backoff_ns: u64,
}

impl DirectPodReconnectPolicy {
    pub const PRODUCTION: Self = Self {
        max_attempts: 8,
        initial_backoff_ns: 250_000_000,
        max_backoff_ns: 30_000_000_000,
    };

    pub fn validate(self) -> io::Result<Self> {
        if self.max_attempts == 0
            || self.max_attempts > 64
            || self.initial_backoff_ns == 0
            || self.initial_backoff_ns > self.max_backoff_ns
            || self.max_backoff_ns > 300_000_000_000
        {
            return Err(invalid_input(
                "direct-Pod reconnect policy is outside fixed bounds",
            ));
        }
        Ok(self)
    }

    fn delay_after(self, failed_attempts: u32) -> u64 {
        let shift = failed_attempts.min(63);
        self.initial_backoff_ns
            .checked_shl(shift)
            .unwrap_or(u64::MAX)
            .min(self.max_backoff_ns)
    }
}

fn current_unix_ns() -> io::Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::Error::other("system clock is before the Unix epoch"))?
            .as_nanos(),
    )
    .map_err(|_| io::Error::other("system wall-clock timestamp exceeds receipt range"))
}

enum ReconnectingDirectPodState<T, P>
where
    T: DirectPodByteTransport,
    P: DirectPodRunPlanProvider,
{
    Active(Box<BootstrappingDirectPodBackend<T, P>>),
    Waiting {
        previous_transport_epoch: u64,
        completed_attempts: u32,
        next_attempt_host_ns: u64,
        unavailable: crate::UnavailableHardwareBackend,
    },
    Candidate {
        backend: Box<BootstrappingDirectPodBackend<T, P>>,
        previous_transport_epoch: u64,
        attempt_number: u32,
        deadline_host_ns: u64,
    },
    Exhausted(crate::UnavailableHardwareBackend),
}

pub(crate) struct ReconnectingDirectPodBackend<T, P, F>
where
    T: DirectPodByteTransport,
    P: DirectPodRunPlanProvider,
    F: DirectPodReconnectFactory<T, P>,
{
    state: Option<ReconnectingDirectPodState<T, P>>,
    factory: F,
    ledger: DirectPodReconnectLedger,
    policy: DirectPodReconnectPolicy,
    deployment_evidence_hash: Hash32,
    service_instance_id: Id16,
    last_host_monotonic_ns: u64,
}

impl<T, P, F> ReconnectingDirectPodBackend<T, P, F>
where
    T: DirectPodByteTransport,
    P: DirectPodRunPlanProvider,
    F: DirectPodReconnectFactory<T, P>,
{
    #[cfg(test)]
    pub(crate) fn new(
        mut initial: BootstrappingDirectPodBackend<T, P>,
        factory: F,
        ledger: DirectPodReconnectLedger,
        policy: DirectPodReconnectPolicy,
        deployment_evidence_hash: Hash32,
        service_instance_id: Id16,
    ) -> io::Result<Self> {
        let policy = match policy.validate() {
            Ok(policy) => policy,
            Err(error) => {
                let _ = initial.shutdown_owner_now();
                return Err(error);
            }
        };
        if deployment_evidence_hash == [0; 32]
            || service_instance_id == [0; 16]
            || ledger.is_poisoned()
        {
            let _ = initial.shutdown_owner_now();
            return Err(invalid_input(
                "direct-Pod reconnect owner evidence is invalid",
            ));
        }
        Ok(Self {
            state: Some(ReconnectingDirectPodState::Active(Box::new(initial))),
            factory,
            ledger,
            policy,
            deployment_evidence_hash,
            service_instance_id,
            last_host_monotonic_ns: 0,
        })
    }

    pub(crate) fn new_waiting(
        factory: F,
        mut ledger: DirectPodReconnectLedger,
        policy: DirectPodReconnectPolicy,
        deployment_evidence_hash: Hash32,
        service_instance_id: Id16,
        minimum_transport_epoch: u64,
    ) -> io::Result<Self> {
        let policy = policy.validate()?;
        if deployment_evidence_hash == [0; 32]
            || service_instance_id == [0; 16]
            || ledger.is_poisoned()
            || ledger
                .recorded_max_attempts()
                .is_some_and(|value| value != policy.max_attempts)
        {
            return Err(invalid_input(
                "direct-Pod reconnect recovery evidence is invalid",
            ));
        }
        let previous_transport_epoch = minimum_transport_epoch
            .max(ledger.highest_admitted_epoch())
            .max(ledger.cycle_previous_epoch());
        if previous_transport_epoch > ledger.cycle_previous_epoch()
            && (ledger.completed_attempts() != 0
                || ledger.pending_attempt().is_some()
                || ledger.attempts_exhausted())
        {
            return Err(invalid_data(
                "Run recovery epoch contradicts the durable reconnect cycle",
            ));
        }
        if let Some(interrupted_attempt) = ledger.pending_attempt() {
            ledger.append(
                DirectPodReconnectEventKind::AttemptFailed,
                previous_transport_epoch,
                0,
                1,
                interrupted_attempt,
                policy.max_attempts,
                u16::from(error_kind_code(io::ErrorKind::Interrupted)).max(1),
                2,
                sha256(b"FORGE-DIRECT-POD-RECONNECT-INTERRUPTED-BY-RESTART-V1"),
                service_instance_id,
            )?;
        }
        if ledger.completed_attempts() >= policy.max_attempts && !ledger.attempts_exhausted() {
            let detail = ledger
                .last_event()
                .ok_or_else(|| invalid_data("reconnect exhaustion has no prior evidence"))?
                .evidence_hash()?;
            ledger.append(
                DirectPodReconnectEventKind::AttemptsExhausted,
                previous_transport_epoch,
                0,
                1,
                policy.max_attempts,
                policy.max_attempts,
                u16::from(error_kind_code(io::ErrorKind::Interrupted)).max(1),
                2,
                detail,
                service_instance_id,
            )?;
        }
        let completed_attempts = ledger.completed_attempts();
        let evidence = ledger
            .last_event()
            .map(|event| event.evidence_hash())
            .transpose()?
            .unwrap_or(deployment_evidence_hash);
        let state = if ledger.attempts_exhausted() {
            ReconnectingDirectPodState::Exhausted(
                crate::UnavailableHardwareBackend::from_verified_evidence(evidence, 9)?,
            )
        } else {
            ReconnectingDirectPodState::Waiting {
                previous_transport_epoch,
                completed_attempts,
                next_attempt_host_ns: 1,
                unavailable: crate::UnavailableHardwareBackend::from_verified_evidence(
                    evidence, 6,
                )?,
            }
        };
        Ok(Self {
            state: Some(state),
            factory,
            ledger,
            policy,
            deployment_evidence_hash,
            service_instance_id,
            last_host_monotonic_ns: 0,
        })
    }

    #[cfg(test)]
    pub(crate) fn reconnect_event_count(&self) -> u64 {
        self.ledger.event_count()
    }

    fn unavailable(
        &self,
        detail_code: u32,
        evidence: Hash32,
    ) -> io::Result<crate::UnavailableHardwareBackend> {
        crate::UnavailableHardwareBackend::from_verified_evidence(evidence, detail_code)
    }

    #[allow(clippy::too_many_arguments)]
    fn append_event(
        &mut self,
        kind: DirectPodReconnectEventKind,
        previous_epoch: u64,
        candidate_epoch: u64,
        host_ns: u64,
        attempt: u32,
        fault_kind: u16,
        result_code: u16,
        detail_hash: Hash32,
    ) -> io::Result<Hash32> {
        self.ledger
            .append(
                kind,
                previous_epoch,
                candidate_epoch,
                host_ns,
                attempt,
                self.policy.max_attempts,
                fault_kind,
                result_code,
                detail_hash,
                self.service_instance_id,
            )?
            .evidence_hash()
    }

    fn schedule_wait(&self, host_ns: u64, completed_attempts: u32) -> io::Result<u64> {
        host_ns
            .checked_add(self.policy.delay_after(completed_attempts))
            .ok_or_else(|| invalid_data("direct-Pod reconnect deadline overflow"))
    }

    fn record_failure_or_exhaustion(
        &mut self,
        previous_epoch: u64,
        attempt: u32,
        host_ns: u64,
        error: &io::Error,
    ) -> io::Result<ReconnectingDirectPodState<T, P>> {
        let fault_kind = u16::from(error_kind_code(error.kind())).max(1);
        let detail_hash = sha256(error.to_string().as_bytes());
        let failed_hash = self.append_event(
            DirectPodReconnectEventKind::AttemptFailed,
            previous_epoch,
            0,
            host_ns,
            attempt,
            fault_kind,
            1,
            detail_hash,
        )?;
        if attempt >= self.policy.max_attempts {
            let exhausted_hash = self.append_event(
                DirectPodReconnectEventKind::AttemptsExhausted,
                previous_epoch,
                0,
                host_ns,
                attempt,
                fault_kind,
                1,
                failed_hash,
            )?;
            Ok(ReconnectingDirectPodState::Exhausted(
                self.unavailable(9, exhausted_hash)?,
            ))
        } else {
            Ok(ReconnectingDirectPodState::Waiting {
                previous_transport_epoch: previous_epoch,
                completed_attempts: attempt,
                next_attempt_host_ns: self.schedule_wait(host_ns, attempt)?,
                unavailable: self.unavailable(7, failed_hash)?,
            })
        }
    }

    fn start_attempt(
        &mut self,
        previous_epoch: u64,
        completed_attempts: u32,
        host_ns: u64,
    ) -> io::Result<ReconnectingDirectPodState<T, P>> {
        let attempt = completed_attempts
            .checked_add(1)
            .ok_or_else(|| invalid_data("direct-Pod reconnect attempt overflow"))?;
        self.append_event(
            DirectPodReconnectEventKind::AttemptStarted,
            previous_epoch,
            0,
            host_ns,
            attempt,
            0,
            0,
            sha256(b"FORGE-DIRECT-POD-RECONNECT-ATTEMPT-START-V1"),
        )?;
        let deadline_host_ns = host_ns
            .checked_add(self.policy.max_backoff_ns)
            .ok_or_else(|| invalid_data("direct-Pod reconnect candidate deadline overflow"))?;
        match self.factory.open_fresh() {
            Ok((bootstrap, plan_provider)) => Ok(ReconnectingDirectPodState::Candidate {
                backend: Box::new(BootstrappingDirectPodBackend::new(
                    bootstrap,
                    plan_provider,
                    self.deployment_evidence_hash,
                )?),
                previous_transport_epoch: previous_epoch,
                attempt_number: attempt,
                deadline_host_ns,
            }),
            Err(error) => {
                self.record_failure_or_exhaustion(previous_epoch, attempt, host_ns, &error)
            }
        }
    }
}

impl HardwareServiceBackend for ProductionDirectPodReconnectBackend {
    fn status(
        &mut self,
        request_id: u64,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        self.inner.status(request_id, host_monotonic_ns)
    }

    fn submit(
        &mut self,
        request: OperatorRunRequestV1,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        self.inner.submit(request, host_monotonic_ns)
    }
}

impl OwnedHardwareServiceBackend for ProductionDirectPodReconnectBackend {
    fn poll_owner_once(&mut self, host_monotonic_ns: u64) -> io::Result<()> {
        self.inner.poll_owner_once(host_monotonic_ns)
    }

    fn shutdown_owner(&mut self) -> io::Result<()> {
        self.inner.shutdown_owner()
    }
}

impl<T, P, F> HardwareServiceBackend for ReconnectingDirectPodBackend<T, P, F>
where
    T: DirectPodByteTransport,
    P: DirectPodRunPlanProvider,
    F: DirectPodReconnectFactory<T, P>,
{
    fn status(
        &mut self,
        request_id: u64,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        match self
            .state
            .as_mut()
            .ok_or_else(|| invalid_data("reconnect state was lost"))?
        {
            ReconnectingDirectPodState::Active(backend) => {
                backend.status(request_id, host_monotonic_ns)
            }
            ReconnectingDirectPodState::Waiting { unavailable, .. }
            | ReconnectingDirectPodState::Exhausted(unavailable) => {
                unavailable.status(request_id, host_monotonic_ns)
            }
            ReconnectingDirectPodState::Candidate { .. } => self
                .unavailable(8, self.ledger.last_event().unwrap().evidence_hash()?)?
                .status(request_id, host_monotonic_ns),
        }
    }

    fn submit(
        &mut self,
        request: OperatorRunRequestV1,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        match self
            .state
            .as_mut()
            .ok_or_else(|| invalid_data("reconnect state was lost"))?
        {
            ReconnectingDirectPodState::Active(backend) => {
                backend.submit(request, host_monotonic_ns)
            }
            ReconnectingDirectPodState::Waiting { unavailable, .. }
            | ReconnectingDirectPodState::Exhausted(unavailable) => {
                unavailable.submit(request, host_monotonic_ns)
            }
            ReconnectingDirectPodState::Candidate { .. } => self
                .unavailable(8, self.ledger.last_event().unwrap().evidence_hash()?)?
                .submit(request, host_monotonic_ns),
        }
    }
}

impl<T, P, F> OwnedHardwareServiceBackend for ReconnectingDirectPodBackend<T, P, F>
where
    T: DirectPodByteTransport + Send + 'static,
    P: DirectPodRunPlanProvider,
    F: DirectPodReconnectFactory<T, P>,
{
    fn poll_owner_once(&mut self, host_ns: u64) -> io::Result<()> {
        if host_ns == 0
            || (self.last_host_monotonic_ns != 0 && host_ns < self.last_host_monotonic_ns)
        {
            return Err(invalid_input(
                "direct-Pod reconnect owner clock is zero or regressed",
            ));
        }
        self.last_host_monotonic_ns = host_ns;
        let fallback = ReconnectingDirectPodState::Exhausted(
            self.unavailable(10, self.deployment_evidence_hash)?,
        );
        let state = self
            .state
            .replace(fallback)
            .ok_or_else(|| invalid_data("reconnect state was lost"))?;
        let next = match state {
            ReconnectingDirectPodState::Active(mut backend) => {
                if let Err(error) = backend.poll_owner_once(host_ns) {
                    let _ = backend.shutdown_owner();
                    return Err(error);
                }
                let observation = match backend.observation() {
                    Ok(observation) => observation,
                    Err(error) => {
                        let _ = backend.shutdown_owner();
                        return Err(error);
                    }
                };
                match observation {
                    DirectPodBackendObservation::Faulted {
                        last_admitted_transport_epoch,
                        evidence_hash,
                    } => {
                        backend.shutdown_owner()?;
                        let fault_hash = self.append_event(
                            DirectPodReconnectEventKind::TransportFault,
                            last_admitted_transport_epoch,
                            0,
                            host_ns,
                            0,
                            1,
                            0,
                            evidence_hash,
                        )?;
                        ReconnectingDirectPodState::Waiting {
                            previous_transport_epoch: last_admitted_transport_epoch,
                            completed_attempts: 0,
                            next_attempt_host_ns: self.schedule_wait(host_ns, 0)?,
                            unavailable: self.unavailable(6, fault_hash)?,
                        }
                    }
                    _ => ReconnectingDirectPodState::Active(backend),
                }
            }
            waiting @ ReconnectingDirectPodState::Waiting {
                previous_transport_epoch,
                completed_attempts,
                next_attempt_host_ns,
                ..
            } => {
                if host_ns < next_attempt_host_ns {
                    waiting
                } else {
                    self.start_attempt(previous_transport_epoch, completed_attempts, host_ns)?
                }
            }
            ReconnectingDirectPodState::Candidate {
                mut backend,
                previous_transport_epoch,
                attempt_number,
                deadline_host_ns,
            } => {
                if host_ns > deadline_host_ns {
                    backend.shutdown_owner()?;
                    let next = self.record_failure_or_exhaustion(
                        previous_transport_epoch,
                        attempt_number,
                        host_ns,
                        &io::Error::new(
                            io::ErrorKind::TimedOut,
                            "reconnected Pod did not complete capability admission before deadline",
                        ),
                    )?;
                    self.state = Some(next);
                    return Ok(());
                }
                if let Err(error) = backend.poll_owner_once(host_ns) {
                    let _ = backend.shutdown_owner();
                    let next = self.record_failure_or_exhaustion(
                        previous_transport_epoch,
                        attempt_number,
                        host_ns,
                        &error,
                    )?;
                    self.state = Some(next);
                    return Ok(());
                }
                let observation = match backend.observation() {
                    Ok(observation) => observation,
                    Err(error) => {
                        let _ = backend.shutdown_owner();
                        return Err(error);
                    }
                };
                match observation {
                    DirectPodBackendObservation::Ready { transport_epoch }
                        if transport_epoch > previous_transport_epoch =>
                    {
                        let admitted_hash = match self.append_event(
                            DirectPodReconnectEventKind::FreshEpochAdmitted,
                            previous_transport_epoch,
                            transport_epoch,
                            host_ns,
                            attempt_number,
                            0,
                            0,
                            sha256(&transport_epoch.to_le_bytes()),
                        ) {
                            Ok(hash) => hash,
                            Err(error) => {
                                let _ = backend.shutdown_owner();
                                return Err(error);
                            }
                        };
                        let _ = admitted_hash;
                        ReconnectingDirectPodState::Active(backend)
                    }
                    DirectPodBackendObservation::Ready { .. }
                    | DirectPodBackendObservation::Faulted { .. } => {
                        backend.shutdown_owner()?;
                        self.record_failure_or_exhaustion(
                            previous_transport_epoch,
                            attempt_number,
                            host_ns,
                            &invalid_data(
                                "reconnected Pod did not provide a strictly newer admitted epoch",
                            ),
                        )?
                    }
                    DirectPodBackendObservation::Bootstrapping => {
                        ReconnectingDirectPodState::Candidate {
                            backend,
                            previous_transport_epoch,
                            attempt_number,
                            deadline_host_ns,
                        }
                    }
                }
            }
            exhausted @ ReconnectingDirectPodState::Exhausted(_) => exhausted,
        };
        self.state = Some(next);
        Ok(())
    }

    fn shutdown_owner(&mut self) -> io::Result<()> {
        let fallback = ReconnectingDirectPodState::Exhausted(
            self.unavailable(10, self.deployment_evidence_hash)?,
        );
        let state = self
            .state
            .replace(fallback)
            .ok_or_else(|| invalid_data("reconnect state was lost"))?;
        match state {
            ReconnectingDirectPodState::Active(mut backend) => backend.shutdown_owner(),
            ReconnectingDirectPodState::Waiting {
                previous_transport_epoch,
                completed_attempts,
                ..
            } => {
                self.append_event(
                    DirectPodReconnectEventKind::ServiceCancelled,
                    previous_transport_epoch,
                    0,
                    self.last_host_monotonic_ns.max(1),
                    completed_attempts,
                    0,
                    0,
                    sha256(b"FORGE-DIRECT-POD-RECONNECT-SERVICE-CANCELLED-V1"),
                )?;
                Ok(())
            }
            ReconnectingDirectPodState::Candidate {
                mut backend,
                previous_transport_epoch,
                attempt_number,
                ..
            } => {
                backend.shutdown_owner()?;
                self.append_event(
                    DirectPodReconnectEventKind::ServiceCancelled,
                    previous_transport_epoch,
                    0,
                    self.last_host_monotonic_ns.max(1),
                    attempt_number,
                    0,
                    0,
                    sha256(b"FORGE-DIRECT-POD-RECONNECT-SERVICE-CANCELLED-V1"),
                )?;
                Ok(())
            }
            ReconnectingDirectPodState::Exhausted(_) => Ok(()),
        }
    }
}

fn validate_recovery_tree(run_root: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(run_root)? {
        let entry = entry?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(permission_denied(
                "hardware Run recovery refuses linked or reparse-point artifacts",
            ));
        }
        if entry.file_name() == "hardware-ledger" {
            if !metadata.is_dir() {
                return Err(invalid_data(
                    "hardware Run lifecycle evidence is not a directory",
                ));
            }
            for ledger_entry in std::fs::read_dir(entry.path())? {
                let ledger_entry = ledger_entry?;
                let ledger_metadata = std::fs::symlink_metadata(ledger_entry.path())?;
                if !ledger_metadata.is_file()
                    || ledger_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(permission_denied(
                        "hardware Run recovery refuses non-file or linked lifecycle evidence",
                    ));
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectPodBootstrapPoll {
    Pending,
    Connected,
}

struct DirectPodBootstrapInner<T: DirectPodByteTransport> {
    admission: VerifiedFt601Admission,
    preflight: DirectPodProtectedPreflightV1,
    #[cfg(test)]
    legacy_identity_bypass: bool,
    transport: T,
    config: DirectPodRuntimeConfig,
    first_frame: Vec<u8>,
    chunks: Vec<(Vec<u8>, u64)>,
    buffered_chunk_bytes: usize,
    last_host_monotonic_ns: Option<u64>,
}

/// Infers a fresh transport epoch only from the first exact Pod capability
/// message while keeping the already-primed IN queue and every source byte.
/// It never invents an epoch from host time, process identity, or a counter.
pub(crate) struct DirectPodTransportBootstrap<T: DirectPodByteTransport> {
    inner: Option<DirectPodBootstrapInner<T>>,
    connected: Option<PreRunDirectPodConnection<T>>,
    last_host_monotonic_ns: Option<u64>,
    poisoned: bool,
}

impl<T: DirectPodByteTransport> DirectPodTransportBootstrap<T> {
    pub(crate) fn new(
        admission: VerifiedFt601Admission,
        transport: T,
        config: DirectPodRuntimeConfig,
        preflight: DirectPodProtectedPreflightV1,
    ) -> io::Result<Self> {
        Self::new_protected(admission, transport, config, preflight)
    }

    fn new_protected(
        admission: VerifiedFt601Admission,
        mut transport: T,
        config: DirectPodRuntimeConfig,
        preflight: DirectPodProtectedPreflightV1,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        if transport.queued_read_count() != 0 || transport.is_poisoned() {
            return Err(invalid_input(
                "direct-Pod bootstrap requires a fresh exclusive transport",
            ));
        }
        for _ in 0..config.read_depth {
            if let Err(error) = transport.queue_read(config.read_buffer_bytes) {
                let _ = transport.cancel_reads();
                return Err(error);
            }
        }
        if transport.queued_read_count() != config.read_depth {
            let _ = transport.cancel_reads();
            return Err(invalid_data(
                "direct-Pod bootstrap did not establish the fixed read depth",
            ));
        }
        Ok(Self {
            inner: Some(DirectPodBootstrapInner {
                admission,
                preflight,
                #[cfg(test)]
                legacy_identity_bypass: false,
                transport,
                config,
                first_frame: Vec::with_capacity(DEVICE_CAPABILITIES_MESSAGE_LEN),
                chunks: Vec::with_capacity(MAX_BOOTSTRAP_COMPLETION_COUNT),
                buffered_chunk_bytes: 0,
                last_host_monotonic_ns: None,
            }),
            connected: None,
            last_host_monotonic_ns: None,
            poisoned: false,
        })
    }

    #[cfg(test)]
    fn new_legacy_test(
        admission: VerifiedFt601Admission,
        transport: T,
        config: DirectPodRuntimeConfig,
    ) -> io::Result<Self> {
        let policy = crate::dhl_identity_admission::DhlIdentityAdmissionPolicyV1 {
            profile_id: "rhd2132x1".to_owned(),
            expected_descriptor_payload_sha256: [1; 32],
            expected_inventory_payload_sha256: [2; 32],
            expected_device_id: [2; 16],
            expected_config_hash: [3; 32],
            sample_rate_numerator_hz: 30_000,
            sample_rate_denominator: 1,
            approved_channel_layout_id: 0x1020_3040,
            assembly_manifest_hash: [4; 32],
            channel_map_hash: [5; 32],
            ordered_expected_instances: vec![
                crate::dhl_identity_admission::DhlExpectedInstancePolicyV1 {
                    instance_id: 0,
                    exact_driver_abi: 1,
                    exact_capability_flags: crate::dhl_identity_admission::DHL_CAP_STREAM_NEURAL
                        | crate::dhl_identity_admission::DHL_CAP_ELECTRODE_IMPEDANCE,
                    config_hash_prefix: [6; 12],
                },
            ],
        };
        let preflight = DirectPodProtectedPreflightV1::new(policy, [1; 16], [2; 16], [7; 32])?;
        let mut bootstrap = Self::new_protected(admission, transport, config, preflight)?;
        bootstrap.inner.as_mut().unwrap().legacy_identity_bypass = true;
        Ok(bootstrap)
    }

    pub fn poll_once(&mut self, host_monotonic_ns: u64) -> io::Result<DirectPodBootstrapPoll> {
        if self.poisoned {
            return Err(invalid_data("direct-Pod bootstrap is poisoned"));
        }
        if host_monotonic_ns == 0
            || self
                .last_host_monotonic_ns
                .is_some_and(|prior| host_monotonic_ns < prior)
        {
            return self.fail(invalid_input(
                "direct-Pod bootstrap host monotonic clock is zero or regressed",
            ));
        }
        self.last_host_monotonic_ns = Some(host_monotonic_ns);
        if self.connected.is_some() {
            let ready = {
                let connection = self.connected.as_mut().expect("checked above");
                connection
                    .poll_once(host_monotonic_ns)
                    .and_then(|_| connection.preflight_identity_ready(host_monotonic_ns))
            };
            return match ready {
                Ok(true) => Ok(DirectPodBootstrapPoll::Connected),
                Ok(false) => Ok(DirectPodBootstrapPoll::Pending),
                Err(error) => self.fail(error),
            };
        }
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| invalid_data("direct-Pod bootstrap lost exclusive transport"))?;
        if host_monotonic_ns == 0
            || inner
                .last_host_monotonic_ns
                .is_some_and(|prior| host_monotonic_ns < prior)
        {
            return self.fail(invalid_input(
                "direct-Pod bootstrap host monotonic clock is zero or regressed",
            ));
        }
        inner.last_host_monotonic_ns = Some(host_monotonic_ns);
        match inner.transport.poll_next_read() {
            Ok(DirectPodTransportRead::Pending) => {
                if inner.transport.queued_read_count() == 0
                    || inner.transport.queued_read_count() > inner.config.read_depth
                {
                    return self.fail(invalid_data(
                        "direct-Pod bootstrap pending queue contradicts fixed depth",
                    ));
                }
                Ok(DirectPodBootstrapPoll::Pending)
            }
            Ok(DirectPodTransportRead::Idle) => self.fail(invalid_data(
                "direct-Pod bootstrap lost its primed read queue",
            )),
            Err(error) => self.fail(error),
            Ok(DirectPodTransportRead::Complete(bytes)) => {
                let epoch = match Self::observe_completion(inner, bytes, host_monotonic_ns) {
                    Ok(value) => value,
                    Err(error) => return self.fail(error),
                };
                let Some(transport_epoch) = epoch else {
                    return Ok(DirectPodBootstrapPoll::Pending);
                };
                let inner = self
                    .inner
                    .take()
                    .ok_or_else(|| invalid_data("direct-Pod bootstrap transport moved twice"))?;
                #[cfg(test)]
                let connection_result = if inner.legacy_identity_bypass {
                    PreRunDirectPodConnection::from_primed_bootstrap(
                        inner.admission,
                        inner.transport,
                        inner.config,
                        transport_epoch,
                        inner.chunks,
                    )
                } else {
                    PreRunDirectPodConnection::from_primed_bootstrap_protected(
                        inner.admission,
                        inner.transport,
                        inner.config,
                        transport_epoch,
                        inner.preflight,
                        inner.chunks,
                    )
                };
                #[cfg(not(test))]
                let connection_result = PreRunDirectPodConnection::from_primed_bootstrap_protected(
                    inner.admission,
                    inner.transport,
                    inner.config,
                    transport_epoch,
                    inner.preflight,
                    inner.chunks,
                );
                match connection_result {
                    #[allow(unused_mut)]
                    Ok(mut connection) => {
                        #[cfg(test)]
                        if inner.legacy_identity_bypass {
                            if let Err(error) =
                                connection.disable_identity_requirement_for_legacy_test()
                            {
                                let _ = connection.shutdown_owner();
                                self.poisoned = true;
                                return Err(error);
                            }
                        }
                        let ready = match connection.preflight_identity_ready(host_monotonic_ns) {
                            Ok(value) => value,
                            Err(error) => {
                                let _ = connection.shutdown_owner();
                                self.poisoned = true;
                                return Err(error);
                            }
                        };
                        self.connected = Some(connection);
                        if ready {
                            Ok(DirectPodBootstrapPoll::Connected)
                        } else {
                            Ok(DirectPodBootstrapPoll::Pending)
                        }
                    }
                    Err(error) => {
                        self.poisoned = true;
                        Err(error)
                    }
                }
            }
        }
    }

    pub fn into_connection(mut self) -> io::Result<PreRunDirectPodConnection<T>> {
        let Some(connection) = self.connected.as_mut() else {
            let _ = self.shutdown_owner();
            return Err(invalid_input(
                "direct-Pod bootstrap has not received exact device capabilities",
            ));
        };
        let host = self.last_host_monotonic_ns.unwrap_or(0);
        let ready = if host == 0 {
            Ok(false)
        } else {
            connection.preflight_identity_ready(host)
        };
        if !matches!(ready, Ok(true)) {
            let _ = connection.shutdown_owner();
            self.poisoned = true;
            return Err(invalid_input(
                "direct-Pod bootstrap has not completed protected preflight identity evidence",
            ));
        }
        Ok(self.connected.take().expect("checked above"))
    }

    /// Cancels the primed bootstrap without creating a Run or inventing a Pod
    /// command. A later service start must open and admit a fresh connection.
    pub fn shutdown_owner(&mut self) -> io::Result<()> {
        self.poisoned = true;
        if let Some(connection) = self.connected.as_mut() {
            return connection.shutdown_owner();
        }
        match self.inner.as_mut() {
            Some(inner) => inner.transport.cancel_reads(),
            None => Ok(()),
        }
    }

    fn observe_completion(
        inner: &mut DirectPodBootstrapInner<T>,
        bytes: Vec<u8>,
        host_monotonic_ns: u64,
    ) -> io::Result<Option<u64>> {
        if bytes.is_empty() {
            return Err(invalid_data(
                "direct-Pod bootstrap completed an empty IN transfer",
            ));
        }
        if inner.transport.queued_read_count() >= inner.config.read_depth {
            return Err(invalid_data(
                "direct-Pod bootstrap completion did not consume one queued read",
            ));
        }
        let (next_chunk_count, next_chunk_bytes) = next_bootstrap_buffer_usage(
            inner.chunks.len(),
            inner.buffered_chunk_bytes,
            inner.config,
            bytes.len(),
        )?;
        let needed = DEVICE_CAPABILITIES_MESSAGE_LEN.saturating_sub(inner.first_frame.len());
        inner
            .first_frame
            .extend_from_slice(&bytes[..bytes.len().min(needed)]);
        if inner.first_frame.len() >= 12
            && (inner.first_frame.get(4..12) != Some(CONTROL_MAGIC)
                || u32::from_le_bytes(
                    inner.first_frame[0..4]
                        .try_into()
                        .map_err(|_| invalid_data("direct-Pod bootstrap prefix is truncated"))?,
                ) as usize
                    != DEVICE_CAPABILITIES_MESSAGE_LEN)
        {
            return Err(invalid_data(
                "the first direct-Pod frame is not exact DeviceCapabilitiesV1 framing",
            ));
        }
        let epoch = if inner.first_frame.len() == DEVICE_CAPABILITIES_MESSAGE_LEN {
            let decoded = decode_low_speed(&inner.first_frame)
                .map_err(|_| invalid_data("first direct-Pod capability frame is invalid"))?;
            let capabilities = DeviceCapabilitiesV1::decode_body(&decoded.body)
                .map_err(|_| invalid_data("first direct-Pod capability body is invalid"))?;
            if decoded.kind != MessageKind::DeviceCapabilities
                || capabilities.device_id != inner.admission.device_id()
                || capabilities.hardware_protocol_hash != inner.admission.hardware_protocol_hash()
            {
                return Err(permission_denied(
                    "first direct-Pod capability does not match internal verification evidence",
                ));
            }
            Some(decoded.epoch)
        } else {
            None
        };
        inner.chunks.push((bytes, host_monotonic_ns));
        debug_assert_eq!(inner.chunks.len(), next_chunk_count);
        inner.buffered_chunk_bytes = next_chunk_bytes;
        inner.transport.queue_read(inner.config.read_buffer_bytes)?;
        if inner.transport.queued_read_count() != inner.config.read_depth {
            return Err(invalid_data(
                "direct-Pod bootstrap did not restore the fixed read depth",
            ));
        }
        Ok(epoch)
    }

    fn fail<R>(&mut self, error: io::Error) -> io::Result<R> {
        self.poisoned = true;
        if let Some(connection) = self.connected.as_mut() {
            let _ = connection.shutdown_owner();
        }
        if let Some(inner) = self.inner.as_mut() {
            let _ = inner.transport.cancel_reads();
        }
        Err(error)
    }
}

/// Bounds source bytes retained before the first exact capability frame. D3XX
/// already bounds each configured completion, but completed buffers are handed
/// to this owner and retained across requeues, so the fixed async queue alone
/// cannot bound this lifecycle.
fn next_bootstrap_buffer_usage(
    buffered_chunk_count: usize,
    buffered_chunk_bytes: usize,
    config: DirectPodRuntimeConfig,
    completion_bytes: usize,
) -> io::Result<(usize, usize)> {
    let next_chunk_count = buffered_chunk_count
        .checked_add(1)
        .ok_or_else(|| invalid_data("direct-Pod bootstrap completion count overflow"))?;
    if next_chunk_count > MAX_BOOTSTRAP_COMPLETION_COUNT {
        return Err(invalid_data(
            "direct-Pod bootstrap exceeded bounded capability completion count",
        ));
    }
    if completion_bytes > config.read_buffer_bytes {
        return Err(invalid_data(
            "direct-Pod bootstrap completion exceeds configured read buffer",
        ));
    }

    // Before the final completion, at most 95 source bytes can precede the
    // 96-byte capability frame; the final D3XX completion is at most the
    // validated configured read buffer. This keeps retained source bytes
    // bounded even for a transport implementation outside d3xx.rs.
    let max_buffered_bytes = config
        .read_buffer_bytes
        .checked_add(DEVICE_CAPABILITIES_MESSAGE_LEN - 1)
        .ok_or_else(|| invalid_data("direct-Pod bootstrap byte limit overflow"))?;
    let next_chunk_bytes = buffered_chunk_bytes
        .checked_add(completion_bytes)
        .ok_or_else(|| invalid_data("direct-Pod bootstrap buffered-byte overflow"))?;
    if next_chunk_bytes > max_buffered_bytes {
        return Err(invalid_data(
            "direct-Pod bootstrap exceeded bounded capability byte budget",
        ));
    }
    Ok((next_chunk_count, next_chunk_bytes))
}

pub struct DirectPodD3xxBootstrap {
    bootstrap: DirectPodTransportBootstrap<D3xxDevice>,
    plan_provider: ProtectedDirectPodRunPlanProvider,
    configuration: Ft601ConfigurationEvidence,
    descriptors: Ft601UsbDescriptorEvidence,
    library_path: PathBuf,
    library_sha256: Hash32,
    policy_file_sha256: Hash32,
}

impl DirectPodD3xxBootstrap {
    pub fn configuration(&self) -> &Ft601ConfigurationEvidence {
        &self.configuration
    }

    pub fn descriptors(&self) -> &Ft601UsbDescriptorEvidence {
        &self.descriptors
    }

    pub fn library_path(&self) -> &Path {
        &self.library_path
    }

    pub fn library_sha256(&self) -> Hash32 {
        self.library_sha256
    }

    pub fn policy_file_sha256(&self) -> Hash32 {
        self.policy_file_sha256
    }
}

enum BootstrappingDirectPodState<T, P>
where
    T: DirectPodByteTransport,
    P: DirectPodRunPlanProvider,
{
    Bootstrap {
        bootstrap: Box<DirectPodTransportBootstrap<T>>,
        plan_provider: P,
    },
    Ready(Box<PromotableDirectPodBackend<T, P>>),
    Faulted {
        owner: Option<Box<PromotableDirectPodBackend<T, P>>>,
        unavailable: crate::UnavailableHardwareBackend,
        evidence_hash: Hash32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectPodBackendObservation {
    Bootstrapping,
    Ready {
        transport_epoch: u64,
    },
    Faulted {
        last_admitted_transport_epoch: u64,
        evidence_hash: Hash32,
    },
}

/// SCM-owner compatible state machine. Before the first exact capability frame
/// it reports unavailable; after bootstrap it moves the same primed transport
/// into the promotable pre-Run backend. Any bootstrap/transport fault latches
/// unavailable and never reconnects or invents a replacement epoch.
pub(crate) struct BootstrappingDirectPodBackend<T, P>
where
    T: DirectPodByteTransport,
    P: DirectPodRunPlanProvider,
{
    state: Option<BootstrappingDirectPodState<T, P>>,
    deployment_evidence_hash: Hash32,
    last_admitted_transport_epoch: u64,
}

impl<T, P> BootstrappingDirectPodBackend<T, P>
where
    T: DirectPodByteTransport,
    P: DirectPodRunPlanProvider,
{
    pub(crate) fn new(
        mut bootstrap: DirectPodTransportBootstrap<T>,
        plan_provider: P,
        deployment_evidence_hash: Hash32,
    ) -> io::Result<Self> {
        if deployment_evidence_hash == [0; 32] {
            let _ = bootstrap.shutdown_owner();
            return Err(invalid_input(
                "bootstrapping direct-Pod backend requires nonzero deployment evidence",
            ));
        }
        Ok(Self {
            state: Some(BootstrappingDirectPodState::Bootstrap {
                bootstrap: Box::new(bootstrap),
                plan_provider,
            }),
            deployment_evidence_hash,
            last_admitted_transport_epoch: 0,
        })
    }

    pub(crate) fn observation(&self) -> io::Result<DirectPodBackendObservation> {
        match self
            .state
            .as_ref()
            .ok_or_else(|| invalid_data("direct-Pod deployment state was lost"))?
        {
            BootstrappingDirectPodState::Bootstrap { .. } => {
                Ok(DirectPodBackendObservation::Bootstrapping)
            }
            BootstrappingDirectPodState::Ready(backend) => Ok(DirectPodBackendObservation::Ready {
                transport_epoch: backend.transport_epoch()?,
            }),
            BootstrappingDirectPodState::Faulted { evidence_hash, .. } => {
                Ok(DirectPodBackendObservation::Faulted {
                    last_admitted_transport_epoch: self.last_admitted_transport_epoch,
                    evidence_hash: *evidence_hash,
                })
            }
        }
    }

    fn unavailable(&self, detail_code: u32) -> io::Result<crate::UnavailableHardwareBackend> {
        crate::UnavailableHardwareBackend::from_verified_evidence(
            self.deployment_evidence_hash,
            detail_code,
        )
    }

    fn fault_evidence(&self, error: &io::Error) -> Hash32 {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"FORGE-DIRECT-POD-OWNER-FAULT-V1");
        bytes.extend_from_slice(&self.deployment_evidence_hash);
        bytes.push(error_kind_code(error.kind()));
        bytes.extend_from_slice(error.to_string().as_bytes());
        sha256(&bytes)
    }

    fn latch_fault(&mut self, error: &io::Error, detail_code: u32) -> io::Result<()> {
        let evidence_hash = self.fault_evidence(error);
        self.state = Some(BootstrappingDirectPodState::Faulted {
            owner: None,
            unavailable: crate::UnavailableHardwareBackend::from_verified_evidence(
                evidence_hash,
                detail_code,
            )?,
            evidence_hash,
        });
        Ok(())
    }

    fn shutdown_owner_now(&mut self) -> io::Result<()> {
        match self
            .state
            .as_mut()
            .ok_or_else(|| invalid_data("direct-Pod deployment state was lost"))?
        {
            BootstrappingDirectPodState::Bootstrap { bootstrap, .. } => bootstrap.shutdown_owner(),
            BootstrappingDirectPodState::Ready(backend) => backend.shutdown_owner_now(),
            BootstrappingDirectPodState::Faulted { owner, .. } => match owner.as_mut() {
                Some(backend) => backend.shutdown_owner_now(),
                None => Ok(()),
            },
        }
    }
}

impl<T, P> HardwareServiceBackend for BootstrappingDirectPodBackend<T, P>
where
    T: DirectPodByteTransport,
    P: DirectPodRunPlanProvider,
{
    fn status(
        &mut self,
        request_id: u64,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        match self
            .state
            .as_mut()
            .ok_or_else(|| invalid_data("direct-Pod deployment state was lost"))?
        {
            BootstrappingDirectPodState::Bootstrap { .. } => {
                self.unavailable(3)?.status(request_id, host_monotonic_ns)
            }
            BootstrappingDirectPodState::Ready(backend) => {
                backend.status(request_id, host_monotonic_ns)
            }
            BootstrappingDirectPodState::Faulted { unavailable, .. } => {
                unavailable.status(request_id, host_monotonic_ns)
            }
        }
    }

    fn submit(
        &mut self,
        request: OperatorRunRequestV1,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        match self
            .state
            .as_mut()
            .ok_or_else(|| invalid_data("direct-Pod deployment state was lost"))?
        {
            BootstrappingDirectPodState::Bootstrap { .. } => {
                self.unavailable(3)?.submit(request, host_monotonic_ns)
            }
            BootstrappingDirectPodState::Ready(backend) => {
                backend.submit(request, host_monotonic_ns)
            }
            BootstrappingDirectPodState::Faulted { unavailable, .. } => {
                unavailable.submit(request, host_monotonic_ns)
            }
        }
    }
}

impl<T, P> OwnedHardwareServiceBackend for BootstrappingDirectPodBackend<T, P>
where
    T: DirectPodByteTransport + Send + 'static,
    P: DirectPodRunPlanProvider,
{
    fn poll_owner_once(&mut self, host_monotonic_ns: u64) -> io::Result<()> {
        let fallback = BootstrappingDirectPodState::Faulted {
            owner: None,
            unavailable: self.unavailable(10)?,
            evidence_hash: self.deployment_evidence_hash,
        };
        let state = self
            .state
            .replace(fallback)
            .ok_or_else(|| invalid_data("direct-Pod deployment state was lost"))?;
        match state {
            BootstrappingDirectPodState::Bootstrap {
                mut bootstrap,
                plan_provider,
            } => match bootstrap.poll_once(host_monotonic_ns) {
                Ok(DirectPodBootstrapPoll::Pending) => {
                    self.state = Some(BootstrappingDirectPodState::Bootstrap {
                        bootstrap,
                        plan_provider,
                    });
                    Ok(())
                }
                Ok(DirectPodBootstrapPoll::Connected) => {
                    let connection = match bootstrap.into_connection() {
                        Ok(connection) => connection,
                        Err(error) => {
                            // into_connection owns the transport and closes it on every
                            // rejection path; the fallback state was installed before take.
                            self.latch_fault(&error, 4)?;
                            return Ok(());
                        }
                    };
                    match PromotableDirectPodBackend::new(connection, plan_provider) {
                        Ok(backend) => {
                            self.state =
                                Some(BootstrappingDirectPodState::Ready(Box::new(backend)));
                            Ok(())
                        }
                        Err(error) => {
                            // PromotableDirectPodBackend::new closes the moved owner before
                            // exposing this error.
                            self.latch_fault(&error, 4)?;
                            Ok(())
                        }
                    }
                }
                Err(error) => {
                    let _ = bootstrap.shutdown_owner();
                    self.latch_fault(&error, 4)?;
                    Ok(())
                }
            },
            BootstrappingDirectPodState::Ready(mut backend) => {
                self.last_admitted_transport_epoch = match backend.transport_epoch() {
                    Ok(epoch) => epoch,
                    Err(error) => {
                        let _ = backend.shutdown_owner();
                        self.latch_fault(&error, 5)?;
                        return Ok(());
                    }
                };
                match backend.poll_owner_once(host_monotonic_ns) {
                    Ok(()) => {
                        self.state = Some(BootstrappingDirectPodState::Ready(backend));
                        Ok(())
                    }
                    Err(error) => {
                        let _ = backend.shutdown_owner();
                        self.latch_fault(&error, 5)?;
                        Ok(())
                    }
                }
            }
            faulted @ BootstrappingDirectPodState::Faulted { .. } => {
                self.state = Some(faulted);
                Ok(())
            }
        }
    }

    fn shutdown_owner(&mut self) -> io::Result<()> {
        self.shutdown_owner_now()
    }
}

fn error_kind_code(kind: io::ErrorKind) -> u8 {
    match kind {
        io::ErrorKind::NotFound => 1,
        io::ErrorKind::PermissionDenied => 2,
        io::ErrorKind::ConnectionRefused => 3,
        io::ErrorKind::ConnectionReset => 4,
        io::ErrorKind::ConnectionAborted => 5,
        io::ErrorKind::NotConnected => 6,
        io::ErrorKind::AddrInUse => 7,
        io::ErrorKind::AddrNotAvailable => 8,
        io::ErrorKind::BrokenPipe => 9,
        io::ErrorKind::AlreadyExists => 10,
        io::ErrorKind::WouldBlock => 11,
        io::ErrorKind::InvalidInput => 12,
        io::ErrorKind::InvalidData => 13,
        io::ErrorKind::TimedOut => 14,
        io::ErrorKind::WriteZero => 15,
        io::ErrorKind::Interrupted => 16,
        io::ErrorKind::UnexpectedEof => 17,
        io::ErrorKind::OutOfMemory => 18,
        _ => 255,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedDirectPodRunPlanProvider {
    canonical_data_root: PathBuf,
    device_id: Id16,
    pod_id: Id16,
    headstage_id: Id16,
    frozen_config_sha256: Hash32,
    approved_cabline_binding_sha256: Hash32,
}

impl DirectPodRunPlanProvider for ProtectedDirectPodRunPlanProvider {
    fn preflight_authority(
        &self,
    ) -> io::Result<crate::hardware_service::DirectPodPreflightAuthority> {
        crate::hardware_service::DirectPodPreflightAuthority::new(
            self.pod_id,
            self.headstage_id,
            self.approved_cabline_binding_sha256,
        )
    }

    fn plan_for_prepare(&mut self, request: &OperatorRunRequestV1) -> io::Result<DirectPodRunPlan> {
        if request.target_device_id != self.device_id
            || request.frozen_config_hash != self.frozen_config_sha256
        {
            return Err(permission_denied(
                "operator Prepare does not match the protected hardware deployment identity",
            ));
        }
        let run_root = self
            .canonical_data_root
            .join(format!("hardware-run-{}", hex(&request.run_id)));
        DirectPodRunPlan::new(
            run_root,
            request.run_id,
            self.pod_id,
            self.headstage_id,
            self.frozen_config_sha256,
            self.approved_cabline_binding_sha256,
        )
    }
}

pub fn windows_data_root_sha256(path: &Path) -> io::Result<Hash32> {
    let canonical = canonical_data_root(path)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"FORGE-WINDOWS-DATA-ROOT-UTF16LE-V1\0");
    for value in canonical.as_os_str().encode_wide() {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    Ok(sha256(&bytes))
}

fn canonical_data_root(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid_input("hardware data root must be absolute"));
    }
    let canonical = std::fs::canonicalize(path)?;
    if !canonical.is_dir() {
        return Err(invalid_input("hardware data root must be a directory"));
    }
    Ok(canonical)
}

fn normalized_absolute_file(value: &str, label: &'static str) -> io::Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || !path.is_file()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be an existing normalized absolute file"),
        ));
    }
    Ok(path)
}

fn parse_hash32(value: &str) -> io::Result<Hash32> {
    parse_hex::<32>(value, "SHA-256")
}

fn parse_id16(value: &str) -> io::Result<Id16> {
    parse_hex::<16>(value, "identity")
}

fn parse_hex<const N: usize>(value: &str, label: &'static str) -> io::Result<[u8; N]> {
    if value.len() != N * 2 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("hardware policy {label} is not exact hexadecimal"),
        ));
    }
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid_data("hardware policy hexadecimal decode failed"))?;
    }
    Ok(output)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeploymentPolicy {
    schema: String,
    data_root_sha256: String,
    admission_receipt_path: String,
    admission_receipt_sha256: String,
    d3xx_library: RawD3xxLibraryPolicy,
    pod_id: String,
    headstage_id: String,
    frozen_config_sha256: String,
    approved_cabline_binding_sha256: String,
    dhl_catalog_component_inventory_sha256: String,
    dhl_catalog_channel_maps_sha256: String,
    dhl_catalog_product_matrix_sha256: String,
    dhl_catalog_source_bundle_sha256: String,
    dhl_profile_id: String,
    dhl_descriptor_payload_sha256: String,
    dhl_inventory_payload_sha256: String,
    dhl_expected_config_hash: String,
    dhl_sample_rate_numerator_hz: u32,
    dhl_sample_rate_denominator: u32,
    dhl_channel_layout_id: u32,
    dhl_assembly_manifest_hash: String,
    dhl_channel_map_hash: String,
    dhl_ordered_expected_instances: Vec<RawDhlExpectedInstancePolicy>,
    read_buffer_bytes: usize,
    read_depth: usize,
    stream_pipe_bytes: u32,
    pipe_timeout_ms: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDhlExpectedInstancePolicy {
    instance_id: u16,
    exact_driver_abi: u16,
    exact_capability_flags: u32,
    config_hash_prefix: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
enum RawD3xxLibraryPolicy {
    System32,
    Absolute { path: String },
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn permission_denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_protocol_v1::{
        crc32c, encode_low_speed, sha256, CAP_ACK_REPLAY, CAP_GLOBAL_TIME, CAP_STOP_ACK,
        PROTOCOL_HASH,
    };
    use serde_json::json;
    use std::collections::VecDeque;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    use crate::d3xx_admission::{FT601_ADMISSION_CONTRACT_HASH, FT601_ADMISSION_RECEIPT_LEN};
    use crate::dhl_identity_admission::{
        DhlExpectedInstancePolicyV1, DhlIdentityAdmissionPolicyV1, DHL_CAP_ELECTRODE_IMPEDANCE,
        DHL_CAP_STREAM_NEURAL,
    };
    use crate::direct_pod_dhl_identity::DirectPodDhlIdentityCapsuleV1;
    use crate::run::RunCommandKind;
    use crate::{
        DirectPodCablineStatusV1, DirectPodTimeSnapshotV1, CABLINE_REQUIRED_READY_FLAGS,
        DIRECT_POD_CABLINE_MAX_HOST_AGE_NS, TIME_FLAG_GLOBAL_TIME_VALID, TIME_FLAG_POD_READY,
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TestFiles {
        root: PathBuf,
        admission: PathBuf,
        policy: PathBuf,
    }

    impl Drop for TestFiles {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn new_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "forge-hardware-policy-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        root
    }

    fn admission_fixture() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FT601_ADMISSION_RECEIPT_LEN);
        bytes.extend_from_slice(b"FGRD3A60");
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&(FT601_ADMISSION_RECEIPT_LEN as u16).to_le_bytes());
        bytes.extend_from_slice(&crate::d3xx_admission::FT601_PROFILE_BRINGUP_66_MHZ.to_le_bytes());
        bytes.extend_from_slice(&FT601_ADMISSION_CONTRACT_HASH);
        bytes.extend_from_slice(&[1; 16]);
        bytes.extend_from_slice(&[2; 16]);
        let mut serial = [0_u8; 16];
        serial[..14].copy_from_slice(b"FORGEPOD000001");
        bytes.extend_from_slice(&serial);
        bytes.extend_from_slice(&[3; 32]);
        bytes.extend_from_slice(&[4; 32]);
        bytes.extend_from_slice(&[5; 32]);
        bytes.extend_from_slice(&PROTOCOL_HASH);
        bytes.extend_from_slice(&[7; 32]);
        bytes.extend_from_slice(&[6; 32]);
        bytes.extend_from_slice(&100_u64.to_le_bytes());
        bytes.extend_from_slice(&200_u64.to_le_bytes());
        bytes.extend_from_slice(&[0; 12]);
        let checksum = crc32c(&bytes);
        bytes.extend_from_slice(&checksum.to_le_bytes());
        bytes
    }

    fn write_new(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn policy_fixture(extra: Option<(&str, serde_json::Value)>) -> (TestFiles, Vec<u8>) {
        let root = new_root();
        let admission = root.join("admission.bin");
        let admission_bytes = admission_fixture();
        write_new(&admission, &admission_bytes);
        let catalog_hashes = embedded_source_hashes_v1();
        let mut value = json!({
            "schema": DIRECT_POD_DEPLOYMENT_POLICY_SCHEMA,
            "data_root_sha256": hex(&windows_data_root_sha256(&root).unwrap()),
            "admission_receipt_path": admission,
            "admission_receipt_sha256": hex(&Sha256::digest(&admission_bytes)),
            "d3xx_library": {"source": "system32"},
            "pod_id": hex(&[7; 16]),
            "headstage_id": hex(&[8; 16]),
            "frozen_config_sha256": hex(&[9; 32]),
            "approved_cabline_binding_sha256": hex(&approved_cabline_binding_sha256()),
            "dhl_catalog_component_inventory_sha256": hex(&catalog_hashes.component_inventory_sha256),
            "dhl_catalog_channel_maps_sha256": hex(&catalog_hashes.channel_maps_sha256),
            "dhl_catalog_product_matrix_sha256": hex(&catalog_hashes.product_matrix_sha256),
            "dhl_catalog_source_bundle_sha256": hex(&catalog_hashes.bundle_sha256),
            "dhl_profile_id": "rhd2132x1",
            "dhl_descriptor_payload_sha256": hex(&[10; 32]),
            "dhl_inventory_payload_sha256": hex(&[11; 32]),
            "dhl_expected_config_hash": hex(&[12; 32]),
            "dhl_sample_rate_numerator_hz": 30000,
            "dhl_sample_rate_denominator": 1,
            "dhl_channel_layout_id": 0x10203040_u32,
            "dhl_assembly_manifest_hash": hex(&[13; 32]),
            "dhl_channel_map_hash": hex(&[14; 32]),
            "dhl_ordered_expected_instances": [{
                "instance_id": 0,
                "exact_driver_abi": 1,
                "exact_capability_flags": crate::dhl_identity_admission::DHL_CAP_STREAM_NEURAL | crate::dhl_identity_admission::DHL_CAP_ELECTRODE_IMPEDANCE,
                "config_hash_prefix": hex(&[15; 12])
            }],
            "read_buffer_bytes": 256 * 1024,
            "read_depth": 16,
            "stream_pipe_bytes": 4 * 1024 * 1024,
            "pipe_timeout_ms": 1000
        });
        if let Some((key, replacement)) = extra {
            value
                .as_object_mut()
                .unwrap()
                .insert(key.to_owned(), replacement);
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        let policy = root.join("policy.json");
        write_new(&policy, &bytes);
        (
            TestFiles {
                root,
                admission,
                policy,
            },
            bytes,
        )
    }

    struct TestTransport {
        reads: VecDeque<DirectPodTransportRead>,
        queued: usize,
        poisoned: bool,
        cancelled: Arc<AtomicBool>,
        writes: Vec<Vec<u8>>,
        write_count: Arc<AtomicU64>,
        fail_when_empty: bool,
    }

    impl TestTransport {
        fn new(reads: impl IntoIterator<Item = DirectPodTransportRead>) -> Self {
            Self {
                reads: reads.into_iter().collect(),
                queued: 0,
                poisoned: false,
                cancelled: Arc::new(AtomicBool::new(false)),
                writes: Vec::new(),
                write_count: Arc::new(AtomicU64::new(0)),
                fail_when_empty: false,
            }
        }

        fn disconnect_after_reads(mut self) -> Self {
            self.fail_when_empty = true;
            self
        }

        fn cancellation_flag(&self) -> Arc<AtomicBool> {
            Arc::clone(&self.cancelled)
        }

        fn write_count_flag(&self) -> Arc<AtomicU64> {
            Arc::clone(&self.write_count)
        }
    }

    impl DirectPodByteTransport for TestTransport {
        fn queue_read(&mut self, _buffer_bytes: usize) -> io::Result<()> {
            if self.poisoned {
                return Err(io::Error::other("test transport poisoned"));
            }
            self.queued += 1;
            Ok(())
        }

        fn queued_read_count(&self) -> usize {
            self.queued
        }

        fn poll_next_read(&mut self) -> io::Result<DirectPodTransportRead> {
            let read = match self.reads.pop_front() {
                Some(read) => read,
                None if self.fail_when_empty => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "synthetic Pod disconnect",
                    ));
                }
                None => DirectPodTransportRead::Pending,
            };
            if matches!(read, DirectPodTransportRead::Complete(_)) {
                self.queued = self.queued.saturating_sub(1);
            }
            Ok(read)
        }

        fn write_control(&mut self, message: &[u8]) -> io::Result<()> {
            self.writes.push(message.to_vec());
            self.write_count.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn cancel_reads(&mut self) -> io::Result<()> {
            self.queued = 0;
            self.poisoned = true;
            self.cancelled.store(true, Ordering::Release);
            Ok(())
        }

        fn is_poisoned(&self) -> bool {
            self.poisoned
        }
    }

    struct FailingPreflightProvider;

    impl DirectPodRunPlanProvider for FailingPreflightProvider {
        fn preflight_authority(
            &self,
        ) -> io::Result<crate::hardware_service::DirectPodPreflightAuthority> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic protected preflight authority rejection",
            ))
        }

        fn plan_for_prepare(
            &mut self,
            _request: &OperatorRunRequestV1,
        ) -> io::Result<DirectPodRunPlan> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic protected plan rejection",
            ))
        }
    }

    fn capability(epoch: u64) -> Vec<u8> {
        encode_low_speed(
            0,
            1,
            epoch,
            &DeviceCapabilitiesV1 {
                device_id: [2; 16],
                transport: 1,
                max_pods: 1,
                max_channels_per_pod: 256,
                sample_format_mask: 1,
                min_sample_rate_hz: 30_000,
                max_sample_rate_hz: 30_000,
                stim_kind: 0,
                stim_channels: 0,
                max_sample_block_us: 1_000,
                capability_flags: CAP_ACK_REPLAY | CAP_GLOBAL_TIME | CAP_STOP_ACK,
                runtime_safety_flags: 0,
                hardware_protocol_hash: PROTOCOL_HASH,
            },
        )
        .unwrap()
    }

    fn cabline_status(epoch: u64) -> DirectPodCablineStatusV1 {
        DirectPodCablineStatusV1 {
            device_id: [2; 16],
            pod_id: [7; 16],
            headstage_id: [8; 16],
            transport_epoch: epoch,
            status_sequence: 1,
            global_time_ns: 1_000,
            headstage_boot_id: 1,
            next_dhl_sequence: 1,
            source_id: 1,
            state_flags: CABLINE_REQUIRED_READY_FLAGS,
            symbol_error_count: 0,
            crc_error_count: 0,
            sequence_error_count: 0,
            packet_drop_count: 0,
            receiver_overflow_count: 0,
            relock_count: 0,
            headstage_config_hash: [14; 32],
            descriptor_hash: [15; 32],
            inventory_hash: [16; 32],
            assembly_manifest_hash: [17; 32],
            channel_map_hash: [18; 32],
        }
    }

    fn approved_cabline_binding_sha256() -> Hash32 {
        cabline_status(1).configuration_binding_hash()
    }

    fn time_snapshot(epoch: u64) -> Vec<u8> {
        let mut bytes = DirectPodTimeSnapshotV1 {
            device_id: [2; 16],
            transport_epoch: epoch,
            status_sequence: 1,
            global_time_ns: 1_000,
            sample_counter: 0,
            frame_counter: 0,
            runtime_flags: TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY,
            hardware_state_hash: [13; 32],
        }
        .encode()
        .unwrap()
        .to_vec();
        bytes.extend_from_slice(&cabline_status(epoch).encode().unwrap());
        bytes
    }

    fn dhl_wire(packet_type: u8, sequence: u64, payload: &[u8]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(40 + payload.len() + 4);
        wire.push(1);
        wire.push(packet_type);
        wire.extend_from_slice(&0_u16.to_le_bytes());
        wire.extend_from_slice(&40_u16.to_le_bytes());
        wire.extend_from_slice(&0_u16.to_le_bytes());
        wire.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        wire.extend_from_slice(&1_u32.to_le_bytes());
        wire.extend_from_slice(&1_u64.to_le_bytes());
        wire.extend_from_slice(&sequence.to_le_bytes());
        wire.extend_from_slice(&sequence.to_le_bytes());
        wire.extend_from_slice(payload);
        wire.extend_from_slice(&crc32c(&wire).to_le_bytes());
        wire
    }

    fn refresh_dhl_crc(wire: &mut [u8]) {
        let footer_offset = wire.len() - 4;
        let crc = crc32c(&wire[..footer_offset]);
        wire[footer_offset..].copy_from_slice(&crc.to_le_bytes());
    }

    fn protected_identity_fixture(
        epoch: u64,
    ) -> (
        DirectPodProtectedPreflightV1,
        Vec<u8>,
        DirectPodCablineStatusV1,
        Vec<u8>,
    ) {
        let mut descriptor = vec![0_u8; 96];
        descriptor[0..2].copy_from_slice(&1_u16.to_le_bytes());
        descriptor[2..4].copy_from_slice(&96_u16.to_le_bytes());
        descriptor[4] = 1;
        descriptor[5] = 1;
        descriptor[8..10].copy_from_slice(&32_u16.to_le_bytes());
        descriptor[10..12].copy_from_slice(&1_u16.to_le_bytes());
        descriptor[12..16].copy_from_slice(&30_000_u32.to_le_bytes());
        descriptor[16..20].copy_from_slice(&1_u32.to_le_bytes());
        descriptor[20..24].copy_from_slice(&25_000_000_u32.to_le_bytes());
        descriptor[28..44].copy_from_slice(&[8; 16]);
        descriptor[44..76].copy_from_slice(&[12; 32]);
        descriptor[76..92].copy_from_slice(&[0x33; 16]);

        let mut inventory = vec![0_u8; 108];
        inventory[0..2].copy_from_slice(&1_u16.to_le_bytes());
        inventory[2..4].copy_from_slice(&76_u16.to_le_bytes());
        inventory[4..6].copy_from_slice(&32_u16.to_le_bytes());
        inventory[6..8].copy_from_slice(&1_u16.to_le_bytes());
        inventory[8..12].copy_from_slice(&1_u32.to_le_bytes());
        inventory[12..44].copy_from_slice(&[13; 32]);
        inventory[44..76].copy_from_slice(&[14; 32]);
        inventory[76..78].copy_from_slice(&0_u16.to_le_bytes());
        inventory[78] = 1;
        inventory[79] = 2;
        inventory[80..84].copy_from_slice(&0x0001_0001_u32.to_le_bytes());
        inventory[84..86].copy_from_slice(&0_u16.to_le_bytes());
        inventory[86..88].copy_from_slice(&32_u16.to_le_bytes());
        inventory[88..90].copy_from_slice(&0_u16.to_le_bytes());
        inventory[90..92].copy_from_slice(&1_u16.to_le_bytes());
        inventory[92..96]
            .copy_from_slice(&(DHL_CAP_STREAM_NEURAL | DHL_CAP_ELECTRODE_IMPEDANCE).to_le_bytes());
        inventory[96..108].copy_from_slice(&[15; 12]);

        let descriptor_hash = sha256(&descriptor);
        let inventory_hash = sha256(&inventory);
        let capsule = DirectPodDhlIdentityCapsuleV1 {
            device_id: [2; 16],
            pod_id: [7; 16],
            headstage_id: [8; 16],
            transport_epoch: epoch,
            descriptor_wire: dhl_wire(1, 1, &descriptor),
            inventory_wire: dhl_wire(9, 2, &inventory),
        }
        .encode()
        .unwrap();
        let status = DirectPodCablineStatusV1 {
            device_id: [2; 16],
            pod_id: [7; 16],
            headstage_id: [8; 16],
            transport_epoch: epoch,
            status_sequence: 1,
            global_time_ns: 1_000,
            headstage_boot_id: 1,
            next_dhl_sequence: 3,
            source_id: 1,
            state_flags: CABLINE_REQUIRED_READY_FLAGS,
            symbol_error_count: 0,
            crc_error_count: 0,
            sequence_error_count: 0,
            packet_drop_count: 0,
            receiver_overflow_count: 0,
            relock_count: 0,
            headstage_config_hash: [12; 32],
            descriptor_hash,
            inventory_hash,
            assembly_manifest_hash: [13; 32],
            channel_map_hash: [14; 32],
        };
        let policy = DhlIdentityAdmissionPolicyV1 {
            profile_id: "rhd2132x1".to_owned(),
            expected_descriptor_payload_sha256: descriptor_hash,
            expected_inventory_payload_sha256: inventory_hash,
            expected_device_id: [8; 16],
            expected_config_hash: [12; 32],
            sample_rate_numerator_hz: 30_000,
            sample_rate_denominator: 1,
            approved_channel_layout_id: 0x1020_3040,
            assembly_manifest_hash: [13; 32],
            channel_map_hash: [14; 32],
            ordered_expected_instances: vec![DhlExpectedInstancePolicyV1 {
                instance_id: 0,
                exact_driver_abi: 1,
                exact_capability_flags: DHL_CAP_STREAM_NEURAL | DHL_CAP_ELECTRODE_IMPEDANCE,
                config_hash_prefix: [15; 12],
            }],
        };
        let preflight = DirectPodProtectedPreflightV1::new(
            policy,
            [7; 16],
            [8; 16],
            status.configuration_binding_hash(),
        )
        .unwrap();
        let time = DirectPodTimeSnapshotV1 {
            device_id: [2; 16],
            transport_epoch: epoch,
            status_sequence: 1,
            global_time_ns: 1_000,
            sample_counter: 0,
            frame_counter: 0,
            runtime_flags: TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY,
            hardware_state_hash: [0x66; 32],
        }
        .encode()
        .unwrap()
        .to_vec();
        (preflight, capsule, status, time)
    }

    fn protected_time(epoch: u64, sequence: u64, global_time_ns: u64, flags: u32) -> Vec<u8> {
        DirectPodTimeSnapshotV1 {
            device_id: [2; 16],
            transport_epoch: epoch,
            status_sequence: sequence,
            global_time_ns,
            sample_counter: sequence,
            frame_counter: sequence,
            runtime_flags: flags,
            hardware_state_hash: [0x66; 32],
        }
        .encode()
        .unwrap()
        .to_vec()
    }

    enum TestReconnectStep {
        OpenFail,
        Epoch(u64),
        ProtectedEpoch { epoch: u64, include_identity: bool },
    }

    struct TestReconnectFactory {
        admission: VerifiedFt601Admission,
        provider: ProtectedDirectPodRunPlanProvider,
        steps: VecDeque<TestReconnectStep>,
    }

    impl DirectPodReconnectFactory<TestTransport, ProtectedDirectPodRunPlanProvider>
        for TestReconnectFactory
    {
        fn open_fresh(
            &mut self,
        ) -> io::Result<(
            DirectPodTransportBootstrap<TestTransport>,
            ProtectedDirectPodRunPlanProvider,
        )> {
            match self.steps.pop_front().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no synthetic Pod is available")
            })? {
                TestReconnectStep::OpenFail => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "synthetic D3XX open failed",
                )),
                TestReconnectStep::Epoch(epoch) => {
                    let mut bytes = capability(epoch);
                    bytes.extend_from_slice(&time_snapshot(epoch));
                    Ok((
                        DirectPodTransportBootstrap::new_legacy_test(
                            self.admission.clone(),
                            TestTransport::new([DirectPodTransportRead::Complete(bytes)]),
                            DirectPodRuntimeConfig::default(),
                        )?,
                        self.provider.clone(),
                    ))
                }
                TestReconnectStep::ProtectedEpoch {
                    epoch,
                    include_identity,
                } => {
                    let (preflight, capsule, status, time) = protected_identity_fixture(epoch);
                    let mut provider = self.provider.clone();
                    provider.approved_cabline_binding_sha256 = status.configuration_binding_hash();
                    let mut bytes = capability(epoch);
                    if include_identity {
                        bytes.extend_from_slice(&capsule);
                    }
                    bytes.extend_from_slice(&time);
                    bytes.extend_from_slice(&status.encode().unwrap());
                    let reads = if include_identity {
                        vec![DirectPodTransportRead::Complete(bytes)]
                    } else {
                        vec![
                            DirectPodTransportRead::Complete(bytes),
                            // A later malformed completion lets the reconnect
                            // owner abandon this still-pending candidate.
                            DirectPodTransportRead::Complete(Vec::new()),
                        ]
                    };
                    Ok((
                        DirectPodTransportBootstrap::new(
                            self.admission.clone(),
                            TestTransport::new(reads),
                            DirectPodRuntimeConfig::default(),
                            preflight,
                        )?,
                        provider,
                    ))
                }
            }
        }
    }

    fn test_reconnect_owner(
        verified: &VerifiedDirectPodDeploymentPolicy,
        root: &Path,
        minimum_epoch: u64,
        steps: impl IntoIterator<Item = TestReconnectStep>,
        policy: DirectPodReconnectPolicy,
    ) -> ReconnectingDirectPodBackend<
        TestTransport,
        ProtectedDirectPodRunPlanProvider,
        TestReconnectFactory,
    > {
        let deployment = verified.evidence_hash();
        let ledger = DirectPodReconnectLedger::open(
            root.join("test-reconnect-ledger"),
            verified.admission().device_id(),
            deployment,
        )
        .unwrap();
        ReconnectingDirectPodBackend::new_waiting(
            TestReconnectFactory {
                admission: verified.admission().clone(),
                provider: verified.run_plan_provider(),
                steps: steps.into_iter().collect(),
            },
            ledger,
            policy,
            deployment,
            [0x55; 16],
            minimum_epoch,
        )
        .unwrap()
    }

    #[test]
    fn exact_policy_receipt_root_and_run_identity_are_bound() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        assert_eq!(verified.admission().device_id(), [2; 16]);
        assert_eq!(verified.runtime_config(), DirectPodRuntimeConfig::default());
        assert_eq!(verified.stream_pipe_bytes(), 4 * 1024 * 1024);
        assert_eq!(verified.pipe_timeout_ms(), 1000);
        assert_eq!(verified.d3xx_library(), &D3xxLibraryPolicy::System32);
        assert_eq!(
            verified.approved_cabline_binding_sha256(),
            approved_cabline_binding_sha256()
        );
        assert_eq!(verified.dhl_identity_policy().profile_id, "rhd2132x1");
        assert_eq!(
            verified.dhl_identity_policy().approved_channel_layout_id,
            0x1020_3040
        );
        assert_ne!(
            verified.dhl_identity_policy().approved_channel_layout_id,
            1,
            "channel layout is a protected Host identity, not board_profile_id"
        );
        assert_eq!(
            verified.dhl_catalog_source_hashes(),
            embedded_source_hashes_v1()
        );
        let evidence_hash = verified.evidence_hash();
        assert_ne!(evidence_hash, [0; 32]);
        let mut evidence_bytes = Vec::new();
        evidence_bytes.extend_from_slice(b"FORGE-DIRECT-POD-DEPLOYMENT-EVIDENCE-V4");
        evidence_bytes.extend_from_slice(&verified.policy_file_sha256);
        evidence_bytes.extend_from_slice(&verified.admission.receipt_file_sha256());
        evidence_bytes.extend_from_slice(&verified.admission.device_id());
        evidence_bytes.extend_from_slice(&verified.pod_id);
        evidence_bytes.extend_from_slice(&verified.headstage_id);
        evidence_bytes.extend_from_slice(&verified.frozen_config_sha256);
        evidence_bytes.extend_from_slice(&verified.approved_cabline_binding_sha256);
        evidence_bytes.extend_from_slice(&verified.dhl_catalog_source_hashes.bundle_sha256);
        evidence_bytes.extend_from_slice(
            &verified
                .dhl_identity_policy
                .expected_descriptor_payload_sha256,
        );
        evidence_bytes.extend_from_slice(
            &verified
                .dhl_identity_policy
                .expected_inventory_payload_sha256,
        );
        evidence_bytes.extend_from_slice(&verified.dhl_identity_policy.expected_config_hash);
        let layout_offset = evidence_bytes.len();
        evidence_bytes.extend_from_slice(&0x1020_3040_u32.to_le_bytes());
        assert_eq!(evidence_hash, sha256(&evidence_bytes));
        evidence_bytes[layout_offset..].copy_from_slice(&0x1020_3041_u32.to_le_bytes());
        assert_ne!(evidence_hash, sha256(&evidence_bytes));

        let mut provider = verified.run_plan_provider();
        let request = OperatorRunRequestV1 {
            request_id: 1,
            epoch: 77,
            command: RunCommandKind::Prepare,
            relative_deadline_ms: 100,
            run_id: [10; 16],
            target_device_id: [2; 16],
            frozen_config_hash: [9; 32],
            expected_hardware_state_hash: [11; 32],
        };
        let plan = provider.plan_for_prepare(&request).unwrap();
        assert_eq!(plan.run_id(), [10; 16]);
        assert_eq!(plan.pod_id(), [7; 16]);
        assert_eq!(plan.headstage_id(), [8; 16]);
        assert_eq!(
            plan.approved_cabline_binding_sha256(),
            approved_cabline_binding_sha256()
        );
        assert_eq!(
            plan.run_root(),
            files
                .root
                .canonicalize()
                .unwrap()
                .join(format!("hardware-run-{}", hex(&[10; 16])))
        );
        let mut wrong = request;
        wrong.target_device_id = [12; 16];
        assert_eq!(
            provider.plan_for_prepare(&wrong).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(files.admission.is_file());
    }

    #[test]
    fn policy_hash_root_schema_unknown_fields_and_queue_shape_fail_closed() {
        let (files, bytes) = policy_fixture(None);
        let wrong_hash =
            ProtectedDirectPodPolicyReference::new(&files.policy, [1; 32], [6; 32]).unwrap();
        assert_eq!(
            VerifiedDirectPodDeploymentPolicy::load(&wrong_hash, &files.root, 150)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let good = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let other_root = new_root();
        assert_eq!(
            VerifiedDirectPodDeploymentPolicy::load(&good, &other_root, 150)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::remove_dir(other_root).unwrap();

        for (key, value) in [
            ("unexpected", json!(1)),
            ("stream_pipe_bytes", json!(4096)),
            ("schema", json!("forge.wrong")),
            ("schema", json!("forge.direct-pod-deployment-policy.v1")),
            ("schema", json!("forge.direct-pod-deployment-policy.v2")),
            ("schema", json!("forge.direct-pod-deployment-policy.v3")),
            ("approved_cabline_binding_sha256", json!(hex(&[0; 32]))),
        ] {
            let (changed_files, changed_bytes) = policy_fixture(Some((key, value)));
            let changed = ProtectedDirectPodPolicyReference::new(
                &changed_files.policy,
                Sha256::digest(&changed_bytes).into(),
                [6; 32],
            )
            .unwrap();
            assert!(
                VerifiedDirectPodDeploymentPolicy::load(&changed, &changed_files.root, 150)
                    .is_err()
            );
        }

        let (missing_files, missing_bytes) = policy_fixture(None);
        let mut missing_value: serde_json::Value = serde_json::from_slice(&missing_bytes).unwrap();
        missing_value
            .as_object_mut()
            .unwrap()
            .remove("dhl_channel_layout_id");
        let missing_bytes = replace_policy_json(&missing_files, missing_value);
        let missing_reference = ProtectedDirectPodPolicyReference::new(
            &missing_files.policy,
            Sha256::digest(&missing_bytes).into(),
            [6; 32],
        )
        .unwrap();
        assert_eq!(
            VerifiedDirectPodDeploymentPolicy::load(&missing_reference, &missing_files.root, 150,)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let (small_files, _) = policy_fixture(None);
        let mut small_value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&small_files.policy).unwrap()).unwrap();
        let small_object = small_value.as_object_mut().unwrap();
        small_object.insert("read_buffer_bytes".to_owned(), json!(1_024));
        small_object.insert("read_depth".to_owned(), json!(2));
        small_object.insert("stream_pipe_bytes".to_owned(), json!(2_048));
        let small_bytes = replace_policy_json(&small_files, small_value);
        let small_reference = ProtectedDirectPodPolicyReference::new(
            &small_files.policy,
            Sha256::digest(&small_bytes).into(),
            [6; 32],
        )
        .unwrap();
        assert_eq!(
            VerifiedDirectPodDeploymentPolicy::load(&small_reference, &small_files.root, 150,)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    fn replace_policy_json(files: &TestFiles, value: serde_json::Value) -> Vec<u8> {
        let bytes = serde_json::to_vec(&value).unwrap();
        std::fs::remove_file(&files.policy).unwrap();
        write_new(&files.policy, &bytes);
        bytes
    }

    #[test]
    fn v4_dhl_policy_and_embedded_catalog_binding_fail_closed() {
        for (key, replacement) in [
            (
                "dhl_catalog_component_inventory_sha256",
                json!("4b7350207feffd07c5674865248bf639575eceb5b04c1e097db5cfe5aa139bcd"),
            ),
            ("dhl_catalog_channel_maps_sha256", json!(hex(&[1; 32]))),
            ("dhl_catalog_product_matrix_sha256", json!(hex(&[2; 32]))),
            (
                "dhl_catalog_source_bundle_sha256",
                json!("aada3bc8e4300689d4fbd75324b974d5bd35f1720289118687241237f4118179"),
            ),
            ("dhl_profile_id", json!("unknown-profile")),
            ("dhl_profile_id", json!("rhd2132x2")),
            ("dhl_descriptor_payload_sha256", json!(hex(&[0; 32]))),
            ("dhl_inventory_payload_sha256", json!(hex(&[0; 32]))),
            ("dhl_expected_config_hash", json!(hex(&[0; 32]))),
            ("dhl_sample_rate_numerator_hz", json!(0)),
            ("dhl_sample_rate_denominator", json!(0)),
            ("dhl_channel_layout_id", json!(0)),
        ] {
            let (files, bytes) = policy_fixture(Some((key, replacement)));
            let reference = ProtectedDirectPodPolicyReference::new(
                &files.policy,
                Sha256::digest(&bytes).into(),
                [6; 32],
            )
            .unwrap();
            assert!(
                VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).is_err(),
                "{key}"
            );
        }

        for (field, replacement) in [
            ("instance_id", json!(1)),
            ("exact_driver_abi", json!(2)),
            (
                "exact_capability_flags",
                json!(crate::dhl_identity_admission::DHL_CAP_STREAM_NEURAL),
            ),
            ("config_hash_prefix", json!(hex(&[0; 12]))),
            ("unknown", json!(1)),
        ] {
            let (files, bytes) = policy_fixture(None);
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            value["dhl_ordered_expected_instances"][0][field] = replacement;
            let changed = replace_policy_json(&files, value);
            let reference = ProtectedDirectPodPolicyReference::new(
                &files.policy,
                Sha256::digest(&changed).into(),
                [6; 32],
            )
            .unwrap();
            assert!(
                VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn protected_reference_requires_all_nonzero_exact_values() {
        let (files, bytes) = policy_fixture(None);
        let hash = hex(&Sha256::digest(&bytes));
        assert!(
            ProtectedDirectPodPolicyReference::from_hex(&files.policy, &hash, &hex(&[6; 32]))
                .is_ok()
        );
        assert!(
            ProtectedDirectPodPolicyReference::from_hex(&files.policy, "00", &hex(&[6; 32]))
                .is_err()
        );
        assert!(ProtectedDirectPodPolicyReference::new(&files.policy, [0; 32], [6; 32]).is_err());
        assert!(ProtectedDirectPodPolicyReference::new(&files.policy, [1; 32], [0; 32]).is_err());
    }

    #[test]
    fn bootstrap_takes_epoch_from_fragmented_capability_and_preserves_primed_bytes() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let capability = capability(77);
        let split = capability.len() / 2;
        let mut tail = capability[split..].to_vec();
        tail.extend_from_slice(&time_snapshot(77));
        let transport = TestTransport::new([
            DirectPodTransportRead::Complete(capability[..split].to_vec()),
            DirectPodTransportRead::Complete(tail),
        ]);
        let mut bootstrap = DirectPodTransportBootstrap::new_legacy_test(
            verified.admission().clone(),
            transport,
            DirectPodRuntimeConfig::default(),
        )
        .unwrap();
        assert_eq!(
            bootstrap.poll_once(100).unwrap(),
            DirectPodBootstrapPoll::Pending
        );
        assert_eq!(
            bootstrap.poll_once(101).unwrap(),
            DirectPodBootstrapPoll::Connected
        );
        assert_eq!(
            bootstrap.poll_once(102).unwrap(),
            DirectPodBootstrapPoll::Connected
        );
        let connection = bootstrap.into_connection().unwrap();
        let snapshot = connection.snapshot();
        assert_eq!(snapshot.stream.transport_epoch, 77);
        assert!(snapshot.control.capability_admitted);
        assert_eq!(snapshot.hardware_time.latest.unwrap().transport_epoch, 77);
        assert_eq!(snapshot.completed_reads, 2);
        assert_eq!(
            snapshot.queued_reads,
            DirectPodRuntimeConfig::default().read_depth
        );
    }

    #[test]
    fn protected_bootstrap_requires_admitted_capsule_and_bound_time_cabline_evidence() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let admission = VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150)
            .unwrap()
            .admission()
            .clone();

        for order in [
            [0_usize, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let epoch = 77;
            let (preflight, capsule, status, time) = protected_identity_fixture(epoch);
            let evidence = [capsule, time, status.encode().unwrap().to_vec()];
            let mut reads = vec![DirectPodTransportRead::Complete(capability(epoch))];
            reads.extend(
                order
                    .into_iter()
                    .map(|index| DirectPodTransportRead::Complete(evidence[index].clone())),
            );
            let mut bootstrap = DirectPodTransportBootstrap::new(
                admission.clone(),
                TestTransport::new(reads),
                DirectPodRuntimeConfig::default(),
                preflight,
            )
            .unwrap();
            for now in 1..=3 {
                assert_eq!(
                    bootstrap.poll_once(now).unwrap(),
                    DirectPodBootstrapPoll::Pending,
                    "identity evidence must not be Ready before all three inputs"
                );
            }
            assert_eq!(
                bootstrap.poll_once(4).unwrap(),
                DirectPodBootstrapPoll::Connected
            );
            let connection = bootstrap.into_connection().unwrap();
            assert!(connection.preflight_identity_ready(4).unwrap());
        }
    }

    #[test]
    fn protected_bootstrap_capsule_mutation_and_missing_evidence_fail_closed() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let admission = VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150)
            .unwrap()
            .admission()
            .clone();
        let epoch = 77;
        let (preflight, capsule, _status, _time) = protected_identity_fixture(epoch);
        let mut mutated = capsule;
        let last = mutated.len() - 1;
        mutated[last] ^= 1;
        let transport = TestTransport::new([
            DirectPodTransportRead::Complete(capability(epoch)),
            DirectPodTransportRead::Complete(mutated),
        ]);
        let cancellation = transport.cancellation_flag();
        let mut bootstrap = DirectPodTransportBootstrap::new(
            admission.clone(),
            transport,
            DirectPodRuntimeConfig::default(),
            preflight,
        )
        .unwrap();
        assert_eq!(
            bootstrap.poll_once(1).unwrap(),
            DirectPodBootstrapPoll::Pending
        );
        assert!(bootstrap.poll_once(2).is_err());
        assert!(cancellation.load(Ordering::Acquire));
        assert!(bootstrap.poll_once(3).is_err());
        assert!(bootstrap.into_connection().is_err());

        let (preflight, _capsule, _status, _time) = protected_identity_fixture(epoch + 1);
        let mut incomplete = DirectPodTransportBootstrap::new(
            admission,
            TestTransport::new([DirectPodTransportRead::Complete(capability(epoch + 1))]),
            DirectPodRuntimeConfig::default(),
            preflight,
        )
        .unwrap();
        assert_eq!(
            incomplete.poll_once(1).unwrap(),
            DirectPodBootstrapPoll::Pending
        );
        assert!(incomplete.into_connection().is_err());
    }

    #[test]
    fn promotable_constructor_cancels_owner_when_preflight_provider_rejects() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let admission = VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150)
            .unwrap()
            .admission()
            .clone();
        let epoch = 77;
        let (preflight, capsule, status, time) = protected_identity_fixture(epoch);
        let mut bytes = capability(epoch);
        bytes.extend_from_slice(&capsule);
        bytes.extend_from_slice(&time);
        bytes.extend_from_slice(&status.encode().unwrap());
        let transport = TestTransport::new([DirectPodTransportRead::Complete(bytes)]);
        let cancelled = transport.cancellation_flag();
        let mut bootstrap = DirectPodTransportBootstrap::new(
            admission,
            transport,
            DirectPodRuntimeConfig::default(),
            preflight,
        )
        .unwrap();
        assert_eq!(
            bootstrap.poll_once(1).unwrap(),
            DirectPodBootstrapPoll::Connected
        );
        let connection = bootstrap.into_connection().unwrap();
        let error = PromotableDirectPodBackend::new(connection, FailingPreflightProvider)
            .err()
            .expect("synthetic preflight provider must reject promotion");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(cancelled.load(Ordering::Acquire));
    }

    #[test]
    fn bootstrapping_transition_failure_latches_unavailable_without_losing_owner_state() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let admission = VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150)
            .unwrap()
            .admission()
            .clone();
        let epoch = 78;
        let (preflight, capsule, status, time) = protected_identity_fixture(epoch);
        let mut bytes = capability(epoch);
        bytes.extend_from_slice(&capsule);
        bytes.extend_from_slice(&time);
        bytes.extend_from_slice(&status.encode().unwrap());
        let transport = TestTransport::new([DirectPodTransportRead::Complete(bytes)]);
        let cancelled = transport.cancellation_flag();
        let bootstrap = DirectPodTransportBootstrap::new(
            admission,
            transport,
            DirectPodRuntimeConfig::default(),
            preflight,
        )
        .unwrap();
        let mut backend =
            BootstrappingDirectPodBackend::new(bootstrap, FailingPreflightProvider, [0x44; 32])
                .unwrap();
        backend.poll_owner_once(1).unwrap();
        assert!(matches!(
            backend.observation().unwrap(),
            DirectPodBackendObservation::Faulted { .. }
        ));
        let status = backend.status(1, 2).unwrap();
        assert_eq!(
            status.service_state,
            crate::hardware_service_protocol::HardwareServiceState::Unavailable
        );
        assert_eq!(
            status.error_code,
            crate::hardware_service_protocol::HardwareServiceError::Unavailable
        );
        backend.shutdown_owner().unwrap();
        assert!(cancelled.load(Ordering::Acquire));
    }

    #[test]
    fn bootstrapping_constructor_rejection_cancels_bootstrap_owner() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let transport = TestTransport::new([]);
        let cancelled = transport.cancellation_flag();
        let bootstrap = DirectPodTransportBootstrap::new_legacy_test(
            verified.admission().clone(),
            transport,
            DirectPodRuntimeConfig::default(),
        )
        .unwrap();
        let error =
            BootstrappingDirectPodBackend::new(bootstrap, verified.run_plan_provider(), [0; 32])
                .err()
                .expect("zero deployment evidence must reject the bootstrap owner");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(cancelled.load(Ordering::Acquire));
    }

    #[test]
    fn reconnect_constructor_policy_rejection_cancels_initial_owner() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let transport = TestTransport::new([]);
        let cancelled = transport.cancellation_flag();
        let bootstrap = DirectPodTransportBootstrap::new_legacy_test(
            verified.admission().clone(),
            transport,
            DirectPodRuntimeConfig::default(),
        )
        .unwrap();
        let initial = BootstrappingDirectPodBackend::new(
            bootstrap,
            verified.run_plan_provider(),
            verified.evidence_hash(),
        )
        .unwrap();
        let ledger = DirectPodReconnectLedger::open(
            files.root.join("constructor-reconnect-ledger"),
            verified.admission().device_id(),
            verified.evidence_hash(),
        )
        .unwrap();
        let error = ReconnectingDirectPodBackend::new(
            initial,
            TestReconnectFactory {
                admission: verified.admission().clone(),
                provider: verified.run_plan_provider(),
                steps: VecDeque::new(),
            },
            ledger,
            DirectPodReconnectPolicy {
                max_attempts: 0,
                initial_backoff_ns: 1,
                max_backoff_ns: 1,
            },
            verified.evidence_hash(),
            [0x55; 16],
        )
        .err()
        .expect("invalid reconnect policy must reject the initial owner");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(cancelled.load(Ordering::Acquire));
    }

    #[test]
    fn protected_preflight_constructor_rejects_invalid_or_mismatched_inputs() {
        let (preflight, _, status, _) = protected_identity_fixture(77);
        let policy = preflight.dhl_identity_policy().clone();
        assert!(DirectPodProtectedPreflightV1::new(
            policy.clone(),
            [0; 16],
            preflight.headstage_id(),
            status.configuration_binding_hash(),
        )
        .is_err());
        assert!(DirectPodProtectedPreflightV1::new(
            policy.clone(),
            preflight.pod_id(),
            [0; 16],
            status.configuration_binding_hash(),
        )
        .is_err());
        assert!(DirectPodProtectedPreflightV1::new(
            policy,
            preflight.pod_id(),
            preflight.headstage_id(),
            [0; 32],
        )
        .is_err());
    }

    #[test]
    fn protected_bootstrap_preserves_capsule_fragments_and_duplicate_is_idempotent() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let admission = VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150)
            .unwrap()
            .admission()
            .clone();
        let (_, representative_capsule, _, _) = protected_identity_fixture(88);
        for split in [12, representative_capsule.len() / 2] {
            let epoch = 88;
            let (preflight, capsule, status, time) = protected_identity_fixture(epoch);
            let mut first = capability(epoch);
            first.extend_from_slice(&capsule[..split]);
            let mut second = capsule[split..].to_vec();
            second.extend_from_slice(&time);
            let transport = TestTransport::new([
                DirectPodTransportRead::Complete(first),
                DirectPodTransportRead::Complete(second),
                DirectPodTransportRead::Complete(status.encode().unwrap().to_vec()),
                DirectPodTransportRead::Complete(capsule.clone()),
            ]);
            let mut bootstrap = DirectPodTransportBootstrap::new(
                admission.clone(),
                transport,
                DirectPodRuntimeConfig::default(),
                preflight,
            )
            .unwrap();
            assert_eq!(
                bootstrap.poll_once(1).unwrap(),
                DirectPodBootstrapPoll::Pending
            );
            assert_eq!(
                bootstrap.poll_once(2).unwrap(),
                DirectPodBootstrapPoll::Pending
            );
            assert_eq!(
                bootstrap.poll_once(3).unwrap(),
                DirectPodBootstrapPoll::Connected
            );
            assert_eq!(
                bootstrap.poll_once(4).unwrap(),
                DirectPodBootstrapPoll::Connected,
                "exact duplicate capsule must be idempotent"
            );
        }
    }

    #[test]
    fn protected_bootstrap_reencoded_capsule_and_every_cabline_binding_mismatch_poison() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let admission = VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150)
            .unwrap()
            .admission()
            .clone();
        let epoch = 91;

        let (preflight, capsule, status, time) = protected_identity_fixture(epoch);
        let mut changed = DirectPodDhlIdentityCapsuleV1::decode(&capsule).unwrap();
        changed.descriptor_wire[24..32].copy_from_slice(&10_u64.to_le_bytes());
        changed.inventory_wire[24..32].copy_from_slice(&11_u64.to_le_bytes());
        refresh_dhl_crc(&mut changed.descriptor_wire);
        refresh_dhl_crc(&mut changed.inventory_wire);
        let changed = changed.encode().unwrap();
        let transport = TestTransport::new([
            DirectPodTransportRead::Complete(capability(epoch)),
            DirectPodTransportRead::Complete(capsule),
            DirectPodTransportRead::Complete(time),
            DirectPodTransportRead::Complete(status.encode().unwrap().to_vec()),
            DirectPodTransportRead::Complete(changed),
        ]);
        let cancellation = transport.cancellation_flag();
        let mut bootstrap = DirectPodTransportBootstrap::new(
            admission.clone(),
            transport,
            DirectPodRuntimeConfig::default(),
            preflight,
        )
        .unwrap();
        for now in 1..=3 {
            assert_eq!(
                bootstrap.poll_once(now).unwrap(),
                DirectPodBootstrapPoll::Pending
            );
        }
        assert_eq!(
            bootstrap.poll_once(4).unwrap(),
            DirectPodBootstrapPoll::Connected
        );
        assert!(bootstrap.poll_once(5).is_err());
        assert!(cancellation.load(Ordering::Acquire));
        assert!(bootstrap.poll_once(6).is_err());

        for mismatch in 0_u8..=8 {
            let (preflight, capsule, mut status, time) = protected_identity_fixture(epoch + 1);
            let policy = preflight.dhl_identity_policy().clone();
            match mismatch {
                0 => status.descriptor_hash[0] ^= 1,
                1 => status.inventory_hash[0] ^= 1,
                2 => status.headstage_config_hash[0] ^= 1,
                3 => status.assembly_manifest_hash[0] ^= 1,
                4 => status.channel_map_hash[0] ^= 1,
                5 => status.source_id = 2,
                6 => status.headstage_boot_id = 2,
                7 => status.next_dhl_sequence = 2,
                8 => {}
                _ => unreachable!(),
            }
            let approved_binding = if mismatch == 8 {
                [0x99; 32]
            } else {
                status.configuration_binding_hash()
            };
            let preflight =
                DirectPodProtectedPreflightV1::new(policy, [7; 16], [8; 16], approved_binding)
                    .unwrap();
            let transport = TestTransport::new([
                DirectPodTransportRead::Complete(capability(epoch + 1)),
                DirectPodTransportRead::Complete(capsule),
                DirectPodTransportRead::Complete(time),
                DirectPodTransportRead::Complete(status.encode().unwrap().to_vec()),
            ]);
            let cancellation = transport.cancellation_flag();
            let mut bootstrap = DirectPodTransportBootstrap::new(
                admission.clone(),
                transport,
                DirectPodRuntimeConfig::default(),
                preflight,
            )
            .unwrap();
            for now in 1..=3 {
                assert_eq!(
                    bootstrap.poll_once(now).unwrap(),
                    DirectPodBootstrapPoll::Pending
                );
            }
            assert!(bootstrap.poll_once(4).is_err(), "mismatch {mismatch}");
            assert!(cancellation.load(Ordering::Acquire), "mismatch {mismatch}");
            assert!(bootstrap.poll_once(5).is_err(), "mismatch {mismatch}");
        }
    }

    #[test]
    fn protected_bootstrap_time_readiness_staleness_and_coherence_wait_or_fail_closed() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let admission = VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150)
            .unwrap()
            .admission()
            .clone();
        let epoch = 93;
        let (preflight, capsule, mut status, _) = protected_identity_fixture(epoch);
        status.global_time_ns = 1_000;
        let mut refreshed_status = status;
        refreshed_status.status_sequence = 2;
        refreshed_status.global_time_ns = 200_000_000;
        let mut stale_recovery_status = refreshed_status;
        stale_recovery_status.status_sequence = 3;
        stale_recovery_status.global_time_ns = 300_000_000;
        let mut bootstrap = DirectPodTransportBootstrap::new(
            admission.clone(),
            TestTransport::new([
                DirectPodTransportRead::Complete(capability(epoch)),
                DirectPodTransportRead::Complete(capsule),
                DirectPodTransportRead::Complete(protected_time(epoch, 1, 1_000, 0)),
                DirectPodTransportRead::Complete(status.encode().unwrap().to_vec()),
                DirectPodTransportRead::Complete(protected_time(
                    epoch,
                    2,
                    200_000_000,
                    TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY,
                )),
                DirectPodTransportRead::Complete(refreshed_status.encode().unwrap().to_vec()),
                DirectPodTransportRead::Pending,
                DirectPodTransportRead::Complete(protected_time(
                    epoch,
                    3,
                    300_000_000,
                    TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY,
                )),
                DirectPodTransportRead::Complete(stale_recovery_status.encode().unwrap().to_vec()),
            ]),
            DirectPodRuntimeConfig::default(),
            preflight,
        )
        .unwrap();
        for now in 1..=5 {
            assert_eq!(
                bootstrap.poll_once(now).unwrap(),
                DirectPodBootstrapPoll::Pending
            );
        }
        assert_eq!(
            bootstrap.poll_once(6).unwrap(),
            DirectPodBootstrapPoll::Connected
        );
        assert_eq!(
            bootstrap
                .poll_once(6 + DIRECT_POD_CABLINE_MAX_HOST_AGE_NS + 1)
                .unwrap(),
            DirectPodBootstrapPoll::Pending
        );
        assert_eq!(
            bootstrap
                .poll_once(7 + DIRECT_POD_CABLINE_MAX_HOST_AGE_NS)
                .unwrap(),
            DirectPodBootstrapPoll::Pending
        );
        assert_eq!(
            bootstrap
                .poll_once(8 + DIRECT_POD_CABLINE_MAX_HOST_AGE_NS)
                .unwrap(),
            DirectPodBootstrapPoll::Connected
        );

        let (preflight, capsule, status, _) = protected_identity_fixture(epoch + 1);
        let transport = TestTransport::new([
            DirectPodTransportRead::Complete(capability(epoch + 1)),
            DirectPodTransportRead::Complete(capsule),
            DirectPodTransportRead::Complete(protected_time(
                epoch + 1,
                1,
                1_000,
                TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY | crate::TIME_FLAG_POD_FAULT,
            )),
            DirectPodTransportRead::Complete(status.encode().unwrap().to_vec()),
        ]);
        let cancellation = transport.cancellation_flag();
        let mut faulted = DirectPodTransportBootstrap::new(
            admission,
            transport,
            DirectPodRuntimeConfig::default(),
            preflight,
        )
        .unwrap();
        for now in 1..=3 {
            assert_eq!(
                faulted.poll_once(now).unwrap(),
                DirectPodBootstrapPoll::Pending
            );
        }
        assert!(faulted.poll_once(4).is_err());
        assert!(cancellation.load(Ordering::Acquire));
    }

    #[test]
    fn bootstrap_buffer_budget_is_exact_and_overflow_safe() {
        let config = DirectPodRuntimeConfig {
            read_buffer_bytes: 1_024,
            read_depth: 2,
        };
        let exact = next_bootstrap_buffer_usage(
            MAX_BOOTSTRAP_COMPLETION_COUNT - 1,
            DEVICE_CAPABILITIES_MESSAGE_LEN - 1,
            config,
            config.read_buffer_bytes,
        )
        .unwrap();
        assert_eq!(exact.0, MAX_BOOTSTRAP_COMPLETION_COUNT);
        assert_eq!(
            exact.1,
            config.read_buffer_bytes + DEVICE_CAPABILITIES_MESSAGE_LEN - 1
        );
        assert_eq!(
            next_bootstrap_buffer_usage(MAX_BOOTSTRAP_COMPLETION_COUNT, 0, config, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            next_bootstrap_buffer_usage(1, exact.1, config, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            next_bootstrap_buffer_usage(1, usize::MAX, config, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn bootstrap_over_budget_completion_poisons_without_ready_promotion() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let config = DirectPodRuntimeConfig {
            read_buffer_bytes: 1_024,
            read_depth: 2,
        };
        let frame = capability(77);
        assert_eq!(frame.len(), DEVICE_CAPABILITIES_MESSAGE_LEN);
        let mut reads: Vec<_> = frame[..DEVICE_CAPABILITIES_MESSAGE_LEN - 1]
            .iter()
            .map(|byte| DirectPodTransportRead::Complete(vec![*byte]))
            .collect();
        let mut limit_plus_one = frame[DEVICE_CAPABILITIES_MESSAGE_LEN - 1..].to_vec();
        limit_plus_one.resize(config.read_buffer_bytes + 1, 0);
        reads.push(DirectPodTransportRead::Complete(limit_plus_one));
        let mut bootstrap = DirectPodTransportBootstrap::new_legacy_test(
            verified.admission().clone(),
            TestTransport::new(reads),
            config,
        )
        .unwrap();
        for now in 1..DEVICE_CAPABILITIES_MESSAGE_LEN as u64 {
            assert_eq!(
                bootstrap.poll_once(now).unwrap(),
                DirectPodBootstrapPoll::Pending
            );
        }
        assert_eq!(
            bootstrap
                .poll_once(DEVICE_CAPABILITIES_MESSAGE_LEN as u64)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(bootstrap.poll_once(97).is_err());
        assert!(bootstrap.into_connection().is_err());
    }

    #[test]
    fn bootstrap_empty_completion_remains_fail_closed() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let mut bootstrap = DirectPodTransportBootstrap::new_legacy_test(
            verified.admission().clone(),
            TestTransport::new([DirectPodTransportRead::Complete(Vec::new())]),
            DirectPodRuntimeConfig::default(),
        )
        .unwrap();
        assert_eq!(
            bootstrap.poll_once(1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(bootstrap.poll_once(2).is_err());
        assert!(bootstrap.into_connection().is_err());
    }

    #[test]
    fn bootstrap_rejects_host_invented_or_non_capability_first_epochs() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let transport = TestTransport::new([DirectPodTransportRead::Complete(time_snapshot(99))]);
        let mut bootstrap = DirectPodTransportBootstrap::new_legacy_test(
            verified.admission().clone(),
            transport,
            DirectPodRuntimeConfig::default(),
        )
        .unwrap();
        assert!(bootstrap.poll_once(1).is_err());
        assert!(bootstrap.poll_once(2).is_err());
        assert!(bootstrap.into_connection().is_err());
    }

    #[test]
    fn scm_owner_stays_unavailable_until_exact_bootstrap_then_becomes_ready() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let mut first_completion = capability(88);
        first_completion.extend_from_slice(&time_snapshot(88));
        let transport = TestTransport::new([DirectPodTransportRead::Complete(first_completion)]);
        let write_count = transport.write_count_flag();
        let bootstrap = DirectPodTransportBootstrap::new_legacy_test(
            verified.admission().clone(),
            transport,
            DirectPodRuntimeConfig::default(),
        )
        .unwrap();
        let mut backend = BootstrappingDirectPodBackend::new(
            bootstrap,
            verified.run_plan_provider(),
            verified.evidence_hash(),
        )
        .unwrap();
        let before = backend.status(1, 1).unwrap();
        assert_eq!(
            before.service_state,
            crate::hardware_service_protocol::HardwareServiceState::Unavailable
        );
        assert_eq!(before.detail_code, 3);
        let rejected = backend
            .submit(
                OperatorRunRequestV1 {
                    request_id: 1,
                    epoch: 88,
                    command: RunCommandKind::Prepare,
                    relative_deadline_ms: 100,
                    run_id: [10; 16],
                    target_device_id: [2; 16],
                    frozen_config_hash: [9; 32],
                    expected_hardware_state_hash: [0; 32],
                },
                2,
            )
            .unwrap();
        assert_eq!(
            rejected.service_state,
            crate::hardware_service_protocol::HardwareServiceState::Unavailable
        );
        assert_eq!(
            rejected.error_code,
            crate::hardware_service_protocol::HardwareServiceError::Unavailable
        );
        assert_eq!(write_count.load(Ordering::Acquire), 0);
        assert!(!files
            .root
            .join(format!("hardware-run-{}", hex(&[10; 16])))
            .exists());
        backend.poll_owner_once(100).unwrap();
        let ready = backend.status(2, 101).unwrap();
        assert_eq!(
            ready.service_state,
            crate::hardware_service_protocol::HardwareServiceState::Ready
        );
        assert_eq!(ready.transport_epoch, 88);
        assert_eq!(ready.device_id, [2; 16]);
        assert!(!files
            .root
            .join(format!("hardware-run-{}", hex(&[10; 16])))
            .exists());
    }

    #[test]
    fn scm_owner_shutdown_durably_fails_an_unfinished_run_before_exit() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let mut first_completion = capability(88);
        first_completion.extend_from_slice(&time_snapshot(88));
        let bootstrap = DirectPodTransportBootstrap::new_legacy_test(
            verified.admission().clone(),
            TestTransport::new([DirectPodTransportRead::Complete(first_completion)]),
            DirectPodRuntimeConfig::default(),
        )
        .unwrap();
        let mut backend = BootstrappingDirectPodBackend::new(
            bootstrap,
            verified.run_plan_provider(),
            verified.evidence_hash(),
        )
        .unwrap();
        backend.poll_owner_once(1).unwrap();
        let ready = backend.status(1, 2).unwrap();
        assert_eq!(
            ready.service_state,
            crate::hardware_service_protocol::HardwareServiceState::Ready
        );
        let clock = crate::hardware_service::HostMonotonicClock::new();
        let owner = crate::hardware_service::HardwareServiceOwner::spawn(
            backend,
            clock.clone(),
            2,
            std::time::Duration::from_millis(1),
            std::time::Duration::from_millis(2_000),
        )
        .unwrap();
        let mut proxy = owner.proxy();
        let run_id = [10; 16];
        let requested = proxy
            .submit(
                OperatorRunRequestV1 {
                    request_id: 101,
                    epoch: 88,
                    command: RunCommandKind::Prepare,
                    relative_deadline_ms: 100,
                    run_id,
                    target_device_id: [2; 16],
                    frozen_config_hash: [9; 32],
                    expected_hardware_state_hash: ready.hardware_state_hash,
                },
                clock.now_ns(),
            )
            .unwrap();
        assert_eq!(
            requested.service_state,
            crate::hardware_service_protocol::HardwareServiceState::PrepareRequested
        );

        owner.shutdown().unwrap();
        let ledger_path = files
            .root
            .join(format!("hardware-run-{}", hex(&run_id)))
            .join("hardware-ledger");
        let reopened = crate::hardware_run::HardwareRunCoordinator::open(ledger_path).unwrap();
        let status = reopened.status();
        assert_eq!(status.phase, crate::hardware_run::HardwareRunPhase::Failed);
        assert!(!status.auto_failed_on_restart);
        assert!(!status.hardware_transport_available);
    }

    #[test]
    fn reconnect_records_attempt_before_open_and_requires_a_strictly_fresh_epoch() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let policy = DirectPodReconnectPolicy {
            max_attempts: 3,
            initial_backoff_ns: 10,
            max_backoff_ns: 40,
        };
        let mut backend = test_reconnect_owner(
            &verified,
            &files.root,
            88,
            [TestReconnectStep::Epoch(89)],
            policy,
        );
        assert_eq!(backend.reconnect_event_count(), 0);
        assert_eq!(
            backend.status(1, 1).unwrap().service_state,
            crate::hardware_service_protocol::HardwareServiceState::Unavailable
        );
        backend.poll_owner_once(1).unwrap();
        assert_eq!(backend.reconnect_event_count(), 1);
        assert_eq!(
            backend.ledger.last_event().unwrap().event_kind,
            DirectPodReconnectEventKind::AttemptStarted
        );
        assert_eq!(
            backend.status(2, 2).unwrap().service_state,
            crate::hardware_service_protocol::HardwareServiceState::Unavailable
        );
        backend.poll_owner_once(2).unwrap();
        let ready = backend.status(3, 3).unwrap();
        assert_eq!(
            ready.service_state,
            crate::hardware_service_protocol::HardwareServiceState::Ready
        );
        assert_eq!(ready.transport_epoch, 89);
        assert_eq!(backend.ledger.highest_admitted_epoch(), 89);
        assert_eq!(backend.reconnect_event_count(), 2);
    }

    #[test]
    fn protected_reconnect_candidate_requires_a_new_identity_capsule_each_epoch() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let policy = DirectPodReconnectPolicy {
            max_attempts: 3,
            initial_backoff_ns: 1,
            max_backoff_ns: 2,
        };
        let mut backend = test_reconnect_owner(
            &verified,
            &files.root,
            88,
            [
                TestReconnectStep::ProtectedEpoch {
                    epoch: 89,
                    include_identity: false,
                },
                TestReconnectStep::ProtectedEpoch {
                    epoch: 90,
                    include_identity: true,
                },
            ],
            policy,
        );

        // The first candidate has capability, time, and CABLINE status but no
        // identity capsule.  It must remain bootstrapping rather than reuse an
        // identity admitted in any prior epoch.
        backend.poll_owner_once(1).unwrap();
        backend.poll_owner_once(2).unwrap();
        assert_eq!(
            backend.status(1, 3).unwrap().service_state,
            crate::hardware_service_protocol::HardwareServiceState::Unavailable
        );

        // The missing candidate is discarded during the next reconnect; only
        // the fresh epoch's own admitted capsule can promote the backend.
        for host_ns in 3..=8 {
            backend.poll_owner_once(host_ns).unwrap();
            let status = backend.status(2, host_ns + 10).unwrap();
            if status.service_state == crate::hardware_service_protocol::HardwareServiceState::Ready
            {
                assert_eq!(status.transport_epoch, 90);
                return;
            }
        }
        panic!("fresh protected reconnect candidate never became Ready");
    }

    #[test]
    fn stale_reconnect_epoch_fails_and_backoff_is_not_bypassed() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let policy = DirectPodReconnectPolicy {
            max_attempts: 2,
            initial_backoff_ns: 10,
            max_backoff_ns: 20,
        };
        let mut backend = test_reconnect_owner(
            &verified,
            &files.root,
            88,
            [TestReconnectStep::Epoch(88), TestReconnectStep::Epoch(89)],
            policy,
        );
        backend.poll_owner_once(1).unwrap();
        backend.poll_owner_once(2).unwrap();
        assert_eq!(backend.ledger.completed_attempts(), 1);
        assert_eq!(
            backend.status(1, 3).unwrap().service_state,
            crate::hardware_service_protocol::HardwareServiceState::Unavailable
        );
        backend.poll_owner_once(21).unwrap();
        assert_eq!(backend.reconnect_event_count(), 2);
        backend.poll_owner_once(22).unwrap();
        assert_eq!(
            backend.ledger.last_event().unwrap().event_kind,
            DirectPodReconnectEventKind::AttemptStarted
        );
        backend.poll_owner_once(23).unwrap();
        assert_eq!(backend.status(2, 24).unwrap().transport_epoch, 89);
    }

    #[test]
    fn reconnect_failures_exhaust_durable_budget_without_infinite_open() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let policy = DirectPodReconnectPolicy {
            max_attempts: 2,
            initial_backoff_ns: 1,
            max_backoff_ns: 2,
        };
        let mut backend = test_reconnect_owner(
            &verified,
            &files.root,
            12,
            [TestReconnectStep::OpenFail, TestReconnectStep::OpenFail],
            policy,
        );
        backend.poll_owner_once(1).unwrap();
        backend.poll_owner_once(3).unwrap();
        backend.poll_owner_once(4).unwrap();
        assert!(backend.ledger.attempts_exhausted());
        assert_eq!(backend.ledger.completed_attempts(), 2);
        let count = backend.reconnect_event_count();
        for time in 5..20 {
            backend.poll_owner_once(time).unwrap();
        }
        assert_eq!(backend.reconnect_event_count(), count);
        assert_eq!(
            backend.ledger.last_event().unwrap().event_kind,
            DirectPodReconnectEventKind::AttemptsExhausted
        );
    }

    #[test]
    fn reconnect_candidate_without_capability_times_out_and_consumes_budget() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let deployment = verified.evidence_hash();
        let ledger = DirectPodReconnectLedger::open(
            files.root.join("test-reconnect-ledger"),
            verified.admission().device_id(),
            deployment,
        )
        .unwrap();
        struct PendingFactory {
            admission: VerifiedFt601Admission,
            provider: ProtectedDirectPodRunPlanProvider,
        }
        impl DirectPodReconnectFactory<TestTransport, ProtectedDirectPodRunPlanProvider>
            for PendingFactory
        {
            fn open_fresh(
                &mut self,
            ) -> io::Result<(
                DirectPodTransportBootstrap<TestTransport>,
                ProtectedDirectPodRunPlanProvider,
            )> {
                Ok((
                    DirectPodTransportBootstrap::new_legacy_test(
                        self.admission.clone(),
                        TestTransport::new([]),
                        DirectPodRuntimeConfig::default(),
                    )?,
                    self.provider.clone(),
                ))
            }
        }
        let mut backend = ReconnectingDirectPodBackend::new_waiting(
            PendingFactory {
                admission: verified.admission().clone(),
                provider: verified.run_plan_provider(),
            },
            ledger,
            DirectPodReconnectPolicy {
                max_attempts: 2,
                initial_backoff_ns: 1,
                max_backoff_ns: 5,
            },
            deployment,
            [0x55; 16],
            12,
        )
        .unwrap();
        backend.poll_owner_once(1).unwrap();
        backend.poll_owner_once(2).unwrap();
        assert_eq!(backend.ledger.pending_attempt(), Some(1));
        backend.poll_owner_once(6).unwrap();
        assert_eq!(backend.ledger.pending_attempt(), Some(1));
        backend.poll_owner_once(7).unwrap();
        assert_eq!(backend.ledger.completed_attempts(), 1);
        assert_eq!(
            backend.ledger.last_event().unwrap().event_kind,
            DirectPodReconnectEventKind::AttemptFailed
        );
    }

    #[test]
    fn transport_fault_durably_fails_old_run_before_reconnect_evidence() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let mut first_completion = capability(88);
        first_completion.extend_from_slice(&time_snapshot(88));
        let transport = TestTransport::new([DirectPodTransportRead::Complete(first_completion)])
            .disconnect_after_reads();
        let cancelled = transport.cancellation_flag();
        let bootstrap = DirectPodTransportBootstrap::new_legacy_test(
            verified.admission().clone(),
            transport,
            DirectPodRuntimeConfig::default(),
        )
        .unwrap();
        let initial = BootstrappingDirectPodBackend::new(
            bootstrap,
            verified.run_plan_provider(),
            verified.evidence_hash(),
        )
        .unwrap();
        let ledger = DirectPodReconnectLedger::open(
            files.root.join("test-reconnect-ledger"),
            verified.admission().device_id(),
            verified.evidence_hash(),
        )
        .unwrap();
        let mut backend = ReconnectingDirectPodBackend::new(
            initial,
            TestReconnectFactory {
                admission: verified.admission().clone(),
                provider: verified.run_plan_provider(),
                steps: [TestReconnectStep::Epoch(89)].into_iter().collect(),
            },
            ledger,
            DirectPodReconnectPolicy {
                max_attempts: 2,
                initial_backoff_ns: 1,
                max_backoff_ns: 2,
            },
            verified.evidence_hash(),
            [0x55; 16],
        )
        .unwrap();
        backend.poll_owner_once(1).unwrap();
        let ready = backend.status(1, 2).unwrap();
        let run_id = [0x33; 16];
        backend
            .submit(
                OperatorRunRequestV1 {
                    request_id: 7,
                    epoch: 88,
                    command: RunCommandKind::Prepare,
                    relative_deadline_ms: 100,
                    run_id,
                    target_device_id: [2; 16],
                    frozen_config_hash: [9; 32],
                    expected_hardware_state_hash: ready.hardware_state_hash,
                },
                2,
            )
            .unwrap();
        backend.poll_owner_once(3).unwrap();
        let reopened = crate::hardware_run::HardwareRunCoordinator::open(
            files
                .root
                .join(format!("hardware-run-{}", hex(&run_id)))
                .join("hardware-ledger"),
        )
        .unwrap();
        assert_eq!(reopened.status().phase, HardwareRunPhase::Failed);
        assert_eq!(
            backend.ledger.last_event().unwrap().event_kind,
            DirectPodReconnectEventKind::TransportFault
        );
        assert!(cancelled.load(Ordering::Acquire));
        let unavailable = backend.status(2, 4).unwrap();
        assert_eq!(
            unavailable.service_state,
            crate::hardware_service_protocol::HardwareServiceState::Unavailable
        );
        assert_eq!(
            unavailable.error_code,
            crate::hardware_service_protocol::HardwareServiceError::Unavailable
        );
        backend.poll_owner_once(4).unwrap();
        assert_eq!(
            backend.ledger.last_event().unwrap().event_kind,
            DirectPodReconnectEventKind::AttemptStarted
        );
        assert_eq!(
            backend.status(3, 4).unwrap().service_state,
            crate::hardware_service_protocol::HardwareServiceState::Unavailable
        );
        backend.poll_owner_once(5).unwrap();
        assert_eq!(
            backend.status(4, 5).unwrap().service_state,
            crate::hardware_service_protocol::HardwareServiceState::Ready
        );
    }

    #[test]
    fn service_restart_reconciles_unfinished_runs_before_device_open() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        let mut first_completion = capability(91);
        first_completion.extend_from_slice(&time_snapshot(91));
        let bootstrap = DirectPodTransportBootstrap::new_legacy_test(
            verified.admission().clone(),
            TestTransport::new([DirectPodTransportRead::Complete(first_completion)]),
            DirectPodRuntimeConfig::default(),
        )
        .unwrap();
        let mut backend = BootstrappingDirectPodBackend::new(
            bootstrap,
            verified.run_plan_provider(),
            verified.evidence_hash(),
        )
        .unwrap();
        backend.poll_owner_once(1).unwrap();
        let ready = backend.status(1, 2).unwrap();
        let run_id = [14; 16];
        let requested = backend
            .submit(
                OperatorRunRequestV1 {
                    request_id: 2,
                    epoch: 91,
                    command: RunCommandKind::Prepare,
                    relative_deadline_ms: 100,
                    run_id,
                    target_device_id: [2; 16],
                    frozen_config_hash: [9; 32],
                    expected_hardware_state_hash: ready.hardware_state_hash,
                },
                3,
            )
            .unwrap();
        assert_eq!(
            requested.service_state,
            crate::hardware_service_protocol::HardwareServiceState::PrepareRequested
        );

        // Simulate abrupt process loss: no orderly owner shutdown hook runs.
        drop(backend);
        let recovered = verified.recover_prior_runs().unwrap();
        assert_eq!(recovered.inspected_run_roots, 1);
        assert_eq!(recovered.failed_on_recovery, 1);
        assert_eq!(recovered.terminal_run_roots, 0);
        assert_eq!(recovered.unstarted_run_roots, 0);
        assert_ne!(recovered.evidence_hash, [0; 32]);

        // Reconciliation is idempotent and never appends another failure.
        let reopened = verified.recover_prior_runs().unwrap();
        assert_eq!(reopened.inspected_run_roots, 1);
        assert_eq!(reopened.failed_on_recovery, 0);
        assert_eq!(reopened.terminal_run_roots, 1);
        assert_eq!(reopened.unstarted_run_roots, 0);
    }

    #[test]
    fn service_restart_recovery_rejects_malformed_or_incomplete_run_roots() {
        let (files, bytes) = policy_fixture(None);
        let reference = ProtectedDirectPodPolicyReference::new(
            &files.policy,
            Sha256::digest(&bytes).into(),
            [6; 32],
        )
        .unwrap();
        let verified =
            VerifiedDirectPodDeploymentPolicy::load(&reference, &files.root, 150).unwrap();
        std::fs::create_dir(files.root.join("hardware-run-not-an-id")).unwrap();
        assert_eq!(
            verified.recover_prior_runs().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        std::fs::remove_dir(files.root.join("hardware-run-not-an-id")).unwrap();
        std::fs::create_dir(files.root.join(format!("hardware-run-{}", hex(&[15; 16])))).unwrap();
        assert_eq!(
            verified.recover_prior_runs().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
