//! Ordered direct-Pod ingest boundary between one FT601 stream and one journal.
//!
//! This module composes the independently checked D3XX admission, stream
//! reassembly, request/reply tracker, source Stop boundary and journal writer.
//! It contains no simulator fallback and never advertises hardware availability.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use forge_protocol_v1::{
    decode_low_speed, decode_record, encode_low_speed, sha256, AckV1, DecodedRecord, MessageKind,
    RecordKind, ReplayRequestV1, RunCommandV1, SampleBlockV1, WireBody, PROTOCOL_HASH,
};

#[cfg(windows)]
use crate::d3xx::{D3xxDevice, D3xxReadPoll};
use crate::d3xx_admission::VerifiedFt601Admission;
use crate::dhl_identity_admission::{
    validate_dhl_identity_admission_policy_v1, DhlIdentityAdmissionPolicyV1,
};
use crate::dhl_identity_catalog::DhlIdentityCatalog;
use crate::direct_pod_cabline::{
    DirectPodCablineStatusV1, DirectPodCablineTracker, DirectPodCablineTrackerSnapshot,
    DIRECT_POD_CABLINE_MAX_HOST_AGE_NS,
};
use crate::direct_pod_control::{
    DirectPodControlSnapshot, DirectPodControlTracker, DirectPodReply, DirectPodSendDecision,
    MatchedDirectPodReply,
};
use crate::direct_pod_dhl_identity::{
    admit_new_run_dhl_identity_capsule_v1, AdmittedDirectPodDhlIdentityCapsuleV1,
    DirectPodDhlIdentityCapsuleV1, DirectPodDhlIdentityContextV1,
};
use crate::direct_pod_replay::{
    DirectPodReplayBoundarySnapshot, DirectPodReplayBoundaryTracker, DirectPodReplayState,
};
use crate::direct_pod_replay_offer::DirectPodReplayOfferV1;
use crate::direct_pod_stop::{DirectPodStopBoundarySnapshot, DirectPodStopBoundaryTracker};
use crate::direct_pod_stream::{
    DirectPodExtendedFrameKind, DirectPodIdentityFrameKind, DirectPodStreamReassembler,
    DirectPodStreamStats,
};
use crate::direct_pod_time::{
    DirectPodTimeTracker, DirectPodTimeTrackerSnapshot, TIME_FLAG_GLOBAL_TIME_VALID,
    TIME_FLAG_POD_FAULT, TIME_FLAG_POD_READY,
};
use crate::hardware_run::{
    HardwareReplayReceipt, HardwareRunContext, HardwareRunCoordinator, HardwareRunPhase,
    HardwareRunReceipt, HardwareRunStatus, HARDWARE_FAULT_OWNER_SHUTDOWN, HARDWARE_FAULT_TRANSPORT,
};
use crate::hardware_service_protocol::{translate_operator_run_request, OperatorRunRequestV1};
use crate::journal::{
    seal_evidence_hash, DurableCheckpoint, JournalIdentity, JournalScan, JournalWriter,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DirectPodAcquisitionState {
    AwaitingCapabilities = 0,
    Ready = 1,
    Prepared = 2,
    Armed = 3,
    Recording = 4,
    Stopped = 5,
    Aborted = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodIngestSnapshot {
    pub acquisition_state: DirectPodAcquisitionState,
    pub stream: DirectPodStreamStats,
    pub control: DirectPodControlSnapshot,
    pub stop_boundary: DirectPodStopBoundarySnapshot,
    pub replay_boundary: Option<DirectPodReplayBoundarySnapshot>,
    pub pending_replay_offer: Option<DirectPodReplayOfferV1>,
    pub replay_offer_count: u64,
    pub hardware_time: DirectPodTimeTrackerSnapshot,
    pub cabline_source: DirectPodCablineTrackerSnapshot,
    pub committed_record_count: u64,
    pub durable_record_count: u64,
    pub first_journal_sequence: Option<u64>,
    pub last_journal_sequence: Option<u64>,
    pub first_record_evidence_hash: Option<[u8; 32]>,
    pub source_stop_boundary_verified: bool,
    pub verified_replay_count: u64,
    pub reply_waiting_for_owner: bool,
    pub poisoned: bool,
}

struct PlannedReplayFromOffer {
    encoded_offer: Vec<u8>,
    encoded_request: Vec<u8>,
}

/// Protected, policy-supplied identity and storage binding for one direct-Pod
/// Run.  The hardware service request cannot choose storage filenames or
/// device/channel identity: the trusted owner constructs this plan first and
/// the request must match it exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectPodRunPlan {
    run_root: PathBuf,
    run_id: [u8; 16],
    pod_id: [u8; 16],
    headstage_id: [u8; 16],
    frozen_config_hash: [u8; 32],
    approved_cabline_binding_sha256: [u8; 32],
}

/// Protected identity context required before a direct-Pod transport can be
/// considered preflight-capable.  It is local policy, not device evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectPodProtectedPreflightV1 {
    dhl_identity_policy: DhlIdentityAdmissionPolicyV1,
    pod_id: [u8; 16],
    headstage_id: [u8; 16],
    approved_cabline_binding_sha256: [u8; 32],
}

impl DirectPodProtectedPreflightV1 {
    pub(crate) fn new(
        dhl_identity_policy: DhlIdentityAdmissionPolicyV1,
        pod_id: [u8; 16],
        headstage_id: [u8; 16],
        approved_cabline_binding_sha256: [u8; 32],
    ) -> io::Result<Self> {
        if pod_id == [0; 16]
            || headstage_id == [0; 16]
            || approved_cabline_binding_sha256 == [0; 32]
            || dhl_identity_policy.expected_device_id != headstage_id
        {
            return Err(invalid_input(
                "protected direct-Pod preflight identities are invalid",
            ));
        }
        let catalog = DhlIdentityCatalog::load_embedded()
            .map_err(|_| invalid_data("embedded DHL identity catalog is invalid"))?;
        validate_dhl_identity_admission_policy_v1(&catalog, &dhl_identity_policy)
            .map_err(|_| invalid_data("protected DHL identity policy is not admissible"))?;
        Ok(Self {
            dhl_identity_policy,
            pod_id,
            headstage_id,
            approved_cabline_binding_sha256,
        })
    }

    pub(crate) fn dhl_identity_policy(&self) -> &DhlIdentityAdmissionPolicyV1 {
        &self.dhl_identity_policy
    }

    pub(crate) fn pod_id(&self) -> [u8; 16] {
        self.pod_id
    }

    pub(crate) fn headstage_id(&self) -> [u8; 16] {
        self.headstage_id
    }

    pub(crate) fn approved_cabline_binding_sha256(&self) -> [u8; 32] {
        self.approved_cabline_binding_sha256
    }
}

#[derive(Debug)]
enum HostFreshnessElapsed {
    System(Instant),
    #[cfg(test)]
    Scripted {
        checks: std::cell::Cell<u8>,
        expires_on_check: u8,
    },
}

#[derive(Debug)]
struct HostFreshnessGuard {
    elapsed: HostFreshnessElapsed,
    remaining_ns: u64,
}

impl HostFreshnessGuard {
    fn from_trackers(
        cabline_source: &DirectPodCablineTracker,
        hardware_time: &DirectPodTimeTracker,
        host_monotonic_ns: u64,
        wall_started: Instant,
    ) -> io::Result<Self> {
        let source = cabline_source.snapshot();
        let time = hardware_time.snapshot();
        let source_received = source
            .latest_host_monotonic_ns
            .ok_or_else(|| invalid_data("CABLINE source status has no host freshness evidence"))?;
        let time_received = time
            .latest_host_monotonic_ns
            .ok_or_else(|| invalid_data("Pod time has no host freshness evidence"))?;
        let source_age = host_monotonic_ns
            .checked_sub(source_received)
            .ok_or_else(|| invalid_data("CABLINE source status is from the future host clock"))?;
        let time_age = host_monotonic_ns
            .checked_sub(time_received)
            .ok_or_else(|| invalid_data("Pod time is from the future host clock"))?;
        let source_remaining = source
            .max_host_age_ns
            .checked_sub(source_age)
            .ok_or_else(|| invalid_data("CABLINE source status is stale"))?;
        let time_remaining = time
            .max_host_age_ns
            .checked_sub(time_age)
            .ok_or_else(|| invalid_data("Pod time is stale"))?;
        Ok(Self {
            elapsed: HostFreshnessElapsed::System(wall_started),
            remaining_ns: source_remaining.min(time_remaining),
        })
    }

    fn from_preflight(
        state: &DirectPodPreflightState,
        host_monotonic_ns: u64,
        wall_started: Instant,
    ) -> io::Result<Self> {
        Self::from_trackers(
            &state.cabline_source,
            &state.hardware_time,
            host_monotonic_ns,
            wall_started,
        )
    }

    fn from_session(
        session: &DirectPodIngestSession,
        host_monotonic_ns: u64,
        wall_started: Instant,
    ) -> io::Result<Self> {
        Self::from_trackers(
            &session.cabline_source,
            &session.hardware_time,
            host_monotonic_ns,
            wall_started,
        )
    }

    #[cfg(test)]
    fn expire_on_check(mut self, expires_on_check: u8) -> Self {
        assert!(expires_on_check > 0);
        self.elapsed = HostFreshnessElapsed::Scripted {
            checks: std::cell::Cell::new(0),
            expires_on_check,
        };
        self
    }

    fn ensure_valid(&self) -> io::Result<()> {
        let elapsed_ns = match &self.elapsed {
            HostFreshnessElapsed::System(started) => started.elapsed().as_nanos(),
            #[cfg(test)]
            HostFreshnessElapsed::Scripted {
                checks,
                expires_on_check,
            } => {
                let next = checks.get().saturating_add(1);
                checks.set(next);
                if next >= *expires_on_check {
                    u128::from(self.remaining_ns)
                } else {
                    0
                }
            }
        };
        if elapsed_ns >= u128::from(self.remaining_ns) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "direct-Pod source evidence expired before hardware OUT",
            ));
        }
        Ok(())
    }
}

impl DirectPodRunPlan {
    pub fn new(
        run_root: impl AsRef<Path>,
        run_id: [u8; 16],
        pod_id: [u8; 16],
        headstage_id: [u8; 16],
        frozen_config_hash: [u8; 32],
        approved_cabline_binding_sha256: [u8; 32],
    ) -> io::Result<Self> {
        let run_root = run_root.as_ref().to_path_buf();
        if !run_root.is_absolute()
            || run_root
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || run_id == [0; 16]
            || pod_id == [0; 16]
            || headstage_id == [0; 16]
            || frozen_config_hash == [0; 32]
            || approved_cabline_binding_sha256 == [0; 32]
        {
            return Err(invalid_input(
                "direct-Pod Run plan requires an absolute normalized root and nonzero frozen identities",
            ));
        }
        let parent = run_root
            .parent()
            .ok_or_else(|| invalid_input("direct-Pod Run root has no parent"))?;
        if !parent.is_dir() {
            return Err(invalid_input(
                "direct-Pod Run root parent must already exist under protected storage policy",
            ));
        }
        Ok(Self {
            run_root,
            run_id,
            pod_id,
            headstage_id,
            frozen_config_hash,
            approved_cabline_binding_sha256,
        })
    }

    pub fn run_root(&self) -> &Path {
        &self.run_root
    }

    pub fn journal_path(&self) -> PathBuf {
        self.run_root.join("run.forgewal")
    }

    pub fn hardware_ledger_path(&self) -> PathBuf {
        self.run_root.join("hardware-ledger")
    }

    pub fn run_id(&self) -> [u8; 16] {
        self.run_id
    }

    pub fn pod_id(&self) -> [u8; 16] {
        self.pod_id
    }

    pub fn headstage_id(&self) -> [u8; 16] {
        self.headstage_id
    }

    pub fn frozen_config_hash(&self) -> [u8; 32] {
        self.frozen_config_hash
    }

    pub fn approved_cabline_binding_sha256(&self) -> [u8; 32] {
        self.approved_cabline_binding_sha256
    }

    fn validate_request(
        &self,
        request: &OperatorRunRequestV1,
        device_id: [u8; 16],
        transport_epoch: u64,
    ) -> io::Result<()> {
        if request.command != crate::run::RunCommandKind::Prepare
            || request.run_id != self.run_id
            || request.target_device_id != device_id
            || request.epoch != transport_epoch
            || request.frozen_config_hash != self.frozen_config_hash
        {
            return Err(invalid_input(
                "operator Prepare does not match the protected direct-Pod Run plan",
            ));
        }
        Ok(())
    }

    fn create_artifacts(&self) -> io::Result<(JournalWriter, HardwareRunCoordinator)> {
        // One atomic directory create is the no-overwrite reservation. Any
        // later failure leaves a conspicuous, non-reusable forensic root and
        // occurs before hardware OUT.
        fs::create_dir(&self.run_root)?;
        let writer =
            JournalWriter::create(self.journal_path(), JournalIdentity::for_run(self.run_id)?)?;
        let lifecycle = HardwareRunCoordinator::open(self.hardware_ledger_path())?;
        Ok((writer, lifecycle))
    }
}

struct DirectPodPreflightState {
    admission: VerifiedFt601Admission,
    dhl_identity_policy: DhlIdentityAdmissionPolicyV1,
    dhl_catalog: DhlIdentityCatalog,
    dhl_context: DirectPodDhlIdentityContextV1,
    approved_cabline_binding_sha256: [u8; 32],
    admitted_dhl_identity: Option<AdmittedDirectPodDhlIdentityCapsuleV1>,
    dhl_capsule_evidence_hash: Option<[u8; 32]>,
    identity_required: bool,
    stream: DirectPodStreamReassembler,
    control: DirectPodControlTracker,
    hardware_time: DirectPodTimeTracker,
    cabline_source: DirectPodCablineTracker,
    poisoned: bool,
}

impl DirectPodPreflightState {
    fn new_protected(
        admission: VerifiedFt601Admission,
        policy: DhlIdentityAdmissionPolicyV1,
        pod_id: [u8; 16],
        headstage_id: [u8; 16],
        approved_cabline_binding_sha256: [u8; 32],
        transport_epoch: u64,
    ) -> io::Result<Self> {
        let device_id = admission.device_id();
        if approved_cabline_binding_sha256 == [0; 32] {
            return Err(invalid_input("protected CABLINE binding hash is zero"));
        }
        Ok(Self {
            admission,
            dhl_identity_policy: policy,
            dhl_catalog: DhlIdentityCatalog::load_embedded()
                .map_err(|_| invalid_data("embedded DHL identity catalog is invalid"))?,
            dhl_context: DirectPodDhlIdentityContextV1 {
                device_id,
                pod_id,
                headstage_id,
                transport_epoch,
            },
            approved_cabline_binding_sha256,
            admitted_dhl_identity: None,
            dhl_capsule_evidence_hash: None,
            identity_required: true,
            stream: DirectPodStreamReassembler::new(transport_epoch)?,
            control: DirectPodControlTracker::new(transport_epoch)?,
            hardware_time: DirectPodTimeTracker::new(device_id, transport_epoch, 100_000_000)?,
            cabline_source: DirectPodCablineTracker::new(
                device_id,
                pod_id,
                headstage_id,
                transport_epoch,
            )?,
            poisoned: false,
        })
    }

    #[cfg(test)]
    fn new_legacy_test(
        admission: VerifiedFt601Admission,
        pod_id: [u8; 16],
        headstage_id: [u8; 16],
        transport_epoch: u64,
    ) -> io::Result<Self> {
        use crate::dhl_identity_admission::{
            DhlExpectedInstancePolicyV1, DHL_CAP_ELECTRODE_IMPEDANCE, DHL_CAP_STREAM_NEURAL,
        };
        let mut state = Self::new_protected(
            admission,
            DhlIdentityAdmissionPolicyV1 {
                profile_id: "rhd2132x1".to_owned(),
                expected_descriptor_payload_sha256: [1; 32],
                expected_inventory_payload_sha256: [2; 32],
                expected_device_id: headstage_id,
                expected_config_hash: [3; 32],
                sample_rate_numerator_hz: 30_000,
                sample_rate_denominator: 1,
                approved_channel_layout_id: 0x1020_3040,
                assembly_manifest_hash: [4; 32],
                channel_map_hash: [5; 32],
                ordered_expected_instances: vec![DhlExpectedInstancePolicyV1 {
                    instance_id: 0,
                    exact_driver_abi: 1,
                    exact_capability_flags: DHL_CAP_STREAM_NEURAL | DHL_CAP_ELECTRODE_IMPEDANCE,
                    config_hash_prefix: [6; 12],
                }],
            },
            pod_id,
            headstage_id,
            [7; 32],
            transport_epoch,
        )?;
        state.identity_required = false;
        state.cabline_source =
            DirectPodCablineTracker::new_unbound(state.admission.device_id(), transport_epoch)?;
        Ok(state)
    }
}

/// Owns the exact ordering domain for a single admitted direct-Pod Run.
///
/// The caller must feed D3XX IN bytes in read-completion order. Canonical
/// records are identity-checked, appended, and only then admitted to the Stop
/// boundary. Low-speed replies are handled in the same callback, so a Stop ACK
/// can never overtake a preceding record from the same byte stream.
pub struct DirectPodIngestSession {
    admission: VerifiedFt601Admission,
    admitted_dhl_identity: Option<AdmittedDirectPodDhlIdentityCapsuleV1>,
    dhl_capsule_evidence_hash: Option<[u8; 32]>,
    run_id: [u8; 16],
    pod_id: [u8; 16],
    headstage_id: [u8; 16],
    frozen_config_hash: [u8; 32],
    approved_cabline_binding_sha256: [u8; 32],
    acquisition_state: DirectPodAcquisitionState,
    stream: DirectPodStreamReassembler,
    control: DirectPodControlTracker,
    stop_boundary: DirectPodStopBoundaryTracker,
    replay_boundary: Option<DirectPodReplayBoundaryTracker>,
    pending_replay_offer: Option<DirectPodReplayOfferV1>,
    latest_replay_offer_sequence: Option<u64>,
    replay_offer_count: u64,
    hardware_time: DirectPodTimeTracker,
    cabline_source: DirectPodCablineTracker,
    writer: JournalWriter,
    committed_record_count: u64,
    durable_record_count: u64,
    first_journal_sequence: Option<u64>,
    last_journal_sequence: Option<u64>,
    first_record_evidence_hash: Option<[u8; 32]>,
    source_stop_boundary_verified: bool,
    verified_replay_count: u64,
    last_reply: Option<MatchedDirectPodReply>,
    poisoned: bool,
}

fn validate_canonical_record_against_admitted_dhl_identity(
    decoded: &DecodedRecord,
    admitted: Option<&AdmittedDirectPodDhlIdentityCapsuleV1>,
) -> io::Result<()> {
    // `None` exists only for legacy unit-test construction. Production
    // promotion requires the protected identity capsule before a Run exists.
    let Some(admitted) = admitted else {
        return Ok(());
    };
    let admitted = &admitted.admitted_identity;
    let identity = &admitted.identity;
    let descriptor = &admitted.descriptor;
    if admitted.profile_id != identity.profile_id
        || admitted.inventory.board_profile_id != u32::from(identity.board_profile_id)
        || descriptor.tuple.channel_count != identity.acquisition_channel_count
        || descriptor.sample_format != 1
        || descriptor.sample_rate_numerator_hz != admitted.approved_sample_rate_numerator_hz
        || descriptor.sample_rate_denominator != admitted.approved_sample_rate_denominator
    {
        return Err(invalid_data(
            "admitted DHL identity has inconsistent catalog, Descriptor, Inventory, or rate facts",
        ));
    }
    if decoded.envelope.channel_layout_id != admitted.approved_channel_layout_id
        || decoded.envelope.channel_count != descriptor.tuple.channel_count
        || decoded.envelope.channel_count != identity.acquisition_channel_count
        || decoded.envelope.sample_format != descriptor.sample_format
        || decoded.envelope.sample_format != 1
    {
        return Err(invalid_data(
            "direct-Pod canonical record geometry differs from the admitted DHL identity",
        ));
    }
    if decoded.envelope.record_kind == RecordKind::SampleBlock {
        let block = SampleBlockV1::decode(&decoded.payload)
            .map_err(|_| invalid_data("direct-Pod SampleBlockV1 payload is invalid"))?;
        if block.channel_count != decoded.envelope.channel_count
            || block.sample_format != decoded.envelope.sample_format
            || block.sample_rate_numerator_hz != admitted.approved_sample_rate_numerator_hz
            || block.sample_rate_denominator != admitted.approved_sample_rate_denominator
        {
            return Err(invalid_data(
                "direct-Pod SampleBlockV1 geometry or rational rate differs from the admitted DHL identity",
            ));
        }
    }
    Ok(())
}

impl DirectPodIngestSession {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        writer: JournalWriter,
        admission: &VerifiedFt601Admission,
        run_id: [u8; 16],
        pod_id: [u8; 16],
        headstage_id: [u8; 16],
        frozen_config_hash: [u8; 32],
        approved_cabline_binding_sha256: [u8; 32],
        transport_epoch: u64,
    ) -> io::Result<Self> {
        if run_id == [0; 16]
            || pod_id == [0; 16]
            || headstage_id == [0; 16]
            || frozen_config_hash == [0; 32]
            || approved_cabline_binding_sha256 == [0; 32]
            || writer.identity().run_id != run_id
            || writer.identity().protocol_contract_hash != PROTOCOL_HASH
            || admission.hardware_protocol_hash() != PROTOCOL_HASH
        {
            return Err(invalid_input(
                "direct-Pod ingest identities do not match the journal and admission",
            ));
        }
        let preflight = DirectPodPreflightState::new_legacy_test(
            admission.clone(),
            pod_id,
            headstage_id,
            transport_epoch,
        )?;
        Self::from_preflight(
            writer,
            preflight,
            run_id,
            pod_id,
            headstage_id,
            frozen_config_hash,
            approved_cabline_binding_sha256,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_preflight(
        writer: JournalWriter,
        preflight: DirectPodPreflightState,
        run_id: [u8; 16],
        pod_id: [u8; 16],
        headstage_id: [u8; 16],
        frozen_config_hash: [u8; 32],
        approved_cabline_binding_sha256: [u8; 32],
        require_admitted: bool,
    ) -> io::Result<Self> {
        let DirectPodPreflightState {
            admission,
            dhl_identity_policy: _,
            dhl_catalog: _,
            dhl_context: _,
            admitted_dhl_identity,
            dhl_capsule_evidence_hash,
            approved_cabline_binding_sha256: _,
            stream,
            control,
            hardware_time,
            cabline_source,
            poisoned,
            identity_required,
        } = preflight;
        let stream_snapshot = stream.stats();
        let control_snapshot = control.snapshot();
        let time_snapshot = hardware_time.snapshot();
        let cabline_snapshot = cabline_source.snapshot();
        if run_id == [0; 16]
            || pod_id == [0; 16]
            || headstage_id == [0; 16]
            || frozen_config_hash == [0; 32]
            || approved_cabline_binding_sha256 == [0; 32]
            || writer.identity().run_id != run_id
            || writer.identity().protocol_contract_hash != PROTOCOL_HASH
            || admission.hardware_protocol_hash() != PROTOCOL_HASH
            || poisoned
            || stream_snapshot.poisoned
            || control_snapshot.poisoned
            || time_snapshot.poisoned
            || cabline_snapshot.poisoned
            || control_snapshot.pending_request_id.is_some()
            || control_snapshot.highest_request_id.is_some()
            || (require_admitted
                && (!control_snapshot.capability_admitted
                    || (identity_required && admitted_dhl_identity.is_none())
                    || (identity_required && dhl_capsule_evidence_hash.is_none())
                    || time_snapshot.latest.is_none()
                    || cabline_snapshot.latest.is_none()
                    || cabline_snapshot.latest.is_some_and(|status| {
                        status.pod_id != pod_id
                            || status.headstage_id != headstage_id
                            || status.configuration_binding_hash()
                                != approved_cabline_binding_sha256
                    })))
        {
            return Err(invalid_input(
                "direct-Pod preflight state cannot be bound to this Run",
            ));
        }
        let acquisition_state = if control_snapshot.capability_admitted {
            DirectPodAcquisitionState::Ready
        } else {
            DirectPodAcquisitionState::AwaitingCapabilities
        };
        let device_id = admission.device_id();
        Ok(Self {
            admission,
            admitted_dhl_identity,
            dhl_capsule_evidence_hash,
            run_id,
            pod_id,
            headstage_id,
            frozen_config_hash,
            approved_cabline_binding_sha256,
            acquisition_state,
            stream,
            control,
            stop_boundary: DirectPodStopBoundaryTracker::new(
                run_id,
                device_id,
                pod_id,
                headstage_id,
            )?,
            replay_boundary: None,
            pending_replay_offer: None,
            latest_replay_offer_sequence: None,
            replay_offer_count: 0,
            hardware_time,
            cabline_source,
            writer,
            committed_record_count: 0,
            durable_record_count: 0,
            first_journal_sequence: None,
            last_journal_sequence: None,
            first_record_evidence_hash: None,
            source_stop_boundary_verified: false,
            verified_replay_count: 0,
            last_reply: None,
            poisoned: false,
        })
    }

    /// Registers one outbound message before the transport write. The owner
    /// must consume the previous reply before starting another transaction.
    pub fn admit_outbound(
        &mut self,
        message: &[u8],
        now_global_time_ns: u64,
    ) -> io::Result<DirectPodSendDecision> {
        self.require_healthy()?;
        if self.last_reply.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the previous direct-Pod reply has not been consumed",
            ));
        }
        let decoded = decode_low_speed(message)
            .map_err(|_| invalid_data("outbound direct-Pod message is not exact protocol v1"))?;
        if self
            .replay_boundary
            .as_ref()
            .is_some_and(|boundary| !boundary.is_terminal())
            && decoded.kind != MessageKind::ReplayRequest
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "direct-Pod Replay must finish before another control transaction",
            ));
        }
        let disposition = match decoded.kind {
            MessageKind::RunCommand => {
                let command = RunCommandV1::decode_body(&decoded.body)
                    .map_err(|_| invalid_data("outbound direct-Pod RunCommandV1 is invalid"))?;
                match classify_command(self.acquisition_state, command.command) {
                    CommandDisposition::Invalid => return Err(invalid_data(
                        "direct-Pod acquisition command is invalid in the current hardware state",
                    )),
                    value => value,
                }
            }
            MessageKind::ReplayRequest => {
                if self.acquisition_state != DirectPodAcquisitionState::Recording {
                    return Err(invalid_data(
                        "direct-Pod Replay is admitted only while the Run is recording",
                    ));
                }
                let request = ReplayRequestV1::decode_body(&decoded.body)
                    .map_err(|_| invalid_data("outbound direct-Pod ReplayRequestV1 is invalid"))?;
                let prior = self.stop_boundary.snapshot().last_record_sequence;
                if let Some(existing) = self.replay_boundary.as_ref() {
                    if existing.snapshot().request_id == decoded.request_id {
                        existing.verify_request_message(message)?;
                        return self.control.admit_replay_outbound(
                            message,
                            now_global_time_ns,
                            existing,
                        );
                    }
                }
                let boundary = DirectPodReplayBoundaryTracker::new(
                    self.run_id,
                    self.admission.device_id(),
                    self.pod_id,
                    self.headstage_id,
                    self.stream.stats().transport_epoch,
                    decoded.request_id,
                    request,
                    prior,
                    self.admission.receipt_file_sha256(),
                    self.frozen_config_hash,
                )?;
                let decision =
                    self.control
                        .admit_replay_outbound(message, now_global_time_ns, &boundary)?;
                if decision == DirectPodSendDecision::Send {
                    self.replay_boundary = Some(boundary);
                }
                return Ok(decision);
            }
            _ => CommandDisposition::New,
        };
        let decision = self.control.admit_outbound(message, now_global_time_ns)?;
        if disposition == CommandDisposition::Idempotent
            && decision != DirectPodSendDecision::AlreadyCompleted
        {
            self.control.poison_after_transport_failure();
            self.poisoned = true;
            return Err(invalid_data(
                "an already-applied direct-Pod command changed request identity or bytes",
            ));
        }
        Ok(decision)
    }

    /// Performs the immutable Replay/context checks without creating a control
    /// transaction. Durable owners call this before recording intent in the
    /// hardware ledger; `admit_outbound` repeats the checks immediately before
    /// transport OUT and remains the sole mutating admission point.
    fn validate_replay_request_before_persistence(&self, message: &[u8]) -> io::Result<()> {
        self.require_healthy()?;
        if self.last_reply.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the previous direct-Pod reply has not been consumed",
            ));
        }
        let decoded = decode_low_speed(message)
            .map_err(|_| invalid_data("outbound direct-Pod message is not exact protocol v1"))?;
        if decoded.kind != MessageKind::ReplayRequest
            || self.acquisition_state != DirectPodAcquisitionState::Recording
        {
            return Err(invalid_data(
                "direct-Pod Replay is admitted only while the Run is recording",
            ));
        }
        let request = ReplayRequestV1::decode_body(&decoded.body)
            .map_err(|_| invalid_data("outbound direct-Pod ReplayRequestV1 is invalid"))?;
        let control = self.control.snapshot();
        if control
            .pending_request_id
            .is_some_and(|pending| pending != decoded.request_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another direct-Pod control transaction is pending",
            ));
        }
        if let Some(existing) = self.replay_boundary.as_ref() {
            let existing_snapshot = existing.snapshot();
            if !existing.is_terminal() && existing_snapshot.request_id != decoded.request_id {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "direct-Pod Replay must finish before another Replay request",
                ));
            }
            if existing_snapshot.request_id == decoded.request_id {
                return existing.verify_request_message(message);
            }
        }
        if control
            .highest_request_id
            .is_some_and(|highest| decoded.request_id <= highest)
        {
            return Err(invalid_data(
                "direct-Pod Replay request ID is not strictly monotonic",
            ));
        }
        DirectPodReplayBoundaryTracker::new(
            self.run_id,
            self.admission.device_id(),
            self.pod_id,
            self.headstage_id,
            self.stream.stats().transport_epoch,
            decoded.request_id,
            request,
            self.stop_boundary.snapshot().last_record_sequence,
            self.admission.receipt_file_sha256(),
            self.frozen_config_hash,
        )?;
        Ok(())
    }

    /// Production D3XX write path. Registration happens before the syscall and
    /// a transport failure poisons both the transaction tracker and session.
    pub fn write_control_via(
        &mut self,
        message: &[u8],
        now_global_time_ns: u64,
        write: impl FnOnce(&[u8]) -> io::Result<()>,
    ) -> io::Result<DirectPodSendDecision> {
        let decision = self.admit_outbound(message, now_global_time_ns)?;
        if decision == DirectPodSendDecision::Send {
            if let Err(error) = write(message) {
                self.poison_after_transport_failure();
                return Err(error);
            }
        }
        Ok(decision)
    }

    #[cfg(windows)]
    pub fn write_control(
        &mut self,
        device: &mut D3xxDevice,
        message: &[u8],
        now_global_time_ns: u64,
    ) -> io::Result<DirectPodSendDecision> {
        self.write_control_via(message, now_global_time_ns, |bytes| {
            device.write_control(bytes)
        })
    }

    /// Feeds one D3XX read completion. The chunk may contain any split or
    /// coalescing of exact records and low-speed messages.
    pub fn push_chunk(&mut self, chunk: &[u8], now_global_time_ns: u64) -> io::Result<()> {
        self.push_chunk_with_clocks(chunk, now_global_time_ns, now_global_time_ns)
    }

    pub fn push_chunk_with_clocks(
        &mut self,
        chunk: &[u8],
        now_global_time_ns: u64,
        host_monotonic_ns: u64,
    ) -> io::Result<()> {
        self.require_healthy()?;
        if chunk.is_empty() || now_global_time_ns == 0 || host_monotonic_ns == 0 {
            return Err(invalid_input(
                "direct-Pod ingest requires bytes and current hardware time",
            ));
        }

        let Self {
            admission,
            admitted_dhl_identity,
            run_id,
            pod_id,
            headstage_id,
            acquisition_state,
            stream,
            control,
            stop_boundary,
            replay_boundary,
            pending_replay_offer,
            latest_replay_offer_sequence,
            replay_offer_count,
            hardware_time,
            cabline_source,
            writer,
            committed_record_count,
            durable_record_count,
            first_journal_sequence,
            last_journal_sequence,
            first_record_evidence_hash,
            source_stop_boundary_verified,
            verified_replay_count,
            last_reply,
            ..
        } = self;

        let transport_epoch = stream.stats().transport_epoch;
        let result = stream.push_with_cabline(chunk, |kind, message| match kind {
            DirectPodExtendedFrameKind::CanonicalRecord => {
                if *source_stop_boundary_verified {
                    return Err(invalid_data(
                        "canonical record arrived after the verified Stop boundary",
                    ));
                }
                if !control.snapshot().capability_admitted {
                    return Err(invalid_data(
                        "canonical record arrived before device capabilities",
                    ));
                }
                if *acquisition_state != DirectPodAcquisitionState::Recording {
                    return Err(invalid_data(
                        "canonical record arrived before a verified Start ACK",
                    ));
                }
                if pending_replay_offer.is_some()
                    && replay_boundary
                        .as_ref()
                        .is_none_or(|boundary| boundary.is_terminal())
                {
                    return Err(invalid_data(
                        "canonical live record arrived after a quiesced Replay offer and before Replay OUT",
                    ));
                }
                let decoded = decode_record(message)
                    .map_err(|_| invalid_data("direct-Pod canonical record is invalid"))?;
                if decoded.envelope.run_id != *run_id
                    || decoded.envelope.pod_id != *pod_id
                    || decoded.envelope.headstage_id != *headstage_id
                {
                    return Err(invalid_data(
                        "direct-Pod record identity does not match the admitted Run",
                    ));
                }
                validate_canonical_record_against_admitted_dhl_identity(
                    &decoded,
                    admitted_dhl_identity.as_ref(),
                )?;
                if let Some(replay) = replay_boundary.as_mut() {
                    match replay.snapshot().state {
                        DirectPodReplayState::Receiving => replay.stage_next_record(message)?,
                        DirectPodReplayState::Durable => {
                            return Err(invalid_data(
                                "canonical record arrived while Replay awaited its ACK",
                            ))
                        }
                        DirectPodReplayState::Verified | DirectPodReplayState::Rejected => {}
                    }
                }
                let receipt = writer.append_record(message)?;
                if let Some(replay) = replay_boundary.as_mut() {
                    if replay.is_receiving() {
                        replay.commit_journaled_record(receipt)?;
                    }
                }
                stop_boundary.observe_journaled_record(message, receipt)?;
                *committed_record_count = committed_record_count
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("direct-Pod committed counter overflow"))?;
                if first_journal_sequence.is_none() {
                    *first_journal_sequence = Some(receipt.journal_sequence);
                }
                *last_journal_sequence = Some(receipt.journal_sequence);
                if first_record_evidence_hash.is_none() {
                    *first_record_evidence_hash = Some(sha256(message));
                }
                if let Some(replay) = replay_boundary.as_mut() {
                    let snapshot = replay.snapshot();
                    if snapshot.state == DirectPodReplayState::Receiving
                        && snapshot.next_record_sequence == snapshot.last_record_sequence_exclusive
                    {
                        let checkpoint = writer.durability_barrier()?;
                        *durable_record_count = checkpoint.durable_record_count;
                        replay.mark_durable(checkpoint)?;
                    }
                }
                Ok(())
            }
            DirectPodExtendedFrameKind::LowSpeedMessage => {
                let decoded = decode_low_speed(message)
                    .map_err(|_| invalid_data("direct-Pod low-speed message is invalid"))?;
                match decoded.kind {
                    MessageKind::DeviceCapabilities => {
                        if *committed_record_count != 0
                            || *source_stop_boundary_verified
                            || control.snapshot().pending_request_id.is_some()
                        {
                            return Err(invalid_data(
                                "device capabilities arrived after the data/control epoch began",
                            ));
                        }
                        control.admit_capabilities(message, admission)?;
                        *acquisition_state = DirectPodAcquisitionState::Ready;
                        Ok(())
                    }
                    MessageKind::Ack | MessageKind::Nack => {
                        let reply_header = decode_low_speed(message)
                            .map_err(|_| invalid_data("direct-Pod reply is invalid"))?;
                        let replay_matches = replay_boundary.as_ref().is_some_and(|boundary| {
                            !boundary.is_terminal()
                                && boundary.snapshot().request_id == reply_header.request_id
                        });
                        let matched = if replay_matches {
                            control.handle_reply_with_replay_boundary(
                                message,
                                now_global_time_ns,
                                replay_boundary.as_mut().unwrap(),
                            )?
                        } else {
                            control.handle_reply_with_stop_boundary(
                                message,
                                now_global_time_ns,
                                stop_boundary,
                            )?
                        };
                        if matched.source_stop_boundary_verified {
                            *source_stop_boundary_verified = true;
                        }
                        if matched.replay_boundary_verified && !matched.duplicate {
                            *verified_replay_count = verified_replay_count
                                .checked_add(1)
                                .ok_or_else(|| invalid_data("verified Replay counter overflow"))?;
                        }
                        if replay_matches && !matched.duplicate {
                            if let Some(offer) = pending_replay_offer.take() {
                                *latest_replay_offer_sequence = Some(offer.offer_sequence);
                            }
                        }
                        if !matched.duplicate {
                            advance_state(acquisition_state, &matched)?;
                            if last_reply.is_some() {
                                return Err(invalid_data(
                                    "direct-Pod reply mailbox was not consumed",
                                ));
                            }
                            *last_reply = Some(matched);
                        }
                        Ok(())
                    }
                    _ => Err(invalid_data(
                        "direct-Pod IN accepts only capabilities and ACK/NACK control messages",
                    )),
                }
            }
            DirectPodExtendedFrameKind::TimeSnapshot => {
                if !control.snapshot().capability_admitted {
                    return Err(invalid_data(
                        "direct-Pod time snapshot arrived before device capabilities",
                    ));
                }
                hardware_time.observe(message, host_monotonic_ns)
            }
            DirectPodExtendedFrameKind::ReplayOffer => {
                if *acquisition_state != DirectPodAcquisitionState::Recording
                    || !control.snapshot().capability_admitted
                    || control.snapshot().pending_request_id.is_some()
                    || last_reply.is_some()
                    || pending_replay_offer.is_some()
                    || replay_boundary
                        .as_ref()
                        .is_some_and(|boundary| !boundary.is_terminal())
                {
                    return Err(invalid_data(
                        "direct-Pod Replay offer arrived outside an idle Recording control boundary",
                    ));
                }
                let offer = DirectPodReplayOfferV1::decode(message)?;
                let time_state = hardware_time.snapshot();
                let latest_time = time_state
                    .latest
                    .ok_or_else(|| invalid_data("Replay offer arrived before Pod time evidence"))?;
                let latest_host_time = time_state.latest_host_monotonic_ns.ok_or_else(|| {
                    invalid_data("Replay offer arrived without host freshness evidence")
                })?;
                offer.validate_active_boundary(
                    *run_id,
                    admission.device_id(),
                    *pod_id,
                    *headstage_id,
                    transport_epoch,
                    stop_boundary.snapshot().last_record_sequence,
                    latest_time.hardware_state_hash,
                    *latest_replay_offer_sequence,
                )?;
                if host_monotonic_ns < latest_host_time
                    || host_monotonic_ns - latest_host_time > time_state.max_host_age_ns
                    || offer.offer_global_time_ns != latest_time.global_time_ns
                    || offer.deadline_global_time_ns <= now_global_time_ns
                {
                    return Err(invalid_data(
                        "direct-Pod Replay offer time does not match current Pod state or is expired",
                    ));
                }
                *pending_replay_offer = Some(offer);
                *replay_offer_count = replay_offer_count
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("Replay offer counter overflow"))?;
                Ok(())
            }
            DirectPodExtendedFrameKind::CablineStatus => {
                if !control.snapshot().capability_admitted {
                    return Err(invalid_data(
                        "direct-Pod CABLINE status arrived before device capabilities",
                    ));
                }
                cabline_source.observe(message, host_monotonic_ns)
            }
        });
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub fn take_reply(&mut self) -> Option<MatchedDirectPodReply> {
        self.last_reply.take()
    }

    /// Converts one exact source-authored offer into a Replay request. This is
    /// side-effect free: the durable owner persists the offer evidence and
    /// request intent before calling the normal mutating OUT admission path.
    fn planned_replay_request_from_offer(&self) -> io::Result<Option<PlannedReplayFromOffer>> {
        self.require_healthy()?;
        let Some(offer) = self.pending_replay_offer else {
            return Ok(None);
        };
        if self
            .replay_boundary
            .as_ref()
            .is_some_and(|boundary| !boundary.is_terminal())
            || self.control.snapshot().pending_request_id.is_some()
        {
            return Ok(None);
        }
        let request_id = self
            .control
            .snapshot()
            .highest_request_id
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| invalid_data("automatic Replay request ID overflow"))?;
        let context_hash = self.expected_replay_request_context_hash(
            request_id,
            offer.first_missing_record_sequence,
            offer.last_missing_record_sequence_exclusive,
            offer.deadline_global_time_ns,
            offer.reason_code,
        )?;
        let request = encode_low_speed(
            0,
            request_id,
            offer.transport_epoch,
            &ReplayRequestV1 {
                run_id: offer.run_id,
                pod_id: offer.pod_id,
                first_record_sequence: offer.first_missing_record_sequence,
                last_record_sequence_exclusive: offer.last_missing_record_sequence_exclusive,
                deadline_global_time_ns: offer.deadline_global_time_ns,
                reason_code: offer.reason_code,
                request_context_hash: context_hash,
            },
        )
        .map_err(|_| invalid_data("automatic Replay request encoding failed"))?;
        Ok(Some(PlannedReplayFromOffer {
            encoded_offer: offer.encode()?.to_vec(),
            encoded_request: request,
        }))
    }

    pub fn check_control_timeout(&mut self, now_global_time_ns: u64) -> io::Result<()> {
        self.require_healthy()?;
        self.control
            .check_timeout(now_global_time_ns)
            .inspect_err(|_| self.poisoned = true)
    }

    pub fn require_fresh_hardware_time(&mut self, host_monotonic_ns: u64) -> io::Result<u64> {
        self.require_healthy()?;
        let source_status = match self.cabline_source.require_fresh_ready_status_for(
            host_monotonic_ns,
            self.pod_id,
            self.headstage_id,
            self.approved_cabline_binding_sha256,
        ) {
            Ok(value) => value,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let hardware_time = self
            .hardware_time
            .require_fresh_ready_time(host_monotonic_ns)
            .inspect_err(|_| self.poisoned = true)?;
        validate_cabline_time_coherence(source_status, hardware_time).inspect_err(|error| {
            if error.kind() != io::ErrorKind::WouldBlock {
                self.poisoned = true;
            }
        })?;
        Ok(hardware_time)
    }

    /// Returns the exact Stop boundary hash that an independently implemented
    /// Pod must produce for this ordered record prefix.
    pub fn expected_stop_receipt_hash(&self, stop_request_id: u64) -> io::Result<[u8; 32]> {
        self.require_healthy()?;
        self.stop_boundary
            .receipt_hash(self.stream.stats().transport_epoch, stop_request_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn expected_replay_request_context_hash(
        &self,
        request_id: u64,
        first_record_sequence: u64,
        last_record_sequence_exclusive: u64,
        deadline_global_time_ns: u64,
        reason_code: u16,
    ) -> io::Result<[u8; 32]> {
        self.require_healthy()?;
        DirectPodReplayBoundaryTracker::request_context_hash(
            self.run_id,
            self.admission.device_id(),
            self.pod_id,
            self.headstage_id,
            self.stream.stats().transport_epoch,
            request_id,
            first_record_sequence,
            last_record_sequence_exclusive,
            self.stop_boundary.snapshot().last_record_sequence,
            deadline_global_time_ns,
            reason_code,
            self.admission.receipt_file_sha256(),
            self.frozen_config_hash,
        )
    }

    pub fn expected_replay_receipt_hash(&self) -> io::Result<[u8; 32]> {
        self.require_healthy()?;
        self.replay_boundary
            .as_ref()
            .ok_or_else(|| invalid_data("no direct-Pod Replay is active"))?
            .receipt_hash()
    }

    pub fn durability_barrier(&mut self) -> io::Result<DurableCheckpoint> {
        self.require_healthy()?;
        let checkpoint = self.writer.durability_barrier().inspect_err(|_| {
            self.poisoned = true;
        })?;
        self.durable_record_count = checkpoint.durable_record_count;
        Ok(checkpoint)
    }

    /// Terminal success path. A verified source Stop boundary is necessary but
    /// not sufficient: this method also proves no partial frame/pending control,
    /// then performs the journal durability barrier and explicit seal.
    pub fn finish_and_seal(mut self) -> io::Result<JournalScan> {
        self.require_healthy()?;
        self.stream.finish()?;
        self.control.finish()?;
        if !self.source_stop_boundary_verified {
            return Err(invalid_data(
                "direct-Pod journal cannot seal without a verified source Stop boundary",
            ));
        }
        if self.acquisition_state != DirectPodAcquisitionState::Stopped {
            return Err(invalid_data(
                "direct-Pod journal cannot seal before the hardware stopped state",
            ));
        }
        if self.stop_boundary.snapshot().last_journal_sequence != self.last_journal_sequence {
            return Err(invalid_data(
                "direct-Pod Stop boundary and journal sequence disagree",
            ));
        }
        self.writer.seal(self.last_journal_sequence)
    }

    pub fn snapshot(&self) -> DirectPodIngestSnapshot {
        let stream = self.stream.stats();
        let control = self.control.snapshot();
        let stop_boundary = self.stop_boundary.snapshot();
        let replay_boundary = self
            .replay_boundary
            .as_ref()
            .map(DirectPodReplayBoundaryTracker::snapshot);
        let hardware_time = self.hardware_time.snapshot();
        let cabline_source = self.cabline_source.snapshot();
        DirectPodIngestSnapshot {
            acquisition_state: self.acquisition_state,
            stream,
            control,
            stop_boundary,
            replay_boundary,
            pending_replay_offer: self.pending_replay_offer,
            replay_offer_count: self.replay_offer_count,
            hardware_time,
            cabline_source,
            committed_record_count: self.committed_record_count,
            durable_record_count: self.durable_record_count,
            first_journal_sequence: self.first_journal_sequence,
            last_journal_sequence: self.last_journal_sequence,
            first_record_evidence_hash: self.first_record_evidence_hash,
            source_stop_boundary_verified: self.source_stop_boundary_verified,
            verified_replay_count: self.verified_replay_count,
            reply_waiting_for_owner: self.last_reply.is_some(),
            poisoned: self.poisoned
                || stream.poisoned
                || control.poisoned
                || stop_boundary.poisoned
                || replay_boundary.is_some_and(|boundary| boundary.poisoned)
                || hardware_time.poisoned
                || cabline_source.poisoned
                || self.writer.is_poisoned(),
        }
    }

    fn require_healthy(&self) -> io::Result<()> {
        if self.snapshot().poisoned {
            Err(invalid_data("direct-Pod ingest session is poisoned"))
        } else {
            Ok(())
        }
    }

    fn poison_after_transport_failure(&mut self) {
        self.control.poison_after_transport_failure();
        self.poisoned = true;
    }
}

const MIN_RUNTIME_READ_BYTES: usize = 1_024;
const MAX_RUNTIME_READ_BYTES: usize = 16 * 1024 * 1024;
const MAX_RUNTIME_READ_DEPTH: usize = 64;
const MAX_RUNTIME_QUEUED_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodRuntimeConfig {
    pub read_buffer_bytes: usize,
    pub read_depth: usize,
}

impl Default for DirectPodRuntimeConfig {
    fn default() -> Self {
        Self {
            read_buffer_bytes: 256 * 1024,
            read_depth: 16,
        }
    }
}

impl DirectPodRuntimeConfig {
    pub fn validate(self) -> io::Result<Self> {
        let queued_bytes = self
            .read_buffer_bytes
            .checked_mul(self.read_depth)
            .ok_or_else(|| invalid_input("direct-Pod runtime queue size overflow"))?;
        if !(MIN_RUNTIME_READ_BYTES..=MAX_RUNTIME_READ_BYTES).contains(&self.read_buffer_bytes)
            || !self.read_buffer_bytes.is_multiple_of(1_024)
            || !(2..=MAX_RUNTIME_READ_DEPTH).contains(&self.read_depth)
            || queued_bytes > MAX_RUNTIME_QUEUED_BYTES
        {
            return Err(invalid_input(
                "direct-Pod runtime queue shape violates the fixed memory policy",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectPodTransportRead {
    Idle,
    Pending,
    Complete(Vec<u8>),
}

pub trait DirectPodByteTransport {
    fn queue_read(&mut self, buffer_bytes: usize) -> io::Result<()>;
    fn queued_read_count(&self) -> usize;
    fn poll_next_read(&mut self) -> io::Result<DirectPodTransportRead>;
    fn write_control(&mut self, message: &[u8]) -> io::Result<()>;
    fn cancel_reads(&mut self) -> io::Result<()>;
    fn is_poisoned(&self) -> bool;
}

#[cfg(windows)]
impl DirectPodByteTransport for D3xxDevice {
    fn queue_read(&mut self, buffer_bytes: usize) -> io::Result<()> {
        D3xxDevice::queue_read(self, buffer_bytes)
    }

    fn queued_read_count(&self) -> usize {
        D3xxDevice::queued_read_count(self)
    }

    fn poll_next_read(&mut self) -> io::Result<DirectPodTransportRead> {
        Ok(match D3xxDevice::poll_next_read(self)? {
            D3xxReadPoll::Idle => DirectPodTransportRead::Idle,
            D3xxReadPoll::Pending => DirectPodTransportRead::Pending,
            D3xxReadPoll::Complete(bytes) => DirectPodTransportRead::Complete(bytes),
        })
    }

    fn write_control(&mut self, message: &[u8]) -> io::Result<()> {
        D3xxDevice::write_control(self, message)
    }

    fn cancel_reads(&mut self) -> io::Result<()> {
        D3xxDevice::cancel_queued_reads(self)
    }

    fn is_poisoned(&self) -> bool {
        D3xxDevice::is_io_poisoned(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectPodRuntimePoll {
    Pending,
    Ingested { bytes: usize },
    StopFrontier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodRuntimeSnapshot {
    pub ingest: DirectPodIngestSnapshot,
    pub queued_reads: usize,
    pub completed_reads: u64,
    pub completed_bytes: u64,
    pub primed: bool,
    pub stop_frontier_observed: bool,
    pub poisoned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreRunDirectPodSnapshot {
    pub stream: DirectPodStreamStats,
    pub control: DirectPodControlSnapshot,
    pub hardware_time: DirectPodTimeTrackerSnapshot,
    pub cabline_source: DirectPodCablineTrackerSnapshot,
    pub queued_reads: usize,
    pub completed_reads: u64,
    pub completed_bytes: u64,
    pub primed: bool,
    pub promoted: bool,
    pub poisoned: bool,
}

struct PreRunDirectPodInner<T: DirectPodByteTransport> {
    state: DirectPodPreflightState,
    transport: T,
    config: DirectPodRuntimeConfig,
    completed_reads: u64,
    completed_bytes: u64,
    primed: bool,
}

/// Exclusive direct-Pod owner before a Run exists.
///
/// It continuously maintains the same fixed IN queue later used by the Run,
/// and accepts only the exact admitted capability and explicit Pod-time
/// messages.  Promotion moves the parser, any partial frame, transport, queued
/// reads and counters into the journal-bound runtime; it never cancels or
/// re-primes the USB epoch.
pub struct PreRunDirectPodConnection<T: DirectPodByteTransport> {
    inner: Option<PreRunDirectPodInner<T>>,
}

pub struct DirectPodRunPromotion<T: DirectPodByteTransport> {
    runtime: DurableDirectPodRuntime<T>,
    prepare_decision: DirectPodSendDecision,
    prepare_receipt: HardwareRunReceipt,
    run_root: PathBuf,
    journal_path: PathBuf,
    hardware_ledger_path: PathBuf,
}

impl<T: DirectPodByteTransport> DirectPodRunPromotion<T> {
    pub fn runtime(&self) -> &DurableDirectPodRuntime<T> {
        &self.runtime
    }

    pub fn prepare_decision(&self) -> DirectPodSendDecision {
        self.prepare_decision
    }

    pub fn prepare_receipt(&self) -> &HardwareRunReceipt {
        &self.prepare_receipt
    }

    pub fn run_root(&self) -> &Path {
        &self.run_root
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    pub fn hardware_ledger_path(&self) -> &Path {
        &self.hardware_ledger_path
    }

    pub fn into_runtime(self) -> DurableDirectPodRuntime<T> {
        self.runtime
    }
}

impl<T: DirectPodByteTransport> PreRunDirectPodConnection<T> {
    #[cfg(test)]
    fn new_legacy_test(
        admission: VerifiedFt601Admission,
        transport: T,
        config: DirectPodRuntimeConfig,
        transport_epoch: u64,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        if admission.hardware_protocol_hash() != PROTOCOL_HASH
            || transport_epoch == 0
            || transport.queued_read_count() != 0
            || transport.is_poisoned()
        {
            return Err(invalid_input(
                "pre-Run direct-Pod connection requires admitted protocol v1 and a fresh exclusive transport",
            ));
        }
        Ok(Self {
            inner: Some(PreRunDirectPodInner {
                state: DirectPodPreflightState::new_legacy_test(
                    admission,
                    [1; 16],
                    [2; 16],
                    transport_epoch,
                )?,
                transport,
                config,
                completed_reads: 0,
                completed_bytes: 0,
                primed: false,
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_primed_bootstrap(
        admission: VerifiedFt601Admission,
        transport: T,
        config: DirectPodRuntimeConfig,
        transport_epoch: u64,
        chunks: Vec<(Vec<u8>, u64)>,
    ) -> io::Result<Self> {
        let state = DirectPodPreflightState::new_legacy_test(
            admission.clone(),
            [1; 16],
            [2; 16],
            transport_epoch,
        )?;
        Self::from_primed_with_state(state, transport, config, transport_epoch, chunks)
    }

    pub(crate) fn from_primed_bootstrap_protected(
        admission: VerifiedFt601Admission,
        transport: T,
        config: DirectPodRuntimeConfig,
        transport_epoch: u64,
        preflight: DirectPodProtectedPreflightV1,
        chunks: Vec<(Vec<u8>, u64)>,
    ) -> io::Result<Self> {
        let state = DirectPodPreflightState::new_protected(
            admission.clone(),
            preflight.dhl_identity_policy().clone(),
            preflight.pod_id(),
            preflight.headstage_id(),
            preflight.approved_cabline_binding_sha256(),
            transport_epoch,
        )?;
        Self::from_primed_with_state(state, transport, config, transport_epoch, chunks)
    }

    fn from_primed_with_state(
        state: DirectPodPreflightState,
        transport: T,
        config: DirectPodRuntimeConfig,
        transport_epoch: u64,
        chunks: Vec<(Vec<u8>, u64)>,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        if state.admission.hardware_protocol_hash() != PROTOCOL_HASH
            || transport_epoch == 0
            || transport.queued_read_count() != config.read_depth
            || transport.is_poisoned()
            || chunks.is_empty()
        {
            return Err(invalid_input(
                "bootstrapped direct-Pod connection requires admitted protocol v1, exact primed queue, and captured source bytes",
            ));
        }
        let completed_reads = u64::try_from(chunks.len())
            .map_err(|_| invalid_data("bootstrap completion count exceeds u64"))?;
        let completed_bytes = chunks.iter().try_fold(0_u64, |total, (chunk, _)| {
            if chunk.is_empty() {
                return Err(invalid_data("bootstrap captured an empty IN completion"));
            }
            total
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| invalid_data("bootstrap completed-byte counter overflow"))
        })?;
        let mut connection = Self {
            inner: Some(PreRunDirectPodInner {
                state,
                transport,
                config,
                completed_reads,
                completed_bytes,
                primed: true,
            }),
        };
        for (chunk, observed_at) in chunks {
            let result = {
                let inner = connection.inner_mut()?;
                Self::push_preflight_chunk(inner, &chunk, observed_at)
            };
            if let Err(error) = result {
                connection.fail_transport();
                return Err(error);
            }
        }
        let snapshot = connection.snapshot();
        if !snapshot.control.capability_admitted
            || snapshot.stream.canonical_records != 0
            || snapshot.queued_reads != config.read_depth
        {
            connection.fail_transport();
            return Err(invalid_data(
                "bootstrap did not yield exactly one admitted pre-Run capability state",
            ));
        }
        Ok(connection)
    }

    pub fn prime_reads(&mut self) -> io::Result<()> {
        self.require_healthy()?;
        let inner = self.inner_mut()?;
        if inner.primed || inner.transport.queued_read_count() != 0 {
            return Err(invalid_input(
                "pre-Run direct-Pod reads are already primed or externally changed",
            ));
        }
        while inner.transport.queued_read_count() < inner.config.read_depth {
            let before = inner.transport.queued_read_count();
            if let Err(error) = inner.transport.queue_read(inner.config.read_buffer_bytes) {
                self.fail_transport();
                return Err(error);
            }
            if inner.transport.queued_read_count() != before + 1 {
                self.fail_transport();
                return Err(invalid_data(
                    "pre-Run transport did not queue exactly one read",
                ));
            }
        }
        if inner.transport.queued_read_count() != inner.config.read_depth {
            self.fail_transport();
            return Err(invalid_data(
                "pre-Run transport contradicted the fixed read depth",
            ));
        }
        inner.primed = true;
        Ok(())
    }

    pub fn poll_once(&mut self, host_monotonic_ns: u64) -> io::Result<DirectPodRuntimePoll> {
        self.require_healthy()?;
        if host_monotonic_ns == 0 {
            return Err(invalid_input(
                "pre-Run direct-Pod poll requires host monotonic time",
            ));
        }
        let inner = self.inner_mut()?;
        if !inner.primed {
            return Err(invalid_input("pre-Run direct-Pod reads are not primed"));
        }
        match inner.transport.poll_next_read() {
            Ok(DirectPodTransportRead::Pending) => {
                if inner.transport.queued_read_count() == 0
                    || inner.transport.queued_read_count() > inner.config.read_depth
                {
                    self.fail_transport();
                    return Err(invalid_data(
                        "pre-Run pending poll contradicts the bounded read queue",
                    ));
                }
                Ok(DirectPodRuntimePoll::Pending)
            }
            Ok(DirectPodTransportRead::Complete(bytes)) => {
                if bytes.is_empty() {
                    self.fail_transport();
                    return Err(invalid_data(
                        "pre-Run transport completed an empty IN transfer",
                    ));
                }
                let length = bytes.len();
                if let Err(error) = Self::push_preflight_chunk(inner, &bytes, host_monotonic_ns) {
                    self.fail_transport();
                    return Err(error);
                }
                inner.completed_reads = inner
                    .completed_reads
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("pre-Run read counter overflow"))?;
                inner.completed_bytes = inner
                    .completed_bytes
                    .checked_add(length as u64)
                    .ok_or_else(|| invalid_data("pre-Run byte counter overflow"))?;
                if inner.transport.queued_read_count() >= inner.config.read_depth {
                    self.fail_transport();
                    return Err(invalid_data(
                        "pre-Run completion did not consume one queued read",
                    ));
                }
                if let Err(error) = inner.transport.queue_read(inner.config.read_buffer_bytes) {
                    self.fail_transport();
                    return Err(error);
                }
                if inner.transport.queued_read_count() != inner.config.read_depth {
                    self.fail_transport();
                    return Err(invalid_data(
                        "pre-Run read queue was not restored to its fixed depth",
                    ));
                }
                Ok(DirectPodRuntimePoll::Ingested { bytes: length })
            }
            Ok(DirectPodTransportRead::Idle) => {
                self.fail_transport();
                Err(invalid_data("pre-Run transport lost its primed read queue"))
            }
            Err(error) => {
                self.fail_transport();
                Err(error)
            }
        }
    }

    /// Creates a no-overwrite Run root, moves the still-primed connection into
    /// the journal-bound lifecycle, durably records Prepare, and only then
    /// writes the translated command to hardware.
    #[cfg(test)]
    fn prepare_and_promote(
        &mut self,
        request: &OperatorRunRequestV1,
        plan: &DirectPodRunPlan,
        host_monotonic_ns: u64,
    ) -> io::Result<DirectPodRunPromotion<T>> {
        self.prepare_and_promote_from_owner(request, plan, host_monotonic_ns, Instant::now())
    }

    pub(crate) fn prepare_and_promote_from_owner(
        &mut self,
        request: &OperatorRunRequestV1,
        plan: &DirectPodRunPlan,
        host_monotonic_ns: u64,
        wall_started: Instant,
    ) -> io::Result<DirectPodRunPromotion<T>> {
        self.require_ready_for_promotion()?;
        let inner = self.inner_mut()?;
        let transport_epoch = inner.state.stream.stats().transport_epoch;
        plan.validate_request(request, inner.state.admission.device_id(), transport_epoch)?;
        let source_status = inner.state.cabline_source.require_fresh_ready_status_for(
            host_monotonic_ns,
            plan.pod_id,
            plan.headstage_id,
            plan.approved_cabline_binding_sha256,
        )?;
        let message = translate_operator_run_request(
            request,
            &mut inner.state.hardware_time,
            host_monotonic_ns,
        )?;
        let hardware_now = inner
            .state
            .hardware_time
            .require_fresh_ready_time(host_monotonic_ns)?;
        if let Err(error) = validate_cabline_time_coherence(source_status, hardware_now) {
            if error.kind() != io::ErrorKind::WouldBlock {
                inner.state.poisoned = true;
            }
            return Err(error);
        }
        let freshness_guard =
            HostFreshnessGuard::from_preflight(&inner.state, host_monotonic_ns, wall_started)?;

        // Artifact creation can fail while this object still owns the healthy
        // transport.  No state is moved and no OUT occurs before both succeed.
        let (writer, lifecycle) = plan.create_artifacts()?;
        let inner = self
            .inner
            .take()
            .ok_or_else(|| invalid_data("pre-Run connection was already promoted"))?;
        let session = DirectPodIngestSession::from_preflight(
            writer,
            inner.state,
            plan.run_id,
            plan.pod_id,
            plan.headstage_id,
            plan.frozen_config_hash,
            plan.approved_cabline_binding_sha256,
            true,
        )?;
        let runtime = DirectPodRuntime::from_promoted_preflight(
            session,
            inner.transport,
            inner.config,
            inner.completed_reads,
            inner.completed_bytes,
        )?;
        let mut runtime = DurableDirectPodRuntime::from_promoted_preflight(runtime, lifecycle)?;
        let (prepare_decision, prepare_receipt) =
            runtime.send_run_command_guarded(&message, hardware_now, &freshness_guard)?;
        if prepare_decision != DirectPodSendDecision::Send {
            return Err(invalid_data(
                "newly promoted direct-Pod Prepare was not a new hardware send",
            ));
        }
        Ok(DirectPodRunPromotion {
            runtime,
            prepare_decision,
            prepare_receipt,
            run_root: plan.run_root.clone(),
            journal_path: plan.journal_path(),
            hardware_ledger_path: plan.hardware_ledger_path(),
        })
    }

    pub fn snapshot(&self) -> PreRunDirectPodSnapshot {
        let Some(inner) = self.inner.as_ref() else {
            return PreRunDirectPodSnapshot {
                stream: DirectPodStreamStats {
                    transport_epoch: 0,
                    received_bytes: 0,
                    canonical_records: 0,
                    low_speed_messages: 0,
                    time_snapshots: 0,
                    replay_offers: 0,
                    emitted_bytes: 0,
                    pending_bytes: 0,
                    poisoned: false,
                },
                control: DirectPodControlSnapshot {
                    transport_epoch: 0,
                    capability_admitted: false,
                    pending_request_id: None,
                    highest_request_id: None,
                    sent_request_count: 0,
                    matched_reply_count: 0,
                    duplicate_reply_count: 0,
                    poisoned: false,
                },
                hardware_time: DirectPodTimeTrackerSnapshot {
                    transport_epoch: 0,
                    status_count: 0,
                    latest: None,
                    latest_host_monotonic_ns: None,
                    max_host_age_ns: 0,
                    poisoned: false,
                },
                cabline_source: DirectPodCablineTrackerSnapshot {
                    transport_epoch: 0,
                    status_count: 0,
                    latest: None,
                    latest_host_monotonic_ns: None,
                    max_host_age_ns: 0,
                    poisoned: false,
                },
                queued_reads: 0,
                completed_reads: 0,
                completed_bytes: 0,
                primed: false,
                promoted: true,
                poisoned: false,
            };
        };
        let stream = inner.state.stream.stats();
        let control = inner.state.control.snapshot();
        let hardware_time = inner.state.hardware_time.snapshot();
        let cabline_source = inner.state.cabline_source.snapshot();
        PreRunDirectPodSnapshot {
            stream,
            control,
            hardware_time,
            cabline_source,
            queued_reads: inner.transport.queued_read_count(),
            completed_reads: inner.completed_reads,
            completed_bytes: inner.completed_bytes,
            primed: inner.primed,
            promoted: false,
            poisoned: inner.state.poisoned
                || stream.poisoned
                || control.poisoned
                || hardware_time.poisoned
                || cabline_source.poisoned
                || inner.transport.is_poisoned(),
        }
    }

    pub fn admission_receipt_sha256(&self) -> io::Result<[u8; 32]> {
        self.require_healthy()?;
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| invalid_input("pre-Run direct-Pod connection was already promoted"))?
            .state
            .admission
            .receipt_file_sha256())
    }

    pub(crate) fn preflight_identity_ready(&self, host_monotonic_ns: u64) -> io::Result<bool> {
        self.require_healthy()?;
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| invalid_input("pre-Run direct-Pod connection was already promoted"))?;
        let snapshot = self.snapshot();
        if !snapshot.primed
            || !snapshot.control.capability_admitted
            || snapshot.hardware_time.latest.is_none()
            || snapshot.cabline_source.latest.is_none()
            || inner.transport.queued_read_count() != inner.config.read_depth
        {
            return Ok(false);
        }
        for (received, max_age) in [
            (
                snapshot.hardware_time.latest_host_monotonic_ns,
                snapshot.hardware_time.max_host_age_ns,
            ),
            (
                snapshot.cabline_source.latest_host_monotonic_ns,
                snapshot.cabline_source.max_host_age_ns,
            ),
        ] {
            let Some(received) = received else {
                return Ok(false);
            };
            let age = host_monotonic_ns
                .checked_sub(received)
                .ok_or_else(|| invalid_data("pre-Run host monotonic clock regressed"))?;
            if age > max_age {
                return Ok(false);
            }
        }
        if inner.state.identity_required {
            let Some(identity) = inner.state.admitted_dhl_identity.as_ref() else {
                return Ok(false);
            };
            let status = snapshot.cabline_source.latest.expect("checked above");
            if status.configuration_binding_hash() != inner.state.approved_cabline_binding_sha256 {
                return Err(invalid_data(
                    "CABLINE configuration binding hash contradicts protected policy",
                ));
            }
            validate_cabline_identity_binding(status, identity)?;
        }
        let time = snapshot.hardware_time.latest.expect("checked above");
        let required_time_flags = TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY;
        if time.runtime_flags & TIME_FLAG_POD_FAULT != 0 {
            return Err(invalid_data("pre-Run Pod time reports a hardware fault"));
        }
        if time.runtime_flags & required_time_flags != required_time_flags {
            return Ok(false);
        }
        let status = snapshot.cabline_source.latest.expect("checked above");
        if status.global_time_ns > time.global_time_ns
            || time.global_time_ns - status.global_time_ns > DIRECT_POD_CABLINE_MAX_HOST_AGE_NS
        {
            return Ok(false);
        }
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn disable_identity_requirement_for_legacy_test(&mut self) -> io::Result<()> {
        self.inner_mut()?.state.identity_required = false;
        Ok(())
    }

    pub fn require_fresh_hardware_time_for(
        &mut self,
        host_monotonic_ns: u64,
        pod_id: [u8; 16],
        headstage_id: [u8; 16],
        approved_cabline_binding_sha256: [u8; 32],
    ) -> io::Result<u64> {
        self.require_healthy()?;
        let inner = self.inner_mut()?;
        let source_status = inner.state.cabline_source.require_fresh_ready_status_for(
            host_monotonic_ns,
            pod_id,
            headstage_id,
            approved_cabline_binding_sha256,
        )?;
        if inner.state.identity_required {
            let identity = inner.state.admitted_dhl_identity.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "DHL identity capsule is not admitted",
                )
            })?;
            validate_cabline_identity_binding(source_status, identity)?;
        }
        let hardware_time = inner
            .state
            .hardware_time
            .require_fresh_ready_time(host_monotonic_ns)?;
        if let Err(error) = validate_cabline_time_coherence(source_status, hardware_time) {
            if error.kind() != io::ErrorKind::WouldBlock {
                inner.state.poisoned = true;
            }
            return Err(error);
        }
        Ok(hardware_time)
    }

    fn push_preflight_chunk(
        inner: &mut PreRunDirectPodInner<T>,
        chunk: &[u8],
        host_monotonic_ns: u64,
    ) -> io::Result<()> {
        let DirectPodPreflightState {
            admission,
            dhl_identity_policy,
            dhl_catalog,
            dhl_context,
            admitted_dhl_identity,
            dhl_capsule_evidence_hash,
            stream,
            control,
            hardware_time,
            cabline_source,
            ..
        } = &mut inner.state;
        let result = stream.push_with_identity(chunk, |kind, message| match kind {
            DirectPodIdentityFrameKind::CanonicalRecord => Err(invalid_data(
                "canonical data arrived before a direct-Pod Run was prepared",
            )),
            DirectPodIdentityFrameKind::LowSpeedMessage => {
                let decoded = decode_low_speed(message)
                    .map_err(|_| invalid_data("pre-Run direct-Pod control is invalid"))?;
                if decoded.kind != MessageKind::DeviceCapabilities {
                    return Err(invalid_data(
                        "pre-Run direct-Pod accepts only DeviceCapabilitiesV1",
                    ));
                }
                control.admit_capabilities(message, admission)?;
                Ok(())
            }
            DirectPodIdentityFrameKind::TimeSnapshot => {
                if !control.snapshot().capability_admitted {
                    return Err(invalid_data(
                        "pre-Run Pod time arrived before device capabilities",
                    ));
                }
                hardware_time.observe(message, host_monotonic_ns)
            }
            DirectPodIdentityFrameKind::ReplayOffer => Err(invalid_data(
                "Replay offer arrived before a direct-Pod Run was recording",
            )),
            DirectPodIdentityFrameKind::CablineStatus => {
                if !control.snapshot().capability_admitted {
                    return Err(invalid_data(
                        "pre-Run CABLINE status arrived before device capabilities",
                    ));
                }
                cabline_source.observe(message, host_monotonic_ns)
            }
            DirectPodIdentityFrameKind::DhlIdentityCapsule => {
                if !control.snapshot().capability_admitted {
                    return Err(invalid_data(
                        "DHL identity capsule arrived before device capabilities",
                    ));
                }
                let capsule = DirectPodDhlIdentityCapsuleV1::decode(message)
                    .map_err(|_| invalid_data("pre-Run DHL identity capsule is invalid"))?;
                let admitted = admit_new_run_dhl_identity_capsule_v1(
                    &capsule,
                    dhl_context,
                    dhl_catalog,
                    dhl_identity_policy,
                )
                .map_err(|_| {
                    invalid_data("pre-Run DHL identity capsule does not match protected policy")
                })?;
                // Keep the admitted identity out of preflight state until the
                // first DeviceCapabilities statement proves its capacity,
                // format, and exact rational-rate bounds.
                control
                    .validate_admitted_identity_against_capabilities(&admitted.admitted_identity)?;
                let evidence_hash = sha256(message);
                match (admitted_dhl_identity.as_ref(), *dhl_capsule_evidence_hash) {
                    (None, None) => {
                        *admitted_dhl_identity = Some(admitted);
                        *dhl_capsule_evidence_hash = Some(evidence_hash);
                        Ok(())
                    }
                    (Some(prior), Some(prior_hash))
                        if prior_hash == evidence_hash && prior == &admitted =>
                    {
                        Ok(())
                    }
                    _ => Err(invalid_data(
                        "second or mutated DHL identity capsule contradicts pre-Run identity",
                    )),
                }
            }
        });
        if result.is_err() {
            inner.state.poisoned = true;
        }
        result
    }

    fn require_ready_for_promotion(&self) -> io::Result<()> {
        self.require_healthy()?;
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| invalid_input("pre-Run direct-Pod connection was already promoted"))?;
        let snapshot = self.snapshot();
        if !snapshot.primed
            || !snapshot.control.capability_admitted
            || snapshot.hardware_time.latest.is_none()
            || snapshot.cabline_source.latest.is_none()
            || snapshot.control.pending_request_id.is_some()
            || snapshot.control.highest_request_id.is_some()
            || snapshot.stream.canonical_records != 0
            || inner.transport.queued_read_count() != inner.config.read_depth
            || (inner.state.identity_required && inner.state.admitted_dhl_identity.is_none())
        {
            return Err(invalid_input(
                "pre-Run direct-Pod promotion requires admitted capabilities, Pod time, CABLINE source status, and an exact primed queue",
            ));
        }
        if let (Some(status), Some(identity)) = (
            snapshot.cabline_source.latest,
            inner.state.admitted_dhl_identity.as_ref(),
        ) {
            validate_cabline_identity_binding(status, identity)?;
        }
        Ok(())
    }

    fn require_healthy(&self) -> io::Result<()> {
        let snapshot = self.snapshot();
        if snapshot.promoted {
            Err(invalid_input(
                "pre-Run direct-Pod connection was already promoted",
            ))
        } else if snapshot.poisoned {
            Err(invalid_data("pre-Run direct-Pod connection is poisoned"))
        } else {
            Ok(())
        }
    }

    fn inner_mut(&mut self) -> io::Result<&mut PreRunDirectPodInner<T>> {
        self.inner
            .as_mut()
            .ok_or_else(|| invalid_input("pre-Run direct-Pod connection was already promoted"))
    }

    /// Ends an admitted pre-Run owner without synthesizing a hardware command.
    /// A later connection must be opened and admitted as a new transport epoch.
    pub fn shutdown_owner(&mut self) -> io::Result<()> {
        let inner = self.inner_mut()?;
        inner.state.poisoned = true;
        inner.state.control.poison_after_transport_failure();
        inner.transport.cancel_reads()
    }

    fn fail_transport(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            inner.state.poisoned = true;
            inner.state.control.poison_after_transport_failure();
            let _ = inner.transport.cancel_reads();
        }
    }
}

/// Single-owner scheduler for one admitted direct-Pod transport and ingest
/// session. It never creates threads and never derives hardware time from USB
/// arrival; the owning service must supply the current hardware-global time.
pub struct DirectPodRuntime<T: DirectPodByteTransport> {
    session: DirectPodIngestSession,
    transport: T,
    config: DirectPodRuntimeConfig,
    completed_reads: u64,
    completed_bytes: u64,
    primed: bool,
    stop_frontier_observed: bool,
    poisoned: bool,
}

impl<T: DirectPodByteTransport> DirectPodRuntime<T> {
    pub fn new(
        session: DirectPodIngestSession,
        transport: T,
        config: DirectPodRuntimeConfig,
    ) -> io::Result<Self> {
        if session.admitted_dhl_identity.is_some() != session.dhl_capsule_evidence_hash.is_some() {
            return Err(invalid_input(
                "direct-Pod Run must retain both admitted DHL identity and capsule evidence hash",
            ));
        }
        Ok(Self {
            session,
            transport,
            config: config.validate()?,
            completed_reads: 0,
            completed_bytes: 0,
            primed: false,
            stop_frontier_observed: false,
            poisoned: false,
        })
    }

    fn from_promoted_preflight(
        session: DirectPodIngestSession,
        transport: T,
        config: DirectPodRuntimeConfig,
        completed_reads: u64,
        completed_bytes: u64,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        let snapshot = session.snapshot();
        if snapshot.poisoned
            || snapshot.acquisition_state != DirectPodAcquisitionState::Ready
            || !snapshot.control.capability_admitted
            || snapshot.control.pending_request_id.is_some()
            || snapshot.control.highest_request_id.is_some()
            || snapshot.hardware_time.latest.is_none()
            || snapshot.cabline_source.latest.is_none()
            || snapshot.committed_record_count != 0
            || snapshot.reply_waiting_for_owner
            || transport.is_poisoned()
            || transport.queued_read_count() != config.read_depth
        {
            return Err(invalid_input(
                "promoted direct-Pod runtime state does not preserve a healthy exact pre-Run queue",
            ));
        }
        Ok(Self {
            session,
            transport,
            config,
            completed_reads,
            completed_bytes,
            primed: true,
            stop_frontier_observed: false,
            poisoned: false,
        })
    }

    pub fn prime_reads(&mut self) -> io::Result<()> {
        self.require_healthy()?;
        if self.primed || self.transport.queued_read_count() != 0 {
            return Err(invalid_input(
                "direct-Pod runtime reads are already primed or externally changed",
            ));
        }
        while self.transport.queued_read_count() < self.config.read_depth {
            let before = self.transport.queued_read_count();
            if let Err(error) = self.transport.queue_read(self.config.read_buffer_bytes) {
                self.fail_transport();
                return Err(error);
            }
            if self.transport.queued_read_count() != before + 1 {
                self.fail_transport();
                return Err(invalid_data(
                    "direct-Pod transport did not queue exactly one read",
                ));
            }
        }
        if self.transport.queued_read_count() != self.config.read_depth {
            self.fail_transport();
            return Err(invalid_data(
                "direct-Pod transport contradicted the requested read depth",
            ));
        }
        self.primed = true;
        Ok(())
    }

    pub(crate) fn send_control(
        &mut self,
        message: &[u8],
        now_global_time_ns: u64,
    ) -> io::Result<DirectPodSendDecision> {
        self.require_healthy()?;
        let mut transport_failed = false;
        let result =
            self.session
                .write_control_via(message, now_global_time_ns, |bytes| {
                    match self.transport.write_control(bytes) {
                        Ok(()) => Ok(()),
                        Err(error) => {
                            transport_failed = true;
                            Err(error)
                        }
                    }
                });
        if transport_failed || (result.is_err() && self.session.snapshot().poisoned) {
            self.fail_transport();
        }
        result
    }

    pub fn poll_once(&mut self, now_global_time_ns: u64) -> io::Result<DirectPodRuntimePoll> {
        self.poll_once_with_clocks(now_global_time_ns, now_global_time_ns)
    }

    pub fn poll_once_with_clocks(
        &mut self,
        now_global_time_ns: u64,
        host_monotonic_ns: u64,
    ) -> io::Result<DirectPodRuntimePoll> {
        self.require_healthy()?;
        if !self.primed {
            return Err(invalid_input("direct-Pod runtime reads are not primed"));
        }
        if let Err(error) = self.session.check_control_timeout(now_global_time_ns) {
            self.fail_transport();
            return Err(error);
        }
        match self.transport.poll_next_read() {
            Ok(DirectPodTransportRead::Pending) => {
                if self.transport.queued_read_count() == 0
                    || self.transport.queued_read_count() > self.config.read_depth
                {
                    self.fail_transport();
                    return Err(invalid_data(
                        "direct-Pod pending poll contradicts the bounded read queue",
                    ));
                }
                if self.session.snapshot().source_stop_boundary_verified {
                    self.stop_frontier_observed = true;
                    Ok(DirectPodRuntimePoll::StopFrontier)
                } else {
                    Ok(DirectPodRuntimePoll::Pending)
                }
            }
            Ok(DirectPodTransportRead::Complete(bytes)) => {
                if bytes.is_empty() {
                    self.fail_transport();
                    return Err(invalid_data(
                        "direct-Pod transport completed an empty IN transfer",
                    ));
                }
                let length = bytes.len();
                if let Err(error) = self.session.push_chunk_with_clocks(
                    &bytes,
                    now_global_time_ns,
                    host_monotonic_ns,
                ) {
                    self.fail_transport();
                    return Err(error);
                }
                let Some(completed_reads) = self.completed_reads.checked_add(1) else {
                    self.fail_transport();
                    return Err(invalid_data("direct-Pod read counter overflow"));
                };
                let Some(completed_bytes) = self.completed_bytes.checked_add(length as u64) else {
                    self.fail_transport();
                    return Err(invalid_data("direct-Pod byte counter overflow"));
                };
                self.completed_reads = completed_reads;
                self.completed_bytes = completed_bytes;
                if self.transport.queued_read_count() >= self.config.read_depth {
                    self.fail_transport();
                    return Err(invalid_data(
                        "direct-Pod completion did not consume one queued read",
                    ));
                }
                if !self.session.snapshot().source_stop_boundary_verified {
                    if let Err(error) = self.transport.queue_read(self.config.read_buffer_bytes) {
                        self.fail_transport();
                        return Err(error);
                    }
                    if self.transport.queued_read_count() != self.config.read_depth {
                        self.fail_transport();
                        return Err(invalid_data(
                            "direct-Pod read queue was not restored to its fixed depth",
                        ));
                    }
                }
                Ok(DirectPodRuntimePoll::Ingested { bytes: length })
            }
            Ok(DirectPodTransportRead::Idle) => {
                self.fail_transport();
                Err(invalid_data(
                    "direct-Pod transport lost its primed read queue",
                ))
            }
            Err(error) => {
                self.fail_transport();
                Err(error)
            }
        }
    }

    pub fn take_reply(&mut self) -> Option<MatchedDirectPodReply> {
        self.session.take_reply()
    }

    pub fn require_fresh_hardware_time(&mut self, host_monotonic_ns: u64) -> io::Result<u64> {
        self.session.require_fresh_hardware_time(host_monotonic_ns)
    }

    pub fn expected_stop_receipt_hash(&self, stop_request_id: u64) -> io::Result<[u8; 32]> {
        self.session.expected_stop_receipt_hash(stop_request_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn expected_replay_request_context_hash(
        &self,
        request_id: u64,
        first_record_sequence: u64,
        last_record_sequence_exclusive: u64,
        deadline_global_time_ns: u64,
        reason_code: u16,
    ) -> io::Result<[u8; 32]> {
        self.session.expected_replay_request_context_hash(
            request_id,
            first_record_sequence,
            last_record_sequence_exclusive,
            deadline_global_time_ns,
            reason_code,
        )
    }

    pub fn expected_replay_receipt_hash(&self) -> io::Result<[u8; 32]> {
        self.session.expected_replay_receipt_hash()
    }

    pub fn snapshot(&self) -> DirectPodRuntimeSnapshot {
        let ingest = self.session.snapshot();
        DirectPodRuntimeSnapshot {
            ingest,
            queued_reads: self.transport.queued_read_count(),
            completed_reads: self.completed_reads,
            completed_bytes: self.completed_bytes,
            primed: self.primed,
            stop_frontier_observed: self.stop_frontier_observed,
            poisoned: self.poisoned || ingest.poisoned || self.transport.is_poisoned(),
        }
    }

    pub fn finish_and_seal(mut self) -> io::Result<JournalScan> {
        self.require_healthy()?;
        if !self.stop_frontier_observed {
            return Err(invalid_data(
                "direct-Pod seal requires a pending-read frontier after verified Stop",
            ));
        }
        self.transport.cancel_reads()?;
        self.session.finish_and_seal()
    }

    fn require_healthy(&self) -> io::Result<()> {
        if self.snapshot().poisoned {
            Err(invalid_data("direct-Pod runtime is poisoned"))
        } else {
            Ok(())
        }
    }

    fn fail_transport(&mut self) {
        self.poisoned = true;
        self.session.poison_after_transport_failure();
        let _ = self.transport.cancel_reads();
    }

    fn shutdown_owner(&mut self) -> io::Result<()> {
        self.poisoned = true;
        self.session.poison_after_transport_failure();
        self.transport.cancel_reads()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableDirectPodRuntimeSnapshot {
    pub runtime: DirectPodRuntimeSnapshot,
    pub lifecycle: HardwareRunStatus,
    pub reply_waiting_for_owner: bool,
    pub poisoned: bool,
}

/// Couples one real transport owner to the durable hardware lifecycle.
///
/// The request event is on stable storage before OUT is written. Matched ACK or
/// NACK evidence is persisted from the same ordered owner that journals IN
/// records. Start becomes Recording only after this wrapper observes the first
/// successful journal append. It does not install a service or claim hardware
/// availability.
pub struct DurableDirectPodRuntime<T: DirectPodByteTransport> {
    runtime: DirectPodRuntime<T>,
    lifecycle: HardwareRunCoordinator,
    last_reply: Option<MatchedDirectPodReply>,
    poisoned: bool,
}

impl<T: DirectPodByteTransport> DurableDirectPodRuntime<T> {
    pub fn new(
        runtime: DirectPodRuntime<T>,
        lifecycle: HardwareRunCoordinator,
    ) -> io::Result<Self> {
        let runtime_snapshot = runtime.snapshot();
        if lifecycle.phase() != HardwareRunPhase::New
            || runtime_snapshot.ingest.acquisition_state
                != DirectPodAcquisitionState::AwaitingCapabilities
            || runtime_snapshot.ingest.committed_record_count != 0
            || runtime_snapshot.ingest.reply_waiting_for_owner
            || runtime_snapshot.primed
            || runtime_snapshot.poisoned
        {
            return Err(invalid_input(
                "durable direct-Pod ownership requires fresh transport, ingest, and lifecycle state",
            ));
        }
        Ok(Self {
            runtime,
            lifecycle,
            last_reply: None,
            poisoned: false,
        })
    }

    fn from_promoted_preflight(
        runtime: DirectPodRuntime<T>,
        lifecycle: HardwareRunCoordinator,
    ) -> io::Result<Self> {
        let runtime_snapshot = runtime.snapshot();
        if lifecycle.phase() != HardwareRunPhase::New
            || runtime_snapshot.ingest.acquisition_state != DirectPodAcquisitionState::Ready
            || !runtime_snapshot.ingest.control.capability_admitted
            || runtime_snapshot.ingest.hardware_time.latest.is_none()
            || runtime_snapshot.ingest.cabline_source.latest.is_none()
            || runtime_snapshot.ingest.committed_record_count != 0
            || runtime_snapshot.ingest.reply_waiting_for_owner
            || !runtime_snapshot.primed
            || runtime_snapshot.poisoned
        {
            return Err(invalid_input(
                "promoted durable direct-Pod ownership requires a ready primed preflight and fresh lifecycle",
            ));
        }
        Ok(Self {
            runtime,
            lifecycle,
            last_reply: None,
            poisoned: false,
        })
    }

    pub fn prime_reads(&mut self) -> io::Result<()> {
        self.require_healthy()?;
        match self.runtime.prime_reads() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.fail_closed_for_error(&error);
                Err(error)
            }
        }
    }

    fn capture_source_freshness(
        &mut self,
        host_monotonic_ns: u64,
        wall_started: Instant,
    ) -> io::Result<(u64, HostFreshnessGuard)> {
        let result = (|| {
            let hardware_now = self
                .runtime
                .require_fresh_hardware_time(host_monotonic_ns)?;
            let guard = HostFreshnessGuard::from_session(
                &self.runtime.session,
                host_monotonic_ns,
                wall_started,
            )?;
            Ok((hardware_now, guard))
        })();
        if let Err(error) = &result {
            self.runtime.fail_transport();
            self.fail_closed_for_error(error);
        }
        result
    }

    fn enforce_freshness_guard(&mut self, guard: &HostFreshnessGuard) -> io::Result<()> {
        if let Err(error) = guard.ensure_valid() {
            self.runtime.fail_transport();
            self.fail_closed_for_error(&error);
            return Err(error);
        }
        Ok(())
    }

    fn send_run_command_guarded(
        &mut self,
        message: &[u8],
        now_global_time_ns: u64,
        freshness_guard: &HostFreshnessGuard,
    ) -> io::Result<(DirectPodSendDecision, HardwareRunReceipt)> {
        self.require_healthy()?;
        self.enforce_freshness_guard(freshness_guard)?;
        let receipt = match self.lifecycle.request(message, now_global_time_ns) {
            Ok(receipt) => receipt,
            Err(error) => {
                // No OUT has occurred, but the connection can no longer prove
                // that accepted intent is durable. Close this transport epoch
                // instead of leaving a still-live, unaccounted hardware owner.
                self.runtime.fail_transport();
                self.fail_closed_for_error(&error);
                return Err(error);
            }
        };
        if receipt.hardware_accepted.is_some() {
            return Ok((DirectPodSendDecision::AlreadyCompleted, receipt));
        }
        self.enforce_freshness_guard(freshness_guard)?;
        match self.runtime.send_control(message, now_global_time_ns) {
            Ok(DirectPodSendDecision::AlreadyCompleted) => {
                let error = invalid_data(
                    "transport reports completion before durable hardware reply evidence",
                );
                self.fail_closed_for_error(&error);
                Err(error)
            }
            Ok(decision) => Ok((decision, receipt)),
            Err(error) => {
                self.fail_closed_for_error(&error);
                Err(error)
            }
        }
    }

    /// Production clock path: the command deadline is evaluated against the
    /// latest fresh Pod time snapshot; host monotonic time only gates staleness.
    #[cfg(test)]
    fn send_run_command_from_snapshot(
        &mut self,
        message: &[u8],
        host_monotonic_ns: u64,
    ) -> io::Result<(DirectPodSendDecision, HardwareRunReceipt)> {
        let wall_started = Instant::now();
        let (hardware_now, freshness_guard) =
            self.capture_source_freshness(host_monotonic_ns, wall_started)?;
        self.send_run_command_guarded(message, hardware_now, &freshness_guard)
    }

    /// Persists Replay intent in the hardware ledger before writing OUT.
    /// Exact completed retries return the durable receipt without retransmit.
    fn send_replay_request_guarded(
        &mut self,
        message: &[u8],
        now_global_time_ns: u64,
        freshness_guard: &HostFreshnessGuard,
    ) -> io::Result<(DirectPodSendDecision, HardwareReplayReceipt)> {
        self.require_healthy()?;
        self.enforce_freshness_guard(freshness_guard)?;
        self.runtime
            .session
            .validate_replay_request_before_persistence(message)?;
        let receipt = match self.lifecycle.request_replay(message, now_global_time_ns) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.runtime.fail_transport();
                self.fail_closed_for_error(&error);
                return Err(error);
            }
        };
        if receipt.hardware_accepted.is_some() {
            return Ok((DirectPodSendDecision::AlreadyCompleted, receipt));
        }
        self.enforce_freshness_guard(freshness_guard)?;
        match self.runtime.send_control(message, now_global_time_ns) {
            Ok(DirectPodSendDecision::AlreadyCompleted) => {
                let error = invalid_data(
                    "transport reports Replay completion before durable hardware reply evidence",
                );
                self.fail_closed_for_error(&error);
                Err(error)
            }
            Ok(decision) => Ok((decision, receipt)),
            Err(error) => {
                self.fail_closed_for_error(&error);
                Err(error)
            }
        }
    }

    /// Production Replay path. Pod time supplies the command time while the
    /// owner clock gates both CABLINE/time evidence before durable intent and
    /// again immediately before OUT.
    #[cfg(test)]
    fn send_replay_request_from_snapshot(
        &mut self,
        message: &[u8],
        host_monotonic_ns: u64,
    ) -> io::Result<(DirectPodSendDecision, HardwareReplayReceipt)> {
        let wall_started = Instant::now();
        let (hardware_now, freshness_guard) =
            self.capture_source_freshness(host_monotonic_ns, wall_started)?;
        self.send_replay_request_guarded(message, hardware_now, &freshness_guard)
    }

    /// Converts a local operator request using the exact time tracker owned by
    /// this Run, then persists the resulting M0 intent before hardware OUT.
    pub(crate) fn send_operator_run_request_from_owner(
        &mut self,
        request: &OperatorRunRequestV1,
        host_monotonic_ns: u64,
        wall_started: Instant,
    ) -> io::Result<(DirectPodSendDecision, HardwareRunReceipt)> {
        self.require_healthy()?;
        if request.run_id != self.runtime.session.run_id {
            return Err(invalid_input(
                "operator Run identity does not match the journal-bound direct-Pod session",
            ));
        }
        let message = translate_operator_run_request(
            request,
            &mut self.runtime.session.hardware_time,
            host_monotonic_ns,
        )?;
        let (hardware_now, freshness_guard) =
            self.capture_source_freshness(host_monotonic_ns, wall_started)?;
        self.send_run_command_guarded(&message, hardware_now, &freshness_guard)
    }

    pub fn poll_once(&mut self, now_global_time_ns: u64) -> io::Result<DirectPodRuntimePoll> {
        self.poll_once_with_clocks_started(now_global_time_ns, now_global_time_ns, Instant::now())
    }

    fn poll_once_with_clocks_started(
        &mut self,
        now_global_time_ns: u64,
        host_monotonic_ns: u64,
        wall_started: Instant,
    ) -> io::Result<DirectPodRuntimePoll> {
        self.require_healthy()?;
        if self.last_reply.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the previous durable direct-Pod reply has not been consumed",
            ));
        }
        let before = self.runtime.snapshot().ingest.committed_record_count;
        let polled = match self
            .runtime
            .poll_once_with_clocks(now_global_time_ns, host_monotonic_ns)
        {
            Ok(value) => value,
            Err(error) => {
                self.fail_closed_for_error(&error);
                return Err(error);
            }
        };

        if let Some(plan) = self.runtime.session.planned_replay_request_from_offer()? {
            let (hardware_now, freshness_guard) =
                self.capture_source_freshness(host_monotonic_ns, wall_started)?;
            if let Err(error) = self.lifecycle.record_replay_offer(&plan.encoded_offer) {
                self.fail_closed_for_error(&error);
                return Err(error);
            }
            if let Err(error) = self.send_replay_request_guarded(
                &plan.encoded_request,
                hardware_now,
                &freshness_guard,
            ) {
                self.fail_closed_for_error(&error);
                return Err(error);
            }
        }

        if let Some(reply) = self.runtime.take_reply() {
            let accepted = matches!(reply.reply, DirectPodReply::Ack(_));
            let persisted = if reply.request_kind == MessageKind::ReplayRequest {
                self.lifecycle
                    .complete_replay_reply(
                        reply.epoch,
                        reply.request_id,
                        accepted,
                        reply.reply_sha256,
                        reply.replay_boundary_verified,
                    )
                    .map(|_| ())
            } else {
                self.lifecycle
                    .complete_reply(
                        reply.epoch,
                        reply.request_id,
                        accepted,
                        reply.reply_sha256,
                        reply.source_stop_boundary_verified,
                    )
                    .map(|_| ())
            };
            if let Err(error) = persisted {
                self.fail_closed_for_error(&error);
                return Err(error);
            }
            if !accepted {
                self.runtime.fail_transport();
                self.poisoned = true;
            }
            self.last_reply = Some(reply);
        }

        let ingest = self.runtime.snapshot().ingest;
        if ingest.committed_record_count > before
            && self.lifecycle.phase() == HardwareRunPhase::StartAcknowledged
        {
            let epoch = self
                .lifecycle
                .status()
                .active_epoch
                .ok_or_else(|| invalid_data("acknowledged Start has no durable epoch"))?;
            let run_id = self.runtime.session.run_id;
            let journal_sequence = ingest
                .first_journal_sequence
                .ok_or_else(|| invalid_data("journaled record has no first sequence"))?;
            let evidence_hash = ingest
                .first_record_evidence_hash
                .ok_or_else(|| invalid_data("journaled record has no evidence hash"))?;
            if let Err(error) = self.lifecycle.observe_first_journaled_record(
                epoch,
                run_id,
                journal_sequence,
                evidence_hash,
            ) {
                self.fail_closed_for_error(&error);
                return Err(error);
            }
        }
        Ok(polled)
    }

    /// Polls capabilities/time snapshots before a Run and uses only a fresh Pod
    /// time while a control request is pending. The fallback value is never
    /// exposed as hardware time and is legal only when no command is in flight.
    pub fn poll_once_from_snapshot(
        &mut self,
        host_monotonic_ns: u64,
    ) -> io::Result<DirectPodRuntimePoll> {
        self.poll_once_from_snapshot_started(host_monotonic_ns, Instant::now())
    }

    pub(crate) fn poll_once_from_snapshot_started(
        &mut self,
        host_monotonic_ns: u64,
        wall_started: Instant,
    ) -> io::Result<DirectPodRuntimePoll> {
        let snapshot = self.runtime.snapshot().ingest;
        let now_global_time_ns = if snapshot.control.pending_request_id.is_some() {
            self.runtime
                .require_fresh_hardware_time(host_monotonic_ns)?
        } else {
            snapshot
                .hardware_time
                .latest
                .map(|value| value.global_time_ns)
                .unwrap_or(1)
        };
        self.poll_once_with_clocks_started(now_global_time_ns, host_monotonic_ns, wall_started)
    }

    pub fn take_reply(&mut self) -> Option<MatchedDirectPodReply> {
        self.last_reply.take()
    }

    pub fn expected_stop_receipt_hash(&self, stop_request_id: u64) -> io::Result<[u8; 32]> {
        self.runtime.expected_stop_receipt_hash(stop_request_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn expected_replay_request_context_hash(
        &self,
        request_id: u64,
        first_record_sequence: u64,
        last_record_sequence_exclusive: u64,
        deadline_global_time_ns: u64,
        reason_code: u16,
    ) -> io::Result<[u8; 32]> {
        self.runtime.expected_replay_request_context_hash(
            request_id,
            first_record_sequence,
            last_record_sequence_exclusive,
            deadline_global_time_ns,
            reason_code,
        )
    }

    pub fn expected_replay_receipt_hash(&self) -> io::Result<[u8; 32]> {
        self.runtime.expected_replay_receipt_hash()
    }

    pub fn durability_barrier(&mut self) -> io::Result<DurableCheckpoint> {
        self.require_healthy()?;
        match self.runtime.session.durability_barrier() {
            Ok(value) => Ok(value),
            Err(error) => {
                self.fail_closed_for_error(&error);
                Err(error)
            }
        }
    }

    pub fn snapshot(&self) -> DurableDirectPodRuntimeSnapshot {
        let runtime = self.runtime.snapshot();
        let lifecycle = self.lifecycle.status();
        DurableDirectPodRuntimeSnapshot {
            poisoned: self.poisoned || runtime.poisoned || lifecycle.poisoned,
            runtime,
            lifecycle,
            reply_waiting_for_owner: self.last_reply.is_some(),
        }
    }

    pub fn active_context(&self) -> Option<HardwareRunContext> {
        self.lifecycle.active_context()
    }

    pub fn admission_receipt_sha256(&self) -> [u8; 32] {
        self.runtime.session.admission.receipt_file_sha256()
    }

    /// Requires a Pod-originated time snapshot that is still fresh in the
    /// caller's host-monotonic domain. USB arrival time is never substituted.
    pub fn require_fresh_hardware_time(&mut self, host_monotonic_ns: u64) -> io::Result<u64> {
        self.require_healthy()?;
        self.runtime.require_fresh_hardware_time(host_monotonic_ns)
    }

    pub fn finish_and_seal(mut self) -> io::Result<(JournalScan, HardwareRunStatus)> {
        self.require_healthy()?;
        if self.lifecycle.phase() != HardwareRunPhase::Stopped {
            return Err(invalid_input(
                "durable direct-Pod seal requires verified hardware Stop",
            ));
        }
        let scan = self.runtime.finish_and_seal()?;
        let seal = scan
            .seal
            .as_ref()
            .ok_or_else(|| invalid_data("journal seal receipt is missing"))?;
        let evidence_hash = seal_evidence_hash(scan.identity.run_id, seal);
        self.lifecycle.mark_sealed(evidence_hash)?;
        Ok((scan, self.lifecycle.status()))
    }

    /// Cancels the transport and durably marks every unfinished hardware Run
    /// failed before the exclusive owner exits. This is a local fault record,
    /// not a Pod Stop ACK and never permits the old Run to resume.
    pub fn shutdown_owner(&mut self) -> io::Result<()> {
        let cancel_result = self.runtime.shutdown_owner();
        self.poisoned = true;
        self.last_reply = None;

        let phase = self.lifecycle.phase();
        let failure_result = if matches!(
            phase,
            HardwareRunPhase::New
                | HardwareRunPhase::Sealed
                | HardwareRunPhase::Aborted
                | HardwareRunPhase::Failed
        ) {
            Ok(())
        } else {
            let context = self
                .lifecycle
                .active_context()
                .ok_or_else(|| invalid_data("unfinished hardware Run has no durable context"))?;
            let mut evidence = Vec::new();
            evidence.extend_from_slice(b"FORGE-DIRECT-POD-OWNER-SHUTDOWN-V1");
            evidence.extend_from_slice(&context.run_id);
            evidence.extend_from_slice(&context.epoch.to_le_bytes());
            evidence.extend_from_slice(&(phase as u16).to_le_bytes());
            self.lifecycle
                .fail_closed(HARDWARE_FAULT_OWNER_SHUTDOWN, sha256(&evidence))
        };

        failure_result.and(cancel_result)
    }

    fn require_healthy(&self) -> io::Result<()> {
        if self.snapshot().poisoned {
            Err(invalid_data("durable direct-Pod runtime is poisoned"))
        } else {
            Ok(())
        }
    }

    fn fail_closed_for_error(&mut self, error: &io::Error) {
        self.poisoned = true;
        let evidence_hash = sha256(error.to_string().as_bytes());
        let _ = self
            .lifecycle
            .fail_closed(HARDWARE_FAULT_TRANSPORT, evidence_hash);
    }
}

fn command_allowed(state: DirectPodAcquisitionState, command: u16) -> bool {
    matches!(
        (state, command),
        (DirectPodAcquisitionState::Ready, 1)
            | (DirectPodAcquisitionState::Prepared, 2)
            | (DirectPodAcquisitionState::Armed, 3)
            | (DirectPodAcquisitionState::Recording, 4)
            | (
                DirectPodAcquisitionState::Prepared
                    | DirectPodAcquisitionState::Armed
                    | DirectPodAcquisitionState::Recording,
                5
            )
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandDisposition {
    New,
    Idempotent,
    Invalid,
}

fn classify_command(state: DirectPodAcquisitionState, command: u16) -> CommandDisposition {
    if command_allowed(state, command) {
        return CommandDisposition::New;
    }
    if matches!(
        (state, command),
        (DirectPodAcquisitionState::Prepared, 1)
            | (DirectPodAcquisitionState::Armed, 2)
            | (DirectPodAcquisitionState::Recording, 3)
            | (DirectPodAcquisitionState::Stopped, 4)
            | (DirectPodAcquisitionState::Aborted, 5)
    ) {
        CommandDisposition::Idempotent
    } else {
        CommandDisposition::Invalid
    }
}

fn advance_state(
    state: &mut DirectPodAcquisitionState,
    matched: &MatchedDirectPodReply,
) -> io::Result<()> {
    let DirectPodReply::Ack(AckV1 {
        ack_code,
        state_code,
        ..
    }) = &matched.reply
    else {
        return Ok(());
    };
    let Some(command) = matched.run_command else {
        return Ok(());
    };
    let (required_state_code, next) = match command {
        1 => (1, DirectPodAcquisitionState::Prepared),
        2 => (2, DirectPodAcquisitionState::Armed),
        3 => (3, DirectPodAcquisitionState::Recording),
        4 => (4, DirectPodAcquisitionState::Stopped),
        5 => (6, DirectPodAcquisitionState::Aborted),
        _ => return Err(invalid_data("unknown direct-Pod acquisition command ACK")),
    };
    if *ack_code != 1 || *state_code != required_state_code || !command_allowed(*state, command) {
        return Err(invalid_data(
            "direct-Pod ACK code/state contradicts the requested transition",
        ));
    }
    *state = next;
    Ok(())
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate_cabline_time_coherence(
    source_status: DirectPodCablineStatusV1,
    hardware_time_ns: u64,
) -> io::Result<()> {
    if source_status.global_time_ns > hardware_time_ns {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "CABLINE source status is newer than the latest Pod time snapshot",
        ));
    }
    if hardware_time_ns - source_status.global_time_ns > DIRECT_POD_CABLINE_MAX_HOST_AGE_NS {
        return Err(invalid_data(
            "CABLINE source status is stale relative to Pod hardware time",
        ));
    }
    Ok(())
}

fn validate_cabline_identity_binding(
    status: DirectPodCablineStatusV1,
    identity: &AdmittedDirectPodDhlIdentityCapsuleV1,
) -> io::Result<()> {
    if status.device_id != identity.device_id
        || status.pod_id != identity.pod_id
        || status.headstage_id != identity.headstage_id
        || status.transport_epoch != identity.transport_epoch
        || status.headstage_boot_id != identity.boot_id
        || status.source_id != identity.source_id
        || status.next_dhl_sequence < identity.next_sequence
        || status.headstage_config_hash != identity.admitted_identity.approved_config_hash
        || status.descriptor_hash != identity.admitted_identity.descriptor_payload_sha256
        || status.inventory_hash != identity.admitted_identity.inventory_payload_sha256
        || status.assembly_manifest_hash != identity.admitted_identity.assembly_manifest_hash
        || status.channel_map_hash != identity.admitted_identity.channel_map_hash
    {
        return Err(invalid_data(
            "CABLINE source status contradicts admitted DHL identity evidence",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_protocol_v1::{
        crc32c, decode_record, encode_low_speed, encode_record, sha256, AckV1,
        DeviceCapabilitiesV1, NackV1, ReplayRequestV1, RunCommandV1, CAP_ACK_REPLAY,
        CAP_GLOBAL_TIME, CAP_STOP_ACK, RECORD_FLAG_REPLAYED, RECORD_HEADER_LEN,
    };

    use crate::d3xx_admission::{FT601_ADMISSION_CONTRACT_HASH, FT601_ADMISSION_RECEIPT_LEN};
    use crate::dhl_identity_admission::{
        DhlExpectedInstancePolicyV1, DhlIdentityAdmissionPolicyV1, DHL_CAP_ELECTRODE_IMPEDANCE,
        DHL_CAP_STREAM_NEURAL,
    };
    use crate::direct_pod_cabline::{DirectPodCablineStatusV1, CABLINE_REQUIRED_READY_FLAGS};
    use crate::direct_pod_replay_offer::{DirectPodReplayOfferV1, REPLAY_OFFER_REQUIRED_FLAGS};
    use crate::direct_pod_time::{
        DirectPodTimeSnapshotV1, TIME_FLAG_GLOBAL_TIME_VALID, TIME_FLAG_POD_READY,
    };
    use crate::hardware_service::{
        DirectPodRunPlanProvider, JournalBoundDirectPodBackend, OwnedHardwareServiceBackend,
        PromotableDirectPodBackend,
    };
    use crate::hardware_service_protocol::{
        HardwareServiceBackend, HardwareServiceState, OperatorRunRequestV1,
        AVAIL_HARDWARE_AVAILABLE,
    };
    use crate::journal::{inspect_recovery, JournalIdentity, JournalReader, JournalRecovery};
    use crate::run::RunCommandKind;
    use crate::source::{DeterministicReplayConfig, DeterministicReplaySource};

    const RUN_ID: [u8; 16] = [1; 16];
    const DEVICE_ID: [u8; 16] = [2; 16];
    const POD_ID: [u8; 16] = [3; 16];
    const HEADSTAGE_ID: [u8; 16] = [4; 16];
    const EPOCH: u64 = 7;

    #[derive(Default)]
    struct FakeTransportState {
        queued_reads: usize,
        polls: VecDeque<DirectPodTransportRead>,
        writes: Vec<Vec<u8>>,
        cancel_count: usize,
        poisoned: bool,
        fail_next_write: bool,
    }

    #[derive(Clone)]
    struct FakeTransportController(Arc<Mutex<FakeTransportState>>);

    struct FakeTransport(Arc<Mutex<FakeTransportState>>);

    impl FakeTransportController {
        fn push(&self, value: DirectPodTransportRead) {
            self.0.lock().unwrap().polls.push_back(value);
        }

        fn snapshot(&self) -> (usize, usize, usize, bool) {
            let state = self.0.lock().unwrap();
            (
                state.queued_reads,
                state.writes.len(),
                state.cancel_count,
                state.poisoned,
            )
        }

        fn writes(&self) -> Vec<Vec<u8>> {
            self.0.lock().unwrap().writes.clone()
        }

        fn fail_next_write(&self) {
            self.0.lock().unwrap().fail_next_write = true;
        }
    }

    impl FakeTransport {
        fn new() -> (Self, FakeTransportController) {
            let state = Arc::new(Mutex::new(FakeTransportState::default()));
            (Self(Arc::clone(&state)), FakeTransportController(state))
        }
    }

    impl DirectPodByteTransport for FakeTransport {
        fn queue_read(&mut self, _buffer_bytes: usize) -> io::Result<()> {
            let mut state = self.0.lock().unwrap();
            if state.poisoned {
                return Err(invalid_data("fake direct-Pod transport is poisoned"));
            }
            state.queued_reads += 1;
            Ok(())
        }

        fn queued_read_count(&self) -> usize {
            self.0.lock().unwrap().queued_reads
        }

        fn poll_next_read(&mut self) -> io::Result<DirectPodTransportRead> {
            let mut state = self.0.lock().unwrap();
            if state.poisoned {
                return Err(invalid_data("fake direct-Pod transport is poisoned"));
            }
            if state.queued_reads == 0 {
                return Ok(DirectPodTransportRead::Idle);
            }
            let value = state
                .polls
                .pop_front()
                .unwrap_or(DirectPodTransportRead::Pending);
            if matches!(value, DirectPodTransportRead::Complete(_)) {
                state.queued_reads -= 1;
            }
            Ok(value)
        }

        fn write_control(&mut self, message: &[u8]) -> io::Result<()> {
            let mut state = self.0.lock().unwrap();
            if state.poisoned {
                return Err(invalid_data("fake direct-Pod transport is poisoned"));
            }
            if state.fail_next_write {
                state.fail_next_write = false;
                state.poisoned = true;
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected direct-Pod control write failure",
                ));
            }
            state.writes.push(message.to_vec());
            Ok(())
        }

        fn cancel_reads(&mut self) -> io::Result<()> {
            let mut state = self.0.lock().unwrap();
            state.queued_reads = 0;
            state.cancel_count += 1;
            Ok(())
        }

        fn is_poisoned(&self) -> bool {
            self.0.lock().unwrap().poisoned
        }
    }

    struct TestFiles {
        journal: PathBuf,
        admission: PathBuf,
    }

    impl TestFiles {
        fn new(name: &str) -> Self {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "forge-direct-pod-ingest-{name}-{}-{stamp}",
                std::process::id()
            ));
            Self {
                journal: PathBuf::from(format!("{}.forgewal", root.display())),
                admission: PathBuf::from(format!("{}.admission", root.display())),
            }
        }
    }

    impl Drop for TestFiles {
        fn drop(&mut self) {
            for path in [&self.admission, &self.journal] {
                let _ = std::fs::remove_file(path);
            }
            for suffix in [".checkpoint-a", ".checkpoint-b", ".seal"] {
                let _ = std::fs::remove_file(PathBuf::from(format!(
                    "{}{suffix}",
                    self.journal.display()
                )));
            }
            let _ = std::fs::remove_dir_all(PathBuf::from(format!(
                "{}.hardware-ledger",
                self.journal.display()
            )));
            for suffix in [".promotion", ".wrong-run", ".wrong-state", ".existing"] {
                let _ = std::fs::remove_dir_all(PathBuf::from(format!(
                    "{}{suffix}",
                    self.journal.display()
                )));
            }
        }
    }

    fn verified_admission(path: &PathBuf) -> VerifiedFt601Admission {
        let authority = [8; 32];
        let mut bytes = Vec::with_capacity(FT601_ADMISSION_RECEIPT_LEN);
        bytes.extend_from_slice(b"FGRD3A61");
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&(FT601_ADMISSION_RECEIPT_LEN as u16).to_le_bytes());
        bytes.extend_from_slice(&crate::d3xx_admission::FT601_PROFILE_BRINGUP_66_MHZ.to_le_bytes());
        bytes.extend_from_slice(&FT601_ADMISSION_CONTRACT_HASH);
        bytes.extend_from_slice(&[9; 16]);
        bytes.extend_from_slice(&DEVICE_ID);
        let mut serial = [0_u8; 16];
        serial[..8].copy_from_slice(b"FORGE001");
        bytes.extend_from_slice(&serial);
        bytes.extend_from_slice(&[5; 32]);
        bytes.extend_from_slice(&[6; 32]);
        bytes.extend_from_slice(&[7; 32]);
        bytes.extend_from_slice(&PROTOCOL_HASH);
        bytes.extend_from_slice(&[10; 32]);
        bytes.extend_from_slice(&authority);
        bytes.extend_from_slice(&10_u64.to_le_bytes());
        bytes.extend_from_slice(&100_u64.to_le_bytes());
        bytes.extend_from_slice(&[0; 12]);
        let checksum = crc32c(&bytes);
        bytes.extend_from_slice(&checksum.to_le_bytes());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        VerifiedFt601Admission::load(path, sha256(&bytes), authority, 50).unwrap()
    }

    fn new_session(name: &str) -> (TestFiles, DirectPodIngestSession) {
        let files = TestFiles::new(name);
        let admission = verified_admission(&files.admission);
        let writer =
            JournalWriter::create(&files.journal, JournalIdentity::for_run(RUN_ID).unwrap())
                .unwrap();
        let session = DirectPodIngestSession::new(
            writer,
            &admission,
            RUN_ID,
            POD_ID,
            HEADSTAGE_ID,
            [0x55; 32],
            approved_cabline_binding_sha256(),
            EPOCH,
        )
        .unwrap();
        (files, session)
    }

    fn protected_descriptor_payload() -> Vec<u8> {
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
        descriptor[28..44].copy_from_slice(&HEADSTAGE_ID);
        descriptor[44..76].copy_from_slice(&[0x55; 32]);
        descriptor[76..92].copy_from_slice(&[0x33; 16]);
        descriptor
    }

    fn protected_inventory_payload() -> Vec<u8> {
        let mut inventory = vec![0_u8; 108];
        inventory[0..2].copy_from_slice(&1_u16.to_le_bytes());
        inventory[2..4].copy_from_slice(&76_u16.to_le_bytes());
        inventory[4..6].copy_from_slice(&32_u16.to_le_bytes());
        inventory[6..8].copy_from_slice(&1_u16.to_le_bytes());
        inventory[8..12].copy_from_slice(&1_u32.to_le_bytes());
        inventory[12..44].copy_from_slice(&[0x66; 32]);
        inventory[44..76].copy_from_slice(&[0x77; 32]);
        let entry = 76;
        inventory[entry..entry + 2].copy_from_slice(&0_u16.to_le_bytes());
        inventory[entry + 2] = 1;
        inventory[entry + 3] = 2;
        inventory[entry + 4..entry + 8].copy_from_slice(&0x0001_0001_u32.to_le_bytes());
        inventory[entry + 8..entry + 10].copy_from_slice(&0_u16.to_le_bytes());
        inventory[entry + 10..entry + 12].copy_from_slice(&32_u16.to_le_bytes());
        inventory[entry + 12..entry + 14].copy_from_slice(&0_u16.to_le_bytes());
        inventory[entry + 14..entry + 16].copy_from_slice(&1_u16.to_le_bytes());
        inventory[entry + 16..entry + 20]
            .copy_from_slice(&(DHL_CAP_STREAM_NEURAL | DHL_CAP_ELECTRODE_IMPEDANCE).to_le_bytes());
        inventory[entry + 20..entry + 32].copy_from_slice(&[0x44; 12]);
        inventory
    }

    fn protected_admitted_identity() -> AdmittedDirectPodDhlIdentityCapsuleV1 {
        let descriptor = protected_descriptor_payload();
        let inventory = protected_inventory_payload();
        let policy = protected_policy();
        let capsule = DirectPodDhlIdentityCapsuleV1 {
            device_id: DEVICE_ID,
            pod_id: POD_ID,
            headstage_id: HEADSTAGE_ID,
            transport_epoch: EPOCH,
            descriptor_wire: identity_dhl_wire(1, 1, &descriptor),
            inventory_wire: identity_dhl_wire(9, 2, &inventory),
        };
        let capsule = DirectPodDhlIdentityCapsuleV1::decode(&capsule.encode().unwrap()).unwrap();
        admit_new_run_dhl_identity_capsule_v1(
            &capsule,
            &DirectPodDhlIdentityContextV1 {
                device_id: DEVICE_ID,
                pod_id: POD_ID,
                headstage_id: HEADSTAGE_ID,
                transport_epoch: EPOCH,
            },
            &DhlIdentityCatalog::load_embedded().unwrap(),
            &policy,
        )
        .unwrap()
    }

    fn protected_policy() -> DhlIdentityAdmissionPolicyV1 {
        DhlIdentityAdmissionPolicyV1 {
            profile_id: "rhd2132x1".to_owned(),
            expected_descriptor_payload_sha256: sha256(&protected_descriptor_payload()),
            expected_inventory_payload_sha256: sha256(&protected_inventory_payload()),
            expected_device_id: HEADSTAGE_ID,
            expected_config_hash: [0x55; 32],
            sample_rate_numerator_hz: 30_000,
            sample_rate_denominator: 1,
            approved_channel_layout_id: 0x1020_3040,
            assembly_manifest_hash: [0x66; 32],
            channel_map_hash: [0x77; 32],
            ordered_expected_instances: vec![DhlExpectedInstancePolicyV1 {
                instance_id: 0,
                exact_driver_abi: 1,
                exact_capability_flags: DHL_CAP_STREAM_NEURAL | DHL_CAP_ELECTRODE_IMPEDANCE,
                config_hash_prefix: [0x44; 12],
            }],
        }
    }

    fn new_protected_record_session(name: &str) -> (TestFiles, DirectPodIngestSession) {
        let (files, mut session) = new_session(name);
        let admitted = protected_admitted_identity();
        assert_eq!(
            admitted.admitted_identity.approved_channel_layout_id,
            0x1020_3040
        );
        assert_ne!(
            admitted.admitted_identity.approved_channel_layout_id,
            u32::from(admitted.admitted_identity.identity.board_profile_id)
        );
        session.dhl_capsule_evidence_hash = Some(sha256(b"protected-test-capsule"));
        session.admitted_dhl_identity = Some(admitted);
        (files, session)
    }

    fn start_protected_recording(session: &mut DirectPodIngestSession) {
        session.push_chunk(&capabilities(), 50).unwrap();
        for (request_id, command_code) in [(1_u64, 1_u16), (2, 2), (3, 3)] {
            session
                .admit_outbound(&command(request_id, command_code), request_id * 100)
                .unwrap();
            session
                .push_chunk(
                    &ack(request_id, command_code, [0x40 + request_id as u8; 32]),
                    request_id * 100 + 50,
                )
                .unwrap();
            session.take_reply().unwrap();
        }
        assert_eq!(
            session.snapshot().acquisition_state,
            DirectPodAcquisitionState::Recording
        );
    }

    fn protected_record(channel_count: u16) -> Vec<u8> {
        let mut source = DeterministicReplaySource::new(DeterministicReplayConfig {
            run_id: RUN_ID,
            pod_id: POD_ID,
            headstage_id: HEADSTAGE_ID,
            channel_layout_id: 0x1020_3040,
            channel_count,
            samples_per_channel: 3,
            sample_rate_hz: 30_000,
            total_records: 1,
            seed: 1,
        })
        .unwrap();
        source.next_encoded_record().unwrap().unwrap()
    }

    fn protected_record_with_rate(numerator: u32, denominator: u32) -> Vec<u8> {
        let record = protected_record(32);
        let decoded = decode_record(&record).unwrap();
        let mut block = SampleBlockV1::decode(&decoded.payload).unwrap();
        block.sample_rate_numerator_hz = numerator;
        block.sample_rate_denominator = denominator;
        encode_record(&decoded.envelope, &block.encode().unwrap()).unwrap()
    }

    fn protected_record_with_noncanonical_format() -> Vec<u8> {
        let mut record = protected_record(32);
        record[134..136].copy_from_slice(&2_u16.to_le_bytes());
        record[RECORD_HEADER_LEN + 14..RECORD_HEADER_LEN + 16]
            .copy_from_slice(&2_u16.to_le_bytes());
        let payload_crc = crc32c(&record[RECORD_HEADER_LEN..]);
        record[168..172].copy_from_slice(&payload_crc.to_le_bytes());
        let header_crc = crc32c(&record[..172]);
        record[172..176].copy_from_slice(&header_crc.to_le_bytes());
        record
    }

    fn new_pre_run(
        name: &str,
    ) -> (
        TestFiles,
        PreRunDirectPodConnection<FakeTransport>,
        FakeTransportController,
    ) {
        let files = TestFiles::new(name);
        let admission = verified_admission(&files.admission);
        let (transport, controller) = FakeTransport::new();
        let connection = PreRunDirectPodConnection::new_legacy_test(
            admission,
            transport,
            DirectPodRuntimeConfig {
                read_buffer_bytes: 1_024,
                read_depth: 2,
            },
            EPOCH,
        )
        .unwrap();
        (files, connection, controller)
    }

    fn new_protected_pre_run(
        name: &str,
    ) -> (
        TestFiles,
        PreRunDirectPodConnection<FakeTransport>,
        FakeTransportController,
    ) {
        let files = TestFiles::new(name);
        let admission = verified_admission(&files.admission);
        let (transport, controller) = FakeTransport::new();
        let state = DirectPodPreflightState::new_protected(
            admission,
            protected_policy(),
            POD_ID,
            HEADSTAGE_ID,
            approved_cabline_binding_sha256(),
            EPOCH,
        )
        .unwrap();
        let connection = PreRunDirectPodConnection {
            inner: Some(PreRunDirectPodInner {
                state,
                transport,
                config: DirectPodRuntimeConfig {
                    read_buffer_bytes: 1_024,
                    read_depth: 2,
                },
                completed_reads: 0,
                completed_bytes: 0,
                primed: false,
            }),
        };
        (files, connection, controller)
    }

    fn run_plan(files: &TestFiles, suffix: &str) -> DirectPodRunPlan {
        DirectPodRunPlan::new(
            PathBuf::from(format!("{}.{suffix}", files.journal.display())),
            RUN_ID,
            POD_ID,
            HEADSTAGE_ID,
            [0x55; 32],
            approved_cabline_binding_sha256(),
        )
        .unwrap()
    }

    fn operator_prepare(state_sequence: u64) -> OperatorRunRequestV1 {
        OperatorRunRequestV1 {
            request_id: 1,
            epoch: EPOCH,
            command: RunCommandKind::Prepare,
            relative_deadline_ms: 100,
            run_id: RUN_ID,
            target_device_id: DEVICE_ID,
            frozen_config_hash: [0x55; 32],
            expected_hardware_state_hash: sha256(&state_sequence.to_le_bytes()),
        }
    }

    struct TestRunPlanProvider {
        plan: DirectPodRunPlan,
    }

    impl DirectPodRunPlanProvider for TestRunPlanProvider {
        fn preflight_authority(
            &self,
        ) -> io::Result<crate::hardware_service::DirectPodPreflightAuthority> {
            crate::hardware_service::DirectPodPreflightAuthority::new(
                self.plan.pod_id(),
                self.plan.headstage_id(),
                self.plan.approved_cabline_binding_sha256(),
            )
        }

        fn plan_for_prepare(
            &mut self,
            _request: &OperatorRunRequestV1,
        ) -> io::Result<DirectPodRunPlan> {
            Ok(self.plan.clone())
        }
    }

    fn capabilities() -> Vec<u8> {
        capabilities_with_limits(256, 30_000, 30_000)
    }

    fn capabilities_with_limits(
        max_channels_per_pod: u16,
        min_sample_rate_hz: u32,
        max_sample_rate_hz: u32,
    ) -> Vec<u8> {
        encode_low_speed(
            0,
            900,
            EPOCH,
            &DeviceCapabilitiesV1 {
                device_id: DEVICE_ID,
                transport: 1,
                max_pods: 1,
                max_channels_per_pod,
                sample_format_mask: 1,
                min_sample_rate_hz,
                max_sample_rate_hz,
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

    fn protected_capsule_bytes() -> Vec<u8> {
        let capsule = DirectPodDhlIdentityCapsuleV1 {
            device_id: DEVICE_ID,
            pod_id: POD_ID,
            headstage_id: HEADSTAGE_ID,
            transport_epoch: EPOCH,
            descriptor_wire: identity_dhl_wire(1, 1, &protected_descriptor_payload()),
            inventory_wire: identity_dhl_wire(9, 2, &protected_inventory_payload()),
        };
        capsule.encode().unwrap()
    }

    fn bare_time_snapshot(sequence: u64, global_time_ns: u64) -> Vec<u8> {
        DirectPodTimeSnapshotV1 {
            device_id: DEVICE_ID,
            transport_epoch: EPOCH,
            status_sequence: sequence,
            global_time_ns,
            sample_counter: sequence,
            frame_counter: sequence,
            runtime_flags: TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY,
            hardware_state_hash: sha256(&sequence.to_le_bytes()),
        }
        .encode()
        .unwrap()
        .to_vec()
    }

    fn cabline_status(sequence: u64, global_time_ns: u64) -> Vec<u8> {
        cabline_status_with_identity(sequence, global_time_ns, POD_ID, HEADSTAGE_ID)
    }

    fn approved_cabline_binding_sha256() -> [u8; 32] {
        DirectPodCablineStatusV1::decode(&cabline_status(1, 1_000))
            .unwrap()
            .configuration_binding_hash()
    }

    fn cabline_status_with_identity(
        sequence: u64,
        global_time_ns: u64,
        pod_id: [u8; 16],
        headstage_id: [u8; 16],
    ) -> Vec<u8> {
        DirectPodCablineStatusV1 {
            device_id: DEVICE_ID,
            pod_id,
            headstage_id,
            transport_epoch: EPOCH,
            status_sequence: sequence,
            global_time_ns,
            headstage_boot_id: 1,
            next_dhl_sequence: sequence.max(1),
            source_id: 1,
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

    fn time_snapshot(sequence: u64, global_time_ns: u64) -> Vec<u8> {
        let mut bytes = bare_time_snapshot(sequence, global_time_ns);
        bytes.extend_from_slice(&cabline_status(sequence, global_time_ns));
        bytes
    }

    fn runtime_identity_capsule() -> Vec<u8> {
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
        descriptor[28..44].copy_from_slice(&HEADSTAGE_ID);
        descriptor[44..76].copy_from_slice(&[0x55; 32]);
        descriptor[76..92].copy_from_slice(&[0x33; 16]);
        let mut inventory = vec![0_u8; 108];
        inventory[0..2].copy_from_slice(&1_u16.to_le_bytes());
        inventory[2..4].copy_from_slice(&76_u16.to_le_bytes());
        inventory[4..6].copy_from_slice(&32_u16.to_le_bytes());
        inventory[6..8].copy_from_slice(&1_u16.to_le_bytes());
        inventory[8..12].copy_from_slice(&1_u32.to_le_bytes());
        DirectPodDhlIdentityCapsuleV1 {
            device_id: DEVICE_ID,
            pod_id: POD_ID,
            headstage_id: HEADSTAGE_ID,
            transport_epoch: EPOCH,
            descriptor_wire: identity_dhl_wire(1, 1, &descriptor),
            inventory_wire: identity_dhl_wire(9, 2, &inventory),
        }
        .encode()
        .unwrap()
    }

    fn identity_dhl_wire(packet_type: u8, sequence: u64, payload: &[u8]) -> Vec<u8> {
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

    fn replay_offer(
        offer_sequence: u64,
        first: u64,
        last_exclusive: u64,
        offer_global_time_ns: u64,
        hardware_state_hash: [u8; 32],
    ) -> Vec<u8> {
        DirectPodReplayOfferV1 {
            flags: REPLAY_OFFER_REQUIRED_FLAGS,
            device_id: DEVICE_ID,
            run_id: RUN_ID,
            pod_id: POD_ID,
            headstage_id: HEADSTAGE_ID,
            transport_epoch: EPOCH,
            offer_sequence,
            first_missing_record_sequence: first,
            last_missing_record_sequence_exclusive: last_exclusive,
            oldest_replayable_record_sequence: first,
            newest_replayable_record_sequence_exclusive: last_exclusive,
            source_next_live_record_sequence: last_exclusive,
            last_produced_record_sequence_exclusive: last_exclusive,
            prior_record_sequence: first.checked_sub(1),
            offer_global_time_ns,
            deadline_global_time_ns: 10_000,
            reason_code: 1,
            hardware_state_hash,
        }
        .encode()
        .unwrap()
        .to_vec()
    }

    fn command(request_id: u64, command: u16) -> Vec<u8> {
        encode_low_speed(
            0,
            request_id,
            EPOCH,
            &RunCommandV1 {
                command,
                scope: 1,
                run_id: RUN_ID,
                target_device_id: DEVICE_ID,
                deadline_global_time_ns: 10_000,
                frozen_config_hash: [0x55; 32],
            },
        )
        .unwrap()
    }

    fn ack(request_id: u64, state_code: u16, receipt_hash: [u8; 32]) -> Vec<u8> {
        encode_low_speed(
            0,
            request_id,
            EPOCH,
            &AckV1 {
                acknowledged_request_id: request_id,
                applied_epoch: EPOCH,
                ack_code: 1,
                state_code,
                receipt_hash,
            },
        )
        .unwrap()
    }

    fn nack(request_id: u64) -> Vec<u8> {
        encode_low_speed(
            0,
            request_id,
            EPOCH,
            &NackV1 {
                rejected_request_id: request_id,
                current_epoch: EPOCH,
                error_code: 1,
                retryable: 0,
                detail_code: 7,
                state_hash: [0x66; 32],
            },
        )
        .unwrap()
    }

    fn records(count: u64) -> Vec<Vec<u8>> {
        let mut source = DeterministicReplaySource::new(DeterministicReplayConfig {
            run_id: RUN_ID,
            pod_id: POD_ID,
            headstage_id: HEADSTAGE_ID,
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

    fn replay_records(first: u64, last_exclusive: u64) -> Vec<Vec<u8>> {
        records(last_exclusive)
            .into_iter()
            .skip(first as usize)
            .map(|record| {
                let decoded = decode_record(&record).unwrap();
                encode_record(
                    &forge_protocol_v1::CanonicalRecordEnvelopeV1 {
                        flags: decoded.envelope.flags | RECORD_FLAG_REPLAYED,
                        ..decoded.envelope
                    },
                    &decoded.payload,
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn protected_identity_binds_layout_geometry_format_and_exact_rate_before_append() {
        let valid = protected_record(32);
        let decoded = decode_record(&valid).unwrap();
        let wrong_layout = encode_record(
            &forge_protocol_v1::CanonicalRecordEnvelopeV1 {
                channel_layout_id: 0x1020_3041,
                ..decoded.envelope.clone()
            },
            &decoded.payload,
        )
        .unwrap();
        let mutations = [
            ("layout", wrong_layout),
            ("channel-count", protected_record(31)),
            ("rate-numerator", protected_record_with_rate(29_999, 1)),
            ("rate-denominator", protected_record_with_rate(30_000, 2)),
            ("sample-format", protected_record_with_noncanonical_format()),
        ];

        for (index, (name, record)) in mutations.into_iter().enumerate() {
            let test_name = format!("protected-record-contract-{index}-{name}");
            let (files, mut session) = new_protected_record_session(&test_name);
            start_protected_recording(&mut session);
            let error = session.push_chunk(&record, 1_000).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{name}");
            let snapshot = session.snapshot();
            assert!(snapshot.poisoned, "{name}");
            assert_eq!(snapshot.committed_record_count, 0, "{name}");
            assert_eq!(snapshot.durable_record_count, 0, "{name}");
            match inspect_recovery(&files.journal).unwrap() {
                JournalRecovery::Clean(scan) => assert_eq!(scan.complete_chunks, 0, "{name}"),
                recovery => panic!("{name} reached the journal before rejection: {recovery:?}"),
            }
        }

        let (files, mut session) = new_protected_record_session("protected-record-contract-ok");
        start_protected_recording(&mut session);
        session.push_chunk(&valid, 1_000).unwrap();
        assert_eq!(session.snapshot().committed_record_count, 1);
        session.durability_barrier().unwrap();
        assert_eq!(
            JournalReader::open_durable(&files.journal).unwrap().count(),
            1
        );
    }

    fn replay_request(
        session: &DirectPodIngestSession,
        request_id: u64,
        first: u64,
        last_exclusive: u64,
    ) -> Vec<u8> {
        let deadline = 10_000;
        let reason_code = 1;
        let context = session
            .expected_replay_request_context_hash(
                request_id,
                first,
                last_exclusive,
                deadline,
                reason_code,
            )
            .unwrap();
        encode_low_speed(
            0,
            request_id,
            EPOCH,
            &ReplayRequestV1 {
                run_id: RUN_ID,
                pod_id: POD_ID,
                first_record_sequence: first,
                last_record_sequence_exclusive: last_exclusive,
                deadline_global_time_ns: deadline,
                reason_code,
                request_context_hash: context,
            },
        )
        .unwrap()
    }

    fn transact(session: &mut DirectPodIngestSession, request_id: u64, command_code: u16) {
        let request = command(request_id, command_code);
        assert_eq!(
            session.admit_outbound(&request, 100).unwrap(),
            DirectPodSendDecision::Send
        );
        session
            .push_chunk(&ack(request_id, command_code, [0x77; 32]), 200)
            .unwrap();
        let reply = session.take_reply().unwrap();
        assert_eq!(reply.request_id, request_id);
        assert!(!reply.source_stop_boundary_verified);
    }

    fn start_recording(session: &mut DirectPodIngestSession) {
        session.push_chunk(&capabilities(), 50).unwrap();
        for (id, code) in [(1, 1), (2, 2), (3, 3)] {
            transact(session, id, code);
        }
    }

    #[test]
    fn replay_range_is_journaled_durable_then_acknowledged_without_changing_run_state() {
        let (files, mut session) = new_session("replay-complete");
        start_recording(&mut session);
        session.push_chunk(&records(1).pop().unwrap(), 300).unwrap();
        let request = replay_request(&session, 4, 1, 3);
        assert_eq!(
            session.admit_outbound(&request, 400).unwrap(),
            DirectPodSendDecision::Send
        );
        for record in replay_records(1, 3) {
            session.push_chunk(&record, 500).unwrap();
        }
        let before_ack = session.snapshot();
        assert_eq!(before_ack.committed_record_count, 3);
        assert_eq!(before_ack.durable_record_count, 3);
        assert_eq!(
            before_ack.replay_boundary.unwrap().state,
            DirectPodReplayState::Durable
        );
        assert_eq!(
            before_ack.acquisition_state,
            DirectPodAcquisitionState::Recording
        );
        let receipt_hash = session.expected_replay_receipt_hash().unwrap();
        session.push_chunk(&ack(4, 3, receipt_hash), 600).unwrap();
        let reply = session.take_reply().unwrap();
        assert!(reply.replay_boundary_verified);
        assert!(!reply.source_stop_boundary_verified);
        let after = session.snapshot();
        assert_eq!(after.verified_replay_count, 1);
        assert_eq!(
            after.replay_boundary.unwrap().state,
            DirectPodReplayState::Verified
        );
        assert_eq!(
            after.acquisition_state,
            DirectPodAcquisitionState::Recording
        );
        drop(session);
        let scan = crate::journal::scan_journal(&files.journal).unwrap();
        assert_eq!(scan.complete_chunks, 3);
        assert_eq!(scan.durable.durable_record_count, 3);
    }

    #[test]
    fn replay_early_ack_and_unflagged_record_fail_before_false_completion() {
        let (files, mut early) = new_session("replay-early-ack");
        start_recording(&mut early);
        let request = replay_request(&early, 4, 0, 1);
        early.admit_outbound(&request, 400).unwrap();
        assert!(early.push_chunk(&ack(4, 3, [0x44; 32]), 500).is_err());
        assert!(early.snapshot().poisoned);
        drop(early);
        assert_eq!(
            crate::journal::scan_journal(&files.journal)
                .unwrap()
                .complete_chunks,
            0
        );

        let (files, mut unflagged) = new_session("replay-unflagged");
        start_recording(&mut unflagged);
        let request = replay_request(&unflagged, 4, 0, 1);
        unflagged.admit_outbound(&request, 400).unwrap();
        assert!(unflagged
            .push_chunk(&records(1).pop().unwrap(), 500)
            .is_err());
        assert!(unflagged.snapshot().poisoned);
        drop(unflagged);
        assert_eq!(
            crate::journal::scan_journal(&files.journal)
                .unwrap()
                .complete_chunks,
            0
        );
    }

    #[test]
    fn replay_nack_before_data_keeps_recording_and_allows_a_fresh_request() {
        let (_files, mut session) = new_session("replay-nack");
        start_recording(&mut session);
        let first = replay_request(&session, 4, 0, 1);
        session.admit_outbound(&first, 400).unwrap();
        session.push_chunk(&nack(4), 500).unwrap();
        assert!(matches!(
            session.take_reply().unwrap().reply,
            DirectPodReply::Nack(_)
        ));
        assert_eq!(
            session.snapshot().replay_boundary.unwrap().state,
            DirectPodReplayState::Rejected
        );
        assert_eq!(
            session.snapshot().acquisition_state,
            DirectPodAcquisitionState::Recording
        );
        let second = replay_request(&session, 5, 0, 1);
        assert_eq!(
            session.admit_outbound(&second, 600).unwrap(),
            DirectPodSendDecision::Send
        );
    }

    #[test]
    fn quiesced_source_offer_rejects_live_data_before_replay_out() {
        let (files, mut session) = new_session("replay-offer-live-interleave");
        start_recording(&mut session);
        session.push_chunk(&time_snapshot(1, 1_000), 350).unwrap();
        session
            .push_chunk(
                &replay_offer(1, 0, 2, 1_000, sha256(&1_u64.to_le_bytes())),
                351,
            )
            .unwrap();
        assert!(session.snapshot().pending_replay_offer.is_some());
        assert!(session.push_chunk(&records(1).remove(0), 352).is_err());
        assert!(session.snapshot().poisoned);
        drop(session);
        assert_eq!(
            crate::journal::scan_journal(&files.journal)
                .unwrap()
                .complete_chunks,
            0,
            "live data after a quiesced source offer reached the journal"
        );
    }

    #[test]
    fn full_fragmented_run_requires_stop_boundary_then_durably_seals() {
        let (files, mut session) = new_session("full");
        for byte in capabilities() {
            session.push_chunk(&[byte], 50).unwrap();
        }
        for (id, code) in [(1, 1), (2, 2), (3, 3)] {
            transact(&mut session, id, code);
        }
        for record in records(2) {
            for piece in record.chunks(7) {
                session.push_chunk(piece, 300).unwrap();
            }
        }
        let stop = command(4, 4);
        session.admit_outbound(&stop, 400).unwrap();
        let boundary_hash = session.expected_stop_receipt_hash(4).unwrap();
        let stop_ack = ack(4, 4, boundary_hash);
        session.push_chunk(&stop_ack, 500).unwrap();
        let reply = session.take_reply().unwrap();
        assert!(reply.source_stop_boundary_verified);
        let scan = session.finish_and_seal().unwrap();
        assert_eq!(scan.complete_chunks, 2);
        assert_eq!(scan.durable.durable_record_count, 2);
        assert_eq!(scan.last_journal_sequence, Some(1));
        assert!(scan.seal.is_some());
        assert_eq!(
            JournalReader::open_sealed(&files.journal).unwrap().count(),
            2
        );
    }

    #[test]
    fn record_after_verified_stop_poisons_and_cannot_be_sealed() {
        let (_files, mut session) = new_session("late-record");
        session.push_chunk(&capabilities(), 50).unwrap();
        transact(&mut session, 1, 1);
        transact(&mut session, 2, 2);
        transact(&mut session, 3, 3);
        let first = records(2);
        session.push_chunk(&first[0], 300).unwrap();
        let stop = command(4, 4);
        session.admit_outbound(&stop, 400).unwrap();
        let stop_ack = ack(4, 4, session.expected_stop_receipt_hash(4).unwrap());
        session.push_chunk(&stop_ack, 500).unwrap();
        assert!(session.push_chunk(&first[1], 600).is_err());
        assert!(session.snapshot().poisoned);
        assert!(session.finish_and_seal().is_err());
    }

    #[test]
    fn wrong_record_identity_is_rejected_before_journal_append() {
        let (files, mut session) = new_session("identity");
        session.push_chunk(&capabilities(), 50).unwrap();
        for (id, code) in [(1, 1), (2, 2), (3, 3)] {
            transact(&mut session, id, code);
        }
        let mut source = DeterministicReplaySource::new(DeterministicReplayConfig {
            run_id: RUN_ID,
            pod_id: [0x66; 16],
            headstage_id: HEADSTAGE_ID,
            channel_layout_id: 1,
            channel_count: 1,
            samples_per_channel: 1,
            sample_rate_hz: 30_000,
            total_records: 1,
            seed: 1,
        })
        .unwrap();
        let record = source.next_encoded_record().unwrap().unwrap();
        assert!(session.push_chunk(&record, 100).is_err());
        assert_eq!(session.snapshot().committed_record_count, 0);
        drop(session);
        assert_eq!(
            crate::journal::scan_journal(&files.journal)
                .unwrap()
                .complete_chunks,
            0
        );
    }

    #[test]
    fn data_before_capabilities_and_stop_without_records_fail_closed() {
        let (_files, mut session) = new_session("ordering");
        let record = records(1).pop().unwrap();
        assert!(session.push_chunk(&record, 50).is_err());
        assert!(session.snapshot().poisoned);

        let (_files, mut session) = new_session("before-start");
        session.push_chunk(&capabilities(), 50).unwrap();
        assert!(session.push_chunk(&records(1).pop().unwrap(), 60).is_err());
        assert!(session.snapshot().poisoned);

        let (_files, mut session) = new_session("empty-stop");
        session.push_chunk(&capabilities(), 50).unwrap();
        transact(&mut session, 1, 1);
        transact(&mut session, 2, 2);
        transact(&mut session, 3, 3);
        session.admit_outbound(&command(4, 4), 400).unwrap();
        assert!(session.expected_stop_receipt_hash(4).is_err());
    }

    #[test]
    fn durability_is_reported_separately_from_append_and_stop() {
        let (_files, mut session) = new_session("durability");
        session.push_chunk(&capabilities(), 50).unwrap();
        for (id, code) in [(1, 1), (2, 2), (3, 3)] {
            transact(&mut session, id, code);
        }
        session.push_chunk(&records(1).pop().unwrap(), 100).unwrap();
        let before = session.snapshot();
        assert_eq!(before.committed_record_count, 1);
        assert_eq!(before.durable_record_count, 0);
        let checkpoint = session.durability_barrier().unwrap();
        assert_eq!(checkpoint.durable_record_count, 1);
        assert_eq!(session.snapshot().durable_record_count, 1);
        assert!(!session.snapshot().source_stop_boundary_verified);
    }

    #[test]
    fn exact_command_retry_is_idempotent_but_new_identity_cannot_reapply_state() {
        let (_files, mut session) = new_session("idempotent");
        session.push_chunk(&capabilities(), 50).unwrap();
        let prepare = command(1, 1);
        assert_eq!(
            session.admit_outbound(&prepare, 100).unwrap(),
            DirectPodSendDecision::Send
        );
        session.push_chunk(&ack(1, 1, [0x77; 32]), 200).unwrap();
        session.take_reply().unwrap();
        assert_eq!(
            session.admit_outbound(&prepare, 250).unwrap(),
            DirectPodSendDecision::AlreadyCompleted
        );
        assert!(!session.snapshot().poisoned);

        let (_files, mut session) = new_session("reapply");
        session.push_chunk(&capabilities(), 50).unwrap();
        transact(&mut session, 1, 1);
        assert!(session.admit_outbound(&command(2, 1), 250).is_err());
        assert!(session.snapshot().poisoned);
    }

    #[test]
    fn nack_preserves_state_but_contradictory_ack_state_poisons() {
        let (_files, mut session) = new_session("nack");
        session.push_chunk(&capabilities(), 50).unwrap();
        session.admit_outbound(&command(1, 1), 100).unwrap();
        session.push_chunk(&nack(1), 200).unwrap();
        assert!(matches!(
            session.take_reply().unwrap().reply,
            DirectPodReply::Nack(_)
        ));
        assert_eq!(
            session.snapshot().acquisition_state,
            DirectPodAcquisitionState::Ready
        );
        session.admit_outbound(&command(2, 1), 250).unwrap();
        session.push_chunk(&ack(2, 1, [0x77; 32]), 300).unwrap();
        session.take_reply().unwrap();
        assert_eq!(
            session.snapshot().acquisition_state,
            DirectPodAcquisitionState::Prepared
        );

        let (_files, mut session) = new_session("wrong-state");
        session.push_chunk(&capabilities(), 50).unwrap();
        session.admit_outbound(&command(1, 1), 100).unwrap();
        assert!(session.push_chunk(&ack(1, 2, [0x77; 32]), 200).is_err());
        assert!(session.snapshot().poisoned);
    }

    fn assert_capsule_capability_mismatch_fails_closed(
        name: &str,
        max_channels_per_pod: u16,
        min_sample_rate_hz: u32,
        max_sample_rate_hz: u32,
    ) {
        let (files, mut connection, controller) = new_protected_pre_run(name);
        connection.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities_with_limits(
            max_channels_per_pod,
            min_sample_rate_hz,
            max_sample_rate_hz,
        )));
        connection.poll_once(100).unwrap();
        controller.push(DirectPodTransportRead::Complete(protected_capsule_bytes()));
        let error = connection.poll_once(101).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let snapshot = connection.snapshot();
        assert!(snapshot.poisoned);
        assert!(snapshot.control.poisoned);
        let transport = controller.snapshot();
        assert_eq!(transport.0, 0, "poisoned owner must cancel all reads");
        assert!(transport.2 > 0, "poisoned owner must cancel the transport");
        let plan = run_plan(&files, "capability-mismatch");
        assert!(connection
            .prepare_and_promote(&operator_prepare(1), &plan, 102)
            .is_err());
        assert_eq!(controller.snapshot().1, 0, "poisoned owner reached OUT");
        assert!(!plan.run_root().exists());
    }

    #[test]
    fn pre_run_capsule_rejects_insufficient_max_channels_before_ready() {
        assert_capsule_capability_mismatch_fails_closed("capsule-max-channels", 16, 30_000, 30_000);
    }

    #[test]
    fn pre_run_capsule_rejects_rate_below_capability_min_before_ready() {
        assert_capsule_capability_mismatch_fails_closed("capsule-rate-low", 256, 30_001, 60_000);
    }

    #[test]
    fn pre_run_capsule_rejects_rate_above_capability_max_before_ready() {
        assert_capsule_capability_mismatch_fails_closed("capsule-rate-high", 256, 1, 29_999);
    }

    #[test]
    fn admitted_rational_rate_uses_exact_integer_bounds() {
        let (_files, mut connection, controller) = new_protected_pre_run("capsule-rate-rational");
        connection.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities_with_limits(
            256, 30_000, 30_000,
        )));
        connection.poll_once(100).unwrap();

        let mut admitted = protected_admitted_identity().admitted_identity;
        admitted.descriptor.sample_rate_numerator_hz = 60_000;
        admitted.descriptor.sample_rate_denominator = 2;
        admitted.approved_sample_rate_numerator_hz = 60_000;
        admitted.approved_sample_rate_denominator = 2;
        connection
            .inner
            .as_mut()
            .unwrap()
            .state
            .control
            .validate_admitted_identity_against_capabilities(&admitted)
            .unwrap();
        assert!(!connection.snapshot().poisoned);
        assert!(!connection.snapshot().control.poisoned);
    }

    #[test]
    fn pre_run_promotion_preserves_fragmented_parser_queue_and_exactly_once_ingest() {
        let (files, mut connection, controller) = new_pre_run("pre-run-promotion");
        connection.prime_reads().unwrap();
        assert_eq!(controller.snapshot().0, 2);

        let capability = capabilities();
        let capability_split = capability.len() / 2;
        controller.push(DirectPodTransportRead::Complete(
            capability[..capability_split].to_vec(),
        ));
        connection.poll_once(100).unwrap();
        assert!(!connection.snapshot().control.capability_admitted);
        assert_eq!(connection.snapshot().stream.pending_bytes, capability_split);
        assert_eq!(controller.snapshot().0, 2);

        controller.push(DirectPodTransportRead::Complete(
            capability[capability_split..].to_vec(),
        ));
        connection.poll_once(101).unwrap();
        controller.push(DirectPodTransportRead::Complete(time_snapshot(1, 1_000)));
        connection.poll_once(102).unwrap();

        // Begin a second status message before promotion. Its parser state and
        // the two already-queued reads must move into the Run unchanged.
        let second_time = time_snapshot(2, 2_000);
        controller.push(DirectPodTransportRead::Complete(second_time[..40].to_vec()));
        connection.poll_once(103).unwrap();
        let before = connection.snapshot();
        assert_eq!(before.stream.low_speed_messages, 1);
        assert_eq!(before.stream.time_snapshots, 1);
        assert_eq!(before.stream.pending_bytes, 40);
        assert_eq!(before.hardware_time.status_count, 1);
        assert_eq!(before.completed_reads, 4);
        assert_eq!(before.queued_reads, 2);

        let plan = run_plan(&files, "promotion");
        let promotion = connection
            .prepare_and_promote(&operator_prepare(1), &plan, 104)
            .unwrap();
        assert!(connection.snapshot().promoted);
        assert_eq!(promotion.prepare_decision(), DirectPodSendDecision::Send);
        assert_eq!(
            promotion.prepare_receipt().phase,
            HardwareRunPhase::PrepareRequested
        );
        assert_eq!(promotion.journal_path(), plan.journal_path());
        assert_eq!(controller.snapshot().0, 2, "promotion changed IN depth");
        assert_eq!(controller.snapshot().1, 1, "Prepare must be the first OUT");

        let mut runtime = promotion.into_runtime();
        let promoted = runtime.snapshot();
        assert_eq!(promoted.runtime.completed_reads, 4);
        assert_eq!(promoted.runtime.queued_reads, 2);
        assert_eq!(promoted.runtime.ingest.stream.pending_bytes, 40);
        assert_eq!(promoted.runtime.ingest.stream.low_speed_messages, 1);
        assert_eq!(promoted.runtime.ingest.stream.time_snapshots, 1);

        controller.push(DirectPodTransportRead::Complete(second_time[40..].to_vec()));
        runtime.poll_once_from_snapshot(105).unwrap();
        let after_time = runtime.snapshot();
        assert_eq!(after_time.runtime.ingest.stream.pending_bytes, 0);
        assert_eq!(after_time.runtime.ingest.stream.time_snapshots, 2);
        assert_eq!(after_time.runtime.ingest.hardware_time.status_count, 2);

        controller.push(DirectPodTransportRead::Complete(ack(1, 1, [0x41; 32])));
        runtime.poll_once_from_snapshot(106).unwrap();
        assert_eq!(runtime.take_reply().unwrap().request_id, 1);
        assert_eq!(
            runtime.snapshot().lifecycle.phase,
            HardwareRunPhase::Prepared
        );

        runtime
            .send_run_command_from_snapshot(&command(2, 2), 107)
            .unwrap();
        controller.push(DirectPodTransportRead::Complete(ack(2, 2, [0x42; 32])));
        runtime.poll_once_from_snapshot(108).unwrap();
        runtime.take_reply().unwrap();
        runtime
            .send_run_command_from_snapshot(&command(3, 3), 109)
            .unwrap();

        // The Start ACK and first record share one USB completion. The ordered
        // parser must apply both exactly once and journal the record once.
        let mut ack_and_record = ack(3, 3, [0x43; 32]);
        ack_and_record.extend_from_slice(&records(1).remove(0));
        controller.push(DirectPodTransportRead::Complete(ack_and_record));
        runtime.poll_once_from_snapshot(110).unwrap();
        assert_eq!(runtime.take_reply().unwrap().request_id, 3);
        let final_snapshot = runtime.snapshot();
        assert_eq!(final_snapshot.lifecycle.phase, HardwareRunPhase::Recording);
        assert_eq!(final_snapshot.runtime.ingest.committed_record_count, 1);
        assert_eq!(final_snapshot.runtime.ingest.stream.canonical_records, 1);
        assert_eq!(final_snapshot.runtime.ingest.stream.low_speed_messages, 4);
        assert_eq!(final_snapshot.runtime.ingest.stream.time_snapshots, 2);
        assert_eq!(controller.snapshot().0, 2);
        assert_eq!(
            JournalReader::open_durable(plan.journal_path())
                .unwrap()
                .count(),
            0
        );
        runtime.durability_barrier().unwrap();
        assert_eq!(
            JournalReader::open_durable(plan.journal_path())
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn pre_run_promotion_rejects_identity_state_and_existing_root_before_out() {
        let (files, mut connection, controller) = new_pre_run("pre-run-rejections");
        connection.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities()));
        connection.poll_once(100).unwrap();
        controller.push(DirectPodTransportRead::Complete(time_snapshot(1, 1_000)));
        connection.poll_once(101).unwrap();

        let wrong_run_plan = run_plan(&files, "wrong-run");
        let mut request = operator_prepare(1);
        request.run_id = [0x99; 16];
        assert!(connection
            .prepare_and_promote(&request, &wrong_run_plan, 102)
            .is_err());
        assert!(!wrong_run_plan.run_root().exists());
        assert_eq!(controller.snapshot().1, 0);

        let wrong_state_plan = run_plan(&files, "wrong-state");
        let mut request = operator_prepare(1);
        request.expected_hardware_state_hash = [0x99; 32];
        assert!(connection
            .prepare_and_promote(&request, &wrong_state_plan, 103)
            .is_err());
        assert!(!wrong_state_plan.run_root().exists());
        assert_eq!(controller.snapshot().1, 0);

        let existing_plan = run_plan(&files, "existing");
        std::fs::create_dir(existing_plan.run_root()).unwrap();
        assert_eq!(
            connection
                .prepare_and_promote(&operator_prepare(1), &existing_plan, 104)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(controller.snapshot().1, 0);
        assert!(!connection.snapshot().promoted);
        assert!(!connection.snapshot().poisoned);

        // A later no-overwrite plan can still use the same continuously primed
        // connection; only then may the first hardware OUT occur.
        let valid_plan = run_plan(&files, "promotion");
        let promotion = connection
            .prepare_and_promote(&operator_prepare(1), &valid_plan, 105)
            .unwrap();
        assert_eq!(promotion.prepare_decision(), DirectPodSendDecision::Send);
        assert_eq!(controller.snapshot().1, 1);
        assert_eq!(controller.snapshot().0, 2);
    }

    #[test]
    fn pre_run_availability_and_promotion_require_bound_cabline_source_status() {
        let (files, mut missing, missing_controller) = new_pre_run("pre-run-missing-cabline");
        missing.prime_reads().unwrap();
        missing_controller.push(DirectPodTransportRead::Complete(capabilities()));
        missing.poll_once(100).unwrap();
        missing_controller.push(DirectPodTransportRead::Complete(bare_time_snapshot(
            1, 1_000,
        )));
        missing.poll_once(101).unwrap();
        let missing_plan = run_plan(&files, "promotion");
        assert!(missing
            .prepare_and_promote(&operator_prepare(1), &missing_plan, 102)
            .is_err());
        assert!(!missing_plan.run_root().exists());
        assert_eq!(
            missing_controller.snapshot().1,
            0,
            "missing source status reached OUT"
        );
        let mut missing_backend = PromotableDirectPodBackend::new(
            missing,
            TestRunPlanProvider {
                plan: missing_plan.clone(),
            },
        )
        .unwrap();
        assert!(missing_backend.status(10, 103).is_err());
        assert_eq!(
            missing_controller.snapshot().1,
            0,
            "missing source status advertised hardware availability"
        );

        let (files, mut wrong, wrong_controller) = new_pre_run("pre-run-wrong-cabline");
        wrong.prime_reads().unwrap();
        wrong_controller.push(DirectPodTransportRead::Complete(capabilities()));
        wrong.poll_once(100).unwrap();
        wrong_controller.push(DirectPodTransportRead::Complete(bare_time_snapshot(
            1, 1_000,
        )));
        wrong.poll_once(101).unwrap();
        wrong_controller.push(DirectPodTransportRead::Complete(
            cabline_status_with_identity(1, 1_000, [0x99; 16], HEADSTAGE_ID),
        ));
        wrong.poll_once(102).unwrap();
        let wrong_plan = run_plan(&files, "promotion");
        assert!(wrong
            .prepare_and_promote(&operator_prepare(1), &wrong_plan, 103)
            .is_err());
        assert!(wrong.snapshot().poisoned);
        assert!(!wrong_plan.run_root().exists());
        assert_eq!(
            wrong_controller.snapshot().1,
            0,
            "wrong source identity reached OUT"
        );

        let (files, mut unapproved, unapproved_controller) =
            new_pre_run("pre-run-unapproved-cabline");
        unapproved.prime_reads().unwrap();
        unapproved_controller.push(DirectPodTransportRead::Complete(capabilities()));
        unapproved.poll_once(100).unwrap();
        unapproved_controller.push(DirectPodTransportRead::Complete(time_snapshot(1, 1_000)));
        unapproved.poll_once(101).unwrap();
        let unapproved_plan = DirectPodRunPlan::new(
            PathBuf::from(format!("{}.promotion", files.journal.display())),
            RUN_ID,
            POD_ID,
            HEADSTAGE_ID,
            [0x55; 32],
            [0x77; 32],
        )
        .unwrap();
        let mut unapproved_backend = PromotableDirectPodBackend::new(
            unapproved,
            TestRunPlanProvider {
                plan: unapproved_plan.clone(),
            },
        )
        .unwrap();
        assert!(unapproved_backend.status(20, 102).is_err());
        assert!(unapproved_backend.submit(operator_prepare(1), 102).is_err());
        assert!(!unapproved_plan.run_root().exists());
        assert_eq!(
            unapproved_controller.snapshot().1,
            0,
            "unapproved source configuration reached OUT"
        );
    }

    #[test]
    fn owner_watchdog_rejects_stale_cabline_without_a_pending_control_request() {
        let (files, mut connection, controller) = new_pre_run("pre-run-source-watchdog");
        connection.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities()));
        connection.poll_once(100).unwrap();
        controller.push(DirectPodTransportRead::Complete(time_snapshot(1, 1_000)));
        connection.poll_once(101).unwrap();
        let plan = run_plan(&files, "promotion");
        let mut backend =
            PromotableDirectPodBackend::new(connection, TestRunPlanProvider { plan: plan.clone() })
                .unwrap();
        assert!(backend.status(1, 102).is_ok());
        assert_eq!(controller.snapshot().1, 0);

        let error = backend
            .poll_owner_once(101 + DIRECT_POD_CABLINE_MAX_HOST_AGE_NS + 1)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!plan.run_root().exists());
        assert_eq!(controller.snapshot().1, 0, "stale source reached OUT");
    }

    #[test]
    fn promotion_rechecks_the_last_freshness_budget_after_artifact_creation() {
        let (files, mut connection, controller) = new_pre_run("pre-run-out-freshness");
        connection.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities()));
        connection.poll_once(100).unwrap();
        controller.push(DirectPodTransportRead::Complete(time_snapshot(1, 1_000)));
        connection.poll_once(101).unwrap();
        let plan = run_plan(&files, "promotion");

        let error = connection
            .prepare_and_promote(
                &operator_prepare(1),
                &plan,
                101 + DIRECT_POD_CABLINE_MAX_HOST_AGE_NS,
            )
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert!(
            plan.run_root().exists(),
            "forensic Run root was not retained"
        );
        assert_eq!(controller.snapshot().1, 0, "expired evidence reached OUT");
    }

    #[test]
    fn active_run_command_rechecks_freshness_after_durable_intent_before_out() {
        let (files, session) = new_session("active-run-out-freshness");
        let hardware_ledger = PathBuf::from(format!("{}.hardware-ledger", files.journal.display()));
        let lifecycle = HardwareRunCoordinator::open(&hardware_ledger).unwrap();
        let (transport, controller) = FakeTransport::new();
        let runtime = DirectPodRuntime::new(
            session,
            transport,
            DirectPodRuntimeConfig {
                read_buffer_bytes: 1_024,
                read_depth: 2,
            },
        )
        .unwrap();
        let mut durable = DurableDirectPodRuntime::new(runtime, lifecycle).unwrap();
        durable.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities()));
        durable.poll_once_from_snapshot(100).unwrap();
        controller.push(DirectPodTransportRead::Complete(time_snapshot(1, 1_000)));
        durable.poll_once_from_snapshot(200).unwrap();

        let (hardware_now, guard) = durable
            .capture_source_freshness(201, Instant::now())
            .unwrap();
        let guard = guard.expire_on_check(2);
        let error = durable
            .send_run_command_guarded(&command(1, 1), hardware_now, &guard)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(controller.snapshot().1, 0, "expired intent reached OUT");
        assert_eq!(durable.snapshot().lifecycle.phase, HardwareRunPhase::Failed);
        assert!(
            durable.snapshot().lifecycle.ledger_events >= 2,
            "durable intent and fail-closed evidence were not retained"
        );
        let _ = std::fs::remove_dir_all(hardware_ledger);
    }

    #[test]
    fn near_expiry_cabline_cannot_send_automatic_replay_after_poll_work() {
        let (files, session) = new_session("near-expiry-cabline-auto-replay");
        let hardware_ledger = PathBuf::from(format!("{}.hardware-ledger", files.journal.display()));
        let lifecycle = HardwareRunCoordinator::open(&hardware_ledger).unwrap();
        let (transport, controller) = FakeTransport::new();
        let runtime = DirectPodRuntime::new(
            session,
            transport,
            DirectPodRuntimeConfig {
                read_buffer_bytes: 1_024,
                read_depth: 2,
            },
        )
        .unwrap();
        let mut durable = DurableDirectPodRuntime::new(runtime, lifecycle).unwrap();
        durable.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities()));
        durable.poll_once_from_snapshot(100).unwrap();
        controller.push(DirectPodTransportRead::Complete(time_snapshot(1, 1_000)));
        durable.poll_once_from_snapshot(200).unwrap();
        for (request_id, command_code, state_code) in [(1_u64, 1_u16, 1_u16), (2, 2, 2), (3, 3, 3)]
        {
            durable
                .send_run_command_from_snapshot(&command(request_id, command_code), 201)
                .unwrap();
            controller.push(DirectPodTransportRead::Complete(ack(
                request_id, state_code, [0x44; 32],
            )));
            durable.poll_once_from_snapshot(202).unwrap();
            durable.take_reply().unwrap();
        }
        controller.push(DirectPodTransportRead::Complete(records(1).remove(0)));
        durable.poll_once_from_snapshot(203).unwrap();
        assert_eq!(
            durable.snapshot().lifecycle.phase,
            HardwareRunPhase::Recording
        );
        assert_eq!(controller.snapshot().1, 3);

        let mut offered = bare_time_snapshot(2, 1_001);
        offered.extend_from_slice(&replay_offer(1, 1, 3, 1_001, sha256(&2_u64.to_le_bytes())));
        controller.push(DirectPodTransportRead::Complete(offered));
        let host_near_expiry = 200 + DIRECT_POD_CABLINE_MAX_HOST_AGE_NS - 20_000_000;
        let poll_started = Instant::now()
            .checked_sub(std::time::Duration::from_millis(25))
            .unwrap();
        let error = durable
            .poll_once_with_clocks_started(1_001, host_near_expiry, poll_started)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert_eq!(
            controller.snapshot().1,
            3,
            "pre-capture work restored an expired CABLINE budget before Replay OUT"
        );
        assert_eq!(durable.snapshot().lifecycle.phase, HardwareRunPhase::Failed);
        assert_eq!(durable.snapshot().lifecycle.replay_offer_count, 1);
        let _ = std::fs::remove_dir_all(hardware_ledger);
    }

    #[test]
    fn cabline_source_time_must_track_explicit_pod_hardware_time() {
        let source = DirectPodCablineStatusV1::decode(&cabline_status(1, 1_000)).unwrap();
        assert!(validate_cabline_time_coherence(source, 1_000).is_ok());
        assert!(validate_cabline_time_coherence(
            source,
            1_000 + DIRECT_POD_CABLINE_MAX_HOST_AGE_NS
        )
        .is_ok());
        assert_eq!(
            validate_cabline_time_coherence(source, 999)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            validate_cabline_time_coherence(source, 1_001 + DIRECT_POD_CABLINE_MAX_HOST_AGE_NS)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn promotable_service_backend_changes_state_without_changing_transport_owner() {
        let (files, mut connection, controller) = new_pre_run("pre-run-service-promotion");
        connection.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities()));
        connection.poll_once(100).unwrap();
        controller.push(DirectPodTransportRead::Complete(time_snapshot(1, 1_000)));
        connection.poll_once(101).unwrap();
        let plan = run_plan(&files, "promotion");
        let mut backend =
            PromotableDirectPodBackend::new(connection, TestRunPlanProvider { plan: plan.clone() })
                .unwrap();

        let ready = backend.status(10, 102).unwrap();
        assert_eq!(ready.service_state, HardwareServiceState::Ready);
        assert_eq!(ready.active_run_id, [0; 16]);
        assert_eq!(ready.pending_request_id, 0);
        assert_eq!(controller.snapshot().0, 2);

        let requested = backend.submit(operator_prepare(1), 103).unwrap();
        assert!(backend.is_run_bound());
        assert_eq!(
            requested.service_state,
            HardwareServiceState::PrepareRequested
        );
        assert_eq!(requested.active_run_id, RUN_ID);
        assert_eq!(requested.pending_request_id, 1);
        assert_eq!(controller.snapshot().0, 2);
        assert_eq!(controller.snapshot().1, 1);

        controller.push(DirectPodTransportRead::Complete(ack(1, 1, [0x44; 32])));
        backend.poll_owner_once(104).unwrap();
        let prepared = backend.status(11, 105).unwrap();
        assert_eq!(prepared.service_state, HardwareServiceState::Prepared);
        assert_eq!(prepared.pending_request_id, 0);
        assert_eq!(prepared.active_run_id, RUN_ID);
        assert_ne!(ready.evidence_hash, prepared.evidence_hash);
        assert_eq!(controller.snapshot().0, 2);
    }

    #[test]
    fn pre_run_connection_rejects_data_replies_and_changed_capability() {
        let (_files, mut connection, controller) = new_pre_run("pre-run-data");
        connection.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(records(1).remove(0)));
        assert!(connection.poll_once(100).is_err());
        assert!(connection.snapshot().poisoned);
        assert_eq!(controller.snapshot().0, 0);
        assert_eq!(controller.snapshot().1, 0);

        let (_files, mut connection, controller) = new_pre_run("pre-run-reply");
        connection.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(ack(1, 1, [1; 32])));
        assert!(connection.poll_once(100).is_err());
        assert!(connection.snapshot().poisoned);
        assert_eq!(controller.snapshot().1, 0);

        let (_files, mut connection, controller) = new_pre_run("pre-run-cap-change");
        connection.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities()));
        connection.poll_once(100).unwrap();
        let changed = encode_low_speed(
            0,
            901,
            EPOCH,
            &DeviceCapabilitiesV1 {
                device_id: DEVICE_ID,
                transport: 1,
                max_pods: 1,
                max_channels_per_pod: 128,
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
        .unwrap();
        controller.push(DirectPodTransportRead::Complete(changed));
        assert!(connection.poll_once(101).is_err());
        assert!(connection.snapshot().poisoned);
        assert_eq!(controller.snapshot().1, 0);
    }

    #[test]
    fn single_owner_runtime_preserves_transport_journal_and_stop_order() {
        let (files, session) = new_session("runtime-ordered");
        let (transport, controller) = FakeTransport::new();
        let mut runtime = DirectPodRuntime::new(
            session,
            transport,
            DirectPodRuntimeConfig {
                read_buffer_bytes: 1_024,
                read_depth: 2,
            },
        )
        .unwrap();
        runtime.prime_reads().unwrap();
        assert_eq!(controller.snapshot().0, 2);

        controller.push(DirectPodTransportRead::Complete(capabilities()));
        assert!(matches!(
            runtime.poll_once(100).unwrap(),
            DirectPodRuntimePoll::Ingested { .. }
        ));

        for (request_id, command_code, state_code) in [(1_u64, 1_u16, 1_u16), (2, 2, 2), (3, 3, 3)]
        {
            assert_eq!(
                runtime
                    .send_control(&command(request_id, command_code), 100)
                    .unwrap(),
                DirectPodSendDecision::Send
            );
            controller.push(DirectPodTransportRead::Complete(ack(
                request_id, state_code, [0x44; 32],
            )));
            runtime.poll_once(101).unwrap();
            assert_eq!(runtime.take_reply().unwrap().request_id, request_id);
        }

        for record in records(2) {
            controller.push(DirectPodTransportRead::Complete(record));
            runtime.poll_once(102).unwrap();
        }
        let stop_hash = runtime.expected_stop_receipt_hash(4).unwrap();
        assert_eq!(
            runtime.send_control(&command(4, 4), 103).unwrap(),
            DirectPodSendDecision::Send
        );
        controller.push(DirectPodTransportRead::Complete(ack(4, 4, stop_hash)));
        runtime.poll_once(104).unwrap();
        assert!(runtime.take_reply().unwrap().source_stop_boundary_verified);
        assert!(!runtime.snapshot().stop_frontier_observed);

        controller.push(DirectPodTransportRead::Pending);
        assert_eq!(
            runtime.poll_once(105).unwrap(),
            DirectPodRuntimePoll::StopFrontier
        );
        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.completed_reads, 7);
        assert!(snapshot.ingest.source_stop_boundary_verified);
        assert_eq!(snapshot.queued_reads, 1);

        let scan = runtime.finish_and_seal().unwrap();
        assert!(scan.seal.is_some());
        assert_eq!(scan.complete_chunks, 2);
        assert_eq!(
            JournalReader::open_sealed(&files.journal).unwrap().count(),
            2
        );
        let transport = controller.snapshot();
        assert_eq!(transport.0, 0);
        assert_eq!(transport.1, 4);
        assert_eq!(transport.2, 1);
        assert!(!transport.3);
    }

    #[test]
    fn runtime_rejects_identity_capsules_after_run_construction() {
        let (_files, session) = new_session("runtime-identity-capsule");
        let (transport, controller) = FakeTransport::new();
        let mut runtime = DirectPodRuntime::new(
            session,
            transport,
            DirectPodRuntimeConfig {
                read_buffer_bytes: 1_024,
                read_depth: 2,
            },
        )
        .unwrap();
        runtime.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities()));
        runtime.poll_once(100).unwrap();

        controller.push(DirectPodTransportRead::Complete(runtime_identity_capsule()));
        assert_eq!(
            runtime.poll_once(101).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(runtime.snapshot().poisoned);
        let transport = controller.snapshot();
        assert_eq!(transport.0, 0);
        assert!(transport.2 >= 1);
    }

    #[test]
    fn durable_runtime_never_reports_recording_before_first_journal_append() {
        let (files, session) = new_session("runtime-durable-lifecycle");
        let hardware_ledger = PathBuf::from(format!("{}.hardware-ledger", files.journal.display()));
        let lifecycle = HardwareRunCoordinator::open(&hardware_ledger).unwrap();
        let (transport, controller) = FakeTransport::new();
        let runtime = DirectPodRuntime::new(
            session,
            transport,
            DirectPodRuntimeConfig {
                read_buffer_bytes: 1_024,
                read_depth: 2,
            },
        )
        .unwrap();
        let mut durable = DurableDirectPodRuntime::new(runtime, lifecycle).unwrap();
        durable.prime_reads().unwrap();

        controller.push(DirectPodTransportRead::Complete(capabilities()));
        durable.poll_once_from_snapshot(100).unwrap();
        controller.push(DirectPodTransportRead::Complete(time_snapshot(1, 1_000)));
        durable.poll_once_from_snapshot(200).unwrap();
        assert_eq!(
            durable
                .snapshot()
                .runtime
                .ingest
                .hardware_time
                .latest
                .unwrap()
                .global_time_ns,
            1_000
        );
        for (request_id, command_code, state_code, expected_phase) in [
            (1_u64, 1_u16, 1_u16, HardwareRunPhase::Prepared),
            (2, 2, 2, HardwareRunPhase::Armed),
        ] {
            assert_eq!(
                durable
                    .send_run_command_from_snapshot(&command(request_id, command_code), 201)
                    .unwrap()
                    .0,
                DirectPodSendDecision::Send
            );
            controller.push(DirectPodTransportRead::Complete(ack(
                request_id, state_code, [0x44; 32],
            )));
            durable.poll_once_from_snapshot(202).unwrap();
            durable.take_reply().unwrap();
            assert_eq!(durable.snapshot().lifecycle.phase, expected_phase);
        }

        durable
            .send_run_command_from_snapshot(&command(3, 3), 203)
            .unwrap();
        controller.push(DirectPodTransportRead::Complete(ack(3, 3, [0x45; 32])));
        durable.poll_once_from_snapshot(204).unwrap();
        durable.take_reply().unwrap();
        assert_eq!(
            durable.snapshot().lifecycle.phase,
            HardwareRunPhase::StartAcknowledged
        );
        assert_eq!(durable.snapshot().runtime.ingest.committed_record_count, 0);

        controller.push(DirectPodTransportRead::Complete(records(1).remove(0)));
        durable.poll_once_from_snapshot(205).unwrap();
        assert_eq!(
            durable.snapshot().lifecycle.phase,
            HardwareRunPhase::Recording
        );
        assert_eq!(durable.snapshot().lifecycle.first_journal_sequence, Some(0));

        let stop_hash = durable.expected_stop_receipt_hash(4).unwrap();
        durable
            .send_run_command_from_snapshot(&command(4, 4), 206)
            .unwrap();
        controller.push(DirectPodTransportRead::Complete(ack(4, 4, stop_hash)));
        durable.poll_once_from_snapshot(207).unwrap();
        assert!(durable.take_reply().unwrap().source_stop_boundary_verified);
        assert_eq!(
            durable.snapshot().lifecycle.phase,
            HardwareRunPhase::Stopped
        );
        controller.push(DirectPodTransportRead::Pending);
        assert_eq!(
            durable.poll_once_from_snapshot(208).unwrap(),
            DirectPodRuntimePoll::StopFrontier
        );
        let (scan, status) = durable.finish_and_seal().unwrap();
        assert_eq!(scan.complete_chunks, 1);
        assert_eq!(status.phase, HardwareRunPhase::Sealed);
        assert!(!status.hardware_transport_available);
        assert_eq!(
            JournalReader::open_sealed(&files.journal).unwrap().count(),
            1
        );
        let _ = std::fs::remove_dir_all(hardware_ledger);
    }

    #[test]
    fn durable_runtime_persists_replay_before_out_and_completion_after_durable_data() {
        let (files, session) = new_session("runtime-durable-replay");
        let hardware_ledger = PathBuf::from(format!("{}.hardware-ledger", files.journal.display()));
        let lifecycle = HardwareRunCoordinator::open(&hardware_ledger).unwrap();
        let (transport, controller) = FakeTransport::new();
        let runtime = DirectPodRuntime::new(
            session,
            transport,
            DirectPodRuntimeConfig {
                read_buffer_bytes: 1_024,
                read_depth: 2,
            },
        )
        .unwrap();
        let mut durable = DurableDirectPodRuntime::new(runtime, lifecycle).unwrap();
        durable.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities()));
        durable.poll_once_from_snapshot(100).unwrap();
        controller.push(DirectPodTransportRead::Complete(time_snapshot(1, 1_000)));
        durable.poll_once_from_snapshot(200).unwrap();
        for (request_id, command_code, state_code) in [(1_u64, 1_u16, 1_u16), (2, 2, 2), (3, 3, 3)]
        {
            durable
                .send_run_command_from_snapshot(&command(request_id, command_code), 201)
                .unwrap();
            controller.push(DirectPodTransportRead::Complete(ack(
                request_id, state_code, [0x44; 32],
            )));
            durable.poll_once_from_snapshot(202).unwrap();
            durable.take_reply().unwrap();
        }
        controller.push(DirectPodTransportRead::Complete(records(1).remove(0)));
        durable.poll_once_from_snapshot(203).unwrap();
        assert_eq!(
            durable.snapshot().lifecycle.phase,
            HardwareRunPhase::Recording
        );

        let context_hash = durable
            .expected_replay_request_context_hash(4, 1, 3, 10_000, 1)
            .unwrap();
        let request = encode_low_speed(
            0,
            4,
            EPOCH,
            &ReplayRequestV1 {
                run_id: RUN_ID,
                pod_id: POD_ID,
                first_record_sequence: 1,
                last_record_sequence_exclusive: 3,
                deadline_global_time_ns: 10_000,
                reason_code: 1,
                request_context_hash: context_hash,
            },
        )
        .unwrap();
        let event_count_before = durable.snapshot().lifecycle.ledger_events;
        let invalid_context = encode_low_speed(
            0,
            4,
            EPOCH,
            &ReplayRequestV1 {
                run_id: RUN_ID,
                pod_id: POD_ID,
                first_record_sequence: 1,
                last_record_sequence_exclusive: 3,
                deadline_global_time_ns: 10_000,
                reason_code: 1,
                request_context_hash: [0x99; 32],
            },
        )
        .unwrap();
        assert!(durable
            .send_replay_request_from_snapshot(&invalid_context, 203)
            .is_err());
        assert_eq!(
            durable.snapshot().lifecycle.ledger_events,
            event_count_before
        );
        assert_eq!(controller.snapshot().1, 3);
        assert!(!durable.snapshot().poisoned);

        let (decision, receipt) = durable
            .send_replay_request_from_snapshot(&request, 203)
            .unwrap();
        assert_eq!(decision, DirectPodSendDecision::Send);
        assert_eq!(receipt.hardware_accepted, None);
        assert_eq!(controller.snapshot().1, 4);
        assert_eq!(
            durable.snapshot().lifecycle.ledger_events,
            event_count_before + 1,
            "Replay intent was not durable before OUT"
        );
        for record in replay_records(1, 3) {
            controller.push(DirectPodTransportRead::Complete(record));
            durable.poll_once_from_snapshot(204).unwrap();
        }
        assert_eq!(durable.snapshot().runtime.ingest.durable_record_count, 3);
        let replay_hash = durable.expected_replay_receipt_hash().unwrap();
        controller.push(DirectPodTransportRead::Complete(ack(4, 3, replay_hash)));
        durable.poll_once_from_snapshot(205).unwrap();
        let matched = durable.take_reply().unwrap();
        assert!(matched.replay_boundary_verified);
        let status = durable.snapshot().lifecycle;
        assert_eq!(status.phase, HardwareRunPhase::Recording);
        assert_eq!(status.pending_replay_request_id, None);
        assert_eq!(status.verified_replay_count, 1);
        assert_eq!(status.ledger_events, event_count_before + 2);

        drop(durable);
        let reopened = HardwareRunCoordinator::open(&hardware_ledger).unwrap();
        assert_eq!(reopened.status().verified_replay_count, 1);
        assert!(reopened.status().auto_failed_on_restart);
        let _ = std::fs::remove_dir_all(hardware_ledger);
    }

    #[test]
    fn source_offer_automatically_persists_and_requests_replay_without_operator_command() {
        let (files, session) = new_session("runtime-auto-replay-offer");
        let hardware_ledger = PathBuf::from(format!("{}.hardware-ledger", files.journal.display()));
        let lifecycle = HardwareRunCoordinator::open(&hardware_ledger).unwrap();
        let (transport, controller) = FakeTransport::new();
        let runtime = DirectPodRuntime::new(
            session,
            transport,
            DirectPodRuntimeConfig {
                read_buffer_bytes: 1_024,
                read_depth: 2,
            },
        )
        .unwrap();
        let mut durable = DurableDirectPodRuntime::new(runtime, lifecycle).unwrap();
        durable.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities()));
        durable.poll_once_from_snapshot(100).unwrap();
        controller.push(DirectPodTransportRead::Complete(time_snapshot(1, 1_000)));
        durable.poll_once_from_snapshot(200).unwrap();
        for (request_id, command_code, state_code) in [(1_u64, 1_u16, 1_u16), (2, 2, 2), (3, 3, 3)]
        {
            durable
                .send_run_command_from_snapshot(&command(request_id, command_code), 201)
                .unwrap();
            controller.push(DirectPodTransportRead::Complete(ack(
                request_id, state_code, [0x44; 32],
            )));
            durable.poll_once_from_snapshot(202).unwrap();
            durable.take_reply().unwrap();
        }
        controller.push(DirectPodTransportRead::Complete(records(1).remove(0)));
        durable.poll_once_from_snapshot(203).unwrap();
        assert_eq!(
            durable.snapshot().lifecycle.phase,
            HardwareRunPhase::Recording
        );

        let events_before = durable.snapshot().lifecycle.ledger_events;
        controller.push(DirectPodTransportRead::Complete(replay_offer(
            1,
            1,
            3,
            1_000,
            sha256(&1_u64.to_le_bytes()),
        )));
        durable.poll_once_from_snapshot(204).unwrap();
        let after_offer = durable.snapshot();
        assert_eq!(after_offer.lifecycle.replay_offer_count, 1);
        assert_eq!(after_offer.lifecycle.pending_replay_request_id, Some(4));
        assert_eq!(after_offer.lifecycle.ledger_events, events_before + 2);
        assert_eq!(after_offer.runtime.ingest.replay_offer_count, 1);
        assert!(after_offer.runtime.ingest.pending_replay_offer.is_some());
        let writes = controller.writes();
        assert_eq!(writes.len(), 4);
        let outbound = decode_low_speed(writes.last().unwrap()).unwrap();
        assert_eq!(outbound.kind, MessageKind::ReplayRequest);
        let planned = ReplayRequestV1::decode_body(&outbound.body).unwrap();
        assert_eq!(planned.first_record_sequence, 1);
        assert_eq!(planned.last_record_sequence_exclusive, 3);

        for record in replay_records(1, 3) {
            controller.push(DirectPodTransportRead::Complete(record));
            durable.poll_once_from_snapshot(205).unwrap();
        }
        let receipt_hash = durable.expected_replay_receipt_hash().unwrap();
        controller.push(DirectPodTransportRead::Complete(ack(4, 3, receipt_hash)));
        durable.poll_once_from_snapshot(206).unwrap();
        assert!(durable.take_reply().unwrap().replay_boundary_verified);
        let final_status = durable.snapshot();
        assert_eq!(final_status.lifecycle.phase, HardwareRunPhase::Recording);
        assert_eq!(final_status.lifecycle.verified_replay_count, 1);
        assert!(final_status.runtime.ingest.pending_replay_offer.is_none());
        assert_eq!(final_status.runtime.ingest.durable_record_count, 3);

        drop(durable);
        let reopened = HardwareRunCoordinator::open(&hardware_ledger).unwrap();
        assert_eq!(reopened.status().replay_offer_count, 1);
        assert_eq!(reopened.status().verified_replay_count, 1);
        let _ = std::fs::remove_dir_all(hardware_ledger);
    }

    #[test]
    fn journal_bound_service_persists_before_out_and_owner_poll_applies_ack() {
        let (files, session) = new_session("journal-bound-service");
        let hardware_ledger = PathBuf::from(format!("{}.hardware-ledger", files.journal.display()));
        let lifecycle = HardwareRunCoordinator::open(&hardware_ledger).unwrap();
        let (transport, controller) = FakeTransport::new();
        let runtime = DirectPodRuntime::new(
            session,
            transport,
            DirectPodRuntimeConfig {
                read_buffer_bytes: 1_024,
                read_depth: 2,
            },
        )
        .unwrap();
        let mut durable = DurableDirectPodRuntime::new(runtime, lifecycle).unwrap();
        durable.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities()));
        durable.poll_once_from_snapshot(100).unwrap();
        controller.push(DirectPodTransportRead::Complete(time_snapshot(1, 1_000)));
        durable.poll_once_from_snapshot(200).unwrap();

        let mut backend = JournalBoundDirectPodBackend::new(durable).unwrap();
        let request = OperatorRunRequestV1 {
            request_id: 1,
            epoch: EPOCH,
            command: RunCommandKind::Prepare,
            relative_deadline_ms: 100,
            run_id: RUN_ID,
            target_device_id: DEVICE_ID,
            frozen_config_hash: [0x55; 32],
            expected_hardware_state_hash: sha256(&1_u64.to_le_bytes()),
        };

        let mut wrong_run = request;
        wrong_run.run_id = [0x99; 16];
        assert!(backend.submit(wrong_run, 201).is_err());
        assert_eq!(controller.snapshot().1, 0, "identity failure reached OUT");

        let requested = backend.submit(request, 201).unwrap();
        assert_eq!(
            requested.service_state,
            HardwareServiceState::PrepareRequested
        );
        assert_eq!(requested.active_run_id, RUN_ID);
        assert_eq!(requested.active_epoch, EPOCH);
        assert_eq!(requested.pending_request_id, 1);
        assert_ne!(requested.availability_flags & AVAIL_HARDWARE_AVAILABLE, 0);
        assert_eq!(controller.snapshot().1, 1);

        controller.push(DirectPodTransportRead::Complete(ack(1, 1, [0x44; 32])));
        let (_, reply) = backend.poll_once(202).unwrap();
        assert_eq!(reply.unwrap().request_id, 1);
        let prepared = backend.status(2, 203).unwrap();
        assert_eq!(prepared.service_state, HardwareServiceState::Prepared);
        assert_eq!(prepared.pending_request_id, 0);
        assert_ne!(requested.evidence_hash, prepared.evidence_hash);

        drop(backend);
        let _ = std::fs::remove_dir_all(hardware_ledger);
    }

    #[test]
    fn runtime_queue_policy_and_empty_completion_fail_closed() {
        assert!(DirectPodRuntimeConfig {
            read_buffer_bytes: 1_024,
            read_depth: 1,
        }
        .validate()
        .is_err());
        assert!(DirectPodRuntimeConfig {
            read_buffer_bytes: 16 * 1024 * 1024,
            read_depth: 5,
        }
        .validate()
        .is_err());

        let (_files, session) = new_session("runtime-empty");
        let (transport, controller) = FakeTransport::new();
        let mut runtime = DirectPodRuntime::new(
            session,
            transport,
            DirectPodRuntimeConfig {
                read_buffer_bytes: 1_024,
                read_depth: 2,
            },
        )
        .unwrap();
        runtime.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(Vec::new()));
        assert!(runtime.poll_once(100).is_err());
        assert!(runtime.snapshot().poisoned);
        assert_eq!(controller.snapshot().2, 1);
    }

    #[test]
    fn runtime_control_transport_failure_cancels_reads_and_poisons_epoch() {
        let (_files, session) = new_session("runtime-write-failure");
        let (transport, controller) = FakeTransport::new();
        let mut runtime = DirectPodRuntime::new(
            session,
            transport,
            DirectPodRuntimeConfig {
                read_buffer_bytes: 1_024,
                read_depth: 2,
            },
        )
        .unwrap();
        runtime.prime_reads().unwrap();
        controller.push(DirectPodTransportRead::Complete(capabilities()));
        runtime.poll_once(100).unwrap();
        controller.fail_next_write();
        assert_eq!(
            runtime
                .send_control(&command(1, 1), 101)
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        let snapshot = runtime.snapshot();
        assert!(snapshot.poisoned);
        assert_eq!(snapshot.queued_reads, 0);
        assert_eq!(controller.snapshot().2, 1);
    }
}
