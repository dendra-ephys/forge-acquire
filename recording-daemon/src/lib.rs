//! Forge acquisition data-plane primitives.
//!
//! The crate contains a fail-closed Windows FT601/D3XX direct-Pod owner with
//! protected deployment/admission, source-status and Run-promotion gates. It
//! does not manufacture those approvals, qualify an active Receiver-Pod RTL
//! implementation, or bind an Aggregator transport. Hardware acquisition must
//! therefore remain unavailable unless every external gate is supplied and
//! verified. The journal is the crash-recovery boundary for admitted records.

pub mod analysis_fault_evidence;
#[cfg(windows)]
pub mod analysis_mapping;
pub mod analysis_ring;
#[cfg(windows)]
pub mod analysis_worker_protocol;
#[cfg(windows)]
pub mod analysis_worker_service;
pub mod buffer_pool;
pub mod canonical_stream;
#[cfg(windows)]
pub mod d3xx;
pub mod d3xx_admission;
pub mod dhl_identity_admission;
pub mod dhl_identity_catalog;
pub mod direct_pod_cabline;
pub mod direct_pod_control;
#[cfg(windows)]
pub mod direct_pod_deployment;
pub mod direct_pod_dhl_identity;
pub mod direct_pod_ingest;
#[cfg(windows)]
pub mod direct_pod_reconnect;
pub mod direct_pod_record_release;
pub mod direct_pod_replay;
pub mod direct_pod_replay_offer;
pub mod direct_pod_stop;
pub mod direct_pod_stream;
pub mod direct_pod_time;
#[cfg(all(windows, feature = "qualification-harness"))]
pub(crate) mod gui_kill_audit;
#[cfg(all(windows, feature = "qualification-harness"))]
pub(crate) mod gui_kill_control;
#[cfg(all(windows, feature = "qualification-harness"))]
pub(crate) mod gui_kill_owner;
#[cfg(all(windows, feature = "qualification-harness"))]
pub mod gui_kill_qualification;
pub mod hardware_run;
pub mod hardware_service;
pub mod hardware_service_protocol;
pub mod ipc;
pub mod journal;
pub mod journal_retention;
pub(crate) mod nwb_generation_audit;
mod nwb_publication;
pub mod nwb_receipt;
pub mod receiver_pod_v2_session;
// These owner-internal primitives compile in production so the service can
// supervise an optional materializer without giving acquisition or public IPC
// code publication authority. Production launch remains fail-closed until the
// installed worker image and generation-root proofs are supplied.
pub(crate) mod nwb_supervisor;
#[cfg(windows)]
pub(crate) mod nwb_worker_launcher;
pub mod qualification;
pub mod replay;
pub mod run;
pub mod run_ledger;
pub mod safety_arbiter;
#[cfg(windows)]
pub(crate) mod scm_owner_protocol;
#[cfg(windows)]
pub mod scm_qualification;
#[cfg(windows)]
pub(crate) mod scm_stop_receipt;
pub mod service_protocol;
pub mod service_replay;
pub mod software_replay_control;
#[cfg(windows)]
pub mod software_replay_service;
pub mod source;
#[cfg(windows)]
pub(crate) mod windows_contained_process;
#[cfg(windows)]
pub mod windows_deployment_manifest;
#[cfg(windows)]
pub mod windows_deployment_security;
#[cfg(windows)]
pub mod windows_service_host;
#[cfg(windows)]
pub mod windows_service_install;
#[cfg(windows)]
pub mod windows_service_owner;

pub use analysis_ring::{
    AnalysisRing, AnalysisRingError, ConsumedAnalysisRecord, ANALYSIS_RING_SCHEMA_HASH,
    ANALYSIS_RING_SCHEMA_HASH_HEX,
};
pub use canonical_stream::{
    CanonicalStreamReassembler, CanonicalStreamStats, MAX_CANONICAL_RECORD_BYTES,
};
#[cfg(windows)]
pub use d3xx::{
    select_unique_ft600, validate_ft600_configuration, validate_ft600_device_state,
    validate_ft600_usb_descriptors, D3xxDevice, D3xxDeviceInfo, D3xxLibrary, D3xxReadPoll,
    Ft600ConfigurationEvidence, Ft600UsbDescriptorEvidence,
};
pub use d3xx_admission::{
    Ft600FifoClockProfile, VerifiedFt600Admission, FT600_ADMISSION_CONTRACT_HASH,
    FT600_ADMISSION_CONTRACT_HASH_HEX, FT600_ADMISSION_RECEIPT_LEN, FT600_PROFILE_BRINGUP_66_MHZ,
    FT600_PROFILE_RELEASE_100_MHZ,
};
pub use direct_pod_cabline::{
    DirectPodCablineStatusV1, DirectPodCablineTracker, DirectPodCablineTrackerSnapshot,
    CABLINE_FLAG_CTRL_READY, CABLINE_FLAG_DESCRIPTOR_ADMITTED, CABLINE_FLAG_INVENTORY_ADMITTED,
    CABLINE_FLAG_LINK_LOCKED, CABLINE_FLAG_RECEIVER_OVERFLOW, CABLINE_FLAG_SOURCE_FAULT,
    CABLINE_REQUIRED_READY_FLAGS, DIRECT_POD_CABLINE_MAX_HOST_AGE_NS,
    DIRECT_POD_CABLINE_STATUS_CONTRACT_HASH, DIRECT_POD_CABLINE_STATUS_CONTRACT_HASH_HEX,
    DIRECT_POD_CABLINE_STATUS_LEN,
};
pub use direct_pod_control::{
    DirectPodControlSnapshot, DirectPodControlTracker, DirectPodReply, DirectPodSendDecision,
    MatchedDirectPodReply,
};
#[cfg(windows)]
pub use direct_pod_deployment::{
    windows_data_root_sha256, D3xxLibraryPolicy, DirectPodD3xxBootstrap, DirectPodRecoveryReport,
    ProductionDirectPodReconnectBackend, ProtectedDirectPodPolicyReference,
    VerifiedDirectPodDeploymentPolicy, DIRECT_POD_DEPLOYMENT_POLICY_SCHEMA,
};
pub use direct_pod_dhl_identity::{
    decode_dhl_outer_packet_v1, DhlOuterPacketEvidenceV1, DirectPodDhlIdentityCapsuleError,
    DirectPodDhlIdentityCapsuleV1, DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_CONTRACT_HASH,
    DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_CONTRACT_HASH_HEX,
    DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_DESCRIPTOR_WIRE_LEN,
    DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_HEADER_LEN,
    DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_INVENTORY_WIRE_MAX_LEN,
    DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_INVENTORY_WIRE_MIN_LEN,
    DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MAX_LEN, DIRECT_POD_DHL_IDENTITY_CAPSULE_V1_MIN_LEN,
};
pub use direct_pod_ingest::{
    DirectPodAcquisitionState, DirectPodByteTransport, DirectPodIngestSession,
    DirectPodIngestSnapshot, DirectPodRunPlan, DirectPodRunPromotion, DirectPodRuntime,
    DirectPodRuntimeConfig, DirectPodRuntimePoll, DirectPodRuntimeSnapshot, DirectPodTransportRead,
    DurableDirectPodRuntime, DurableDirectPodRuntimeSnapshot, PreRunDirectPodConnection,
    PreRunDirectPodSnapshot,
};
#[cfg(windows)]
pub use direct_pod_reconnect::{
    DirectPodReconnectEventKind, DirectPodReconnectEventV1, DirectPodReconnectLedger,
    DIRECT_POD_RECONNECT_CONTRACT_HASH, DIRECT_POD_RECONNECT_CONTRACT_HASH_HEX,
    DIRECT_POD_RECONNECT_EVENT_LEN,
};
pub use direct_pod_record_release::{
    record_prefix_hash, store_state_hash, DirectPodRecordReleaseReplyV1,
    DirectPodRecordReleaseRequestV1, DirectPodRecordReleaseStatusV1, RetainedCanonicalRecord,
    DIRECT_POD_RECORD_RELEASE_CONTRACT_HASH, DIRECT_POD_RECORD_RELEASE_CONTRACT_HASH_HEX,
    DIRECT_POD_RECORD_RELEASE_LEN, RELEASE_FLAG_HAS_COMMITTED, RELEASE_FLAG_HAS_RELEASED,
    RELEASE_FLAG_HAS_RETAINED, RELEASE_FLAG_SEQUENCE_TERMINAL,
};
pub use direct_pod_replay::{
    DirectPodReplayBoundarySnapshot, DirectPodReplayBoundaryTracker, DirectPodReplayState,
    DIRECT_POD_REPLAY_COMPLETION_LEN, DIRECT_POD_REPLAY_CONTEXT_LEN,
    DIRECT_POD_REPLAY_CONTRACT_HASH, DIRECT_POD_REPLAY_CONTRACT_HASH_HEX,
    MAX_DIRECT_POD_REPLAY_RECORDS, REPLAY_ACK_CODE_APPLIED, REPLAY_STATE_CODE_RECORDING,
};
pub use direct_pod_replay_offer::{
    DirectPodReplayOfferV1, DIRECT_POD_REPLAY_OFFER_CONTRACT_HASH,
    DIRECT_POD_REPLAY_OFFER_CONTRACT_HASH_HEX, DIRECT_POD_REPLAY_OFFER_LEN,
    REPLAY_OFFER_FLAG_HOLD_UNTIL_DEADLINE, REPLAY_OFFER_FLAG_LIVE_STREAM_QUIESCED,
    REPLAY_OFFER_FLAG_RANGE_REPLAYABLE, REPLAY_OFFER_REQUIRED_FLAGS,
};
pub use direct_pod_stop::{
    DirectPodStopBoundarySnapshot, DirectPodStopBoundaryTracker,
    DIRECT_POD_STOP_BOUNDARY_CONTRACT_HASH, DIRECT_POD_STOP_BOUNDARY_CONTRACT_HASH_HEX,
    DIRECT_POD_STOP_BOUNDARY_LEN, STOP_ACK_CODE_APPLIED, STOP_STATE_CODE_STOPPED,
};
pub use direct_pod_stream::{
    DirectPodExtendedFrameKind, DirectPodExtendedStreamStats, DirectPodFrameKind,
    DirectPodIdentityFrameKind, DirectPodIdentityStreamStats, DirectPodStreamReassembler,
    DirectPodStreamStats,
};
pub use direct_pod_time::{
    DirectPodTimeSnapshotV1, DirectPodTimeTracker, DirectPodTimeTrackerSnapshot,
    DIRECT_POD_TIME_SNAPSHOT_CONTRACT_HASH, DIRECT_POD_TIME_SNAPSHOT_CONTRACT_HASH_HEX,
    DIRECT_POD_TIME_SNAPSHOT_LEN, TIME_FLAG_GLOBAL_TIME_VALID, TIME_FLAG_POD_FAULT,
    TIME_FLAG_POD_READY, TIME_FLAG_SYNCHRONIZED,
};
#[cfg(all(windows, feature = "qualification-harness"))]
pub use gui_kill_qualification::{
    receipt_evidence_hash, run_gui_kill_client, run_gui_kill_owner, run_gui_kill_qualification,
    verify_gui_kill_qualification_receipt, GuiKillContainmentEvidenceV3, GuiKillInjectedFailure,
    GuiKillQualificationOptions, GuiKillQualificationReceiptV3, GuiKillReapEvidenceV3,
    GUI_KILL_QUALIFICATION_SCHEMA,
};
pub use hardware_run::{
    HardwareReplayReceipt, HardwareRunContext, HardwareRunCoordinator, HardwareRunPhase,
    HardwareRunReceipt, HardwareRunStatus, HARDWARE_FAULT_DAEMON_RESTART,
    HARDWARE_FAULT_OWNER_SHUTDOWN, HARDWARE_FAULT_PERSISTENCE, HARDWARE_FAULT_TRANSPORT,
};
pub use hardware_service::{
    HardwareServiceDispatcher, HardwareServiceOwner, HardwareServiceProxy, HostMonotonicClock,
    JournalBoundDirectPodBackend, OwnedHardwareServiceBackend, UnavailableHardwareBackend,
};
#[cfg(windows)]
pub use hardware_service_protocol::{call_hardware_run_command, query_hardware_service};
pub use hardware_service_protocol::{
    translate_operator_run_request, HardwareServiceBackend, HardwareServiceError,
    HardwareServiceSnapshotV1, HardwareServiceState, HardwareStatusRequestV1, OperatorRunRequestV1,
    AVAIL_ADMISSION_VERIFIED, AVAIL_HARDWARE_AVAILABLE, AVAIL_TIME_FRESH, AVAIL_TRANSPORT_OPEN,
    HARDWARE_SERVICE_CONTRACT_HASH, HARDWARE_SERVICE_CONTRACT_HASH_HEX,
    HARDWARE_SERVICE_SNAPSHOT_LEN, HARDWARE_STATUS_REQUEST_LEN, OPERATOR_RUN_REQUEST_LEN,
};
pub use journal::{
    inspect_recovery, recover_to_durable, scan_journal, seal_evidence_hash, AppendReceipt,
    ChunkMetadata, DurableCheckpoint, JournalContentProfile, JournalIdentity,
    JournalPodSampleProfile, JournalReader, JournalRecord, JournalRecovery, JournalScan,
    JournalWriter, SealReceipt,
};
pub use journal_retention::{
    BackupVerifiedRetentionLockedV1, JournalBackupReceiptV1, JournalRetentionDecisionV1,
    JournalRetentionGate, JournalRetentionOwnerConfigV1, StableFileIdentityV1,
    JOURNAL_BACKUP_RECEIPT_SCHEMA,
};
pub use nwb_publication::{NwbGenerationPublicationReceiptV1, PublishedNwbGeneration};
pub use receiver_pod_v2_session::{
    validate_rps2_frame, Rps2FrameTransport, Rps2Opcode, Rps2SessionControl, Rps2SessionRuntime,
    Rps2TicketV1, RPS2_FRAME_LEN, RPS2_VERSION,
};
// Publication mutates the final namespace and Run ledger. Keep it out of the
// normal application API/CLI until the service-owner capability and
// handle-relative generation-root boundary are qualified. The explicit
// qualification build retains the existing engineering fixture.
#[cfg(feature = "qualification-harness")]
pub use nwb_publication::{finalize_nwb_publication, publish_nwb_generation};
pub use nwb_receipt::{
    verify_nwb_validation_bundle, NwbGenerationValidationReceiptV1, NwbValidationBundlePaths,
    VerifiedNwbGeneration,
};
pub use qualification::{
    run_journal_qualification, verify_journal_qualification_receipt, BuildIdentityV1,
    JournalQualificationEvidenceV2, JournalQualificationOptions, JournalQualificationReceiptV2,
    JournalQualificationSourceProfile, LatencySummaryV1, VolumeIdentityV1,
};
pub use replay::{run_protected_replay, ProtectedReplayOptions, ProtectedReplayReceipt};
pub use run_ledger::{DurableRunService, DurableRunStatus};
#[cfg(windows)]
pub use service_protocol::{
    call_daemon_run_command, call_software_replay_run_command, query_daemon_snapshot,
    query_software_replay_snapshot,
};
pub use service_protocol::{DaemonResponseV1, ServiceDispatcher, ServiceErrorV1};
#[cfg(windows)]
pub use software_replay_control::call_software_replay_control;
pub use software_replay_control::{
    SoftwareReplayControlCommandV1, SoftwareReplayControlRequestV1,
    SoftwareReplayControlResponseV1, SOFTWARE_REPLAY_CONTROL_RESPONSE_SCHEMA,
    SOFTWARE_REPLAY_CONTROL_SCHEMA,
};
