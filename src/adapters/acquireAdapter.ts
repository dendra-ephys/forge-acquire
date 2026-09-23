/** Domain-only acquisition contract. UI code must not depend on Tauri or Rust IPC. */

export const MAX_PODS_PER_RUN = 8 as const;

export type AdapterScope = "mock" | "software" | "hardware";
export type CapabilityStatus = "available" | "unavailable" | "qualification_required";

export type CapabilityId =
  | "mock_acquisition"
  | "decimated_preview"
  | "lfp_preview"
  | "spike_preview"
  | "fault_injection"
  | "ft601_direct"
  | "aggregator_10gbe"
  | "rhs_acquisition"
  | "nwb_materialization"
  | "stimulation"
  | "closed_loop"
  | "release_24h";

export interface CapabilityEvidence {
  id: CapabilityId;
  status: CapabilityStatus;
  claimScope: AdapterScope;
  reasonCode: string;
  summary: string;
  evidenceHash: string | null;
}

export interface CapabilitySnapshot {
  adapterId: string;
  scope: AdapterScope;
  synthetic: boolean;
  sequence: bigint;
  observedAtMonotonicMs: number;
  maxPodsPerRun: typeof MAX_PODS_PER_RUN;
  capabilities: Readonly<Record<CapabilityId, CapabilityEvidence>>;
  evidenceHash: string;
}

export type AcquireLifecycleState =
  | "disconnected"
  | "connected_idle"
  | "preflighting"
  | "preflight_passed"
  | "arm_requested"
  | "armed"
  | "start_requested"
  | "recording"
  | "stop_requested"
  | "recording_stopped"
  | "finalizing"
  | "finalized"
  | "recovery_required";

export type ControlConnectionState = "disconnected" | "connected" | "lost" | "stale";

/** Preview is an independent low-rate session. It is never inferred from a Recording Run. */
export type PreviewSessionState =
  | "stopped"
  | "start_requested"
  | "live"
  | "stop_requested"
  | "fault";

export type EvidenceSlotId =
  | "acquisition"
  | "durability"
  | "nwb"
  | "analysis"
  | "stim_receipt";

export type EvidenceStatus =
  | "unavailable"
  | "qualification_required"
  | "idle"
  | "pending"
  | "active"
  | "proven"
  | "degraded"
  | "failed";

export interface EvidenceSlot {
  id: EvidenceSlotId;
  status: EvidenceStatus;
  scope: AdapterScope;
  summary: string;
  watermark: bigint | null;
  receiptSequence: bigint | null;
  evidenceHash: string | null;
  updatedAtMonotonicMs: number;
}

export interface RunIntegrityEvidence {
  acquisition: EvidenceSlot;
  durability: EvidenceSlot;
  nwb: EvidenceSlot;
  analysis: EvidenceSlot;
  stimReceipt: EvidenceSlot;
}

/** Low-rate operational load indicators. Values are adapter-authored, never UI estimates. */
export interface DaemonLoadSnapshot {
  sourceBufferPercent: number | null;
  writerQueuePercent: number | null;
  controlLoadPercent: number | null;
  inputBytesPerSecond: number | null;
  expectedBytesPerSecond: number | null;
  /** Adapter-authored bytes currently present in the active recording file. */
  recordingFileBytes: number | null;
  /** Adapter-authored free bytes on the selected recording volume. */
  storageFreeBytes: number | null;
}

export type PodKey = string;
export type PodState = "mock_ready" | "mock_recording" | "ready" | "recording" | "fault";

export type DeviceKind = "pod" | "aggregator";
export type DeviceNamePersistence = "device_nonvolatile" | "mock_session" | "host_local" | "none";
export type DeviceIdentitySource = "device_otp" | "device_certificate" | "mock_fixture" | "host_cache";

/**
 * Adapter-authored device identity and display name. `deviceId` is immutable;
 * routes and user-visible names must never be used as hardware identity.
 */
export interface DeviceIdentitySnapshot {
  deviceId: string;
  identitySource: DeviceIdentitySource;
  identityEvidenceHash: string | null;
  displayName: string;
  revision: bigint;
  persistence: DeviceNamePersistence;
  writable: boolean;
  revisionCasSupported: boolean;
  nameReadBackVerified: boolean;
  crossHostPersistenceQualified: boolean;
  powerLossSafeWriteQualified: boolean;
  maxNameUtf8Bytes: number | null;
  normalization: "NFC" | null;
  status: CapabilityStatus;
  reasonCode: string;
  /** Evidence for the current mutable name record, separate from immutable identity evidence. */
  evidenceHash: string | null;
}

export type NeuralSampleEncoding =
  | "signed_i16_le"
  | "offset_binary_u16_le"
  | "synthetic_generator"
  | "nwb_waveform_reconstruction"
  | "unknown";

export type PreviewValueUnit = "adc_count" | "microvolt";

/**
 * Receipt-authored neural input identity. The UI must not infer any of these
 * fields from a local hardware catalogue or from a transport name.
 */
export interface HeadstageInputSnapshot {
  headstageId: string | null;
  profileId: string | null;
  profileLabel: string | null;
  neuralChannelCount: number;
  sampleRateHz: number;
  channelLayoutId: string | null;
  sourceEncoding: NeuralSampleEncoding;
  previewValueUnit: PreviewValueUnit;
  microvoltsPerCount: number | null;
  zeroCode: number | null;
  status: CapabilityStatus;
  scope: AdapterScope;
  reasonCode: string;
  descriptorHash: string | null;
  inventoryHash: string | null;
  configHash: string | null;
  evidenceHash: string | null;
}

export type PodConnectionPath =
  | {
      kind: "direct_pc";
      connectionId: string;
      podTransport: "usb3";
    }
  | {
      kind: "aggregator";
      aggregatorId: string;
      port: number;
      podTransport: "usb3";
      hostUplink: "10gbe";
    };

export interface PodSnapshot {
  key: PodKey;
  state: PodState;
  scope: AdapterScope;
  synthetic: boolean;
  podId: string | null;
  identity: DeviceIdentitySnapshot;
  /** Compatibility mirror of `identity.displayName`; never an immutable identifier. */
  label: string;
  connection: PodConnectionPath;
  neuralInput: HeadstageInputSnapshot | null;
  selectedForRun: boolean;
  selectable: boolean;
  selectionReasonCode: string;
  evidenceHash: string;
}

export type AggregatorState =
  | "mock_fixture"
  | "unavailable"
  | "qualification_required"
  | "ready"
  | "fault";

export interface AggregatorPortSnapshot {
  port: number;
  pod: PodSnapshot | null;
}

export interface AggregatorSnapshot {
  aggregatorId: string;
  identity: DeviceIdentitySnapshot;
  /** Compatibility mirror of `identity.displayName`; never an immutable identifier. */
  label: string;
  scope: AdapterScope;
  synthetic: boolean;
  state: AggregatorState;
  capabilityId: "aggregator_10gbe";
  hardwareStatus: CapabilityStatus;
  hardwareReasonCode: string;
  maxPodPorts: typeof MAX_PODS_PER_RUN;
  ports: readonly AggregatorPortSnapshot[];
  evidenceHash: string | null;
}

export interface PodTopologySnapshot {
  sequence: bigint;
  maxPodsPerRun: typeof MAX_PODS_PER_RUN;
  directPods: readonly PodSnapshot[];
  aggregators: readonly AggregatorSnapshot[];
  evidenceHash: string;
}

export type FaultCode =
  | "counter_gap"
  | "control_pipe_loss"
  | "durability_failure"
  | "recording_pipeline_failure";

export interface FaultRecord {
  code: FaultCode;
  scope: AdapterScope;
  message: string;
  latched: boolean;
  recoverable: boolean;
  injected: boolean;
  /** Exact affected source interval when known; never a guessed event count. */
  sampleStart: bigint | null;
  sampleEndExclusive: bigint | null;
  observedAtMonotonicMs: number;
  evidenceHash: string;
}

export type RunReceiptStatus =
  | "active"
  | "stopped_not_durable"
  | "raw_sealed"
  | "finalizing"
  | "finalized"
  | "recovery_required"
  | "degraded";

/**
 * Final user artifact receipt. The GUI must not derive this path from the Run
 * directory or promote a sealed recovery journal into a completed NWB file.
 */
export interface NwbArtifactReceipt {
  artifactKind: "nwb";
  filePath: string;
  createDisposition: "created_new";
  schemaValidated: true;
  inspectorPassed: true;
  publicationCommitted: true;
  publicationReceiptId: string;
  evidenceHash: string;
}

/** Immutable low-rate run evidence. `finalized` is always scoped; mock is not release evidence. */
export interface RunReceipt {
  receiptKind: "run";
  scope: AdapterScope;
  synthetic: boolean;
  runId: string;
  runEpoch: bigint;
  status: RunReceiptStatus;
  lifecycle: AcquireLifecycleState;
  receiptSequence: bigint;
  generatedAtMonotonicMs: number;
  evidence: RunIntegrityEvidence;
  recordingTarget: RecordingTargetReservation;
  /** Null until a real adapter reports a validated, create-new NWB publication. */
  nwbArtifact: NwbArtifactReceipt | null;
  faults: readonly FaultRecord[];
  evidenceHash: string;
}

export interface DaemonSnapshot {
  adapterId: string;
  scope: AdapterScope;
  synthetic: boolean;
  lifecycle: AcquireLifecycleState;
  /** True only when the adapter has explicitly acknowledged a reversible recording pause. */
  recordingPaused: boolean;
  previewState: PreviewSessionState;
  controlConnection: ControlConnectionState;
  stale: boolean;
  snapshotSequence: bigint;
  observedAtMonotonicMs: number;
  runId: string | null;
  runEpoch: bigint | null;
  recordingTarget: RecordingTargetReservation | null;
  selectedPodKeys: readonly PodKey[];
  topology: PodTopologySnapshot;
  load: DaemonLoadSnapshot;
  evidence: RunIntegrityEvidence;
  faults: readonly FaultRecord[];
  lastCommandReceiptId: string | null;
  runReceipt: RunReceipt | null;
  evidenceHash: string;
}

export interface RunPlan {
  label: string;
  plannedDurationSeconds: number;
  selectedDevices: readonly RunDeviceSelection[];
  topologyEvidenceHash: string;
  recordingTarget: RecordingTargetRequest;
}

/** Immutable identity and neural-input receipts frozen into a Recording plan. */
export interface RunDeviceSelection {
  podKey: PodKey;
  deviceId: string;
  identityEvidenceHash: string;
  inputEvidenceHash: string;
}

/** Operator intent. The adapter/daemon owns the final create-new allocation. */
export interface RecordingTargetRequest {
  requestedDirectory: string;
  baseName: string;
  allocationPolicy: "create_new_incrementing_suffix";
  overwritePolicy: "forbid";
}

/** Receipt-bound target. Mock reservations never imply a real directory was created. */
export interface RecordingTargetReservation {
  reservationId: string;
  requestedDirectory: string;
  allocatedLeafName: string;
  resolvedRunDirectory: string;
  allocationSequence: bigint;
  journalFileName: "run.forgewal";
  /** `created_new` must come from the native filesystem operation, never from UI path formatting. */
  directoryCreateDisposition: "simulated" | "created_new";
  journalCreateDisposition: "simulated" | "created_new";
  overwritePolicy: "forbid";
  scope: AdapterScope;
  synthetic: boolean;
  reasonCode: string;
  evidenceHash: string;
}

export type AcquireIntent =
  | { type: "connect" }
  | { type: "disconnect_control" }
  | { type: "start_preview"; podKey: PodKey; topologyEvidenceHash: string }
  | { type: "stop_preview"; reason?: string }
  | { type: "preflight"; plan: RunPlan }
  | { type: "arm_recording" }
  | { type: "start_recording" }
  | { type: "pause_recording" }
  | { type: "resume_recording" }
  | { type: "stop_recording"; reason?: string }
  | { type: "recover_run" }
  | { type: "acknowledge_failed_run" };

export interface CommandReceipt {
  receiptKind: "command";
  receiptId: string;
  requestId: bigint;
  scope: AdapterScope;
  synthetic: boolean;
  intent: AcquireIntent["type"];
  accepted: boolean;
  reasonCode: string;
  message: string;
  stateAtAcceptance: AcquireLifecycleState;
  requestedState: AcquireLifecycleState | null;
  previewStateAtAcceptance: PreviewSessionState;
  requestedPreviewState: PreviewSessionState | null;
  runId: string | null;
  runEpoch: bigint | null;
  issuedAtMonotonicMs: number;
  evidenceHash: string;
}

export type SnapshotListener = (snapshot: DaemonSnapshot) => void;
export type Unsubscribe = () => void;

export type PreviewSignalKind = "wideband" | "lfp" | "spike";

export interface PreviewRequest {
  podKey: PodKey;
  signalKind: PreviewSignalKind;
  windowSeconds: number;
  channelStart: number;
  channelCount: number;
  selectedChannel: number;
}

export interface PreviewProcessingEvidence {
  status: CapabilityStatus;
  scope: AdapterScope;
  algorithmId: string;
  summary: string;
  sourceSampleRateHz: number;
  displaySampleRateHz: number | null;
  passbandHz: readonly [number, number] | null;
  filterProfileId: string | null;
  configHash: string | null;
  groupDelayMs: number | null;
  evidenceHash: string | null;
}

export type PreviewCoverageState = "complete" | "fault" | "unknown";

/** Exact source-sample interval that could not be covered; never an event-count estimate. */
export interface PreviewCoverageRange {
  sampleStart: bigint;
  sampleEndExclusive: bigint;
  reasonCode: string;
}

export interface PreviewCoverageEvidence {
  source: PreviewCoverageState;
  analysis: PreviewCoverageState;
  sourceGapRanges: readonly PreviewCoverageRange[];
  analysisGapRanges: readonly PreviewCoverageRange[];
}

/** Low-rate preview bounds: either complete bucket min/max or explicitly sampled candidates. Never continuous raw sample bytes. */
export interface PreviewChannelEnvelope {
  channel: number;
  minValues: readonly number[];
  maxValues: readonly number[];
  rmsValue: number | null;
  peakAbsValue: number | null;
}

export interface PreviewFrameBase {
  scope: AdapterScope;
  synthetic: boolean;
  /** Continuous source samples never cross into the WebView preview contract. */
  containsContinuousRawSamples: false;
  /** True only for bounded, event-aligned snippets in a Spike frame. */
  containsEventWaveformSnippets: boolean;
  sequence: bigint;
  generatedAtMonotonicMs: number;
  /** Non-null only while this source interval is inside a source-confirmed Recording capture window. */
  runId: string | null;
  runEpoch: bigint | null;
  podKey: PodKey;
  podId: string | null;
  podLabel: string;
  inputChannelCount: number;
  inputEvidenceHash: string | null;
  valueUnit: PreviewValueUnit;
  valueUnitScope: AdapterScope;
  valueUnitReasonCode: string;
  valueEvidenceHash: string | null;
  channelStart: number;
  channelCount: number;
  signalKind: PreviewSignalKind;
  windowSeconds: number;
  sourceSampleStart: bigint | null;
  sourceSampleEndExclusive: bigint | null;
  /** Presentation freshness is separate from source and analysis coverage. */
  previewFreshness: "current" | "stale" | "unknown";
  coverage: PreviewCoverageEvidence;
  processing: PreviewProcessingEvidence;
}

export interface EnvelopePreviewFrame extends PreviewFrameBase {
  encoding: "min_max_envelope_v1" | "sampled_extrema_preview_v1";
  aggregation: "complete_bucket_min_max" | "sampled_candidates";
  signalKind: "wideband" | "lfp";
  pointsPerChannel: number;
  samplesPerBucket: number;
  channels: readonly PreviewChannelEnvelope[];
}

export interface SpikeRasterEvent {
  eventId: string;
  channel: number;
  eventOffsetMs: number;
  peakValue: number;
}

export interface SpikeWaveformSummary {
  channel: number;
  /** Null when events come from a synthetic schedule rather than a detector. */
  thresholdValue: number | null;
  contributingWaveformCount: number;
  meanValues: readonly number[];
  p10Values: readonly number[];
  p90Values: readonly number[];
}

/** One bounded event-aligned snippet, never a continuous raw stream. */
export interface SpikeWaveformEvent {
  eventId: string;
  channel: number;
  centerSample: bigint;
  snippetSampleStart: bigint;
  snippetSampleEndExclusive: bigint;
  preTriggerSamples: number;
  values: readonly number[];
}

/**
 * Complete rolling-window snapshot for the selected channel. A caller may
 * label this view "all waveforms" only while coverage is complete and the
 * returned count equals the observed count.
 */
export interface SpikeWaveformWindow {
  retentionSamples: bigint;
  coverage: PreviewCoverageState;
  reasonCode: string | null;
  observedEventCount: number;
  returnedEventCount: number;
  events: readonly SpikeWaveformEvent[];
}

export interface SpikeChannelActivity {
  channel: number;
  observedEventCount: number;
  rateHz: number;
  valid: boolean;
  /** Up to three recent event-aligned snippets for the all-channel overview. */
  recentWaveforms: readonly (readonly number[])[];
}

export interface SpikeRasterAccounting {
  selectionPolicy: "channel_stratified_rotating_v1";
  maxReturnedEvents: number;
  observedEventCount: number;
  rasterCandidateEventCount: number;
  sampledOutEventCount: number;
  returnedRasterEventCount: number;
  rotationOffset: number;
}

/**
 * Full-Pod event activity from the declared processing source (detector or
 * synthetic oracle), plus a bounded raster for the requested channel bank and
 * a complete rolling snapshot of selected-channel event snippets, and
 * statistics computed from that same snapshot. Never contains a continuous
 * raw sample stream.
 */
export interface SpikePreviewFrame extends PreviewFrameBase {
  encoding: "spike_preview_v3";
  signalKind: "spike";
  sorting: "unsorted";
  waveformSampleRateHz: number;
  podObservedEventCount: number;
  channelActivity: readonly SpikeChannelActivity[];
  accounting: SpikeRasterAccounting;
  raster: readonly SpikeRasterEvent[];
  selectedChannel: number;
  selectedChannelWaveforms: SpikeWaveformWindow;
  selectedChannelWaveformStats: SpikeWaveformSummary | null;
}

export type PreviewFrame = EnvelopePreviewFrame | SpikePreviewFrame;

export interface PreviewSource {
  readonly maxFramesPerSecond: number;
  setRequest(request: PreviewRequest): void;
  getLatest(): PreviewFrame | null;
  subscribe(listener: (frame: PreviewFrame) => void): Unsubscribe;
}

export interface AcquireAdapter {
  readonly adapterId: string;
  readonly scope: AdapterScope;
  readonly previewSource: PreviewSource;
  readCapabilities(): Promise<CapabilitySnapshot>;
  readSnapshot(): Promise<DaemonSnapshot>;
  subscribeSnapshots(listener: SnapshotListener): Unsubscribe;
  execute(intent: AcquireIntent): Promise<CommandReceipt>;
  renameDevice(request: RenameDeviceRequest): Promise<DeviceNameReceipt>;
  dispose(): void;
}

export interface RenameDeviceRequest {
  kind: DeviceKind;
  deviceId: string;
  expectedIdentityEvidenceHash: string;
  displayName: string;
  expectedRevision: bigint;
}

export interface DeviceNameReceipt {
  receiptKind: "device_name";
  receiptId: string;
  scope: AdapterScope;
  synthetic: boolean;
  accepted: boolean;
  reasonCode: string;
  message: string;
  kind: DeviceKind;
  deviceId: string;
  identityEvidenceHash: string | null;
  previousRevision: bigint;
  committedRevision: bigint | null;
  committedDisplayName: string | null;
  persistence: DeviceNamePersistence;
  readBackVerified: boolean;
  nameRecordEvidenceHash: string | null;
  issuedAtMonotonicMs: number;
  evidenceHash: string;
}

export type MockFault =
  | { type: "counter_gap"; missingSamples?: number }
  | { type: "control_pipe_loss" }
  | { type: "durability_failure"; reason?: string };

/** Deliberately separate from AcquireAdapter so production adapters cannot inject faults. */
export interface MockFaultControl {
  inject(fault: MockFault): Promise<void>;
  clear(code: FaultCode): Promise<void>;
}
