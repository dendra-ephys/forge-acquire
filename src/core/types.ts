export type BackendKind =
  | "simulator"
  | "replay"
  | "direct_d3xx"
  | "aggregator_10gbe";

export type TransportState =
  | "absent"
  | "enumerating"
  | "available"
  | "opening"
  | "open"
  | "reconnecting"
  | "failed";

export type AcquisitionState =
  | "idle"
  | "preparing"
  | "start_requested"
  | "initializing"
  | "streaming"
  | "stop_requested"
  | "stopping"
  | "aborted";

export type WriterState =
  | "disabled"
  | "opening"
  | "armed"
  | "writing"
  | "flushing"
  | "finalized"
  | "failed";

export type IntegrityState = "clean" | "degraded_latched" | "invalid";
export type SyncState = "standalone" | "waiting" | "synchronized" | "lost";
export type OperatorState =
  | "disconnected"
  | "ready"
  | "monitoring"
  | "recording";

export interface MachineState {
  transport: TransportState;
  acquisition: AcquisitionState;
  writer: WriterState;
  integrity: IntegrityState;
  sync: SyncState;
  runId: string | null;
  lastFinalizedRunId: string | null;
  lastError: string | null;
}

export interface PodSnapshot {
  id: string;
  label: string;
  serial: string | null;
  headstageProfileId: import("./hardwareProfiles").HeadstageProfileId | null;
  headstageProfileLabel: string | null;
  usbBridge: "FT600Q" | null;
  dhlLinkLocked: boolean | null;
  dhlDescriptorAdmitted: boolean;
  attached: boolean;
  ready: boolean;
  fault: boolean;
  synchronized: boolean;
  channelCount: number | null;
  sampleRate: number | null;
  bytesPerSecond: number;
  frameCounter: number | null;
  sampleCounter: number | null;
  crcErrors: number;
  counterGaps: number;
  resyncs: number;
  overflows: number;
}

export interface HealthMetrics {
  inputBytesPerSecond: number;
  expectedBytesPerSecond: number;
  writerBytesPerSecond: number;
  writerQueuePercent: number;
  bufferPercent: number;
  crcErrors: number;
  counterGaps: number;
  overflows: number;
  storageFreeBytes: number | null;
  storageRemainingSeconds: number | null;
}

export type SpoolState =
  | "unavailable"
  | "preparing"
  | "armed"
  | "writing"
  | "sealing"
  | "sealed"
  | "failed";

export type NwbMaterializationState =
  | "unavailable"
  | "waiting"
  | "materializing"
  | "validating"
  | "finalized"
  | "failed";

export type WorkerState =
  | "unavailable"
  | "stopped"
  | "observing"
  | "controller"
  | "lagging"
  | "failed";

export interface AnalysisPipelineSnapshot {
  cppWorker: WorkerState;
  pythonWorker: WorkerState;
  controllerTokenOwner: "none" | "cpp" | "python";
  referenceAlgorithmsOnly: boolean;
  processedSequence: number | null;
  droppedBlocks: number;
  lastError: string | null;
}

export type PhysicalInterlockState = "unknown" | "open" | "closed";
export type StimulationState =
  | "unavailable"
  | "disarmed"
  | "arming"
  | "armed"
  | "disarming"
  | "fault_latched";

/**
 * Low-rate, evidence-bearing stimulation status. An `armed` value is valid only
 * when it comes from the independent Rust SafetyArbiter and a matching hardware
 * receipt; the control plane must never infer it from a button press.
 */
export interface StimulationSafetySnapshot {
  state: StimulationState;
  headstageProfileId: import("./hardwareProfiles").HeadstageProfileId | null;
  rhsChannelCount: number;
  capabilityHash: string | null;
  safetyProfileHash: string | null;
  safetyProfileApprovalId: string | null;
  templateSetHash: string | null;
  algorithmBuildHash: string | null;
  algorithmConfigHash: string | null;
  channelMapHash: string | null;
  controllerWorkerBuildHash: string | null;
  physicalEnable: PhysicalInterlockState;
  emergencyStopHealthy: boolean | null;
  watchdogHealthy: boolean | null;
  complianceHealthy: boolean | null;
  hardwareClockLocked: boolean | null;
  frozenContextReceiptHash: string | null;
  closedLoopReleaseQualified: boolean;
  qualificationReceiptHash: string | null;
  armEpoch: number | null;
  deadlineBudgetMs: number | null;
  lastIntentSequence: number | null;
  lastReceiptSequence: number | null;
  receiptGapCount: number;
  duplicateReceiptCount: number;
  unavailableReasons: string[];
}

/**
 * Low-rate status only. Raw samples never cross into React.
 * Sequence fields are null until a production daemon can prove them.
 */
export interface RecordingPipelineSnapshot {
  spoolState: SpoolState;
  nwbState: NwbMaterializationState;
  receivedSequence: number | null;
  spooledSequence: number | null;
  durableSequence: number | null;
  nwbSequence: number | null;
  durableLagBytes: number | null;
  nwbLagBytes: number | null;
  spoolPath: string | null;
  nwbPath: string | null;
  protectionVerified: boolean;
}

export interface StoragePreflightSnapshot {
  plannedDurationSeconds: number;
  plannedInputBytesPerSecond: number;
  engineeringInputBytesPerSecond: number;
  concurrentUncompressedCopies: number;
  reserveFraction: number;
  requiredUsableBytes: number;
  requiredSustainedWriteBytesPerSecond: number;
  targetPath: string | null;
  volumeIdentity: string | null;
  filesystem: string | null;
  freeBytes: number | null;
  measuredSustainedWriteBytesPerSecond: number | null;
  powerLossProtectionVerified: boolean | null;
  qualificationReceiptHash: string | null;
  qualificationProfileHash: string | null;
  qualificationDurationSeconds: number | null;
  eligibleForProtectedRecording: boolean;
  blockers: string[];
}

export interface Marker {
  id: string;
  label: string;
  note: string;
  hostMonotonicMs: number;
  hardwareGlobalTime: number | null;
  nearestSampleCounter: number | null;
  timestampSource: "host_monotonic" | "hardware_global_time";
  runId: string | null;
  podId: string | null;
}

export interface SystemEvent {
  id: string;
  severity: "info" | "warning" | "error";
  code: string;
  message: string;
  hostMonotonicMs: number;
}

export interface SystemSnapshot {
  backendKind: BackendKind;
  backendLabel: string;
  isSynthetic: boolean;
  machine: MachineState;
  operatorState: OperatorState;
  pods: PodSnapshot[];
  metrics: HealthMetrics;
  recordingPipeline: RecordingPipelineSnapshot;
  storagePreflight: StoragePreflightSnapshot;
  analysisPipeline: AnalysisPipelineSnapshot;
  stimulation: StimulationSafetySnapshot;
  markers: Marker[];
  events: SystemEvent[];
  monitoringSeconds: number;
  recordingSeconds: number;
}

export interface TraceBlock {
  podId: string;
  channelOffset: number;
  channelCount: number;
  pointsPerChannel: number;
  sampleWindowSeconds: number;
  valuesUv: Float32Array[];
  generatedAtMonotonicMs: number;
  synthetic: boolean;
  displayEncoding?: "samples" | "min_max_pairs";
}

export interface BackendOption {
  kind: BackendKind;
  label: string;
  detail: string;
  available: boolean;
  badge: string;
  blockedReason?: string;
}
