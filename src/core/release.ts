export const PLANNED_SYSTEM_BYTES_PER_SECOND = 126_720_000;
export const STRESS_SYSTEM_BYTES_PER_SECOND = 190_080_000;
export const REQUIRED_RUN_SECONDS = 24 * 60 * 60;
export const REQUIRED_STIM_TRIALS_PER_PATH = 1_000_000;

export type QualifiedPath = "direct_d3xx" | "aggregator_10gbe";

export interface PathReleaseEvidence {
  path: QualifiedPath;
  acquisitionDurationSeconds: number;
  sustainedInputBytesPerSecond: number;
  stressInputBytesPerSecond: number;
  concurrentJournalAndNwbPassed: boolean;
  reconciledWithoutUnexplainedGap: boolean;
  stimulusTrials: number;
  duplicateStimuli: number;
  executedWithoutReceipt: number;
  latePhysicalStimuli: number;
  spikePhysicalLatencyP99Ms: number | null;
  lfpPhysicalLatencyP99Ms: number | null;
}

export type InjectedFault =
  | "daemon_header_cut"
  | "daemon_payload_cut"
  | "daemon_footer_cut"
  | "daemon_barrier_cut"
  | "short_write"
  | "io_stall"
  | "enospc"
  | "permission_error"
  | "crc_corruption"
  | "rename_failure"
  | "usb_disconnect"
  | "ethernet_disconnect"
  | "clock_loss";

export const REQUIRED_INJECTED_FAULTS: readonly InjectedFault[] = [
  "daemon_header_cut",
  "daemon_payload_cut",
  "daemon_footer_cut",
  "daemon_barrier_cut",
  "short_write",
  "io_stall",
  "enospc",
  "permission_error",
  "crc_corruption",
  "rename_failure",
  "usb_disconnect",
  "ethernet_disconnect",
  "clock_loss",
] as const;

export interface ReleaseEvidenceV1 {
  protocolContractHash: string | null;
  softwareBuildHash: string | null;
  hardwareBuildHash: string | null;
  storageProfileHash: string | null;
  guiKillCount: number;
  nwbWorkerKillCount: number;
  algorithmWorkerKillCount: number;
  injectedFaultsPassed: readonly InjectedFault[];
  direct: PathReleaseEvidence;
  aggregator: PathReleaseEvidence;
  qualifiedOperators: number;
  stopEqualsSavedMisunderstandings: number;
}

export interface ReleaseEvaluationV1 {
  recordingReleaseEligible: boolean;
  closedLoopReleaseEligible: boolean;
  recordingBlockers: string[];
  closedLoopBlockers: string[];
}

function presentHash(value: string | null): boolean {
  return value !== null && /^[0-9a-f]{64}$/.test(value) && !/^0+$/.test(value);
}

function evaluateRecordingPath(path: PathReleaseEvidence): string[] {
  const label = path.path === "direct_d3xx" ? "Direct" : "Aggregator";
  const blockers: string[] = [];
  if (path.acquisitionDurationSeconds < REQUIRED_RUN_SECONDS) {
    blockers.push(`${label} path has not passed 24-hour continuous acquisition`);
  }
  if (path.sustainedInputBytesPerSecond < PLANNED_SYSTEM_BYTES_PER_SECOND) {
    blockers.push(`${label} path has not passed the 126.72 MB/s nominal load`);
  }
  if (path.stressInputBytesPerSecond < STRESS_SYSTEM_BYTES_PER_SECOND) {
    blockers.push(`${label} path has not passed the 190.08 MB/s stress load`);
  }
  if (!path.concurrentJournalAndNwbPassed) {
    blockers.push(`${label} path has not passed concurrent journal and uncompressed NWB writing`);
  }
  if (!path.reconciledWithoutUnexplainedGap) {
    blockers.push(`${label} counters, CRC, and NWB have not reconciled without unexplained gaps`);
  }
  return blockers;
}

function evaluateClosedLoopPath(path: PathReleaseEvidence): string[] {
  const label = path.path === "direct_d3xx" ? "Direct" : "Aggregator";
  const blockers: string[] = [];
  if (path.stimulusTrials < REQUIRED_STIM_TRIALS_PER_PATH) {
    blockers.push(`${label} dummy-load stimulation count is below 10^6`);
  }
  if (path.duplicateStimuli !== 0) blockers.push(`${label} path has duplicate stimuli`);
  if (path.executedWithoutReceipt !== 0) blockers.push(`${label} path has executions without receipts`);
  if (path.latePhysicalStimuli !== 0) blockers.push(`${label} path has late physical stimuli`);
  if (path.spikePhysicalLatencyP99Ms === null || path.spikePhysicalLatencyP99Ms > 20) {
    blockers.push(`${label} physical spike closed-loop p99 ≤20 ms is unproven`);
  }
  if (path.lfpPhysicalLatencyP99Ms === null || path.lfpPhysicalLatencyP99Ms > 100) {
    blockers.push(`${label} physical LFP closed-loop p99 ≤100 ms is unproven`);
  }
  return blockers;
}

/**
 * Receipt preflight only. A passing value authorizes the independent release
 * service to construct and sign a receipt; it is never itself a receipt.
 */
export function evaluateReleaseEvidence(evidence: ReleaseEvidenceV1): ReleaseEvaluationV1 {
  const recordingBlockers: string[] = [];
  for (const [name, value] of [
    ["protocol contract", evidence.protocolContractHash],
    ["software build", evidence.softwareBuildHash],
    ["hardware build", evidence.hardwareBuildHash],
    ["storage profile", evidence.storageProfileHash],
  ] as const) {
    if (!presentHash(value)) recordingBlockers.push(`Valid ${name} hash is missing`);
  }
  if (evidence.guiKillCount < 1_000) recordingBlockers.push("GUI kill test count is below 1,000");
  if (evidence.nwbWorkerKillCount < 100) recordingBlockers.push("NWB worker kill test count is below 100");
  if (evidence.algorithmWorkerKillCount < 100) {
    recordingBlockers.push("Algorithm-worker kill test count is below 100");
  }
  for (const fault of REQUIRED_INJECTED_FAULTS) {
    if (!evidence.injectedFaultsPassed.includes(fault)) {
      recordingBlockers.push(`Fault injection did not pass: ${fault}`);
    }
  }
  recordingBlockers.push(...evaluateRecordingPath(evidence.direct));
  recordingBlockers.push(...evaluateRecordingPath(evidence.aggregator));
  if (evidence.qualifiedOperators < 5) recordingBlockers.push("Fewer than 5 target operators completed usability qualification");
  if (evidence.stopEqualsSavedMisunderstandings !== 0) {
    recordingBlockers.push("An operator still confuses stopping acquisition with save completion");
  }

  const closedLoopBlockers = [
    ...recordingBlockers,
    ...evaluateClosedLoopPath(evidence.direct),
    ...evaluateClosedLoopPath(evidence.aggregator),
  ];
  return {
    recordingReleaseEligible: recordingBlockers.length === 0,
    closedLoopReleaseEligible: closedLoopBlockers.length === 0,
    recordingBlockers,
    closedLoopBlockers,
  };
}
