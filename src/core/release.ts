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
  const label = path.path === "direct_d3xx" ? "直连" : "Aggregator";
  const blockers: string[] = [];
  if (path.acquisitionDurationSeconds < REQUIRED_RUN_SECONDS) {
    blockers.push(`${label}尚未通过24小时连续采集`);
  }
  if (path.sustainedInputBytesPerSecond < PLANNED_SYSTEM_BYTES_PER_SECOND) {
    blockers.push(`${label}尚未通过126.72 MB/s正常负载`);
  }
  if (path.stressInputBytesPerSecond < STRESS_SYSTEM_BYTES_PER_SECOND) {
    blockers.push(`${label}尚未通过190.08 MB/s压力负载`);
  }
  if (!path.concurrentJournalAndNwbPassed) {
    blockers.push(`${label}尚未通过journal与未压缩NWB并行写入`);
  }
  if (!path.reconciledWithoutUnexplainedGap) {
    blockers.push(`${label}计数器、CRC与NWB尚未完成无未解释缺口对账`);
  }
  return blockers;
}

function evaluateClosedLoopPath(path: PathReleaseEvidence): string[] {
  const label = path.path === "direct_d3xx" ? "直连" : "Aggregator";
  const blockers: string[] = [];
  if (path.stimulusTrials < REQUIRED_STIM_TRIALS_PER_PATH) {
    blockers.push(`${label}dummy-load刺激少于10^6次`);
  }
  if (path.duplicateStimuli !== 0) blockers.push(`${label}存在重复刺激`);
  if (path.executedWithoutReceipt !== 0) blockers.push(`${label}存在无回执执行`);
  if (path.latePhysicalStimuli !== 0) blockers.push(`${label}存在逾期物理刺激`);
  if (path.spikePhysicalLatencyP99Ms === null || path.spikePhysicalLatencyP99Ms > 20) {
    blockers.push(`${label}Spike物理闭环p99未证明≤20 ms`);
  }
  if (path.lfpPhysicalLatencyP99Ms === null || path.lfpPhysicalLatencyP99Ms > 100) {
    blockers.push(`${label}LFP物理闭环p99未证明≤100 ms`);
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
    ["协议契约", evidence.protocolContractHash],
    ["软件build", evidence.softwareBuildHash],
    ["硬件build", evidence.hardwareBuildHash],
    ["存储profile", evidence.storageProfileHash],
  ] as const) {
    if (!presentHash(value)) recordingBlockers.push(`缺少有效${name} hash`);
  }
  if (evidence.guiKillCount < 1_000) recordingBlockers.push("GUI kill测试少于1000次");
  if (evidence.nwbWorkerKillCount < 100) recordingBlockers.push("NWB worker kill测试少于100次");
  if (evidence.algorithmWorkerKillCount < 100) {
    recordingBlockers.push("算法worker kill测试少于100次");
  }
  for (const fault of REQUIRED_INJECTED_FAULTS) {
    if (!evidence.injectedFaultsPassed.includes(fault)) {
      recordingBlockers.push(`故障注入未通过：${fault}`);
    }
  }
  recordingBlockers.push(...evaluateRecordingPath(evidence.direct));
  recordingBlockers.push(...evaluateRecordingPath(evidence.aggregator));
  if (evidence.qualifiedOperators < 5) recordingBlockers.push("目标实验人员可用性验证少于5人");
  if (evidence.stopEqualsSavedMisunderstandings !== 0) {
    recordingBlockers.push("仍有人误解停止采集等于保存完成");
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
