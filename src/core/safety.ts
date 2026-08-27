import type {
  AnalysisPipelineSnapshot,
  MachineState,
  StimulationSafetySnapshot,
} from "./types";
import {
  headstageProfile,
  isNewRunCatalogEligible,
  type HeadstageProfile,
} from "./hardwareProfiles";

export type StimArmBlockCode =
  | "STIMULATION_UNAVAILABLE"
  | "RUN_NOT_STREAMING"
  | "RUN_INTEGRITY_NOT_CLEAN"
  | "SYNC_NOT_READY"
  | "HEADSTAGE_PROFILE_NOT_STIM_ADMITTED"
  | "RHS_CAPABILITY_MISSING"
  | "CAPABILITY_HASH_MISSING"
  | "SAFETY_PROFILE_UNAPPROVED"
  | "TEMPLATE_HASH_MISSING"
  | "ALGORITHM_HASH_MISSING"
  | "CONFIG_HASH_MISSING"
  | "CHANNEL_MAP_HASH_MISSING"
  | "WORKER_BUILD_HASH_MISSING"
  | "FROZEN_CONTEXT_RECEIPT_MISSING"
  | "CONTROL_TOKEN_MISSING"
  | "PHYSICAL_ENABLE_OPEN"
  | "EMERGENCY_STOP_UNHEALTHY"
  | "WATCHDOG_UNHEALTHY"
  | "COMPLIANCE_UNHEALTHY"
  | "HARDWARE_CLOCK_UNLOCKED"
  | "DEADLINE_BUDGET_MISSING"
  | "RELEASE_QUALIFICATION_MISSING";

export interface StimArmBlocker {
  code: StimArmBlockCode;
  message: string;
}

export interface StimArmEvaluation {
  eligibleToRequest: boolean;
  blockers: StimArmBlocker[];
}

/**
 * Host-v1 request-shape predicate only. It deliberately remains stricter than
 * an RHS-shaped catalog identity and does not replace hardware Arm receipts.
 */
export function isHostV1StimProfileEligible(profile: Pick<HeadstageProfile,
  "id" | "hostStimCapabilityV1" | "stimulationChannelCount" | "graphClosed" | "catalogStatus"
>): boolean {
  return isNewRunCatalogEligible(profile.id)
    && profile.graphClosed
    && profile.hostStimCapabilityV1
    && profile.stimulationChannelCount === 16;
}

/**
 * Control-plane preflight only. A true result permits sending an Arm request;
 * it never means the hardware is armed. The Rust SafetyArbiter and headstage
 * must independently revalidate the same contract and return an Arm receipt.
 */
export function evaluateStimArmRequest(
  machine: MachineState,
  analysis: AnalysisPipelineSnapshot,
  stimulation: StimulationSafetySnapshot,
): StimArmEvaluation {
  const blockers: StimArmBlocker[] = [];
  const add = (condition: boolean, code: StimArmBlockCode, message: string) => {
    if (condition) blockers.push({ code, message });
  };

  add(
    stimulation.state !== "disarmed",
    "STIMULATION_UNAVAILABLE",
    "SafetyArbiter 尚未报告可请求 Arm 的 disarmed 状态",
  );
  add(machine.acquisition !== "streaming", "RUN_NOT_STREAMING", "采集尚未处于有效 streaming Run");
  add(machine.integrity !== "clean", "RUN_INTEGRITY_NOT_CLEAN", "当前 Run 完整性不是 clean");
  add(["waiting", "lost"].includes(machine.sync), "SYNC_NOT_READY", "硬件同步正在等待或已丢失");
  const stimProfile = stimulation.headstageProfileId === null
    ? null
    : headstageProfile(stimulation.headstageProfileId);
  add(
    stimProfile === null || !isHostV1StimProfileEligible(stimProfile),
    "HEADSTAGE_PROFILE_NOT_STIM_ADMITTED",
    "Headstage 电气图未闭合或目录身份未获得 Host v1 的 16 通道刺激请求能力",
  );
  add(stimulation.rhsChannelCount !== 16, "RHS_CAPABILITY_MISSING", "设备未证明 RHS2116 16 通道能力");
  add(stimulation.capabilityHash === null, "CAPABILITY_HASH_MISSING", "缺少能力描述 hash");
  add(
    stimulation.safetyProfileHash === null || stimulation.safetyProfileApprovalId === null,
    "SAFETY_PROFILE_UNAPPROVED",
    "缺少获批 Safety Profile hash/approval",
  );
  add(stimulation.templateSetHash === null, "TEMPLATE_HASH_MISSING", "未冻结刺激模板集合 hash");
  add(stimulation.algorithmBuildHash === null, "ALGORITHM_HASH_MISSING", "未冻结算法 build/config hash");
  add(stimulation.algorithmConfigHash === null, "CONFIG_HASH_MISSING", "未冻结算法 config hash");
  add(stimulation.channelMapHash === null, "CHANNEL_MAP_HASH_MISSING", "未冻结通道映射 hash");
  add(
    stimulation.controllerWorkerBuildHash === null,
    "WORKER_BUILD_HASH_MISSING",
    "未冻结控制 worker build hash",
  );
  add(
    stimulation.frozenContextReceiptHash === null,
    "FROZEN_CONTEXT_RECEIPT_MISSING",
    "缺少相互绑定的 frozen-context 收据",
  );
  add(analysis.controllerTokenOwner === "none", "CONTROL_TOKEN_MISSING", "没有唯一闭环控制令牌");
  add(stimulation.physicalEnable !== "closed", "PHYSICAL_ENABLE_OPEN", "实体 ENABLE 未闭合");
  add(stimulation.emergencyStopHealthy !== true, "EMERGENCY_STOP_UNHEALTHY", "急停回路未证明健康");
  add(stimulation.watchdogHealthy !== true, "WATCHDOG_UNHEALTHY", "独立看门狗未证明健康");
  add(stimulation.complianceHealthy !== true, "COMPLIANCE_UNHEALTHY", "compliance 预检未通过");
  add(stimulation.hardwareClockLocked !== true, "HARDWARE_CLOCK_UNLOCKED", "硬件时钟未证明锁定");
  add(
    stimulation.deadlineBudgetMs === null || stimulation.deadlineBudgetMs <= 0,
    "DEADLINE_BUDGET_MISSING",
    "没有有效的硬件时基 deadline 预算",
  );
  add(
    !stimulation.closedLoopReleaseQualified || stimulation.qualificationReceiptHash === null,
    "RELEASE_QUALIFICATION_MISSING",
    "直连/Aggregator HIL 与 10⁶ 次 dummy-load 发布收据尚未齐备",
  );

  return { eligibleToRequest: blockers.length === 0, blockers };
}
