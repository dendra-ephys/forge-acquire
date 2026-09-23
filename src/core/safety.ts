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
    "SafetyArbiter has not reported a disarmed state eligible for an Arm request",
  );
  add(machine.acquisition !== "streaming", "RUN_NOT_STREAMING", "Acquisition is not in a valid streaming Run");
  add(machine.integrity !== "clean", "RUN_INTEGRITY_NOT_CLEAN", "Current Run integrity is not clean");
  add(["waiting", "lost"].includes(machine.sync), "SYNC_NOT_READY", "Hardware synchronization is waiting or lost");
  const stimProfile = stimulation.headstageProfileId === null
    ? null
    : headstageProfile(stimulation.headstageProfileId);
  add(
    stimProfile === null || !isHostV1StimProfileEligible(stimProfile),
    "HEADSTAGE_PROFILE_NOT_STIM_ADMITTED",
    "The Headstage schematic is incomplete or its catalog identity lacks Host v1 16-channel stimulation-request capability",
  );
  add(stimulation.rhsChannelCount !== 16, "RHS_CAPABILITY_MISSING", "The device has not proven RHS2116 16-channel capability");
  add(stimulation.capabilityHash === null, "CAPABILITY_HASH_MISSING", "Capability descriptor hash is missing");
  add(
    stimulation.safetyProfileHash === null || stimulation.safetyProfileApprovalId === null,
    "SAFETY_PROFILE_UNAPPROVED",
    "Approved Safety Profile hash or approval is missing",
  );
  add(stimulation.templateSetHash === null, "TEMPLATE_HASH_MISSING", "Stimulation template-set hash is not frozen");
  add(stimulation.algorithmBuildHash === null, "ALGORITHM_HASH_MISSING", "Algorithm build hash is not frozen");
  add(stimulation.algorithmConfigHash === null, "CONFIG_HASH_MISSING", "Algorithm config hash is not frozen");
  add(stimulation.channelMapHash === null, "CHANNEL_MAP_HASH_MISSING", "Channel-map hash is not frozen");
  add(
    stimulation.controllerWorkerBuildHash === null,
    "WORKER_BUILD_HASH_MISSING",
    "Control-worker build hash is not frozen",
  );
  add(
    stimulation.frozenContextReceiptHash === null,
    "FROZEN_CONTEXT_RECEIPT_MISSING",
    "Mutually bound frozen-context receipts are missing",
  );
  add(analysis.controllerTokenOwner === "none", "CONTROL_TOKEN_MISSING", "There is no unique closed-loop control token");
  add(stimulation.physicalEnable !== "closed", "PHYSICAL_ENABLE_OPEN", "Physical ENABLE is open");
  add(stimulation.emergencyStopHealthy !== true, "EMERGENCY_STOP_UNHEALTHY", "Emergency-stop circuit health is unproven");
  add(stimulation.watchdogHealthy !== true, "WATCHDOG_UNHEALTHY", "Independent watchdog health is unproven");
  add(stimulation.complianceHealthy !== true, "COMPLIANCE_UNHEALTHY", "Compliance preflight has not passed");
  add(stimulation.hardwareClockLocked !== true, "HARDWARE_CLOCK_UNLOCKED", "Hardware clock lock is unproven");
  add(
    stimulation.deadlineBudgetMs === null || stimulation.deadlineBudgetMs <= 0,
    "DEADLINE_BUDGET_MISSING",
    "There is no valid hardware-timebase deadline budget",
  );
  add(
    !stimulation.closedLoopReleaseQualified || stimulation.qualificationReceiptHash === null,
    "RELEASE_QUALIFICATION_MISSING",
    "Direct and Aggregator HIL plus 10^6 dummy-load release receipts are incomplete",
  );

  return { eligibleToRequest: blockers.length === 0, blockers };
}
