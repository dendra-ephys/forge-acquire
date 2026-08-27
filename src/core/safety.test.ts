import { describe, expect, it } from "vitest";
import { initialMachineState } from "./machine";
import { evaluateStimArmRequest, isHostV1StimProfileEligible } from "./safety";
import { headstageProfile } from "./hardwareProfiles";
import type { AnalysisPipelineSnapshot, StimulationSafetySnapshot } from "./types";

const controller: AnalysisPipelineSnapshot = {
  cppWorker: "controller",
  pythonWorker: "observing",
  controllerTokenOwner: "cpp",
  referenceAlgorithmsOnly: false,
  processedSequence: 10,
  droppedBlocks: 0,
  lastError: null,
};

const qualifiedStim: StimulationSafetySnapshot = {
  state: "disarmed",
  headstageProfileId: "rhs2116x1",
  rhsChannelCount: 16,
  capabilityHash: "cap",
  safetyProfileHash: "profile",
  safetyProfileApprovalId: "approval",
  templateSetHash: "templates",
  algorithmBuildHash: "algorithm",
  algorithmConfigHash: "config",
  channelMapHash: "channel-map",
  controllerWorkerBuildHash: "worker-build",
  physicalEnable: "closed",
  emergencyStopHealthy: true,
  watchdogHealthy: true,
  complianceHealthy: true,
  hardwareClockLocked: true,
  frozenContextReceiptHash: "frozen-context",
  closedLoopReleaseQualified: true,
  qualificationReceiptHash: "qualification",
  armEpoch: null,
  deadlineBudgetMs: 20,
  lastIntentSequence: null,
  lastReceiptSequence: null,
  receiptGapCount: 0,
  duplicateReceiptCount: 0,
  unavailableReasons: [],
};

const streamingMachine = {
  ...initialMachineState,
  transport: "open" as const,
  acquisition: "streaming" as const,
  sync: "standalone" as const,
};

describe("stimulation Arm control-plane preflight", () => {
  it("only permits an Arm request when every evidence field is present", () => {
    expect(evaluateStimArmRequest(streamingMachine, controller, qualifiedStim)).toEqual({
      eligibleToRequest: true,
      blockers: [],
    });
  });

  it("fails closed when release evidence and physical interlocks are absent", () => {
    const result = evaluateStimArmRequest(
      streamingMachine,
      { ...controller, controllerTokenOwner: "none" },
      {
        ...qualifiedStim,
        state: "unavailable",
        physicalEnable: "unknown",
        safetyProfileApprovalId: null,
        emergencyStopHealthy: null,
        watchdogHealthy: null,
        complianceHealthy: null,
        closedLoopReleaseQualified: false,
        qualificationReceiptHash: null,
      },
    );
    expect(result.eligibleToRequest).toBe(false);
    expect(result.blockers.map(({ code }) => code)).toEqual(expect.arrayContaining([
      "STIMULATION_UNAVAILABLE",
      "SAFETY_PROFILE_UNAPPROVED",
      "CONTROL_TOKEN_MISSING",
      "PHYSICAL_ENABLE_OPEN",
      "RELEASE_QUALIFICATION_MISSING",
    ]));
  });

  it("does not confuse a button-eligible request with an armed state", () => {
    const result = evaluateStimArmRequest(streamingMachine, controller, qualifiedStim);
    expect(result.eligibleToRequest).toBe(true);
    expect(qualifiedStim.state).toBe("disarmed");
    expect(qualifiedStim.armEpoch).toBeNull();
  });

  it("does not derive stimulation authority from a physical RHS channel shape", () => {
    for (const headstageProfileId of [
      "rhs2116x2",
      "rhs2116x2_imu",
      "rhs2116x1_echem",
      "rhd2132x1_rhs2116x1",
      "rhd2164x1_rhs2116x1",
    ] as const) {
      const result = evaluateStimArmRequest(
        streamingMachine,
        controller,
        { ...qualifiedStim, headstageProfileId },
      );
      expect(result.eligibleToRequest).toBe(false);
      expect(result.blockers.map(({ code }) => code)).toContain(
        "HEADSTAGE_PROFILE_NOT_STIM_ADMITTED",
      );
    }
  });

  it("never grants a future RHS-shaped profile with an open electrical graph", () => {
    const futureOpenGraphRhs = {
      ...headstageProfile("rhs2116x1"),
      graphClosed: false,
    } as const;
    expect(futureOpenGraphRhs.hostStimCapabilityV1).toBe(true);
    expect(isHostV1StimProfileEligible(futureOpenGraphRhs)).toBe(false);
  });
});
