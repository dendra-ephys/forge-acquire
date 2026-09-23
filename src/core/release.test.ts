import { describe, expect, it } from "vitest";
import {
  evaluateReleaseEvidence,
  REQUIRED_INJECTED_FAULTS,
  type PathReleaseEvidence,
  type ReleaseEvidenceV1,
} from "./release";

const hash = "1".repeat(64);

function path(pathName: PathReleaseEvidence["path"]): PathReleaseEvidence {
  return {
    path: pathName,
    acquisitionDurationSeconds: 86_400,
    sustainedInputBytesPerSecond: 126_720_000,
    stressInputBytesPerSecond: 190_080_000,
    concurrentJournalAndNwbPassed: true,
    reconciledWithoutUnexplainedGap: true,
    stimulusTrials: 1_000_000,
    duplicateStimuli: 0,
    executedWithoutReceipt: 0,
    latePhysicalStimuli: 0,
    spikePhysicalLatencyP99Ms: 20,
    lfpPhysicalLatencyP99Ms: 100,
  };
}

function completeEvidence(): ReleaseEvidenceV1 {
  return {
    protocolContractHash: hash,
    softwareBuildHash: hash,
    hardwareBuildHash: hash,
    storageProfileHash: hash,
    guiKillCount: 1_000,
    nwbWorkerKillCount: 100,
    algorithmWorkerKillCount: 100,
    injectedFaultsPassed: REQUIRED_INJECTED_FAULTS,
    direct: path("direct_d3xx"),
    aggregator: path("aggregator_10gbe"),
    qualifiedOperators: 5,
    stopEqualsSavedMisunderstandings: 0,
  };
}

describe("Forge release receipt preflight", () => {
  it("requires both direct and Aggregator recording paths", () => {
    const evidence = completeEvidence();
    evidence.aggregator.acquisitionDurationSeconds = 60;
    const result = evaluateReleaseEvidence(evidence);
    expect(result.recordingReleaseEligible).toBe(false);
    expect(result.recordingBlockers.some((item) => item.includes("Aggregator"))).toBe(true);
  });

  it("keeps closed loop blocked when physical latency or receipt evidence fails", () => {
    const evidence = completeEvidence();
    evidence.direct.executedWithoutReceipt = 1;
    evidence.aggregator.spikePhysicalLatencyP99Ms = 20.01;
    const result = evaluateReleaseEvidence(evidence);
    expect(result.recordingReleaseEligible).toBe(true);
    expect(result.closedLoopReleaseEligible).toBe(false);
    expect(result.closedLoopBlockers).toEqual(expect.arrayContaining([
      expect.stringContaining("without receipts"),
      expect.stringContaining("spike"),
    ]));
  });

  it("passes only the exact approved evidence floor", () => {
    expect(evaluateReleaseEvidence(completeEvidence())).toEqual({
      recordingReleaseEligible: true,
      closedLoopReleaseEligible: true,
      recordingBlockers: [],
      closedLoopBlockers: [],
    });
  });
});
