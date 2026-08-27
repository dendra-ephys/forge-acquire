import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { RecordingTargetReservation } from "../adapters/acquireAdapter";
import { PreflightDialog, recordingSelectionProblem } from "./PreflightDialog";

const MOCK_TARGET: RecordingTargetReservation = {
  reservationId: "MOCK-TARGET-000001",
  requestedDirectory: "F:\\ForgeRuns",
  allocatedLeafName: "FORGE-RUN-001",
  resolvedRunDirectory: "F:\\ForgeRuns\\FORGE-RUN-001",
  allocationSequence: 1n,
  journalFileName: "run.forgewal",
  directoryCreateDisposition: "simulated",
  journalCreateDisposition: "simulated",
  overwritePolicy: "forbid",
  scope: "mock",
  synthetic: true,
  reasonCode: "MOCK_SESSION_RESERVATION",
  evidenceHash: "b".repeat(64),
};

describe("PreflightDialog", () => {
  it("keeps Recording Arm distinct from stimulation and describes mock target allocation honestly", () => {
    const markup = renderToStaticMarkup(
      <PreflightDialog
        open
        running={false}
        passed
        armed={false}
        recordingMode="single"
        adapterScope="mock"
        runLabel="FORGE-RUN"
        requestedDirectory="F:\\ForgeRuns"
        plannedDurationHours={24}
        devices={[]}
        selectedPodKeys={new Set(["MOCK-DIRECT-01"])}
        recordingTarget={MOCK_TARGET}
        receiptId="MOCK-CMD-000001"
        checks={[]}
        onRunLabelChange={() => undefined}
        onRequestedDirectoryChange={() => undefined}
        onPlannedDurationHoursChange={() => undefined}
        onTogglePod={() => undefined}
        onRunPreflight={() => undefined}
        onRequestArm={() => undefined}
        onCancel={() => undefined}
      />,
    );

    expect(markup).toContain("MOCK NAME ALLOCATED · NO FILE CREATED");
    expect(markup).toContain("单设备记录设置");
    expect(markup).toContain("directory=simulated");
    expect(markup).toContain("Recording Arm 只是 writer 写入互锁，不是刺激授权");
    expect(markup).toContain("准备开始记录");
    expect(markup).not.toContain("Stimulation Arm");
  });

  it("requires exactly one Pod for single-device setup and 2–8 explicit Pods for multi-device setup", () => {
    expect(recordingSelectionProblem("single", 0)).toContain("1 个");
    expect(recordingSelectionProblem("single", 1)).toBeNull();
    expect(recordingSelectionProblem("single", 2)).toContain("1 个");
    expect(recordingSelectionProblem("multi", 0)).toContain("至少 2 个");
    expect(recordingSelectionProblem("multi", 1)).toContain("至少 2 个");
    expect(recordingSelectionProblem("multi", 2)).toBeNull();
    expect(recordingSelectionProblem("multi", 8)).toBeNull();
    expect(recordingSelectionProblem("multi", 9)).toContain("最多记录 8 个");
  });
});
