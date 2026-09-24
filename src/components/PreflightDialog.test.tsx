import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { RecordingTargetReservation } from "../adapters/acquireAdapter";
import type { RunDirectoryListing } from "../adapters/runDirectoryBrowser";
import { PreflightDialog, recordingSelectionProblem } from "./PreflightDialog";
import { RunDirectoryBrowserView } from "./RunDirectoryBrowserView";

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

const DIRECTORY_LISTING: RunDirectoryListing = {
  schema: "forge.run-directory-listing.v1",
  requestId: 1,
  currentDirectory: "F:\\ForgeRuns",
  parentDirectory: "F:\\",
  roots: [{ label: "F:", path: "F:\\" }],
  directories: [{ name: "2026-08-28", path: "F:\\ForgeRuns\\2026-08-28" }],
  truncated: false,
  entryLimit: 128,
  scannedEntries: 1,
  omittedEntries: 0,
  validationScope: "browse_only",
};

describe("PreflightDialog", () => {
  it("keeps recording setup focused on editable inputs and actions", () => {
    const markup = renderToStaticMarkup(
      <PreflightDialog
        open
        running={false}
        passed
        armed={false}
        recordingMode="single"
        adapterScope="mock"
        finalOutputReady
        finalOutputLabel="Simulation only · no file"
        runLabel="FORGE-RUN"
        requestedDirectory="F:\\ForgeRuns"
        plannedDurationHours={24}
        devices={[{
          key: "MOCK-DIRECT-01",
          displayName: "Mock Direct Pod 1",
          deviceId: "MOCK-POD-SN-0001",
          routeLabel: "USB 01",
        }]}
        selectedPodKeys={new Set(["MOCK-DIRECT-01"])}
        recordingTarget={MOCK_TARGET}
        receiptId="MOCK-CMD-000001"
        checks={[{
          id: "recording-target",
          label: "New recording directory",
          status: "pass",
          detail: "Simulation name allocated",
          evidence: MOCK_TARGET.evidenceHash,
        }]}
        directoryBrowserAvailable
        directoryBrowserOpen={false}
        directoryBrowserListing={null}
        directoryBrowserBusy={false}
        directoryBrowserError={null}
        onRunLabelChange={() => undefined}
        onRequestedDirectoryChange={() => undefined}
        onOpenDirectoryBrowser={() => undefined}
        onBrowseDirectory={() => undefined}
        onUseDirectory={() => undefined}
        onCloseDirectoryBrowser={() => undefined}
        onPlannedDurationHoursChange={() => undefined}
        onTogglePod={() => undefined}
        onRunPreflight={() => undefined}
        onRequestArm={() => undefined}
        onCancel={() => undefined}
      />,
    );

    expect(markup).not.toContain("data-preflight-conclusion");
    expect(markup).not.toContain('data-testid="preflight-operator-summary"');
    expect(markup).not.toContain("Technical details");
    expect(markup).not.toContain("Adapter and evidence scope");
    expect(markup).not.toContain("Ready to check recording conditions");
    expect(markup).toContain("Mock Direct Pod 1");
    expect(markup).toContain('id="recording-run-root"');
    expect(markup).toContain("Single-device recording");
    expect(markup).toContain("Arm recording");
  });

  it("disables allocation when final output is unavailable without exposing internal checks", () => {
    const markup = renderToStaticMarkup(
      <PreflightDialog
        open
        running={false}
        passed={false}
        armed={false}
        recordingMode="single"
        adapterScope="software"
        finalOutputReady={false}
        finalOutputLabel="NWB output unavailable"
        runLabel="FORGE-RUN"
        requestedDirectory="F:\\ForgeRuns"
        plannedDurationHours={24}
        devices={[{ key: "MOCK-DIRECT-01", displayName: "Pod 1", deviceId: "POD-1", routeLabel: "USB 01" }]}
        selectedPodKeys={new Set(["MOCK-DIRECT-01"])}
        recordingTarget={null}
        receiptId={null}
        checks={[
          {
            id: "recording-target",
            label: "New recording directory",
            status: "pending",
            detail: "Waiting for creation",
            evidence: "no reservation receipt",
          },
          {
            id: "final-nwb-output",
            label: "Final file · NWB",
            status: "qualification_required",
            detail: "NWB output module is not connected",
            evidence: "PRODUCT_GATE_OPEN",
          },
          {
            id: "daemon-preflight",
            label: "Recording admission snapshot",
            status: "pending",
            detail: "Waiting for adapter report",
            evidence: "snapshot-hash",
          },
        ]}
        directoryBrowserAvailable
        directoryBrowserOpen={false}
        directoryBrowserListing={null}
        directoryBrowserBusy={false}
        directoryBrowserError={null}
        onRunLabelChange={() => undefined}
        onRequestedDirectoryChange={() => undefined}
        onOpenDirectoryBrowser={() => undefined}
        onBrowseDirectory={() => undefined}
        onUseDirectory={() => undefined}
        onCloseDirectoryBrowser={() => undefined}
        onPlannedDurationHoursChange={() => undefined}
        onTogglePod={() => undefined}
        onRunPreflight={() => undefined}
        onRequestArm={() => undefined}
        onCancel={() => undefined}
      />,
    );

    expect(markup).not.toContain("data-preflight-conclusion");
    expect(markup).toContain("Browse…");
    expect(markup).toContain("Browse local folders");
    expect(markup).not.toContain("system folder picker");
    expect(markup).not.toContain("NWB output module is not connected");
    expect(markup).not.toContain("Recording admission snapshot");
    expect(markup).not.toContain("Technical details");
    expect(markup).toMatch(/<button[^>]*disabled=""[^>]*>[^<]*(?:<svg[\s\S]*?<\/svg>)?[^<]*Check &amp; allocate target/);
  });

  it("reuses the recording dialog as a bounded Run directory browser view", () => {
    const markup = renderToStaticMarkup(
      <PreflightDialog
        open
        running={false}
        passed={false}
        armed={false}
        recordingMode="single"
        adapterScope="software"
        finalOutputReady
        finalOutputLabel="NWB 2.x · CREATE NEW"
        runLabel="FORGE-RUN"
        requestedDirectory="F:\\ForgeRuns"
        plannedDurationHours={24}
        devices={[{ key: "MOCK-DIRECT-01", displayName: "Pod 1", deviceId: "POD-1", routeLabel: "USB 01" }]}
        selectedPodKeys={new Set(["MOCK-DIRECT-01"])}
        recordingTarget={null}
        receiptId={null}
        checks={[]}
        directoryBrowserAvailable
        directoryBrowserOpen
        directoryBrowserListing={DIRECTORY_LISTING}
        directoryBrowserBusy={false}
        directoryBrowserError={null}
        onRunLabelChange={() => undefined}
        onRequestedDirectoryChange={() => undefined}
        onOpenDirectoryBrowser={() => undefined}
        onBrowseDirectory={() => undefined}
        onUseDirectory={() => undefined}
        onCloseDirectoryBrowser={() => undefined}
        onPlannedDurationHoursChange={() => undefined}
        onTogglePod={() => undefined}
        onRunPreflight={() => undefined}
        onRequestArm={() => undefined}
        onCancel={() => undefined}
      />,
    );

    const browserMarkup = renderToStaticMarkup(
      <RunDirectoryBrowserView
        initialDirectory="F:\\ForgeRuns"
        listing={DIRECTORY_LISTING}
        loading={false}
        errorMessage={null}
        onBrowse={() => undefined}
        onUseCurrent={() => undefined}
        onCancel={() => undefined}
      />,
    );

    expect(markup).toContain("Choose Run root");
    expect(markup).not.toContain("Recording readiness summary");
    expect(markup).not.toContain("Check &amp; allocate target");
    expect(markup).not.toContain("Explorer");
    expect(browserMarkup).toContain('data-testid="run-directory-browser"');
    expect(browserMarkup).toContain('data-picker-state="ready"');
    expect(browserMarkup).toContain("F:\\ForgeRuns\\2026-08-28");
    expect(browserMarkup).toContain("Use current folder");
    expect(browserMarkup).toContain("Back to setup");
  });

  it("requires exactly one Pod for single-device setup and 2–8 explicit Pods for multi-device setup", () => {
    expect(recordingSelectionProblem("single", 0)).toContain("exactly one");
    expect(recordingSelectionProblem("single", 1)).toBeNull();
    expect(recordingSelectionProblem("single", 2)).toContain("exactly one");
    expect(recordingSelectionProblem("multi", 0)).toContain("at least 2");
    expect(recordingSelectionProblem("multi", 1)).toContain("at least 2");
    expect(recordingSelectionProblem("multi", 2)).toBeNull();
    expect(recordingSelectionProblem("multi", 8)).toBeNull();
    expect(recordingSelectionProblem("multi", 9)).toContain("at most 8");
  });
});
