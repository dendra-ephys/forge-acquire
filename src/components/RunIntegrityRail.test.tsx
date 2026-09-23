import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type {
  AdapterScope,
  EvidenceSlot,
  EvidenceSlotId,
  EvidenceStatus,
  NwbArtifactReceipt,
  RunIntegrityEvidence,
  RunReceipt,
} from "../adapters/acquireAdapter";
import { deriveRunOutput } from "../core/runOutputState";
import { RunIntegrityRail } from "./RunIntegrityRail";

function slot(
  id: EvidenceSlotId,
  status: EvidenceStatus,
  scope: AdapterScope = "software",
  summary = `${id} summary`,
): EvidenceSlot {
  return {
    id,
    status,
    scope,
    summary,
    watermark: status === "proven" ? 42n : null,
    receiptSequence: status === "proven" ? 7n : null,
    evidenceHash: status === "proven" ? "a".repeat(64) : null,
    updatedAtMonotonicMs: 100,
  };
}

function evidence(
  scope: AdapterScope = "software",
  nwbStatus: EvidenceStatus = "unavailable",
): RunIntegrityEvidence {
  return {
    acquisition: slot("acquisition", "proven", scope),
    durability: slot("durability", "proven", scope),
    nwb: slot("nwb", nwbStatus, scope),
    analysis: slot("analysis", "unavailable", scope),
    stimReceipt: slot("stim_receipt", "unavailable", scope),
  };
}

const VALID_NWB: NwbArtifactReceipt = {
  artifactKind: "nwb",
  filePath: "F:\\ForgeRuns\\FORGE-RUN-001\\FORGE-RUN-001.nwb",
  createDisposition: "created_new",
  schemaValidated: true,
  inspectorPassed: true,
  publicationCommitted: true,
  publicationReceiptId: "NWB-PUBLISH-000001",
  evidenceHash: "c".repeat(64),
};

function receipt(
  status: RunReceipt["status"],
  runEvidence: RunIntegrityEvidence,
  nwbArtifact: NwbArtifactReceipt | null = null,
  scope: AdapterScope = "software",
): RunReceipt {
  const created = scope === "mock" ? "simulated" : "created_new";
  return {
    receiptKind: "run",
    scope,
    synthetic: scope !== "hardware",
    runId: "RUN-0001",
    runEpoch: 1n,
    status,
    lifecycle: status === "active" ? "recording" : "finalized",
    receiptSequence: 9n,
    generatedAtMonotonicMs: 100,
    evidence: runEvidence,
    recordingTarget: {
      reservationId: "TARGET-0001",
      requestedDirectory: "F:\\ForgeRuns",
      allocatedLeafName: "FORGE-RUN-001",
      resolvedRunDirectory: "F:\\ForgeRuns\\FORGE-RUN-001",
      allocationSequence: 1n,
      journalFileName: "run.forgewal",
      directoryCreateDisposition: created,
      journalCreateDisposition: created,
      overwritePolicy: "forbid",
      scope,
      synthetic: scope !== "hardware",
      reasonCode: "TEST",
      evidenceHash: "b".repeat(64),
    },
    nwbArtifact,
    faults: [],
    evidenceHash: "d".repeat(64),
  };
}

describe("RunIntegrityRail", () => {
  it("shows one quiet result before recording and removes the five-slot technical model", () => {
    const idle = evidence("mock");
    idle.acquisition = slot("acquisition", "idle", "mock");
    idle.durability = slot("durability", "idle", "mock");
    const markup = renderToStaticMarkup(
      <RunIntegrityRail lifecycle="connected_idle" evidence={idle} runReceipt={null} scope="mock" />,
    );

    expect(markup.match(/data-run-result-state=/g)).toHaveLength(1);
    expect(markup).toContain('data-run-result-state="idle"');
    expect(markup).toContain("Not recorded");
    expect(markup).not.toMatch(/data-operator-slot|data-integrity-slot|data-evidence-group/);
    expect(markup).not.toMatch(/TECHNICAL DETAILS|DATA CONTINUITY|FILE SAVE|EXTERNAL EVENTS|seq /);
  });

  it("moves storage into the Run result tooltip and flags less than 20 GB", () => {
    const idle = evidence("mock");
    const lowMarkup = renderToStaticMarkup(
      <RunIntegrityRail
        lifecycle="connected_idle"
        evidence={idle}
        runReceipt={null}
        scope="mock"
        recordingFileSize="1.25 GB"
        storageFree="19.9 GB"
        storageFreeBytes={19_900_000_000}
      />,
    );
    const thresholdMarkup = renderToStaticMarkup(
      <RunIntegrityRail
        lifecycle="connected_idle"
        evidence={idle}
        runReceipt={null}
        scope="mock"
        recordingFileSize="1.25 GB"
        storageFree="20.0 GB"
        storageFreeBytes={20_000_000_000}
      />,
    );

    expect(lowMarkup).toContain("File size: 1.25 GB");
    expect(lowMarkup).toContain("Storage free: 19.9 GB");
    expect(lowMarkup).toContain('data-storage-low="true"');
    expect(thresholdMarkup).toContain('data-storage-low="false"');
  });

  it("shows recording as a single live state", () => {
    const active = evidence("mock");
    active.acquisition = slot("acquisition", "active", "mock");
    active.durability = slot("durability", "active", "mock");
    const markup = renderToStaticMarkup(
      <RunIntegrityRail lifecycle="recording" evidence={active} runReceipt={null} scope="mock" />,
    );

    expect(markup).toContain('data-run-result-state="recording"');
    expect(markup).toContain("Recording");
    expect(markup).toContain("Synthetic data stream");
    expect(markup.match(/data-run-result-state=/g)).toHaveLength(1);
  });

  it("does not mistake an active preflight receipt for an active writer", () => {
    const planned = evidence("mock");
    const result = deriveRunOutput(
      "preflight_passed",
      planned,
      receipt("active", planned, null, "mock"),
      "mock",
    );

    expect(result.state).toBe("idle");
    expect(result.label).toBe("Not recorded");
  });

  it("does not call an accepted Start request Recording before the snapshot confirms it", () => {
    const pending = evidence("mock");
    const result = deriveRunOutput(
      "start_requested",
      pending,
      receipt("active", pending, null, "mock"),
      "mock",
    );

    expect(result.state).toBe("recording");
    expect(result.label).toBe("Starting recording");
    expect(result.label).not.toBe("Recording");
  });

  it("turns a sample gap into the only urgent Run result", () => {
    const failed = evidence();
    failed.acquisition = slot(
      "acquisition",
      "failed",
      "software",
      "sample 9000–12000 was not processed; this Run is invalid.",
    );
    const markup = renderToStaticMarkup(
      <RunIntegrityRail lifecycle="recovery_required" evidence={failed} runReceipt={null} scope="software" />,
    );

    expect(markup).toContain('role="alert"');
    expect(markup).toContain('data-run-result-state="failed"');
    expect(markup).toContain("Recording failed · recovery required");
    expect(markup).toContain("sample 9000–12000 was not processed; this Run is invalid.");
    expect(markup).not.toContain("saved");
  });

  it("keeps stop and NWB generation pending until the final receipt arrives", () => {
    const runEvidence = evidence();
    expect(deriveRunOutput(
      "recording_stopped",
      runEvidence,
      receipt("stopped_not_durable", runEvidence),
      "software",
    )).toMatchObject({
      state: "saving",
      label: "Ending and generating NWB",
    });
  });

  it("ends Browser mock as simulation only and never calls it saved", () => {
    const runEvidence = evidence("mock", "qualification_required");
    const result = deriveRunOutput(
      "finalized",
      runEvidence,
      receipt("finalized", runEvidence, null, "mock"),
      "mock",
    );

    expect(result).toMatchObject({ state: "mock_complete", label: "Simulation complete" });
    expect(result.detail).toContain("No recording file");
    expect(result.detail).toContain("NWB was created");
    expect(result.label).not.toContain("saved");
  });

  it("reports a sealed software journal as raw retained, not as a final file", () => {
    const runEvidence = evidence("software", "unavailable");
    const result = deriveRunOutput(
      "finalized",
      runEvidence,
      receipt("raw_sealed", runEvidence),
      "software",
    );

    expect(result).toMatchObject({
      state: "raw_retained",
      label: "Raw data retained · NWB incomplete",
      phaseLabel: "NWB INCOMPLETE",
    });
    expect(result.detail).toContain("sealed raw journal");
    expect(result.label).not.toContain("saved");
  });

  it("requires a real validated create-new NWB artifact receipt before saved", () => {
    const runEvidence = evidence("software", "proven");
    const withoutArtifact = deriveRunOutput(
      "finalized",
      runEvidence,
      receipt("finalized", runEvidence),
      "software",
    );
    const withArtifact = deriveRunOutput(
      "finalized",
      runEvidence,
      receipt("finalized", runEvidence, VALID_NWB),
      "software",
    );

    expect(withoutArtifact.state).toBe("raw_retained");
    expect(withArtifact).toMatchObject({
      state: "nwb_saved",
      label: "NWB saved",
      phaseLabel: "NWB SAVED",
    });
    expect(withArtifact.detail).toContain("FORGE-RUN-001.nwb");
  });

  it("does not let Analysis or external-event fields change the Run result", () => {
    const first = evidence("software", "unavailable");
    const second = evidence("software", "unavailable");
    second.analysis = slot("analysis", "proven");
    second.stimReceipt = slot("stim_receipt", "proven");

    const firstResult = deriveRunOutput("finalized", first, receipt("raw_sealed", first), "software");
    const secondResult = deriveRunOutput("finalized", second, receipt("raw_sealed", second), "software");
    expect(secondResult).toEqual(firstResult);

    const markup = renderToStaticMarkup(
      <RunIntegrityRail
        lifecycle="finalized"
        evidence={second}
        runReceipt={receipt("raw_sealed", second)}
        scope="software"
      />,
    );
    expect(markup).not.toMatch(/Analysis|External events|Stim Receipt/);
  });
});
