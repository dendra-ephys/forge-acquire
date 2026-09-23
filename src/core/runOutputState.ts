import type {
  AcquireLifecycleState,
  AdapterScope,
  EvidenceSlot,
  RunIntegrityEvidence,
  RunReceipt,
} from "../adapters/acquireAdapter";

export type RunOutputState =
  | "idle"
  | "recording"
  | "saving"
  | "mock_complete"
  | "raw_retained"
  | "nwb_saved"
  | "failed";

export interface RunOutputSummary {
  state: RunOutputState;
  label: string;
  detail: string;
  phaseLabel: string;
  compactLabel: string;
  urgent: boolean;
}

function isFault(slot: EvidenceSlot): boolean {
  return slot.status === "failed" || slot.status === "degraded";
}

function firstFaultDetail(evidence: RunIntegrityEvidence): string | null {
  for (const slot of [evidence.acquisition, evidence.durability]) {
    if (isFault(slot) && slot.summary.trim().length > 0) return slot.summary;
  }
  return null;
}

function hasCreatedRawTarget(receipt: RunReceipt | null): boolean {
  return receipt?.recordingTarget.directoryCreateDisposition === "created_new"
    && receipt.recordingTarget.journalCreateDisposition === "created_new";
}

function hasValidNwbArtifact(receipt: RunReceipt | null): boolean {
  const artifact = receipt?.nwbArtifact;
  return artifact !== null
    && artifact !== undefined
    && artifact.artifactKind === "nwb"
    && artifact.createDisposition === "created_new"
    && artifact.schemaValidated === true
    && artifact.inspectorPassed === true
    && artifact.publicationCommitted === true
    && artifact.publicationReceiptId.trim().length > 0
    && artifact.evidenceHash.trim().length > 0
    && /\.nwb$/i.test(artifact.filePath.trim());
}

function failedSummary(detail: string): RunOutputSummary {
  return {
    state: "failed",
    label: "Recording failed · recovery required",
    detail,
    phaseLabel: "RECOVERY REQUIRED",
    compactLabel: "FAIL",
    urgent: true,
  };
}

/**
 * Converts adapter-authored receipts into the one operator-facing Run result.
 * Optional analysis or external-event evidence deliberately does not participate.
 */
export function deriveRunOutput(
  lifecycle: AcquireLifecycleState,
  evidence: RunIntegrityEvidence,
  runReceipt: RunReceipt | null,
  scope: AdapterScope,
): RunOutputSummary {
  const receiptStatus = runReceipt?.status ?? null;
  const coreFault = isFault(evidence.acquisition) || isFault(evidence.durability);
  const fatalReceiptFault = runReceipt?.faults.some((fault) => fault.latched
    && fault.code !== "control_pipe_loss") ?? false;
  const recoveryRequired = lifecycle === "recovery_required"
    || receiptStatus === "recovery_required"
    || receiptStatus === "degraded";

  if (recoveryRequired || coreFault || fatalReceiptFault) {
    return failedSummary(
      firstFaultDetail(evidence)
      ?? runReceipt?.faults.find((fault) => fault.latched && fault.code !== "control_pipe_loss")?.message
      ?? "The current Run does not meet the requirements for a complete recording and final NWB output.",
    );
  }

  if (
    ["stop_requested", "recording_stopped", "finalizing"].includes(lifecycle)
    || receiptStatus === "stopped_not_durable"
    || receiptStatus === "finalizing"
  ) {
    return {
      state: "saving",
      label: scope === "mock" ? "Ending simulation" : "Ending and generating NWB",
      detail: scope === "mock"
        ? "Waiting for the simulation completion receipt."
        : "Stopping input, draining the raw journal, and generating, validating, and publishing NWB.",
      phaseLabel: scope === "mock" ? "ENDING SIMULATION" : "ENDING / NWB",
      compactLabel: "SAVE",
      urgent: false,
    };
  }

  if (lifecycle === "start_requested") {
    return {
      state: "recording",
      label: "Starting recording",
      detail: "Waiting for the adapter snapshot to confirm that the source and writer entered Recording.",
      phaseLabel: "START REQUESTED",
      compactLabel: "START",
      urgent: false,
    };
  }

  if (lifecycle === "recording") {
    return {
      state: "recording",
      label: "Recording",
      detail: scope === "mock" ? "Synthetic data stream" : "The final NWB will be generated and validated when recording ends.",
      phaseLabel: "RECORDING",
      compactLabel: "REC",
      urgent: false,
    };
  }

  if (lifecycle === "finalized") {
    if (scope === "mock") {
      return {
        state: "mock_complete",
        label: "Simulation complete",
        detail: "No recording file or NWB was created.",
        phaseLabel: "SIMULATION COMPLETE",
        compactLabel: "MOCK",
        urgent: false,
      };
    }

    const coreProven = evidence.acquisition.status === "proven"
      && evidence.durability.status === "proven"
      && hasCreatedRawTarget(runReceipt);
    const nwbSaved = coreProven
      && receiptStatus === "finalized"
      && evidence.nwb.status === "proven"
      && hasValidNwbArtifact(runReceipt);
    if (nwbSaved) {
      return {
        state: "nwb_saved",
        label: "NWB saved",
        detail: `Generated, validated, and published as a new file: ${runReceipt?.nwbArtifact?.filePath ?? ""}`,
        phaseLabel: "NWB SAVED",
        compactLabel: "SAVED",
        urgent: false,
      };
    }

    if (coreProven && (receiptStatus === "raw_sealed" || receiptStatus === "finalized")) {
      return {
        state: "raw_retained",
        label: "Raw data retained · NWB incomplete",
        detail: isFault(evidence.nwb)
          ? evidence.nwb.summary
          : "Only the sealed raw journal is confirmed; there is no final NWB publication receipt.",
        phaseLabel: "NWB INCOMPLETE",
        compactLabel: "NWB!",
        urgent: true,
      };
    }

    return failedSummary("The Run ended, but its raw-recording or final-NWB receipt is incomplete.");
  }

  return {
    state: "idle",
    label: "Not recorded",
    detail: "",
    phaseLabel: "NO RECORDING",
    compactLabel: "IDLE",
    urgent: false,
  };
}
