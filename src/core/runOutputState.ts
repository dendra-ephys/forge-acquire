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
    label: "记录失败 · 需要恢复",
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
      ?? "当前 Run 没有满足完整记录与最终 NWB 输出条件。",
    );
  }

  if (
    ["stop_requested", "recording_stopped", "finalizing"].includes(lifecycle)
    || receiptStatus === "stopped_not_durable"
    || receiptStatus === "finalizing"
  ) {
    return {
      state: "saving",
      label: scope === "mock" ? "正在结束模拟流程" : "正在结束并生成 NWB",
      detail: scope === "mock"
        ? "等待模拟结束回执。"
        : "正在停止输入、排空原始 journal，并生成、验证和发布 NWB。",
      phaseLabel: scope === "mock" ? "ENDING SIMULATION" : "ENDING / NWB",
      compactLabel: "SAVE",
      urgent: false,
    };
  }

  if (lifecycle === "start_requested") {
    return {
      state: "recording",
      label: "正在启动记录",
      detail: "等待 adapter snapshot 确认数据源与 writer 已进入 Recording。",
      phaseLabel: "START REQUESTED",
      compactLabel: "START",
      urgent: false,
    };
  }

  if (lifecycle === "recording") {
    return {
      state: "recording",
      label: "正在记录",
      detail: scope === "mock" ? "模拟数据流" : "最终 NWB 将在结束记录时生成并验证。",
      phaseLabel: "RECORDING",
      compactLabel: "REC",
      urgent: false,
    };
  }

  if (lifecycle === "finalized") {
    if (scope === "mock") {
      return {
        state: "mock_complete",
        label: "模拟流程完成",
        detail: "未创建记录文件，也未生成 NWB。",
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
        label: "NWB 已保存",
        detail: `已生成、验证并以新文件发布：${runReceipt?.nwbArtifact?.filePath ?? ""}`,
        phaseLabel: "NWB SAVED",
        compactLabel: "SAVED",
        urgent: false,
      };
    }

    if (coreProven && (receiptStatus === "raw_sealed" || receiptStatus === "finalized")) {
      return {
        state: "raw_retained",
        label: "原始数据已保留 · NWB 未完成",
        detail: isFault(evidence.nwb)
          ? evidence.nwb.summary
          : "只确认原始 journal 已封存；尚无最终 NWB 发布回执。",
        phaseLabel: "NWB INCOMPLETE",
        compactLabel: "NWB!",
        urgent: true,
      };
    }

    return failedSummary("Run 已结束，但原始记录或最终 NWB 回执不完整。");
  }

  return {
    state: "idle",
    label: "尚未记录",
    detail: "",
    phaseLabel: "NO RECORDING",
    compactLabel: "IDLE",
    urgent: false,
  };
}
