import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type {
  EvidenceSlot,
  EvidenceSlotId,
  EvidenceStatus,
  RunIntegrityEvidence,
} from "../adapters/acquireAdapter";
import { recordingSaveSummary, RunIntegrityRail } from "./RunIntegrityRail";

function slot(id: EvidenceSlotId, status: EvidenceStatus): EvidenceSlot {
  return {
    id,
    status,
    scope: "mock",
    summary: `${id} summary`,
    watermark: status === "proven" ? 42n : null,
    receiptSequence: status === "proven" ? 7n : null,
    evidenceHash: status === "proven" ? "a".repeat(64) : null,
    updatedAtMonotonicMs: 100,
  };
}

function evidence(externalStatus: EvidenceStatus): RunIntegrityEvidence {
  return {
    acquisition: slot("acquisition", "proven"),
    durability: slot("durability", "proven"),
    nwb: slot("nwb", "qualification_required"),
    analysis: slot("analysis", "unavailable"),
    stimReceipt: slot("stim_receipt", externalStatus),
  };
}

describe("RunIntegrityRail", () => {
  it("groups two required raw-recording checks apart from three optional outputs and receipts", () => {
    const markup = renderToStaticMarkup(
      <RunIntegrityRail
        runId="MOCK-RUN-0001"
        lifecycle="finalized"
        evidence={evidence("unavailable")}
        runReceipt={null}
        synthetic
        collapsed={false}
        onToggleCollapsed={() => undefined}
      />,
    );

    expect(markup.match(/data-evidence-group=/g)).toHaveLength(2);
    expect(markup.match(/data-integrity-slot=/g)).toHaveLength(5);
    expect(markup).toContain("原始记录（必须）");
    expect(markup).toContain("可选输出与外部回执");
    expect(markup).toContain("数据接收与采集范围");
    expect(markup).toContain("文件写入与封存");
    expect(markup).toContain("停止记录 ≠ 保存完成");
    expect(markup).toContain("前 2 项回答");
    expect(markup).toContain("后 3 项即使完成，也不能反推前 2 项安全");
    expect(markup).not.toContain("Stimulation Arm");
    expect(markup).not.toContain("Stim Receipt");
  });

  it("does not let optional external-event status change the raw-recording closure rule", () => {
    for (const status of ["unavailable", "proven"] as const) {
      const markup = renderToStaticMarkup(
        <RunIntegrityRail
          runId="MOCK-RUN-0001"
          lifecycle="finalized"
          evidence={evidence(status)}
          runReceipt={null}
          synthetic
          collapsed={false}
          onToggleCollapsed={() => undefined}
        />,
      );
      expect(markup).toContain("2 项共同决定是否安全");
      expect(markup).toContain("外部事件时间线");
      expect(markup).toContain("3 项不反推原始记录安全");
    }
  });

  it("never treats Stop as a safe recording closure", () => {
    const summary = recordingSaveSummary(
      "recording_stopped",
      evidence("unavailable"),
      "stopped_not_durable",
      true,
    );

    expect(summary.state).toBe("stopped_unsealed");
    expect(summary.label).toBe("已停止 · 尚未安全封存");
    expect(summary.detail).toContain("停止记录 ≠ 保存完成");
  });

  it("distinguishes a mock finalized receipt from a real durable file", () => {
    const mockSummary = recordingSaveSummary(
      "finalized",
      evidence("unavailable"),
      "finalized",
      true,
    );
    const daemonSummary = recordingSaveSummary(
      "finalized",
      evidence("unavailable"),
      "finalized",
      false,
    );

    expect(mockSummary).toMatchObject({
      state: "mock_sealed",
      label: "模拟封存完成",
    });
    expect(mockSummary.detail).toContain("未创建真实文件");
    expect(daemonSummary).toMatchObject({
      state: "sealed",
      label: "原始记录已安全封存",
    });
  });

  it("treats a synthetic software source with real created-new files as a real durable recording", () => {
    expect(recordingSaveSummary(
      "recording_stopped",
      evidence("unavailable"),
      "raw_sealed",
      true,
      true,
    )).toMatchObject({
      state: "sealed",
      label: "原始记录已安全封存",
    });
  });

  it("fails closed when lifecycle says finalized but closure evidence is incomplete", () => {
    const incomplete = evidence("unavailable");
    incomplete.durability = slot("durability", "pending");

    expect(recordingSaveSummary("finalized", incomplete, "finalized", false)).toMatchObject({
      state: "recovery_required",
      label: "封存证据不完整 · 需要恢复",
    });
  });
});
