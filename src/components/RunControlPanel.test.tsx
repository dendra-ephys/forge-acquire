import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { RunOutputState, RunOutputSummary } from "../core/runOutputState";
import { RunControlPanel, type RunControlPanelProps } from "./RunControlPanel";

const noop = () => undefined;

function output(state: RunOutputState, label = "尚未记录", detail = ""): RunOutputSummary {
  return {
    state,
    label,
    detail,
    phaseLabel: state.toUpperCase(),
    compactLabel: state === "nwb_saved" ? "SAVED" : state.toUpperCase(),
    urgent: state === "failed" || state === "raw_retained",
  };
}

function renderPanel(overrides: Partial<RunControlPanelProps> = {}): string {
  const props: RunControlPanelProps = {
    connected: true,
    busy: false,
    phase: "connected_idle",
    phaseLabel: "CONNECTED / IDLE",
    phaseDetail: "Preview is live",
    runId: null,
    previewState: "live",
    recordingTarget: null,
    preflightPassed: false,
    recordingArmed: false,
    recording: false,
    recordingStopped: false,
    runOutput: output("idle"),
    finalized: false,
    recoveryRequired: false,
    canConnect: false,
    canDisconnect: true,
    canStartPreview: false,
    canStopPreview: true,
    canSetupSingleRecording: true,
    canSetupMultiRecording: true,
    recordingSetupMode: "single",
    recordingDeviceCount: 1,
    previewDeviceName: "Direct Pod 1",
    canStart: false,
    canStopRecording: false,
    canRecover: false,
    canAcknowledgeFailed: false,
    onConnect: noop,
    onDisconnect: noop,
    onStartPreview: noop,
    onStopPreview: noop,
    onSetupSingleRecording: noop,
    onSetupMultiRecording: noop,
    onStart: noop,
    onStopRecording: noop,
    onRecover: noop,
    onAcknowledgeFailed: noop,
    onCollapse: noop,
    ...overrides,
  };
  return renderToStaticMarkup(<RunControlPanel {...props} />);
}

describe("RunControlPanel", () => {
  it("offers explicit single- and multi-device setup entries but only one actual Start action", () => {
    const markup = renderPanel();

    expect(markup).toContain("单设备记录…");
    expect(markup).toContain("多设备记录…");
    expect(markup).toContain("冻结当前 Preview 设备：Direct Pod 1；只进入设置，不开始记录");
    expect(markup).toContain("开始记录 · 1 台");
    expect(markup.match(/instrument-button--record"/g)).toHaveLength(1);
    expect(markup).not.toContain("同步");
  });

  it("exposes one end-and-save action without a second Finalize command", () => {
    const markup = renderPanel({
      phase: "recording",
      phaseLabel: "RECORDING",
      runId: "ACTIVE-RUN",
      recording: true,
      canStopRecording: true,
    });

    expect(markup.match(/结束并保存/g)).not.toHaveLength(0);
    expect(markup.match(/instrument-button--stop"/g)).toHaveLength(1);
    expect(markup).toContain("一次请求完成停止输入、排空，并生成、验证和发布最终 NWB");
    expect(markup).not.toContain(">Finalize</button>");
    expect(markup).not.toContain("封存 Run");
  });

  it("keeps the compound operation pending until the final NWB receipt is proven", () => {
    const saving = renderPanel({
      phase: "finalizing",
      phaseLabel: "ENDING / NWB",
      runId: "ACTIVE-RUN",
      recordingStopped: true,
      runOutput: output("saving", "正在结束并生成 NWB", "正在生成最终 NWB"),
      finalized: false,
    });
    expect(saving).toContain("正在结束并生成 NWB");
    expect(saving).toContain("最终 NWB 回执到达前不显示保存成功");

    const rawRetained = renderPanel({
      phase: "finalized",
      phaseLabel: "NWB INCOMPLETE",
      runId: "INCOMPLETE-RUN",
      recordingStopped: true,
      runOutput: output(
        "raw_retained",
        "原始数据已保留 · NWB 未完成",
        "只确认原始 journal 已封存；尚无最终 NWB 发布回执。",
      ),
      finalized: true,
    });
    expect(rawRetained).toContain("原始数据已保留 · NWB 未完成");
    expect(rawRetained).toContain("尚无最终 NWB 发布回执");
    expect(rawRetained).not.toContain("NWB 已保存");

    const saved = renderPanel({
      phase: "finalized",
      phaseLabel: "NWB SAVED",
      runId: "SEALED-RUN",
      recordingStopped: true,
      runOutput: output(
        "nwb_saved",
        "NWB 已保存",
        "已生成、验证并以新文件发布：F:\\ForgeRuns\\FORGE-RUN-001.nwb",
      ),
      finalized: true,
    });
    expect(saved).toContain("NWB 已保存");
    expect(saved).toContain("FORGE-RUN-001.nwb");
  });

  it("keeps a completed Browser mock visibly separate from a saved NWB", () => {
    const markup = renderPanel({
      phase: "finalized",
      phaseLabel: "SIMULATION COMPLETE",
      runId: "MOCK-RUN",
      recordingStopped: true,
      runOutput: output("mock_complete", "模拟流程完成", "未创建记录文件，也未生成 NWB。"),
      finalized: true,
    });

    expect(markup).toContain("模拟流程完成");
    expect(markup).toContain("未创建记录文件，也未生成 NWB");
    expect(markup).not.toContain("NWB SAVED");
  });

  it("offers an honest failed-Run close action without a rejected Recover button", () => {
    const markup = renderPanel({
      phase: "recovery_required",
      phaseLabel: "RECOVERY REQUIRED",
      phaseDetail: "未封存；generated 10 / committed 9 / durable 8",
      runId: "FAILED-RUN",
      recoveryRequired: true,
      canStopPreview: true,
      canAcknowledgeFailed: true,
    });

    expect(markup).toContain("确认失败并关闭 Run");
    expect(markup).toContain("保留 partial journal");
    expect(markup).toContain("不补写 seal");
    expect(markup).not.toContain(">Recover<");
  });

  it("does not render a clickable recovery command when the adapter provides none", () => {
    const markup = renderPanel({
      phase: "recovery_required",
      phaseLabel: "RECOVERY REQUIRED",
      recoveryRequired: true,
      canRecover: false,
      canAcknowledgeFailed: false,
    });

    expect(markup).toContain("当前 snapshot 未提供可执行的 GUI 恢复命令");
    expect(markup).not.toContain(">Recover<");
    expect(markup).not.toContain("确认失败并关闭 Run");
  });

  it("does not offer a fake Connect action while an active Run is waiting for control recovery", () => {
    const markup = renderPanel({
      connected: false,
      canConnect: false,
      runId: "ACTIVE-RUN",
      phase: "recording",
      phaseLabel: "CONTROL LOST",
    });

    expect(markup).toContain("等待控制面恢复");
    expect(markup).toContain("Run 仍由独立 daemon 持有");
    expect(markup).not.toContain(">Connect<");
  });

  it("disables explicit Disconnect while a Run still needs its control path", () => {
    const markup = renderPanel({
      phase: "recording",
      phaseLabel: "RECORDING",
      runId: "ACTIVE-RUN",
      recording: true,
      canDisconnect: false,
      canStopRecording: true,
    });

    expect(markup).toContain("当前 Run 尚未结束；必须保留控制连接");
    expect(markup).toMatch(/<button[^>]*disabled=""[^>]*title="当前 Run 尚未结束/);
    expect(markup).toContain(">Disconnect<");
  });
});
