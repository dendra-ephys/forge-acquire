import {
  Cable,
  Check,
  CircleStop,
  Eye,
  EyeOff,
  PanelRightClose,
  Play,
  RefreshCw,
  Unplug,
  UserRound,
  UsersRound,
} from "lucide-react";
import type {
  PreviewSessionState,
  RecordingTargetReservation,
} from "../adapters/acquireAdapter";
import type { RunOutputSummary } from "../core/runOutputState";
import type { RecordingSetupMode } from "./PreflightDialog";

export interface RunControlPanelProps {
  connected: boolean;
  busy: boolean;
  phase: string;
  phaseLabel: string;
  phaseDetail: string;
  runId: string | null;
  previewState: PreviewSessionState;
  recordingTarget: RecordingTargetReservation | null;
  preflightPassed: boolean;
  recordingArmed: boolean;
  recording: boolean;
  recordingStopped: boolean;
  runOutput: RunOutputSummary;
  finalized: boolean;
  recoveryRequired: boolean;
  canConnect: boolean;
  canDisconnect: boolean;
  canStartPreview: boolean;
  canStopPreview: boolean;
  canSetupSingleRecording: boolean;
  canSetupMultiRecording: boolean;
  recordingSetupMode: RecordingSetupMode;
  recordingDeviceCount: number;
  previewDeviceName: string;
  canStart: boolean;
  canStopRecording: boolean;
  canRecover: boolean;
  canAcknowledgeFailed: boolean;
  onConnect: () => void;
  onDisconnect: () => void;
  onStartPreview: () => void;
  onStopPreview: () => void;
  onSetupSingleRecording: () => void;
  onSetupMultiRecording: () => void;
  onStart: () => void;
  onStopRecording: () => void;
  onRecover: () => void;
  onAcknowledgeFailed: () => void;
  onCollapse: () => void;
}

const FLOW = [
  { id: "setup", label: "设置" },
  { id: "armed", label: "可记录" },
  { id: "recording", label: "记录中" },
  { id: "saved", label: "最终 NWB" },
] as const;

function previewLabel(state: PreviewSessionState): string {
  if (state === "live") return "LIVE";
  if (state === "start_requested") return "STARTING";
  if (state === "stop_requested") return "STOPPING";
  if (state === "fault") return "FAULT";
  return "STOPPED";
}

function targetReadoutLabel(target: RecordingTargetReservation): string {
  return target.directoryCreateDisposition === "created_new"
    ? "记录目录已创建 · 禁止覆盖"
    : "模拟名称 · 未创建文件";
}

export function RunControlPanel({
  connected,
  busy,
  phase,
  phaseLabel,
  phaseDetail,
  runId,
  previewState,
  recordingTarget,
  preflightPassed,
  recordingArmed,
  recording,
  recordingStopped,
  runOutput,
  finalized,
  recoveryRequired,
  canConnect,
  canDisconnect,
  canStartPreview,
  canStopPreview,
  canSetupSingleRecording,
  canSetupMultiRecording,
  recordingSetupMode,
  recordingDeviceCount,
  previewDeviceName,
  canStart,
  canStopRecording,
  canRecover,
  canAcknowledgeFailed,
  onConnect,
  onDisconnect,
  onStartPreview,
  onStopPreview,
  onSetupSingleRecording,
  onSetupMultiRecording,
  onStart,
  onStopRecording,
  onRecover,
  onAcknowledgeFailed,
  onCollapse,
}: RunControlPanelProps) {
  const reconnectPending = !connected && !canConnect && runId !== null;
  const complete = new Set<string>();
  if (preflightPassed || recordingArmed || recording || recordingStopped || finalized) complete.add("setup");
  if (recordingArmed || recording || recordingStopped || finalized) complete.add("armed");
  if (recording || recordingStopped || finalized) complete.add("recording");
  if (runOutput.state === "nwb_saved") complete.add("saved");
  const saving = ["stop_requested", "recording_stopped", "finalizing"].includes(phase);
  const phaseTone = recoveryRequired || runOutput.state === "failed"
    ? "fault"
    : runOutput.state === "raw_retained"
      ? "caution"
      : recording ? "recording" : connected ? "ready" : "idle";

  return (
    <section className="run-control" aria-labelledby="run-control-title">
      <header className="instrument-section-heading">
        <div>
          <span className="instrument-kicker">PREVIEW / RECORDING</span>
          <h2 id="run-control-title">采集控制</h2>
        </div>
        <div className="instrument-section-heading__actions">
          <span className={"phase-chip phase-chip--" + phaseTone}>
            {phaseLabel}
          </span>
          <button
            className="panel-collapse-button"
            type="button"
            aria-label="收起采集控制栏"
            aria-expanded={true}
            title="收起控制栏；录制中仍保留结束并保存动作"
            onClick={onCollapse}
          >
            <PanelRightClose size={17} aria-hidden="true" />
          </button>
        </div>
      </header>

      <div className="run-readout" data-phase={phase}>
        <span className="run-readout__label">CURRENT RUN</span>
        <strong>{runId ?? "NO RUN"}</strong>
        <p>{phaseDetail}</p>
      </div>

      <div className={"preview-session-card preview-session-card--" + previewState}>
        <div>
          <span>MONITOR / PREVIEW SOURCE</span>
          <strong>{previewLabel(previewState)}</strong>
          <small>显示实时低速派生预览；冻结只暂停显示。</small>
        </div>
        <button
          className="instrument-button instrument-button--preview"
          type="button"
          disabled={busy || (previewState === "live" ? !canStopPreview : !canStartPreview)}
          onClick={previewState === "live" ? onStopPreview : onStartPreview}
        >
          {previewState === "live" ? <EyeOff size={17} aria-hidden="true" /> : <Eye size={17} aria-hidden="true" />}
          {previewState === "live" ? "停止预览" : "开始预览"}
        </button>
      </div>

      <ol className="run-flow" aria-label="Recording lifecycle">
        {FLOW.map((step, index) => (
          <li key={step.id} className={complete.has(step.id) ? "is-complete" : ""}>
            <span>{complete.has(step.id) ? <Check size={13} aria-hidden="true" /> : index + 1}</span>
            <strong>{step.label}</strong>
          </li>
        ))}
      </ol>

      <div className="run-actions">
        <button
          className="instrument-button instrument-button--secondary"
          type="button"
          disabled={busy || (connected ? !canDisconnect : !canConnect)}
          title={reconnectPending
            ? "Run 仍由独立 daemon 持有；正在等待自动轮询恢复控制连接"
            : connected && !canDisconnect
              ? "当前 Run 尚未结束；必须保留控制连接，才能结束并保存或确认失败"
              : undefined}
          onClick={connected ? onDisconnect : onConnect}
        >
          {busy || reconnectPending ? <RefreshCw className="is-spinning" size={17} aria-hidden="true" /> : connected ? <Unplug size={17} aria-hidden="true" /> : <Cable size={17} aria-hidden="true" />}
          {connected ? "Disconnect" : reconnectPending ? "等待控制面恢复" : "Connect"}
        </button>

        <div className="recording-mode-actions" role="group" aria-label="选择记录设备范围；两个入口都只进入设置与 Preflight">
          <button
            className="instrument-button instrument-button--secondary instrument-button--recording-mode"
            type="button"
            disabled={!canSetupSingleRecording || busy || (recordingTarget !== null && recordingSetupMode !== "single")}
            title={`冻结当前 Preview 设备：${previewDeviceName}；只进入设置，不开始记录`}
            onClick={onSetupSingleRecording}
          >
            <UserRound size={17} aria-hidden="true" />
            <span>{recordingTarget && recordingSetupMode === "single" ? "查看单设备设置" : "单设备记录…"}</span>
          </button>
          <button
            className="instrument-button instrument-button--secondary instrument-button--recording-mode"
            type="button"
            disabled={!canSetupMultiRecording || busy || (recordingTarget !== null && recordingSetupMode !== "multi")}
            title="显式选择 2–8 个 Pod；只进入设置，不开始记录"
            onClick={onSetupMultiRecording}
          >
            <UsersRound size={17} aria-hidden="true" />
            <span>{recordingTarget && recordingSetupMode === "multi" ? "查看多设备设置" : "多设备记录…"}</span>
          </button>
        </div>

        {recordingTarget ? (
          <div className="recording-target-readout" role="note">
            <span>{targetReadoutLabel(recordingTarget)}</span>
            <strong title={recordingTarget.resolvedRunDirectory}>{recordingTarget.resolvedRunDirectory}</strong>
            <small>{recordingTarget.scope === "mock" ? "SIMULATION · NO FILE" : "FINAL OUTPUT · NWB REQUIRED"}</small>
          </div>
        ) : null}

        <button
          className="instrument-button instrument-button--record"
          type="button"
          disabled={!canStart || busy}
          onClick={onStart}
        >
          <Play size={18} fill="currentColor" aria-hidden="true" />
          {recordingDeviceCount > 0 ? `开始记录 · ${recordingDeviceCount} 台` : "开始记录"}
        </button>

        <button
          className="instrument-button instrument-button--stop"
          type="button"
          disabled={!canStopRecording || busy}
          title="一次请求完成停止输入、排空，并生成、验证和发布最终 NWB"
          onClick={onStopRecording}
        >
          <CircleStop size={18} aria-hidden="true" />
          结束并保存
        </button>

        <div className={`stop-safety-separator${saving ? " is-active" : ""} is-${runOutput.state}`} role="note">
          <strong>{saving ? "正在结束并生成 NWB" : runOutput.label}</strong>
          <span>{saving
            ? "Preview 可继续；最终 NWB 回执到达前不显示保存成功。"
            : runOutput.state === "idle"
              ? "结束记录时由 adapter / daemon 连续生成并验证 NWB，无需第二次操作。"
              : runOutput.detail}</span>
        </div>

        {recoveryRequired && canAcknowledgeFailed ? (
          <>
            <button
              className="instrument-button instrument-button--acknowledge-failed"
              type="button"
              disabled={busy}
              title="只关闭失败 Run 的控制上下文；保留 partial journal，不删除文件、不补写 seal"
              onClick={onAcknowledgeFailed}
            >
              <CircleStop size={17} aria-hidden="true" />
              确认失败并关闭 Run
            </button>
            <p className="failed-run-retention-note">
              只关闭控制上下文；保留 partial journal，不删除文件、不补写 seal。
            </p>
          </>
        ) : recoveryRequired && canRecover ? (
          <button
            className="instrument-button instrument-button--recover"
            type="button"
            disabled={busy}
            onClick={onRecover}
          >
            <RefreshCw size={17} aria-hidden="true" />
            Recover
          </button>
        ) : recoveryRequired ? (
          <div className="recovery-action-unavailable" role="note">
            当前 snapshot 未提供可执行的 GUI 恢复命令；保留 partial journal，并等待 daemon 状态或人工检查。
          </div>
        ) : null}
      </div>
    </section>
  );
}
