import {
  Cable,
  Check,
  CircleStop,
  Eye,
  EyeOff,
  FileCheck2,
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
  durabilityProven: boolean;
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
  canFinalize: boolean;
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
  onFinalize: () => void;
  onRecover: () => void;
  onAcknowledgeFailed: () => void;
  onCollapse: () => void;
}

const FLOW = [
  { id: "setup", label: "Setup" },
  { id: "armed", label: "Record Ready" },
  { id: "recording", label: "Recording" },
  { id: "stopped", label: "Input Stopped" },
  { id: "finalized", label: "Sealed" },
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
    ? "RUN FOLDER CREATED NEW · NO OVERWRITE"
    : "MOCK TARGET NAME · NO FILE CREATED";
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
  durabilityProven,
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
  canFinalize,
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
  onFinalize,
  onRecover,
  onAcknowledgeFailed,
  onCollapse,
}: RunControlPanelProps) {
  const reconnectPending = !connected && !canConnect && runId !== null;
  const complete = new Set<string>();
  if (preflightPassed || recordingArmed || recording || recordingStopped || finalized) complete.add("setup");
  if (recordingArmed || recording || recordingStopped || finalized) complete.add("armed");
  if (recording || recordingStopped || finalized) complete.add("recording");
  if (recordingStopped || finalized) complete.add("stopped");
  if (finalized) complete.add("finalized");

  return (
    <section className="run-control" aria-labelledby="run-control-title">
      <header className="instrument-section-heading">
        <div>
          <span className="instrument-kicker">PREVIEW / RECORDING</span>
          <h2 id="run-control-title">采集控制</h2>
        </div>
        <div className="instrument-section-heading__actions">
          <span className={"phase-chip phase-chip--" + (recoveryRequired ? "fault" : recording ? "recording" : connected ? "ready" : "idle")}>
            {phaseLabel}
          </span>
          <button
            className="panel-collapse-button"
            type="button"
            aria-label="收起采集控制栏"
            aria-expanded={true}
            title="收起控制栏；录制中仍保留停止记录动作"
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
          <small>启动后建立数据源并显示低速派生预览；不是 Recording，也不写文件。冻结显示只暂停 WebView 重绘。</small>
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
              ? "当前 Run 尚未结束；必须保留控制连接，才能 Stop、Finalize 或确认失败"
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
            <small>{recordingTarget.scope.toUpperCase()} · {recordingTarget.journalFileName}</small>
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
          onClick={onStopRecording}
        >
          <CircleStop size={18} aria-hidden="true" />
          停止记录
        </button>

        <div className={"stop-safety-separator" + (recordingStopped && !finalized ? " is-active" : "")} role="note">
          <strong>{recordingStopped
            ? durabilityProven ? "记录输入已停止；文件封存回执已确认" : "记录输入已停止；Preview 可继续"
            : "停止记录会请求停止输入；是否排空并封存只看后续回执"}</strong>
          <span>{durabilityProven
            ? "文件写入与封存证据已确认；仍需同时检查数据接收与采集范围。"
            : finalized
              ? "Run 状态已结束，但 durability / seal 证据不足时仍不能称为安全保存。"
              : "当前不等于文件已安全保存；等待 adapter / daemon 的 durability 与 seal receipt。"}</span>
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
        ) : (
          <button
            className="instrument-button instrument-button--finalize"
            type="button"
            disabled={!canFinalize || busy}
            onClick={onFinalize}
          >
            <FileCheck2 size={17} aria-hidden="true" />
            Finalize / 封存 Run
          </button>
        )}
      </div>
    </section>
  );
}
