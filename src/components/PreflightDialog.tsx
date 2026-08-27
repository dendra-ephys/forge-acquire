import {
  AlertTriangle,
  CheckCircle2,
  CircleSlash2,
  FlaskConical,
  FolderLock,
  LockKeyhole,
  Play,
  RefreshCw,
  ShieldQuestion,
  UserRound,
  UsersRound,
} from "lucide-react";
import type {
  AdapterScope,
  PodKey,
  RecordingTargetReservation,
} from "../adapters/acquireAdapter";
import { useModalFocus } from "../core/useModalFocus";

export type PreflightCheckStatus = "pass" | "pending" | "blocked" | "unavailable" | "qualification_required";
export type RecordingSetupMode = "single" | "multi";

export interface PreflightCheck {
  id: string;
  label: string;
  status: PreflightCheckStatus;
  detail: string;
  evidence: string;
}

export interface RecordingDeviceOption {
  key: PodKey;
  displayName: string;
  deviceId: string;
  routeLabel: string;
}

export function recordingSelectionProblem(mode: RecordingSetupMode, selectedCount: number): string | null {
  if (mode === "single") {
    return selectedCount === 1 ? null : "单设备记录必须冻结 1 个当前 Preview Pod。";
  }
  if (selectedCount < 2) return "多设备记录需要显式选择至少 2 个 Pod。";
  if (selectedCount > 8) return "单个 Run 最多记录 8 个 Pod。";
  return null;
}

export interface PreflightDialogProps {
  open: boolean;
  running: boolean;
  passed: boolean;
  armed: boolean;
  recordingMode: RecordingSetupMode;
  adapterScope: AdapterScope;
  runLabel: string;
  requestedDirectory: string;
  plannedDurationHours: number;
  devices: readonly RecordingDeviceOption[];
  selectedPodKeys: ReadonlySet<PodKey>;
  recordingTarget: RecordingTargetReservation | null;
  receiptId: string | null;
  checks: readonly PreflightCheck[];
  onRunLabelChange: (value: string) => void;
  onRequestedDirectoryChange: (value: string) => void;
  onPlannedDurationHoursChange: (value: number) => void;
  onTogglePod: (podKey: PodKey, selected: boolean) => void;
  onRunPreflight: () => void;
  onRequestArm: () => void;
  onCancel: () => void;
}

function iconFor(status: PreflightCheckStatus) {
  if (status === "pass") return <CheckCircle2 size={17} aria-hidden="true" />;
  if (status === "pending") return <RefreshCw className="is-spinning" size={17} aria-hidden="true" />;
  if (status === "blocked") return <AlertTriangle size={17} aria-hidden="true" />;
  if (status === "qualification_required") return <ShieldQuestion size={17} aria-hidden="true" />;
  return <CircleSlash2 size={17} aria-hidden="true" />;
}

function labelFor(status: PreflightCheckStatus): string {
  if (status === "pass") return "PASS";
  if (status === "pending") return "PENDING";
  if (status === "blocked") return "BLOCKED";
  if (status === "qualification_required") return "QUALIFICATION";
  return "UNAVAILABLE";
}

function targetAllocationLabel(target: RecordingTargetReservation): string {
  return target.directoryCreateDisposition === "created_new"
    ? "TARGET CREATED NEW · NO OVERWRITE"
    : "MOCK NAME ALLOCATED · NO FILE CREATED";
}

export function PreflightDialog({
  open,
  running,
  passed,
  armed,
  recordingMode,
  adapterScope,
  runLabel,
  requestedDirectory,
  plannedDurationHours,
  devices,
  selectedPodKeys,
  recordingTarget,
  receiptId,
  checks,
  onRunLabelChange,
  onRequestedDirectoryChange,
  onPlannedDurationHoursChange,
  onTogglePod,
  onRunPreflight,
  onRequestArm,
  onCancel,
}: PreflightDialogProps) {
  const { backdropRef, dialogRef } = useModalFocus(open, onCancel);
  const locked = running || passed || armed;
  const selectionProblem = recordingSelectionProblem(recordingMode, selectedPodKeys.size);
  const selectedDevices = devices.filter((device) => selectedPodKeys.has(device.key));
  const canPreflight = !locked
    && runLabel.trim().length > 0
    && requestedDirectory.trim().length > 0
    && plannedDurationHours > 0
    && selectionProblem === null;
  if (!open) return null;

  return (
    <div
      ref={backdropRef}
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <section
        ref={dialogRef}
        tabIndex={-1}
        className="dialog preflight-dialog recording-setup-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="preflight-title"
        aria-describedby="preflight-description"
      >
        <header className="dialog-header">
          <div>
            <span className="instrument-kicker">{adapterScope.toUpperCase()} RECORDING SETUP · {recordingMode.toUpperCase()}</span>
            <h2 id="preflight-title">{recordingMode === "single" ? "单设备记录设置" : "多设备记录设置"}</h2>
            <p id="preflight-description">
              {recordingMode === "single"
                ? "当前 Preview Pod 将作为唯一记录设备冻结；Preflight 不会开始记录，也不会改变 Preview 选择。"
                : "显式选择 2–8 个 Pod 后冻结同一个 Run plan；Preflight 不会开始记录，也不声称设备间同步。"}
            </p>
          </div>
          <button
            className="dialog-close"
            type="button"
            aria-label="关闭记录设置"
            data-modal-initial-focus
            onClick={onCancel}
          >
            ×
          </button>
        </header>

        <div className="dialog-body">
          {!passed && !armed ? <>
          <div className="recording-setup-grid">
            <label className="recording-field recording-field--wide">
              <span>保存位置 · Run 根目录</span>
              <input
                type="text"
                value={requestedDirectory}
                disabled={locked}
                spellCheck={false}
                onChange={(event) => onRequestedDirectoryChange(event.currentTarget.value)}
              />
              <small>{adapterScope === "mock"
                ? "Mock 只验证路径文本并分配名称，不创建真实目录。"
                : "只有 adapter 返回 created_new filesystem receipt 后，界面才会显示目录已创建；始终禁止覆盖。"}</small>
            </label>
            <label className="recording-field">
              <span>Run 名称前缀</span>
              <input
                type="text"
                value={runLabel}
                disabled={locked}
                maxLength={80}
                spellCheck={false}
                onChange={(event) => onRunLabelChange(event.currentTarget.value)}
              />
              <small>最终目录自动追加 -001、-002…；create-new，禁止覆盖。</small>
            </label>
            <label className="recording-field">
              <span>计划时长 · h</span>
              <input
                type="number"
                min={0.1}
                max={24}
                step={0.5}
                value={plannedDurationHours}
                disabled={locked}
                onChange={(event) => onPlannedDurationHoursChange(Number(event.currentTarget.value))}
              />
              <small>本轮产品上限 24 h；这里只是计划值，不是发布资格。</small>
            </label>
          </div>

          <fieldset className="recording-device-selection" disabled={locked}>
            <legend>{recordingMode === "single" ? "单设备记录对象" : "多设备记录对象 · 2–8 台"}</legend>
            <p>
              {recordingMode === "single"
                ? "来自打开设置时的 Preview Pod；切换记录方式不会替你更改 Preview。"
                : "必须由操作者逐项勾选；这些勾选只形成多设备 Run 草案，不改变当前 Preview Pod。"}
            </p>
            <div>
              {(recordingMode === "single" ? selectedDevices : devices).map((device) => (
                <label key={device.key} className={selectedPodKeys.has(device.key) ? "is-selected" : ""}>
                  <input
                    type={recordingMode === "single" ? "radio" : "checkbox"}
                    checked={selectedPodKeys.has(device.key)}
                    disabled={recordingMode === "single"
                      || (!selectedPodKeys.has(device.key) && selectedPodKeys.size >= 8)}
                    readOnly={recordingMode === "single"}
                    onChange={recordingMode === "multi"
                      ? (event) => onTogglePod(device.key, event.currentTarget.checked)
                      : undefined}
                  />
                  <span>
                    <strong>{device.displayName}</strong>
                    <small>{device.routeLabel} · {device.deviceId}</small>
                  </span>
                </label>
              ))}
            </div>
            {selectionProblem ? <div className="arm-boundary-callout" role="alert">{selectionProblem}</div> : null}
          </fieldset>
          </> : null}

          <div className="preflight-summary">
            <FlaskConical size={19} aria-hidden="true" />
            <div><span>Run prefix</span><strong>{runLabel || "—"}</strong></div>
            <div><span>计划时长</span><strong>{plannedDurationHours || "—"} h</strong></div>
            <div>
              {recordingMode === "single" ? <UserRound size={15} aria-hidden="true" /> : <UsersRound size={15} aria-hidden="true" />}
              <span>记录方式</span><strong>{recordingMode === "single" ? "单设备" : "多设备"} · {selectedPodKeys.size} 台</strong>
            </div>
          </div>

          {recordingTarget ? (
            <div className="recording-reservation" role="status">
              <FolderLock size={18} aria-hidden="true" />
              <div>
                <span>{targetAllocationLabel(recordingTarget)}</span>
                <strong title={recordingTarget.resolvedRunDirectory}>{recordingTarget.resolvedRunDirectory}</strong>
                <code>
                  {recordingTarget.reservationId} · directory={recordingTarget.directoryCreateDisposition}
                  {" · "}{recordingTarget.evidenceHash}
                </code>
              </div>
            </div>
          ) : (
            <div className="recording-reservation is-pending" role="note">
              <FolderLock size={18} aria-hidden="true" />
              <div>
                <span>尚未分配最终 Run 目录</span>
                <strong>{requestedDirectory || "选择根目录"}\{runLabel || "RUN"}-###</strong>
                <code>最终序号与完整路径只接受 adapter reservation receipt</code>
              </div>
            </div>
          )}

          <ul className="preflight-checks">
            {checks.map((check) => (
              <li className={"preflight-check preflight-check--" + check.status} key={check.id}>
                <span className="preflight-check__icon">{iconFor(check.status)}</span>
                <div>
                  <strong>{check.label}</strong>
                  <p>{check.detail}</p>
                  <code>{check.evidence}</code>
                </div>
                <span className="preflight-check__state">{labelFor(check.status)}</span>
              </li>
            ))}
          </ul>

          <div className={"arm-boundary-callout" + (passed || armed ? " is-ready" : "")} role="note">
            <LockKeyhole size={18} aria-hidden="true" />
            <div>
              <strong>{running ? "正在等待 Preflight snapshot…" : armed ? "Recording Arm 已由 snapshot 证明" : passed ? "Preflight 已通过，可以请求 Recording Arm" : "尚未运行 Preflight"}</strong>
              <span>
                {receiptId ? "Command receipt " + receiptId : "尚无 command receipt"}；Recording Arm 只是 writer 写入互锁，不是刺激授权，也不会自行开始记录。
              </span>
            </div>
          </div>
        </div>

        <footer className="dialog-actions">
          <button className="instrument-button instrument-button--secondary" type="button" onClick={onCancel}>
            {armed ? "完成" : "关闭"}
          </button>
          {!passed && !armed ? (
            <button
              className="instrument-button instrument-button--arm"
              type="button"
              disabled={!canPreflight || running}
              onClick={onRunPreflight}
            >
              {running ? <RefreshCw className="is-spinning" size={17} aria-hidden="true" /> : <Play size={17} aria-hidden="true" />}
              检查并分配记录目标
            </button>
          ) : armed ? null : (
            <button
              className="instrument-button instrument-button--arm"
              type="button"
              disabled={!passed || running}
              onClick={onRequestArm}
            >
              <LockKeyhole size={17} aria-hidden="true" />
              准备开始记录
            </button>
          )}
        </footer>
      </section>
    </div>
  );
}
