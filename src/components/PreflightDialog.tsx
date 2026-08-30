import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Clock3,
  CircleSlash2,
  FolderLock,
  FolderOpen,
  LockKeyhole,
  Play,
  RefreshCw,
  ShieldQuestion,
  Wrench,
} from "lucide-react";
import { lazy, Suspense, useEffect, useRef } from "react";
import type {
  AdapterScope,
  PodKey,
  RecordingTargetReservation,
} from "../adapters/acquireAdapter";
import type { RunDirectoryListing } from "../adapters/runDirectoryBrowser";
import { useModalFocus } from "../core/useModalFocus";
import "./PreflightDialog.css";

const RunDirectoryBrowserView = lazy(async () => {
  const module = await import("./RunDirectoryBrowserView");
  return { default: module.RunDirectoryBrowserView };
});

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
  finalOutputReady: boolean;
  finalOutputLabel: string;
  runLabel: string;
  requestedDirectory: string;
  plannedDurationHours: number;
  devices: readonly RecordingDeviceOption[];
  selectedPodKeys: ReadonlySet<PodKey>;
  recordingTarget: RecordingTargetReservation | null;
  receiptId: string | null;
  checks: readonly PreflightCheck[];
  directoryBrowserAvailable: boolean;
  directoryBrowserOpen: boolean;
  directoryBrowserListing: RunDirectoryListing | null;
  directoryBrowserBusy: boolean;
  directoryBrowserError: string | null;
  onRunLabelChange: (value: string) => void;
  onRequestedDirectoryChange: (value: string) => void;
  onOpenDirectoryBrowser: () => void;
  onBrowseDirectory: (directory: string) => void;
  onUseDirectory: (directory: string) => void;
  onCloseDirectoryBrowser: () => void;
  onPlannedDurationHoursChange: (value: number) => void;
  onTogglePod: (podKey: PodKey, selected: boolean) => void;
  onRunPreflight: () => void;
  onRequestArm: () => void;
  onCancel: () => void;
}

function iconFor(status: PreflightCheckStatus) {
  if (status === "pass") return <CheckCircle2 size={17} aria-hidden="true" />;
  if (status === "pending") return <Clock3 size={17} aria-hidden="true" />;
  if (status === "blocked") return <AlertTriangle size={17} aria-hidden="true" />;
  if (status === "qualification_required") return <ShieldQuestion size={17} aria-hidden="true" />;
  return <CircleSlash2 size={17} aria-hidden="true" />;
}

function labelFor(status: PreflightCheckStatus): string {
  if (status === "pass") return "已通过";
  if (status === "pending") return "等待";
  if (status === "blocked") return "被阻止";
  if (status === "qualification_required") return "需验证";
  return "不可用";
}

function targetAllocationLabel(target: RecordingTargetReservation): string {
  return target.directoryCreateDisposition === "created_new"
    ? "已创建新目录 · 禁止覆盖"
    : "仅分配模拟名称 · 未创建文件";
}

export function PreflightDialog({
  open,
  running,
  passed,
  armed,
  recordingMode,
  adapterScope,
  finalOutputReady,
  finalOutputLabel,
  runLabel,
  requestedDirectory,
  plannedDurationHours,
  devices,
  selectedPodKeys,
  recordingTarget,
  receiptId,
  checks,
  directoryBrowserAvailable,
  directoryBrowserOpen,
  directoryBrowserListing,
  directoryBrowserBusy,
  directoryBrowserError,
  onRunLabelChange,
  onRequestedDirectoryChange,
  onOpenDirectoryBrowser,
  onBrowseDirectory,
  onUseDirectory,
  onCloseDirectoryBrowser,
  onPlannedDurationHoursChange,
  onTogglePod,
  onRunPreflight,
  onRequestArm,
  onCancel,
}: PreflightDialogProps) {
  const requestClose = directoryBrowserOpen ? onCloseDirectoryBrowser : onCancel;
  const { backdropRef, dialogRef } = useModalFocus(open, requestClose);
  const directoryTriggerRef = useRef<HTMLButtonElement>(null);
  const directoryBrowserWasOpen = useRef(directoryBrowserOpen);

  useEffect(() => {
    const wasOpen = directoryBrowserWasOpen.current;
    directoryBrowserWasOpen.current = directoryBrowserOpen;
    if (!wasOpen || directoryBrowserOpen || !open) return undefined;
    const focusTimer = window.setTimeout(() => directoryTriggerRef.current?.focus(), 0);
    return () => window.clearTimeout(focusTimer);
  }, [directoryBrowserOpen, open]);
  const locked = running || passed || armed;
  const selectionProblem = recordingSelectionProblem(recordingMode, selectedPodKeys.size);
  const selectedDevices = devices.filter((device) => selectedPodKeys.has(device.key));
  const plannedRunDirectory = requestedDirectory.trim().length > 0
    ? `${requestedDirectory.replace(/[\\/]+$/, "")}\\${runLabel.trim() || "RUN"}-###`
    : "尚未选择保存位置";
  const selectedDeviceLabel = selectedDevices.length === 0
    ? "尚未选择"
    : selectedDevices.length === 1
      ? selectedDevices[0].displayName
      : `${selectedDevices.length} 台设备`;
  const selectedDeviceDetail = selectedDevices.length === 0
    ? recordingMode === "single" ? "选择一个 Preview 设备" : "选择 2–8 台设备"
    : selectedDevices.length === 1
      ? selectedDevices[0].routeLabel
      : selectedDevices.map((device) => device.displayName).join("、");
  const setupProblem = runLabel.trim().length === 0
    ? "请填写 Run 名称前缀。"
    : requestedDirectory.trim().length === 0
      ? "请选择保存位置。"
      : plannedDurationHours <= 0
        ? "计划时长必须大于 0。"
        : selectionProblem;
  const readiness = !finalOutputReady
    ? {
      state: "blocked",
      rootCause: "nwb-output-unavailable",
      shortLabel: "不可记录",
      summaryDetail: "查看下方原因",
      title: "当前不能开始正式记录",
      detail: "NWB 输出模块尚未接入。",
    }
    : running
      ? {
        state: "working",
        rootCause: undefined,
        shortLabel: "检查中",
        summaryDetail: "请稍候",
        title: "正在检查记录条件",
        detail: adapterScope === "mock" ? "正在分配模拟名称。" : "正在创建新的记录目录。",
      }
      : armed
        ? {
          state: "ready",
          rootCause: undefined,
          shortLabel: "可以开始",
          summaryDetail: "设备和保存位置已锁定",
          title: adapterScope === "mock" ? "模拟流程已准备好" : "可以开始记录",
          detail: adapterScope === "mock" ? "可以继续验证记录控制流程。" : "设备和保存位置已锁定。",
        }
        : passed
          ? {
            state: "ready",
            rootCause: undefined,
            shortLabel: "可准备记录",
            summaryDetail: "下一步锁定本次设置",
            title: adapterScope === "mock" ? "模拟检查已通过" : "记录条件已通过",
            detail: "点击“准备开始记录”锁定本次设置。",
          }
          : setupProblem
            ? {
              state: "needs-setup",
              rootCause: "recording-setup-incomplete",
              shortLabel: "设置未完成",
              summaryDetail: "补全上方设置",
              title: "记录设置尚未完成",
              detail: setupProblem,
            }
            : {
              state: "pending",
              rootCause: undefined,
              shortLabel: "待检查",
              summaryDetail: "设置完成",
              title: "等待检查记录条件",
              detail: adapterScope === "mock"
                ? "检查会分配模拟名称，不创建文件。"
                : "检查通过后创建新目录；不会覆盖已有记录。",
            };
  const canPreflight = !locked
    && runLabel.trim().length > 0
    && requestedDirectory.trim().length > 0
    && plannedDurationHours > 0
    && finalOutputReady
    && selectionProblem === null;
  if (!open) return null;

  return (
    <div
      ref={backdropRef}
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) requestClose();
      }}
    >
      <section
        ref={dialogRef}
        tabIndex={-1}
        className={`dialog preflight-dialog recording-setup-dialog${directoryBrowserOpen ? " run-directory-dialog" : ""}`}
        data-testid="recording-setup-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="preflight-title"
        aria-describedby="preflight-description"
      >
        <header className="dialog-header">
          <div>
            <span className="instrument-kicker">{directoryBrowserOpen
              ? "RUN ROOT · LOCAL FILESYSTEM"
              : `${adapterScope.toUpperCase()} RECORDING SETUP · ${recordingMode.toUpperCase()}`}</span>
            <h2 id="preflight-title">{directoryBrowserOpen
              ? "选择 Run 根目录"
              : recordingMode === "single" ? "单设备记录设置" : "多设备记录设置"}</h2>
            <p id="preflight-description">
              {directoryBrowserOpen
                ? "选择一个现有文件夹作为本次记录的保存位置。"
                : recordingMode === "single"
                ? "确认记录设备、保存位置和最终文件，然后检查记录条件。"
                : "选择 2–8 台记录设备，并保存到同一个 Run。"}
            </p>
          </div>
          <button
            className="dialog-close"
            type="button"
            aria-label={directoryBrowserOpen ? "返回记录设置" : "关闭记录设置"}
            data-modal-initial-focus={directoryBrowserOpen ? undefined : ""}
            onClick={requestClose}
          >
            ×
          </button>
        </header>

        {directoryBrowserOpen ? (
          <Suspense fallback={<div className="dialog-body" role="status">正在加载文件夹列表…</div>}>
            <RunDirectoryBrowserView
              initialDirectory={requestedDirectory}
              listing={directoryBrowserListing}
              loading={directoryBrowserBusy}
              errorMessage={directoryBrowserError}
              onBrowse={onBrowseDirectory}
              onUseCurrent={onUseDirectory}
              onCancel={onCloseDirectoryBrowser}
            />
          </Suspense>
        ) : <>
        <div className="dialog-body">
          {!passed && !armed ? <>
          <div className="recording-setup-grid">
            <div className="recording-field recording-field--wide">
              <label htmlFor="recording-run-root">保存位置 · Run 根目录</label>
              <div className="recording-directory-control">
                <input
                  id="recording-run-root"
                  type="text"
                  value={requestedDirectory}
                  disabled={locked}
                  spellCheck={false}
                  aria-describedby="recording-run-root-help"
                  onChange={(event) => onRequestedDirectoryChange(event.currentTarget.value)}
                />
                <button
                  ref={directoryTriggerRef}
                  className="instrument-button instrument-button--secondary recording-directory-picker"
                  data-testid="run-directory-browser-open"
                  type="button"
                  disabled={locked || !directoryBrowserAvailable}
                  title={directoryBrowserAvailable ? "浏览本机文件夹" : "文件夹浏览仅在 Forge 桌面版可用"}
                  onClick={onOpenDirectoryBrowser}
                >
                  <FolderOpen size={16} aria-hidden="true" />
                  浏览文件夹…
                </button>
              </div>
              <small id="recording-run-root-help">{adapterScope === "mock"
                ? "模拟模式只分配名称。"
                : "检查通过后创建新目录；不会覆盖已有记录。"}</small>
            </div>
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
              <small>自动追加 -001、-002…</small>
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
              <small>最长 24 小时。</small>
            </label>
          </div>

          <fieldset className="recording-device-selection" disabled={locked}>
            <legend>{recordingMode === "single" ? "单设备记录对象" : "多设备记录对象 · 2–8 台"}</legend>
            <p>
              {recordingMode === "single"
                ? "使用当前正在预览的设备。"
                : "逐项选择要写入本次 Run 的设备。"}
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
          </fieldset>
          </> : null}

          <section
            className="preflight-operator-summary"
            aria-label="记录准备摘要"
            data-testid="preflight-operator-summary"
            data-readiness={readiness.state}
          >
            <div data-preflight-conclusion="devices" data-state={selectedDevices.length > 0 ? "selected" : "missing"}>
              <span>记录设备</span>
              <strong title={selectedDevices.map((device) => device.displayName).join("、")}>{selectedDeviceLabel}</strong>
              <small>{selectedDeviceDetail}</small>
            </div>
            <div
              data-preflight-conclusion="save-location"
              data-allocation-state={recordingTarget?.directoryCreateDisposition ?? "pending"}
            >
              <span>保存位置</span>
              <strong title={recordingTarget?.resolvedRunDirectory ?? plannedRunDirectory}>
                {recordingTarget?.resolvedRunDirectory ?? "尚未创建"}
              </strong>
              <small>{recordingTarget
                ? recordingTarget.directoryCreateDisposition === "created_new" ? "新目录已创建" : "模拟名称已分配"
                : plannedRunDirectory}</small>
            </div>
            <div
              data-preflight-conclusion="final-output"
              data-state={finalOutputReady ? "available" : "unavailable"}
            >
              <span>最终文件</span>
              <strong>{finalOutputLabel}</strong>
              <small>{adapterScope === "mock"
                ? "模拟流程不产生文件"
                : finalOutputReady ? "记录结束时生成并验证" : "需要接入 NWB 输出模块"}</small>
            </div>
            <div data-preflight-conclusion="readiness" data-state={readiness.state}>
              <span>当前状态</span>
              <strong>{readiness.shortLabel}</strong>
              <small>{readiness.summaryDetail}</small>
            </div>
          </section>

          <div
            className={`arm-boundary-callout${readiness.state === "ready" ? " is-ready" : ""}${readiness.state === "blocked" ? " is-blocked" : ""}`}
            role={readiness.state === "blocked" || readiness.state === "needs-setup" ? "alert" : "status"}
            data-root-cause={readiness.rootCause}
          >
            <LockKeyhole size={18} aria-hidden="true" />
            <div>
              <strong>{readiness.title}</strong>
              <span>{readiness.detail}</span>
            </div>
          </div>

          <details className="preflight-technical-details">
            <summary>
              <span>
                <Wrench size={17} aria-hidden="true" />
                <span>
                  <strong>技术详情</strong>
                  <small>设备身份、路径回执与适配器证据</small>
                </span>
              </span>
              <ChevronDown className="preflight-technical-details__chevron" size={18} aria-hidden="true" />
            </summary>
            <div className="preflight-technical-details__body">
              {recordingTarget ? (
                <div className="recording-reservation">
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
                <div className="recording-reservation is-pending">
                  <FolderLock size={18} aria-hidden="true" />
                  <div>
                    <span>尚无目录分配回执</span>
                    <strong>{plannedRunDirectory}</strong>
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

              <div className="preflight-technical-receipt">
                <span>写入互锁回执</span>
                <code>{receiptId ?? "尚无 command receipt"}</code>
                <small>“准备开始记录”只锁定本次写入设置，不会自行开始记录。</small>
              </div>
            </div>
          </details>
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
              disabled={!passed || running || !finalOutputReady}
              onClick={onRequestArm}
            >
              <LockKeyhole size={17} aria-hidden="true" />
              准备开始记录
            </button>
          )}
        </footer>
        </>}
      </section>
    </div>
  );
}
