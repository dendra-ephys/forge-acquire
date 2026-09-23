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
    return selectedCount === 1 ? null : "Single-device recording must freeze exactly one current Preview Pod.";
  }
  if (selectedCount < 2) return "Multi-device recording requires at least 2 explicitly selected Pods.";
  if (selectedCount > 8) return "A single Run can record at most 8 Pods.";
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
  if (status === "pass") return "Passed";
  if (status === "pending") return "Pending";
  if (status === "blocked") return "Blocked";
  if (status === "qualification_required") return "Qualification required";
  return "Unavailable";
}

function targetAllocationLabel(target: RecordingTargetReservation): string {
  return target.directoryCreateDisposition === "created_new"
    ? "New directory created · no overwrite"
    : "Simulation name allocated · no file created";
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
    : "No save location selected";
  const selectedDeviceLabel = selectedDevices.length === 0
    ? "None selected"
    : selectedDevices.length === 1
      ? selectedDevices[0].displayName
      : `${selectedDevices.length} devices`;
  const selectedDeviceDetail = selectedDevices.length === 0
    ? recordingMode === "single" ? "Select one Preview device" : "Select 2–8 devices"
    : selectedDevices.length === 1
      ? selectedDevices[0].routeLabel
      : selectedDevices.map((device) => device.displayName).join("、");
  const setupProblem = runLabel.trim().length === 0
    ? "Enter a Run name prefix."
    : requestedDirectory.trim().length === 0
      ? "Choose a save location."
      : plannedDurationHours <= 0
        ? "Planned duration must be greater than zero."
        : selectionProblem;
  const readiness = !finalOutputReady
    ? {
      state: "blocked",
      rootCause: "nwb-output-unavailable",
      shortLabel: "Unavailable",
      summaryDetail: "See reason below",
      title: "Formal recording is unavailable",
      detail: "The NWB output module is not connected.",
    }
    : running
      ? {
        state: "working",
        rootCause: undefined,
        shortLabel: "Checking",
        summaryDetail: "Please wait",
        title: "Checking recording conditions",
        detail: adapterScope === "mock" ? "Allocating a simulation name." : "Creating a new recording directory.",
      }
      : armed
        ? {
          state: "ready",
          rootCause: undefined,
          shortLabel: "Ready",
          summaryDetail: "Devices and destination locked",
          title: adapterScope === "mock" ? "Simulation ready" : "Ready to record",
          detail: adapterScope === "mock" ? "Continue to validate the recording control flow." : "Devices and destination are locked.",
        }
        : passed
          ? {
            state: "ready",
            rootCause: undefined,
            shortLabel: "Ready to arm",
            summaryDetail: "Lock this setup next",
            title: adapterScope === "mock" ? "Simulation check passed" : "Recording checks passed",
            detail: "Choose Arm recording to lock this setup.",
          }
          : setupProblem
            ? {
              state: "needs-setup",
              rootCause: "recording-setup-incomplete",
              shortLabel: "Incomplete",
              summaryDetail: "Complete the setup above",
              title: "Recording setup is incomplete",
              detail: setupProblem,
            }
            : {
              state: "pending",
              rootCause: undefined,
              shortLabel: "Ready to check",
              summaryDetail: "Setup complete",
              title: "Ready to check recording conditions",
              detail: adapterScope === "mock"
                ? "The check allocates a simulation name without creating a file."
                : "A passed check creates a new directory and never overwrites an existing recording.",
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
              ? "Choose Run root"
              : recordingMode === "single" ? "Single-device recording" : "Multi-device recording"}</h2>
            <p id="preflight-description">
              {directoryBrowserOpen
                ? "Choose an existing folder as the save location for this recording."
                : recordingMode === "single"
                ? "Confirm the device, save location, and final output, then check recording conditions."
                : "Select 2–8 devices to save in one Run."}
            </p>
          </div>
          <button
            className="dialog-close"
            type="button"
            aria-label={directoryBrowserOpen ? "Back to recording setup" : "Close recording setup"}
            data-modal-initial-focus={directoryBrowserOpen ? undefined : ""}
            onClick={requestClose}
          >
            ×
          </button>
        </header>

        {directoryBrowserOpen ? (
          <Suspense fallback={<div className="dialog-body" role="status">Loading folders…</div>}>
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
              <label htmlFor="recording-run-root">Save location · Run root</label>
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
                  title={directoryBrowserAvailable ? "Browse local folders" : "Folder browsing is available only in Forge Desktop"}
                  onClick={onOpenDirectoryBrowser}
                >
                  <FolderOpen size={16} aria-hidden="true" />
                  Browse…
                </button>
              </div>
              <small id="recording-run-root-help">{adapterScope === "mock"
                ? "Simulation mode allocates a name only."
                : "A passed check creates a new directory and never overwrites an existing recording."}</small>
            </div>
            <label className="recording-field">
              <span>Run name prefix</span>
              <input
                type="text"
                value={runLabel}
                disabled={locked}
                maxLength={80}
                spellCheck={false}
                onChange={(event) => onRunLabelChange(event.currentTarget.value)}
              />
              <small>Automatically appends -001, -002…</small>
            </label>
            <label className="recording-field">
              <span>Planned duration · h</span>
              <input
                type="number"
                min={0.1}
                max={24}
                step={0.5}
                value={plannedDurationHours}
                disabled={locked}
                onChange={(event) => onPlannedDurationHoursChange(Number(event.currentTarget.value))}
              />
              <small>Maximum 24 hours.</small>
            </label>
          </div>

          <fieldset className="recording-device-selection" disabled={locked}>
            <legend>{recordingMode === "single" ? "Recording device" : "Recording devices · 2–8"}</legend>
            <p>
              {recordingMode === "single"
                ? "Uses the device currently shown in Preview."
                : "Select each device to include in this Run."}
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
            aria-label="Recording readiness summary"
            data-testid="preflight-operator-summary"
            data-readiness={readiness.state}
          >
            <div data-preflight-conclusion="devices" data-state={selectedDevices.length > 0 ? "selected" : "missing"}>
              <span>Devices</span>
              <strong title={selectedDevices.map((device) => device.displayName).join("、")}>{selectedDeviceLabel}</strong>
              <small>{selectedDeviceDetail}</small>
            </div>
            <div
              data-preflight-conclusion="save-location"
              data-allocation-state={recordingTarget?.directoryCreateDisposition ?? "pending"}
            >
              <span>Save location</span>
              <strong title={recordingTarget?.resolvedRunDirectory ?? plannedRunDirectory}>
                {recordingTarget?.resolvedRunDirectory ?? "Not created"}
              </strong>
              <small>{recordingTarget
                ? recordingTarget.directoryCreateDisposition === "created_new" ? "New directory created" : "Simulation name allocated"
                : plannedRunDirectory}</small>
            </div>
            <div
              data-preflight-conclusion="final-output"
              data-state={finalOutputReady ? "available" : "unavailable"}
            >
              <span>Final output</span>
              <strong>{finalOutputLabel}</strong>
              <small>{adapterScope === "mock"
                ? "Simulation creates no file"
                : finalOutputReady ? "Generated and validated when recording ends" : "NWB output module required"}</small>
            </div>
            <div data-preflight-conclusion="readiness" data-state={readiness.state}>
              <span>Current status</span>
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
                  <strong>Technical details</strong>
                  <small>Device identities, route receipts, and adapter evidence</small>
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
                    <span>No directory reservation receipt</span>
                    <strong>{plannedRunDirectory}</strong>
                    <code>Final suffix and full path require an adapter reservation receipt</code>
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
                <span>Write-interlock receipt</span>
                <code>{receiptId ?? "No command receipt"}</code>
                <small>Arm recording locks this setup; it does not start recording.</small>
              </div>
            </div>
          </details>
        </div>

        <footer className="dialog-actions">
          <button className="instrument-button instrument-button--secondary" type="button" onClick={onCancel}>
            {armed ? "Done" : "Close"}
          </button>
          {!passed && !armed ? (
            <button
              className="instrument-button instrument-button--arm"
              type="button"
              disabled={!canPreflight || running}
              onClick={onRunPreflight}
            >
              {running ? <RefreshCw className="is-spinning" size={17} aria-hidden="true" /> : <Play size={17} aria-hidden="true" />}
              Check & allocate target
            </button>
          ) : armed ? null : (
            <button
              className="instrument-button instrument-button--arm"
              type="button"
              disabled={!passed || running || !finalOutputReady}
              onClick={onRequestArm}
            >
              <LockKeyhole size={17} aria-hidden="true" />
              Arm recording
            </button>
          )}
        </footer>
        </>}
      </section>
    </div>
  );
}
