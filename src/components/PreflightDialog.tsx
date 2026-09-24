import {
  FolderOpen,
  LockKeyhole,
  Play,
  RefreshCw,
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

export function PreflightDialog({
  open,
  running,
  passed,
  armed,
  recordingMode,
  adapterScope,
  finalOutputReady,
  runLabel,
  requestedDirectory,
  plannedDurationHours,
  devices,
  selectedPodKeys,
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
