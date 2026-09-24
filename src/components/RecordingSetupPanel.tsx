import { FolderOpen, LockKeyhole, Play, RefreshCw, X } from "lucide-react";
import type { AdapterScope } from "../adapters/acquireAdapter";
import "./RecordingSetupPanel.css";

export interface RecordingSetupPanelProps {
  running: boolean;
  passed: boolean;
  armed: boolean;
  adapterScope: AdapterScope;
  finalOutputReady: boolean;
  runLabel: string;
  requestedDirectory: string;
  plannedDurationHours: number;
  selectionValid: boolean;
  directoryBrowserAvailable: boolean;
  onRunLabelChange: (value: string) => void;
  onRequestedDirectoryChange: (value: string) => void;
  onOpenDirectoryBrowser: () => void;
  onPlannedDurationHoursChange: (value: number) => void;
  onRunPreflight: () => void;
  onRequestArm: () => void;
  onClose: () => void;
}

export function RecordingSetupPanel({
  running,
  passed,
  armed,
  adapterScope,
  finalOutputReady,
  runLabel,
  requestedDirectory,
  plannedDurationHours,
  selectionValid,
  directoryBrowserAvailable,
  onRunLabelChange,
  onRequestedDirectoryChange,
  onOpenDirectoryBrowser,
  onPlannedDurationHoursChange,
  onRunPreflight,
  onRequestArm,
  onClose,
}: RecordingSetupPanelProps) {
  const locked = running || passed || armed;
  const setupProblem = !finalOutputReady
    ? "Recording output is unavailable."
    : !selectionValid
      ? "Select one Pod for this recording."
      : runLabel.trim().length === 0
        ? "Enter a recording name."
        : requestedDirectory.trim().length === 0
          ? "Choose a save location."
          : plannedDurationHours <= 0
            ? "Duration must be greater than zero."
            : null;
  const canAllocate = !locked && setupProblem === null;

  return (
    <section className="recording-setup-panel" aria-labelledby="recording-setup-panel-title">
      <header className="recording-setup-panel__header">
        <div>
          <span>RECORDING SETUP</span>
          <strong id="recording-setup-panel-title">Single Pod</strong>
        </div>
        <button type="button" aria-label="Close recording setup" onClick={onClose}>
          <X size={15} aria-hidden="true" />
        </button>
      </header>

      <div className="recording-setup-panel__fields">
        <div className="recording-setup-panel__field recording-setup-panel__field--path">
          <label htmlFor="inline-recording-run-root">Save location</label>
          <div>
            <input
              id="inline-recording-run-root"
              type="text"
              value={requestedDirectory}
              disabled={locked}
              spellCheck={false}
              onChange={(event) => onRequestedDirectoryChange(event.currentTarget.value)}
            />
            <button
              className="recording-setup-panel__browse"
              type="button"
              aria-label="Browse save locations"
              disabled={locked || !directoryBrowserAvailable}
              title={directoryBrowserAvailable ? "Browse local folders" : "Folder browsing is available only in Forge Desktop"}
              onClick={onOpenDirectoryBrowser}
            >
              <FolderOpen size={15} aria-hidden="true" />
            </button>
          </div>
        </div>

        <label className="recording-setup-panel__field">
          <span>Recording name</span>
          <input
            type="text"
            value={runLabel}
            disabled={locked}
            maxLength={80}
            spellCheck={false}
            onChange={(event) => onRunLabelChange(event.currentTarget.value)}
          />
        </label>

        <label className="recording-setup-panel__field recording-setup-panel__field--duration">
          <span>Hours</span>
          <input
            type="number"
            min={0.1}
            max={24}
            step={0.5}
            value={plannedDurationHours}
            disabled={locked}
            onChange={(event) => onPlannedDurationHoursChange(Number(event.currentTarget.value))}
          />
        </label>
      </div>

      {setupProblem ? <p className="recording-setup-panel__problem" role="alert">{setupProblem}</p> : null}

      <div className="recording-setup-panel__actions">
        {!passed && !armed ? (
          <button type="button" disabled={!canAllocate || running} onClick={onRunPreflight}>
            {running ? <RefreshCw className="is-spinning" size={15} aria-hidden="true" /> : <Play size={15} aria-hidden="true" />}
            {running ? "Checking…" : adapterScope === "mock" ? "Use demo target" : "Choose target"}
          </button>
        ) : armed ? (
          <button type="button" onClick={onClose}>Done</button>
        ) : (
          <button type="button" disabled={!finalOutputReady || running} onClick={onRequestArm}>
            <LockKeyhole size={15} aria-hidden="true" />
            Use this setup
          </button>
        )}
      </div>
    </section>
  );
}
