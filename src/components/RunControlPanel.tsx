import {
  CircleStop,
  Eye,
  EyeOff,
  Pause,
  Play,
  RefreshCw,
  UserRound,
  UsersRound,
} from "lucide-react";
import type { ReactNode } from "react";
import { InfoHint } from "./InfoHint";
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
  recording: boolean;
  recordingPaused: boolean;
  runOutput: RunOutputSummary;
  recoveryRequired: boolean;
  canStartPreview: boolean;
  canStopPreview: boolean;
  canSetupSingleRecording: boolean;
  canSetupMultiRecording: boolean;
  recordingSetupMode: RecordingSetupMode;
  recordingDeviceCount: number;
  previewDeviceName: string;
  canStart: boolean;
  canPauseRecording: boolean;
  canStopRecording: boolean;
  canRecover: boolean;
  canAcknowledgeFailed: boolean;
  onStartPreview: () => void;
  onStopPreview: () => void;
  onSetupSingleRecording: () => void;
  onSetupMultiRecording: () => void;
  onStart: () => void;
  onToggleRecordingPause: () => void;
  onStopRecording: () => void;
  onRecover: () => void;
  onAcknowledgeFailed: () => void;
  runStatus: ReactNode;
}

function targetReadoutLabel(target: RecordingTargetReservation): string {
  return target.directoryCreateDisposition === "created_new"
    ? "Directory created · no overwrite"
    : "Simulation name · no file created";
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
  recording,
  recordingPaused,
  runOutput,
  recoveryRequired,
  canStartPreview,
  canStopPreview,
  canSetupSingleRecording,
  canSetupMultiRecording,
  recordingSetupMode,
  recordingDeviceCount,
  previewDeviceName,
  canStart,
  canPauseRecording,
  canStopRecording,
  canRecover,
  canAcknowledgeFailed,
  onStartPreview,
  onStopPreview,
  onSetupSingleRecording,
  onSetupMultiRecording,
  onStart,
  onToggleRecordingPause,
  onStopRecording,
  onRecover,
  onAcknowledgeFailed,
  runStatus,
}: RunControlPanelProps) {
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
          <h2 id="run-control-title">Acquisition</h2>
        </div>
        <div className="instrument-section-heading__actions">
          <InfoHint label="About the current acquisition state" align="end">
            <strong>{phaseLabel}</strong>
            <span>{phaseDetail}</span>
          </InfoHint>
          <span className={"phase-chip phase-chip--" + phaseTone}>
            {phaseLabel}
          </span>
        </div>
      </header>

      <div className="run-readout" data-phase={phase}>
        <span className="run-readout__label">CURRENT RUN</span>
        <strong>{runId ?? "NO RUN"}</strong>
      </div>

      <div className="run-actions">
        <div className="recording-mode-actions" role="group" aria-label="Choose the recording scope">
          <button
            className="instrument-button instrument-button--secondary instrument-button--recording-mode"
            type="button"
            disabled={!canSetupSingleRecording || busy || (recordingTarget !== null && recordingSetupMode !== "single")}
            aria-label={recordingTarget && recordingSetupMode === "single" ? "Open single-device setup" : "Single-device setup"}
            data-tooltip={`Single-device setup · ${previewDeviceName}`}
            onClick={onSetupSingleRecording}
          >
            <UserRound size={17} aria-hidden="true" />
            <span>Setup</span>
          </button>
          <button
            className="instrument-button instrument-button--secondary instrument-button--recording-mode"
            type="button"
            disabled={!canSetupMultiRecording || busy || (recordingTarget !== null && recordingSetupMode !== "multi")}
            aria-label={recordingTarget && recordingSetupMode === "multi" ? "Open multi-device setup" : "Multi-device setup"}
            data-tooltip="Multi-device setup · select 2–8 Pods"
            onClick={onSetupMultiRecording}
          >
            <UsersRound size={17} aria-hidden="true" />
            <span>Multi-Pod</span>
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
          className="instrument-button instrument-button--preview"
          type="button"
          aria-label={previewState === "live" ? "Stop Preview" : "Start Preview"}
          data-tooltip={previewState === "live" ? "Stop Preview" : "Start Preview"}
          disabled={busy || (previewState === "live" ? !canStopPreview : !canStartPreview)}
          onClick={previewState === "live" ? onStopPreview : onStartPreview}
        >
          {previewState === "live" ? <EyeOff size={17} aria-hidden="true" /> : <Eye size={17} aria-hidden="true" />}
          <span>{previewState === "live" ? "Stop Preview" : "Start Preview"}</span>
        </button>

        <button
          className="instrument-button instrument-button--record"
          type="button"
          aria-label={recordingDeviceCount > 0
            ? `Start recording · ${recordingDeviceCount} device${recordingDeviceCount === 1 ? "" : "s"}`
            : "Start recording"}
          disabled={!canStart || busy}
          onClick={onStart}
        >
          <Play size={18} fill="currentColor" aria-hidden="true" />
          Start Recording
        </button>

        <button
          className={`instrument-button instrument-button--pause${recordingPaused ? " is-active" : ""}`}
          type="button"
          aria-label={recordingPaused ? "Resume recording" : "Pause recording"}
          disabled={!canPauseRecording || busy}
          title={recordingPaused
            ? "Resume appending samples to the current recording."
            : "Pause source writes without ending or saving the current recording."}
          onClick={onToggleRecordingPause}
        >
          {recordingPaused
            ? <Play size={18} fill="currentColor" aria-hidden="true" />
            : <Pause size={18} aria-hidden="true" />}
          {recordingPaused ? "Resume" : "Pause"}
        </button>

        <button
          className="instrument-button instrument-button--stop"
          type="button"
          disabled={!canStopRecording || busy}
          aria-label="End recording"
          title="End input, drain, generate, validate, and publish the final NWB."
          onClick={onStopRecording}
        >
          <CircleStop size={18} aria-hidden="true" />
          End Recording
        </button>

        {recoveryRequired && canAcknowledgeFailed ? (
          <>
            <button
              className="instrument-button instrument-button--acknowledge-failed"
              type="button"
              disabled={busy}
              title="Close only the failed Run control context. Keep the partial journal; do not delete files or synthesize a seal."
              onClick={onAcknowledgeFailed}
            >
              <CircleStop size={17} aria-hidden="true" />
              Acknowledge failure
            </button>
            <p className="failed-run-retention-note">
              Closes only the control context. The partial journal is retained without deletion or a fabricated seal.
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
            The current snapshot provides no GUI recovery command. Keep the partial journal and wait for daemon state or manual inspection.
          </div>
        ) : null}
      </div>

      <div className="run-control__device-status">
        {runStatus}
      </div>
    </section>
  );
}
