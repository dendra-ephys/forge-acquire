import { AlertTriangle, CheckCircle2, CircleDot, Database, LoaderCircle } from "lucide-react";
import type {
  AcquireLifecycleState,
  AdapterScope,
  RunIntegrityEvidence,
  RunReceipt,
} from "../adapters/acquireAdapter";
import { deriveRunOutput, type RunOutputState } from "../core/runOutputState";

export interface RunIntegrityRailProps {
  lifecycle: AcquireLifecycleState;
  evidence: RunIntegrityEvidence;
  runReceipt: RunReceipt | null;
  scope: AdapterScope;
  recordingFileSize?: string;
  storageFree?: string;
  storageFreeBytes?: number | null;
  deviceName?: string;
  recordingPath?: string;
  recordingPaused?: boolean;
}

const LOW_STORAGE_THRESHOLD_BYTES = 20_000_000_000;

function StateIcon({ state }: { state: RunOutputState }) {
  if (state === "failed" || state === "raw_retained") {
    return <AlertTriangle size={18} aria-hidden="true" />;
  }
  if (state === "nwb_saved" || state === "mock_complete") {
    return <CheckCircle2 size={18} aria-hidden="true" />;
  }
  if (state === "saving") return <LoaderCircle className="is-spinning" size={18} aria-hidden="true" />;
  if (state === "recording") return <CircleDot size={18} aria-hidden="true" />;
  return <Database size={18} aria-hidden="true" />;
}

export function RunIntegrityRail({
  lifecycle,
  evidence,
  runReceipt,
  scope,
  recordingFileSize = "—",
  storageFree = "—",
  storageFreeBytes = null,
  deviceName = "No device selected",
  recordingPath = "Not configured",
  recordingPaused = false,
}: RunIntegrityRailProps) {
  const result = deriveRunOutput(lifecycle, evidence, runReceipt, scope);
  const visibleLabel = recordingPaused ? "Recording paused" : result.label;
  const storageLow = storageFreeBytes !== null
    && Number.isFinite(storageFreeBytes)
    && storageFreeBytes >= 0
    && storageFreeBytes < LOW_STORAGE_THRESHOLD_BYTES;
  const storageTooltip = [
    recordingPaused ? "Recording is paused; the Run remains open." : result.detail || result.label,
    `Device: ${deviceName}`,
    `Path: ${recordingPath}`,
    `File size: ${recordingFileSize}`,
    `Storage free: ${storageFree}`,
  ].join("\n");

  return (
    <section
      className={`integrity-rail integrity-rail--${result.state}`}
      data-run-result-state={result.state}
      role={result.urgent ? "alert" : "status"}
      aria-live={result.urgent ? "assertive" : "polite"}
      aria-label={`Recording status for ${deviceName}: ${visibleLabel}; path ${recordingPath}; file size ${recordingFileSize}; storage free ${storageFree}`}
      data-tooltip={storageTooltip}
      data-storage-low={storageLow ? "true" : "false"}
      tabIndex={0}
    >
      <StateIcon state={result.state} />
      <span className="integrity-rail__kicker">DEVICE RECORDING</span>
      <strong>{visibleLabel}</strong>
      <span className="integrity-rail__device" title={deviceName}>{deviceName}</span>
      <dl className="integrity-rail__storage">
        <div><dt>PATH</dt><dd title={recordingPath}>{recordingPath}</dd></div>
        <div><dt>FILE</dt><dd>{recordingFileSize}</dd></div>
        <div><dt>FREE</dt><dd>{storageFree}</dd></div>
      </dl>
      {recordingPaused
        ? <span className="integrity-rail__detail">Run remains open; resume or end it.</span>
        : result.detail ? <span className="integrity-rail__detail">{result.detail}</span> : null}
    </section>
  );
}
