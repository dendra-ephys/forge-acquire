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
}

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

export function RunIntegrityRail({ lifecycle, evidence, runReceipt, scope }: RunIntegrityRailProps) {
  const result = deriveRunOutput(lifecycle, evidence, runReceipt, scope);

  return (
    <section
      className={`integrity-rail integrity-rail--${result.state}`}
      data-run-result-state={result.state}
      role={result.urgent ? "alert" : "status"}
      aria-live={result.urgent ? "assertive" : "polite"}
      aria-label={`本次记录状态：${result.label}`}
    >
      <StateIcon state={result.state} />
      <span className="integrity-rail__kicker">RUN RESULT</span>
      <strong>{result.label}</strong>
      {result.detail ? <span className="integrity-rail__detail">{result.detail}</span> : null}
    </section>
  );
}
