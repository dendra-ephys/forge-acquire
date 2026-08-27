import { Cable, Clock3, Cpu, ShieldX } from "lucide-react";
import type {
  CapabilityEvidence,
  ControlConnectionState,
} from "../adapters/acquireAdapter";

export interface HardwareStatusCardProps {
  connection: ControlConnectionState;
  stale: boolean;
  snapshotSequence: bigint;
  observedAtMonotonicMs: number;
  evidenceHash: string;
  capabilities: readonly CapabilityEvidence[];
}

function compactHash(hash: string | null): string {
  return hash ? `${hash.slice(0, 10)}…${hash.slice(-8)}` : "none";
}

export function HardwareStatusCard({
  connection,
  stale,
  snapshotSequence,
  observedAtMonotonicMs,
  evidenceHash,
  capabilities,
}: HardwareStatusCardProps) {
  return (
    <section className="hardware-status" aria-labelledby="hardware-status-title">
      <header>
        <div>
          <span className="instrument-kicker">DAEMON SNAPSHOT</span>
          <h2 id="hardware-status-title">证据边界</h2>
        </div>
        <span className={`snapshot-freshness${stale ? " is-stale" : ""}`}>
          {stale ? "STALE" : connection.toUpperCase()}
        </span>
      </header>

      <dl className="snapshot-readout">
        <div><dt><Cpu size={14} aria-hidden="true" />Sequence</dt><dd>{snapshotSequence.toString()}</dd></div>
        <div><dt><Clock3 size={14} aria-hidden="true" />Observed</dt><dd>{Math.round(observedAtMonotonicMs)} ms</dd></div>
        <div><dt><Cable size={14} aria-hidden="true" />Evidence</dt><dd title={evidenceHash}>{compactHash(evidenceHash)}</dd></div>
      </dl>

      <div className="capability-matrix">
        {capabilities.map((capability) => (
          <div className={`capability-row capability-row--${capability.status}`} key={capability.id}>
            <ShieldX size={14} aria-hidden="true" />
            <div>
              <strong>{capability.id.replaceAll("_", " ")}</strong>
              <span>{capability.summary}</span>
            </div>
            <em>{capability.status.replaceAll("_", " ")}</em>
          </div>
        ))}
      </div>

      <p className="snapshot-boundary-copy">
        此卡只渲染 adapter snapshot；不读取 Tauri、named pipe 或 USB，也不由通道形状推测硬件能力。
      </p>
    </section>
  );
}

