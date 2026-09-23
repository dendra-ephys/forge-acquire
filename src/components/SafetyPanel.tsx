import { LockKeyhole, OctagonAlert, ShieldOff, Zap } from "lucide-react";
import type { CapabilityEvidence } from "../adapters/acquireAdapter";

export interface SafetyPanelProps {
  stimulation: CapabilityEvidence;
  closedLoop: CapabilityEvidence;
  armState: "unavailable" | "disarmed" | "arm_requested" | "armed" | "fault_latched";
  physicalEnable: "unknown" | "open" | "closed";
  canRequestArm: boolean;
  onRequestArm?: () => void;
}

export function SafetyPanel({
  stimulation,
  closedLoop,
  armState,
  physicalEnable,
  canRequestArm,
  onRequestArm,
}: SafetyPanelProps) {
  return (
    <section className="safety-panel" aria-labelledby="stim-arm-title">
      <header className="safety-panel__heading">
        <div>
          <span className="instrument-kicker instrument-kicker--danger">INDEPENDENT INTERLOCK</span>
          <h2 id="stim-arm-title">Stimulation Arm</h2>
        </div>
        <span className={`stim-state stim-state--${armState}`}>
          <Zap size={14} aria-hidden="true" />
          {armState.replaceAll("_", " ").toUpperCase()}
        </span>
      </header>

      <div className="stim-boundary-grid">
        <div><span>Recording Arm</span><strong>SEPARATE</strong></div>
        <div><span>Physical enable</span><strong>{physicalEnable.toUpperCase()}</strong></div>
        <div><span>Stim capability</span><strong>{stimulation.status.replaceAll("_", " ").toUpperCase()}</strong></div>
        <div><span>Closed loop</span><strong>{closedLoop.status.replaceAll("_", " ").toUpperCase()}</strong></div>
      </div>

      <div className="stim-blocker" role="note">
        <OctagonAlert size={17} aria-hidden="true" />
        <div>
          <strong>{stimulation.reasonCode}</strong>
          <span>{stimulation.summary}</span>
          <small>{closedLoop.summary}</small>
        </div>
      </div>

      <button
        className="instrument-button instrument-button--stim"
        type="button"
        disabled={!canRequestArm}
        onClick={onRequestArm}
      >
        {canRequestArm ? <LockKeyhole size={17} aria-hidden="true" /> : <ShieldOff size={17} aria-hidden="true" />}
        Request stimulation arm
      </button>
      <p>A button request cannot establish Armed. Only the SafetyArbiter and a matching hardware receipt can.</p>
    </section>
  );
}
