import type {
  AcquireLifecycleState,
  CommandReceipt,
  PreviewSessionState,
} from "../adapters/acquireAdapter";
import type { ReactNode } from "react";

interface RunSpineProps {
  lifecycle: AcquireLifecycleState;
  previewState: PreviewSessionState;
  lastCommand: CommandReceipt | null;
  result?: ReactNode;
}

const LIFECYCLE_RANK: Record<AcquireLifecycleState, number> = {
  disconnected: 0,
  connected_idle: 0,
  preflighting: 1,
  preflight_passed: 1,
  arm_requested: 1,
  armed: 1,
  start_requested: 2,
  recording: 2,
  stop_requested: 3,
  recording_stopped: 3,
  finalizing: 3,
  finalized: 4,
  recovery_required: 4,
};

const STEPS = [
  { label: "Preview", short: "Preview" },
  { label: "Ready", short: "Ready" },
  { label: "Recording", short: "Recording" },
  { label: "Saving", short: "Saving" },
  { label: "Result", short: "Result" },
] as const;

export function RunSpine({ lifecycle, previewState, lastCommand, result }: RunSpineProps) {
  const rank = LIFECYCLE_RANK[lifecycle];
  const isFault = lifecycle === "recovery_required";
  const lastCommandLabel = lastCommand?.intent === "stop_recording"
    ? "END & SAVE"
    : lastCommand?.intent.replaceAll("_", " ").toUpperCase();

  return (
    <section className="run-spine" aria-label="Run lifecycle">
      <ol className="run-spine__steps">
        {STEPS.map((step, index) => {
          const state = index < rank ? "complete" : index === rank ? "active" : "pending";
          return (
            <li
              key={step.short}
              className={`run-spine__step is-${state}${isFault && index === rank ? " has-fault" : ""}`}
              aria-current={state === "active" ? "step" : undefined}
            >
              <i aria-hidden="true" />
              <span>{step.label}</span>
            </li>
          );
        })}
      </ol>
      {result ? <div className="run-spine__result">{result}</div> : null}
      <span
        className="sr-only"
        role={lastCommand?.accepted === false ? "alert" : "status"}
      >
        {lastCommand
          ? `${lastCommand.accepted ? "Accepted" : "Rejected"}: ${lastCommandLabel}; ${lastCommand.receiptId}`
          : `${previewState === "live" ? "Preview live" : "Standby"}; waiting for a control command`}
      </span>
    </section>
  );
}
