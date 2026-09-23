import { AlertTriangle, Beaker, RotateCcw, Siren } from "lucide-react";

export interface FaultItem {
  id: string;
  severity: "warning" | "error";
  title: string;
  detail: string;
  recovery: string;
  recoverable: boolean;
}

export interface FaultOption {
  id: string;
  label: string;
  description: string;
  enabled: boolean;
}

export interface FaultRecoveryPanelProps {
  faults: readonly FaultItem[];
  options: readonly FaultOption[];
  selectedFaultId: string;
  onSelectFault: (faultId: string) => void;
  onInject: () => void;
  onClearResolved: () => void;
  busy: boolean;
  injectionAvailable: boolean;
}

export function FaultRecoveryPanel({
  faults,
  options,
  selectedFaultId,
  onSelectFault,
  onInject,
  onClearResolved,
  busy,
  injectionAvailable,
}: FaultRecoveryPanelProps) {
  const selected = options.find((option) => option.id === selectedFaultId) ?? options[0];
  const hasRecoverableFault = faults.some((fault) => fault.recoverable);

  return (
    <section className={`fault-recovery${faults.length ? " has-fault" : ""}`} aria-labelledby="fault-recovery-title">
      <header>
        <div>
          <span className="instrument-kicker">FAULT / RECOVERY</span>
          <h2 id="fault-recovery-title">Latched faults</h2>
        </div>
        <span className="fault-count">{faults.length}</span>
      </header>

      {faults.length ? (
        <div className="fault-list" role="alert" aria-live="assertive">
          {faults.map((fault) => (
            <article className={`fault-item fault-item--${fault.severity}`} key={fault.id}>
              {fault.severity === "error" ? <Siren size={17} aria-hidden="true" /> : <AlertTriangle size={17} aria-hidden="true" />}
              <div>
                <strong>{fault.title}</strong>
                <span>{fault.detail}</span>
                <small>Recovery: {fault.recovery}</small>
              </div>
            </article>
          ))}
          <button
            className="fault-clear"
            type="button"
            disabled={busy || !hasRecoverableFault}
            title={hasRecoverableFault ? "Clear notices marked recoverable by the adapter" : "Current faults cannot be cleared; failure evidence must be retained"}
            onClick={onClearResolved}
          >
            <RotateCcw size={14} aria-hidden="true" />
            {hasRecoverableFault ? "Clear recoverable notices" : "Failure evidence latched"}
          </button>
        </div>
      ) : (
        <p className="fault-empty">No latched faults. Transient toasts never replace Run state.</p>
      )}

      {injectionAvailable ? <div className="fault-injector">
        <div className="fault-injector__title">
          <Beaker size={15} aria-hidden="true" />
          <strong>Mock fault injection</strong>
          <span>TEST ONLY</span>
        </div>
        <select
          aria-label="Choose a mock fault"
          value={selectedFaultId}
          onChange={(event) => onSelectFault(event.target.value)}
        >
          {options.map((option) => (
            <option key={option.id} value={option.id} disabled={!option.enabled}>
              {option.label}{option.enabled ? "" : " · unavailable in this phase"}
            </option>
          ))}
        </select>
        <p>{selected?.description}</p>
        <button
          className="instrument-button instrument-button--fault"
          type="button"
          disabled={busy || !selected?.enabled}
          onClick={onInject}
        >
          Inject selected fault
        </button>
      </div> : (
        <div className="fault-injector fault-injector--unavailable" role="note">
          <div className="fault-injector__title">
            <Beaker size={15} aria-hidden="true" />
            <strong>Fault injection unavailable</strong>
            <span>REAL JOURNAL PROTECTED</span>
          </div>
          <p>The Tauri software path writes a real create-new journal, so the GUI cannot inject packet-loss or persistence faults. Browser mock QA retains the test port.</p>
        </div>
      )}
    </section>
  );
}
