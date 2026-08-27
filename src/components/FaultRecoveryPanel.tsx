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
          <h2 id="fault-recovery-title">锁存故障</h2>
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
                <small>恢复：{fault.recovery}</small>
              </div>
            </article>
          ))}
          <button
            className="fault-clear"
            type="button"
            disabled={busy || !hasRecoverableFault}
            title={hasRecoverableFault ? "清除 adapter 标记为 recoverable 的提示" : "当前故障不可清除；必须保留失败证据"}
            onClick={onClearResolved}
          >
            <RotateCcw size={14} aria-hidden="true" />
            {hasRecoverableFault ? "清除可恢复提示" : "失败证据已锁存"}
          </button>
        </div>
      ) : (
        <p className="fault-empty">无锁存故障。告警不会以短暂 toast 代替 Run 状态。</p>
      )}

      {injectionAvailable ? <div className="fault-injector">
        <div className="fault-injector__title">
          <Beaker size={15} aria-hidden="true" />
          <strong>Mock fault injection</strong>
          <span>测试专用</span>
        </div>
        <select
          aria-label="选择 mock 故障"
          value={selectedFaultId}
          onChange={(event) => onSelectFault(event.target.value)}
        >
          {options.map((option) => (
            <option key={option.id} value={option.id} disabled={!option.enabled}>
              {option.label}{option.enabled ? "" : " · 当前阶段不可注入"}
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
          注入选定故障
        </button>
      </div> : (
        <div className="fault-injector fault-injector--unavailable" role="note">
          <div className="fault-injector__title">
            <Beaker size={15} aria-hidden="true" />
            <strong>Fault injection unavailable</strong>
            <span>REAL JOURNAL PROTECTED</span>
          </div>
          <p>当前 Tauri 软件记录路径会写入真实 create-new journal，因此不允许 GUI 注入丢包或持久化故障；浏览器 mock QA 仍保留测试端口。</p>
        </div>
      )}
    </section>
  );
}
