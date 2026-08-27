import {
  Activity,
  BrainCircuit,
  Clock3,
  DatabaseZap,
  FileHeart,
  PanelBottomClose,
  PanelBottomOpen,
  ShieldCheck,
} from "lucide-react";
import type {
  AcquireLifecycleState,
  EvidenceSlot,
  RunIntegrityEvidence,
  RunReceipt,
} from "../adapters/acquireAdapter";

export interface RunIntegrityRailProps {
  runId: string | null;
  lifecycle: AcquireLifecycleState;
  evidence: RunIntegrityEvidence;
  runReceipt: RunReceipt | null;
  synthetic: boolean;
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

interface EvidenceTrack {
  key: keyof RunIntegrityEvidence;
  label: string;
  short: string;
  purpose: string;
  icon: typeof Activity;
}

interface EvidenceGroup {
  key: "recording-core" | "optional-results";
  label: string;
  short: string;
  tracks: EvidenceTrack[];
}

const EVIDENCE_GROUPS: EvidenceGroup[] = [
  {
    key: "recording-core",
    label: "原始记录（必须）",
    short: "2 项共同决定是否安全",
    tracks: [
      {
        key: "acquisition",
        label: "数据接收与采集范围",
        short: "数据连续性",
        purpose: "确认计划内 sample 范围是否完整接收；有缺口就不能声明原始记录完整。",
        icon: Activity,
      },
      {
        key: "durability",
        label: "文件写入与封存",
        short: "持久化与封存",
        purpose: "确认数据已写入稳定介质并完成封口；必须与数据连续性同时确认。",
        icon: DatabaseZap,
      },
    ],
  },
  {
    key: "optional-results",
    label: "可选输出与外部回执",
    short: "3 项不反推原始记录安全",
    tracks: [
      {
        key: "nwb",
        label: "NWB 导出",
        short: "物化与验证",
        purpose: "确认已从封存 Run 生成并验证 NWB，供共享和后续分析；不能补救原始数据缺口。",
        icon: FileHeart,
      },
      {
        key: "analysis",
        label: "分析结果",
        short: "分析消费",
        purpose: "确认下游分析消费了哪个 Run 与配置并产生结果；不决定原始文件是否安全。",
        icon: BrainCircuit,
      },
      {
        key: "stimReceipt",
        label: "外部事件时间线",
        short: "外部事件",
        purpose: "把外部 Python、刺激或行为事件及时间基准绑定到 Run；可选、不授予刺激能力。",
        icon: Clock3,
      },
    ],
  },
];

function statusLabel(key: keyof RunIntegrityEvidence, slot: EvidenceSlot): string {
  if (key === "stimReceipt") {
    if (slot.status === "proven") return "时间线回执已确认";
    if (slot.status === "active") return "时间线进行中";
    if (slot.status === "pending") return "等待时间线回执";
  }

  switch (slot.status) {
    case "proven": return "回执已确认";
    case "active": return "进行中";
    case "pending": return "等待回执";
    case "degraded": return "降级";
    case "failed": return "失败";
    case "qualification_required": return "需要验证";
    case "unavailable": return "不可用";
    default: return "未开始";
  }
}

function compactHash(hash: string | null): string {
  return hash ? `${hash.slice(0, 8)}…${hash.slice(-6)}` : "no receipt";
}

function evidenceSummary(key: keyof RunIntegrityEvidence, slot: EvidenceSlot): string {
  if (key !== "stimReceipt") return slot.summary;
  return slot.receiptSequence === null && slot.evidenceHash === null
    ? "未附加可选外部事件时间线；不影响记录闭环。"
    : "外部事件时间线回执已附加；它不授予刺激能力。";
}

export type RecordingSaveState =
  | "not_started"
  | "recording_unsealed"
  | "stopped_unsealed"
  | "finalizing"
  | "sealed"
  | "mock_sealed"
  | "recovery_required";

export interface RecordingSaveSummary {
  state: RecordingSaveState;
  label: string;
  detail: string;
}

export function recordingSaveSummary(
  lifecycle: AcquireLifecycleState,
  evidence: RunIntegrityEvidence,
  receiptStatus: RunReceipt["status"] | "raw_sealed" | null,
  synthetic: boolean,
  targetCreated = !synthetic,
): RecordingSaveSummary {
  const coreFault = evidence.acquisition.status === "failed"
    || evidence.acquisition.status === "degraded"
    || evidence.durability.status === "failed"
    || evidence.durability.status === "degraded";
  const needsRecovery = lifecycle === "recovery_required"
    || receiptStatus === "recovery_required"
    || receiptStatus === "degraded"
    || (receiptStatus !== null && coreFault);
  if (needsRecovery) {
    return {
      state: "recovery_required",
      label: "记录异常 · 需要恢复",
      detail: "当前状态不能视为安全保存",
    };
  }

  const sealed = (receiptStatus === "finalized" || receiptStatus === "raw_sealed")
    && evidence.acquisition.status === "proven"
    && evidence.durability.status === "proven";
  if (sealed) {
    if (targetCreated) {
      return {
        state: "sealed",
        label: "原始记录已安全封存",
        detail: "数据接收范围、真实文件目标与封存回执均已确认",
      };
    }
    return {
      state: "mock_sealed",
      label: "模拟封存完成",
      detail: synthetic ? "未创建真实文件；仅验证界面与回执流程" : "真实文件目标缺少 created_new 回执",
    };
  }

  if (lifecycle === "finalized") {
    return {
      state: "recovery_required",
      label: "封存证据不完整 · 需要恢复",
      detail: "不能仅凭 FINALIZED 状态宣称文件安全",
    };
  }
  if (lifecycle === "finalizing" || receiptStatus === "finalizing") {
    return {
      state: "finalizing",
      label: "正在封存",
      detail: "正在完成文件写入、持久化屏障与 Run 回执",
    };
  }
  if (lifecycle === "recording_stopped" || receiptStatus === "stopped_not_durable") {
    return {
      state: "stopped_unsealed",
      label: "已停止 · 尚未安全封存",
      detail: "停止输入后仍须 Finalize；停止记录 ≠ 保存完成",
    };
  }
  if (
    lifecycle === "start_requested"
    || lifecycle === "recording"
    || lifecycle === "stop_requested"
    || receiptStatus === "active"
  ) {
    return {
      state: "recording_unsealed",
      label: "正在记录 · 尚未封存",
      detail: "数据仍在写入，当前不能称为安全保存",
    };
  }
  return {
    state: "not_started",
    label: "尚未开始记录",
    detail: "Preview 不创建 Run，也不会写入记录文件",
  };
}

export function RunIntegrityRail({
  runId,
  lifecycle,
  evidence,
  runReceipt,
  synthetic,
  collapsed,
  onToggleCollapsed,
}: RunIntegrityRailProps) {
  const saveSummary = recordingSaveSummary(
    lifecycle,
    evidence,
    runReceipt?.status ?? null,
    synthetic,
    runReceipt?.recordingTarget.directoryCreateDisposition === "created_new"
      && runReceipt.recordingTarget.journalCreateDisposition === "created_new",
  );

  return (
    <section
      className={`integrity-rail${collapsed ? " integrity-rail--collapsed" : ""}`}
      aria-labelledby="integrity-rail-title"
      data-collapsed={collapsed ? "true" : "false"}
    >
      <header className="integrity-rail__header">
        <div className="integrity-rail__identity">
          <ShieldCheck size={17} aria-hidden="true" />
          <div>
            <span className="instrument-kicker">RUN STATUS</span>
            <strong id="integrity-rail-title">记录完整性与输出</strong>
          </div>
        </div>
        <div className="integrity-rail__run">
          <span>{runId ?? "NO RUN"}</span>
          <strong>{lifecycle.replaceAll("_", " ").toUpperCase()}</strong>
        </div>
        <div
          className={`integrity-rail__verdict integrity-rail__verdict--${saveSummary.state}`}
          role="status"
          data-recording-save-state={saveSummary.state}
        >
          <span>{saveSummary.label}</span>
          <strong>{saveSummary.detail}</strong>
        </div>
        <button
          className="panel-collapse-button integrity-rail__toggle"
          type="button"
          aria-label={collapsed ? "展开记录保存状态" : "收起记录保存状态"}
          aria-expanded={!collapsed}
          title={collapsed ? "展开记录保存与输出明细" : "压缩为记录保存总判定"}
          onClick={onToggleCollapsed}
        >
          {collapsed
            ? <PanelBottomOpen size={17} aria-hidden="true" />
            : <PanelBottomClose size={17} aria-hidden="true" />}
        </button>
      </header>

      {collapsed ? null : (
        <div className="integrity-evidence-layout">
          <div className="integrity-rail__boundary integrity-evidence-guide" role="note">
            <strong>这 5 项用来回答两个不同问题</strong>
            <span>前 2 项回答“原始记录是否完整且已安全封存”；后 3 项回答“可选输出或外部时间线是否有对应回执”。后 3 项即使完成，也不能反推前 2 项安全。</span>
          </div>
          <div
            className="integrity-rail__boundary"
            role="note"
            aria-label="只有数据接收范围与文件写入封存都确认，原始记录才算完成。停止记录不等于保存完成。NWB、分析和外部事件不决定原始记录是否安全。"
            style={{ height: "auto", minHeight: 0 }}
          >
            <span title="只有数据接收范围与文件写入封存都确认，原始记录才算完成。停止记录不等于保存完成。">
              停止记录 ≠ 保存完成；只有“数据接收与采集范围”和“文件写入与封存”都确认，原始记录才完成
            </span>
            <strong>{runReceipt
              ? `${runReceipt.recordingTarget.directoryCreateDisposition === "created_new" ? "FILE RECEIPT" : "SIMULATED RECEIPT"} #${runReceipt.receiptSequence.toString()} · ${compactHash(runReceipt.evidenceHash)}`
              : "NO RUN RECEIPT"}</strong>
          </div>

          <div className="integrity-evidence-groups">
            {EVIDENCE_GROUPS.map((group) => (
              <section
                className="integrity-evidence-group"
                data-evidence-group={group.key}
                aria-labelledby={`evidence-group-${group.key}`}
                key={group.key}
              >
                <header className="integrity-rail__boundary">
                  <span id={`evidence-group-${group.key}`}>{group.label}</span>
                  <strong>{group.short}</strong>
                </header>
                <div
                  className="integrity-tracks"
                  style={{ gridTemplateColumns: `repeat(${group.tracks.length}, minmax(0, 1fr))` }}
                >
                  {group.tracks.map(({ key, label, short, purpose, icon: Icon }) => {
                    const slot = evidence[key];
                    return (
                      <article
                        className={`integrity-track integrity-track--${slot.status}`}
                        data-integrity-slot={key}
                        key={key}
                      >
                        <div className="integrity-track__lamp" aria-hidden="true"><Icon size={17} /></div>
                        <div className="integrity-track__copy">
                          <span>{label}</span>
                          <strong>{statusLabel(key, slot)}</strong>
                          <p title={evidenceSummary(key, slot)}>{purpose}</p>
                        </div>
                        <div className="integrity-track__receipt">
                          <span>{short}</span>
                          <code>{slot.receiptSequence === null ? "seq —" : `seq ${slot.receiptSequence.toString()}`}</code>
                          <code>{compactHash(slot.evidenceHash)}</code>
                        </div>
                      </article>
                    );
                  })}
                </div>
              </section>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
