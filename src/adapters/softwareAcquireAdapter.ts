import type {
  AcquireAdapter,
  AcquireIntent,
  CapabilitySnapshot,
  CommandReceipt,
  DaemonLoadSnapshot,
  DaemonSnapshot,
  DeviceNameReceipt,
  EvidenceSlot,
  FaultRecord,
  PreviewFrame,
  PreviewRequest,
  PreviewSource,
  RecordingTargetReservation,
  RenameDeviceRequest,
  RunIntegrityEvidence,
  RunPlan,
  RunReceipt,
  SnapshotListener,
  Unsubscribe,
} from "./acquireAdapter";
import { MockAcquireAdapter, type MockAcquireAdapterOptions } from "./mockAcquireAdapter";
import type { DaemonRunContext, DaemonSnapshotV1 } from "../core/daemon";
import {
  launchSoftwareReplay,
  readSoftwareReplaySnapshot,
  sendSoftwareReplayRunCommand,
  type SoftwareReplayReservation,
} from "../core/softwareDaemon";

const SOFTWARE_ADAPTER_ID = "forge.acquire.software-replay.v1";
const POLL_INTERVAL_MS = 250;

interface ActiveSoftwareRun {
  context: DaemonRunContext;
  pipeName: string;
  selectedPodKeys: readonly string[];
  selectedDeviceIds: readonly string[];
  reservation: RecordingTargetReservation;
}

export interface SoftwareAcquireAdapterOptions extends MockAcquireAdapterOptions {
  pollIntervalMs?: number;
  now?: () => number;
}

function nowMs(): number {
  return globalThis.performance?.now() ?? Date.now();
}

function randomHex(bytes: number): string {
  const values = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(values);
  return Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
}

function bytesHex(values: readonly number[]): string {
  return values.map((value) => value.toString(16).padStart(2, "0")).join("");
}

async function frozenPlanHash(plan: RunPlan): Promise<string> {
  const canonical = JSON.stringify({
    label: plan.label,
    plannedDurationSeconds: plan.plannedDurationSeconds,
    topologyEvidenceHash: plan.topologyEvidenceHash,
    selectedDevices: plan.selectedDevices.map((device) => ({
      podKey: device.podKey,
      deviceId: device.deviceId,
      identityEvidenceHash: device.identityEvidenceHash,
      inputEvidenceHash: device.inputEvidenceHash,
    })),
    recordingTarget: plan.recordingTarget,
  });
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join("");
}

function allocationSequence(leafName: string): bigint {
  const match = /-(\d{3,})$/.exec(leafName);
  return match ? BigInt(match[1]) : 0n;
}

function recordingReservation(receipt: SoftwareReplayReservation): RecordingTargetReservation {
  return {
    reservationId: receipt.reservationId,
    requestedDirectory: receipt.requestedDirectory,
    allocatedLeafName: receipt.allocatedLeafName,
    resolvedRunDirectory: receipt.resolvedRunDirectory,
    allocationSequence: allocationSequence(receipt.allocatedLeafName),
    journalFileName: receipt.journalFileName,
    directoryCreateDisposition: "created_new",
    journalCreateDisposition: receipt.journalCreateDisposition === "created_new" ? "created_new" : "simulated",
    overwritePolicy: "forbid",
    scope: "software",
    synthetic: true,
    reasonCode: "SOFTWARE_DAEMON_CREATE_NEW",
    evidenceHash: receipt.evidenceHash,
  };
}

function copyFrameWithRun(frame: PreviewFrame, active: ActiveSoftwareRun | null): PreviewFrame {
  if (active === null) {
    return frame.runId === null ? frame : { ...frame, runId: null, runEpoch: null };
  }
  if (frame.runId === null) return frame;
  return {
    ...frame,
    runId: active.context.runIdHex,
    runEpoch: BigInt(active.context.epoch),
  };
}

class SoftwarePreviewSource implements PreviewSource {
  readonly maxFramesPerSecond: number;

  constructor(
    private readonly inner: PreviewSource,
    private readonly activeRun: () => ActiveSoftwareRun | null,
  ) {
    this.maxFramesPerSecond = inner.maxFramesPerSecond;
  }

  setRequest(request: PreviewRequest): void {
    this.inner.setRequest(request);
  }

  getLatest(): PreviewFrame | null {
    const frame = this.inner.getLatest();
    return frame === null ? null : copyFrameWithRun(frame, this.activeRun());
  }

  subscribe(listener: (frame: PreviewFrame) => void): Unsubscribe {
    return this.inner.subscribe((frame) => listener(copyFrameWithRun(frame, this.activeRun())));
  }
}

function softwareSlot(
  id: EvidenceSlot["id"],
  status: EvidenceSlot["status"],
  summary: string,
  watermark: bigint | null,
  receiptSequence: bigint | null,
  evidenceHash: string | null,
  updatedAtMonotonicMs: number,
): EvidenceSlot {
  return {
    id,
    status,
    scope: "software",
    summary,
    watermark,
    receiptSequence,
    evidenceHash,
    updatedAtMonotonicMs,
  };
}

function unavailableOptionalEvidence(now: number): Pick<RunIntegrityEvidence, "nwb" | "analysis" | "stimReceipt"> {
  return {
    nwb: softwareSlot(
      "nwb",
      "unavailable",
      "未连接 NWB materializer；原始 journal 可独立封存。",
      null,
      null,
      null,
      now,
    ),
    analysis: softwareSlot(
      "analysis",
      "unavailable",
      "未连接 Analysis worker；不伪造分析完成或遗漏数量。",
      null,
      null,
      null,
      now,
    ),
    stimReceipt: softwareSlot(
      "stim_receipt",
      "unavailable",
      "未连接外部刺激/事件回执；不授予刺激能力，也不影响原始 journal 封存。",
      null,
      null,
      null,
      now,
    ),
  };
}

/**
 * Hybrid engineering adapter: mock fixtures provide bounded Preview only,
 * while an independent Rust process owns every recording file and journal
 * transition. It is software/synthetic evidence, never hardware evidence.
 */
export class SoftwareAcquireAdapter implements AcquireAdapter {
  readonly adapterId = SOFTWARE_ADAPTER_ID;
  readonly scope = "software" as const;
  readonly previewSource: PreviewSource;

  private readonly inner: MockAcquireAdapter;
  private readonly now: () => number;
  private readonly pollIntervalMs: number;
  private readonly listeners = new Set<SnapshotListener>();
  private activeRun: ActiveSoftwareRun | null = null;
  private daemon: DaemonSnapshotV1 | null = null;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private pollGeneration = 0;
  private requestId = 1;
  private receiptSequence = 0n;
  private lastOuterReceiptId: string | null = null;
  private lastInnerReceiptId: string | null = null;
  private pipeFault: string | null = null;
  private disposed = false;

  constructor(options: SoftwareAcquireAdapterOptions = {}) {
    this.now = options.now ?? nowMs;
    this.pollIntervalMs = options.pollIntervalMs ?? POLL_INTERVAL_MS;
    this.inner = new MockAcquireAdapter(options);
    this.previewSource = new SoftwarePreviewSource(this.inner.previewSource, () => this.activeRun);
    this.inner.subscribeSnapshots(() => this.publish());
  }

  async readCapabilities(): Promise<CapabilitySnapshot> {
    const inner = await this.inner.readCapabilities();
    return {
      ...inner,
      adapterId: this.adapterId,
      scope: "software",
      synthetic: true,
      capabilities: {
        ...inner.capabilities,
        mock_acquisition: {
          ...inner.capabilities.mock_acquisition,
          claimScope: "software",
          reasonCode: "INDEPENDENT_SYNTHETIC_JOURNAL",
          summary: "低速 Preview 来自 mock fixture；Recording 由独立 Rust software daemon 写入真实 create-new journal。",
        },
        fault_injection: {
          ...inner.capabilities.fault_injection,
          status: "unavailable",
          claimScope: "software",
          reasonCode: "REAL_JOURNAL_FAULT_INJECTION_DISABLED",
          summary: "真实 software journal 路径不开放 GUI 故障注入。",
        },
      },
      evidenceHash: inner.evidenceHash,
    };
  }

  async readSnapshot(): Promise<DaemonSnapshot> {
    return this.mergeSnapshot(await this.inner.readSnapshot());
  }

  subscribeSnapshots(listener: SnapshotListener): Unsubscribe {
    this.listeners.add(listener);
    void this.readSnapshot().then(listener);
    return () => this.listeners.delete(listener);
  }

  async execute(intent: AcquireIntent): Promise<CommandReceipt> {
    if (this.disposed) return this.reject(intent, "ADAPTER_DISPOSED", "Software adapter 已释放");
    try {
      switch (intent.type) {
        case "preflight":
          return await this.preflight(intent.plan);
        case "arm_recording":
          return await this.realThenMock(intent, 2, "armed");
        case "start_recording":
          return await this.realThenMock(intent, 3, "recording");
        case "stop_recording":
          return await this.stopAndSeal(intent);
        case "recover_run":
          return this.reject(intent, "SOFTWARE_RECOVERY_NOT_CONNECTED", "当前 software daemon 不提供 GUI 内恢复；保留 Run 目录并检查 journal。 ");
        case "acknowledge_failed_run": {
          if (this.daemon?.state !== "failed" || this.activeRun === null) {
            return this.reject(
              intent,
              "FAILED_RUN_NOT_CONFIRMED",
              "只有 daemon snapshot 明确报告 Failed 的 software Run 才能确认关闭；控制连接丢失不能当作记录已停止。",
            );
          }
          const preservedRunDirectory = this.activeRun.reservation.resolvedRunDirectory;
          const acknowledged = await this.command(7);
          if (!acknowledged.accepted || acknowledged.state !== "new") {
            return this.reject(intent, "FAILURE_ACK_NOT_PROVEN", acknowledged.reason);
          }
          const inner = await this.inner.acknowledgeExternalFailedRun();
          if (!inner.accepted) return this.outerReceipt(inner, inner.message, false);
          const receipt = {
            ...this.outerReceipt(
            inner,
            `失败 Run 已从控制面关闭；partial journal 保留在 ${preservedRunDirectory}，未删除、未补写 seal，也不声称数据完整。`,
            ),
            stateAtAcceptance: "recovery_required" as const,
            requestedState: "connected_idle" as const,
          };
          this.stopPolling();
          this.activeRun = null;
          this.daemon = null;
          this.pipeFault = null;
          this.publish();
          return receipt;
        }
        default:
          return await this.mockReceipt(intent);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "software daemon command failed";
      this.pipeFault = message;
      this.publish();
      return this.reject(intent, "SOFTWARE_DAEMON_ERROR", message);
    }
  }

  renameDevice(request: RenameDeviceRequest): Promise<DeviceNameReceipt> {
    // These are explicitly mock fixture names; the real cross-host device-name
    // contract remains unavailable and is not promoted by the software scope.
    return this.inner.renameDevice(request);
  }

  dispose(): void {
    this.disposed = true;
    this.stopPolling();
    // Deliberately no Stop/Abort request here. GUI lifetime does not own the
    // independent Rust recording process.
    this.inner.dispose();
    this.listeners.clear();
  }

  private async preflight(plan: RunPlan): Promise<CommandReceipt> {
    const current = await this.inner.readSnapshot();
    const invalid = this.validatePlan(current, plan);
    if (invalid !== null) return this.reject({ type: "preflight", plan }, "INVALID_PLAN", invalid);
    if (this.activeRun !== null && !["journal_sealed", "finalized", "aborted", "failed"].includes(this.daemon?.state ?? "new")) {
      return this.reject({ type: "preflight", plan }, "RUN_ALREADY_ACTIVE", "已有 software Run 尚未封存或失败关闭");
    }

    const runIdHex = randomHex(16);
    const targetDeviceIdHex = randomHex(16);
    const frozenConfigHashHex = await frozenPlanHash(plan);
    const epoch = Math.max(1, Math.trunc(Date.now()));
    const context: DaemonRunContext = { epoch, runIdHex, targetDeviceIdHex, frozenConfigHashHex };
    const launch = await launchSoftwareReplay({
      requestedDirectory: plan.recordingTarget.requestedDirectory,
      baseName: plan.recordingTarget.baseName,
      runIdHex,
      targetGroupIdHex: targetDeviceIdHex,
      frozenConfigHashHex,
      selectedDeviceIds: plan.selectedDevices.map((device) => device.deviceId),
    });
    this.activeRun = {
      context,
      pipeName: launch.pipeName,
      selectedPodKeys: plan.selectedDevices.map((device) => device.podKey),
      selectedDeviceIds: plan.selectedDevices.map((device) => device.deviceId),
      reservation: recordingReservation(launch),
    };
    this.pipeFault = null;
    const prepared = await this.command(1);
    if (!prepared.accepted || prepared.state !== "prepared") {
      throw new Error(`software daemon did not prepare the Run: ${prepared.reason}`);
    }
    this.activeRun = {
      ...this.activeRun,
      reservation: {
        ...this.activeRun.reservation,
        journalCreateDisposition: "created_new",
        reasonCode: "SOFTWARE_DAEMON_PREPARE_CREATE_NEW",
      },
    };
    this.startPolling();
    const receipt = await this.inner.execute({ type: "preflight", plan });
    if (!receipt.accepted) {
      const aborted = await this.command(5).catch(() => null);
      if (aborted?.accepted && aborted.state === "aborted") this.stopPolling();
      return this.outerReceipt(
        receipt,
        aborted?.accepted && aborted.state === "aborted"
          ? "内部 Preview plan 在 daemon Prepare 后拒绝；daemon 已 Abort 关闭并完成回执。"
          : "内部 Preview plan 在 daemon Prepare 后拒绝；Abort 尚未由 daemon 确认。",
        false,
      );
    }
    return this.outerReceipt(
      receipt,
      `Rust daemon 已 create-new 分配 ${this.activeRun.reservation.resolvedRunDirectory} 并创建 run.forgewal；尚未开始写样本。`,
    );
  }

  private validatePlan(snapshot: DaemonSnapshot, plan: RunPlan): string | null {
    if (!["connected_idle", "finalized"].includes(snapshot.lifecycle) || snapshot.previewState !== "live") {
      return "必须先连接并启动 Preview，且当前不能有 active Run";
    }
    if (!plan.label.trim() || !plan.recordingTarget.requestedDirectory.trim()
      || !plan.recordingTarget.baseName.trim() || plan.recordingTarget.overwritePolicy !== "forbid"
      || plan.recordingTarget.allocationPolicy !== "create_new_incrementing_suffix") {
      return "记录位置、名称或 NO OVERWRITE 策略无效";
    }
    if (plan.selectedDevices.length < 1 || plan.selectedDevices.length > 8
      || new Set(plan.selectedDevices.map((item) => item.podKey)).size !== plan.selectedDevices.length
      || new Set(plan.selectedDevices.map((item) => item.deviceId)).size !== plan.selectedDevices.length) {
      return "Run 必须包含 1–8 个唯一设备";
    }
    const pods = [
      ...snapshot.topology.directPods,
      ...snapshot.topology.aggregators.flatMap((aggregator) =>
        aggregator.ports.flatMap((port) => port.pod === null ? [] : [port.pod])),
    ];
    if (plan.topologyEvidenceHash !== snapshot.topology.evidenceHash
      || plan.selectedDevices.some((selection) => {
        const pod = pods.find((candidate) => candidate.key === selection.podKey);
        return pod === undefined || !pod.selectable || pod.identity.deviceId !== selection.deviceId
          || pod.identity.identityEvidenceHash !== selection.identityEvidenceHash
          || pod.neuralInput?.evidenceHash !== selection.inputEvidenceHash;
      })) {
      return "设备身份、输入描述或 topology receipt 已变化";
    }
    return null;
  }

  private async realThenMock(
    intent: Extract<AcquireIntent, { type: "arm_recording" | "start_recording" }>,
    command: 2 | 3,
    expectedState: "armed" | "recording",
  ): Promise<CommandReceipt> {
    const daemon = await this.command(command);
    if (!daemon.accepted || daemon.state !== expectedState) {
      return this.reject(intent, "DAEMON_REJECTED", daemon.reason);
    }
    return this.mockReceipt(intent, command === 2
      ? "独立 Rust writer 已 Armed；尚未开始记录。"
      : `独立 Rust writer 正在记录 ${this.activeRun?.selectedDeviceIds.length ?? 0} 个 deterministic software source。`);
  }

  private async stopAndSeal(
    intent: Extract<AcquireIntent, { type: "stop_recording" }>,
  ): Promise<CommandReceipt> {
    const daemon = await this.command(4, false);
    if (!daemon.accepted || daemon.state !== "journal_sealed") {
      return this.reject(intent, "SEAL_NOT_PROVEN", "Stop 返回但 journal seal 尚未由 daemon 证明");
    }
    // The per-Run software daemon exits after the sealed Stop response is
    // consumption-acknowledged. Stop polling before the inner UI transition so
    // an expected clean process exit cannot be misclassified as pipe loss.
    this.stopPolling();
    const receipt = await this.mockReceipt(intent,
      "daemon 已停止输入、排空队列、完成 durability barrier 并封存 run.forgewal；Preview 继续。",
    );
    return receipt;
  }

  private async mockReceipt(intent: AcquireIntent, message?: string): Promise<CommandReceipt> {
    const inner = await this.inner.execute(intent);
    return this.outerReceipt(inner, message);
  }

  private outerReceipt(inner: CommandReceipt, message?: string, accepted = inner.accepted): CommandReceipt {
    this.receiptSequence += 1n;
    this.lastInnerReceiptId = inner.receiptId;
    this.lastOuterReceiptId = `SOFTWARE-CMD-${this.receiptSequence.toString().padStart(6, "0")}`;
    return {
      ...inner,
      receiptId: this.lastOuterReceiptId,
      requestId: this.receiptSequence,
      scope: "software",
      synthetic: true,
      accepted,
      reasonCode: accepted ? "SOFTWARE_DAEMON_ACCEPTED" : inner.reasonCode,
      message: message ?? inner.message,
      runId: this.activeRun?.context.runIdHex ?? inner.runId,
      runEpoch: this.activeRun === null ? inner.runEpoch : BigInt(this.activeRun.context.epoch),
      evidenceHash: this.daemon === null ? inner.evidenceHash : bytesHex(this.daemon.receipt_hash),
    };
  }

  private async reject(intent: AcquireIntent, reasonCode: string, message: string): Promise<CommandReceipt> {
    const snapshot = await this.inner.readSnapshot();
    this.receiptSequence += 1n;
    this.lastOuterReceiptId = `SOFTWARE-CMD-${this.receiptSequence.toString().padStart(6, "0")}`;
    return {
      receiptKind: "command",
      receiptId: this.lastOuterReceiptId,
      requestId: this.receiptSequence,
      scope: "software",
      synthetic: true,
      intent: intent.type,
      accepted: false,
      reasonCode,
      message,
      stateAtAcceptance: snapshot.lifecycle,
      requestedState: null,
      previewStateAtAcceptance: snapshot.previewState,
      requestedPreviewState: null,
      runId: this.activeRun?.context.runIdHex ?? snapshot.runId,
      runEpoch: this.activeRun === null ? snapshot.runEpoch : BigInt(this.activeRun.context.epoch),
      issuedAtMonotonicMs: this.now(),
      evidenceHash: this.daemon === null ? snapshot.evidenceHash : bytesHex(this.daemon.receipt_hash),
    };
  }

  private async command(
    command: 1 | 2 | 3 | 4 | 5 | 7,
    publishSnapshot = true,
  ): Promise<DaemonSnapshotV1> {
    if (this.activeRun === null) throw new Error("software Run context is missing");
    const result = await sendSoftwareReplayRunCommand(
      this.activeRun.pipeName,
      command,
      this.activeRun.context,
      this.nextRequestId(),
    );
    if (result.snapshot === null) throw new Error(result.reason);
    this.daemon = result.snapshot;
    this.pipeFault = null;
    if (publishSnapshot) this.publish();
    return this.daemon;
  }

  private nextRequestId(): number {
    const current = this.requestId;
    this.requestId = this.requestId >= Number.MAX_SAFE_INTEGER ? 1 : this.requestId + 1;
    return current;
  }

  private startPolling(): void {
    this.stopPolling();
    const generation = this.pollGeneration;
    this.pollTimer = setInterval(() => {
      const active = this.activeRun;
      if (active === null) return;
      void readSoftwareReplaySnapshot(
        active.pipeName,
        this.nextRequestId(),
        active.context.epoch,
      ).then((result) => {
        if (this.disposed || generation !== this.pollGeneration) return;
        if (result.snapshot !== null) {
          this.daemon = result.snapshot;
          this.pipeFault = null;
          this.publish();
        }
      }).catch((error: unknown) => {
        if (this.disposed || generation !== this.pollGeneration) return;
        this.pipeFault = error instanceof Error ? error.message : "software daemon poll failed";
        this.publish();
      });
    }, this.pollIntervalMs);
  }

  private stopPolling(): void {
    this.pollGeneration += 1;
    if (this.pollTimer !== null) clearInterval(this.pollTimer);
    this.pollTimer = null;
  }

  private mergeSnapshot(inner: DaemonSnapshot): DaemonSnapshot {
    const active = this.activeRun;
    const daemon = this.daemon;
    const now = this.now();
    const receiptSequence = daemon?.ledger_events ?? null;
    const evidenceHash = daemon === null ? null : bytesHex(daemon.receipt_hash);
    const generated = daemon?.generated_record_count ?? null;
    const committed = daemon?.committed_record_count ?? null;
    const durable = daemon?.durable_record_count ?? null;
    const expected = daemon?.expected_last_journal_sequence ?? null;
    const sourceClosed = daemon?.state === "journal_sealed"
      && generated !== null && generated > 0n && committed === generated
      && expected === committed - 1n;
    const durableClosed = sourceClosed && durable === committed;
    // A per-Run daemon normally exits after the sealed Stop receipt is
    // consumption-acknowledged. A late transport error cannot invalidate that
    // already verified terminal receipt.
    const pipeFailureActive = this.pipeFault !== null && daemon?.state !== "journal_sealed";
    // Transport loss only makes the last daemon snapshot stale. It cannot
    // prove that the independent recording process stopped or failed.
    const failed = daemon?.state === "failed";
    const failedReason = daemon?.reason ?? "daemon reported Failed";
    const recordCounts = `generated ${generated?.toString() ?? "—"} / committed ${committed?.toString() ?? "—"} / durable ${durable?.toString() ?? "—"}`;
    const softwareFailure: FaultRecord | null = daemon?.state === "failed" ? {
      code: "recording_pipeline_failure",
      scope: "software",
      message: `Software recording failed and is unsealed; ${recordCounts}. ${failedReason}`,
      latched: true,
      recoverable: false,
      injected: false,
      sampleStart: null,
      sampleEndExclusive: null,
      observedAtMonotonicMs: now,
      evidenceHash: evidenceHash ?? active?.reservation.evidenceHash ?? inner.evidenceHash,
    } : null;
    const faults = softwareFailure === null ? inner.faults : [...inner.faults, softwareFailure];
    const acquisition = softwareSlot(
      "acquisition",
      failed ? "failed" : sourceClosed ? "proven" : daemon?.state === "recording" ? "active"
        : daemon?.state === "stopped" ? "pending" : "idle",
      failed
        ? `Software recording failed; ${recordCounts}. ${failedReason}`
        : sourceClosed
          ? `Software source-to-journal closure proven for ${active?.selectedDeviceIds.length ?? 0} deterministic source(s); this is not hardware sample coverage.`
          : daemon?.state === "recording"
            ? `${active?.selectedDeviceIds.length ?? 0} deterministic 32-channel source(s) active; committed ${committed?.toString() ?? "—"} records.`
            : "Software recording has not started; Preview does not count as acquisition evidence.",
      committed === null || committed === 0n ? null : committed - 1n,
      receiptSequence,
      evidenceHash,
      now,
    );
    const durability = softwareSlot(
      "durability",
      failed ? "failed" : durableClosed ? "proven" : daemon?.state === "recording" ? "active"
        : daemon?.state === "stopped" ? "pending" : "idle",
      failed
        ? `未封存；${recordCounts}. ${failedReason}. Partial journal 必须保留，不能当作完整 Run。`
        : durableClosed
          ? `run.forgewal sealed; durable ${durable?.toString()} / committed ${committed?.toString()} records.`
          : daemon?.state === "recording"
            ? `Journal accumulating; durable ${durable?.toString() ?? "0"} / committed ${committed?.toString() ?? "0"}. Stop has not sealed it.`
            : "No durable recording journal has been proven yet.",
      durable === null || durable === 0n ? null : durable - 1n,
      receiptSequence,
      evidenceHash,
      now,
    );
    const evidence: RunIntegrityEvidence = {
      acquisition,
      durability,
      ...unavailableOptionalEvidence(now),
    };
    const load: DaemonLoadSnapshot = daemon === null ? inner.load : {
      sourceBufferPercent: null,
      writerQueuePercent: daemon.queue_used_slots === null || daemon.queue_capacity_slots === null
        || daemon.queue_capacity_slots === 0n
        ? null
        : Number(daemon.queue_used_slots * 100n / daemon.queue_capacity_slots),
      controlLoadPercent: null,
      inputBytesPerSecond: null,
      expectedBytesPerSecond: null,
    };
    const recordingTarget = active?.reservation ?? null;
    const runReceipt: RunReceipt | null = active === null || recordingTarget === null ? null : {
      receiptKind: "run",
      scope: "software",
      synthetic: true,
      runId: active.context.runIdHex,
      runEpoch: BigInt(active.context.epoch),
      status: failed ? "recovery_required" : durableClosed ? "raw_sealed"
        : inner.lifecycle === "finalizing" ? "finalizing"
          : ["recording_stopped", "stop_requested"].includes(inner.lifecycle) ? "stopped_not_durable" : "active",
      lifecycle: failed ? "recovery_required" : inner.lifecycle,
      receiptSequence: receiptSequence ?? 0n,
      generatedAtMonotonicMs: now,
      evidence,
      recordingTarget,
      nwbArtifact: null,
      faults,
      evidenceHash: evidenceHash ?? recordingTarget.evidenceHash,
    };
    return {
      ...inner,
      adapterId: this.adapterId,
      scope: "software",
      synthetic: true,
      lifecycle: failed ? "recovery_required" : inner.lifecycle,
      controlConnection: pipeFailureActive ? "lost" : inner.controlConnection,
      stale: inner.stale || pipeFailureActive,
      runId: active?.context.runIdHex ?? inner.runId,
      runEpoch: active === null ? inner.runEpoch : BigInt(active.context.epoch),
      recordingTarget,
      selectedPodKeys: active?.selectedPodKeys ?? inner.selectedPodKeys,
      load,
      evidence,
      faults,
      lastCommandReceiptId: inner.lastCommandReceiptId === this.lastInnerReceiptId
        ? this.lastOuterReceiptId
        : inner.lastCommandReceiptId,
      runReceipt,
      evidenceHash: evidenceHash ?? inner.evidenceHash,
    };
  }

  private publish(): void {
    if (this.disposed) return;
    void this.readSnapshot().then((snapshot) => {
      for (const listener of this.listeners) listener(snapshot);
    });
  }
}
