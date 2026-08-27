import {
  initialMachineState,
  operatorStateOf,
  transitionMachine,
} from "./machine";
import { evaluateStoragePreflight } from "./storage";
import {
  DEFAULT_SYNTHETIC_HEADSTAGE_PROFILE,
  headstageProfile,
  isNewRunCatalogEligible,
  type HeadstageProfile,
  type HeadstageProfileId,
} from "./hardwareProfiles";
import type {
  AnalysisPipelineSnapshot,
  BackendKind,
  HealthMetrics,
  MachineState,
  Marker,
  PodSnapshot,
  RecordingPipelineSnapshot,
  StimulationSafetySnapshot,
  SystemEvent,
  SystemSnapshot,
  TraceBlock,
} from "./types";

const SYNTHETIC_BACKEND_LABEL = "SIMULATOR — SYNTHETIC DATA";
const DEFAULT_POD_ID = "synthetic-pod-1";
const DEFAULT_SAMPLE_RATE = 30_000;
const DEFAULT_FLUSH_DELAY_MS = 180;

export interface SimulatorBackendOptions {
  now?: () => number;
  wait?: (delayMs: number) => Promise<void>;
  flushDelayMs?: number;
  podId?: string;
  headstageProfileId?: HeadstageProfileId;
  sampleRate?: number;
}

export interface SimulatorTraceRequest {
  podId?: string;
  channelOffset?: number;
  channelCount?: number;
  pointsPerChannel?: number;
  sampleWindowSeconds?: number;
}

export type SimulatorSubscriber = (snapshot: SystemSnapshot) => void;

function defaultNow(): number {
  return globalThis.performance?.now() ?? Date.now();
}

function defaultWait(delayMs: number): Promise<void> {
  return new Promise((resolve) => globalThis.setTimeout(resolve, delayMs));
}

function copyMachine(state: MachineState): MachineState {
  return { ...state };
}

function deterministicNoise(sampleIndex: number, channel: number): number {
  let value = Math.imul(sampleIndex | 0, 0x45d9f3b);
  value ^= Math.imul(channel + 1, 0x27d4eb2d);
  value ^= value >>> 16;
  value = Math.imul(value, 0x45d9f3b);
  value ^= value >>> 16;
  return ((value >>> 0) / 0xffffffff) * 2 - 1;
}

/**
 * Synthetic UI backend only. It never opens hardware and never creates or
 * claims to create a raw-data file.
 */
export class SimulatorBackend {
  readonly kind: BackendKind = "simulator";
  readonly label: string;
  readonly isSynthetic = true;

  private machine: MachineState = copyMachine(initialMachineState);
  private readonly now: () => number;
  private readonly wait: (delayMs: number) => Promise<void>;
  private readonly flushDelayMs: number;
  private readonly podId: string;
  private readonly headstageProfile: HeadstageProfile;
  private readonly channelCount: number;
  private readonly sampleRate: number;
  private readonly subscribers = new Set<SimulatorSubscriber>();
  private readonly markers: Marker[] = [];
  private readonly events: SystemEvent[] = [];
  private eventSequence = 0;
  private markerSequence = 0;
  private runSequence = 0;
  private monitoringStartedAtMs: number | null = null;
  private monitoringAccumulatedMs = 0;
  private recordingStartedAtMs: number | null = null;
  private recordingAccumulatedMs = 0;
  private lifecycleGeneration = 0;

  constructor(options: SimulatorBackendOptions = {}) {
    this.now = options.now ?? defaultNow;
    this.wait = options.wait ?? defaultWait;
    this.flushDelayMs = options.flushDelayMs ?? DEFAULT_FLUSH_DELAY_MS;
    this.podId = options.podId ?? DEFAULT_POD_ID;
    this.headstageProfile = headstageProfile(
      options.headstageProfileId ?? DEFAULT_SYNTHETIC_HEADSTAGE_PROFILE,
    );
    this.channelCount = this.headstageProfile.acquisitionChannelCount;
    this.label = `${SYNTHETIC_BACKEND_LABEL} · ${this.headstageProfile.label}`;
    this.sampleRate = options.sampleRate ?? DEFAULT_SAMPLE_RATE;

    if (!Number.isFinite(this.flushDelayMs) || this.flushDelayMs < 0) {
      throw new RangeError("flushDelayMs must be a finite non-negative number");
    }
    if (!Number.isInteger(this.channelCount) || this.channelCount <= 0) {
      throw new RangeError("channelCount must be a positive integer");
    }
    if (!Number.isFinite(this.sampleRate) || this.sampleRate <= 0) {
      throw new RangeError("sampleRate must be a finite positive number");
    }

    this.addEvent(
      "info",
      "SIMULATOR_SYNTHETIC_ONLY",
      "已选择确定性演示源；未连接任何硬件，也不会写入原始神经数据。",
    );
  }

  subscribe(subscriber: SimulatorSubscriber): () => void {
    this.subscribers.add(subscriber);
    subscriber(this.getSnapshot());
    return () => this.subscribers.delete(subscriber);
  }

  async connect(): Promise<void> {
    if (this.machine.transport === "open") return;

    if (this.machine.transport !== "available") {
      this.machine = transitionMachine(this.machine, { type: "ENUMERATE" });
      this.machine = transitionMachine(this.machine, { type: "AVAILABLE" });
    }
    this.machine = transitionMachine(this.machine, { type: "OPEN_REQUEST" });
    this.machine = transitionMachine(this.machine, {
      type: "OPENED",
      synchronized: false,
    });
    this.addEvent(
      "info",
      "SIMULATOR_CONNECTED",
      "演示源已连接；这不是 Receiver Pod 硬件连接。",
    );
    this.publish();
  }

  startMonitoring(): SystemSnapshot {
    if (this.machine.transport !== "open") {
      throw new Error("请先连接演示源，再开始监看");
    }
    if (this.machine.acquisition === "streaming") return this.getSnapshot();

    const before = this.machine;
    this.machine = transitionMachine(this.machine, { type: "START_MONITOR" });
    this.machine = transitionMachine(this.machine, { type: "FIRST_VALID_FRAME" });
    if (this.machine === before || this.machine.acquisition !== "streaming") {
      throw new Error("monitoring cannot start from the current state");
    }
    this.beginMonitoringIfNeeded(this.now());
    this.addEvent(
      "info",
      "SIMULATOR_MONITORING",
      "确定性合成波形已开始显示。",
    );
    this.publish();
    return this.getSnapshot();
  }

  stopMonitoring(): SystemSnapshot {
    if (["opening", "armed", "writing", "flushing"].includes(this.machine.writer)) {
      throw new Error("请先结束并完成演示 Run，再停止监看");
    }
    if (this.machine.acquisition !== "streaming") return this.getSnapshot();

    this.machine = transitionMachine(this.machine, { type: "STOP_MONITOR" });
    this.endMonitoring(this.now());
    this.addEvent("info", "SIMULATOR_MONITORING_STOPPED", "合成波形显示已停止。");
    this.publish();
    return this.getSnapshot();
  }

  startRecording(runId?: string): SystemSnapshot {
    if (!isNewRunCatalogEligible(this.headstageProfile.id)) {
      throw new Error("该 Headstage 仅用于历史解码，不能开始新的演示 Run");
    }
    if (this.machine.transport !== "open") {
      throw new Error("请先连接演示源，再开始演示 Run");
    }
    if (["opening", "armed", "writing", "flushing"].includes(this.machine.writer)) {
      throw new Error("已有演示 Run 生命周期处于活动状态");
    }

    if (this.machine.writer === "failed") {
      throw new Error("请先确认并归档失败的演示 Run，再开始新 Run");
    }

    if (this.machine.writer === "finalized") {
      // The state machine intentionally preserves a finalized run as visible
      // evidence. Re-arm its writer slot without claiming any file was opened.
      this.machine = transitionMachine(this.machine, { type: "REARM_AFTER_FINALIZED" });
    }

    const syntheticRunId = runId ?? `SIM-RUN-${String(++this.runSequence).padStart(4, "0")}`;
    const previousWriter = this.machine.writer;
    this.machine = transitionMachine(this.machine, {
      type: "PREPARE_RECORD",
      runId: syntheticRunId,
    });
    this.machine = transitionMachine(this.machine, { type: "WRITER_ARMED" });
    this.machine = transitionMachine(this.machine, { type: "RECORDING_CONFIRMED" });
    if (this.machine.writer === previousWriter || this.machine.writer !== "writing") {
      throw new Error("当前状态不能开始演示 Run");
    }

    const now = this.now();
    this.beginMonitoringIfNeeded(now);
    this.recordingAccumulatedMs = 0;
    this.recordingStartedAtMs = now;
    this.addEvent(
      "warning",
      "SIMULATOR_RECORDING_NO_RAW_FILE",
      `演示 Run ${syntheticRunId} 已开始，仅用于界面验证；不会写入 raw 文件。`,
    );
    this.publish();
    return this.getSnapshot();
  }

  async stopRecording(): Promise<void> {
    if (this.machine.writer !== "writing") {
      throw new Error("当前没有活动的演示 Run");
    }

    const now = this.now();
    this.endRecording(now);
    this.machine = transitionMachine(this.machine, { type: "STOP_RECORD" });
    this.machine = transitionMachine(this.machine, { type: "SOURCE_STOPPED" });
    const generation = this.lifecycleGeneration;
    this.addEvent(
      "info",
      "SIMULATOR_FLUSHING",
      "正在结束演示 metadata 生命周期；不存在 raw 数据载荷。",
    );
    this.publish();

    await this.wait(this.flushDelayMs);
    if (generation !== this.lifecycleGeneration || this.machine.writer !== "flushing") {
      return;
    }

    this.machine = transitionMachine(this.machine, { type: "WRITER_FINALIZED" });
    this.addEvent(
      "info",
      "SIMULATOR_FINALIZED",
      "演示生命周期已完成；这不构成硬件记录或 raw 文件证据。",
    );
    this.publish();
  }

  disconnect(): SystemSnapshot {
    const wasRecording = ["opening", "armed", "writing", "flushing"].includes(this.machine.writer);
    const now = this.now();
    this.endRecording(now);
    this.endMonitoring(now);
    this.lifecycleGeneration += 1;
    this.machine = transitionMachine(this.machine, { type: "DISCONNECT" });
    this.addEvent(
      wasRecording ? "error" : "info",
      wasRecording ? "SIMULATOR_RECORDING_INTERRUPTED" : "SIMULATOR_DISCONNECTED",
      wasRecording
        ? "演示 Run 在完成前被中断。"
        : "演示源已断开。",
    );
    this.publish();
    return this.getSnapshot();
  }

  captureMarker(): Marker {
    const now = this.now();
    const sampleCounter = this.machine.acquisition === "streaming"
      ? this.sampleCounterAt(now)
      : null;
    return {
      id: `SIM-MARKER-${String(++this.markerSequence).padStart(4, "0")}`,
      label: "Marker",
      note: "",
      hostMonotonicMs: now,
      hardwareGlobalTime: null,
      nearestSampleCounter: sampleCounter,
      timestampSource: "host_monotonic",
      runId: this.machine.runId,
      podId: this.machine.transport === "open" ? this.podId : null,
    };
  }

  saveMarker(marker: Marker): Marker {
    const saved: Marker = {
      ...marker,
      label: marker.label.trim() || "Marker",
      note: marker.note,
      // A synthetic marker never acquires a hardware timestamp while edited.
      hardwareGlobalTime: null,
      timestampSource: "host_monotonic",
    };
    const existingIndex = this.markers.findIndex((item) => item.id === saved.id);
    if (existingIndex >= 0) this.markers[existingIndex] = saved;
    else this.markers.push(saved);
    this.addEvent(
      "info",
      "SIMULATOR_MARKER_CAPTURED",
      `演示标记“${saved.label}”已保存；沿用打开对话框前捕获的主机单调时间。`,
    );
    this.publish();
    return { ...saved };
  }

  /** Returns an immutable-by-copy status snapshot. No filesystem snapshot is created. */
  getSnapshot(): SystemSnapshot {
    const now = this.now();
    return {
      backendKind: this.kind,
      backendLabel: this.label,
      isSynthetic: true,
      machine: copyMachine(this.machine),
      operatorState: operatorStateOf(this.machine),
      pods: [this.podSnapshot(now)],
      metrics: this.healthMetrics(),
      recordingPipeline: this.recordingPipelineSnapshot(),
      storagePreflight: evaluateStoragePreflight({
        targetPath: null,
        volumeIdentity: null,
        filesystem: null,
        freeBytes: null,
        measuredSustainedWriteBytesPerSecond: null,
        powerLossProtectionVerified: null,
        qualificationReceiptHash: null,
        qualificationProfileHash: null,
        qualificationDurationSeconds: null,
      }),
      analysisPipeline: this.analysisPipelineSnapshot(),
      stimulation: this.stimulationSafetySnapshot(),
      markers: this.markers.map((marker) => ({ ...marker })),
      events: this.events.map((event) => ({ ...event })),
      monitoringSeconds: this.elapsedSeconds(
        this.monitoringAccumulatedMs,
        this.monitoringStartedAtMs,
        now,
      ),
      recordingSeconds: this.elapsedSeconds(
        this.recordingAccumulatedMs,
        this.recordingStartedAtMs,
        now,
      ),
    };
  }

  /** Alias emphasizing that this captures state only, never a raw-data file. */
  captureSnapshot(): SystemSnapshot {
    return this.getSnapshot();
  }

  getTraceBlock(request: SimulatorTraceRequest = {}): TraceBlock {
    if (this.machine.acquisition !== "streaming") {
      throw new Error("只有监看期间可以读取合成波形");
    }

    const podId = request.podId ?? this.podId;
    const channelOffset = request.channelOffset ?? 0;
    const channelCount = request.channelCount ?? Math.min(16, this.channelCount);
    const pointsPerChannel = request.pointsPerChannel ?? 400;
    const sampleWindowSeconds = request.sampleWindowSeconds ?? 1;

    if (podId !== this.podId) throw new RangeError(`未知演示 Pod：${podId}`);
    if (!Number.isInteger(channelOffset) || channelOffset < 0) {
      throw new RangeError("channelOffset must be a non-negative integer");
    }
    if (!Number.isInteger(channelCount) || channelCount <= 0) {
      throw new RangeError("channelCount must be a positive integer");
    }
    if (channelOffset + channelCount > this.channelCount) {
      throw new RangeError("请求的演示通道超过可用通道数");
    }
    if (!Number.isInteger(pointsPerChannel) || pointsPerChannel < 2) {
      throw new RangeError("pointsPerChannel must be an integer of at least 2");
    }
    if (!Number.isFinite(sampleWindowSeconds) || sampleWindowSeconds <= 0) {
      throw new RangeError("sampleWindowSeconds must be a finite positive number");
    }

    const now = this.now();
    const endSample = this.sampleCounterAt(now);
    const windowSamples = Math.max(1, Math.round(sampleWindowSeconds * this.sampleRate));
    const valuesUv = Array.from({ length: channelCount }, (_, localChannel) => {
      const channel = channelOffset + localChannel;
      const values = new Float32Array(pointsPerChannel);
      for (let point = 0; point < pointsPerChannel; point += 1) {
        const fraction = point / (pointsPerChannel - 1);
        const sampleIndex = endSample - windowSamples + Math.round(fraction * windowSamples);
        const timeSeconds = sampleIndex / this.sampleRate;
        const primaryHz = 7.5 + channel * 0.17;
        const phase = channel * 0.37;
        values[point] =
          42 * Math.sin(2 * Math.PI * primaryHz * timeSeconds + phase)
          + 11 * Math.sin(2 * Math.PI * 50 * timeSeconds + channel * 0.11)
          + 3.5 * deterministicNoise(sampleIndex, channel);
      }
      return values;
    });

    return {
      podId,
      channelOffset,
      channelCount,
      pointsPerChannel,
      sampleWindowSeconds,
      valuesUv,
      generatedAtMonotonicMs: now,
      synthetic: true,
    };
  }

  private beginMonitoringIfNeeded(now: number): void {
    if (this.monitoringStartedAtMs === null) this.monitoringStartedAtMs = now;
  }

  private endMonitoring(now: number): void {
    if (this.monitoringStartedAtMs === null) return;
    this.monitoringAccumulatedMs += Math.max(0, now - this.monitoringStartedAtMs);
    this.monitoringStartedAtMs = null;
  }

  private endRecording(now: number): void {
    if (this.recordingStartedAtMs === null) return;
    this.recordingAccumulatedMs += Math.max(0, now - this.recordingStartedAtMs);
    this.recordingStartedAtMs = null;
  }

  private elapsedSeconds(accumulatedMs: number, startedAtMs: number | null, now: number): number {
    const activeMs = startedAtMs === null ? 0 : Math.max(0, now - startedAtMs);
    return (accumulatedMs + activeMs) / 1000;
  }

  private sampleCounterAt(now: number): number {
    const seconds = this.elapsedSeconds(
      this.monitoringAccumulatedMs,
      this.monitoringStartedAtMs,
      now,
    );
    return Math.floor(seconds * this.sampleRate);
  }

  private podSnapshot(now: number): PodSnapshot {
    const connected = this.machine.transport === "open";
    const streaming = connected && this.machine.acquisition === "streaming";
    const sampleCounter = streaming ? this.sampleCounterAt(now) : null;
    return {
      id: this.podId,
      label: `Synthetic Receiver Pod · ${this.headstageProfile.label}`,
      serial: "SYNTHETIC-NO-HARDWARE",
      headstageProfileId: this.headstageProfile.id,
      headstageProfileLabel: this.headstageProfile.label,
      usbBridge: null,
      dhlLinkLocked: null,
      dhlDescriptorAdmitted: false,
      attached: connected,
      ready: connected,
      fault: this.machine.integrity === "invalid",
      synchronized: false,
      channelCount: connected ? this.channelCount : null,
      sampleRate: connected ? this.sampleRate : null,
      bytesPerSecond: streaming ? this.channelCount * this.sampleRate * 2 : 0,
      frameCounter: sampleCounter === null ? null : Math.floor(sampleCounter / 30),
      sampleCounter,
      crcErrors: 0,
      counterGaps: 0,
      resyncs: 0,
      overflows: 0,
    };
  }

  private healthMetrics(): HealthMetrics {
    const streaming = this.machine.transport === "open"
      && this.machine.acquisition === "streaming";
    const configuredRate = this.machine.transport === "open"
      ? this.channelCount * this.sampleRate * 2
      : 0;
    const syntheticRate = streaming ? configuredRate : 0;
    return {
      inputBytesPerSecond: syntheticRate,
      expectedBytesPerSecond: configuredRate,
      // Deliberately zero: this simulator never writes a raw-data payload.
      writerBytesPerSecond: 0,
      writerQueuePercent: 0,
      bufferPercent: streaming ? 8 : 0,
      crcErrors: 0,
      counterGaps: 0,
      overflows: 0,
      storageFreeBytes: null,
      storageRemainingSeconds: null,
    };
  }

  private recordingPipelineSnapshot(): RecordingPipelineSnapshot {
    return {
      spoolState: "unavailable",
      nwbState: "unavailable",
      receivedSequence: null,
      spooledSequence: null,
      durableSequence: null,
      nwbSequence: null,
      durableLagBytes: null,
      nwbLagBytes: null,
      spoolPath: null,
      nwbPath: null,
      protectionVerified: false,
    };
  }

  private analysisPipelineSnapshot(): AnalysisPipelineSnapshot {
    return {
      cppWorker: "unavailable",
      pythonWorker: "unavailable",
      controllerTokenOwner: "none",
      referenceAlgorithmsOnly: true,
      processedSequence: null,
      droppedBlocks: 0,
      lastError: null,
    };
  }

  private stimulationSafetySnapshot(): StimulationSafetySnapshot {
    return {
      state: "unavailable",
      headstageProfileId: this.headstageProfile.id,
      rhsChannelCount: 0,
      capabilityHash: null,
      safetyProfileHash: null,
      safetyProfileApprovalId: null,
      templateSetHash: null,
      algorithmBuildHash: null,
      algorithmConfigHash: null,
      channelMapHash: null,
      controllerWorkerBuildHash: null,
      physicalEnable: "unknown",
      emergencyStopHealthy: null,
      watchdogHealthy: null,
      complianceHealthy: null,
      hardwareClockLocked: null,
      frozenContextReceiptHash: null,
      closedLoopReleaseQualified: false,
      qualificationReceiptHash: null,
      armEpoch: null,
      deadlineBudgetMs: null,
      lastIntentSequence: null,
      lastReceiptSequence: null,
      receiptGapCount: 0,
      duplicateReceiptCount: 0,
      unavailableReasons: [
        "模拟器没有 RHS2116 硬件能力",
        "未连接独立 Rust SafetyArbiter",
        "没有已批准的 Safety Profile 与实体联锁证据",
      ],
    };
  }

  private addEvent(
    severity: SystemEvent["severity"],
    code: string,
    message: string,
  ): void {
    this.events.push({
      id: `SIM-EVENT-${String(++this.eventSequence).padStart(4, "0")}`,
      severity,
      code,
      message,
      hostMonotonicMs: this.now(),
    });
    if (this.events.length > 200) this.events.splice(0, this.events.length - 200);
  }

  private publish(): void {
    if (this.subscribers.size === 0) return;
    const snapshot = this.getSnapshot();
    for (const subscriber of this.subscribers) subscriber(snapshot);
  }
}
