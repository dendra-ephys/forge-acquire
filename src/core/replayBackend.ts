import { evaluateStoragePreflight } from "./storage";
import {
  readDaemonSnapshot,
  sendDaemonRunCommand,
  type DaemonRunContext,
  type DaemonSnapshotV1,
} from "./daemon";
import type {
  Marker,
  MachineState,
  SystemEvent,
  SystemSnapshot,
} from "./types";

type Subscriber = (snapshot: SystemSnapshot) => void;

export class ProtectedReplayBackend {
  private connected = false;
  private daemon: DaemonSnapshotV1 | null = null;
  private context: DaemonRunContext | null = null;
  private lastSealedRunId: string | null = null;
  private subscribers = new Set<Subscriber>();
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private events: SystemEvent[] = [];
  private eventSequence = 0;
  private recordingStartedAt: number | null = null;
  private recordingAccumulatedMs = 0;

  subscribe(subscriber: Subscriber): () => void {
    this.subscribers.add(subscriber);
    subscriber(this.getSnapshot());
    return () => this.subscribers.delete(subscriber);
  }

  async connect(): Promise<SystemSnapshot> {
    const result = await readDaemonSnapshot();
    if (!result.available || result.snapshot === null) throw new Error(result.reason);
    if (!result.snapshot.protected_replay_available) {
      throw new Error("The SCM daemon is online, but Protected Replay capability is disabled");
    }
    this.daemon = result.snapshot;
    this.restoreDaemonContext(result.snapshot);
    this.connected = true;
    this.addEvent("info", "REPLAY_DAEMON_CONNECTED", "SCM daemon authenticated; no neural acquisition hardware is connected.");
    this.startPolling();
    this.publish();
    return this.getSnapshot();
  }

  disconnect(): SystemSnapshot {
    if (this.daemon?.state === "recording") {
      throw new Error("Closing the GUI does not stop a daemon Run; stay connected or complete Stop and seal first");
    }
    this.connected = false;
    this.stopPolling();
    this.addEvent("info", "REPLAY_UI_DISCONNECTED", "Control plane disconnected; the GUI does not own the daemon lifecycle.");
    this.publish();
    return this.getSnapshot();
  }

  startMonitoring(): never {
    throw new Error("Protected Replay sends no raw or waveform data to the WebView; start the qualification Run directly");
  }

  stopMonitoring(): SystemSnapshot {
    return this.getSnapshot();
  }

  async startRecording(): Promise<SystemSnapshot> {
    if (!this.connected || this.daemon === null) throw new Error("Connect an authenticated SCM daemon first");
    if (this.daemon.state === "failed") throw new Error("Acknowledge the previous failed Run first");
    if (!["new", "journal_sealed", "finalized"].includes(this.daemon.state)) {
      throw new Error(`The daemon is in ${this.daemon.state}; a new Run cannot start`);
    }
    const nextDaemonEpoch = this.daemon.highest_epoch + 1n;
    const epochValue = nextDaemonEpoch > BigInt(Date.now()) ? nextDaemonEpoch : BigInt(Date.now());
    const epoch = safeMetricNumber(epochValue);
    if (epoch === null) throw new Error("daemon epoch exceeded JavaScript safe integer range");
    this.context = {
      epoch,
      runIdHex: randomHex(16),
      targetDeviceIdHex: "44".repeat(16),
      frozenConfigHashHex: randomHex(32),
    };
    try {
      await this.command(1);
      await this.command(2);
      await this.command(3);
    } catch (error) {
      try {
        if (this.context && this.daemon && ["prepared", "armed", "recording"].includes(this.daemon.state)) {
          await this.command(5);
        }
      } catch {
        // Preserve the original failure; daemon state remains visible on poll.
      }
      throw error;
    }
    this.recordingStartedAt = performance.now();
    this.addEvent("info", "REPLAY_RUN_STARTED", "Protected Replay entered the independent daemon journal path.");
    this.publish();
    return this.getSnapshot();
  }

  async acknowledgeFailure(): Promise<SystemSnapshot> {
    if (!this.connected || this.daemon?.state !== "failed") {
      throw new Error("There is no failed Run to acknowledge");
    }
    if (!this.context) {
      throw new Error("The failed Run has an incomplete frozen context; remain fail-closed and inspect the daemon ledger");
    }
    const acknowledgedRunId = this.context.runIdHex;
    const response = await this.command(7);
    if (response.state !== "new") {
      throw new Error("The daemon did not return to New after accepting acknowledgement");
    }
    this.context = null;
    this.addEvent("warning", "REPLAY_FAILURE_ACKNOWLEDGED", `Failed Run ${acknowledgedRunId} acknowledged; prior evidence was not deleted.`);
    this.publish();
    return this.getSnapshot();
  }

  async stopRecording(): Promise<SystemSnapshot> {
    if (!this.context || this.daemon?.state !== "recording") {
      throw new Error("There is no Protected Replay Run to stop");
    }
    const stopped = await this.command(4);
    if (stopped.state !== "journal_sealed") {
      throw new Error("Stop returned, but the durable journal seal is not proven");
    }
    this.finishRecordingClock();
    this.lastSealedRunId = this.context.runIdHex;
    this.addEvent("info", "REPLAY_JOURNAL_SEALED", "Stop, drain, durability barrier, and journal seal completed.");
    this.publish();
    return this.getSnapshot();
  }

  captureMarker(): never {
    throw new Error("The Protected Replay marker journal is not connected; GUI-only markers will not be fabricated");
  }

  saveMarker(_marker: Marker): never {
    throw new Error("The Protected Replay marker journal is not connected");
  }

  getSnapshot(): SystemSnapshot {
    const daemon = this.daemon;
    const machine = this.machine(daemon);
    const generatedRaw = daemon?.generated_record_count ?? null;
    const committedRaw = daemon?.committed_record_count ?? null;
    const durableRaw = daemon?.durable_record_count ?? null;
    const generated = safeMetricNumber(generatedRaw);
    const committed = safeMetricNumber(committedRaw);
    const durable = safeMetricNumber(durableRaw);
    const queueUsed = safeMetricNumber(daemon?.queue_used_slots ?? null) ?? 0;
    const queueCapacity = safeMetricNumber(daemon?.queue_capacity_slots ?? null) ?? 0;
    const recording = daemon?.state === "recording";
    const protectedSeal = daemon?.state === "journal_sealed"
      && committedRaw !== null
      && committedRaw === durableRaw
      && daemon.expected_last_journal_sequence === committedRaw - 1n;
    return {
      backendKind: "replay",
      backendLabel: "Protected Replay · forge-acqd",
      isSynthetic: true,
      machine,
      operatorState: !this.connected ? "disconnected" : recording ? "recording" : "ready",
      pods: [{
        id: "REPLAY-POD-00",
        label: "Deterministic Replay Source",
        serial: "SYNTHETIC-NO-HARDWARE",
        headstageProfileId: null,
        headstageProfileLabel: null,
        usbBridge: null,
        dhlLinkLocked: null,
        dhlDescriptorAdmitted: false,
        attached: this.connected,
        ready: this.connected && daemon?.protected_replay_available === true,
        fault: daemon?.state === "failed" || daemon?.poisoned === true,
        synchronized: false,
        channelCount: this.connected ? 1 : null,
        sampleRate: this.connected ? 30_000 : null,
        bytesPerSecond: recording ? 60_000 : 0,
        frameCounter: generated,
        sampleCounter: generated === null ? null : generated * 30,
        crcErrors: 0,
        counterGaps: 0,
        resyncs: 0,
        overflows: 0,
      }],
      metrics: {
        inputBytesPerSecond: recording ? 60_000 : 0,
        expectedBytesPerSecond: this.connected ? 60_000 : 0,
        writerBytesPerSecond: recording ? 60_000 : 0,
        writerQueuePercent: queueCapacity > 0 ? (queueUsed / queueCapacity) * 100 : 0,
        bufferPercent: queueCapacity > 0 ? (queueUsed / queueCapacity) * 100 : 0,
        crcErrors: 0,
        counterGaps: 0,
        overflows: 0,
        storageFreeBytes: null,
        storageRemainingSeconds: null,
      },
      recordingPipeline: {
        spoolState: daemon?.state === "recording"
          ? "writing"
          : daemon?.state === "stopped"
            ? "sealing"
            : daemon?.state === "journal_sealed"
              ? "sealed"
              : daemon?.state === "failed"
                ? "failed"
                : daemon && ["prepared", "armed"].includes(daemon.state)
                  ? "armed"
                  : "unavailable",
        nwbState: "unavailable",
        receivedSequence: lastSequence(generated),
        spooledSequence: lastSequence(committed),
        durableSequence: lastSequence(durable),
        nwbSequence: null,
        durableLagBytes: generated !== null && durable !== null ? Math.max(0, generated - durable) * 268 : null,
        nwbLagBytes: null,
        spoolPath: null,
        nwbPath: null,
        protectionVerified: protectedSeal,
      },
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
      analysisPipeline: {
        cppWorker: "unavailable",
        pythonWorker: "unavailable",
        controllerTokenOwner: "none",
        referenceAlgorithmsOnly: true,
        processedSequence: null,
        droppedBlocks: 0,
        lastError: null,
      },
      stimulation: {
        state: "unavailable",
        headstageProfileId: null,
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
          "Protected Replay has no RHS2116 hardware capability",
          "Algorithm and stimulation paths are not connected to this qualification Run",
          "No physical interlock or approved Safety Profile is present",
        ],
      },
      markers: [],
      events: this.events.map((event) => ({ ...event })),
      monitoringSeconds: this.recordingSeconds(),
      recordingSeconds: this.recordingSeconds(),
    };
  }

  private async command(command: 1 | 2 | 3 | 4 | 5 | 7): Promise<DaemonSnapshotV1> {
    if (!this.context) throw new Error("Protected Replay Run context is missing");
    const result = await sendDaemonRunCommand(command, this.context);
    this.daemon = result.snapshot;
    if (!this.daemon?.accepted) throw new Error(this.daemon?.reason ?? "daemon rejected Run command");
    return this.daemon;
  }

  private machine(daemon: DaemonSnapshotV1 | null): MachineState {
    const state = daemon?.state ?? "new";
    const active = ["prepared", "armed", "recording", "stopped", "failed"].includes(state);
    return {
      transport: this.connected ? "open" : "absent",
      acquisition: state === "recording"
        ? "streaming"
        : state === "prepared"
          ? "preparing"
          : state === "armed"
            ? "start_requested"
            : state === "stopped"
              ? "stopping"
              : state === "failed" || state === "aborted"
                ? "aborted"
                : "idle",
      writer: state === "recording"
        ? "writing"
        : state === "prepared"
          ? "opening"
          : state === "armed"
            ? "armed"
            : state === "stopped"
              ? "flushing"
              : state === "journal_sealed" || state === "finalized"
                ? "finalized"
                : state === "failed" || state === "aborted"
                  ? "failed"
                  : "disabled",
      integrity: state === "failed" ? "invalid" : "clean",
      sync: "standalone",
      runId: active ? this.context?.runIdHex ?? null : null,
      lastFinalizedRunId: this.lastSealedRunId,
      lastError: state === "failed" ? daemon?.reason ?? "daemon Run failed" : null,
    };
  }

  private startPolling(): void {
    this.stopPolling();
    this.pollTimer = setInterval(() => {
      void readDaemonSnapshot()
        .then((result) => {
          if (result.available && result.snapshot) {
            this.daemon = result.snapshot;
            this.restoreDaemonContext(result.snapshot);
            this.publish();
          }
        })
        .catch(() => {
          // Last authenticated snapshot remains visible; command paths fail closed.
        });
    }, 250);
  }

  private restoreDaemonContext(snapshot: DaemonSnapshotV1): void {
    const runIdHex = bytesToOptionalHex(snapshot.active_run_id, 16);
    const targetDeviceIdHex = bytesToOptionalHex(snapshot.active_target_device_id, 16);
    const frozenConfigHashHex = bytesToOptionalHex(snapshot.active_frozen_config_hash, 32);
    if (snapshot.active_epoch !== null && runIdHex && targetDeviceIdHex && frozenConfigHashHex) {
      const activeEpoch = safeMetricNumber(snapshot.active_epoch);
      if (activeEpoch === null) {
        throw new Error("daemon active epoch exceeded JavaScript safe integer range");
      }
      this.context = {
        epoch: activeEpoch,
        runIdHex,
        targetDeviceIdHex,
        frozenConfigHashHex,
      };
    } else if (!["prepared", "armed", "recording", "stopped", "failed"].includes(snapshot.state)) {
      this.context = null;
    }
    const latestSealed = bytesToOptionalHex(snapshot.latest_sealed_run_id, 16);
    if (latestSealed) this.lastSealedRunId = latestSealed;
  }

  private stopPolling(): void {
    if (this.pollTimer !== null) clearInterval(this.pollTimer);
    this.pollTimer = null;
  }

  private addEvent(severity: SystemEvent["severity"], code: string, message: string): void {
    this.events.push({
      id: `REPLAY-EVENT-${String(++this.eventSequence).padStart(4, "0")}`,
      severity,
      code,
      message,
      hostMonotonicMs: performance.now(),
    });
  }

  private finishRecordingClock(): void {
    if (this.recordingStartedAt !== null) {
      this.recordingAccumulatedMs += Math.max(0, performance.now() - this.recordingStartedAt);
      this.recordingStartedAt = null;
    }
  }

  private recordingSeconds(): number {
    const active = this.recordingStartedAt === null
      ? 0
      : Math.max(0, performance.now() - this.recordingStartedAt);
    return (this.recordingAccumulatedMs + active) / 1_000;
  }

  private publish(): void {
    const snapshot = this.getSnapshot();
    for (const subscriber of this.subscribers) subscriber(snapshot);
  }
}

function randomHex(bytes: number): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
}

function bytesToOptionalHex(values: readonly number[], expectedLength: number): string | null {
  if (values.length !== expectedLength) throw new Error("daemon identifier has an invalid byte length");
  if (values.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
    throw new Error("daemon identifier contains an invalid byte");
  }
  if (values.every((value) => value === 0)) return null;
  return values.map((value) => value.toString(16).padStart(2, "0")).join("");
}

function lastSequence(count: number | null): number | null {
  return count === null || count === 0 ? null : count - 1;
}

function safeMetricNumber(value: bigint | null): number | null {
  if (value === null || value > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(value);
}
