import {
  MAX_PODS_PER_RUN,
  type AcquireAdapter,
  type AcquireIntent,
  type AcquireLifecycleState,
  type AggregatorSnapshot,
  type CapabilityEvidence,
  type CapabilityId,
  type CapabilitySnapshot,
  type CommandReceipt,
  type ControlConnectionState,
  type DaemonLoadSnapshot,
  type DaemonSnapshot,
  type DeviceIdentitySnapshot,
  type DeviceKind,
  type DeviceNameReceipt,
  type EvidenceSlot,
  type EvidenceSlotId,
  type EvidenceStatus,
  type FaultCode,
  type FaultRecord,
  type MockFault,
  type MockFaultControl,
  type PodKey,
  type PodSnapshot,
  type PodTopologySnapshot,
  type PreviewFrame,
  type PreviewRequest,
  type PreviewSessionState,
  type PreviewSource,
  type RunIntegrityEvidence,
  type RunPlan,
  type RunReceipt,
  type RunReceiptStatus,
  type RecordingTargetRequest,
  type RecordingTargetReservation,
  type RenameDeviceRequest,
  type SnapshotListener,
  type Unsubscribe,
} from "./acquireAdapter";
import {
  SYNTHETIC_DEFAULT_SEED,
  SYNTHETIC_PREVIEW_MICROVOLTS_PER_COUNT,
  SYNTHETIC_SPIKE_PRETRIGGER_SAMPLES,
  SYNTHETIC_SPIKE_TEMPLATE,
  SyntheticNeuralModel,
} from "../core/syntheticNeural";

const MOCK_ADAPTER_ID = "forge.acquire.mock.v1";
const DEFAULT_TRANSITION_DELAY_MS = 12;
const DEFAULT_PREVIEW_INTERVAL_MS = 50;
const MAX_SELECTED_CHANNEL_WAVEFORMS = 128;

export interface MockAcquireAdapterOptions {
  transitionDelayMs?: number;
  previewIntervalMs?: number;
  connectedPodCount?: number;
  neuralChannelCount?: number;
  syntheticSeed?: number | bigint;
  now?: () => number;
}

function monotonicNow(): number {
  return globalThis.performance?.now() ?? Date.now();
}

/** Synthetic evidence identifier. Scope, not hash shape, prevents promotion to hardware evidence. */
function mockHash(sequence: bigint, salt = 0): string {
  const value = (sequence * 0x9e3779b97f4a7c15n + BigInt(salt + 1)) & ((1n << 256n) - 1n);
  return value.toString(16).padStart(64, "0");
}

function copySlot(slot: EvidenceSlot): EvidenceSlot {
  return { ...slot };
}

function copyEvidence(evidence: RunIntegrityEvidence): RunIntegrityEvidence {
  return {
    acquisition: copySlot(evidence.acquisition),
    durability: copySlot(evidence.durability),
    nwb: copySlot(evidence.nwb),
    analysis: copySlot(evidence.analysis),
    stimReceipt: copySlot(evidence.stimReceipt),
  };
}

function copyFault(fault: FaultRecord): FaultRecord {
  return { ...fault };
}

function copyRunReceipt(receipt: RunReceipt | null): RunReceipt | null {
  return receipt === null
    ? null
    : {
        ...receipt,
        evidence: copyEvidence(receipt.evidence),
        recordingTarget: { ...receipt.recordingTarget },
        nwbArtifact: receipt.nwbArtifact === null ? null : { ...receipt.nwbArtifact },
        faults: receipt.faults.map(copyFault),
      };
}

function copyPod(pod: PodSnapshot): PodSnapshot {
  return {
    ...pod,
    identity: { ...pod.identity },
    connection: { ...pod.connection },
    neuralInput: pod.neuralInput === null ? null : { ...pod.neuralInput },
  };
}

function copyAggregator(aggregator: AggregatorSnapshot): AggregatorSnapshot {
  return {
    ...aggregator,
    identity: { ...aggregator.identity },
    ports: aggregator.ports.map((port) => ({
      ...port,
      pod: port.pod === null ? null : copyPod(port.pod),
    })),
  };
}

function copyTopology(topology: PodTopologySnapshot): PodTopologySnapshot {
  return {
    ...topology,
    directPods: topology.directPods.map(copyPod),
    aggregators: topology.aggregators.map(copyAggregator),
  };
}

function copyPreviewFrame(frame: PreviewFrame): PreviewFrame {
  const processing = {
    ...frame.processing,
    passbandHz: frame.processing.passbandHz === null
      ? null
      : [frame.processing.passbandHz[0], frame.processing.passbandHz[1]] as const,
  };
  const coverage = {
    ...frame.coverage,
    sourceGapRanges: frame.coverage.sourceGapRanges.map((range) => ({ ...range })),
    analysisGapRanges: frame.coverage.analysisGapRanges.map((range) => ({ ...range })),
  };
  if (frame.encoding === "spike_preview_v3") {
    return {
      ...frame,
      processing,
      coverage,
      channelActivity: frame.channelActivity.map((channel) => ({ ...channel })),
      accounting: { ...frame.accounting },
      raster: frame.raster.map((event) => ({ ...event })),
      selectedChannelWaveforms: {
        ...frame.selectedChannelWaveforms,
        events: frame.selectedChannelWaveforms.events.map((event) => ({
          ...event,
          values: event.values.slice(),
        })),
      },
      selectedChannelWaveformStats: frame.selectedChannelWaveformStats === null
        ? null
        : {
            ...frame.selectedChannelWaveformStats,
            meanValues: frame.selectedChannelWaveformStats.meanValues.slice(),
            p10Values: frame.selectedChannelWaveformStats.p10Values.slice(),
            p90Values: frame.selectedChannelWaveformStats.p90Values.slice(),
          },
    };
  }
  return {
    ...frame,
    processing,
    coverage,
    channels: frame.channels.map((channel) => ({
      ...channel,
      minValues: channel.minValues.slice(),
      maxValues: channel.maxValues.slice(),
    })),
  };
}

class MockPreviewSource implements PreviewSource {
  readonly maxFramesPerSecond: number;
  private readonly now: () => number;
  private readonly intervalMs: number;
  private readonly resolvePod: (key: PodKey) => PodSnapshot | null;
  private readonly runContext: () => { runId: string | null; runEpoch: bigint | null };
  private readonly model: SyntheticNeuralModel;
  private readonly listeners = new Set<(frame: PreviewFrame) => void>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private latest: PreviewFrame | null = null;
  private timelineSampleEndExclusive: bigint | null = null;
  private sequence = 0n;
  private active = false;
  private request: PreviewRequest = {
    podKey: "MOCK-DIRECT-01",
    signalKind: "wideband",
    windowSeconds: 1,
    channelStart: 0,
    channelCount: 8,
    selectedChannel: 0,
  };

  constructor(
    now: () => number,
    intervalMs: number,
    resolvePod: (key: PodKey) => PodSnapshot | null,
    runContext: () => { runId: string | null; runEpoch: bigint | null },
    model: SyntheticNeuralModel,
  ) {
    this.now = now;
    this.intervalMs = intervalMs;
    this.resolvePod = resolvePod;
    this.runContext = runContext;
    this.model = model;
    this.maxFramesPerSecond = 1_000 / intervalMs;
  }

  setRequest(request: PreviewRequest): void {
    if (!request.podKey.trim()) throw new RangeError("preview podKey must not be empty");
    if (!Number.isFinite(request.windowSeconds) || request.windowSeconds < 0.25 || request.windowSeconds > 10) {
      throw new RangeError("preview windowSeconds must be between 0.25 and 10");
    }
    if (!Number.isInteger(request.channelStart) || request.channelStart < 0) {
      throw new RangeError("preview channelStart must be a non-negative integer");
    }
    if (!Number.isInteger(request.channelCount) || request.channelCount < 1 || request.channelCount > 16) {
      throw new RangeError("preview channelCount must be an integer from 1 through 16");
    }
    if (!Number.isInteger(request.selectedChannel) || request.selectedChannel < 0) {
      throw new RangeError("preview selectedChannel must be a non-negative integer");
    }
    this.request = { ...request };
    this.latest = null;
    if (this.active) this.emit(false);
  }

  getLatest(): PreviewFrame | null {
    return this.latest === null ? null : copyPreviewFrame(this.latest);
  }

  refresh(): void {
    if (this.active) this.emit(false);
  }

  subscribe(listener: (frame: PreviewFrame) => void): Unsubscribe {
    this.listeners.add(listener);
    if (this.latest) listener(this.getLatest()!);
    return () => this.listeners.delete(listener);
  }

  setActive(active: boolean, podKey?: PodKey): void {
    if (podKey) this.request = { ...this.request, podKey };
    this.active = active;
    if (!active) {
      if (this.timer !== null) clearInterval(this.timer);
      this.timer = null;
      return;
    }
    if (this.timer === null) {
      this.emit(true);
      this.timer = setInterval(() => this.emit(true), this.intervalMs);
    }
  }

  dispose(): void {
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
    this.listeners.clear();
  }

  private emit(advanceTimeline: boolean): void {
    const pod = this.resolvePod(this.request.podKey);
    const input = pod?.neuralInput ?? null;
    if (pod === null || input === null) return;
    if (this.request.channelStart >= input.neuralChannelCount
      || this.request.selectedChannel >= input.neuralChannelCount) return;
    this.sequence += 1n;
    const generatedAtMonotonicMs = this.now();
    const run = this.runContext();
    const sourceSampleCount = BigInt(Math.round(this.request.windowSeconds * input.sampleRateHz));
    const observedSampleEndExclusive = BigInt(Math.max(
      Number(sourceSampleCount),
      Math.round(generatedAtMonotonicMs * input.sampleRateHz / 1_000),
    ));
    if (this.timelineSampleEndExclusive === null || advanceTimeline) {
      this.timelineSampleEndExclusive = this.timelineSampleEndExclusive === null
        ? observedSampleEndExclusive
        : observedSampleEndExclusive > this.timelineSampleEndExclusive
          ? observedSampleEndExclusive
          : this.timelineSampleEndExclusive;
    }
    const sourceSampleEndExclusive = this.timelineSampleEndExclusive > sourceSampleCount
      ? this.timelineSampleEndExclusive
      : sourceSampleCount;
    const channelStart = this.request.channelStart;
    const channelCount = Math.min(
      this.request.channelCount,
      input.neuralChannelCount - channelStart,
    );
    const base = {
      scope: "mock" as const,
      synthetic: true,
      containsContinuousRawSamples: false as const,
      containsEventWaveformSnippets: this.request.signalKind === "spike",
      sequence: this.sequence,
      generatedAtMonotonicMs,
      runId: run.runId,
      runEpoch: run.runEpoch,
      podKey: pod.key,
      podId: pod.podId,
      podLabel: pod.label,
      inputChannelCount: input.neuralChannelCount,
      inputEvidenceHash: input.evidenceHash,
      valueUnit: input.previewValueUnit,
      valueUnitScope: input.scope,
      valueUnitReasonCode: input.reasonCode,
      valueEvidenceHash: input.evidenceHash,
      channelStart,
      channelCount,
      windowSeconds: this.request.windowSeconds,
      sourceSampleStart: sourceSampleEndExclusive > sourceSampleCount
        ? sourceSampleEndExclusive - sourceSampleCount
        : 0n,
      sourceSampleEndExclusive,
      previewFreshness: "current" as const,
      coverage: {
        source: "complete" as const,
        analysis: "complete" as const,
        sourceGapRanges: [],
        analysisGapRanges: [],
      },
    };

    if (this.request.signalKind === "spike") {
      const maxReturnedEvents = 64;
      const channelActivity = Array.from({ length: input.neuralChannelCount }, (_, channel) => {
        const observedEventCount = this.model.eventCountInRange(
          channel,
          base.sourceSampleStart,
          base.sourceSampleEndExclusive,
        );
        return {
          channel,
          observedEventCount,
          rateHz: observedEventCount / this.request.windowSeconds,
          valid: true,
        };
      });
      const bankActivity = channelActivity.slice(channelStart, channelStart + channelCount);
      const bankObservedEventCount = bankActivity.reduce(
        (sum, channel) => sum + channel.observedEventCount,
        0,
      );
      const activeChannels = bankActivity.filter((channel) => channel.observedEventCount > 0);
      const rotationOffset = activeChannels.length === 0
        ? 0
        : Number(this.sequence % BigInt(activeChannels.length));
      const quotas = new Map<number, number>(activeChannels.map((channel) => [channel.channel, 0]));
      const eventsByChannel = new Map(activeChannels.map((activity) => [
        activity.channel,
        [...this.model.eventCentersInRange(
          activity.channel,
          base.sourceSampleStart,
          base.sourceSampleEndExclusive,
        )],
      ]));
      let remaining = Math.min(maxReturnedEvents, bankObservedEventCount);
      let cursor = rotationOffset;
      while (remaining > 0 && activeChannels.length > 0) {
        const activity = activeChannels[cursor % activeChannels.length];
        const quota = quotas.get(activity.channel) ?? 0;
        if (quota < activity.observedEventCount) {
          quotas.set(activity.channel, quota + 1);
          remaining -= 1;
        }
        cursor += 1;
      }
      const raster = activeChannels.flatMap((activity) => {
        const quota = quotas.get(activity.channel) ?? 0;
        const centers = eventsByChannel.get(activity.channel) ?? [];
        return Array.from({ length: quota }, (_, returnedIndex) => {
          const sourceIndex = Math.min(
            activity.observedEventCount - 1,
            Math.floor(((returnedIndex + 0.5) * activity.observedEventCount) / Math.max(1, quota)),
          );
          const center = centers[sourceIndex];
          if (center === undefined) throw new Error("synthetic spike quota exceeded event schedule");
          return {
            eventId: `MOCK-SPIKE-${this.model.scenarioHash.slice(0, 12)}-${activity.channel}-${center}`,
            channel: activity.channel,
            eventOffsetMs: Number(center - base.sourceSampleStart) * 1_000 / input.sampleRateHz,
            peakValue: this.model.sampleAt(center, activity.channel).wideband
              * SYNTHETIC_PREVIEW_MICROVOLTS_PER_COUNT,
          };
        });
      }).sort((left, right) => left.eventOffsetMs - right.eventOffsetMs || left.channel - right.channel);
      const selectedActivity = channelActivity[this.request.selectedChannel];
      const selectedCenters = selectedActivity
          ? [...this.model.eventCentersInRange(
            selectedActivity.channel,
            base.sourceSampleStart,
            base.sourceSampleEndExclusive,
          )].filter((center) => center > base.sourceSampleStart
            && center + BigInt(
              SYNTHETIC_SPIKE_TEMPLATE.length - SYNTHETIC_SPIKE_PRETRIGGER_SAMPLES,
            ) <= base.sourceSampleEndExclusive)
        : [];
      const waveformCoverage = selectedCenters.length <= MAX_SELECTED_CHANNEL_WAVEFORMS
        ? "complete" as const
        : "fault" as const;
      const returnedCenters = waveformCoverage === "complete"
        ? selectedCenters
        : selectedCenters.slice(-MAX_SELECTED_CHANNEL_WAVEFORMS);
      const selectedChannelWaveformEvents = returnedCenters.map((center) => {
        const values = this.model.waveformAtEvent(this.request.selectedChannel, center)
          .map((value) => value * SYNTHETIC_PREVIEW_MICROVOLTS_PER_COUNT);
        return {
          eventId: `MOCK-SPIKE-${this.model.scenarioHash.slice(0, 12)}-${this.request.selectedChannel}-${center}`,
          channel: this.request.selectedChannel,
          centerSample: center,
          snippetSampleStart: center - BigInt(SYNTHETIC_SPIKE_PRETRIGGER_SAMPLES),
          snippetSampleEndExclusive: center
            + BigInt(values.length - SYNTHETIC_SPIKE_PRETRIGGER_SAMPLES),
          preTriggerSamples: SYNTHETIC_SPIKE_PRETRIGGER_SAMPLES,
          values,
        };
      });
      const selectedChannelWaveformStats = selectedChannelWaveformEvents.length > 0
        ? (() => {
            const waveforms = selectedChannelWaveformEvents.map((event) => event.values);
            const pointCount = waveforms[0]?.length ?? 0;
            const meanValues = Array.from({ length: pointCount }, (_, point) => waveforms.reduce(
              (sum, waveform) => sum + (waveform[point] ?? 0),
              0,
            ) / waveforms.length);
            const percentile = (point: number, fraction: number): number => {
              const values = waveforms.map((waveform) => waveform[point] ?? 0)
                .sort((left, right) => left - right);
              return values[Math.floor((values.length - 1) * fraction)] ?? 0;
            };
            return {
              channel: this.request.selectedChannel,
              thresholdValue: null,
              contributingWaveformCount: waveforms.length,
              meanValues,
              p10Values: meanValues.map((_, point) => percentile(point, 0.1)),
              p90Values: meanValues.map((_, point) => percentile(point, 0.9)),
            };
          })()
        : null;
      this.latest = {
        ...base,
        encoding: "spike_preview_v3",
        signalKind: "spike",
        sorting: "unsorted",
        processing: {
          status: "available",
          scope: "mock",
          algorithmId: "mock.spike.v3",
          summary: "Mock waveforms",
          sourceSampleRateHz: input.sampleRateHz,
          displaySampleRateHz: null,
          passbandHz: null,
          filterProfileId: null,
          configHash: this.model.scenarioHash,
          groupDelayMs: null,
          evidenceHash: this.model.scenarioHash,
        },
        waveformSampleRateHz: input.sampleRateHz,
        podObservedEventCount: channelActivity.reduce(
          (sum, channel) => sum + channel.observedEventCount,
          0,
        ),
        channelActivity,
        accounting: {
          selectionPolicy: "channel_stratified_rotating_v1",
          maxReturnedEvents,
          observedEventCount: bankObservedEventCount,
          rasterCandidateEventCount: bankObservedEventCount,
          sampledOutEventCount: bankObservedEventCount - raster.length,
          returnedRasterEventCount: raster.length,
          rotationOffset,
        },
        raster,
        selectedChannel: this.request.selectedChannel,
        selectedChannelWaveforms: {
          retentionSamples: sourceSampleCount,
          coverage: waveformCoverage,
          reasonCode: waveformCoverage === "complete"
            ? null
            : "SELECTED_CHANNEL_WAVEFORM_WINDOW_CAPACITY_EXCEEDED",
          observedEventCount: selectedCenters.length,
          returnedEventCount: selectedChannelWaveformEvents.length,
          events: selectedChannelWaveformEvents,
        },
        selectedChannelWaveformStats,
      };
    } else {
      const lfp = this.request.signalKind === "lfp";
      const points = Math.min(480, Math.max(160, Math.round(96 * this.request.windowSeconds)));
      const channels = Array.from({ length: channelCount }, (_, localChannel) => {
        const channel = channelStart + localChannel;
        const minima: number[] = [];
        const maxima: number[] = [];
        const representatives: number[] = [];
        for (let point = 0; point < points; point += 1) {
          const bucketStart = base.sourceSampleStart
            + (sourceSampleCount * BigInt(point)) / BigInt(points);
          const bucketEnd = base.sourceSampleStart
            + (sourceSampleCount * BigInt(point + 1)) / BigInt(points);
          const candidates = new Set<bigint>([
            bucketStart,
            bucketStart + (bucketEnd - bucketStart) / 2n,
            bucketEnd - 1n,
          ]);
          if (!lfp) {
            const pre = BigInt(SYNTHETIC_SPIKE_PRETRIGGER_SAMPLES);
            const eventSearchStart = bucketStart > pre ? bucketStart - pre : 0n;
            const eventSearchEnd = bucketEnd + pre + 1n;
            for (const center of this.model.eventCentersInRange(
              channel,
              eventSearchStart,
              eventSearchEnd,
            )) {
              for (let offset = -SYNTHETIC_SPIKE_PRETRIGGER_SAMPLES;
                offset <= SYNTHETIC_SPIKE_PRETRIGGER_SAMPLES;
                offset += 1) {
                const sample = center + BigInt(offset);
                if (sample >= bucketStart && sample < bucketEnd) candidates.add(sample);
              }
            }
          }
          const values = [...candidates].map((sample) => (
            lfp
              ? this.model.lfpAt(sample, channel)
              : this.model.sampleAt(sample, channel).wideband
          ) * SYNTHETIC_PREVIEW_MICROVOLTS_PER_COUNT);
          const minimum = Math.min(...values);
          const maximum = Math.max(...values);
          minima.push(minimum);
          maxima.push(maximum);
          representatives.push((minimum + maximum) / 2);
        }
        return {
          channel,
          minValues: minima,
          maxValues: maxima,
          rmsValue: Math.sqrt(representatives.reduce(
            (sum, value) => sum + value * value,
            0,
          ) / representatives.length),
          peakAbsValue: minima.reduce(
            (peak, value, index) => Math.max(peak, Math.abs(value), Math.abs(maxima[index] ?? 0)),
            0,
          ),
        };
      });
      this.latest = {
        ...base,
        encoding: "sampled_extrema_preview_v1",
        aggregation: "sampled_candidates",
        signalKind: this.request.signalKind,
        processing: {
          status: "available",
          scope: "mock",
          algorithmId: lfp
            ? "forge.mock.synthetic-lfp-component-sampled-extrema.v3"
            : "forge.mock.synthetic-wideband-sampled-extrema.v3",
          summary: lfp
            ? "Bounded sampled extrema of the LFP truth component from the shared integer scenario"
            : "Bounded sampled extrema from the shared integer wideband scenario; not complete bucket min/max",
          sourceSampleRateHz: input.sampleRateHz,
          displaySampleRateHz: points / this.request.windowSeconds,
          passbandHz: null,
          filterProfileId: null,
          configHash: this.model.scenarioHash,
          groupDelayMs: lfp ? null : 0,
          evidenceHash: this.model.scenarioHash,
        },
        pointsPerChannel: points,
        samplesPerBucket: Math.max(1, Math.floor(input.sampleRateHz * this.request.windowSeconds / points)),
        channels,
      };
    }
    const frame = this.getLatest()!;
    for (const listener of this.listeners) listener(frame);
  }
}

export class MockFaultController implements MockFaultControl {
  constructor(private readonly adapter: MockAcquireAdapter) {}

  inject(fault: MockFault): Promise<void> {
    this.adapter.injectMockFault(fault);
    return Promise.resolve();
  }

  clear(code: FaultCode): Promise<void> {
    this.adapter.clearMockFault(code);
    return Promise.resolve();
  }
}

export class MockAcquireAdapter implements AcquireAdapter {
  readonly adapterId = MOCK_ADAPTER_ID;
  readonly scope = "mock" as const;
  readonly previewSource: PreviewSource;
  readonly faultController: MockFaultController;

  private readonly now: () => number;
  private readonly transitionDelayMs: number;
  private readonly occupiedPodCount: number;
  private readonly neuralChannelCount: number;
  private readonly syntheticModel: SyntheticNeuralModel;
  private readonly preview: MockPreviewSource;
  private readonly listeners = new Set<SnapshotListener>();
  private readonly timers = new Set<ReturnType<typeof setTimeout>>();
  private readonly timerLanes = new Map<ReturnType<typeof setTimeout>, "preview" | "lifecycle">();
  private readonly topologyEvidenceHash = mockHash(1n, 301);
  private lifecycle: AcquireLifecycleState = "disconnected";
  private previewState: PreviewSessionState = "stopped";
  private controlConnection: ControlConnectionState = "disconnected";
  private stale = false;
  private snapshotSequence = 1n;
  private commandSequence = 0n;
  private runReceiptSequence = 0n;
  private runCounter = 0n;
  private runId: string | null = null;
  private runEpoch: bigint | null = null;
  private recordingTarget: RecordingTargetReservation | null = null;
  private selectedPodKeys: PodKey[] = [];
  private readonly deviceNames = new Map<string, { displayName: string; revision: bigint }>();
  private deviceNameReceiptSequence = 0n;
  /** Preview and Recording have independent command lanes. */
  private pendingLifecycleCommand = false;
  private pendingPreviewCommand = false;
  private lastCommandReceiptId: string | null = null;
  private evidence: RunIntegrityEvidence;
  private faults: FaultRecord[] = [];
  private integrityFailed = false;
  private durabilityFailure = false;
  private disposed = false;

  constructor(options: MockAcquireAdapterOptions = {}) {
    this.now = options.now ?? monotonicNow;
    this.transitionDelayMs = options.transitionDelayMs ?? DEFAULT_TRANSITION_DELAY_MS;
    const previewIntervalMs = options.previewIntervalMs ?? DEFAULT_PREVIEW_INTERVAL_MS;
    this.occupiedPodCount = options.connectedPodCount ?? 3;
    this.neuralChannelCount = options.neuralChannelCount ?? 32;
    this.syntheticModel = new SyntheticNeuralModel({
      sampleRateHz: 30_000,
      seed: options.syntheticSeed ?? SYNTHETIC_DEFAULT_SEED,
    });
    if (!Number.isFinite(this.transitionDelayMs) || this.transitionDelayMs < 0) {
      throw new RangeError("transitionDelayMs must be a finite non-negative number");
    }
    if (!Number.isFinite(previewIntervalMs) || previewIntervalMs <= 0) {
      throw new RangeError("previewIntervalMs must be a finite positive number");
    }
    if (!Number.isInteger(this.occupiedPodCount)
      || this.occupiedPodCount < 1
      || this.occupiedPodCount > MAX_PODS_PER_RUN) {
      throw new RangeError("connectedPodCount must be an integer from 1 through 8");
    }
    if (!Number.isInteger(this.neuralChannelCount)
      || this.neuralChannelCount < 1
      || this.neuralChannelCount > 128) {
      throw new RangeError("neuralChannelCount must be an integer from 1 through 128");
    }
    this.evidence = this.initialEvidence();
    this.preview = new MockPreviewSource(
      this.now,
      previewIntervalMs,
      (key) => this.podForKey(key),
      () => ["recording", "stop_requested"].includes(this.lifecycle)
        ? { runId: this.runId, runEpoch: this.runEpoch }
        : { runId: null, runEpoch: null },
      this.syntheticModel,
    );
    this.previewSource = this.preview;
    this.faultController = new MockFaultController(this);
  }

  readCapabilities(): Promise<CapabilitySnapshot> {
    const capabilities = this.capabilities();
    return Promise.resolve({
      adapterId: this.adapterId,
      scope: "mock",
      synthetic: true,
      sequence: 1n,
      observedAtMonotonicMs: this.now(),
      maxPodsPerRun: MAX_PODS_PER_RUN,
      capabilities,
      evidenceHash: mockHash(1n, 91),
    });
  }

  readSnapshot(): Promise<DaemonSnapshot> {
    return Promise.resolve(this.snapshot());
  }

  subscribeSnapshots(listener: SnapshotListener): Unsubscribe {
    this.listeners.add(listener);
    listener(this.snapshot());
    return () => this.listeners.delete(listener);
  }

  execute(intent: AcquireIntent): Promise<CommandReceipt> {
    if (this.disposed) return Promise.resolve(this.reject(intent, "ADAPTER_DISPOSED", "Mock adapter 已释放"));
    const validation = this.validateIntent(intent);
    if (validation !== null) return Promise.resolve(this.reject(intent, validation.code, validation.message));

    this.commandSequence += 1n;
    const receiptId = `MOCK-CMD-${this.commandSequence.toString().padStart(6, "0")}`;
    const stateAtAcceptance = this.lifecycle;
    const previewStateAtAcceptance = this.previewState;
    const requestedState = this.requestedState(intent);
    const requestedPreviewState = this.requestedPreviewState(intent);
    let pendingRun: { id: string; epoch: bigint; plan: RunPlan } | null = null;
    if (intent.type === "preflight") {
      const next = this.runCounter + 1n;
      pendingRun = {
        id: `MOCK-RUN-${next.toString().padStart(4, "0")}`,
        epoch: next,
        plan: {
          ...intent.plan,
          selectedDevices: intent.plan.selectedDevices.map((device) => ({ ...device })),
          recordingTarget: { ...intent.plan.recordingTarget },
        },
      };
    }
    const receipt: CommandReceipt = {
      receiptKind: "command",
      receiptId,
      requestId: this.commandSequence,
      scope: "mock",
      synthetic: true,
      intent: intent.type,
      accepted: true,
      reasonCode: "ACCEPTED",
      message: "命令已接收；后续状态仅由独立 snapshot 报告",
      stateAtAcceptance,
      requestedState,
      previewStateAtAcceptance,
      requestedPreviewState,
      runId: pendingRun?.id ?? this.runId,
      runEpoch: pendingRun?.epoch ?? this.runEpoch,
      issuedAtMonotonicMs: this.now(),
      evidenceHash: mockHash(this.commandSequence, 101),
    };
    this.lastCommandReceiptId = receiptId;
    if (this.isPreviewIntent(intent)) this.pendingPreviewCommand = true;
    else this.pendingLifecycleCommand = true;
    this.scheduleIntent(intent, pendingRun);
    return Promise.resolve({ ...receipt });
  }

  /**
   * Reset only this bounded fixture's Run bookkeeping after an external data
   * plane has authoritatively reported a terminal failure. The software
   * adapter uses this after its own failure acknowledgement; it never edits,
   * seals, or deletes the external journal.
   */
  acknowledgeExternalFailedRun(): Promise<CommandReceipt> {
    const intent = { type: "acknowledge_failed_run" } as const;
    if (this.disposed) return Promise.resolve(this.reject(intent, "ADAPTER_DISPOSED", "Mock adapter 已释放"));
    if (this.runId === null) {
      return Promise.resolve(this.reject(intent, "NO_ACTIVE_RUN", "没有需要关闭的 fixture Run"));
    }

    this.commandSequence += 1n;
    const receipt: CommandReceipt = {
      receiptKind: "command",
      receiptId: `MOCK-CMD-${this.commandSequence.toString().padStart(6, "0")}`,
      requestId: this.commandSequence,
      scope: "mock",
      synthetic: true,
      intent: intent.type,
      accepted: true,
      reasonCode: "EXTERNAL_FAILURE_ACKNOWLEDGED",
      message: "External failed Run acknowledged; fixture state closed without creating a seal",
      stateAtAcceptance: this.lifecycle,
      requestedState: "connected_idle",
      previewStateAtAcceptance: this.previewState,
      requestedPreviewState: null,
      runId: this.runId,
      runEpoch: this.runEpoch,
      issuedAtMonotonicMs: this.now(),
      evidenceHash: mockHash(this.commandSequence, 102),
    };
    this.lastCommandReceiptId = receipt.receiptId;
    // The external Failed snapshot is authoritative; no queued fixture-only
    // Recording transition may overwrite the closed state afterward.
    this.cancelCommandLane("lifecycle");
    this.resetFailedRunState();
    return Promise.resolve({ ...receipt });
  }

  renameDevice(request: RenameDeviceRequest): Promise<DeviceNameReceipt> {
    this.deviceNameReceiptSequence += 1n;
    const receiptId = `MOCK-NAME-${this.deviceNameReceiptSequence.toString().padStart(6, "0")}`;
    const canonicalDescriptor = this.deviceDescriptors().find((item) =>
      item.kind === request.kind && item.deviceId === request.deviceId);
    const current = canonicalDescriptor === undefined
      ? null
      : this.deviceIdentity(request.kind, canonicalDescriptor.deviceId);
    const rejected = (reasonCode: string, message: string): DeviceNameReceipt => ({
      receiptKind: "device_name",
      receiptId,
      scope: "mock",
      synthetic: true,
      accepted: false,
      reasonCode,
      message,
      kind: request.kind,
      deviceId: request.deviceId,
      identityEvidenceHash: current?.identityEvidenceHash ?? null,
      previousRevision: current?.revision ?? 0n,
      committedRevision: null,
      committedDisplayName: null,
      persistence: "mock_session",
      readBackVerified: false,
      nameRecordEvidenceHash: null,
      issuedAtMonotonicMs: this.now(),
      evidenceHash: mockHash(this.deviceNameReceiptSequence, 211),
    });
    if (this.disposed) return Promise.resolve(rejected("ADAPTER_DISPOSED", "Mock adapter 已释放"));
    if (current === null) return Promise.resolve(rejected("UNKNOWN_DEVICE", "Snapshot 中没有该 immutable device ID"));
    if (request.expectedIdentityEvidenceHash !== current.identityEvidenceHash) {
      return Promise.resolve(rejected("STALE_DEVICE_IDENTITY", "设备 identity receipt 已变化，请刷新后重试"));
    }
    if (!current.writable) return Promise.resolve(rejected("NAME_READ_ONLY", "该设备没有可写的名称 capability"));
    if (request.expectedRevision !== current.revision) {
      return Promise.resolve(rejected("STALE_NAME_REVISION", "设备名称 revision 已变化，请刷新后重试"));
    }
    const displayName = request.displayName.trim().normalize("NFC");
    const utf8Bytes = new TextEncoder().encode(displayName).byteLength;
    if (Array.from(displayName).length < 1 || Array.from(displayName).length > 48
      || utf8Bytes > (current.maxNameUtf8Bytes ?? 0)
      || /[\u0000-\u001f\u007f]/u.test(displayName)) {
      return Promise.resolve(rejected(
        "INVALID_DISPLAY_NAME",
        `显示名称必须是 1–48 个可显示字符且不超过 ${current.maxNameUtf8Bytes ?? 0} UTF-8 bytes`,
      ));
    }
    const duplicate = this.allDeviceIdentities().some((identity) =>
      identity.deviceId !== request.deviceId
      && identity.displayName.localeCompare(displayName, undefined, { sensitivity: "accent" }) === 0);
    if (duplicate) return Promise.resolve(rejected("DUPLICATE_DISPLAY_NAME", "当前设备列表中已存在同名设备"));

    const committedRevision = current.revision + 1n;
    this.deviceNames.set(request.deviceId, { displayName, revision: committedRevision });
    this.publish();
    return Promise.resolve({
      receiptKind: "device_name",
      receiptId,
      scope: "mock",
      synthetic: true,
      accepted: true,
      reasonCode: "MOCK_SESSION_COMMITTED",
      message: "Mock 会话名称已读回；未写入设备非易失存储",
      kind: request.kind,
      deviceId: request.deviceId,
      identityEvidenceHash: current.identityEvidenceHash,
      previousRevision: current.revision,
      committedRevision,
      committedDisplayName: displayName,
      persistence: "mock_session",
      readBackVerified: true,
      nameRecordEvidenceHash: mockHash(committedRevision + 1n, 213),
      issuedAtMonotonicMs: this.now(),
      evidenceHash: mockHash(this.deviceNameReceiptSequence, 212),
    });
  }

  dispose(): void {
    this.disposed = true;
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
    this.timerLanes.clear();
    this.listeners.clear();
    this.preview.dispose();
  }

  injectMockFault(fault: MockFault): void {
    if (this.disposed || this.faults.some((item) => item.code === fault.type && item.latched)) return;
    const now = this.now();
    const runCapturingSource = this.runId !== null
      && ["recording", "stop_requested"].includes(this.lifecycle);
    const recoverable = fault.type !== "counter_gap" || !runCapturingSource;
    const missingSamples = Math.max(1, Math.trunc(
      fault.type === "counter_gap" ? fault.missingSamples ?? 1 : 1,
    ));
    const lastCoveredSample = this.preview.getLatest()?.sourceSampleEndExclusive ?? 0n;
    const faultSampleStart = fault.type === "counter_gap" ? lastCoveredSample : null;
    const faultSampleEndExclusive = fault.type === "counter_gap"
      ? lastCoveredSample + BigInt(missingSamples)
      : null;
    const message = fault.type === "counter_gap"
      ? `Mock ${runCapturingSource ? "Run" : "Preview"} source coverage failed at [${faultSampleStart}, ${faultSampleEndExclusive})`
      : fault.type === "control_pipe_loss"
        ? "Mock control pipe 丢失；daemon Run 未停止"
        : fault.reason ?? "Mock durability barrier 失败";
    this.faults.push({
      code: fault.type,
      scope: "mock",
      message,
      latched: true,
      recoverable,
      injected: true,
      sampleStart: faultSampleStart,
      sampleEndExclusive: faultSampleEndExclusive,
      observedAtMonotonicMs: now,
      evidenceHash: mockHash(this.snapshotSequence + 1n, 121 + this.faults.length),
    });
    if (fault.type === "counter_gap") {
      this.previewState = "fault";
      this.preview.setActive(false);
      if (runCapturingSource) {
        this.integrityFailed = true;
        this.setLifecycle("recovery_required");
        this.setSlot("acquisition", "failed", message, faultSampleStart);
        this.setSlot("analysis", "failed", `Analysis coverage invalid after ${message}`, faultSampleStart);
      }
    } else if (fault.type === "control_pipe_loss") {
      this.controlConnection = "lost";
      this.stale = true;
      this.preview.setActive(false);
    } else {
      this.durabilityFailure = true;
      if (["recording_stopped", "finalizing"].includes(this.lifecycle)) {
        this.setSlot("durability", "failed", message, null);
        this.setLifecycle("recovery_required");
      } else {
        this.setSlot(
          "durability",
          this.lifecycle === "recording" ? "active" : "idle",
          `${message}; fault injection armed for the next End and Save operation`,
          null,
        );
      }
    }
    this.publish();
  }

  clearMockFault(code: FaultCode): void {
    if (code === "counter_gap") {
      if (this.integrityFailed || this.runId !== null) {
        // A missing source interval inside a Run is historical evidence and
        // cannot be cleared. The operator must acknowledge the failed Run.
        this.publish();
        return;
      }
      for (const fault of this.faults) {
        if (fault.code === code) fault.latched = false;
      }
      this.previewState = "stopped";
      this.publish();
      return;
    }
    for (const fault of this.faults) {
      if (fault.code === code) fault.latched = false;
    }
    if (code === "control_pipe_loss") this.stale = false;
    if (code === "durability_failure") this.durabilityFailure = false;
    this.publish();
  }

  private validateIntent(intent: AcquireIntent): { code: string; message: string } | null {
    if (this.isPreviewIntent(intent) ? this.pendingPreviewCommand : this.pendingLifecycleCommand) {
      return {
        code: "COMMAND_IN_FLIGHT",
        message: this.isPreviewIntent(intent)
          ? "上一 Preview 命令仍在等待 snapshot 转移"
          : "上一 Recording 命令仍在等待 snapshot 转移",
      };
    }
    switch (intent.type) {
      case "connect":
        return this.controlConnection === "connected"
          ? { code: "ALREADY_CONNECTED", message: "控制面已连接" }
          : null;
      case "disconnect_control":
        if (this.controlConnection !== "connected") {
          return { code: "NOT_CONNECTED", message: "控制面未连接" };
        }
        if (!["connected_idle", "finalized"].includes(this.lifecycle)) {
          return {
            code: "ACTIVE_RUN_CONTROL_REQUIRED",
            message: "当前 Run 尚未结束；必须保留控制连接，才能执行结束并保存或确认失败",
          };
        }
        return null;
      case "start_preview": {
        if (this.controlConnection !== "connected") {
          return { code: "NOT_CONNECTED", message: "必须先连接控制面" };
        }
        if (!["stopped", "fault"].includes(this.previewState)) {
          return { code: "INVALID_PREVIEW_STATE", message: "Preview 已启动或正在转移" };
        }
        const pod = this.podForKey(intent.podKey);
        if (intent.topologyEvidenceHash !== this.topologyEvidenceHash || pod === null || !pod.selectable) {
          return { code: "INVALID_PREVIEW_DEVICE", message: "Preview 设备或 topology receipt 已失效" };
        }
        return null;
      }
      case "stop_preview":
        if (this.previewState !== "live") {
          return { code: "INVALID_PREVIEW_STATE", message: "当前没有 live Preview" };
        }
        return null;
      case "preflight": {
        if (this.lifecycle !== "connected_idle" && this.lifecycle !== "finalized") {
          return { code: "INVALID_STATE", message: "仅 connected_idle 或 finalized 可开始新 preflight" };
        }
        if (this.previewState !== "live") {
          return { code: "PREVIEW_REQUIRED", message: "必须先启动 Preview 并确认数据流" };
        }
        const devices = intent.plan.selectedDevices;
        const keys = devices.map((device) => device.podKey);
        const uniqueKeys = new Set(keys);
        const uniqueDeviceIds = new Set(devices.map((device) => device.deviceId));
        const selectablePods = new Map(this.allPods()
          .filter((pod) => pod.selectable)
          .map((pod) => [pod.key, pod] as const));
        if (!intent.plan.label.trim() || !Number.isFinite(intent.plan.plannedDurationSeconds)
          || intent.plan.plannedDurationSeconds <= 0 || keys.length === 0
          || keys.length > MAX_PODS_PER_RUN || uniqueKeys.size !== keys.length
          || uniqueDeviceIds.size !== devices.length
          || intent.plan.topologyEvidenceHash !== this.topologyEvidenceHash
          || this.validateRecordingTarget(intent.plan.recordingTarget) !== null
          || devices.some((device) => {
            const pod = selectablePods.get(device.podKey);
            return pod === undefined
              || pod.identity.deviceId !== device.deviceId
              || pod.identity.identityEvidenceHash !== device.identityEvidenceHash
              || pod.neuralInput?.evidenceHash !== device.inputEvidenceHash;
          })) {
          return { code: "INVALID_PLAN", message: "Run plan、记录目标或设备选择无效" };
        }
        return null;
      }
      case "arm_recording":
        return this.lifecycle === "preflight_passed"
          ? null
          : { code: "INVALID_STATE", message: "必须先通过 Recording preflight" };
      case "start_recording":
        return this.lifecycle === "armed"
          ? null
          : { code: "INVALID_STATE", message: "Recording Arm 尚未由 snapshot 证明" };
      case "stop_recording":
        return this.lifecycle === "recording" ? null : { code: "INVALID_STATE", message: "当前没有 recording Run" };
      case "recover_run":
        return this.lifecycle === "recovery_required"
          && !this.durabilityFailure
          && !this.integrityFailed
          ? null
          : { code: "RECOVERY_BLOCKED", message: "只有可恢复的 durability fault 可 Recover；source coverage fault 必须确认失败" };
      case "acknowledge_failed_run":
        return this.lifecycle === "recovery_required" ? null : { code: "INVALID_STATE", message: "没有需要确认的失败 Run" };
    }
  }

  private requestedState(intent: AcquireIntent): AcquireLifecycleState | null {
    switch (intent.type) {
      case "connect": return this.runId === null ? "connected_idle" : this.lifecycle;
      case "disconnect_control": return this.runId === null ? "disconnected" : this.lifecycle;
      case "start_preview":
      case "stop_preview": return null;
      case "preflight": return "preflighting";
      case "arm_recording": return "arm_requested";
      case "start_recording": return "start_requested";
      case "stop_recording": return "stop_requested";
      case "recover_run": return "finalizing";
      case "acknowledge_failed_run": return "connected_idle";
    }
  }

  private requestedPreviewState(intent: AcquireIntent): PreviewSessionState | null {
    if (intent.type === "start_preview") return "start_requested";
    if (intent.type === "stop_preview") return "stop_requested";
    return null;
  }

  private scheduleIntent(
    intent: AcquireIntent,
    pendingRun: { id: string; epoch: bigint; plan: RunPlan } | null,
  ): void {
    const steps: Array<() => void> = [];
    switch (intent.type) {
      case "connect":
        steps.push(() => {
          this.controlConnection = "connected";
          this.stale = false;
          for (const fault of this.faults) if (fault.code === "control_pipe_loss") fault.latched = false;
          if (this.previewState === "live") this.preview.setActive(true);
          if (this.runId === null) this.setLifecycle("connected_idle");
          else this.publish();
        });
        break;
      case "disconnect_control":
        steps.push(() => {
          this.controlConnection = "disconnected";
          this.preview.setActive(false);
          if (this.runId === null) this.setLifecycle("disconnected");
          else this.publish();
        });
        break;
      case "start_preview":
        steps.push(() => this.setPreviewState("start_requested", intent.podKey));
        steps.push(() => this.setPreviewState("live", intent.podKey));
        break;
      case "stop_preview":
        steps.push(() => this.setPreviewState("stop_requested"));
        steps.push(() => this.setPreviewState("stopped"));
        break;
      case "preflight":
        steps.push(() => {
          this.runCounter = pendingRun!.epoch;
          this.runId = pendingRun!.id;
          this.runEpoch = pendingRun!.epoch;
          this.recordingTarget = this.reserveRecordingTarget(
            pendingRun!.plan.recordingTarget,
            pendingRun!.epoch,
          );
          this.selectedPodKeys = pendingRun!.plan.selectedDevices.map((device) => device.podKey);
          this.integrityFailed = false;
          this.faults = [];
          this.runReceiptSequence = 0n;
          this.evidence = this.initialEvidence();
          this.setLifecycle("preflighting");
        });
        steps.push(() => this.setLifecycle("preflight_passed"));
        break;
      case "arm_recording":
        steps.push(() => this.setLifecycle("arm_requested"));
        steps.push(() => this.setLifecycle("armed"));
        break;
      case "start_recording":
        steps.push(() => this.setLifecycle("start_requested"));
        steps.push(() => this.setLifecycle("recording"));
        break;
      case "stop_recording":
        steps.push(() => this.setLifecycle("stop_requested"));
        steps.push(() => this.setLifecycle("recording_stopped"));
        steps.push(() => this.setLifecycle("finalizing"));
        steps.push(() => this.setLifecycle(this.durabilityFailure ? "recovery_required" : "finalized"));
        break;
      case "recover_run":
        steps.push(() => this.setLifecycle("finalizing"));
        steps.push(() => this.setLifecycle(this.durabilityFailure ? "recovery_required" : "finalized"));
        break;
      case "acknowledge_failed_run":
        steps.push(() => this.resetFailedRunState());
        break;
    }
    this.queueSteps(steps, this.isPreviewIntent(intent) ? "preview" : "lifecycle");
  }

  private queueSteps(steps: Array<() => void>, lane: "preview" | "lifecycle"): void {
    steps.forEach((step, index) => {
      const timer = setTimeout(() => {
        this.timers.delete(timer);
        this.timerLanes.delete(timer);
        step();
        if (index === steps.length - 1) {
          if (lane === "preview") this.pendingPreviewCommand = false;
          else this.pendingLifecycleCommand = false;
        }
      }, this.transitionDelayMs * (index + 1));
      this.timers.add(timer);
      this.timerLanes.set(timer, lane);
    });
  }

  private cancelCommandLane(lane: "preview" | "lifecycle"): void {
    for (const [timer, timerLane] of this.timerLanes) {
      if (timerLane !== lane) continue;
      clearTimeout(timer);
      this.timerLanes.delete(timer);
      this.timers.delete(timer);
    }
    if (lane === "preview") this.pendingPreviewCommand = false;
    else this.pendingLifecycleCommand = false;
  }

  private isPreviewIntent(intent: AcquireIntent): boolean {
    return intent.type === "start_preview" || intent.type === "stop_preview";
  }

  private resetFailedRunState(): void {
    this.runId = null;
    this.runEpoch = null;
    this.recordingTarget = null;
    this.selectedPodKeys = [];
    this.faults = [];
    this.integrityFailed = false;
    this.durabilityFailure = false;
    this.evidence = this.initialEvidence();
    if (this.previewState === "fault") this.previewState = "stopped";
    this.setLifecycle("connected_idle");
  }

  private setPreviewState(next: PreviewSessionState, podKey?: PodKey): void {
    this.previewState = next;
    this.preview.setActive(next === "live" && this.controlConnection === "connected", podKey);
    this.publish();
  }

  private setLifecycle(next: AcquireLifecycleState): void {
    this.lifecycle = next;
    const now = this.now();
    const acquisition: Record<AcquireLifecycleState, [EvidenceStatus, string]> = {
      disconnected: ["idle", "Mock control disconnected"],
      connected_idle: ["idle", "Mock source connected; no Run"],
      preflighting: ["idle", "Preflight in progress; no acquisition evidence"],
      preflight_passed: ["idle", "Mock preflight passed; acquisition has not started"],
      arm_requested: ["idle", "Recording Arm requested; acquisition has not started"],
      armed: ["idle", "Recording Arm acknowledged; acquisition has not started"],
      start_requested: ["pending", "Acquisition start requested"],
      recording: ["active", "Synthetic acquisition active"],
      stop_requested: ["pending", "End and Save requested; Preview remains independent"],
      recording_stopped: ["proven", "Recording input closed; draining before durability barrier"],
      finalizing: ["proven", "Recording input closed; mock durability barrier and seal pending"],
      finalized: ["proven", "Mock acquisition evidence finalized"],
      recovery_required: [this.integrityFailed ? "failed" : "proven", this.integrityFailed
        ? "Acquisition source coverage failed; End and Save cannot produce a valid seal"
        : "Acquisition stopped; recoverable durability failure"],
    };
    const [status, summary] = acquisition[next];
    this.setSlot("acquisition", status, summary, next === "recording" ? 0n : null, now);
    if (next === "recording") {
      this.setSlot("durability", "active", "Mock journal is accumulating; not yet durable", null, now);
    } else if (["stop_requested", "recording_stopped", "finalizing"].includes(next)) {
      this.setSlot("durability", "pending", next === "recording_stopped"
        ? "Recording Stop acknowledged; durability barrier has not completed"
        : "Mock durability barrier pending", null, now);
    } else if (next === "finalized") {
      this.setSlot("durability", "proven", "Mock durability and seal evidence complete", 0n, now);
    } else if (next === "recovery_required") {
      this.setSlot(
        "durability",
        this.durabilityFailure ? "failed" : "pending",
        this.durabilityFailure
          ? "Mock durability evidence failed; recovery required"
          : "Run aborted by source coverage failure; no final durability claim",
        null,
        now,
      );
    }
    this.runReceiptSequence += this.runId === null ? 0n : 1n;
    this.preview.refresh();
    this.publish();
  }

  private setSlot(
    id: EvidenceSlotId,
    status: EvidenceStatus,
    summary: string,
    watermark: bigint | null,
    now = this.now(),
  ): void {
    const property = id === "stim_receipt" ? "stimReceipt" : id;
    const previous = this.evidence[property];
    this.evidence[property] = {
      ...previous,
      status,
      summary,
      watermark,
      receiptSequence: this.runReceiptSequence === 0n ? null : this.runReceiptSequence,
      evidenceHash: this.runId === null ? null : mockHash(this.runReceiptSequence + 1n, 141),
      updatedAtMonotonicMs: now,
    };
  }

  private initialEvidence(): RunIntegrityEvidence {
    const now = this.now();
    const slot = (id: EvidenceSlotId, status: EvidenceStatus, summary: string): EvidenceSlot => ({
      id,
      status,
      scope: "mock",
      summary,
      watermark: null,
      receiptSequence: null,
      evidenceHash: null,
      updatedAtMonotonicMs: now,
    });
    return {
      acquisition: slot("acquisition", "idle", "Mock adapter disconnected"),
      durability: slot("durability", "idle", "No active mock Run"),
      nwb: slot("nwb", "qualification_required", "NWB production path is not qualified"),
      analysis: slot("analysis", "unavailable", "No qualified analysis worker is connected"),
      stimReceipt: slot(
        "stim_receipt",
        "unavailable",
        "No optional external-event receipt producer is connected; this does not affect recording closure",
      ),
    };
  }

  private capabilities(): Readonly<Record<CapabilityId, CapabilityEvidence>> {
    const item = (
      id: CapabilityId,
      status: CapabilityEvidence["status"],
      claimScope: CapabilityEvidence["claimScope"],
      reasonCode: string,
      summary: string,
    ): CapabilityEvidence => ({
      id,
      status,
      claimScope,
      reasonCode,
      summary,
      evidenceHash: claimScope === "mock" ? mockHash(1n, id.length) : null,
    });
    return {
      mock_acquisition: item("mock_acquisition", "available", "mock", "MOCK_ONLY", "Synthetic acquisition workflow only"),
      decimated_preview: item("decimated_preview", "available", "mock", "MOCK_SAMPLED_EXTREMA", "Synthetic sampled-extrema preview; not complete bucket min/max and no continuous raw samples"),
      lfp_preview: item("lfp_preview", "available", "mock", "MOCK_SYNTHETIC_COMPONENT", "Synthetic 8 Hz LFP truth-component sampled extrema; production LFP DSP is not connected"),
      spike_preview: item("spike_preview", "available", "mock", "MOCK_SYNTHETIC_ORACLE", "Mock waveforms; detector unavailable"),
      fault_injection: item("fault_injection", "available", "mock", "MOCK_ONLY", "Mock-only fault controller"),
      ft601_direct: item("ft601_direct", "unavailable", "hardware", "NO_ADMISSION_RECEIPT", "FT601/D3XX hardware is unavailable"),
      aggregator_10gbe: item("aggregator_10gbe", "unavailable", "hardware", "API_NOT_FROZEN", "Aggregator discovery/control/stream is unavailable"),
      rhs_acquisition: item("rhs_acquisition", "qualification_required", "hardware", "HIL_REQUIRED", "RHS acquisition requires hardware qualification"),
      nwb_materialization: item("nwb_materialization", "qualification_required", "software", "PRODUCTION_GATE_OPEN", "NWB production materialization is not qualified"),
      stimulation: item("stimulation", "unavailable", "hardware", "NO_SAFETY_RECEIPT", "Physical stimulation Arm is unavailable"),
      closed_loop: item("closed_loop", "unavailable", "hardware", "NO_CLOSED_LOOP_RECEIPT", "Closed-loop control is unavailable"),
      release_24h: item("release_24h", "qualification_required", "hardware", "ENDURANCE_GATE_OPEN", "24-hour product release gate has not passed"),
    };
  }

  private reject(intent: AcquireIntent, reasonCode: string, message: string): CommandReceipt {
    this.commandSequence += 1n;
    return {
      receiptKind: "command",
      receiptId: `MOCK-CMD-${this.commandSequence.toString().padStart(6, "0")}`,
      requestId: this.commandSequence,
      scope: "mock",
      synthetic: true,
      intent: intent.type,
      accepted: false,
      reasonCode,
      message,
      stateAtAcceptance: this.lifecycle,
      requestedState: null,
      previewStateAtAcceptance: this.previewState,
      requestedPreviewState: null,
      runId: this.runId,
      runEpoch: this.runEpoch,
      issuedAtMonotonicMs: this.now(),
      evidenceHash: mockHash(this.commandSequence, 161),
    };
  }

  private validateRecordingTarget(target: RecordingTargetRequest): string | null {
    if (target.allocationPolicy !== "create_new_incrementing_suffix" || target.overwritePolicy !== "forbid") {
      return "UNSAFE_ALLOCATION_POLICY";
    }
    const directory = this.normalizeDirectory(target.requestedDirectory);
    const isDriveAbsolute = /^[A-Za-z]:\\/.test(directory);
    const isUncAbsolute = /^\\\\[^\\]+\\[^\\]+/.test(directory);
    if ((!isDriveAbsolute && !isUncAbsolute) || directory.length > 240
      || directory.split("\\").some((segment) => segment === "..")) {
      return "INVALID_DIRECTORY";
    }
    const baseName = target.baseName.trim();
    const reserved = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/iu;
    if (baseName.length < 1 || baseName.length > 80 || baseName === "." || baseName === ".."
      || /[<>:"/\\|?*\u0000-\u001f]/u.test(baseName)
      || /[. ]$/u.test(baseName) || reserved.test(baseName)) {
      return "INVALID_BASE_NAME";
    }
    return null;
  }

  private normalizeDirectory(value: string): string {
    const normalized = value.trim().replaceAll("/", "\\");
    if (/^[A-Za-z]:\\$/u.test(normalized)) return normalized;
    return normalized.replace(/\\+$/u, "");
  }

  private reserveRecordingTarget(
    target: RecordingTargetRequest,
    sequence: bigint,
  ): RecordingTargetReservation {
    const requestedDirectory = this.normalizeDirectory(target.requestedDirectory);
    const allocatedLeafName = `${target.baseName.trim()}-${sequence.toString().padStart(3, "0")}`;
    const separator = requestedDirectory.endsWith("\\") ? "" : "\\";
    return {
      reservationId: `MOCK-TARGET-${sequence.toString().padStart(6, "0")}`,
      requestedDirectory,
      allocatedLeafName,
      resolvedRunDirectory: `${requestedDirectory}${separator}${allocatedLeafName}`,
      allocationSequence: sequence,
      journalFileName: "run.forgewal",
      directoryCreateDisposition: "simulated",
      journalCreateDisposition: "simulated",
      overwritePolicy: "forbid",
      scope: "mock",
      synthetic: true,
      reasonCode: "MOCK_SESSION_RESERVATION",
      evidenceHash: mockHash(sequence, 241),
    };
  }

  private deviceDescriptors(): Array<{
    kind: DeviceKind;
    lookupId: string;
    deviceId: string;
    defaultName: string;
  }> {
    const directCount = Math.min(2, this.occupiedPodCount);
    const aggregatedCount = Math.max(0, this.occupiedPodCount - directCount);
    return [
      ...Array.from({ length: directCount }, (_, index) => ({
        kind: "pod" as const,
        lookupId: `MOCK-DIRECT-${(index + 1).toString().padStart(2, "0")}`,
        deviceId: `MOCK-POD-SN-${(index + 1).toString().padStart(4, "0")}`,
        defaultName: `Mock Direct Pod ${index + 1}`,
      })),
      ...Array.from({ length: aggregatedCount }, (_, index) => ({
        kind: "pod" as const,
        lookupId: `MOCK-AGG-POD-${(index + 1).toString().padStart(2, "0")}`,
        deviceId: `MOCK-POD-SN-${(directCount + index + 1).toString().padStart(4, "0")}`,
        defaultName: `Mock Aggregated Pod ${index + 1}`,
      })),
      {
        kind: "aggregator" as const,
        lookupId: "MOCK-AGG-01",
        deviceId: "MOCK-AGG-SN-0001",
        defaultName: "Mock Aggregator A",
      },
    ];
  }

  private deviceIdentity(kind: DeviceKind, deviceId: string): DeviceIdentitySnapshot | null {
    const descriptor = this.deviceDescriptors().find((item) => item.kind === kind
      && (item.lookupId === deviceId || item.deviceId === deviceId));
    if (descriptor === undefined) return null;
    const stored = this.deviceNames.get(descriptor.deviceId);
    const revision = stored?.revision ?? 0n;
    return {
      deviceId: descriptor.deviceId,
      identitySource: "mock_fixture",
      identityEvidenceHash: mockHash(1n, 249 + descriptor.deviceId.length),
      displayName: stored?.displayName ?? descriptor.defaultName,
      revision,
      persistence: "mock_session",
      writable: true,
      revisionCasSupported: true,
      nameReadBackVerified: true,
      crossHostPersistenceQualified: false,
      powerLossSafeWriteQualified: false,
      maxNameUtf8Bytes: 192,
      normalization: "NFC",
      status: "available",
      reasonCode: "MOCK_SESSION_ONLY",
      evidenceHash: mockHash(revision + 1n, 250 + descriptor.deviceId.length),
    };
  }

  private allDeviceIdentities(): DeviceIdentitySnapshot[] {
    return this.deviceDescriptors().flatMap((descriptor) => {
      const identity = this.deviceIdentity(descriptor.kind, descriptor.deviceId);
      return identity === null ? [] : [identity];
    });
  }

  private makePod(
    key: PodKey,
    _defaultLabel: string,
    connection: PodSnapshot["connection"],
    salt: number,
  ): PodSnapshot {
    const identity = this.deviceIdentity("pod", key);
    if (identity === null) throw new Error(`missing mock device identity for ${key}`);
    const selected = this.selectedPodKeys.includes(key);
    const gapFault = selected && this.faults.some((fault) => fault.code === "counter_gap" && fault.latched);
    const recording = selected && ["recording", "stop_requested"].includes(this.lifecycle);
    const channelLayoutId = `MOCK-LINEAR-${this.neuralChannelCount}`;
    const inputConfigurationHash = this.syntheticModel.inputConfigurationHash(
      this.neuralChannelCount,
      channelLayoutId,
    );
    return {
      key,
      state: gapFault ? "fault" : recording ? "mock_recording" : "mock_ready",
      scope: "mock",
      synthetic: true,
      podId: key,
      identity,
      label: identity.displayName,
      connection,
      neuralInput: {
        headstageId: `MOCK-HS-${key}`,
        profileId: `MOCK-RHD2132X1-${this.neuralChannelCount}CH-30K`,
        profileLabel: this.neuralChannelCount === 32
          ? "Synthetic RHD2132×1 shape"
          : `Synthetic ${this.neuralChannelCount}-channel fixture`,
        neuralChannelCount: this.neuralChannelCount,
        sampleRateHz: 30_000,
        channelLayoutId,
        sourceEncoding: "synthetic_generator",
        previewValueUnit: "microvolt",
        microvoltsPerCount: SYNTHETIC_PREVIEW_MICROVOLTS_PER_COUNT,
        zeroCode: null,
        status: "available",
        scope: "mock",
        reasonCode: "MOCK_GENERATOR_UNITS",
        descriptorHash: null,
        inventoryHash: null,
        configHash: inputConfigurationHash,
        evidenceHash: inputConfigurationHash,
      },
      selectedForRun: selected,
      selectable: true,
      selectionReasonCode: "MOCK_FIXTURE",
      evidenceHash: mockHash(1n, salt),
    };
  }

  private allPods(): PodSnapshot[] {
    const directCount = Math.min(2, this.occupiedPodCount);
    const aggregatedCount = Math.max(0, this.occupiedPodCount - directCount);
    const direct = Array.from({ length: directCount }, (_, index) => {
      const port = index + 1;
      return this.makePod(
        `MOCK-DIRECT-${port.toString().padStart(2, "0")}`,
        `Mock Direct Pod ${port}`,
        { kind: "direct_pc", connectionId: `PC-USB-${port.toString().padStart(2, "0")}`, podTransport: "usb3" },
        310 + port,
      );
    });
    const aggregated = Array.from({ length: aggregatedCount }, (_, index) => {
      const port = index + 1;
      return this.makePod(
        `MOCK-AGG-POD-${port.toString().padStart(2, "0")}`,
        `Mock Aggregated Pod ${port}`,
        {
          kind: "aggregator",
          aggregatorId: "MOCK-AGG-01",
          port,
          podTransport: "usb3",
          hostUplink: "10gbe",
        },
        330 + port,
      );
    });
    return [...direct, ...aggregated];
  }

  private podForKey(key: PodKey): PodSnapshot | null {
    return this.allPods().find((pod) => pod.key === key) ?? null;
  }

  private topology(): PodTopologySnapshot {
    const pods = this.allPods();
    const directPods = pods.filter((pod) => pod.connection.kind === "direct_pc");
    const aggregatedPods = pods.filter((pod) => pod.connection.kind === "aggregator");
    const aggregator: AggregatorSnapshot = {
      aggregatorId: "MOCK-AGG-01",
      identity: this.deviceIdentity("aggregator", "MOCK-AGG-01")!,
      label: this.deviceIdentity("aggregator", "MOCK-AGG-01")!.displayName,
      scope: "mock",
      synthetic: true,
      state: "mock_fixture",
      capabilityId: "aggregator_10gbe",
      hardwareStatus: "unavailable",
      hardwareReasonCode: "API_NOT_FROZEN",
      maxPodPorts: MAX_PODS_PER_RUN,
      ports: Array.from({ length: MAX_PODS_PER_RUN }, (_, index) => ({
        port: index + 1,
        pod: aggregatedPods.find((pod) => pod.connection.kind === "aggregator"
          && pod.connection.port === index + 1) ?? null,
      })),
      evidenceHash: mockHash(1n, 350),
    };
    return {
      sequence: 1n,
      maxPodsPerRun: MAX_PODS_PER_RUN,
      directPods,
      aggregators: [aggregator],
      evidenceHash: this.topologyEvidenceHash,
    };
  }

  private runReceiptStatus(): RunReceiptStatus {
    if (this.lifecycle === "recovery_required") return "recovery_required";
    if (this.lifecycle === "finalizing") return "finalizing";
    if (this.lifecycle === "finalized") return "finalized";
    if (["stop_requested", "recording_stopped"].includes(this.lifecycle)) return "stopped_not_durable";
    return this.integrityFailed ? "recovery_required" : "active";
  }

  private buildRunReceipt(): RunReceipt | null {
    if (this.runId === null || this.runEpoch === null || this.recordingTarget === null) return null;
    return {
      receiptKind: "run",
      scope: "mock",
      synthetic: true,
      runId: this.runId,
      runEpoch: this.runEpoch,
      status: this.runReceiptStatus(),
      lifecycle: this.lifecycle,
      receiptSequence: this.runReceiptSequence,
      generatedAtMonotonicMs: this.now(),
      evidence: copyEvidence(this.evidence),
      recordingTarget: { ...this.recordingTarget },
      nwbArtifact: null,
      faults: this.faults.map(copyFault),
      evidenceHash: mockHash(this.runReceiptSequence + 1n, 181),
    };
  }

  private loadSnapshot(): DaemonLoadSnapshot {
    const sourceActive = this.previewState === "live" || ["recording", "stop_requested"].includes(this.lifecycle);
    const writerActive = ["recording", "stop_requested"].includes(this.lifecycle);
    const persistenceBusy = ["recording_stopped", "finalizing", "recovery_required"].includes(this.lifecycle);
    const gapActive = this.faults.some((fault) => fault.code === "counter_gap" && fault.latched);
    return {
      sourceBufferPercent: sourceActive ? (gapActive ? 37 : 11) : 0,
      writerQueuePercent: this.durabilityFailure ? 92 : writerActive ? 18 : persistenceBusy ? 31 : 0,
      controlLoadPercent: sourceActive ? 24 : 6,
      inputBytesPerSecond: sourceActive
        ? Math.max(1, writerActive ? this.selectedPodKeys.length : 1) * this.neuralChannelCount * 30_000 * 2
        : 0,
      expectedBytesPerSecond: this.occupiedPodCount * this.neuralChannelCount * 30_000 * 2,
    };
  }

  private snapshot(): DaemonSnapshot {
    return {
      adapterId: this.adapterId,
      scope: "mock",
      synthetic: true,
      lifecycle: this.lifecycle,
      previewState: this.previewState,
      controlConnection: this.controlConnection,
      stale: this.stale,
      snapshotSequence: this.snapshotSequence,
      observedAtMonotonicMs: this.now(),
      runId: this.runId,
      runEpoch: this.runEpoch,
      recordingTarget: this.recordingTarget === null ? null : { ...this.recordingTarget },
      selectedPodKeys: this.selectedPodKeys.slice(),
      topology: copyTopology(this.topology()),
      load: this.loadSnapshot(),
      evidence: copyEvidence(this.evidence),
      faults: this.faults.map(copyFault),
      lastCommandReceiptId: this.lastCommandReceiptId,
      runReceipt: copyRunReceipt(this.buildRunReceipt()),
      evidenceHash: mockHash(this.snapshotSequence, 201),
    };
  }

  private publish(): void {
    this.snapshotSequence += 1n;
    const snapshot = this.snapshot();
    for (const listener of this.listeners) listener(snapshot);
  }
}
