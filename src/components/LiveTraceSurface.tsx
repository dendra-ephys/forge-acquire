import { useCallback, useEffect, useRef, useState } from "react";
import type {
  EnvelopePreviewFrame,
  PodKey,
  PreviewFrame,
  PreviewSignalKind,
  PreviewSource,
  SpikePreviewFrame,
} from "../adapters/acquireAdapter";
import type { Marker, TraceBlock } from "../core/types";
import { SpikeScopeCanvas } from "./SpikeScopeCanvas";
import { TraceCanvas } from "./TraceCanvas";

export interface ChannelDisplayStats {
  rms: number | null;
  peak: number | null;
  eventCount: number | null;
  threshold: number | null;
  unitLabel: string | null;
  podEventCount: number | null;
  bankEventCount: number | null;
  renderedEventCount: number | null;
  previewOmittedEventCount: number | null;
}

export interface LiveTraceSurfaceProps {
  source: PreviewSource;
  podKey: PodKey;
  signalKind: PreviewSignalKind;
  active: boolean;
  inputChannelCount: number | null;
  selectedChannel: number;
  onSelectChannel: (channel: number) => void;
  onStats: (stats: ChannelDisplayStats) => void;
  gainValue: number;
  windowSeconds: number;
  paused: boolean;
  markers: readonly Marker[];
}

const PREVIEW_BANK_SIZE = 8;

const EMPTY_STATS: ChannelDisplayStats = {
  rms: null,
  peak: null,
  eventCount: null,
  threshold: null,
  unitLabel: null,
  podEventCount: null,
  bankEventCount: null,
  renderedEventCount: null,
  previewOmittedEventCount: null,
};

function frameUnitLabel(frame: PreviewFrame): string {
  if (frame.valueUnit === "adc_count") return "ADC counts";
  if (frame.valueUnitReasonCode === "NWB_WAVEFORM_RECONSTRUCTION_UNITS") return "NWB µV";
  return frame.valueUnitScope === "mock" ? "SYNTHETIC µV" : "µV";
}

function frameToTraceBlock(frame: EnvelopePreviewFrame): TraceBlock {
  const valuesUv = frame.channels.map((channel) => {
    const pointCount = Math.min(channel.minValues.length, channel.maxValues.length);
    const values = new Float32Array(pointCount * 2);
    for (let point = 0; point < pointCount; point += 1) {
      values[point * 2] = channel.minValues[point] ?? 0;
      values[point * 2 + 1] = channel.maxValues[point] ?? 0;
    }
    return values;
  });
  return {
    podId: frame.podId ?? frame.podKey,
    channelOffset: frame.channelStart,
    channelCount: valuesUv.length,
    pointsPerChannel: frame.pointsPerChannel,
    sampleWindowSeconds: frame.windowSeconds,
    valuesUv,
    generatedAtMonotonicMs: frame.generatedAtMonotonicMs,
    synthetic: frame.synthetic,
    displayEncoding: "min_max_pairs",
  };
}

function frameStats(frame: PreviewFrame, selectedChannel: number): ChannelDisplayStats {
  if (frame.encoding === "spike_preview_v3") {
    const waveform = frame.selectedChannelWaveformStats;
    return {
      rms: null,
      peak: waveform?.meanValues.reduce((peak, value) => Math.max(peak, Math.abs(value)), 0) ?? null,
      eventCount: frame.selectedChannelWaveforms.observedEventCount,
      threshold: waveform?.thresholdValue ?? null,
      unitLabel: frameUnitLabel(frame),
      podEventCount: frame.podObservedEventCount,
      bankEventCount: frame.accounting.observedEventCount,
      renderedEventCount: frame.accounting.returnedRasterEventCount,
      previewOmittedEventCount: frame.accounting.sampledOutEventCount,
    };
  }
  const channel = frame.channels.find((item) => item.channel === selectedChannel);
  return channel
    ? {
        rms: channel.rmsValue,
        peak: channel.peakAbsValue,
        eventCount: null,
        threshold: null,
        unitLabel: frameUnitLabel(frame),
        podEventCount: null,
        bankEventCount: null,
        renderedEventCount: null,
        previewOmittedEventCount: null,
      }
    : EMPTY_STATS;
}

function frameMatches(
  frame: PreviewFrame,
  podKey: PodKey,
  signalKind: PreviewSignalKind,
  windowSeconds: number,
  channelStart: number,
  channelCount: number,
  selectedChannel: number,
) {
  return frame.podKey === podKey
    && frame.signalKind === signalKind
    && Math.abs(frame.windowSeconds - windowSeconds) < 0.001
    && frame.channelStart === channelStart
    && frame.channelCount === channelCount
    && (frame.encoding !== "spike_preview_v3" || frame.selectedChannel === selectedChannel);
}

/**
 * Preview ownership stays below the App control surface. Wideband/LFP use
 * bounded envelopes; Spike uses full-channel counts, a bounded bank raster,
 * and a complete selected-channel rolling waveform window. No continuous raw
 * neural stream crosses this port.
 */
export function LiveTraceSurface({
  source,
  podKey,
  signalKind,
  active,
  inputChannelCount,
  selectedChannel,
  onSelectChannel,
  onStats,
  gainValue,
  windowSeconds,
  paused,
  markers,
}: LiveTraceSurfaceProps) {
  const [frame, setFrame] = useState<PreviewFrame | null>(null);
  const [spikeDetailOpen, setSpikeDetailOpen] = useState(false);
  const frameRef = useRef<PreviewFrame | null>(null);
  const pausedRef = useRef(paused);
  const lastStatsAtRef = useRef(Number.NEGATIVE_INFINITY);
  const channelStart = Math.floor(selectedChannel / PREVIEW_BANK_SIZE) * PREVIEW_BANK_SIZE;
  const channelCount = Math.max(
    1,
    Math.min(PREVIEW_BANK_SIZE, (inputChannelCount ?? channelStart + PREVIEW_BANK_SIZE) - channelStart),
  );

  const acceptFrame = useCallback((next: PreviewFrame) => {
    if (!frameMatches(
      next,
      podKey,
      signalKind,
      windowSeconds,
      channelStart,
      channelCount,
      selectedChannel,
    )) return;
    frameRef.current = next;
    setFrame(next);
    const now = performance.now();
    if (now - lastStatsAtRef.current >= 200) {
      lastStatsAtRef.current = now;
      onStats(frameStats(next, selectedChannel));
    }
  }, [channelCount, channelStart, onStats, podKey, selectedChannel, signalKind, windowSeconds]);

  useEffect(() => {
    frameRef.current = null;
    setFrame(null);
    onStats(EMPTY_STATS);
    source.setRequest({
      podKey,
      signalKind,
      windowSeconds,
      channelStart,
      channelCount,
      selectedChannel,
    });
    if (!active) return undefined;
    const accept = (next: PreviewFrame) => {
      if (!pausedRef.current) acceptFrame(next);
    };
    const unsubscribe = source.subscribe(accept);
    const latest = source.getLatest();
    if (latest && !pausedRef.current) accept(latest);
    return unsubscribe;
  }, [
    acceptFrame,
    active,
    channelCount,
    channelStart,
    onStats,
    podKey,
    selectedChannel,
    signalKind,
    source,
    windowSeconds,
  ]);

  useEffect(() => {
    pausedRef.current = paused;
    if (!paused) {
      const latest = source.getLatest();
      if (latest) acceptFrame(latest);
    }
  }, [acceptFrame, paused, source]);

  useEffect(() => {
    if (signalKind !== "spike") setSpikeDetailOpen(false);
  }, [signalKind]);

  useEffect(() => {
    if (frameRef.current) onStats(frameStats(frameRef.current, selectedChannel));
  }, [onStats, selectedChannel]);

  if (!frame) {
    const emptyChannels = Array.from({ length: channelCount }, (_, index) => channelStart + index);
    return (
      <div
        className={`trace-empty trace-empty--${signalKind}`}
        role="img"
        aria-label={`Empty ${signalKind} preview with ${channelCount} channel baselines`}
      >
        <div className="trace-empty__lanes" aria-hidden="true">
          {emptyChannels.map((channel) => (
            <div className="trace-empty__lane" key={channel}>
              <span>CH {String(channel + 1).padStart(2, "0")}</span>
              <i />
            </div>
          ))}
        </div>
        <div className="trace-empty__axis" aria-hidden="true">
          <span>−{windowSeconds} s</span>
          <span>0 s</span>
        </div>
      </div>
    );
  }

  if (frame.encoding === "spike_preview_v3") {
    return (
      <SpikeScopeCanvas
        frame={frame as SpikePreviewFrame}
        expectedChannelCount={inputChannelCount}
        selectedChannel={selectedChannel}
        detailOpen={spikeDetailOpen}
        onSelect={(channel) => {
          setSpikeDetailOpen(true);
          onSelectChannel(channel);
        }}
        onCloseDetail={() => setSpikeDetailOpen(false)}
        gainValue={gainValue}
        paused={paused}
      />
    );
  }

  const lfp = frame.signalKind === "lfp";
  const block = frameToTraceBlock(frame);
  return (
    <TraceCanvas
      block={block}
      selectedChannel={selectedChannel}
      onSelect={onSelectChannel}
      gainValue={gainValue}
      amplitudeUnitLabel={frameUnitLabel(frame)}
      paused={paused}
      markers={markers}
      timeline={{
        startMonotonicMs: block.generatedAtMonotonicMs - frame.windowSeconds * 1_000,
        endMonotonicMs: block.generatedAtMonotonicMs,
      }}
      emptyText={`No ${lfp ? "LFP" : "wideband"} preview available`}
      ariaLabel={lfp ? "Live LFP bank traces" : "Live wideband bank traces"}
    />
  );
}
