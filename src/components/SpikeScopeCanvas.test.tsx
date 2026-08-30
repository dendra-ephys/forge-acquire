import { describe, expect, it } from "vitest";
import type { SpikePreviewFrame, SpikeWaveformEvent } from "../adapters/acquireAdapter";
import { waveformEventsForMode, waveformWindowInvariant } from "./SpikeScopeCanvas";

function waveformEvent(
  eventId: string,
  centerSample: bigint,
): SpikeWaveformEvent {
  return {
    eventId,
    channel: 3,
    centerSample,
    snippetSampleStart: centerSample - 2n,
    snippetSampleEndExclusive: centerSample + 3n,
    preTriggerSamples: 2,
    values: [0, -20, -80, -30, 5],
  };
}

function frameFixture(): SpikePreviewFrame {
  const events = [
    waveformEvent("event-1", 1_001n),
    waveformEvent("event-2", 1_600n),
    waveformEvent("event-3", 1_999n),
  ];
  return {
    scope: "mock",
    synthetic: true,
    containsContinuousRawSamples: false,
    containsEventWaveformSnippets: true,
    sequence: 1n,
    generatedAtMonotonicMs: 100,
    runId: null,
    runEpoch: null,
    podKey: "MOCK-DIRECT-01",
    podId: "MOCK-POD-SN-0001",
    podLabel: "Mock Direct Pod 1",
    inputChannelCount: 32,
    inputEvidenceHash: "a".repeat(64),
    valueUnit: "microvolt",
    valueUnitScope: "mock",
    valueUnitReasonCode: "SYNTHETIC_CALIBRATION",
    valueEvidenceHash: "b".repeat(64),
    channelStart: 0,
    channelCount: 8,
    signalKind: "spike",
    windowSeconds: 1,
    sourceSampleStart: 1_000n,
    sourceSampleEndExclusive: 2_000n,
    previewFreshness: "current",
    coverage: {
      source: "complete",
      analysis: "complete",
      sourceGapRanges: [],
      analysisGapRanges: [],
    },
    processing: {
      status: "available",
      scope: "mock",
      algorithmId: "synthetic_spike_oracle_v1",
      summary: "Synthetic event oracle",
      sourceSampleRateHz: 1_000,
      displaySampleRateHz: null,
      passbandHz: null,
      filterProfileId: null,
      configHash: null,
      groupDelayMs: null,
      evidenceHash: null,
    },
    encoding: "spike_preview_v3",
    sorting: "unsorted",
    waveformSampleRateHz: 1_000,
    podObservedEventCount: 3,
    channelActivity: Array.from({ length: 32 }, (_, channel) => ({
      channel,
      observedEventCount: channel === 3 ? 3 : 0,
      rateHz: channel === 3 ? 3 : 0,
      valid: true,
    })),
    accounting: {
      selectionPolicy: "channel_stratified_rotating_v1",
      maxReturnedEvents: 64,
      observedEventCount: 3,
      rasterCandidateEventCount: 3,
      sampledOutEventCount: 0,
      returnedRasterEventCount: 3,
      rotationOffset: 0,
    },
    raster: events.map((event) => ({
      eventId: event.eventId,
      channel: event.channel,
      eventOffsetMs: Number(event.centerSample - 1_000n),
      peakValue: -80,
    })),
    selectedChannel: 3,
    selectedChannelWaveforms: {
      retentionSamples: 1_000n,
      coverage: "complete",
      reasonCode: null,
      observedEventCount: events.length,
      returnedEventCount: events.length,
      events,
    },
    selectedChannelWaveformStats: {
      channel: 3,
      thresholdValue: null,
      contributingWaveformCount: events.length,
      meanValues: [0, -20, -80, -30, 5],
      p10Values: [0, -20, -80, -30, 5],
      p90Values: [0, -20, -80, -30, 5],
    },
  };
}

describe("SpikeScopeCanvas waveform helpers", () => {
  it("accepts a complete selected-channel window with exact count and TTL coverage", () => {
    expect(waveformWindowInvariant(frameFixture())).toBe(true);
  });

  it("fails closed on incomplete coverage, count mismatch, or an event older than TTL", () => {
    const incomplete = frameFixture();
    incomplete.selectedChannelWaveforms = {
      ...incomplete.selectedChannelWaveforms,
      coverage: "fault",
      reasonCode: "ANALYSIS_SAMPLE_GAP",
    };
    expect(waveformWindowInvariant(incomplete)).toBe(false);

    const countMismatch = frameFixture();
    countMismatch.selectedChannelWaveforms = {
      ...countMismatch.selectedChannelWaveforms,
      observedEventCount: 4,
    };
    expect(waveformWindowInvariant(countMismatch)).toBe(false);

    const expired = frameFixture();
    expired.selectedChannelWaveforms = {
      ...expired.selectedChannelWaveforms,
      retentionSamples: 999n,
    };
    expect(waveformWindowInvariant(expired)).toBe(false);
  });

  it("returns every retained waveform for all, only the newest for latest, and none for statistics", () => {
    const frame = frameFixture();

    expect(waveformEventsForMode(frame, "all")).toEqual(
      frame.selectedChannelWaveforms.events,
    );
    expect(waveformEventsForMode(frame, "latest")).toEqual([
      frame.selectedChannelWaveforms.events[2],
    ]);
    expect(waveformEventsForMode(frame, "statistics")).toEqual([]);
  });
});
