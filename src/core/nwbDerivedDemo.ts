import fixtureJson from "../fixtures/nwb-waveform-demo.v3.json";
import type { PreviewNeuralModel, PreviewNeuralSample } from "./previewNeuralModel";
import { neuralEvidenceHash } from "./syntheticNeural";

interface NwbDemoChannel {
  demoChannel: number;
  sourceUnitId: number;
  sourceWindowStartSeconds: number;
  recordingEventCount: number;
  recordingRateHz: number;
  eventSamples: number[];
  waveformCounts: number[][];
  lfpCounts: number[];
}

interface NwbDemoFixture {
  schemaVersion: number;
  fixtureId: string;
  source: {
    relativePath: string;
    sha256: string;
    byteLength: number;
    channelCount: number;
    sourceChannelCount: number;
    demoChannelCount: number;
    durationSeconds: number;
    waveformPointCount: number;
    storedUnit: string;
    storedConversion: number;
    interpretedUnit: string;
    unitInterpretation: string;
    lfpPath: string;
    lfpStoredUnit: string;
    lfpStoredConversion: number;
    lfpInterpretedUnit: string;
    lfpSourceRateHz: number;
  };
  reconstruction: {
    sampleRateHz: number;
    loopSeconds: number;
    sourceWindowStartSeconds: number[];
    microvoltsPerCount: number;
    waveformPretriggerSamples: number;
    waveformSelection: string;
    lfpSampleRateHz: number;
    lfpMicrovoltsPerCount: number;
    lfpSelection: string;
  };
  channels: NwbDemoChannel[];
}

const fixture = fixtureJson as NwbDemoFixture;

export const NWB_DEMO_FIXTURE = Object.freeze(fixture);
export const NWB_DERIVED_SCENARIO_ID = fixture.fixtureId;

function assertChannel(channel: number): NwbDemoChannel {
  if (!Number.isInteger(channel) || channel < 0 || channel >= fixture.channels.length) {
    throw new RangeError(`channel must be in the NWB demo range 0..${fixture.channels.length - 1}`);
  }
  return fixture.channels[channel]!;
}

function assertSample(sample: bigint): void {
  if (sample < 0n) throw new RangeError("absolute sample counter must be non-negative");
}

function clampInt16(value: number): number {
  return Math.max(-32_768, Math.min(32_767, Math.round(value)));
}

function lowerBound(values: readonly number[], target: number): number {
  let left = 0;
  let right = values.length;
  while (left < right) {
    const middle = Math.floor((left + right) / 2);
    if ((values[middle] ?? Number.POSITIVE_INFINITY) < target) left = middle + 1;
    else right = middle;
  }
  return left;
}

/**
 * Browser-only reconstruction from real event-aligned NWB waveform snippets.
 *
 * The 10-second source event schedule is looped deterministically. Between
 * events, a low-amplitude synthetic baseline is supplied because the fixture
 * intentionally does not ship the original continuous recording.
 */
export class NwbDerivedDemoModel implements PreviewNeuralModel {
  readonly sourceKind = "nwb-derived-reconstruction" as const;
  readonly channelCount = fixture.source.demoChannelCount;
  readonly scenarioId = fixture.fixtureId;
  readonly scenarioHash = neuralEvidenceHash([
    fixture.fixtureId,
    `schema=${fixture.schemaVersion}`,
    `source_sha256=${fixture.source.sha256}`,
    `source_windows=${fixture.reconstruction.sourceWindowStartSeconds.join(",")}`,
    `loop_seconds=${fixture.reconstruction.loopSeconds}`,
    `microvolts_per_count=${fixture.reconstruction.microvoltsPerCount}`,
    `lfp_path=${fixture.source.lfpPath}`,
    `lfp_rate=${fixture.reconstruction.lfpSampleRateHz}`,
    `lfp_microvolts_per_count=${fixture.reconstruction.lfpMicrovoltsPerCount}`,
  ].join(";"));
  readonly sampleRateHz = fixture.reconstruction.sampleRateHz;
  readonly previewMicrovoltsPerCount = fixture.reconstruction.microvoltsPerCount;
  readonly waveformPretriggerSamples = fixture.reconstruction.waveformPretriggerSamples;
  readonly waveformPointCount = fixture.source.waveformPointCount;
  private readonly loopSamples = BigInt(
    fixture.reconstruction.sampleRateHz * fixture.reconstruction.loopSeconds,
  );

  inputConfigurationHash(channelCount: number, channelLayoutId: string): string {
    if (channelCount !== this.channelCount) {
      throw new RangeError(`NWB demo fixture requires exactly ${this.channelCount} channels`);
    }
    if (!channelLayoutId.trim()) throw new RangeError("channelLayoutId cannot be empty");
    return neuralEvidenceHash([
      "forge.demo.nwb-waveform.input-config.v1",
      `scenario=${this.scenarioHash}`,
      `channel_count=${channelCount}`,
      `channel_layout=${channelLayoutId}`,
      "source_encoding=nwb_waveform_reconstruction",
      `preview_microvolts_per_count=${this.previewMicrovoltsPerCount}`,
    ].join(";"));
  }

  lfpAt(sample: bigint, channel: number): number {
    assertSample(sample);
    const source = assertChannel(channel);
    const position = Number(sample % this.loopSamples)
      * fixture.reconstruction.lfpSampleRateHz / this.sampleRateHz;
    const left = Math.floor(position) % source.lfpCounts.length;
    const right = (left + 1) % source.lfpCounts.length;
    const fraction = position - Math.floor(position);
    const interpolated = (source.lfpCounts[left] ?? 0) * (1 - fraction)
      + (source.lfpCounts[right] ?? 0) * fraction;
    return Math.round(
      interpolated
      * fixture.reconstruction.lfpMicrovoltsPerCount
      / this.previewMicrovoltsPerCount,
    );
  }

  private noiseAt(sample: bigint, channel: number): number {
    let value = (Number(sample & 0xffff_ffffn) ^ Math.imul(channel + 1, 0x9e37_79b9)) >>> 0;
    value ^= value << 13;
    value ^= value >>> 17;
    value ^= value << 5;
    return (value >>> 0) % 31 - 15;
  }

  private templateForEvent(channel: number, center: bigint): readonly number[] {
    const source = assertChannel(channel);
    const relative = Number(center % this.loopSamples);
    const eventIndex = lowerBound(source.eventSamples, relative);
    if (source.eventSamples[eventIndex] !== relative) {
      throw new RangeError("center is not part of the NWB-derived event schedule");
    }
    const loopIndex = center / this.loopSamples;
    const templateIndex = Number((loopIndex + BigInt(eventIndex + channel))
      % BigInt(source.waveformCounts.length));
    return source.waveformCounts[templateIndex]!;
  }

  private spikeAt(sample: bigint, channel: number): number {
    const pre = BigInt(this.waveformPretriggerSamples);
    const post = BigInt(this.waveformPointCount - this.waveformPretriggerSamples);
    const searchStart = sample > post ? sample - post : 0n;
    const searchEnd = sample + pre + 1n;
    let sum = 0;
    for (const center of this.eventCentersInRange(channel, searchStart, searchEnd)) {
      const waveformIndex = Number(sample - (center - pre));
      if (waveformIndex >= 0 && waveformIndex < this.waveformPointCount) {
        sum += this.templateForEvent(channel, center)[waveformIndex] ?? 0;
      }
    }
    return sum;
  }

  sampleAt(sample: bigint, channel: number): PreviewNeuralSample {
    assertSample(sample);
    assertChannel(channel);
    const lfp = this.lfpAt(sample, channel);
    const spike = this.spikeAt(sample, channel);
    const noise = this.noiseAt(sample, channel);
    return { lfp, spike, noise, wideband: clampInt16(lfp + spike + noise) };
  }

  eventCountInRange(channel: number, start: bigint, endExclusive: bigint): number {
    let count = 0;
    for (const _center of this.eventCentersInRange(channel, start, endExclusive)) count += 1;
    return count;
  }

  *eventCentersInRange(
    channel: number,
    start: bigint,
    endExclusive: bigint,
  ): Generator<bigint, void, undefined> {
    const source = assertChannel(channel);
    assertSample(start);
    assertSample(endExclusive);
    if (endExclusive <= start) return;
    const firstLoop = start / this.loopSamples;
    const lastLoop = (endExclusive - 1n) / this.loopSamples;
    for (let loop = firstLoop; loop <= lastLoop; loop += 1n) {
      const loopBase = loop * this.loopSamples;
      const localStart = loop === firstLoop ? Number(start - loopBase) : 0;
      const localEnd = loop === lastLoop
        ? Number(endExclusive - loopBase)
        : Number(this.loopSamples);
      for (let index = lowerBound(source.eventSamples, localStart);
        index < source.eventSamples.length;
        index += 1) {
        const eventSample = source.eventSamples[index]!;
        if (eventSample >= localEnd) break;
        yield loopBase + BigInt(eventSample);
      }
    }
  }

  waveformAtEvent(channel: number, center: bigint): readonly number[] {
    assertChannel(channel);
    assertSample(center);
    const start = center - BigInt(this.waveformPretriggerSamples);
    if (start < 0n) throw new RangeError("event waveform starts before sample zero");
    return Array.from({ length: this.waveformPointCount }, (_, index) => this.sampleAt(
      start + BigInt(index),
      channel,
    ).wideband);
  }
}
