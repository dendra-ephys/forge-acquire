import type { PreviewNeuralModel, PreviewNeuralSample } from "./previewNeuralModel";

/**
 * Integer-only synthetic neural truth shared by the mock Wideband/LFP/Spike views.
 *
 * The rules deliberately avoid Math.random(), trigonometry, and wall-clock phase so
 * Rust, Python, and TypeScript implementations can reproduce any channel/sample by
 * absolute sample counter without materializing a continuous recording.
 */

export const SYNTHETIC_SCENARIO_ID = "forge.synthetic.neural.integer.v1";
export const SYNTHETIC_DEFAULT_SEED = 9n;
export const SYNTHETIC_SAMPLE_RATE_HZ = 30_000;
export const SYNTHETIC_LFP_PEAK_COUNTS = 2_048;
export const SYNTHETIC_NOISE_MIN_COUNTS = -64;
export const SYNTHETIC_NOISE_MAX_COUNTS = 64;
export const SYNTHETIC_SPIKE_PRETRIGGER_SAMPLES = 5;
export const SYNTHETIC_SPIKE_TEMPLATE = Object.freeze([
  0,
  -256,
  -1_024,
  -4_096,
  -16_000,
  -40_000,
  -16_000,
  -4_096,
  -1_024,
  -256,
  0,
] as const);

/** Mock display calibration only; the model itself always returns canonical counts. */
export const SYNTHETIC_PREVIEW_MICROVOLTS_PER_COUNT = 1 / 128;

const UINT32_MASK = 0xffff_ffffn;
const UINT64_MASK = 0xffff_ffff_ffff_ffffn;
const FNV64_OFFSET = 0xcbf2_9ce4_8422_2325n;
const FNV64_PRIME = 0x0000_0100_0000_01b3n;
const FNV64_LANE_SALT = 0x9e37_79b9_7f4a_7c15n;

export interface SyntheticNeuralOptions {
  seed?: number | bigint;
  sampleRateHz?: number;
}

export interface SyntheticNeuralSample extends PreviewNeuralSample {
  /** The deterministic 8 Hz triangle component before int16 saturation. */
  lfp: number;
  /** The fixed-template contribution before int16 saturation. */
  spike: number;
  /** Bounded xorshift32 noise in [-64, 64]. */
  noise: number;
  /** clamp_i16(lfp + spike + noise), i.e. the canonical continuous source sample. */
  wideband: number;
}

function assertChannel(channel: number): void {
  if (!Number.isSafeInteger(channel) || channel < 0 || channel > 0xffff) {
    throw new RangeError("channel must fit the shared unsigned 16-bit domain");
  }
}

function assertSample(sample: bigint): void {
  if (sample < 0n || sample > UINT64_MASK) {
    throw new RangeError("absolute sample counter must fit unsigned 64-bit");
  }
}

function normalizeSeed(seed: number | bigint): bigint {
  if (typeof seed === "number") {
    if (!Number.isSafeInteger(seed) || seed < 0) {
      throw new RangeError("numeric synthetic seed must be a non-negative safe integer");
    }
  }
  const normalized = BigInt(seed);
  if (normalized < 0n || normalized > UINT64_MASK) {
    throw new RangeError("synthetic seed must fit unsigned 64-bit");
  }
  return normalized;
}

function rotateLeft32(value: number, count: number): number {
  const shift = count & 31;
  return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}

function xorshift32(value: number): number {
  let result = value >>> 0;
  result = (result ^ (result << 13)) >>> 0;
  result = (result ^ (result >>> 17)) >>> 0;
  result = (result ^ (result << 5)) >>> 0;
  return result;
}

function clampInt16(value: number): number {
  return Math.max(-32_768, Math.min(32_767, value));
}

function fnv1a64(text: string, lane: number): bigint {
  let hash = (FNV64_OFFSET ^ (BigInt(lane + 1) * FNV64_LANE_SALT)) & UINT64_MASK;
  const bytes = new TextEncoder().encode(text);
  for (const byte of bytes) {
    hash ^= BigInt(byte);
    hash = (hash * FNV64_PRIME) & UINT64_MASK;
  }
  return hash;
}

export function neuralEvidenceHash(text: string): string {
  return Array.from({ length: 4 }, (_, lane) => fnv1a64(text, lane)
    .toString(16)
    .padStart(16, "0"))
    .join("");
}

function scenarioEvidenceHash(sampleRateHz: number, seed: bigint): string {
  const config = [
    SYNTHETIC_SCENARIO_ID,
    `fs=${sampleRateHz}`,
    `seed=${seed.toString(16).padStart(16, "0")}`,
    `lfp_peak=${SYNTHETIC_LFP_PEAK_COUNTS}`,
    "lfp_hz=8",
    "noise=xorshift32_mod129_minus64",
    `spike_period=max(floor(fs/10),64)`,
    "spike_first=29+53*channel",
    `spike_template=${SYNTHETIC_SPIKE_TEMPLATE.join(",")}`,
  ].join(";");
  return neuralEvidenceHash(config);
}

function safeCount(value: bigint): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError("synthetic event count exceeds Number.MAX_SAFE_INTEGER");
  }
  return Number(value);
}

export class SyntheticNeuralModel implements PreviewNeuralModel {
  readonly sourceKind = "canonical-synthetic" as const;
  readonly channelCount = null;
  readonly scenarioId = SYNTHETIC_SCENARIO_ID;
  readonly seed: bigint;
  readonly sampleRateHz: number;
  readonly scenarioHash: string;
  readonly previewMicrovoltsPerCount = SYNTHETIC_PREVIEW_MICROVOLTS_PER_COUNT;
  readonly waveformPretriggerSamples = SYNTHETIC_SPIKE_PRETRIGGER_SAMPLES;
  readonly waveformPointCount = SYNTHETIC_SPIKE_TEMPLATE.length;

  constructor(options: SyntheticNeuralOptions = {}) {
    const sampleRateHz = options.sampleRateHz ?? SYNTHETIC_SAMPLE_RATE_HZ;
    if (!Number.isSafeInteger(sampleRateHz) || sampleRateHz <= 0 || sampleRateHz > 0xffff_ffff) {
      throw new RangeError("sampleRateHz must be a nonzero unsigned 32-bit integer");
    }
    this.sampleRateHz = sampleRateHz;
    this.seed = normalizeSeed(options.seed ?? SYNTHETIC_DEFAULT_SEED);
    this.scenarioHash = scenarioEvidenceHash(this.sampleRateHz, this.seed);
  }

  /** Bind the formula identity to the adapter-authored channel layout. */
  inputConfigurationHash(channelCount: number, channelLayoutId: string): string {
    if (!Number.isSafeInteger(channelCount) || channelCount <= 0 || channelCount > 0xffff) {
      throw new RangeError("channelCount must fit nonzero unsigned 16-bit");
    }
    if (channelLayoutId.trim().length === 0) {
      throw new RangeError("channelLayoutId cannot be empty");
    }
    return neuralEvidenceHash([
      "forge.synthetic.neural.input-config.v1",
      `scenario=${this.scenarioHash}`,
      `channel_count=${channelCount}`,
      `channel_layout=${channelLayoutId}`,
      "source_encoding=synthetic_generator",
      "preview_unit=synthetic_microvolt",
      "preview_microvolts_per_count=1/128",
    ].join(";"));
  }

  /** Canonical 8 Hz integer triangle; this formula matches the Rust truth source. */
  lfpAt(sample: bigint, channel: number): number {
    assertSample(sample);
    assertChannel(channel);
    const phase = Number((
      (sample % BigInt(this.sampleRateHz)) * 8n
      + BigInt(channel) * BigInt(Math.floor(this.sampleRateHz / 32))
    ) % BigInt(this.sampleRateHz));
    if (phase * 2 < this.sampleRateHz) {
      return -SYNTHETIC_LFP_PEAK_COUNTS
        + Math.floor((8_192 * phase) / this.sampleRateHz);
    }
    return 6_144 - Math.floor((8_192 * phase) / this.sampleRateHz);
  }

  /** Canonical random-access u32 xorshift noise; no preceding sample is required. */
  noiseAt(sample: bigint, channel: number): number {
    assertSample(sample);
    assertChannel(channel);
    const seedLow = Number(this.seed & UINT32_MASK) >>> 0;
    const seedHigh = Number((this.seed >> 32n) & UINT32_MASK) >>> 0;
    const sampleLow = Number(sample & UINT32_MASK) >>> 0;
    const sampleHigh = Number((sample >> 32n) & UINT32_MASK) >>> 0;
    const mixed = (
      seedLow
      ^ rotateLeft32(seedHigh, 16)
      ^ Math.imul(sampleLow, 0x9e37_79b9)
      ^ Math.imul(sampleHigh, 0x85eb_ca6b)
      ^ Math.imul(channel, 0xc2b2_ae35)
      ^ 0xa341_316c
    ) >>> 0;
    return (xorshift32(mixed) % 129) - 64;
  }

  spikePeriodSamples(): bigint {
    return BigInt(Math.max(Math.floor(this.sampleRateHz / 10), 64));
  }

  firstSpikeCenter(channel: number): bigint {
    assertChannel(channel);
    return BigInt(29 + 53 * channel);
  }

  /** Fixed 11-point template contribution at one absolute source sample. */
  spikeAt(sample: bigint, channel: number): number {
    assertSample(sample);
    assertChannel(channel);
    const firstWindowStart = this.firstSpikeCenter(channel)
      - BigInt(SYNTHETIC_SPIKE_PRETRIGGER_SAMPLES);
    if (sample < firstWindowStart) return 0;
    const position = (sample - firstWindowStart) % this.spikePeriodSamples();
    if (position >= BigInt(SYNTHETIC_SPIKE_TEMPLATE.length)) return 0;
    return SYNTHETIC_SPIKE_TEMPLATE[Number(position)];
  }

  sampleAt(sample: bigint, channel: number): SyntheticNeuralSample {
    const lfp = this.lfpAt(sample, channel);
    const spike = this.spikeAt(sample, channel);
    const noise = this.noiseAt(sample, channel);
    return { lfp, spike, noise, wideband: clampInt16(lfp + spike + noise) };
  }

  eventCountInRange(channel: number, start: bigint, endExclusive: bigint): number {
    assertChannel(channel);
    assertSample(start);
    assertSample(endExclusive);
    if (endExclusive <= start) return 0;
    const period = this.spikePeriodSamples();
    const first = this.firstSpikeCenter(channel);
    const firstInRange = start <= first
      ? first
      : first + ((start - first + period - 1n) / period) * period;
    if (firstInRange >= endExclusive) return 0;
    return safeCount(((endExclusive - 1n - firstInRange) / period) + 1n);
  }

  /** Lazily enumerates oracle event centers; callers choose their own bounded window. */
  *eventCentersInRange(
    channel: number,
    start: bigint,
    endExclusive: bigint,
  ): Generator<bigint, void, undefined> {
    const count = this.eventCountInRange(channel, start, endExclusive);
    if (count === 0) return;
    const period = this.spikePeriodSamples();
    const first = this.firstSpikeCenter(channel);
    let center = start <= first
      ? first
      : first + ((start - first + period - 1n) / period) * period;
    for (let index = 0; index < count; index += 1) {
      yield center;
      center += period;
    }
  }

  /** Eleven canonical wideband samples aligned to an oracle event center. */
  waveformAtEvent(channel: number, center: bigint): readonly number[] {
    assertChannel(channel);
    assertSample(center);
    const start = center - BigInt(SYNTHETIC_SPIKE_PRETRIGGER_SAMPLES);
    if (start < 0n) throw new RangeError("event waveform starts before sample zero");
    return SYNTHETIC_SPIKE_TEMPLATE.map((_, index) => this.sampleAt(
      start + BigInt(index),
      channel,
    ).wideband);
  }
}
