import { describe, expect, it } from "vitest";
import {
  SYNTHETIC_DEFAULT_SEED,
  SYNTHETIC_SPIKE_TEMPLATE,
  SyntheticNeuralModel,
} from "./syntheticNeural";

function canonicalLfp(sample: bigint, channel: number, sampleRateHz = 30_000): number {
  const phase = Number((
    (sample % BigInt(sampleRateHz)) * 8n
    + BigInt(channel) * BigInt(Math.floor(sampleRateHz / 32))
  ) % BigInt(sampleRateHz));
  return phase * 2 < sampleRateHz
    ? -2_048 + Math.floor((8_192 * phase) / sampleRateHz)
    : 6_144 - Math.floor((8_192 * phase) / sampleRateHz);
}

function rotl32(value: number, count: number): number {
  return ((value << count) | (value >>> (32 - count))) >>> 0;
}

function canonicalNoise(seed: bigint, sample: bigint, channel: number): number {
  const lo = (value: bigint) => Number(value & 0xffff_ffffn) >>> 0;
  let x = (
    lo(seed)
    ^ rotl32(lo(seed >> 32n), 16)
    ^ Math.imul(lo(sample), 0x9e37_79b9)
    ^ Math.imul(lo(sample >> 32n), 0x85eb_ca6b)
    ^ Math.imul(channel, 0xc2b2_ae35)
    ^ 0xa341_316c
  ) >>> 0;
  x = (x ^ (x << 13)) >>> 0;
  x = (x ^ (x >>> 17)) >>> 0;
  x = (x ^ (x << 5)) >>> 0;
  return (x % 129) - 64;
}

describe("SyntheticNeuralModel", () => {
  it("matches the frozen integer LFP and random-access xorshift rules", () => {
    expect(SYNTHETIC_DEFAULT_SEED).toBe(9n);
    const model = new SyntheticNeuralModel();
    const probes = [
      { sample: 0n, channel: 0 },
      { sample: 1_875n, channel: 0 },
      { sample: 3_750n, channel: 0 },
      { sample: 29_999n, channel: 16 },
      { sample: (1n << 32n) + 12_345n, channel: 31 },
    ];
    for (const { sample, channel } of probes) {
      expect(model.lfpAt(sample, channel)).toBe(canonicalLfp(sample, channel));
      expect(model.noiseAt(sample, channel)).toBe(
        canonicalNoise(SYNTHETIC_DEFAULT_SEED, sample, channel),
      );
      expect(model.noiseAt(sample, channel)).toBeGreaterThanOrEqual(-64);
      expect(model.noiseAt(sample, channel)).toBeLessThanOrEqual(64);
    }
    expect(model.lfpAt(0n, 0)).toBe(-2_048);
    expect(model.lfpAt(1_875n, 0)).toBe(2_048);
  });

  it("matches the cross-language seed-9 component goldens", () => {
    const model = new SyntheticNeuralModel({ seed: 9n });
    expect(model.sampleAt(0n, 0)).toEqual({
      lfp: -2_048,
      spike: 0,
      noise: 59,
      wideband: -1_989,
    });
    expect(model.sampleAt(29n, 0)).toEqual({
      lfp: -1_985,
      spike: -40_000,
      noise: -46,
      wideband: -32_768,
    });
    expect(model.sampleAt(82n, 1)).toEqual({
      lfp: -1_614,
      spike: -40_000,
      noise: -44,
      wideband: -32_768,
    });
    expect(model.sampleAt((1n << 32n) + 7n, 1)).toEqual({
      lfp: 858,
      spike: 0,
      noise: 38,
      wideband: 896,
    });
  });

  it("inserts the fixed 11-point template on the absolute channel schedule", () => {
    const model = new SyntheticNeuralModel();
    expect(model.spikePeriodSamples()).toBe(3_000n);
    expect(model.firstSpikeCenter(0)).toBe(29n);
    expect(model.firstSpikeCenter(3)).toBe(188n);
    expect(Array.from({ length: 11 }, (_, index) => model.spikeAt(24n + BigInt(index), 0)))
      .toEqual(SYNTHETIC_SPIKE_TEMPLATE);
    expect(model.spikeAt(29n, 0)).toBe(-40_000);
    expect(model.spikeAt(3_029n, 0)).toBe(-40_000);
    expect(model.spikeAt(23n, 0)).toBe(0);
    expect(model.spikeAt(35n, 0)).toBe(0);
    expect(model.sampleAt(29n, 0).wideband).toBe(-32_768);
  });

  it("defines wideband as the saturated sum and is independent of query order", () => {
    const left = new SyntheticNeuralModel({ seed: 0xfedc_ba98_7654_3210n });
    const right = new SyntheticNeuralModel({ seed: 0xfedc_ba98_7654_3210n });
    const probes = [0n, 29n, 30n, 77_777n, (1n << 40n) + 9n];
    const forward = probes.map((sample) => left.sampleAt(sample, 7));
    const reverse = probes.slice().reverse().map((sample) => right.sampleAt(sample, 7)).reverse();
    expect(forward).toEqual(reverse);
    for (const value of forward) {
      expect(value.wideband).toBe(Math.max(
        -32_768,
        Math.min(32_767, value.lfp + value.spike + value.noise),
      ));
    }

    const otherSeed = new SyntheticNeuralModel({ seed: 1n });
    expect(otherSeed.scenarioHash).not.toBe(left.scenarioHash);
    expect(otherSeed.noiseAt(77_777n, 7)).not.toBe(left.noiseAt(77_777n, 7));
  });

  it("counts and lazily enumerates only events inside an end-exclusive window", () => {
    const model = new SyntheticNeuralModel();
    expect(model.eventCountInRange(0, 0n, 30_000n)).toBe(10);
    expect([...model.eventCentersInRange(0, 0n, 10_000n)]).toEqual([
      29n,
      3_029n,
      6_029n,
      9_029n,
    ]);
    expect(model.eventCountInRange(0, 29n, 3_029n)).toBe(1);
    expect(model.eventCountInRange(0, 30n, 3_029n)).toBe(0);
    expect(model.eventCountInRange(127, 0n, 30_000n)).toBe(8);
    expect(model.waveformAtEvent(0, 29n)).toEqual(
      Array.from({ length: 11 }, (_, index) => model.sampleAt(24n + BigInt(index), 0).wideband),
    );
  });

  it("binds the fixed scenario and seed to a stable synthetic evidence identifier", () => {
    const first = new SyntheticNeuralModel();
    const second = new SyntheticNeuralModel();
    expect(first.scenarioId).toBe("forge.synthetic.neural.integer.v1");
    expect(first.scenarioHash).toBe(second.scenarioHash);
    expect(first.scenarioHash).toMatch(/^[0-9a-f]{64}$/);
    expect(first.inputConfigurationHash(32, "MOCK-LINEAR-32")).toMatch(/^[0-9a-f]{64}$/);
    expect(first.inputConfigurationHash(32, "MOCK-LINEAR-32"))
      .not.toBe(first.inputConfigurationHash(128, "MOCK-LINEAR-128"));
  });

  it("rejects coordinates outside the shared Rust u16/u64 domain", () => {
    const model = new SyntheticNeuralModel();
    expect(() => model.sampleAt((1n << 64n), 0)).toThrow(/unsigned 64-bit/);
    expect(() => model.sampleAt(0n, 65_536)).toThrow(/unsigned 16-bit/);
    expect(() => new SyntheticNeuralModel({ seed: 1n << 64n })).toThrow(/unsigned 64-bit/);
  });
});
