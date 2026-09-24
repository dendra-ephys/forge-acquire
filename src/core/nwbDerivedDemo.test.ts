import { describe, expect, it } from "vitest";
import { NWB_DEMO_FIXTURE, NwbDerivedDemoModel } from "./nwbDerivedDemo";

describe("NwbDerivedDemoModel", () => {
  it("binds the compact fixture to the audited NWB source", () => {
    expect(NWB_DEMO_FIXTURE.source).toMatchObject({
      sha256: "d9bb7a521a107d6f408186e28c2c2ebd5826b6cee2eb971d79c89ee643769343",
      byteLength: 147_311_211,
      channelCount: 16,
      waveformPointCount: 32,
      interpretedUnit: "millivolt",
      lfpPath: "acquisition/LFP/data",
      lfpSourceRateHz: 1_000,
      lfpInterpretedUnit: "millivolt",
    });
    expect(NWB_DEMO_FIXTURE.schemaVersion).toBe(2);
    expect(NWB_DEMO_FIXTURE.channels).toHaveLength(16);
    expect(NWB_DEMO_FIXTURE.channels.flatMap((channel) => channel.waveformCounts)).toHaveLength(80);
    expect(NWB_DEMO_FIXTURE.channels.every((channel) => channel.lfpCounts.length === 500)).toBe(true);
    expect(NWB_DEMO_FIXTURE.channels.reduce(
      (sum, channel) => sum + channel.eventSamples.length,
      0,
    )).toBe(1_081);
  });

  it("replays the compact real LFP window instead of a synthetic sine baseline", () => {
    const model = new NwbDerivedDemoModel();
    const samplesPerLfpPoint = BigInt(model.sampleRateHz / 50);
    for (const channel of [0, 5, 10, 15]) {
      const source = NWB_DEMO_FIXTURE.channels[channel]!.lfpCounts;
      expect(model.lfpAt(0n, channel)).toBe(source[0]! * 4);
      expect(model.lfpAt(samplesPerLfpPoint * 137n, channel)).toBe(source[137]! * 4);
    }
    expect(new Set([0, 5, 10, 15].map((channel) => (
      NWB_DEMO_FIXTURE.channels[channel]!.lfpCounts.join(",")
    ))).size).toBe(4);
    expect(model.lfpAt(300_000n, 0)).toBe(model.lfpAt(0n, 0));
  });

  it("replays real event timing and repeats only at the declared 10 second boundary", () => {
    const model = new NwbDerivedDemoModel();
    const loop = 300_000n;
    const first = [...model.eventCentersInRange(2, 0n, loop)];
    const second = [...model.eventCentersInRange(2, loop, loop * 2n)];
    expect(first).toHaveLength(NWB_DEMO_FIXTURE.channels[2]!.eventSamples.length);
    expect(second).toEqual(first.map((sample) => sample + loop));
    expect(model.eventCountInRange(2, 0n, loop * 2n)).toBe(first.length * 2);
  });

  it("keeps event snippets sample-identical to the reconstructed continuous timeline", () => {
    const model = new NwbDerivedDemoModel();
    const center = model.eventCentersInRange(4, 0n, 300_000n).next().value;
    if (center === undefined) throw new Error("fixture channel has no event");
    const waveform = model.waveformAtEvent(4, center);
    const start = center - BigInt(model.waveformPretriggerSamples);
    expect(waveform).toHaveLength(32);
    expect(waveform).toEqual(Array.from({ length: 32 }, (_, index) => (
      model.sampleAt(start + BigInt(index), 4).wideband
    )));
    expect(Math.max(...waveform) - Math.min(...waveform)).toBeGreaterThan(80);
  });

  it("preserves channel-specific waveform morphology instead of one fixed V shape", () => {
    const model = new NwbDerivedDemoModel();
    const waveforms = [0, 4, 8, 12].map((channel) => {
      const center = model.eventCentersInRange(channel, 0n, 300_000n).next().value;
      if (center === undefined) throw new Error(`fixture channel ${channel} has no event`);
      return model.waveformAtEvent(channel, center);
    });
    expect(new Set(waveforms.map((values) => values.join(","))).size).toBe(waveforms.length);
    expect(waveforms.some((values) => values.indexOf(Math.min(...values)) !== 16)).toBe(true);
  });

  it("rejects channel-count claims that exceed the 16-channel source", () => {
    const model = new NwbDerivedDemoModel();
    expect(() => model.inputConfigurationHash(32, "NWB-DERIVED-LINEAR-32"))
      .toThrow(/requires exactly 16 channels/);
    expect(model.inputConfigurationHash(16, "NWB-DERIVED-LINEAR-16")).toMatch(/^[0-9a-f]{64}$/);
  });
});
