import { describe, expect, it } from "vitest";
import { SimulatorBackend } from "./simulator";
import {
  DEFAULT_SYNTHETIC_HEADSTAGE_PROFILE,
  isNewRunCatalogEligible,
} from "./hardwareProfiles";

function manualClock(initialMs = 1_000) {
  let currentMs = initialMs;
  return {
    now: () => currentMs,
    advance: (deltaMs: number) => {
      currentMs += deltaMs;
    },
  };
}

describe("SimulatorBackend", () => {
  it("is unambiguously synthetic and never claims raw-data writer throughput", () => {
    const backend = new SimulatorBackend({ now: () => 42 });
    const snapshot = backend.getSnapshot();

    expect(backend.kind).toBe("simulator");
    expect(backend.isSynthetic).toBe(true);
    expect(snapshot.backendLabel).toContain("SYNTHETIC");
    expect(snapshot.pods[0]?.headstageProfileId).toBe("rhd2132x1");
    expect(isNewRunCatalogEligible(DEFAULT_SYNTHETIC_HEADSTAGE_PROFILE)).toBe(true);
    expect(snapshot.pods[0]?.channelCount).toBeNull();
    expect(snapshot.pods[0]?.usbBridge).toBeNull();
    expect(snapshot.pods[0]?.dhlDescriptorAdmitted).toBe(false);
    expect(snapshot.isSynthetic).toBe(true);
    expect(snapshot.metrics.writerBytesPerSecond).toBe(0);
    expect(snapshot.metrics.storageFreeBytes).toBeNull();
    expect(snapshot.recordingPipeline.spoolState).toBe("unavailable");
    expect(snapshot.recordingPipeline.nwbState).toBe("unavailable");
    expect(snapshot.recordingPipeline.protectionVerified).toBe(false);
    expect(snapshot.analysisPipeline.controllerTokenOwner).toBe("none");
    expect(snapshot.analysisPipeline.referenceAlgorithmsOnly).toBe(true);
    expect(snapshot.stimulation.state).toBe("unavailable");
    expect(snapshot.stimulation.rhsChannelCount).toBe(0);
    expect(snapshot.stimulation.safetyProfileHash).toBeNull();
    expect(snapshot.stimulation.unavailableReasons).toHaveLength(3);
    expect(snapshot.storagePreflight.eligibleForProtectedRecording).toBe(false);
    expect(snapshot.storagePreflight.requiredUsableBytes).toBe(40_000_000_000_000);
    expect(snapshot.events[0]?.code).toBe("SIMULATOR_SYNTHETIC_ONLY");
    expect(snapshot.events[0]?.message).toContain("不会写入原始神经数据");
  });

  it("uses only an explicit active SKiDL Headstage profile for synthetic channels", async () => {
    const backend = new SimulatorBackend({ headstageProfileId: "rhs2116x2" });
    await backend.connect();
    const pod = backend.getSnapshot().pods[0];
    expect(pod?.headstageProfileId).toBe("rhs2116x2");
    expect(pod?.channelCount).toBe(32);
    expect(backend.getSnapshot().stimulation.state).toBe("unavailable");
    expect(backend.getSnapshot().stimulation.rhsChannelCount).toBe(0);
  });

  it("recognizes a decode-only profile but refuses a new synthetic Run", async () => {
    const backend = new SimulatorBackend({ headstageProfileId: "rhd2132x2" });
    await backend.connect();
    expect(backend.getSnapshot().pods[0]?.headstageProfileId).toBe("rhd2132x2");
    expect(() => backend.startRecording()).toThrow(/历史解码/);
  });

  it("connects, monitors, and emits deterministic synthetic traces", async () => {
    const clock = manualClock();
    const backend = new SimulatorBackend({ now: clock.now });

    await backend.connect();
    expect(backend.getSnapshot().operatorState).toBe("ready");
    expect(backend.getSnapshot().metrics.inputBytesPerSecond).toBe(0);
    expect(backend.getSnapshot().metrics.expectedBytesPerSecond).toBe(32 * 30_000 * 2);
    backend.startMonitoring();
    expect(backend.getSnapshot().operatorState).toBe("monitoring");

    clock.advance(250);
    const request = {
      channelOffset: 2,
      channelCount: 3,
      pointsPerChannel: 32,
      sampleWindowSeconds: 0.5,
    };
    const first = backend.getTraceBlock(request);
    const second = backend.getTraceBlock(request);

    expect(first.synthetic).toBe(true);
    expect(first.valuesUv).toHaveLength(3);
    expect(Array.from(first.valuesUv[0])).toEqual(Array.from(second.valuesUv[0]));

    clock.advance(10);
    const later = backend.getTraceBlock(request);
    expect(Array.from(later.valuesUv[0])).not.toEqual(Array.from(first.valuesUv[0]));
  });

  it("starts recording from Ready and keeps the raw writer explicitly inactive", async () => {
    const clock = manualClock();
    const backend = new SimulatorBackend({ now: clock.now });
    await backend.connect();

    const snapshot = backend.startRecording("SIM-TEST-RUN");
    expect(snapshot.operatorState).toBe("recording");
    expect(snapshot.machine.acquisition).toBe("streaming");
    expect(snapshot.machine.writer).toBe("writing");
    expect(snapshot.machine.runId).toBe("SIM-TEST-RUN");
    expect(snapshot.metrics.writerBytesPerSecond).toBe(0);
    expect(snapshot.events.at(-1)?.code).toBe("SIMULATOR_RECORDING_NO_RAW_FILE");
    expect(snapshot.machine.lastFinalizedRunId).toBeNull();
  });

  it("exposes flushing immediately and finalizes only after the async flush boundary", async () => {
    let releaseFlush: (() => void) | undefined;
    const wait = () => new Promise<void>((resolve) => {
      releaseFlush = resolve;
    });
    const backend = new SimulatorBackend({ now: () => 100, wait });
    const writerStates: string[] = [];
    backend.subscribe((snapshot) => writerStates.push(snapshot.machine.writer));
    await backend.connect();
    backend.startRecording("SIM-FLUSH-TEST");

    const pendingStop = backend.stopRecording();
    expect(backend.getSnapshot().machine.writer).toBe("flushing");
    expect(backend.getSnapshot().operatorState).toBe("recording");
    expect(writerStates).toContain("flushing");

    releaseFlush?.();
    await pendingStop;
    const finalized = backend.getSnapshot();
    expect(finalized.machine.writer).toBe("finalized");
    expect(finalized.machine.runId).toBe("SIM-FLUSH-TEST");
    expect(finalized.machine.lastFinalizedRunId).toBe("SIM-FLUSH-TEST");
    expect(finalized.operatorState).toBe("monitoring");
    expect(writerStates.at(-1)).toBe("finalized");
  });

  it("captures a marker immediately from the host monotonic clock", async () => {
    const clock = manualClock(5_000);
    const backend = new SimulatorBackend({ now: clock.now, sampleRate: 1_000 });
    await backend.connect();
    backend.startRecording("SIM-MARKER-RUN");
    clock.advance(125);

    const markerDraft = backend.captureMarker();
    expect(markerDraft.hostMonotonicMs).toBe(5_125);
    expect(markerDraft.timestampSource).toBe("host_monotonic");
    expect(markerDraft.hardwareGlobalTime).toBeNull();
    expect(markerDraft.nearestSampleCounter).toBe(125);
    expect(markerDraft.runId).toBe("SIM-MARKER-RUN");
    expect(backend.getSnapshot().markers).toEqual([]);

    clock.advance(500);
    const marker = backend.saveMarker({
      ...markerDraft,
      label: "Stimulus",
      note: "synthetic test marker",
    });
    expect(marker.hostMonotonicMs).toBe(5_125);
    expect(marker.label).toBe("Stimulus");
    expect(backend.getSnapshot().markers).toEqual([marker]);
  });

  it("can begin another synthetic run after the previous lifecycle finalized", async () => {
    const backend = new SimulatorBackend({
      now: () => 1_000,
      wait: async () => undefined,
    });
    await backend.connect();
    backend.startRecording("SIM-FIRST");
    await backend.stopRecording();
    expect(backend.getSnapshot().machine.writer).toBe("finalized");

    const next = backend.startRecording("SIM-SECOND");
    expect(next.machine.writer).toBe("writing");
    expect(next.machine.runId).toBe("SIM-SECOND");
  });

  it("returns state snapshots by copy and marks interrupted recording invalid", async () => {
    const backend = new SimulatorBackend({ now: () => 500 });
    await backend.connect();
    backend.startRecording("SIM-INTERRUPT");

    const before = backend.captureSnapshot();
    before.machine.transport = "failed";
    expect(backend.getSnapshot().machine.transport).toBe("open");

    const disconnected = backend.disconnect();
    expect(disconnected.operatorState).toBe("disconnected");
    expect(disconnected.machine.writer).toBe("failed");
    expect(disconnected.machine.integrity).toBe("invalid");
    expect(disconnected.events.at(-1)?.code).toBe("SIMULATOR_RECORDING_INTERRUPTED");
    await backend.connect();
    expect(() => backend.startRecording("SIM-MUST-NOT-OVERWRITE"))
      .toThrow("请先确认并归档失败的演示 Run");
  });
});
