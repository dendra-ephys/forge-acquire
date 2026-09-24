import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AcquireIntent,
  AcquireLifecycleState,
  PreviewSessionState,
  RecordingTargetRequest,
  RunPlan,
} from "./acquireAdapter";
import { MockAcquireAdapter } from "./mockAcquireAdapter";
import {
  SYNTHETIC_DEFAULT_SEED,
  SYNTHETIC_PREVIEW_MICROVOLTS_PER_COUNT,
  SyntheticNeuralModel,
} from "../core/syntheticNeural";
import { NwbDerivedDemoModel } from "../core/nwbDerivedDemo";

const TRANSITION_MS = 5;
const RECORDING_TARGET: RecordingTargetRequest = {
  requestedDirectory: "F:\\ForgeRuns",
  baseName: "FORGE-TEST",
  allocationPolicy: "create_new_incrementing_suffix",
  overwritePolicy: "forbid",
};

describe("MockAcquireAdapter", () => {
  let adapter: MockAcquireAdapter;

  beforeEach(() => {
    vi.useFakeTimers();
    adapter = new MockAcquireAdapter({
      transitionDelayMs: TRANSITION_MS,
      previewIntervalMs: 1_000,
      connectedPodCount: 4,
    });
  });

  afterEach(() => {
    adapter.dispose();
    vi.useRealTimers();
  });

  async function accept(intent: AcquireIntent, transitionCount: number): Promise<void> {
    const receipt = await adapter.execute(intent);
    expect(receipt.accepted).toBe(true);
    expect(receipt.receiptKind).toBe("command");
    await vi.advanceTimersByTimeAsync(TRANSITION_MS * transitionCount);
  }

  async function runPlan(
    selectedPodKeys = ["MOCK-DIRECT-01", "MOCK-AGG-POD-01"],
    recordingTarget: RecordingTargetRequest = RECORDING_TARGET,
  ): Promise<RunPlan> {
    const snapshot = await adapter.readSnapshot();
    const pods = [
      ...snapshot.topology.directPods,
      ...snapshot.topology.aggregators.flatMap((aggregator) =>
        aggregator.ports.flatMap((port) => port.pod === null ? [] : [port.pod])),
    ];
    return {
      label: "Mock glove-box run",
      plannedDurationSeconds: 60,
      selectedDevices: selectedPodKeys.map((podKey) => {
        const pod = pods.find((candidate) => candidate.key === podKey);
        return {
          podKey,
          deviceId: pod?.identity.deviceId ?? `UNKNOWN-${podKey}`,
          identityEvidenceHash: pod?.identity.identityEvidenceHash ?? "missing-identity",
          inputEvidenceHash: pod?.neuralInput?.evidenceHash ?? "missing-input",
        };
      }),
      topologyEvidenceHash: snapshot.topology.evidenceHash,
      recordingTarget: { ...recordingTarget },
    };
  }

  async function startPreview(podKey = "MOCK-DIRECT-01"): Promise<void> {
    const snapshot = await adapter.readSnapshot();
    await accept({
      type: "start_preview",
      podKey,
      topologyEvidenceHash: snapshot.topology.evidenceHash,
    }, 2);
    expect((await adapter.readSnapshot()).previewState).toBe("live");
  }

  async function reachRecording(): Promise<void> {
    await accept({ type: "connect" }, 1);
    await startPreview();
    await accept({ type: "preflight", plan: await runPlan() }, 2);
    await accept({ type: "arm_recording" }, 2);
    await accept({ type: "start_recording" }, 2);
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "recording", previewState: "live" });
  }

  async function reachFinalized(): Promise<void> {
    await reachRecording();
    await accept({ type: "stop_recording" }, 4);
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "finalized", previewState: "live" });
  }

  it("rejects explicit control disconnect while a Run is active", async () => {
    await reachRecording();

    const receipt = await adapter.execute({ type: "disconnect_control" });

    expect(receipt).toMatchObject({
      accepted: false,
      reasonCode: "ACTIVE_RUN_CONTROL_REQUIRED",
    });
    expect(await adapter.readSnapshot()).toMatchObject({
      controlConnection: "connected",
      lifecycle: "recording",
    });
  });

  it("pauses and resumes a mock recording without ending its Run", async () => {
    await reachRecording();

    await accept({ type: "pause_recording" }, 1);
    expect(await adapter.readSnapshot()).toMatchObject({
      lifecycle: "recording",
      recordingPaused: true,
      previewState: "live",
    });

    await accept({ type: "resume_recording" }, 1);
    expect(await adapter.readSnapshot()).toMatchObject({
      lifecycle: "recording",
      recordingPaused: false,
      previewState: "live",
    });
  });

  it("admits recording setup without requiring Preview to be running", async () => {
    await accept({ type: "connect" }, 1);

    const receipt = await adapter.execute({ type: "preflight", plan: await runPlan() });
    expect(receipt).toMatchObject({ accepted: true, requestedState: "preflighting" });
    await vi.advanceTimersByTimeAsync(TRANSITION_MS * 2);

    expect(await adapter.readSnapshot()).toMatchObject({
      lifecycle: "preflight_passed",
      previewState: "stopped",
    });
  });

  it("keeps command acceptance separate from the complete lifecycle snapshot sequence", async () => {
    const states: Array<{ lifecycle: AcquireLifecycleState; previewState: PreviewSessionState }> = [];
    adapter.subscribeSnapshots(({ lifecycle, previewState }) => states.push({ lifecycle, previewState }));

    const connect = await adapter.execute({ type: "connect" });
    expect(connect).toMatchObject({ accepted: true, requestedState: "connected_idle" });
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "disconnected", previewState: "stopped" });
    await vi.advanceTimersByTimeAsync(TRANSITION_MS);

    const topology = await adapter.readSnapshot();
    const preview = await adapter.execute({
      type: "start_preview",
      podKey: "MOCK-DIRECT-01",
      topologyEvidenceHash: topology.topology.evidenceHash,
    });
    expect(preview).toMatchObject({
      accepted: true,
      requestedState: null,
      requestedPreviewState: "start_requested",
    });
    await vi.advanceTimersByTimeAsync(TRANSITION_MS * 2);
    await accept({ type: "preflight", plan: await runPlan() }, 2);
    await accept({ type: "arm_recording" }, 2);
    await accept({ type: "start_recording" }, 2);
    await accept({ type: "stop_recording" }, 4);

    expect(states).toEqual([
      { lifecycle: "disconnected", previewState: "stopped" },
      { lifecycle: "connected_idle", previewState: "stopped" },
      { lifecycle: "connected_idle", previewState: "start_requested" },
      { lifecycle: "connected_idle", previewState: "live" },
      { lifecycle: "preflighting", previewState: "live" },
      { lifecycle: "preflight_passed", previewState: "live" },
      { lifecycle: "arm_requested", previewState: "live" },
      { lifecycle: "armed", previewState: "live" },
      { lifecycle: "start_requested", previewState: "live" },
      { lifecycle: "recording", previewState: "live" },
      { lifecycle: "stop_requested", previewState: "live" },
      { lifecycle: "recording_stopped", previewState: "live" },
      { lifecycle: "finalizing", previewState: "live" },
      { lifecycle: "finalized", previewState: "live" },
    ]);
  });

  it("streams Preview before any Run without promoting recording evidence", async () => {
    await accept({ type: "connect" }, 1);
    await startPreview();

    let snapshot = await adapter.readSnapshot();
    const first = adapter.previewSource.getLatest();
    expect(snapshot).toMatchObject({
      lifecycle: "connected_idle",
      previewState: "live",
      runId: null,
      runEpoch: null,
      recordingTarget: null,
      evidence: {
        acquisition: { status: "idle" },
        durability: { status: "idle" },
      },
    });
    expect(first).toMatchObject({
      runId: null,
      runEpoch: null,
      containsContinuousRawSamples: false,
      containsEventWaveformSnippets: false,
    });

    await vi.advanceTimersByTimeAsync(1_000);
    const second = adapter.previewSource.getLatest();
    expect(second?.sequence).toBeGreaterThan(first?.sequence ?? 0n);
    snapshot = await adapter.readSnapshot();
    expect(snapshot.runId).toBeNull();
    expect(snapshot.evidence.acquisition.status).toBe("idle");
  });

  it("keeps Preview live while one End and Save command advances through pending states to a durable seal", async () => {
    await reachRecording();
    expect((await adapter.readSnapshot()).load).toMatchObject({
      sourceBufferPercent: 11,
      writerQueuePercent: 18,
      controlLoadPercent: 24,
      recordingFileBytes: null,
      storageFreeBytes: null,
    });

    const frameBeforeStop = adapter.previewSource.getLatest();
    const stop = await adapter.execute({ type: "stop_recording", reason: "operator" });
    expect(stop).toMatchObject({ accepted: true, requestedState: "stop_requested" });
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "recording", previewState: "live" });

    await vi.advanceTimersByTimeAsync(TRANSITION_MS);
    let snapshot = await adapter.readSnapshot();
    expect(snapshot.lifecycle).toBe("stop_requested");
    expect(snapshot.previewState).toBe("live");
    expect(snapshot.evidence.durability.status).toBe("pending");

    await vi.advanceTimersByTimeAsync(TRANSITION_MS);
    snapshot = await adapter.readSnapshot();
    expect(snapshot.lifecycle).toBe("recording_stopped");
    expect(snapshot.previewState).toBe("live");
    expect(snapshot.evidence.acquisition.status).toBe("proven");
    expect(snapshot.evidence.durability.status).toBe("pending");
    expect(snapshot.runReceipt?.status).toBe("stopped_not_durable");
    expect(snapshot.load.sourceBufferPercent).toBe(11);
    expect(snapshot.load.writerQueuePercent).toBe(31);

    await vi.advanceTimersByTimeAsync(TRANSITION_MS);
    snapshot = await adapter.readSnapshot();
    expect(snapshot.lifecycle).toBe("finalizing");
    expect(snapshot.previewState).toBe("live");
    expect(snapshot.evidence.durability.status).toBe("pending");
    expect(snapshot.runReceipt?.status).toBe("finalizing");

    await vi.advanceTimersByTimeAsync(TRANSITION_MS);
    snapshot = await adapter.readSnapshot();
    expect(snapshot.lifecycle).toBe("finalized");
    expect(snapshot.previewState).toBe("live");
    expect(snapshot.evidence.durability.status).toBe("proven");
    expect(snapshot.runReceipt?.status).toBe("finalized");

    await vi.advanceTimersByTimeAsync(1_000);
    const frameAfterStop = adapter.previewSource.getLatest();
    expect(frameAfterStop?.sequence).toBeGreaterThan(frameBeforeStop?.sequence ?? 0n);
    expect(frameAfterStop).toMatchObject({ runId: null, runEpoch: null });
  });

  it("keeps Preview advancing after End and Save without attributing later frames to the sealed Run", async () => {
    await reachRecording();
    const beforeFinalize = adapter.previewSource.getLatest();
    await accept({ type: "stop_recording" }, 4);
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "finalized", previewState: "live" });

    await vi.advanceTimersByTimeAsync(1_000);
    const afterFinalize = adapter.previewSource.getLatest();
    expect(afterFinalize?.sequence).toBeGreaterThan(beforeFinalize?.sequence ?? 0n);
    expect(afterFinalize).toMatchObject({ runId: null, runEpoch: null });
  });

  it("keeps Preview commands independent through Arm, Recording, Stop, and recovery", async () => {
    await accept({ type: "connect" }, 1);
    await startPreview();
    await accept({ type: "preflight", plan: await runPlan() }, 2);

    await accept({ type: "stop_preview", reason: "operator" }, 2);
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "preflight_passed", previewState: "stopped" });

    await accept({ type: "arm_recording" }, 2);
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "armed", previewState: "stopped" });
    await accept({ type: "start_recording" }, 2);
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "recording", previewState: "stopped" });

    await startPreview();
    await adapter.faultController.inject({ type: "durability_failure", reason: "fsync barrier failed" });
    const stopRecording = await adapter.execute({ type: "stop_recording", reason: "operator" });
    const stopPreview = await adapter.execute({ type: "stop_preview", reason: "operator" });
    expect(stopRecording).toMatchObject({ accepted: true, requestedState: "stop_requested" });
    expect(stopPreview).toMatchObject({ accepted: true, requestedPreviewState: "stop_requested" });
    await vi.advanceTimersByTimeAsync(TRANSITION_MS);
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "stop_requested", previewState: "stop_requested" });
    await vi.advanceTimersByTimeAsync(TRANSITION_MS);
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "recording_stopped", previewState: "stopped" });

    await vi.advanceTimersByTimeAsync(TRANSITION_MS * 2);
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "recovery_required", previewState: "stopped" });
    await startPreview();
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "recovery_required", previewState: "live" });
    await accept({ type: "stop_preview", reason: "operator" }, 2);
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "recovery_required", previewState: "stopped" });
    await startPreview();
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "recovery_required", previewState: "live" });
  });

  it("does not promote Preflight or Recording Arm into acquisition evidence", async () => {
    await accept({ type: "connect" }, 1);
    await startPreview();
    await accept({ type: "preflight", plan: await runPlan() }, 2);
    let snapshot = await adapter.readSnapshot();
    expect(snapshot.lifecycle).toBe("preflight_passed");
    expect(snapshot.evidence.acquisition.status).toBe("idle");
    expect(snapshot.evidence.acquisition.summary).toContain("has not started");

    await accept({ type: "arm_recording" }, 2);
    snapshot = await adapter.readSnapshot();
    expect(snapshot.lifecycle).toBe("armed");
    expect(snapshot.evidence.acquisition.status).toBe("idle");
  });

  it("never turns GUI/control-pipe loss into an acquisition Stop", async () => {
    await reachRecording();
    const states: AcquireLifecycleState[] = [];
    adapter.subscribeSnapshots((snapshot) => states.push(snapshot.lifecycle));
    const previewSequence = adapter.previewSource.getLatest()!.sequence;

    await adapter.faultController.inject({ type: "control_pipe_loss" });
    await vi.advanceTimersByTimeAsync(1_000);
    let snapshot = await adapter.readSnapshot();
    expect(snapshot).toMatchObject({
      lifecycle: "recording",
      controlConnection: "lost",
      stale: true,
    });
    expect(snapshot.evidence.acquisition.status).toBe("active");
    expect(adapter.previewSource.getLatest()!.sequence).toBe(previewSequence);
    expect(states).not.toContain("stop_requested");
    expect(states).not.toContain("recording_stopped");

    await adapter.faultController.clear("control_pipe_loss");
    const reconnect = await adapter.execute({ type: "connect" });
    expect(reconnect).toMatchObject({ accepted: true, requestedState: "recording" });
    await vi.advanceTimersByTimeAsync(TRANSITION_MS);
    snapshot = await adapter.readSnapshot();
    expect(snapshot).toMatchObject({ lifecycle: "recording", controlConnection: "connected", stale: false });
    expect(adapter.previewSource.getLatest()!.sequence).toBeGreaterThan(previewSequence);
  });

  it("preserves the selected Preview Pod across control reconnect", async () => {
    await accept({ type: "connect" }, 1);
    await startPreview("MOCK-AGG-POD-01");
    expect(adapter.previewSource.getLatest()?.podKey).toBe("MOCK-AGG-POD-01");

    await adapter.faultController.inject({ type: "control_pipe_loss" });
    await adapter.faultController.clear("control_pipe_loss");
    await accept({ type: "connect" }, 1);

    expect(await adapter.readSnapshot()).toMatchObject({
      lifecycle: "connected_idle",
      previewState: "live",
      controlConnection: "connected",
    });
    expect(adapter.previewSource.getLatest()?.podKey).toBe("MOCK-AGG-POD-01");
  });

  it("keeps a Preview-only source gap out of Run evidence", async () => {
    await accept({ type: "connect" }, 1);
    await startPreview();
    await adapter.faultController.inject({ type: "counter_gap", missingSamples: 17 });

    let snapshot = await adapter.readSnapshot();
    expect(snapshot).toMatchObject({
      lifecycle: "connected_idle",
      previewState: "fault",
      runId: null,
      runReceipt: null,
      evidence: {
        acquisition: { status: "idle" },
        durability: { status: "idle" },
      },
    });
    expect(snapshot.faults.find((fault) => fault.code === "counter_gap")).toMatchObject({
      recoverable: true,
      latched: true,
    });

    await adapter.faultController.clear("counter_gap");
    snapshot = await adapter.readSnapshot();
    expect(snapshot).toMatchObject({ lifecycle: "connected_idle", previewState: "stopped", runId: null });
    expect(snapshot.faults.find((fault) => fault.code === "counter_gap")?.latched).toBe(false);
  });

  it("enters recovery_required on durability failure and finalizes only after recovery", async () => {
    await reachRecording();
    await adapter.faultController.inject({ type: "durability_failure", reason: "fsync barrier failed" });
    expect((await adapter.readSnapshot()).evidence.durability).toMatchObject({
      status: "active",
      summary: expect.stringContaining("armed for the next End and Save"),
    });

    await accept({ type: "stop_recording" }, 4);
    let snapshot = await adapter.readSnapshot();
    expect(snapshot.lifecycle).toBe("recovery_required");
    expect(snapshot.runReceipt?.status).toBe("recovery_required");
    expect(snapshot.evidence.durability.status).toBe("failed");

    await adapter.faultController.clear("durability_failure");
    const recovery = await adapter.execute({ type: "recover_run" });
    expect(recovery).toMatchObject({ accepted: true, requestedState: "finalizing" });
    await vi.advanceTimersByTimeAsync(TRANSITION_MS);
    snapshot = await adapter.readSnapshot();
    expect(snapshot.lifecycle).toBe("finalizing");
    expect(snapshot.evidence.durability.status).toBe("pending");

    await vi.advanceTimersByTimeAsync(TRANSITION_MS);
    snapshot = await adapter.readSnapshot();
    expect(snapshot.lifecycle).toBe("finalized");
    expect(snapshot.evidence.durability.status).toBe("proven");
    expect(snapshot.runReceipt?.status).toBe("finalized");
  });

  it("reports explicit direct-PC and synthetic Aggregator topology without promoting hardware", async () => {
    const capability = await adapter.readCapabilities();
    expect(capability).toMatchObject({ scope: "mock", synthetic: true, maxPodsPerRun: 8 });
    expect(capability.capabilities.mock_acquisition.status).toBe("available");
    expect(capability.capabilities.decimated_preview.status).toBe("available");
    expect(capability.capabilities.lfp_preview.status).toBe("available");
    expect(capability.capabilities.spike_preview.status).toBe("available");
    for (const id of ["ft601_direct", "aggregator_10gbe", "stimulation", "closed_loop"] as const) {
      expect(capability.capabilities[id].status).toBe("unavailable");
    }
    for (const id of ["rhs_acquisition", "nwb_materialization", "release_24h"] as const) {
      expect(capability.capabilities[id].status).toBe("qualification_required");
    }

    const snapshot = await adapter.readSnapshot();
    expect(snapshot.topology.directPods.map((pod) => pod.key)).toEqual([
      "MOCK-DIRECT-01",
      "MOCK-DIRECT-02",
    ]);
    expect(snapshot.topology.aggregators).toHaveLength(1);
    const aggregator = snapshot.topology.aggregators[0];
    expect(aggregator).toMatchObject({
      aggregatorId: "MOCK-AGG-01",
      synthetic: true,
      state: "mock_fixture",
      hardwareStatus: "unavailable",
      maxPodPorts: 8,
    });
    const aggregatedPods = aggregator.ports.flatMap((port) => port.pod ? [port.pod] : []);
    expect(aggregatedPods.map((pod) => pod.key)).toEqual([
      "MOCK-AGG-POD-01",
      "MOCK-AGG-POD-02",
    ]);
    expect(new Set([...snapshot.topology.directPods, ...aggregatedPods].map((pod) => pod.key)).size).toBe(4);
    for (const pod of [...snapshot.topology.directPods, ...aggregatedPods]) {
      expect(pod.neuralInput).toMatchObject({
        profileId: "MOCK-RHD2132X1-32CH-30K",
        neuralChannelCount: 32,
        sampleRateHz: 30_000,
        sourceEncoding: "synthetic_generator",
        previewValueUnit: "microvolt",
        microvoltsPerCount: SYNTHETIC_PREVIEW_MICROVOLTS_PER_COUNT,
        scope: "mock",
        reasonCode: "MOCK_GENERATOR_UNITS",
      });
      expect(pod.neuralInput?.evidenceHash).toMatch(/^[0-9a-f]{64}$/);
      expect(pod.neuralInput?.descriptorHash).toBeNull();
      expect(pod.neuralInput?.inventoryHash).toBeNull();
    }
    expect(capability.capabilities.aggregator_10gbe).toMatchObject({
      status: "unavailable",
      claimScope: "hardware",
      reasonCode: "API_NOT_FROZEN",
    });
  });

  it("rejects unknown, duplicate, and stale-topology Pod selections", async () => {
    await accept({ type: "connect" }, 1);
    await startPreview();
    const base = await runPlan();
    for (const plan of [
      { ...base, selectedDevices: (await runPlan(["UNKNOWN-POD"])).selectedDevices },
      { ...base, selectedDevices: (await runPlan(["MOCK-DIRECT-01", "MOCK-DIRECT-01"])).selectedDevices },
      {
        ...base,
        selectedDevices: [{ ...base.selectedDevices[0], identityEvidenceHash: "stale-identity-hash" }],
      },
      { ...base, topologyEvidenceHash: "stale-topology-hash" },
    ]) {
      const receipt = await adapter.execute({ type: "preflight", plan });
      expect(receipt).toMatchObject({ accepted: false, reasonCode: "INVALID_PLAN" });
    }
  });

  it("reserves create-new no-overwrite recording targets with monotonic Run suffixes", async () => {
    await reachFinalized();
    let snapshot = await adapter.readSnapshot();
    expect(snapshot.recordingTarget).toMatchObject({
      reservationId: "MOCK-TARGET-000001",
      requestedDirectory: "F:\\ForgeRuns",
      allocatedLeafName: "FORGE-TEST-001",
      resolvedRunDirectory: "F:\\ForgeRuns\\FORGE-TEST-001",
      allocationSequence: 1n,
      journalFileName: "run.forgewal",
      directoryCreateDisposition: "simulated",
      journalCreateDisposition: "simulated",
      overwritePolicy: "forbid",
      scope: "mock",
      synthetic: true,
      reasonCode: "MOCK_SESSION_RESERVATION",
    });
    expect(snapshot.runReceipt?.recordingTarget).toEqual(snapshot.recordingTarget);

    await accept({ type: "preflight", plan: await runPlan() }, 2);
    snapshot = await adapter.readSnapshot();
    expect(snapshot).toMatchObject({
      runId: "MOCK-RUN-0002",
      runEpoch: 2n,
      lifecycle: "preflight_passed",
      previewState: "live",
      recordingTarget: {
        reservationId: "MOCK-TARGET-000002",
        allocatedLeafName: "FORGE-TEST-002",
        resolvedRunDirectory: "F:\\ForgeRuns\\FORGE-TEST-002",
        allocationSequence: 2n,
        overwritePolicy: "forbid",
      },
    });
  });

  it("rejects relative or traversing directories and invalid or reserved base names", async () => {
    await accept({ type: "connect" }, 1);
    await startPreview();
    const invalidTargets: RecordingTargetRequest[] = [
      { ...RECORDING_TARGET, requestedDirectory: "relative\\ForgeRuns" },
      { ...RECORDING_TARGET, requestedDirectory: "F:\\ForgeRuns\\..\\escape" },
      { ...RECORDING_TARGET, baseName: "bad/name" },
      { ...RECORDING_TARGET, baseName: "CON" },
    ];

    for (const recordingTarget of invalidTargets) {
      const receipt = await adapter.execute({
        type: "preflight",
        plan: await runPlan(undefined, recordingTarget),
      });
      expect(receipt).toMatchObject({ accepted: false, reasonCode: "INVALID_PLAN" });
    }
    expect(await adapter.readSnapshot()).toMatchObject({
      lifecycle: "connected_idle",
      previewState: "live",
      runId: null,
      recordingTarget: null,
    });
  });

  it("renames by immutable identity with revision CAS and unique mock-session names", async () => {
    const before = await adapter.readSnapshot();
    const first = before.topology.directPods[0];
    const second = before.topology.directPods[1];
    expect(first.identity).toMatchObject({
      deviceId: "MOCK-POD-SN-0001",
      identitySource: "mock_fixture",
      revision: 0n,
      persistence: "mock_session",
      writable: true,
      crossHostPersistenceQualified: false,
      powerLossSafeWriteQualified: false,
    });
    expect(first.identity.deviceId).not.toBe(first.key);
    expect(second.identity.deviceId).not.toBe(second.key);

    const renamed = await adapter.renameDevice({
      kind: "pod",
      deviceId: first.identity.deviceId,
      expectedIdentityEvidenceHash: first.identity.identityEvidenceHash!,
      displayName: "Pod Alpha",
      expectedRevision: 0n,
    });
    expect(renamed).toMatchObject({
      accepted: true,
      reasonCode: "MOCK_SESSION_COMMITTED",
      deviceId: first.identity.deviceId,
      previousRevision: 0n,
      committedRevision: 1n,
      committedDisplayName: "Pod Alpha",
      persistence: "mock_session",
      readBackVerified: true,
    });

    let after = await adapter.readSnapshot();
    let renamedPod = after.topology.directPods[0];
    expect(renamedPod).toMatchObject({
      key: first.key,
      podId: first.podId,
      label: "Pod Alpha",
      identity: {
        deviceId: first.identity.deviceId,
        displayName: "Pod Alpha",
        revision: 1n,
        persistence: "mock_session",
      },
    });

    expect(await adapter.renameDevice({
      kind: "pod",
      deviceId: first.identity.deviceId,
      expectedIdentityEvidenceHash: first.identity.identityEvidenceHash!,
      displayName: "Stale Rename",
      expectedRevision: 0n,
    })).toMatchObject({
      accepted: false,
      reasonCode: "STALE_NAME_REVISION",
      previousRevision: 1n,
      committedRevision: null,
      readBackVerified: false,
    });

    expect(await adapter.renameDevice({
      kind: "pod",
      deviceId: second.identity.deviceId,
      expectedIdentityEvidenceHash: second.identity.identityEvidenceHash!,
      displayName: "Pod Alpha",
      expectedRevision: 0n,
    })).toMatchObject({
      accepted: false,
      reasonCode: "DUPLICATE_DISPLAY_NAME",
      committedRevision: null,
    });

    expect(await adapter.renameDevice({
      kind: "pod",
      deviceId: first.identity.deviceId,
      expectedIdentityEvidenceHash: first.identity.identityEvidenceHash!,
      displayName: "Pod Alpha Revised",
      expectedRevision: 1n,
    })).toMatchObject({
      accepted: true,
      previousRevision: 1n,
      committedRevision: 2n,
      persistence: "mock_session",
    });
    after = await adapter.readSnapshot();
    renamedPod = after.topology.directPods[0];
    expect(renamedPod.identity.deviceId).toBe(first.identity.deviceId);
    expect(renamedPod.identity.revision).toBe(2n);
    expect(after.topology.directPods[1].identity.displayName).toBe(second.identity.displayName);

    expect(await adapter.renameDevice({
      kind: "pod",
      deviceId: first.key,
      expectedIdentityEvidenceHash: first.identity.identityEvidenceHash!,
      displayName: "Route Is Not Identity",
      expectedRevision: 2n,
    })).toMatchObject({
      accepted: false,
      reasonCode: "UNKNOWN_DEVICE",
    });
  });

  it("publishes bounded Wideband, LFP, and Spike mock previews without raw streams", async () => {
    await reachRecording();
    let snapshot = await adapter.readSnapshot();
    const common = {
      scope: "mock",
      synthetic: true,
      containsContinuousRawSamples: false,
      containsEventWaveformSnippets: false,
      podKey: "MOCK-DIRECT-01",
    };
    expect(adapter.previewSource.getLatest()).toMatchObject({
      ...common,
      encoding: "sampled_extrema_preview_v1",
      aggregation: "sampled_candidates",
      signalKind: "wideband",
      windowSeconds: 1,
    });

    adapter.previewSource.setRequest({
      podKey: "MOCK-AGG-POD-01",
      signalKind: "lfp",
      windowSeconds: 5,
      channelStart: 8,
      channelCount: 8,
      selectedChannel: 8,
    });
    expect(adapter.previewSource.getLatest()).toMatchObject({
      encoding: "sampled_extrema_preview_v1",
      aggregation: "sampled_candidates",
      signalKind: "lfp",
      podKey: "MOCK-AGG-POD-01",
      windowSeconds: 5,
      inputChannelCount: 32,
      channelStart: 8,
      channelCount: 8,
      containsContinuousRawSamples: false,
      containsEventWaveformSnippets: false,
      valueUnit: "microvolt",
      valueUnitScope: "mock",
      previewFreshness: "current",
      coverage: {
        source: "complete",
        analysis: "complete",
        sourceGapRanges: [],
        analysisGapRanges: [],
      },
      processing: { scope: "mock", filterProfileId: null, passbandHz: null },
    });
    expect((await adapter.readSnapshot()).lifecycle).toBe("recording");

    adapter.previewSource.setRequest({
      podKey: "MOCK-DIRECT-01",
      signalKind: "spike",
      windowSeconds: 2,
      channelStart: 0,
      channelCount: 8,
      selectedChannel: 0,
    });
    const spike = adapter.previewSource.getLatest();
    expect(spike).toMatchObject({
      encoding: "spike_preview_v3",
      signalKind: "spike",
      podKey: "MOCK-DIRECT-01",
      windowSeconds: 2,
      inputChannelCount: 32,
      channelStart: 0,
      channelCount: 8,
      containsContinuousRawSamples: false,
      containsEventWaveformSnippets: true,
      sorting: "unsorted",
      selectedChannel: 0,
      accounting: {
        selectionPolicy: "channel_stratified_rotating_v1",
        maxReturnedEvents: 64,
      },
    });
    if (spike?.encoding !== "spike_preview_v3") throw new Error("expected spike preview frame");
    expect(spike.channelActivity).toHaveLength(32);
    expect(spike.channelActivity.map((channel) => channel.channel)).toEqual(
      Array.from({ length: 32 }, (_, channel) => channel),
    );
    expect(spike.channelActivity.every((channel) => channel.recentWaveforms.length <= 3)).toBe(true);
    expect(spike.channelActivity.every((channel) => channel.recentWaveforms.every(
      (waveform) => waveform.length === 11,
    ))).toBe(true);
    expect(spike.podObservedEventCount).toBe(
      spike.channelActivity.reduce((sum, channel) => sum + channel.observedEventCount, 0),
    );
    expect(spike.accounting.observedEventCount).toBe(
      spike.channelActivity.slice(0, 8).reduce((sum, channel) => sum + channel.observedEventCount, 0),
    );
    expect(spike.accounting.observedEventCount).toBe(
      spike.accounting.rasterCandidateEventCount,
    );
    expect(spike.accounting.rasterCandidateEventCount).toBe(
      spike.accounting.sampledOutEventCount + spike.accounting.returnedRasterEventCount,
    );
    expect(spike.accounting.returnedRasterEventCount).toBe(spike.raster.length);
    expect(spike.accounting).not.toHaveProperty("detectorOverflowEventCount");
    expect(spike.accounting).not.toHaveProperty("transportDroppedEventCount");
    expect(spike).not.toHaveProperty("displayDrops");
    expect(spike.coverage).toEqual({
      source: "complete",
      analysis: "complete",
      sourceGapRanges: [],
      analysisGapRanges: [],
    });
    expect(spike.accounting.sampledOutEventCount).toBeGreaterThan(0);
    expect(spike.raster.length).toBeLessThanOrEqual(spike.accounting.maxReturnedEvents);
    expect(new Set(spike.raster.map((event) => event.eventId)).size).toBe(spike.raster.length);
    expect(spike.raster.every((event) => event.channel >= 0 && event.channel < 8)).toBe(true);
    expect(spike.raster.every((event) => event.eventOffsetMs >= 0 && event.eventOffsetMs < 2_000)).toBe(true);
    const activeBankChannels = spike.channelActivity
      .slice(0, 8)
      .filter((channel) => channel.observedEventCount > 0)
      .map((channel) => channel.channel);
    expect(new Set(spike.raster.map((event) => event.channel))).toEqual(new Set(activeBankChannels));
    const waveformWindow = spike.selectedChannelWaveforms;
    expect(waveformWindow).toMatchObject({
      retentionSamples: 60_000n,
      coverage: "complete",
      reasonCode: null,
      observedEventCount: spike.channelActivity[0].observedEventCount,
      returnedEventCount: spike.channelActivity[0].observedEventCount,
    });
    expect(waveformWindow.events).toHaveLength(waveformWindow.returnedEventCount);
    expect(new Set(waveformWindow.events.map((event) => event.eventId)).size)
      .toBe(waveformWindow.events.length);
    for (const event of waveformWindow.events) {
      expect(event.channel).toBe(0);
      expect(event.centerSample).toBeGreaterThanOrEqual(spike.sourceSampleStart!);
      expect(event.centerSample).toBeLessThan(spike.sourceSampleEndExclusive!);
      expect(event.eventId.endsWith(`-${event.centerSample}`)).toBe(true);
      expect(event.snippetSampleStart).toBe(event.centerSample - 5n);
      expect(event.snippetSampleEndExclusive).toBe(event.centerSample + 6n);
      expect(event.snippetSampleEndExclusive - event.snippetSampleStart).toBe(11n);
      expect(event.preTriggerSamples).toBe(5);
      expect(event.values).toHaveLength(11);
    }
    const waveformStats = spike.selectedChannelWaveformStats;
    expect(waveformStats?.channel).toBe(0);
    expect(waveformStats?.thresholdValue).toBeNull();
    expect(waveformStats?.contributingWaveformCount).toBe(waveformWindow.returnedEventCount);
    expect(waveformStats?.meanValues).toHaveLength(11);
    expect(waveformStats?.p10Values).toHaveLength(11);
    expect(waveformStats?.p90Values).toHaveLength(11);
    expect(waveformStats?.meanValues.every((value, index) =>
      (waveformStats.p10Values[index] ?? Number.POSITIVE_INFINITY) <= value
      && value <= (waveformStats.p90Values[index] ?? Number.NEGATIVE_INFINITY))).toBe(true);
    waveformStats?.meanValues.forEach((value, point) => {
      expect(value).toBeCloseTo(waveformWindow.events.reduce(
        (sum, event) => sum + (event.values[point] ?? 0),
        0,
      ) / waveformWindow.events.length, 12);
    });
    expect((await adapter.readSnapshot()).lifecycle).toBe("recording");

    await adapter.faultController.inject({ type: "counter_gap", missingSamples: 17 });
    snapshot = await adapter.readSnapshot();
    expect(snapshot.lifecycle).toBe("recovery_required");
    expect(snapshot.evidence.acquisition.status).toBe("failed");
    expect(snapshot.evidence.analysis.status).toBe("failed");
    expect(snapshot.runReceipt?.status).toBe("recovery_required");
    const gap = snapshot.faults.find((fault) => fault.code === "counter_gap");
    expect(gap).toMatchObject({ latched: true, recoverable: false });
    if (gap?.sampleStart === null || gap?.sampleStart === undefined
      || gap.sampleEndExclusive === null) throw new Error("counter gap omitted sample range");
    expect(gap.sampleEndExclusive - gap.sampleStart).toBe(17n);

    expect(snapshot.previewState).toBe("fault");
    expect((await adapter.execute({
      type: "start_preview",
      podKey: "MOCK-DIRECT-01",
      topologyEvidenceHash: snapshot.topology.evidenceHash,
    })).accepted).toBe(true);
    await vi.advanceTimersByTimeAsync(TRANSITION_MS * 2);
    expect(await adapter.readSnapshot()).toMatchObject({
      lifecycle: "recovery_required",
      previewState: "live",
      faults: [{ code: "counter_gap", latched: true }],
    });

    expect(await adapter.execute({ type: "stop_recording" })).toMatchObject({ accepted: false });
    expect(await adapter.execute({ type: "recover_run" })).toMatchObject({
      accepted: false,
      reasonCode: "RECOVERY_BLOCKED",
    });
    await adapter.faultController.clear("counter_gap");
    expect((await adapter.readSnapshot()).faults.find((fault) => fault.code === "counter_gap")?.latched)
      .toBe(true);
    await accept({ type: "acknowledge_failed_run" }, 1);
    expect((await adapter.readSnapshot()).lifecycle).toBe("connected_idle");
  });

  it("binds all three views to one source range, scenario hash, and event truth", async () => {
    await reachRecording();
    const model = new SyntheticNeuralModel({ seed: SYNTHETIC_DEFAULT_SEED });
    const request = {
      podKey: "MOCK-DIRECT-01",
      windowSeconds: 1,
      channelStart: 0,
      channelCount: 8,
      selectedChannel: 0,
    } as const;
    const frames = [] as NonNullable<ReturnType<typeof adapter.previewSource.getLatest>>[];
    for (const signalKind of ["wideband", "lfp", "spike"] as const) {
      adapter.previewSource.setRequest({ ...request, signalKind });
      const frame = adapter.previewSource.getLatest();
      if (frame === null) throw new Error(`missing ${signalKind} frame`);
      frames.push(frame);
      await vi.advanceTimersByTimeAsync(1);
    }

    expect(new Set(frames.map((frame) => frame.sourceSampleStart?.toString()))).toEqual(
      new Set([frames[0].sourceSampleStart?.toString()]),
    );
    expect(new Set(frames.map((frame) => frame.sourceSampleEndExclusive?.toString()))).toEqual(
      new Set([frames[0].sourceSampleEndExclusive?.toString()]),
    );
    expect(frames[0].sourceSampleEndExclusive! - frames[0].sourceSampleStart!).toBe(30_000n);
    expect(new Set(frames.map((frame) => frame.inputEvidenceHash))).toEqual(
      new Set([model.inputConfigurationHash(32, "MOCK-LINEAR-32")]),
    );
    expect(new Set(frames.map((frame) => frame.valueEvidenceHash))).toEqual(
      new Set([model.inputConfigurationHash(32, "MOCK-LINEAR-32")]),
    );
    expect(new Set(frames.map((frame) => frame.processing.evidenceHash))).toEqual(
      new Set([model.scenarioHash]),
    );
    const topologyInput = (await adapter.readSnapshot()).topology.directPods[0].neuralInput;
    expect(topologyInput?.configHash).toBe(model.inputConfigurationHash(32, "MOCK-LINEAR-32"));
    expect(topologyInput?.evidenceHash).toBe(model.inputConfigurationHash(32, "MOCK-LINEAR-32"));

    const spike = frames[2];
    if (spike.encoding !== "spike_preview_v3") throw new Error("expected spike frame");
    const centers = [...model.eventCentersInRange(
      0,
      spike.sourceSampleStart!,
      spike.sourceSampleEndExclusive!,
    )];
    const expectedWaveforms = centers.map((center) => model.waveformAtEvent(0, center));
    const expectedMean = Array.from({ length: 11 }, (_, point) => expectedWaveforms.reduce(
      (sum, waveform) => sum + (waveform[point] ?? 0),
      0,
    ) / expectedWaveforms.length * SYNTHETIC_PREVIEW_MICROVOLTS_PER_COUNT);
    expect(spike.selectedChannelWaveforms.coverage).toBe("complete");
    expect(spike.selectedChannelWaveforms.observedEventCount).toBe(centers.length);
    expect(spike.selectedChannelWaveforms.returnedEventCount).toBe(centers.length);
    expect(spike.selectedChannelWaveforms.events.map((event) => event.centerSample)).toEqual(centers);
    expect(spike.selectedChannelWaveforms.events.map((event) => event.values)).toEqual(
      expectedWaveforms.map((waveform) => waveform.map(
        (value) => value * SYNTHETIC_PREVIEW_MICROVOLTS_PER_COUNT,
      )),
    );
    expect(spike.selectedChannelWaveformStats?.contributingWaveformCount).toBe(centers.length);
    spike.selectedChannelWaveformStats?.meanValues.forEach((value, point) => {
      expect(value).toBeCloseTo(expectedMean[point] ?? Number.NaN, 12);
    });
    for (const event of spike.raster) {
      const centerText = event.eventId.split("-").at(-1);
      if (centerText === undefined) throw new Error("event id omitted its absolute sample");
      const center = BigInt(centerText);
      expect(event.peakValue).toBe(
        model.sampleAt(center, event.channel).wideband
          * SYNTHETIC_PREVIEW_MICROVOLTS_PER_COUNT,
      );
      expect(event.eventOffsetMs).toBe(
        Number(center - spike.sourceSampleStart!) * 1_000 / 30_000,
      );
    }

    const forbiddenRawKeys = new Set(["rawSamples", "sampleValues", "continuousSamples"]);
    const visit = (value: unknown): void => {
      if (Array.isArray(value)) {
        value.forEach(visit);
      } else if (value !== null && typeof value === "object") {
        for (const [key, child] of Object.entries(value)) {
          expect(forbiddenRawKeys.has(key)).toBe(false);
          visit(child);
        }
      }
    };
    for (const frame of frames) {
      expect(frame).toMatchObject({
        synthetic: true,
        containsContinuousRawSamples: false,
        containsEventWaveformSnippets: frame.encoding === "spike_preview_v3",
      });
      visit(frame);
    }
  });

  it("authors an explicitly NWB-derived 128-channel browser demo without changing canonical defaults", async () => {
    const model = new NwbDerivedDemoModel();
    const derived = new MockAcquireAdapter({
      connectedPodCount: 1,
      transitionDelayMs: TRANSITION_MS,
      previewIntervalMs: 1_000,
      previewModel: model,
      now: () => 508_000,
    });
    try {
      await derived.execute({ type: "connect" });
      await vi.advanceTimersByTimeAsync(TRANSITION_MS);
      const connected = await derived.readSnapshot();
      const input = connected.topology.directPods[0]?.neuralInput;
      expect(input).toMatchObject({
        neuralChannelCount: 128,
        sampleRateHz: 30_000,
        sourceEncoding: "nwb_waveform_reconstruction",
        previewValueUnit: "microvolt",
        microvoltsPerCount: 0.125,
        reasonCode: "NWB_WAVEFORM_RECONSTRUCTION_UNITS",
      });
      derived.previewSource.setRequest({
        podKey: "MOCK-DIRECT-01",
        signalKind: "spike",
        windowSeconds: 1,
        channelStart: 0,
        channelCount: 8,
        selectedChannel: 2,
      });
      await derived.execute({
        type: "start_preview",
        podKey: "MOCK-DIRECT-01",
        topologyEvidenceHash: connected.topology.evidenceHash,
      });
      await vi.advanceTimersByTimeAsync(TRANSITION_MS * 2);
      const frame = derived.previewSource.getLatest();
      if (frame?.encoding !== "spike_preview_v3") throw new Error("expected NWB spike preview");
      expect(frame).toMatchObject({
        inputChannelCount: 128,
        valueUnitReasonCode: "NWB_WAVEFORM_RECONSTRUCTION_UNITS",
        waveformSampleRateHz: 30_000,
        processing: {
          algorithmId: "forge.mock.nwb-derived-spike-preview.v1",
          configHash: model.scenarioHash,
        },
      });
      expect(frame.channelActivity).toHaveLength(128);
      expect(frame.selectedChannelWaveforms.events.every((event) => event.values.length === 32)).toBe(true);
    } finally {
      derived.dispose();
    }
  });

  it("keeps 1/2/5 second source spans and late channel banks explicit", async () => {
    await reachRecording();
    const observed: number[] = [];
    for (const windowSeconds of [1, 2, 5]) {
      adapter.previewSource.setRequest({
        podKey: "MOCK-DIRECT-01",
        signalKind: "spike",
        windowSeconds,
        channelStart: 24,
        channelCount: 8,
        selectedChannel: 31,
      });
      const frame = adapter.previewSource.getLatest();
      if (frame?.encoding !== "spike_preview_v3") throw new Error("expected spike preview frame");
      expect(frame.channelStart).toBe(24);
      expect(frame.channelCount).toBe(8);
      expect(frame.raster.every((event) => event.channel >= 24 && event.channel <= 31)).toBe(true);
      expect(frame.selectedChannel).toBe(31);
      expect(frame.selectedChannelWaveforms.coverage).toBe("complete");
      expect(frame.selectedChannelWaveforms.retentionSamples).toBe(
        BigInt(30_000 * windowSeconds),
      );
      expect(frame.selectedChannelWaveforms.returnedEventCount).toBe(
        frame.selectedChannelWaveforms.observedEventCount,
      );
      expect(frame.selectedChannelWaveforms.events.every((event) => event.channel === 31)).toBe(true);
      expect(frame.selectedChannelWaveformStats?.channel).toBe(31);
      expect(frame.selectedChannelWaveformStats?.contributingWaveformCount).toBe(
        frame.selectedChannelWaveforms.returnedEventCount,
      );
      expect(frame.sourceSampleEndExclusive! - frame.sourceSampleStart!).toBe(
        BigInt(30_000 * windowSeconds),
      );
      observed.push(frame.podObservedEventCount);
    }
    expect(observed[0]).toBeLessThan(observed[1]);
    expect(observed[1]).toBeLessThan(observed[2]);
    expect((await adapter.readSnapshot()).lifecycle).toBe("recording");
  });

  it("returns all 100 selected-channel waveforms in a 10 s rolling window and keeps overlap IDs stable", async () => {
    await reachRecording();
    adapter.previewSource.setRequest({
      podKey: "MOCK-DIRECT-01",
      signalKind: "spike",
      windowSeconds: 10,
      channelStart: 24,
      channelCount: 8,
      selectedChannel: 31,
    });
    const first = adapter.previewSource.getLatest();
    if (first?.encoding !== "spike_preview_v3") throw new Error("expected first spike preview frame");

    expect(first.inputChannelCount).toBe(32);
    expect(first.selectedChannel).toBe(31);
    expect(first.containsContinuousRawSamples).toBe(false);
    expect(first.containsEventWaveformSnippets).toBe(true);
    expect(first.accounting.maxReturnedEvents).toBe(64);
    expect(first.raster.length).toBeLessThanOrEqual(64);
    expect(first.selectedChannelWaveforms).toMatchObject({
      retentionSamples: 300_000n,
      coverage: "complete",
      reasonCode: null,
      observedEventCount: 100,
      returnedEventCount: 100,
    });
    expect(first.selectedChannelWaveforms.events).toHaveLength(100);
    expect(first.selectedChannelWaveforms.returnedEventCount).toBeGreaterThan(
      first.accounting.maxReturnedEvents,
    );

    const firstIds = new Set(first.selectedChannelWaveforms.events.map((event) => event.eventId));
    expect(firstIds.size).toBe(100);
    for (const event of first.selectedChannelWaveforms.events) {
      expect(event.channel).toBe(31);
      expect(event.eventId.endsWith(`-${event.centerSample}`)).toBe(true);
      expect(event.centerSample).toBeGreaterThanOrEqual(first.sourceSampleStart!);
      expect(event.centerSample).toBeLessThan(first.sourceSampleEndExclusive!);
      expect(event.snippetSampleStart).toBe(event.centerSample - BigInt(event.preTriggerSamples));
      expect(event.snippetSampleEndExclusive - event.snippetSampleStart).toBe(
        BigInt(event.values.length),
      );
    }

    const stats = first.selectedChannelWaveformStats;
    if (stats === null) throw new Error("selected-channel waveform statistics missing");
    expect(stats).toMatchObject({
      channel: 31,
      contributingWaveformCount: 100,
    });
    stats.meanValues.forEach((mean, point) => {
      const values = first.selectedChannelWaveforms.events
        .map((event) => event.values[point] ?? 0)
        .sort((left, right) => left - right);
      expect(mean).toBeCloseTo(
        values.reduce((sum, value) => sum + value, 0) / values.length,
        12,
      );
      expect(stats.p10Values[point]).toBe(values[Math.floor((values.length - 1) * 0.1)]);
      expect(stats.p90Values[point]).toBe(values[Math.floor((values.length - 1) * 0.9)]);
    });

    await vi.advanceTimersByTimeAsync(11_000);
    const second = adapter.previewSource.getLatest();
    if (second?.encoding !== "spike_preview_v3") throw new Error("expected second spike preview frame");
    expect(second.sequence).toBeGreaterThan(first.sequence);
    expect(second.selectedChannelWaveforms).toMatchObject({
      coverage: "complete",
      observedEventCount: 100,
      returnedEventCount: 100,
      retentionSamples: 300_000n,
    });
    const secondIds = new Set(second.selectedChannelWaveforms.events.map((event) => event.eventId));
    const overlappingIds = [...firstIds].filter((eventId) => secondIds.has(eventId));
    const expectedOverlap = [...new SyntheticNeuralModel({ seed: SYNTHETIC_DEFAULT_SEED })
      .eventCentersInRange(
        31,
        first.sourceSampleStart! > second.sourceSampleStart!
          ? first.sourceSampleStart!
          : second.sourceSampleStart!,
        first.sourceSampleEndExclusive! < second.sourceSampleEndExclusive!
          ? first.sourceSampleEndExclusive!
          : second.sourceSampleEndExclusive!,
      )];
    expect(overlappingIds).toHaveLength(expectedOverlap.length);
    expect(overlappingIds.length).toBeGreaterThan(0);
    expect(overlappingIds.length).toBeLessThan(100);
    for (const eventId of overlappingIds) {
      const previous = first.selectedChannelWaveforms.events.find((event) => event.eventId === eventId);
      const current = second.selectedChannelWaveforms.events.find((event) => event.eventId === eventId);
      expect(current?.centerSample).toBe(previous?.centerSample);
      expect(current?.values).toEqual(previous?.values);
    }
  });

  it("keeps the preview bounded for a 128-channel fixture", async () => {
    const large = new MockAcquireAdapter({
      transitionDelayMs: TRANSITION_MS,
      previewIntervalMs: 1_000,
      connectedPodCount: 1,
      neuralChannelCount: 128,
    });
    try {
      await large.execute({ type: "connect" });
      await vi.advanceTimersByTimeAsync(TRANSITION_MS);
      const topology = await large.readSnapshot();
      await large.execute({
        type: "start_preview",
        podKey: "MOCK-DIRECT-01",
        topologyEvidenceHash: topology.topology.evidenceHash,
      });
      await vi.advanceTimersByTimeAsync(TRANSITION_MS * 2);
      const plan: RunPlan = {
        label: "128-channel fixture",
        plannedDurationSeconds: 60,
        selectedDevices: [{
          podKey: "MOCK-DIRECT-01",
          deviceId: topology.topology.directPods[0].identity.deviceId,
          identityEvidenceHash: topology.topology.directPods[0].identity.identityEvidenceHash!,
          inputEvidenceHash: topology.topology.directPods[0].neuralInput!.evidenceHash!,
        }],
        topologyEvidenceHash: topology.topology.evidenceHash,
        recordingTarget: { ...RECORDING_TARGET, baseName: "FORGE-TEST-128" },
      };
      await large.execute({ type: "preflight", plan });
      await vi.advanceTimersByTimeAsync(TRANSITION_MS * 2);
      await large.execute({ type: "arm_recording" });
      await vi.advanceTimersByTimeAsync(TRANSITION_MS * 2);
      await large.execute({ type: "start_recording" });
      await vi.advanceTimersByTimeAsync(TRANSITION_MS * 2);

      large.previewSource.setRequest({
        podKey: "MOCK-DIRECT-01",
        signalKind: "spike",
        windowSeconds: 5,
        channelStart: 120,
        channelCount: 8,
        selectedChannel: 127,
      });
      const frame = large.previewSource.getLatest();
      if (frame?.encoding !== "spike_preview_v3") throw new Error("expected spike preview frame");
      expect(frame.inputChannelCount).toBe(128);
      expect(frame.channelActivity).toHaveLength(128);
      expect(frame.channelActivity.at(-1)?.channel).toBe(127);
      expect(frame.raster.length).toBeLessThanOrEqual(64);
      expect(frame.raster.every((event) => event.channel >= 120 && event.channel <= 127)).toBe(true);
      expect(frame.selectedChannel).toBe(127);
      expect(frame.selectedChannelWaveforms).toMatchObject({
        retentionSamples: 150_000n,
        coverage: "complete",
        reasonCode: null,
        observedEventCount: frame.channelActivity[127].observedEventCount,
        returnedEventCount: frame.channelActivity[127].observedEventCount,
      });
      expect(frame.selectedChannelWaveforms.events).toHaveLength(
        frame.channelActivity[127].observedEventCount,
      );
      expect(frame.selectedChannelWaveforms.events.every((event) => event.channel === 127)).toBe(true);
      expect(frame.selectedChannelWaveformStats).toMatchObject({
        channel: 127,
        contributingWaveformCount: frame.channelActivity[127].observedEventCount,
      });
      expect((await large.readSnapshot()).lifecycle).toBe("recording");
    } finally {
      large.dispose();
    }
  });
});
