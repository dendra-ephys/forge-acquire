import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DaemonSnapshotV1 } from "../core/daemon";

const software = vi.hoisted(() => ({
  launchSoftwareReplay: vi.fn(),
  readSoftwareReplaySnapshot: vi.fn(),
  sendSoftwareReplayRunCommand: vi.fn(),
}));
vi.mock("../core/softwareDaemon", () => software);

import { SoftwareAcquireAdapter } from "./softwareAcquireAdapter";

const TRANSITION_MS = 5;

function daemon(state: DaemonSnapshotV1["state"], requestId: number, epoch: number): DaemonSnapshotV1 {
  const sealed = state === "journal_sealed";
  const recording = state === "recording";
  const failed = state === "failed";
  const generated = failed ? 10n : sealed ? 8n : recording ? 3n : null;
  const committed = failed ? 9n : generated;
  const durable = failed ? 8n : sealed ? committed : recording ? 0n : null;
  return {
    state,
    accepted: true,
    retryable: false,
    poisoned: false,
    auto_failed_on_restart: false,
    hardware_transport_available: false,
    authenticated_pipe: true,
    scm_owned: false,
    protected_replay_available: true,
    request_id: BigInt(requestId),
    epoch: BigInt(epoch),
    ledger_events: BigInt(requestId),
    active_run_id: sealed ? Array(16).fill(0) : Array(16).fill(0x11),
    latest_published_run_id: Array(16).fill(0),
    receipt_hash: Array(32).fill(requestId & 0xff),
    committed_record_count: committed,
    durable_record_count: durable,
    expected_last_journal_sequence: committed === null ? null : committed - 1n,
    queue_used_slots: recording ? 1n : 0n,
    queue_capacity_slots: 64n,
    generated_record_count: generated,
    active_epoch: sealed ? null : BigInt(epoch),
    highest_epoch: BigInt(epoch),
    active_target_device_id: sealed ? Array(16).fill(0) : Array(16).fill(0x44),
    active_frozen_config_hash: sealed ? Array(32).fill(0) : Array(32).fill(0x55),
    latest_sealed_run_id: sealed ? Array(16).fill(0x11) : Array(16).fill(0),
    error: "none",
    reason: state,
  };
}

describe("SoftwareAcquireAdapter", () => {
  let adapter: SoftwareAcquireAdapter;
  let currentState: DaemonSnapshotV1["state"];

  beforeEach(() => {
    vi.useFakeTimers();
    software.launchSoftwareReplay.mockReset();
    software.readSoftwareReplaySnapshot.mockReset();
    software.sendSoftwareReplayRunCommand.mockReset();
    vi.stubGlobal("crypto", {
      getRandomValues(values: Uint8Array) {
        values.fill(0x11);
        return values;
      },
      subtle: {
        digest: async () => Uint8Array.from({ length: 32 }, () => 0x55).buffer,
      },
    });
    currentState = "new";
    software.launchSoftwareReplay.mockResolvedValue({
      schema: "forge.software-replay-reservation.v1",
      reservationId: "SOFTWARE-RES-001",
      runIdHex: "11".repeat(16),
      pipeName: "\\\\.\\pipe\\forge-acqd-software-replay-test",
      requestedDirectory: "F:\\ForgeRuns",
      allocatedLeafName: "FORGE-RUN-001",
      resolvedRunDirectory: "F:\\ForgeRuns\\FORGE-RUN-001",
      journalFileName: "run.forgewal",
      selectedDeviceIds: ["MOCK-DEVICE-POD-1"],
      directoryCreateDisposition: "created_new",
      journalCreateDisposition: "not_created",
      overwritePolicy: "forbid",
      scope: "software",
      synthetic: true,
      processId: 4242,
      evidenceHash: "22".repeat(32),
    });
    software.sendSoftwareReplayRunCommand.mockImplementation(
      async (_pipe: string, command: number, context: { epoch: number }, requestId: number) => {
        currentState = command === 1 ? "prepared"
          : command === 2 ? "armed"
            : command === 3 ? "recording"
              : command === 4 ? "journal_sealed"
                : command === 5 ? "aborted"
                  : command === 7 ? "new" : "new";
        return { available: true, reason: currentState, snapshot: daemon(currentState, requestId, context.epoch) };
      },
    );
    software.readSoftwareReplaySnapshot.mockImplementation(
      async (_pipe: string, requestId: number, epoch: number) => ({
        available: true,
        reason: currentState,
        snapshot: daemon(currentState, requestId, epoch),
      }),
    );
    adapter = new SoftwareAcquireAdapter({
      transitionDelayMs: TRANSITION_MS,
      previewIntervalMs: 1_000,
      pollIntervalMs: 10_000,
      connectedPodCount: 4,
    });
  });

  afterEach(() => {
    adapter.dispose();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  async function settle(steps: number): Promise<void> {
    await vi.advanceTimersByTimeAsync(TRANSITION_MS * steps);
  }

  it("keeps Preview mock-bounded but binds Recording to a real create-new software journal", async () => {
    expect((await adapter.execute({ type: "connect" })).accepted).toBe(true);
    await settle(1);
    const connected = await adapter.readSnapshot();
    expect((await adapter.execute({
      type: "start_preview",
      podKey: "MOCK-DIRECT-01",
      topologyEvidenceHash: connected.topology.evidenceHash,
    })).accepted).toBe(true);
    await settle(2);

    const preview = await adapter.readSnapshot();
    const pod = preview.topology.directPods[0];
    const plan = {
      label: "FORGE-RUN",
      plannedDurationSeconds: 60,
      selectedDevices: [{
        podKey: pod.key,
        deviceId: pod.identity.deviceId,
        identityEvidenceHash: pod.identity.identityEvidenceHash!,
        inputEvidenceHash: pod.neuralInput!.evidenceHash!,
      }],
      topologyEvidenceHash: preview.topology.evidenceHash,
      recordingTarget: {
        requestedDirectory: "F:\\ForgeRuns",
        baseName: "FORGE-RUN",
        allocationPolicy: "create_new_incrementing_suffix" as const,
        overwritePolicy: "forbid" as const,
      },
    };
    const preflight = await adapter.execute({ type: "preflight", plan });
    expect(preflight).toMatchObject({ accepted: true, scope: "software", runId: "11".repeat(16) });
    await settle(2);
    expect(await adapter.readSnapshot()).toMatchObject({
      lifecycle: "preflight_passed",
      scope: "software",
      recordingTarget: {
        resolvedRunDirectory: "F:\\ForgeRuns\\FORGE-RUN-001",
        directoryCreateDisposition: "created_new",
        journalCreateDisposition: "created_new",
        overwritePolicy: "forbid",
      },
    });

    expect((await adapter.execute({ type: "arm_recording" })).accepted).toBe(true);
    await settle(2);
    expect((await adapter.execute({ type: "stop_preview", reason: "operator" })).accepted).toBe(true);
    await settle(2);
    expect(await adapter.readSnapshot()).toMatchObject({ lifecycle: "armed", previewState: "stopped" });
    expect((await adapter.execute({ type: "start_recording" })).accepted).toBe(true);
    await settle(2);
    let snapshot = await adapter.readSnapshot();
    expect(snapshot).toMatchObject({
      lifecycle: "recording",
      previewState: "stopped",
      evidence: { acquisition: { status: "active" }, durability: { status: "active" } },
    });
    expect((await adapter.execute({
      type: "start_preview",
      podKey: "MOCK-DIRECT-01",
      topologyEvidenceHash: snapshot.topology.evidenceHash,
    })).accepted).toBe(true);
    await settle(2);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(adapter.previewSource.getLatest()).toMatchObject({ runId: "11".repeat(16) });

    software.readSoftwareReplaySnapshot.mockRejectedValueOnce(new Error("transient pipe loss"));
    await vi.advanceTimersByTimeAsync(10_000);
    snapshot = await adapter.readSnapshot();
    expect(snapshot).toMatchObject({
      lifecycle: "recording",
      controlConnection: "lost",
      stale: true,
      evidence: {
        acquisition: { status: "active" },
        durability: { status: "active" },
      },
      runReceipt: { status: "active", lifecycle: "recording" },
    });
    expect(snapshot.faults).not.toContainEqual(expect.objectContaining({ code: "recording_pipeline_failure" }));

    let rejectLatePoll: ((reason?: unknown) => void) | undefined;
    software.readSoftwareReplaySnapshot.mockImplementationOnce(() => new Promise((_resolve, reject) => {
      rejectLatePoll = reject;
    }));
    vi.advanceTimersByTime(10_000);
    await Promise.resolve();
    expect(rejectLatePoll).toBeTypeOf("function");

    const stop = await adapter.execute({ type: "stop_recording", reason: "operator" });
    expect(stop.message).toContain("durability barrier");
    rejectLatePoll?.(new Error("expected pipe close after terminal FACK"));
    await Promise.resolve();
    await settle(4);
    snapshot = await adapter.readSnapshot();
    expect(snapshot).toMatchObject({
      lifecycle: "finalized",
      previewState: "live",
      evidence: {
        acquisition: { status: "proven", scope: "software" },
        durability: { status: "proven", scope: "software" },
        nwb: { status: "unavailable" },
        analysis: { status: "unavailable" },
        stimReceipt: { status: "unavailable" },
      },
      runReceipt: { status: "raw_sealed", lifecycle: "finalized", scope: "software" },
    });
    expect(adapter.previewSource.getLatest()).toMatchObject({ runId: null, runEpoch: null });
    expect(software.sendSoftwareReplayRunCommand).toHaveBeenCalledWith(
      expect.any(String),
      4,
      expect.any(Object),
      expect.any(Number),
    );
  });

  it("does not create a Run directory for an invalid multi-device plan", async () => {
    await adapter.execute({ type: "connect" });
    await settle(1);
    const receipt = await adapter.execute({
      type: "preflight",
      plan: {
        label: "FORGE-RUN",
        plannedDurationSeconds: 60,
        selectedDevices: [],
        topologyEvidenceHash: "invalid",
        recordingTarget: {
          requestedDirectory: "F:\\ForgeRuns",
          baseName: "FORGE-RUN",
          allocationPolicy: "create_new_incrementing_suffix",
          overwritePolicy: "forbid",
        },
      },
    });
    expect(receipt).toMatchObject({ accepted: false, reasonCode: "INVALID_PLAN" });
    expect(software.launchSoftwareReplay).not.toHaveBeenCalled();
  });

  it("reports exact unsealed failure counts and closes only after daemon failure acknowledgement", async () => {
    await adapter.execute({ type: "connect" });
    await settle(1);
    let snapshot = await adapter.readSnapshot();
    await adapter.execute({
      type: "start_preview",
      podKey: "MOCK-DIRECT-01",
      topologyEvidenceHash: snapshot.topology.evidenceHash,
    });
    await settle(2);
    snapshot = await adapter.readSnapshot();
    const pod = snapshot.topology.directPods[0];
    const plan = {
      label: "FORGE-FAILED-RUN",
      plannedDurationSeconds: 60,
      selectedDevices: [{
        podKey: pod.key,
        deviceId: pod.identity.deviceId,
        identityEvidenceHash: pod.identity.identityEvidenceHash!,
        inputEvidenceHash: pod.neuralInput!.evidenceHash!,
      }],
      topologyEvidenceHash: snapshot.topology.evidenceHash,
      recordingTarget: {
        requestedDirectory: "F:\\ForgeRuns",
        baseName: "FORGE-FAILED-RUN",
        allocationPolicy: "create_new_incrementing_suffix" as const,
        overwritePolicy: "forbid" as const,
      },
    };
    expect((await adapter.execute({ type: "preflight", plan })).accepted).toBe(true);
    await settle(2);
    expect((await adapter.execute({ type: "arm_recording" })).accepted).toBe(true);
    await settle(2);
    expect((await adapter.execute({ type: "start_recording" })).accepted).toBe(true);
    await settle(2);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(adapter.previewSource.getLatest()).toMatchObject({ runId: "11".repeat(16) });

    currentState = "failed";
    await vi.advanceTimersByTimeAsync(10_000);
    snapshot = await adapter.readSnapshot();
    expect(snapshot).toMatchObject({
      lifecycle: "recovery_required",
      controlConnection: "connected",
      stale: false,
      evidence: {
        acquisition: { status: "failed" },
        durability: { status: "failed" },
      },
      faults: [{ code: "recording_pipeline_failure", recoverable: false, latched: true }],
      runReceipt: { status: "recovery_required" },
    });
    expect(snapshot.evidence.acquisition.summary).toContain("generated 10 / committed 9 / durable 8");
    expect(snapshot.evidence.durability.summary).toContain("未封存");
    expect(snapshot.evidence.durability.summary).toContain("Partial journal");

    software.sendSoftwareReplayRunCommand.mockImplementationOnce(
      async (_pipe: string, _command: number, context: { epoch: number }, requestId: number) => ({
        available: true,
        reason: "failure acknowledgement rejected",
        snapshot: {
          ...daemon("failed", requestId, context.epoch),
          accepted: false,
          reason: "failure acknowledgement rejected",
        },
      }),
    );
    expect(await adapter.execute({ type: "acknowledge_failed_run" })).toMatchObject({
      accepted: false,
      reasonCode: "FAILURE_ACK_NOT_PROVEN",
    });
    expect(await adapter.readSnapshot()).toMatchObject({
      lifecycle: "recovery_required",
      runId: "11".repeat(16),
      recordingTarget: { resolvedRunDirectory: "F:\\ForgeRuns\\FORGE-RUN-001" },
    });

    const acknowledge = await adapter.execute({ type: "acknowledge_failed_run" });
    expect(acknowledge).toMatchObject({ accepted: true, intent: "acknowledge_failed_run" });
    expect(acknowledge).toMatchObject({
      stateAtAcceptance: "recovery_required",
      requestedState: "connected_idle",
    });
    expect(acknowledge.message).toContain("partial journal 保留");
    expect(software.sendSoftwareReplayRunCommand).toHaveBeenLastCalledWith(
      expect.any(String),
      7,
      expect.any(Object),
      expect.any(Number),
    );
    expect(await adapter.readSnapshot()).toMatchObject({
      lifecycle: "connected_idle",
      previewState: "live",
      runId: null,
      recordingTarget: null,
      faults: [],
    });
    expect(adapter.previewSource.getLatest()).toMatchObject({ runId: null, runEpoch: null });

    expect((await adapter.execute({ type: "preflight", plan })).accepted).toBe(true);
  });
});
