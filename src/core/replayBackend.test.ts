import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  readDaemonSnapshot: vi.fn(),
  sendDaemonRunCommand: vi.fn(),
}));
vi.mock("./daemon", () => mocks);

import { ProtectedReplayBackend } from "./replayBackend";

function daemon(state: string, overrides: Record<string, unknown> = {}) {
  return {
    state,
    accepted: true,
    retryable: false,
    poisoned: false,
    auto_failed_on_restart: false,
    hardware_transport_available: false,
    authenticated_pipe: true,
    scm_owned: true,
    protected_replay_available: true,
    request_id: 1n,
    epoch: 1n,
    ledger_events: 0n,
    active_run_id: Array(16).fill(0),
    latest_published_run_id: Array(16).fill(0),
    receipt_hash: Array(32).fill(1),
    committed_record_count: null,
    durable_record_count: null,
    expected_last_journal_sequence: null,
    queue_used_slots: 0n,
    queue_capacity_slots: 4n,
    generated_record_count: null,
    active_epoch: null,
    highest_epoch: 0n,
    active_target_device_id: Array(16).fill(0),
    active_frozen_config_hash: Array(32).fill(0),
    latest_sealed_run_id: Array(16).fill(0),
    error: "none",
    reason: state,
    ...overrides,
  };
}

describe("ProtectedReplayBackend", () => {
  beforeEach(() => {
    mocks.readDaemonSnapshot.mockReset();
    mocks.sendDaemonRunCommand.mockReset();
  });

  it("runs Prepare Arm Start Stop and exposes only durable journal evidence", async () => {
    mocks.readDaemonSnapshot.mockResolvedValue({
      available: true,
      reason: "snapshot",
      snapshot: daemon("new"),
    });
    mocks.sendDaemonRunCommand.mockImplementation((command: number) => {
      const snapshot = command === 1
        ? daemon("prepared")
        : command === 2
          ? daemon("armed")
          : command === 3
            ? daemon("recording", {
              generated_record_count: 2n,
              committed_record_count: 2n,
              durable_record_count: 0n,
            })
            : daemon("journal_sealed", {
              generated_record_count: 3n,
              committed_record_count: 3n,
              durable_record_count: 3n,
              expected_last_journal_sequence: 2n,
            });
      return Promise.resolve({ available: true, reason: snapshot.reason, snapshot });
    });
    const backend = new ProtectedReplayBackend();
    await backend.connect();
    await backend.startRecording();
    expect(backend.getSnapshot().machine.writer).toBe("writing");
    expect(backend.getSnapshot().recordingPipeline.protectionVerified).toBe(false);
    await backend.stopRecording();
    const sealed = backend.getSnapshot();
    expect(sealed.machine.writer).toBe("finalized");
    expect(sealed.recordingPipeline.protectionVerified).toBe(true);
    expect(sealed.recordingPipeline.durableSequence).toBe(2);
    expect(sealed.isSynthetic).toBe(true);
    expect(mocks.sendDaemonRunCommand.mock.calls.map((call) => call[0])).toEqual([1, 2, 3, 4]);
    backend.disconnect();
  });

  it("refuses a daemon without the protected replay capability", async () => {
    mocks.readDaemonSnapshot.mockResolvedValue({
      available: true,
      reason: "snapshot",
      snapshot: daemon("new", { protected_replay_available: false }),
    });
    const backend = new ProtectedReplayBackend();
    await expect(backend.connect()).rejects.toThrow("capability is disabled");
    backend.disconnect();
  });

  it("restores a failed Run context and acknowledges it without erasing evidence", async () => {
    const failedContext = {
      active_epoch: 41n,
      highest_epoch: 41n,
      active_run_id: Array(16).fill(0x11),
      active_target_device_id: Array(16).fill(0x22),
      active_frozen_config_hash: Array(32).fill(0x33),
    };
    mocks.readDaemonSnapshot.mockResolvedValue({
      available: true,
      reason: "snapshot",
      snapshot: daemon("failed", failedContext),
    });
    mocks.sendDaemonRunCommand.mockImplementation((command: number) => Promise.resolve({
      available: true,
      reason: "failure acknowledged",
      snapshot: daemon("new", { highest_epoch: 41n, ledger_events: 8n }),
    }));
    const backend = new ProtectedReplayBackend();
    await backend.connect();
    expect(backend.getSnapshot().machine.runId).toBe("11".repeat(16));
    await backend.acknowledgeFailure();
    expect(mocks.sendDaemonRunCommand).toHaveBeenCalledWith(7, {
      epoch: 41,
      runIdHex: "11".repeat(16),
      targetDeviceIdHex: "22".repeat(16),
      frozenConfigHashHex: "33".repeat(32),
    });
    expect(backend.getSnapshot().machine.writer).toBe("disabled");
    expect(backend.getSnapshot().events.at(-1)?.code).toBe("REPLAY_FAILURE_ACKNOWLEDGED");
    backend.disconnect();
  });
});
