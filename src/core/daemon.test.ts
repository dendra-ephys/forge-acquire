import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { decodeDaemonSnapshotResult, readDaemonSnapshot } from "./daemon";

function snapshotRaw(requestId: number, overrides: Record<string, unknown> = {}) {
  return {
    state: "new",
    accepted: true,
    retryable: false,
    poisoned: false,
    auto_failed_on_restart: false,
    hardware_transport_available: false,
    authenticated_pipe: true,
    scm_owned: true,
    protected_replay_available: true,
    request_id: requestId.toString(),
    epoch: "1",
    ledger_events: "0",
    active_run_id: Array(16).fill(0),
    latest_published_run_id: Array(16).fill(0),
    receipt_hash: Array(32).fill(1),
    committed_record_count: null,
    durable_record_count: null,
    expected_last_journal_sequence: null,
    queue_used_slots: null,
    queue_capacity_slots: null,
    generated_record_count: null,
    active_epoch: null,
    highest_epoch: "0",
    active_target_device_id: Array(16).fill(0),
    active_frozen_config_hash: Array(32).fill(0),
    latest_sealed_run_id: Array(16).fill(0),
    error: "none",
    reason: "snapshot",
    ...overrides,
  };
}

describe("daemon snapshot adapter", () => {
  beforeEach(() => invoke.mockReset());

  it("accepts only the authenticated SCM read-only snapshot", async () => {
    invoke.mockResolvedValue({
      available: true,
      reason: "authenticated SCM daemon snapshot",
      snapshot: snapshotRaw(41),
    });
    const result = await readDaemonSnapshot(41);
    expect(result.available).toBe(true);
    expect(invoke).toHaveBeenCalledWith("daemon_snapshot", expect.objectContaining({ epoch: 1 }));
  });

  it("keeps a missing service honestly unavailable", async () => {
    invoke.mockResolvedValue({
      available: false,
      reason: "Forge acquisition service unavailable",
      snapshot: null,
    });
    await expect(readDaemonSnapshot()).resolves.toMatchObject({ available: false });
  });

  it("rejects a response that claims hardware or lacks SCM authentication", async () => {
    invoke.mockResolvedValue({
      available: true,
      reason: "bad",
      snapshot: snapshotRaw(43, {
        hardware_transport_available: true,
        authenticated_pipe: false,
        scm_owned: false,
      }),
    });
    await expect(readDaemonSnapshot(43)).rejects.toThrow("contradicted");
  });

  it("preserves daemon u64 values above the JavaScript safe-integer limit", () => {
    const large = "9007199254740993";
    const decoded = decodeDaemonSnapshotResult({
      available: true,
      reason: "ok",
      snapshot: snapshotRaw(1, {
        ledger_events: large,
        committed_record_count: large,
        highest_epoch: large,
      }),
    });
    expect(decoded.snapshot?.ledger_events).toBe(9_007_199_254_740_993n);
    expect(decoded.snapshot?.committed_record_count).toBe(9_007_199_254_740_993n);
    expect(decoded.snapshot?.highest_epoch).toBe(9_007_199_254_740_993n);
  });

  it("rejects numeric, non-canonical, out-of-range, and extra daemon fields", () => {
    for (const ledgerEvents of [1, "01", "18446744073709551616"]) {
      expect(() => decodeDaemonSnapshotResult({
        available: true,
        reason: "bad",
        snapshot: snapshotRaw(1, { ledger_events: ledgerEvents }),
      })).toThrow("daemon snapshot rejected");
    }
    expect(() => decodeDaemonSnapshotResult({
      available: true,
      reason: "bad",
      snapshot: snapshotRaw(1, { raw: [1, 2, 3] }),
    })).toThrow("unsupported fields");
  });
});
