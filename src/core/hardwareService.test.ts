import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  HardwareSnapshotPoller,
  decodeHardwareSnapshotResult,
} from "./hardwareService";

function bytes(length: number, fill = 0): number[] {
  return Array(length).fill(fill);
}

function u64(value: number | bigint): string {
  return value.toString();
}

function reportedRaw(requestId: number, overrides: Record<string, unknown> = {}) {
  return {
    reachable: true,
    reason: "hardware service responded",
    snapshot: {
      request_id: u64(requestId),
      service_state: "ready",
      error_code: "none",
      availability_flags: 0b1111,
      device_id: bytes(16, 2),
      transport_epoch: u64(9),
      status_sequence: u64(3),
      hardware_time_ns: u64(1_000_000),
      sample_counter: u64(30),
      frame_counter: u64(3),
      runtime_flags: 0,
      hardware_state_hash: bytes(32, 3),
      active_run_id: bytes(16),
      active_epoch: u64(0),
      pending_request_id: u64(0),
      first_journal_sequence: null,
      evidence_hash: bytes(32, 4),
      detail_code: 0,
      ...overrides,
    },
  };
}

describe("hardware service snapshot adapter", () => {
  beforeEach(() => invoke.mockReset());

  it("rejects a request ID that does not echo", () => {
    expect(() => decodeHardwareSnapshotResult(reportedRaw(2), 1, 10)).toThrow("did not echo");
  });

  it("does not promote a reachable but unavailable service to hardware available", () => {
    const unavailable = {
      reachable: true,
      reason: "service returned unavailable",
      snapshot: {
        request_id: u64(1),
        service_state: "unavailable",
        error_code: "unavailable",
        availability_flags: 0,
        device_id: bytes(16),
        transport_epoch: u64(0),
        status_sequence: u64(0),
        hardware_time_ns: u64(0),
        sample_counter: u64(0),
        frame_counter: u64(0),
        runtime_flags: 0,
        hardware_state_hash: bytes(32),
        active_run_id: bytes(16),
        active_epoch: u64(0),
        pending_request_id: u64(0),
        first_journal_sequence: null,
        evidence_hash: bytes(32, 4),
        detail_code: 0,
      },
    };
    const poller = new HardwareSnapshotPoller();
    const status = poller.accept(decodeHardwareSnapshotResult(unavailable, 1, 10));
    expect(status).toMatchObject({ kind: "reported", hardwareAvailable: false });
  });

  it("rejects a reachable response whose ready state has incomplete availability flags", () => {
    expect(() => decodeHardwareSnapshotResult(reportedRaw(1, { availability_flags: 0b0111 }), 1, 10))
      .toThrow("snapshot rejected");
  });

  it("rejects unknown availability bits and absent evidence", () => {
    expect(() => decodeHardwareSnapshotResult(reportedRaw(1, { availability_flags: 0b1_1111 }), 1, 10))
      .toThrow("unknown bits");
    expect(() => decodeHardwareSnapshotResult(reportedRaw(1, { evidence_hash: bytes(32) }), 1, 10))
      .toThrow("evidence_hash is zero");
  });

  it("rejects a stale epoch or status sequence instead of replacing newer data", () => {
    const poller = new HardwareSnapshotPoller();
    poller.accept(decodeHardwareSnapshotResult(reportedRaw(1, { transport_epoch: u64(9), status_sequence: u64(8) }), 1, 10));
    const stale = poller.accept(decodeHardwareSnapshotResult(reportedRaw(2, { transport_epoch: u64(9), status_sequence: u64(7) }), 2, 11));
    expect(stale).toMatchObject({ kind: "stale", reason: expect.stringContaining("regressed") });
  });

  it("allows a new epoch to establish a new status-sequence baseline", () => {
    const poller = new HardwareSnapshotPoller();
    poller.accept(decodeHardwareSnapshotResult(reportedRaw(1, { transport_epoch: u64(9), status_sequence: u64(8) }), 1, 10));
    const next = poller.accept(decodeHardwareSnapshotResult(reportedRaw(2, { transport_epoch: u64(10), status_sequence: u64(1) }), 2, 11));
    expect(next).toMatchObject({ kind: "reported", hardwareAvailable: true });
  });

  it("rejects time and acquisition-counter regression within one transport epoch", () => {
    for (const regressed of [
      { hardware_time_ns: u64(999_999) },
      { sample_counter: u64(29) },
      { frame_counter: u64(2) },
    ]) {
      const poller = new HardwareSnapshotPoller();
      poller.accept(decodeHardwareSnapshotResult(reportedRaw(1), 1, 10));
      const stale = poller.accept(decodeHardwareSnapshotResult(
        reportedRaw(2, { status_sequence: u64(4), ...regressed }),
        2,
        11,
      ));
      expect(stale).toMatchObject({ kind: "stale", reason: expect.stringContaining("regressed") });
    }
  });

  it("turns a polling failure into stale instead of retaining green state", () => {
    const poller = new HardwareSnapshotPoller();
    poller.accept(decodeHardwareSnapshotResult(reportedRaw(1, {
      status_sequence: u64(8),
    }), 1, 10));
    const status = poller.markFailure(new Error("timeout"));
    expect(status).toMatchObject({ kind: "stale", reason: expect.stringContaining("timeout") });
  });

  it("does not let a stale interval erase the same-epoch monotonic baseline", () => {
    const poller = new HardwareSnapshotPoller();
    poller.accept(decodeHardwareSnapshotResult(reportedRaw(1, {
      transport_epoch: u64(9),
      status_sequence: u64(8),
    }), 1, 10));
    poller.markFailure(new Error("timeout"));
    const regressed = poller.accept(decodeHardwareSnapshotResult(reportedRaw(2, {
      transport_epoch: u64(9),
      status_sequence: u64(7),
    }), 2, 11));
    expect(regressed).toMatchObject({ kind: "stale", reason: expect.stringContaining("regressed") });
  });

  it("preserves and compares u64 values above the JavaScript safe-integer limit", () => {
    const large = 9_007_199_254_740_993n;
    const first = decodeHardwareSnapshotResult(reportedRaw(1, {
      hardware_time_ns: u64(large),
      sample_counter: u64(large),
      frame_counter: u64(large),
    }), 1, 10);
    expect(first.snapshot?.hardwareTimeNs).toBe(large);
    const poller = new HardwareSnapshotPoller();
    poller.accept(first);
    const next = poller.accept(decodeHardwareSnapshotResult(reportedRaw(2, {
      status_sequence: u64(4),
      hardware_time_ns: u64(large + 1n),
      sample_counter: u64(large + 1n),
      frame_counter: u64(large + 1n),
    }), 2, 11));
    expect(next).toMatchObject({ kind: "reported", hardwareAvailable: true });
  });

  it("rejects numeric, non-canonical, and out-of-range u64 JSON fields", () => {
    expect(() => decodeHardwareSnapshotResult(reportedRaw(1, { hardware_time_ns: 1 }), 1, 10))
      .toThrow("canonical unsigned decimal string");
    expect(() => decodeHardwareSnapshotResult(reportedRaw(1, { hardware_time_ns: "01" }), 1, 10))
      .toThrow("canonical unsigned decimal string");
    expect(() => decodeHardwareSnapshotResult(reportedRaw(1, {
      hardware_time_ns: "18446744073709551616",
    }), 1, 10)).toThrow("outside u64 range");
  });

  it("rejects raw, payload, samples, trace, and extra numeric-array fields", () => {
    for (const field of ["raw", "payload", "samples", "trace", "extra_numbers"]) {
      expect(() => decodeHardwareSnapshotResult(reportedRaw(1, { [field]: bytes(4, 1) }), 1, 10))
        .toThrow("unsupported fields");
    }
  });

  it("uses one serial, increasing request ID and only invokes hardware_snapshot", async () => {
    invoke.mockResolvedValueOnce(reportedRaw(1)).mockResolvedValueOnce(reportedRaw(2));
    const poller = new HardwareSnapshotPoller();
    await poller.poll();
    await poller.poll();
    expect(invoke).toHaveBeenNthCalledWith(1, "hardware_snapshot", { requestId: 1 });
    expect(invoke).toHaveBeenNthCalledWith(2, "hardware_snapshot", { requestId: 2 });
  });

  it("serializes overlapping poll requests", async () => {
    let resolve: ((value: unknown) => void) | undefined;
    invoke.mockReturnValue(new Promise<unknown>((done) => { resolve = done; }));
    const poller = new HardwareSnapshotPoller();
    const first = poller.poll();
    const second = poller.poll();
    expect(second).toBe(first);
    expect(invoke).toHaveBeenCalledTimes(1);
    resolve!(reportedRaw(1));
    await expect(first).resolves.toMatchObject({ kind: "reported", hardwareAvailable: true });
  });
});
