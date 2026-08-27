import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  decodeSoftwareReplayReservation,
  launchSoftwareReplay,
  sendSoftwareReplayRunCommand,
} from "./softwareDaemon";

function reservationRaw(overrides: Record<string, unknown> = {}) {
  return {
    schema: "forge.software-replay-reservation.v1",
    reservationId: "SOFTWARE-RES-001",
    runIdHex: "11".repeat(16),
    pipeName: "\\\\.\\pipe\\forge-acqd-software-replay-1111",
    requestedDirectory: "F:\\ForgeRuns",
    allocatedLeafName: "FORGE-RUN-001",
    resolvedRunDirectory: "F:\\ForgeRuns\\FORGE-RUN-001",
    journalFileName: "run.forgewal",
    selectedDeviceIds: ["DEVICE-01", "DEVICE-02"],
    directoryCreateDisposition: "created_new",
    journalCreateDisposition: "not_created",
    overwritePolicy: "forbid",
    scope: "software",
    synthetic: true,
    processId: 4242,
    evidenceHash: "22".repeat(32),
    ...overrides,
  };
}

function daemonRaw(requestId: number, epoch: number, state = "prepared") {
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
    request_id: requestId.toString(),
    epoch: epoch.toString(),
    ledger_events: "1",
    active_run_id: Array(16).fill(0x11),
    latest_published_run_id: Array(16).fill(0),
    receipt_hash: Array(32).fill(0x33),
    committed_record_count: null,
    durable_record_count: null,
    expected_last_journal_sequence: null,
    queue_used_slots: "0",
    queue_capacity_slots: "64",
    generated_record_count: null,
    active_epoch: epoch.toString(),
    highest_epoch: epoch.toString(),
    active_target_device_id: Array(16).fill(0x44),
    active_frozen_config_hash: Array(32).fill(0x55),
    latest_sealed_run_id: Array(16).fill(0),
    error: "none",
    reason: state,
  };
}

describe("software daemon WebView boundary", () => {
  beforeEach(() => invoke.mockReset());

  it("accepts only a daemon-authored create-new software reservation", () => {
    expect(decodeSoftwareReplayReservation(reservationRaw())).toMatchObject({
      allocatedLeafName: "FORGE-RUN-001",
      directoryCreateDisposition: "created_new",
      journalCreateDisposition: "not_created",
      scope: "software",
      synthetic: true,
    });
    expect(() => decodeSoftwareReplayReservation(reservationRaw({
      directoryCreateDisposition: "existing",
    }))).toThrow("software replay receipt rejected");
    expect(() => decodeSoftwareReplayReservation(reservationRaw({ rawSamples: [1, 2] })))
      .toThrow("unsupported fields");
  });

  it("binds the launch receipt to the exact requested Run and device order", async () => {
    invoke.mockResolvedValue(reservationRaw());
    await expect(launchSoftwareReplay({
      requestedDirectory: "F:\\ForgeRuns",
      baseName: "FORGE-RUN",
      runIdHex: "11".repeat(16),
      targetGroupIdHex: "44".repeat(16),
      frozenConfigHashHex: "55".repeat(32),
      selectedDeviceIds: ["DEVICE-01", "DEVICE-02"],
    })).resolves.toMatchObject({ resolvedRunDirectory: "F:\\ForgeRuns\\FORGE-RUN-001" });
    expect(invoke).toHaveBeenCalledWith("software_replay_launch", expect.objectContaining({
      input: expect.objectContaining({ selectedDeviceIds: ["DEVICE-01", "DEVICE-02"] }),
    }));
  });

  it("requires authenticated non-SCM software responses", async () => {
    invoke.mockResolvedValue({
      available: true,
      reason: "prepared",
      snapshot: daemonRaw(9, 7),
    });
    await expect(sendSoftwareReplayRunCommand(
      "\\\\.\\pipe\\forge-acqd-software-replay-1111",
      1,
      {
        epoch: 7,
        runIdHex: "11".repeat(16),
        targetDeviceIdHex: "44".repeat(16),
        frozenConfigHashHex: "55".repeat(32),
      },
      9,
    )).resolves.toMatchObject({ snapshot: { scm_owned: false, state: "prepared" } });

    invoke.mockResolvedValue({
      available: true,
      reason: "bad",
      snapshot: { ...daemonRaw(10, 7), scm_owned: true },
    });
    await expect(sendSoftwareReplayRunCommand(
      "\\\\.\\pipe\\forge-acqd-software-replay-1111",
      1,
      {
        epoch: 7,
        runIdHex: "11".repeat(16),
        targetDeviceIdHex: "44".repeat(16),
        frozenConfigHashHex: "55".repeat(32),
      },
      10,
    )).rejects.toThrow("software daemon boundary");
  });
});
