import { invoke } from "@tauri-apps/api/core";

export type DaemonRunState =
  | "new"
  | "prepared"
  | "armed"
  | "recording"
  | "stopped"
  | "journal_sealed"
  | "finalized"
  | "aborted"
  | "failed";

export type DaemonServiceError =
  | "none"
  | "malformed_request"
  | "unsupported_message"
  | "hardware_unavailable"
  | "run_command_rejected"
  | "persistence_failure"
  | "internal_failure";

export interface DaemonSnapshotV1 {
  state: DaemonRunState;
  accepted: boolean;
  retryable: boolean;
  poisoned: boolean;
  auto_failed_on_restart: boolean;
  hardware_transport_available: boolean;
  authenticated_pipe: boolean;
  scm_owned: boolean;
  protected_replay_available: boolean;
  request_id: bigint;
  epoch: bigint;
  ledger_events: bigint;
  active_run_id: readonly number[];
  latest_published_run_id: readonly number[];
  receipt_hash: readonly number[];
  committed_record_count: bigint | null;
  durable_record_count: bigint | null;
  expected_last_journal_sequence: bigint | null;
  queue_used_slots: bigint | null;
  queue_capacity_slots: bigint | null;
  generated_record_count: bigint | null;
  active_epoch: bigint | null;
  highest_epoch: bigint;
  active_target_device_id: readonly number[];
  active_frozen_config_hash: readonly number[];
  latest_sealed_run_id: readonly number[];
  error: DaemonServiceError;
  reason: string;
}

export interface DaemonSnapshotResult {
  available: boolean;
  reason: string;
  snapshot: DaemonSnapshotV1 | null;
}

type JsonRecord = Record<string, unknown>;

const DAEMON_RUN_STATES: readonly DaemonRunState[] = [
  "new",
  "prepared",
  "armed",
  "recording",
  "stopped",
  "journal_sealed",
  "finalized",
  "aborted",
  "failed",
];

const DAEMON_SERVICE_ERRORS: readonly DaemonServiceError[] = [
  "none",
  "malformed_request",
  "unsupported_message",
  "hardware_unavailable",
  "run_command_rejected",
  "persistence_failure",
  "internal_failure",
];

const RESULT_KEYS = ["available", "reason", "snapshot"] as const;
const SNAPSHOT_KEYS = [
  "state",
  "accepted",
  "retryable",
  "poisoned",
  "auto_failed_on_restart",
  "hardware_transport_available",
  "authenticated_pipe",
  "scm_owned",
  "protected_replay_available",
  "request_id",
  "epoch",
  "ledger_events",
  "active_run_id",
  "latest_published_run_id",
  "receipt_hash",
  "committed_record_count",
  "durable_record_count",
  "expected_last_journal_sequence",
  "queue_used_slots",
  "queue_capacity_slots",
  "generated_record_count",
  "active_epoch",
  "highest_epoch",
  "active_target_device_id",
  "active_frozen_config_hash",
  "latest_sealed_run_id",
  "error",
  "reason",
] as const;

const U64_MAX = (1n << 64n) - 1n;

function reject(message: string): never {
  throw new Error(`daemon snapshot rejected: ${message}`);
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireExactKeys(value: JsonRecord, expected: readonly string[], name: string): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) {
    reject(`${name} contains missing or unsupported fields`);
  }
}

function requireBoolean(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") reject(`${name} must be boolean`);
  return value;
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string") reject(`${name} must be a string`);
  return value;
}

function requireU64Decimal(value: unknown, name: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    reject(`${name} must be a canonical unsigned decimal string`);
  }
  const number = BigInt(value);
  if (number > U64_MAX) reject(`${name} is outside u64 range`);
  return number;
}

function requireOptionalU64Decimal(value: unknown, name: string): bigint | null {
  return value === null ? null : requireU64Decimal(value, name);
}

function requireByteArray(value: unknown, length: number, name: string): readonly number[] {
  if (!Array.isArray(value) || value.length !== length) {
    reject(`${name} must be an exact ${length}-byte array`);
  }
  if (value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 0xff)) {
    reject(`${name} contains a non-byte value`);
  }
  return value.slice();
}

function requireRunState(value: unknown): DaemonRunState {
  const state = requireString(value, "snapshot.state");
  if (!(DAEMON_RUN_STATES as readonly string[]).includes(state)) reject("snapshot.state is unknown");
  return state as DaemonRunState;
}

function requireServiceError(value: unknown): DaemonServiceError {
  const error = requireString(value, "snapshot.error");
  if (!(DAEMON_SERVICE_ERRORS as readonly string[]).includes(error)) reject("snapshot.error is unknown");
  return error as DaemonServiceError;
}

function decodeDaemonSnapshot(raw: unknown): DaemonSnapshotV1 {
  if (!isRecord(raw)) reject("snapshot must be an object");
  requireExactKeys(raw, SNAPSHOT_KEYS, "snapshot");
  return {
    state: requireRunState(raw.state),
    accepted: requireBoolean(raw.accepted, "snapshot.accepted"),
    retryable: requireBoolean(raw.retryable, "snapshot.retryable"),
    poisoned: requireBoolean(raw.poisoned, "snapshot.poisoned"),
    auto_failed_on_restart: requireBoolean(raw.auto_failed_on_restart, "snapshot.auto_failed_on_restart"),
    hardware_transport_available: requireBoolean(raw.hardware_transport_available, "snapshot.hardware_transport_available"),
    authenticated_pipe: requireBoolean(raw.authenticated_pipe, "snapshot.authenticated_pipe"),
    scm_owned: requireBoolean(raw.scm_owned, "snapshot.scm_owned"),
    protected_replay_available: requireBoolean(raw.protected_replay_available, "snapshot.protected_replay_available"),
    request_id: requireU64Decimal(raw.request_id, "snapshot.request_id"),
    epoch: requireU64Decimal(raw.epoch, "snapshot.epoch"),
    ledger_events: requireU64Decimal(raw.ledger_events, "snapshot.ledger_events"),
    active_run_id: requireByteArray(raw.active_run_id, 16, "snapshot.active_run_id"),
    latest_published_run_id: requireByteArray(raw.latest_published_run_id, 16, "snapshot.latest_published_run_id"),
    receipt_hash: requireByteArray(raw.receipt_hash, 32, "snapshot.receipt_hash"),
    committed_record_count: requireOptionalU64Decimal(raw.committed_record_count, "snapshot.committed_record_count"),
    durable_record_count: requireOptionalU64Decimal(raw.durable_record_count, "snapshot.durable_record_count"),
    expected_last_journal_sequence: requireOptionalU64Decimal(raw.expected_last_journal_sequence, "snapshot.expected_last_journal_sequence"),
    queue_used_slots: requireOptionalU64Decimal(raw.queue_used_slots, "snapshot.queue_used_slots"),
    queue_capacity_slots: requireOptionalU64Decimal(raw.queue_capacity_slots, "snapshot.queue_capacity_slots"),
    generated_record_count: requireOptionalU64Decimal(raw.generated_record_count, "snapshot.generated_record_count"),
    active_epoch: requireOptionalU64Decimal(raw.active_epoch, "snapshot.active_epoch"),
    highest_epoch: requireU64Decimal(raw.highest_epoch, "snapshot.highest_epoch"),
    active_target_device_id: requireByteArray(raw.active_target_device_id, 16, "snapshot.active_target_device_id"),
    active_frozen_config_hash: requireByteArray(raw.active_frozen_config_hash, 32, "snapshot.active_frozen_config_hash"),
    latest_sealed_run_id: requireByteArray(raw.latest_sealed_run_id, 16, "snapshot.latest_sealed_run_id"),
    error: requireServiceError(raw.error),
    reason: requireString(raw.reason, "snapshot.reason"),
  };
}

export function decodeDaemonSnapshotResult(raw: unknown): DaemonSnapshotResult {
  if (!isRecord(raw)) reject("result must be an object");
  requireExactKeys(raw, RESULT_KEYS, "result");
  const available = requireBoolean(raw.available, "result.available");
  const reason = requireString(raw.reason, "result.reason");
  if (!available) {
    if (raw.snapshot !== null || reason.length === 0) reject("unavailable result is malformed");
    return { available: false, reason, snapshot: null };
  }
  if (raw.snapshot === null) reject("available result is missing a snapshot");
  return { available: true, reason, snapshot: decodeDaemonSnapshot(raw.snapshot) };
}

let nextRequestId = 1;

export type DaemonRunCommand = 1 | 2 | 3 | 4 | 5 | 7;

export interface DaemonRunContext {
  epoch: number;
  runIdHex: string;
  targetDeviceIdHex: string;
  frozenConfigHashHex: string;
}

/**
 * Reads only the low-rate, authenticated daemon status. It never requests raw
 * samples and never owns or starts the service. The Rust command performs the
 * frozen-response/hash checks and applies bounded named-pipe deadlines.
 */
export async function readDaemonSnapshot(
  requestedId?: number,
): Promise<DaemonSnapshotResult> {
  const requestId = requestedId ?? nextRequestId;
  if (!Number.isSafeInteger(requestId) || requestId <= 0) {
    throw new Error("daemon snapshot request ID must be a positive safe integer");
  }
  if (requestedId === undefined) {
    nextRequestId = nextRequestId >= Number.MAX_SAFE_INTEGER ? 1 : nextRequestId + 1;
  }
  const result = decodeDaemonSnapshotResult(await invoke<unknown>("daemon_snapshot", {
    requestId,
    epoch: 1,
  }));
  if (result.available) {
    const snapshot = result.snapshot;
    if (
      snapshot === null
      || !snapshot.accepted
      || snapshot.request_id !== BigInt(requestId)
      || snapshot.epoch !== 1n
      || !snapshot.authenticated_pipe
      || !snapshot.scm_owned
      || snapshot.hardware_transport_available
      || snapshot.error !== "none"
    ) {
      throw new Error("daemon snapshot contradicted the authenticated service boundary");
    }
  } else if (result.snapshot !== null || result.reason.length === 0) {
    throw new Error("daemon unavailable response is malformed");
  }
  return result;
}

export async function sendDaemonRunCommand(
  command: DaemonRunCommand,
  context: DaemonRunContext,
  requestedId?: number,
): Promise<DaemonSnapshotResult> {
  const requestId = requestedId ?? nextRequestId;
  if (!Number.isSafeInteger(requestId) || requestId <= 0) {
    throw new Error("daemon Run request ID must be a positive safe integer");
  }
  if (requestedId === undefined) {
    nextRequestId = nextRequestId >= Number.MAX_SAFE_INTEGER ? 1 : nextRequestId + 1;
  }
  const result = decodeDaemonSnapshotResult(await invoke<unknown>("daemon_run_command", {
    input: {
      command,
      requestId,
      epoch: context.epoch,
      runIdHex: context.runIdHex,
      targetDeviceIdHex: context.targetDeviceIdHex,
      frozenConfigHashHex: context.frozenConfigHashHex,
    },
  }));
  if (!result.available || result.snapshot === null) {
    throw new Error(result.reason || "Forge acquisition service unavailable");
  }
  const response = result.snapshot;
  if (
    response.request_id !== BigInt(requestId)
    || response.epoch !== BigInt(context.epoch)
    || !response.authenticated_pipe
    || !response.scm_owned
    || !response.protected_replay_available
    || response.hardware_transport_available
  ) {
    throw new Error("daemon Run response contradicted the protected replay boundary");
  }
  return result;
}
