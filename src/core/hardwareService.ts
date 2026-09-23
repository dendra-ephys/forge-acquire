import { invoke } from "@tauri-apps/api/core";

export const HARDWARE_STATUS_POLL_INTERVAL_MS = 500;

export const HARDWARE_SERVICE_STATES = [
  "unavailable",
  "ready",
  "prepare_requested",
  "prepared",
  "arm_requested",
  "armed",
  "start_requested",
  "start_acknowledged",
  "recording",
  "stop_requested",
  "stopped",
  "abort_requested",
  "aborted",
  "sealed",
  "failed",
] as const;

export const HARDWARE_SERVICE_ERRORS = [
  "none",
  "unavailable",
  "stale_time",
  "device_mismatch",
  "state_mismatch",
  "invalid_request",
  "persistence_failure",
  "transport_failure",
  "protocol_failure",
] as const;

export type HardwareServiceState = (typeof HARDWARE_SERVICE_STATES)[number];
export type HardwareServiceError = (typeof HARDWARE_SERVICE_ERRORS)[number];

export interface HardwareAvailabilityFlags {
  admissionVerified: boolean;
  transportOpen: boolean;
  timeFresh: boolean;
  hardwareAvailable: boolean;
}

export interface HardwareServiceSnapshot {
  requestId: bigint;
  serviceState: HardwareServiceState;
  errorCode: HardwareServiceError;
  availability: HardwareAvailabilityFlags;
  deviceId: readonly number[];
  transportEpoch: bigint;
  statusSequence: bigint;
  hardwareTimeNs: bigint;
  sampleCounter: bigint;
  frameCounter: bigint;
  runtimeFlags: number;
  hardwareStateHash: readonly number[];
  activeRunId: readonly number[];
  activeEpoch: bigint;
  pendingRequestId: bigint;
  firstJournalSequence: bigint | null;
  evidenceHash: readonly number[];
}

export interface HardwareSnapshotResult {
  /** A response to the Tauri command, not a claim that hardware is available. */
  reachable: boolean;
  reason: string;
  snapshot: HardwareServiceSnapshot | null;
  /** Browser monotonic receipt time; never a hardware or sample timestamp. */
  receiptMonotonicMs: number;
}

export type HardwareStatusView =
  | { kind: "unknown"; reason: string }
  | { kind: "stale"; reason: string }
  | { kind: "reported"; result: HardwareSnapshotResult; hardwareAvailable: boolean };

type JsonRecord = Record<string, unknown>;

const AVAIL_ADMISSION_VERIFIED = 1 << 0;
const AVAIL_TRANSPORT_OPEN = 1 << 1;
const AVAIL_TIME_FRESH = 1 << 2;
const AVAIL_HARDWARE_AVAILABLE = 1 << 3;
const AVAIL_KNOWN = AVAIL_ADMISSION_VERIFIED
  | AVAIL_TRANSPORT_OPEN
  | AVAIL_TIME_FRESH
  | AVAIL_HARDWARE_AVAILABLE;

const RESULT_KEYS = ["reachable", "reason", "snapshot"] as const;
const SNAPSHOT_KEYS = [
  "request_id",
  "service_state",
  "error_code",
  "availability_flags",
  "device_id",
  "transport_epoch",
  "status_sequence",
  "hardware_time_ns",
  "sample_counter",
  "frame_counter",
  "runtime_flags",
  "hardware_state_hash",
  "active_run_id",
  "active_epoch",
  "pending_request_id",
  "first_journal_sequence",
  "evidence_hash",
  "detail_code",
] as const;

function fail(message: string): never {
  throw new Error(`hardware snapshot rejected: ${message}`);
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireExactKeys(value: JsonRecord, expected: readonly string[], name: string): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) {
    fail(`${name} contains missing or unsupported fields`);
  }
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string") fail(`${name} must be a string`);
  return value;
}

/** Tauri's JSON-safe view serializes every Rust u64 as canonical decimal text. */
const U64_MAX = (1n << 64n) - 1n;

function requireU64Decimal(value: unknown, name: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    fail(`${name} must be a canonical unsigned decimal string`);
  }
  const number = BigInt(value);
  if (number > U64_MAX) fail(`${name} is outside u64 range`);
  return number;
}

function requireU32(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > 0xffff_ffff) {
    fail(`${name} is outside u32 range`);
  }
  return value as number;
}

function requireByteArray(value: unknown, length: number, name: string): readonly number[] {
  if (!Array.isArray(value) || value.length !== length) {
    fail(`${name} must be an exact ${length}-byte array`);
  }
  for (const byte of value) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 0xff) {
      fail(`${name} contains a non-byte value`);
    }
  }
  return value.slice();
}

function isKnownState(value: string): value is HardwareServiceState {
  return (HARDWARE_SERVICE_STATES as readonly string[]).includes(value);
}

function isKnownError(value: string): value is HardwareServiceError {
  return (HARDWARE_SERVICE_ERRORS as readonly string[]).includes(value);
}

function hasNonZeroByte(bytes: readonly number[]): boolean {
  return bytes.some((byte) => byte !== 0);
}

function decodeSnapshot(raw: unknown, expectedRequestId: number): HardwareServiceSnapshot {
  if (!isRecord(raw)) fail("snapshot must be an object");
  requireExactKeys(raw, SNAPSHOT_KEYS, "snapshot");

  const requestId = requireU64Decimal(raw.request_id, "snapshot.request_id");
  if (requestId !== BigInt(expectedRequestId)) fail("request ID did not echo");

  const serviceStateValue = requireString(raw.service_state, "snapshot.service_state");
  if (!isKnownState(serviceStateValue)) fail("snapshot.service_state is unknown");
  const errorCodeValue = requireString(raw.error_code, "snapshot.error_code");
  if (!isKnownError(errorCodeValue)) fail("snapshot.error_code is unknown");

  const availabilityFlags = requireU32(raw.availability_flags, "snapshot.availability_flags");
  if ((availabilityFlags & ~AVAIL_KNOWN) !== 0) fail("snapshot.availability_flags has unknown bits");
  const availability: HardwareAvailabilityFlags = {
    admissionVerified: (availabilityFlags & AVAIL_ADMISSION_VERIFIED) !== 0,
    transportOpen: (availabilityFlags & AVAIL_TRANSPORT_OPEN) !== 0,
    timeFresh: (availabilityFlags & AVAIL_TIME_FRESH) !== 0,
    hardwareAvailable: (availabilityFlags & AVAIL_HARDWARE_AVAILABLE) !== 0,
  };

  const deviceId = requireByteArray(raw.device_id, 16, "snapshot.device_id");
  const transportEpoch = requireU64Decimal(raw.transport_epoch, "snapshot.transport_epoch");
  const statusSequence = requireU64Decimal(raw.status_sequence, "snapshot.status_sequence");
  const hardwareTimeNs = requireU64Decimal(raw.hardware_time_ns, "snapshot.hardware_time_ns");
  const sampleCounter = requireU64Decimal(raw.sample_counter, "snapshot.sample_counter");
  const frameCounter = requireU64Decimal(raw.frame_counter, "snapshot.frame_counter");
  const runtimeFlags = requireU32(raw.runtime_flags, "snapshot.runtime_flags");
  const hardwareStateHash = requireByteArray(raw.hardware_state_hash, 32, "snapshot.hardware_state_hash");
  const activeRunId = requireByteArray(raw.active_run_id, 16, "snapshot.active_run_id");
  const activeEpoch = requireU64Decimal(raw.active_epoch, "snapshot.active_epoch");
  const pendingRequestId = requireU64Decimal(raw.pending_request_id, "snapshot.pending_request_id");
  const firstJournalSequence = raw.first_journal_sequence === null
    ? null
    : requireU64Decimal(raw.first_journal_sequence, "snapshot.first_journal_sequence");
  const evidenceHash = requireByteArray(raw.evidence_hash, 32, "snapshot.evidence_hash");
  requireU32(raw.detail_code, "snapshot.detail_code");

  if (!hasNonZeroByte(evidenceHash)) fail("snapshot.evidence_hash is zero");
  if (availability.hardwareAvailable) {
    if (!availability.admissionVerified || !availability.transportOpen || !availability.timeFresh
      || errorCodeValue !== "none" || serviceStateValue === "unavailable"
      || !hasNonZeroByte(deviceId) || transportEpoch === 0n || hardwareTimeNs === 0n
      || !hasNonZeroByte(hardwareStateHash)) {
      fail("hardware-available snapshot is incomplete");
    }
  } else if (serviceStateValue !== "unavailable" || errorCodeValue === "none"
    || availabilityFlags !== 0 || hasNonZeroByte(deviceId) || transportEpoch !== 0n
    || statusSequence !== 0n || hardwareTimeNs !== 0n || sampleCounter !== 0n
    || frameCounter !== 0n || runtimeFlags !== 0 || hasNonZeroByte(hardwareStateHash)
    || hasNonZeroByte(activeRunId) || activeEpoch !== 0n || pendingRequestId !== 0n
    || firstJournalSequence !== null) {
    fail("unavailable snapshot leaks active state");
  }

  return {
    requestId,
    serviceState: serviceStateValue,
    errorCode: errorCodeValue,
    availability,
    deviceId,
    transportEpoch,
    statusSequence,
    hardwareTimeNs,
    sampleCounter,
    frameCounter,
    runtimeFlags,
    hardwareStateHash,
    activeRunId,
    activeEpoch,
    pendingRequestId,
    firstJournalSequence,
    evidenceHash,
  };
}

export function decodeHardwareSnapshotResult(
  raw: unknown,
  expectedRequestId: number,
  receiptMonotonicMs: number,
): HardwareSnapshotResult {
  if (!isRecord(raw)) fail("result must be an object");
  requireExactKeys(raw, RESULT_KEYS, "result");
  if (typeof raw.reachable !== "boolean") fail("result.reachable must be boolean");
  const reason = requireString(raw.reason, "result.reason");
  if (!Number.isFinite(receiptMonotonicMs) || receiptMonotonicMs < 0) {
    fail("local receipt time is invalid");
  }

  if (!raw.reachable) {
    if (raw.snapshot !== null) fail("unreachable result contains a snapshot");
    return { reachable: false, reason, snapshot: null, receiptMonotonicMs };
  }
  if (raw.snapshot === null) fail("reachable result is missing a snapshot");
  return {
    reachable: true,
    reason,
    snapshot: decodeSnapshot(raw.snapshot, expectedRequestId),
    receiptMonotonicMs,
  };
}

function monotonicNowMs(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

export async function readHardwareSnapshot(requestId: number): Promise<HardwareSnapshotResult> {
  if (!Number.isSafeInteger(requestId) || requestId <= 0) {
    throw new Error("hardware snapshot request ID must be a positive safe integer");
  }
  const raw = await invoke<unknown>("hardware_snapshot", { requestId });
  return decodeHardwareSnapshotResult(raw, requestId, monotonicNowMs());
}

export class HardwareSnapshotPoller {
  private nextRequestId = 1;
  private inFlight: Promise<HardwareStatusView> | null = null;
  private latest: HardwareStatusView = { kind: "unknown", reason: "Hardware service has not been queried" };
  private lastAcceptedSnapshot: HardwareServiceSnapshot | null = null;

  get status(): HardwareStatusView {
    return this.latest;
  }

  poll(): Promise<HardwareStatusView> {
    if (this.inFlight !== null) return this.inFlight;
    if (this.nextRequestId > Number.MAX_SAFE_INTEGER) {
      this.latest = { kind: "stale", reason: "Hardware-status request IDs are exhausted; polling stopped" };
      return Promise.resolve(this.latest);
    }
    const requestId = this.nextRequestId;
    this.nextRequestId += 1;
    const pending = readHardwareSnapshot(requestId)
      .then((result) => this.accept(result))
      .catch((error: unknown) => this.markFailure(error));
    this.inFlight = pending;
    void pending.then(() => {
      if (this.inFlight === pending) this.inFlight = null;
    });
    return pending;
  }

  accept(result: HardwareSnapshotResult): HardwareStatusView {
    if (!result.reachable || result.snapshot === null) {
      this.latest = { kind: "stale", reason: result.reason || "Hardware service did not respond" };
      return this.latest;
    }

    const previous = this.lastAcceptedSnapshot;
    const next = result.snapshot;
    if (previous !== null && (next.transportEpoch < previous.transportEpoch
      || (next.transportEpoch === previous.transportEpoch
        && (next.statusSequence < previous.statusSequence
          || next.hardwareTimeNs < previous.hardwareTimeNs
          || next.sampleCounter < previous.sampleCounter
          || next.frameCounter < previous.frameCounter)))) {
      return this.markFailure(new Error("hardware snapshot epoch, sequence, time, or counter regressed"));
    }

    this.lastAcceptedSnapshot = next;
    this.latest = {
      kind: "reported",
      result,
      hardwareAvailable: next.serviceState !== "unavailable"
        && next.errorCode === "none"
        && next.availability.admissionVerified
        && next.availability.transportOpen
        && next.availability.timeFresh
        && next.availability.hardwareAvailable,
    };
    return this.latest;
  }

  markFailure(error: unknown): HardwareStatusView {
    this.latest = {
      kind: "stale",
      reason: error instanceof Error ? error.message : "Unable to query hardware service",
    };
    return this.latest;
  }
}
