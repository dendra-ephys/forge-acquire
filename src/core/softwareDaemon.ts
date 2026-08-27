import { invoke } from "@tauri-apps/api/core";
import {
  decodeDaemonSnapshotResult,
  type DaemonRunCommand,
  type DaemonRunContext,
  type DaemonSnapshotResult,
} from "./daemon";

export interface SoftwareReplayLaunchInput {
  requestedDirectory: string;
  baseName: string;
  runIdHex: string;
  targetGroupIdHex: string;
  frozenConfigHashHex: string;
  selectedDeviceIds: readonly string[];
}

export interface SoftwareReplayReservation {
  schema: "forge.software-replay-reservation.v1";
  reservationId: string;
  runIdHex: string;
  pipeName: string;
  requestedDirectory: string;
  allocatedLeafName: string;
  resolvedRunDirectory: string;
  journalFileName: "run.forgewal";
  selectedDeviceIds: readonly string[];
  directoryCreateDisposition: "created_new";
  journalCreateDisposition: "not_created" | "created_new";
  overwritePolicy: "forbid";
  scope: "software";
  synthetic: true;
  processId: number;
  evidenceHash: string;
}

type JsonRecord = Record<string, unknown>;

const RESERVATION_KEYS = [
  "schema",
  "reservationId",
  "runIdHex",
  "pipeName",
  "requestedDirectory",
  "allocatedLeafName",
  "resolvedRunDirectory",
  "journalFileName",
  "selectedDeviceIds",
  "directoryCreateDisposition",
  "journalCreateDisposition",
  "overwritePolicy",
  "scope",
  "synthetic",
  "processId",
  "evidenceHash",
] as const;

function fail(message: string): never {
  throw new Error(`software replay receipt rejected: ${message}`);
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: JsonRecord, expected: readonly string[], label: string): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) {
    fail(`${label} contains missing or unsupported fields`);
  }
}

function stringField(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) fail(`${label} must be a non-empty string`);
  return value;
}

function exactString<T extends string>(value: unknown, expected: T, label: string): T {
  if (value !== expected) fail(`${label} must be ${expected}`);
  return expected;
}

function hexField(value: unknown, bytes: number, label: string): string {
  const text = stringField(value, label);
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(text)) fail(`${label} must be lowercase hexadecimal`);
  return text;
}

export function decodeSoftwareReplayReservation(raw: unknown): SoftwareReplayReservation {
  if (!isRecord(raw)) fail("receipt must be an object");
  exactKeys(raw, RESERVATION_KEYS, "receipt");
  if (!Array.isArray(raw.selectedDeviceIds)
    || raw.selectedDeviceIds.length < 1
    || raw.selectedDeviceIds.length > 8
    || raw.selectedDeviceIds.some((item) => typeof item !== "string" || item.length === 0)
    || new Set(raw.selectedDeviceIds).size !== raw.selectedDeviceIds.length) {
    fail("selectedDeviceIds must contain 1-8 unique non-empty identifiers");
  }
  if (!Number.isSafeInteger(raw.processId) || (raw.processId as number) <= 0) {
    fail("processId must be a positive safe integer");
  }
  const journalCreateDisposition = raw.journalCreateDisposition;
  if (journalCreateDisposition !== "not_created" && journalCreateDisposition !== "created_new") {
    fail("journalCreateDisposition is unknown");
  }
  return {
    schema: exactString(raw.schema, "forge.software-replay-reservation.v1", "schema"),
    reservationId: stringField(raw.reservationId, "reservationId"),
    runIdHex: hexField(raw.runIdHex, 16, "runIdHex"),
    pipeName: stringField(raw.pipeName, "pipeName"),
    requestedDirectory: stringField(raw.requestedDirectory, "requestedDirectory"),
    allocatedLeafName: stringField(raw.allocatedLeafName, "allocatedLeafName"),
    resolvedRunDirectory: stringField(raw.resolvedRunDirectory, "resolvedRunDirectory"),
    journalFileName: exactString(raw.journalFileName, "run.forgewal", "journalFileName"),
    selectedDeviceIds: (raw.selectedDeviceIds as string[]).slice(),
    directoryCreateDisposition: exactString(raw.directoryCreateDisposition, "created_new", "directoryCreateDisposition"),
    journalCreateDisposition,
    overwritePolicy: exactString(raw.overwritePolicy, "forbid", "overwritePolicy"),
    scope: exactString(raw.scope, "software", "scope"),
    synthetic: raw.synthetic === true ? true : fail("synthetic must be true"),
    processId: raw.processId as number,
    evidenceHash: hexField(raw.evidenceHash, 32, "evidenceHash"),
  };
}

function validateLaunchInput(input: SoftwareReplayLaunchInput): void {
  if (!input.requestedDirectory.trim() || !input.baseName.trim()) {
    throw new Error("software replay target directory and base name are required");
  }
  hexField(input.runIdHex, 16, "runIdHex");
  hexField(input.targetGroupIdHex, 16, "targetGroupIdHex");
  hexField(input.frozenConfigHashHex, 32, "frozenConfigHashHex");
  if (input.selectedDeviceIds.length < 1 || input.selectedDeviceIds.length > 8
    || new Set(input.selectedDeviceIds).size !== input.selectedDeviceIds.length
    || input.selectedDeviceIds.some((value) => !value.trim())) {
    throw new Error("software replay requires 1-8 unique selected device identities");
  }
}

/**
 * Starts a detached, current-user authenticated Rust data-plane process. The
 * returned reservation is daemon-authored; this function never creates a Run
 * directory or journal in the WebView.
 */
export async function launchSoftwareReplay(
  input: SoftwareReplayLaunchInput,
): Promise<SoftwareReplayReservation> {
  validateLaunchInput(input);
  const raw = await invoke<unknown>("software_replay_launch", {
    input: {
      ...input,
      selectedDeviceIds: input.selectedDeviceIds.slice(),
    },
  });
  const receipt = decodeSoftwareReplayReservation(raw);
  if (receipt.runIdHex !== input.runIdHex
    || receipt.requestedDirectory !== input.requestedDirectory
    || receipt.selectedDeviceIds.length !== input.selectedDeviceIds.length
    || receipt.selectedDeviceIds.some((value, index) => value !== input.selectedDeviceIds[index])) {
    fail("receipt identity does not match the requested Run plan");
  }
  return receipt;
}

export async function readSoftwareReplaySnapshot(
  pipeName: string,
  requestId: number,
  epoch: number,
): Promise<DaemonSnapshotResult> {
  if (!pipeName || !Number.isSafeInteger(requestId) || requestId <= 0
    || !Number.isSafeInteger(epoch) || epoch <= 0) {
    throw new Error("software replay snapshot requires a pipe and positive safe request/epoch IDs");
  }
  const result = decodeDaemonSnapshotResult(await invoke<unknown>("software_replay_snapshot", {
    pipeName,
    requestId,
    epoch,
  }));
  const snapshot = result.snapshot;
  if (!result.available || snapshot === null) throw new Error(result.reason || "software replay daemon unavailable");
  if (!snapshot.accepted || !snapshot.authenticated_pipe || snapshot.scm_owned
    || !snapshot.protected_replay_available || snapshot.hardware_transport_available
    || snapshot.request_id !== BigInt(requestId) || snapshot.epoch !== BigInt(epoch)) {
    fail("snapshot contradicted the current-user software daemon boundary");
  }
  return result;
}

export async function sendSoftwareReplayRunCommand(
  pipeName: string,
  command: DaemonRunCommand,
  context: DaemonRunContext,
  requestId: number,
): Promise<DaemonSnapshotResult> {
  if (!pipeName || !Number.isSafeInteger(requestId) || requestId <= 0) {
    throw new Error("software replay command requires a pipe and positive safe request ID");
  }
  const result = decodeDaemonSnapshotResult(await invoke<unknown>("software_replay_run_command", {
    pipeName,
    input: {
      command,
      requestId,
      epoch: context.epoch,
      runIdHex: context.runIdHex,
      targetDeviceIdHex: context.targetDeviceIdHex,
      frozenConfigHashHex: context.frozenConfigHashHex,
    },
  }));
  const snapshot = result.snapshot;
  if (!result.available || snapshot === null) throw new Error(result.reason || "software replay daemon unavailable");
  if (!snapshot.authenticated_pipe || snapshot.scm_owned || !snapshot.protected_replay_available
    || snapshot.hardware_transport_available || snapshot.request_id !== BigInt(requestId)
    || snapshot.epoch !== BigInt(context.epoch)) {
    fail("command response contradicted the current-user software daemon boundary");
  }
  return result;
}
