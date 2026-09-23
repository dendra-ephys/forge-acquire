import type { StoragePreflightSnapshot } from "./types";

export const PLANNED_EIGHT_POD_BYTES_PER_SECOND = 126_720_000;
export const RELEASE_STRESS_BYTES_PER_SECOND = 190_080_000;
export const RELEASE_DURATION_SECONDS = 24 * 60 * 60;
export const RELEASE_COPY_COUNT = 2;
export const RELEASE_RESERVE_FRACTION = 0.2;
export const RELEASE_MINIMUM_USABLE_BYTES = 40_000_000_000_000;
export const RELEASE_WRITE_HEADROOM_FRACTION = 0.15;

export interface StorageEvidence {
  targetPath: string | null;
  volumeIdentity: string | null;
  filesystem: string | null;
  freeBytes: number | null;
  measuredSustainedWriteBytesPerSecond: number | null;
  powerLossProtectionVerified: boolean | null;
  qualificationReceiptHash: string | null;
  qualificationProfileHash: string | null;
  qualificationDurationSeconds: number | null;
}

export interface StoragePlan {
  plannedDurationSeconds?: number;
  plannedInputBytesPerSecond?: number;
  engineeringInputBytesPerSecond?: number;
  concurrentUncompressedCopies?: number;
  reserveFraction?: number;
  minimumUsableBytes?: number;
}

export function evaluateStoragePreflight(
  evidence: StorageEvidence,
  plan: StoragePlan = {},
): StoragePreflightSnapshot {
  const plannedDurationSeconds = plan.plannedDurationSeconds ?? RELEASE_DURATION_SECONDS;
  const plannedInputBytesPerSecond = plan.plannedInputBytesPerSecond
    ?? PLANNED_EIGHT_POD_BYTES_PER_SECOND;
  const engineeringInputBytesPerSecond = plan.engineeringInputBytesPerSecond
    ?? RELEASE_STRESS_BYTES_PER_SECOND;
  const concurrentUncompressedCopies = plan.concurrentUncompressedCopies ?? RELEASE_COPY_COUNT;
  const reserveFraction = plan.reserveFraction ?? RELEASE_RESERVE_FRACTION;
  const minimumUsableBytes = plan.minimumUsableBytes ?? RELEASE_MINIMUM_USABLE_BYTES;

  for (const [name, value] of Object.entries({
    plannedDurationSeconds,
    plannedInputBytesPerSecond,
    engineeringInputBytesPerSecond,
    concurrentUncompressedCopies,
  })) {
    if (!Number.isFinite(value) || value <= 0) throw new RangeError(`${name} must be positive`);
  }
  if (!Number.isFinite(reserveFraction) || reserveFraction < 0 || reserveFraction >= 1) {
    throw new RangeError("reserveFraction must be in [0, 1)");
  }

  const calculatedBytes = engineeringInputBytesPerSecond
    * plannedDurationSeconds
    * concurrentUncompressedCopies
    * (1 + reserveFraction);
  const requiredUsableBytes = Math.max(minimumUsableBytes, Math.ceil(calculatedBytes));
  const requiredSustainedWriteBytesPerSecond = Math.ceil(
    engineeringInputBytesPerSecond
      * concurrentUncompressedCopies
      * (1 + RELEASE_WRITE_HEADROOM_FRACTION),
  );
  const blockers: string[] = [];

  if (!evidence.targetPath) blockers.push("No local recording volume selected");
  if (!evidence.volumeIdentity) blockers.push("Recording-volume device identity is not bound");
  if (evidence.filesystem?.toUpperCase() !== "NTFS") blockers.push("Initial live-write release supports only local NTFS");
  if (evidence.freeBytes === null || evidence.freeBytes < requiredUsableBytes) {
    blockers.push(`Insufficient free space: at least ${(requiredUsableBytes / 1e12).toFixed(2)} TB required`);
  }
  if (
    evidence.measuredSustainedWriteBytesPerSecond === null
    || evidence.measuredSustainedWriteBytesPerSecond < requiredSustainedWriteBytesPerSecond
  ) {
    blockers.push(
      `Sustained physical write at ${(requiredSustainedWriteBytesPerSecond / 1e6).toFixed(2)} MB/s plus overhead is unproven`,
    );
  }
  if (evidence.powerLossProtectionVerified !== true) blockers.push("Local storage PLP is unverified");
  const validHash = (value: string | null) => value !== null
    && /^[0-9a-f]{64}$/.test(value)
    && !/^0+$/.test(value);
  if (!validHash(evidence.qualificationProfileHash)) blockers.push("Storage qualification profile hash is missing");
  if (!validHash(evidence.qualificationReceiptHash)) blockers.push("Storage qualification receipt hash is missing");
  if (
    evidence.qualificationDurationSeconds === null
    || evidence.qualificationDurationSeconds < RELEASE_DURATION_SECONDS
  ) {
    blockers.push("The target recording volume has not passed the 24-hour end-to-end dual-write qualification");
  }

  return {
    plannedDurationSeconds,
    plannedInputBytesPerSecond,
    engineeringInputBytesPerSecond,
    concurrentUncompressedCopies,
    reserveFraction,
    requiredUsableBytes,
    requiredSustainedWriteBytesPerSecond,
    ...evidence,
    eligibleForProtectedRecording: blockers.length === 0,
    blockers,
  };
}
