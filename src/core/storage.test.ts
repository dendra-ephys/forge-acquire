import { describe, expect, it } from "vitest";
import {
  RELEASE_MINIMUM_USABLE_BYTES,
  evaluateStoragePreflight,
} from "./storage";

describe("recording storage preflight", () => {
  it("enforces the 40 TB release floor for 24 h stress-rate double write", () => {
    const result = evaluateStoragePreflight({
      targetPath: "D:\\ForgeRuns",
      volumeIdentity: "nvme-fixture-01",
      filesystem: "NTFS",
      freeBytes: RELEASE_MINIMUM_USABLE_BYTES,
      measuredSustainedWriteBytesPerSecond: 500_000_000,
      powerLossProtectionVerified: true,
      qualificationReceiptHash: "1".repeat(64),
      qualificationProfileHash: "2".repeat(64),
      qualificationDurationSeconds: 86_400,
    });
    expect(result.requiredUsableBytes).toBe(40_000_000_000_000);
    expect(result.requiredSustainedWriteBytesPerSecond).toBe(437_184_000);
    expect(result.eligibleForProtectedRecording).toBe(true);
  });

  it("fails closed when capacity, filesystem, write evidence or PLP is unknown", () => {
    const result = evaluateStoragePreflight({
      targetPath: null,
      volumeIdentity: null,
      filesystem: null,
      freeBytes: null,
      measuredSustainedWriteBytesPerSecond: null,
      powerLossProtectionVerified: null,
      qualificationReceiptHash: null,
      qualificationProfileHash: null,
      qualificationDurationSeconds: null,
    });
    expect(result.eligibleForProtectedRecording).toBe(false);
    expect(result.blockers).toHaveLength(9);
  });

  it("does not let a short smoke plan erase an explicit release capacity floor", () => {
    const result = evaluateStoragePreflight(
      {
        targetPath: "D:\\ForgeRuns",
        volumeIdentity: "nvme-small",
        filesystem: "NTFS",
        freeBytes: 10_000_000_000,
        measuredSustainedWriteBytesPerSecond: 500_000_000,
        powerLossProtectionVerified: true,
        qualificationReceiptHash: "1".repeat(64),
        qualificationProfileHash: "2".repeat(64),
        qualificationDurationSeconds: 86_400,
      },
      { plannedDurationSeconds: 10 },
    );
    expect(result.requiredUsableBytes).toBe(RELEASE_MINIMUM_USABLE_BYTES);
    expect(result.eligibleForProtectedRecording).toBe(false);
  });
});
