import { describe, expect, it, vi } from "vitest";
import {
  createRunDirectoryBrowser,
  RUN_DIRECTORY_ERROR_SCHEMA,
  RUN_DIRECTORY_LISTING_SCHEMA,
} from "./runDirectoryBrowser";

function listing(requestId = 1) {
  return {
    schema: RUN_DIRECTORY_LISTING_SCHEMA,
    requestId,
    currentDirectory: "F:\\ForgeRuns",
    parentDirectory: "F:\\",
    roots: [
      { label: "C:", path: "C:\\" },
      { label: "F:", path: "F:\\" },
    ],
    directories: [
      { name: "Session A", path: "F:\\ForgeRuns\\Session A" },
    ],
    truncated: false,
    entryLimit: 128,
    scannedEntries: 3,
    omittedEntries: 0,
    validationScope: "browse_only",
  } as const;
}

describe("RunDirectoryBrowser", () => {
  it("keeps the web preview outside native filesystem enumeration", async () => {
    const invoke = vi.fn();
    const browser = createRunDirectoryBrowser(false, invoke);

    expect(browser.available).toBe(false);
    await expect(browser.browse("F:\\ForgeRuns")).rejects.toMatchObject({ code: "unavailable" });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("reads one bounded directory listing through the narrow Tauri command", async () => {
    const invoke = vi.fn().mockResolvedValue(listing());
    const browser = createRunDirectoryBrowser(true, invoke);

    await expect(browser.browse(" F:\\ForgeRuns ")).resolves.toMatchObject({
      currentDirectory: "F:\\ForgeRuns",
      validationScope: "browse_only",
      entryLimit: 128,
    });
    expect(invoke).toHaveBeenCalledWith("browse_run_root", {
      input: { requestId: 1, directory: "F:\\ForgeRuns" },
    });
  });

  it("coalesces repeated reads and refuses a second path while I/O is pending", async () => {
    let finish: ((value: ReturnType<typeof listing>) => void) | undefined;
    const invoke = vi.fn().mockReturnValueOnce(new Promise((resolve) => {
      finish = resolve;
    }));
    const browser = createRunDirectoryBrowser(true, invoke);

    const first = browser.browse("F:\\ForgeRuns");
    const duplicate = browser.browse("F:\\ForgeRuns");
    await expect(browser.browse("C:\\Data")).rejects.toMatchObject({ code: "busy" });
    expect(invoke).toHaveBeenCalledTimes(1);
    finish?.(listing());
    await expect(Promise.all([first, duplicate])).resolves.toHaveLength(2);

    invoke.mockResolvedValueOnce(listing(2));
    await expect(browser.browse("F:\\ForgeRuns")).resolves.toMatchObject({ requestId: 2 });
    expect(invoke).toHaveBeenCalledTimes(2);
  });

  it("fails closed on malformed, oversized, or mismatched replies", async () => {
    const invoke = vi.fn();
    const browser = createRunDirectoryBrowser(true, invoke);

    invoke.mockResolvedValueOnce({ ...listing(), requestId: 99 });
    await expect(browser.browse("F:\\ForgeRuns")).rejects.toMatchObject({ code: "invalid_response" });

    invoke.mockResolvedValueOnce({ ...listing(2), directories: Array.from({ length: 129 }, (_, index) => ({
      name: `D${index}`,
      path: `F:\\ForgeRuns\\D${index}`,
    })) });
    await expect(browser.browse("F:\\ForgeRuns")).rejects.toMatchObject({ code: "invalid_response" });

    invoke.mockResolvedValueOnce({ ...listing(3), directories: [
      { name: "A", path: "relative" },
    ] });
    await expect(browser.browse("F:\\ForgeRuns")).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("preserves typed host errors and permits retry after failure", async () => {
    const invoke = vi.fn().mockRejectedValueOnce({
      schema: RUN_DIRECTORY_ERROR_SCHEMA,
      requestId: 1,
      code: "access_denied",
      message: "Directory cannot be enumerated.",
      retryable: false,
      osCode: 5,
    }).mockResolvedValueOnce(listing(2));
    const browser = createRunDirectoryBrowser(true, invoke);

    await expect(browser.browse("F:\\Protected")).rejects.toMatchObject({
      code: "access_denied",
      retryable: false,
      requestId: 1,
    });
    await expect(browser.browse("F:\\ForgeRuns")).resolves.toMatchObject({ requestId: 2 });
  });

  it("rejects an empty request without invoking the desktop", async () => {
    const invoke = vi.fn();
    const browser = createRunDirectoryBrowser(true, invoke);

    await expect(browser.browse("   ")).rejects.toMatchObject({ code: "invalid_input" });
    expect(invoke).not.toHaveBeenCalled();
  });
});
