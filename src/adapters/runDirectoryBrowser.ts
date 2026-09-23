import { invoke } from "@tauri-apps/api/core";

export const RUN_DIRECTORY_LISTING_SCHEMA = "forge.run-directory-listing.v1";
export const RUN_DIRECTORY_ERROR_SCHEMA = "forge.run-directory-error.v1";

export interface RunDirectoryRoot {
  readonly label: string;
  readonly path: string;
}

export interface RunDirectoryEntry {
  readonly name: string;
  readonly path: string;
}

export interface RunDirectoryListing {
  readonly schema: typeof RUN_DIRECTORY_LISTING_SCHEMA;
  readonly requestId: number;
  readonly currentDirectory: string;
  readonly parentDirectory: string | null;
  readonly roots: readonly RunDirectoryRoot[];
  readonly directories: readonly RunDirectoryEntry[];
  readonly truncated: boolean;
  readonly entryLimit: number;
  readonly scannedEntries: number;
  readonly omittedEntries: number;
  readonly validationScope: "browse_only";
}

export class RunDirectoryBrowserError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly retryable: boolean,
    readonly requestId: number | null = null,
  ) {
    super(message);
    this.name = "RunDirectoryBrowserError";
  }
}

export interface RunDirectoryBrowser {
  readonly available: boolean;
  browse(directory: string): Promise<RunDirectoryListing>;
}

export function directoryBrowserMessage(error: unknown): string {
  const code = typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : "";
  if (code === "access_denied") return "Permission denied. Go to the parent folder or enter another path.";
  if (code === "not_found") return "This folder does not exist or has moved.";
  if (code === "not_directory") return "The path is not a folder.";
  if (code === "not_absolute") return "Enter a complete absolute folder path.";
  if (code === "unsupported_namespace") return "Windows device namespaces are unsupported. Choose a standard drive or UNC folder.";
  if (code === "busy") return "The previous folder is still loading. Try again shortly.";
  if (code === "invalid_input") return "Enter a valid absolute folder path.";
  return error instanceof Error && error.message
    ? error.message
    : "Forge Desktop could not read this folder.";
}

type InvokeCommand = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;

function runningInsideTauri(): boolean {
  return typeof globalThis === "object" && "__TAURI_INTERNALS__" in globalThis;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAbsoluteDisplayPath(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && (value.startsWith("/")
      || /^[A-Za-z]:[\\/]/.test(value)
      || /^\\\\[^\\]+\\[^\\]+/.test(value));
}

function boundedCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function parsePathItem(
  value: unknown,
  kind: "root" | "directory",
): RunDirectoryRoot | RunDirectoryEntry {
  if (kind === "root"
    && isRecord(value)
    && typeof value.label === "string"
    && value.label.trim().length > 0
    && isAbsoluteDisplayPath(value.path)) {
    return { label: value.label, path: value.path };
  }
  if (kind === "directory"
    && isRecord(value)
    && typeof value.name === "string"
    && value.name.length > 0
    && isAbsoluteDisplayPath(value.path)) {
    return { name: value.name, path: value.path };
  }
  throw new RunDirectoryBrowserError("Forge Desktop returned an invalid directory entry.", "invalid_response", false);
}

function parseListing(value: unknown, expectedRequestId: number): RunDirectoryListing {
  if (!isRecord(value)
    || value.schema !== RUN_DIRECTORY_LISTING_SCHEMA
    || value.requestId !== expectedRequestId
    || !isAbsoluteDisplayPath(value.currentDirectory)
    || !(value.parentDirectory === null || isAbsoluteDisplayPath(value.parentDirectory))
    || !Array.isArray(value.roots)
    || !Array.isArray(value.directories)
    || typeof value.truncated !== "boolean"
    || !boundedCount(value.entryLimit)
    || value.entryLimit < 1
    || value.entryLimit > 256
    || !boundedCount(value.scannedEntries)
    || !boundedCount(value.omittedEntries)
    || value.validationScope !== "browse_only"
    || value.roots.length > 26
    || value.directories.length > value.entryLimit) {
    throw new RunDirectoryBrowserError("Forge Desktop returned an invalid directory listing.", "invalid_response", false);
  }

  const roots = value.roots.map((item) => parsePathItem(item, "root") as RunDirectoryRoot);
  const directories = value.directories.map(
    (item) => parsePathItem(item, "directory") as RunDirectoryEntry,
  );
  if (new Set(roots.map((item) => item.path.toLocaleLowerCase())).size !== roots.length
    || new Set(directories.map((item) => item.path.toLocaleLowerCase())).size !== directories.length) {
    throw new RunDirectoryBrowserError("Forge Desktop returned duplicate directory paths.", "invalid_response", false);
  }

  return {
    schema: RUN_DIRECTORY_LISTING_SCHEMA,
    requestId: expectedRequestId,
    currentDirectory: value.currentDirectory,
    parentDirectory: value.parentDirectory,
    roots,
    directories,
    truncated: value.truncated,
    entryLimit: value.entryLimit,
    scannedEntries: value.scannedEntries,
    omittedEntries: value.omittedEntries,
    validationScope: "browse_only",
  };
}

function mapCommandError(value: unknown): RunDirectoryBrowserError {
  if (isRecord(value)
    && value.schema === RUN_DIRECTORY_ERROR_SCHEMA
    && typeof value.code === "string"
    && typeof value.message === "string"
    && typeof value.retryable === "boolean") {
    return new RunDirectoryBrowserError(
      value.message,
      value.code,
      value.retryable,
      typeof value.requestId === "number" ? value.requestId : null,
    );
  }
  if (value instanceof Error) return new RunDirectoryBrowserError(value.message, "invoke_error", true);
  if (typeof value === "string" && value.length > 0) {
    return new RunDirectoryBrowserError(value, "invoke_error", true);
  }
  return new RunDirectoryBrowserError("Forge Desktop could not read this folder.", "invoke_error", true);
}

class TauriRunDirectoryBrowser implements RunDirectoryBrowser {
  readonly available = true;
  private nextRequestId = 1;
  private pending: { directory: string; promise: Promise<RunDirectoryListing> } | null = null;

  constructor(private readonly invokeCommand: InvokeCommand) {}

  browse(directory: string): Promise<RunDirectoryListing> {
    const normalized = directory.trim();
    if (normalized.length === 0) {
      return Promise.reject(new RunDirectoryBrowserError("Enter an absolute folder path.", "invalid_input", false));
    }
    if (this.pending !== null) {
      if (this.pending.directory === normalized) return this.pending.promise;
      return Promise.reject(new RunDirectoryBrowserError(
        "The previous folder is still loading. Please wait.",
        "busy",
        true,
      ));
    }

    const requestId = this.nextRequestId;
    this.nextRequestId = requestId === 0xffff_ffff ? 1 : requestId + 1;
    const promise = this.invokeListing(normalized, requestId).finally(() => {
      if (this.pending?.promise === promise) this.pending = null;
    });
    this.pending = { directory: normalized, promise };
    return promise;
  }

  private async invokeListing(directory: string, requestId: number): Promise<RunDirectoryListing> {
    try {
      const result = await this.invokeCommand<unknown>("browse_run_root", {
        input: { requestId, directory },
      });
      return parseListing(result, requestId);
    } catch (error) {
      if (error instanceof RunDirectoryBrowserError) throw error;
      throw mapCommandError(error);
    }
  }
}

class UnavailableRunDirectoryBrowser implements RunDirectoryBrowser {
  readonly available = false;

  async browse(): Promise<RunDirectoryListing> {
    throw new RunDirectoryBrowserError("Folder browsing is available only in Forge Desktop.", "unavailable", false);
  }
}

export function createRunDirectoryBrowser(
  tauriAvailable = runningInsideTauri(),
  invokeCommand: InvokeCommand = invoke,
): RunDirectoryBrowser {
  return tauriAvailable
    ? new TauriRunDirectoryBrowser(invokeCommand)
    : new UnavailableRunDirectoryBrowser();
}
