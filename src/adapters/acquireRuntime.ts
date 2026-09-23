import type { AcquireAdapter, MockFaultControl } from "./acquireAdapter";
import { MockAcquireAdapter } from "./mockAcquireAdapter";
import { SoftwareAcquireAdapter } from "./softwareAcquireAdapter";
import { NwbDerivedDemoModel } from "../core/nwbDerivedDemo";

/**
 * Composition-root boundary for the control plane.
 *
 * React components consume only `AcquireAdapter`. A future Tauri named-pipe
 * runtime can be selected here without leaking Rust IPC commands into pages or
 * components. Mock fault injection is a separate optional diagnostics port and
 * therefore cannot accidentally become part of the production adapter API.
 */
export interface AcquireRuntime {
  adapter: AcquireAdapter;
  diagnostics: MockFaultControl | null;
}

function runningInsideTauri(): boolean {
  return typeof globalThis === "object" && "__TAURI_INTERNALS__" in globalThis;
}

export function createAcquireRuntime(): AcquireRuntime {
  if (runningInsideTauri()) {
    return {
      adapter: new SoftwareAcquireAdapter({
        connectedPodCount: 4,
        transitionDelayMs: 180,
        previewIntervalMs: 70,
        previewModel: new NwbDerivedDemoModel(),
      }),
      // Recording now writes a real software journal. GUI fault injection is
      // deliberately unavailable on that path; browser-only visual QA keeps
      // the isolated mock diagnostics port below.
      diagnostics: null,
    };
  }
  const adapter = new MockAcquireAdapter({
    connectedPodCount: 4,
    transitionDelayMs: 180,
    previewIntervalMs: 70,
    previewModel: new NwbDerivedDemoModel(),
  });
  return {
    adapter,
    diagnostics: adapter.faultController,
  };
}
