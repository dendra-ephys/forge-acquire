import type { MachineState, OperatorState } from "./types";

export type MachineEvent =
  | { type: "ENUMERATE" }
  | { type: "AVAILABLE" }
  | { type: "OPEN_REQUEST" }
  | { type: "OPENED"; synchronized: boolean }
  | { type: "OPEN_FAILED"; message: string }
  | { type: "START_MONITOR" }
  | { type: "FIRST_VALID_FRAME" }
  | { type: "PREPARE_RECORD"; runId: string }
  | { type: "WRITER_ARMED" }
  | { type: "RECORDING_CONFIRMED" }
  | { type: "STOP_RECORD" }
  | { type: "SOURCE_STOPPED" }
  | { type: "WRITER_FINALIZED" }
  | { type: "WRITER_FAILED"; message: string }
  | { type: "REARM_AFTER_FINALIZED" }
  | { type: "ACK_FAILED_RUN" }
  | { type: "STOP_MONITOR" }
  | { type: "INTEGRITY_FAULT"; message: string }
  | { type: "SYNC_LOST" }
  | { type: "SYNC_OK" }
  | { type: "DISCONNECT" };

export const initialMachineState: MachineState = {
  transport: "absent",
  acquisition: "idle",
  writer: "disabled",
  integrity: "clean",
  sync: "standalone",
  runId: null,
  lastFinalizedRunId: null,
  lastError: null,
};

export function transitionMachine(
  state: MachineState,
  event: MachineEvent,
): MachineState {
  switch (event.type) {
    case "ENUMERATE":
      return { ...state, transport: "enumerating", lastError: null };
    case "AVAILABLE":
      return { ...state, transport: "available" };
    case "OPEN_REQUEST":
      if (state.transport !== "available") return state;
      return { ...state, transport: "opening", lastError: null };
    case "OPENED":
      if (state.transport !== "opening") return state;
      return {
        ...state,
        transport: "open",
        acquisition: "idle",
        writer: state.writer === "failed" ? "failed" : "disabled",
        sync: event.synchronized ? "synchronized" : "standalone",
      };
    case "OPEN_FAILED":
      return { ...state, transport: "failed", lastError: event.message };
    case "START_MONITOR":
      if (state.transport !== "open" || state.acquisition !== "idle") return state;
      return { ...state, acquisition: "start_requested" };
    case "FIRST_VALID_FRAME":
      if (!['start_requested', 'initializing'].includes(state.acquisition)) return state;
      return { ...state, acquisition: "streaming" };
    case "PREPARE_RECORD":
      if (state.transport !== "open") return state;
      if (!["idle", "streaming"].includes(state.acquisition)) return state;
      if (!["disabled", "finalized"].includes(state.writer)) return state;
      return {
        ...state,
        acquisition: state.acquisition === "idle" ? "preparing" : "streaming",
        writer: "opening",
        integrity: "clean",
        runId: event.runId,
        lastError: null,
      };
    case "WRITER_ARMED":
      if (state.writer !== "opening") return state;
      return {
        ...state,
        acquisition: state.acquisition === "preparing" ? "start_requested" : state.acquisition,
        writer: "armed",
      };
    case "RECORDING_CONFIRMED":
      if (state.writer !== "armed") return state;
      if (!["start_requested", "streaming"].includes(state.acquisition)) return state;
      return { ...state, acquisition: "streaming", writer: "writing" };
    case "STOP_RECORD":
      if (state.writer !== "writing") return state;
      return { ...state, acquisition: "stop_requested" };
    case "SOURCE_STOPPED":
      if (state.writer !== "writing" || state.acquisition !== "stop_requested") return state;
      return { ...state, acquisition: "streaming", writer: "flushing" };
    case "WRITER_FINALIZED":
      if (state.writer !== "flushing") return state;
      return {
        ...state,
        writer: "finalized",
        lastFinalizedRunId: state.runId,
      };
    case "WRITER_FAILED":
      return {
        ...state,
        writer: "failed",
        integrity: "invalid",
        lastError: event.message,
      };
    case "REARM_AFTER_FINALIZED":
      if (state.writer !== "finalized") return state;
      return { ...state, writer: "disabled", runId: null, lastError: null };
    case "ACK_FAILED_RUN":
      if (state.writer !== "failed") return state;
      return { ...state, writer: "disabled", runId: null, lastError: null };
    case "STOP_MONITOR":
      if (["opening", "armed", "writing", "flushing"].includes(state.writer)) return state;
      if (state.acquisition !== "streaming") return state;
      return { ...state, acquisition: "idle", writer: "disabled", runId: null };
    case "INTEGRITY_FAULT":
      return {
        ...state,
        integrity: state.integrity === "invalid" ? "invalid" : "degraded_latched",
        lastError: event.message,
      };
    case "SYNC_LOST":
      return { ...state, sync: "lost" };
    case "SYNC_OK":
      return { ...state, sync: "synchronized" };
    case "DISCONNECT": {
      const interrupted = ["opening", "armed", "writing", "flushing"].includes(state.writer);
      return {
        ...initialMachineState,
        transport: "available",
        writer: interrupted ? "failed" : "disabled",
        integrity: interrupted ? "invalid" : state.integrity,
        runId: interrupted ? state.runId : null,
        lastFinalizedRunId: state.lastFinalizedRunId,
        lastError: interrupted ? "连接在记录完成前中断" : null,
      };
    }
  }
}

export function operatorStateOf(state: MachineState): OperatorState {
  if (state.transport !== "open") return "disconnected";
  if (["opening", "armed", "writing", "flushing"].includes(state.writer)) return "recording";
  if (state.acquisition === "streaming") return "monitoring";
  return "ready";
}
