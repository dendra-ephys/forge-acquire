import { describe, expect, it } from "vitest";
import {
  initialMachineState,
  operatorStateOf,
  transitionMachine,
} from "./machine";

function connectedState() {
  let state = transitionMachine(initialMachineState, { type: "ENUMERATE" });
  state = transitionMachine(state, { type: "AVAILABLE" });
  state = transitionMachine(state, { type: "OPEN_REQUEST" });
  return transitionMachine(state, { type: "OPENED", synchronized: true });
}

describe("Forge acquisition state machine", () => {
  it("reaches ready only after the transport is opened", () => {
    const state = connectedState();
    expect(state.transport).toBe("open");
    expect(state.sync).toBe("synchronized");
    expect(operatorStateOf(state)).toBe("ready");
  });

  it("does not claim recording until writer arm and source confirmation", () => {
    let state = transitionMachine(connectedState(), {
      type: "PREPARE_RECORD",
      runId: "SIM-001",
    });
    expect(state.acquisition).toBe("preparing");
    expect(state.writer).toBe("opening");
    state = transitionMachine(state, { type: "WRITER_ARMED" });
    expect(state.acquisition).toBe("start_requested");
    expect(state.writer).toBe("armed");
    state = transitionMachine(state, { type: "RECORDING_CONFIRMED" });
    expect(state.acquisition).toBe("streaming");
    expect(state.writer).toBe("writing");
    expect(operatorStateOf(state)).toBe("recording");
  });

  it("does not report a recording as safe until writer finalization", () => {
    let state = transitionMachine(connectedState(), {
      type: "PREPARE_RECORD",
      runId: "SIM-002",
    });
    state = transitionMachine(state, { type: "WRITER_ARMED" });
    state = transitionMachine(state, { type: "RECORDING_CONFIRMED" });
    state = transitionMachine(state, { type: "STOP_RECORD" });
    expect(state.acquisition).toBe("stop_requested");
    expect(state.writer).toBe("writing");
    state = transitionMachine(state, { type: "SOURCE_STOPPED" });
    expect(state.writer).toBe("flushing");
    state = transitionMachine(state, { type: "WRITER_FINALIZED" });
    expect(state.writer).toBe("finalized");
    expect(state.runId).toBe("SIM-002");
    expect(state.lastFinalizedRunId).toBe("SIM-002");
    expect(operatorStateOf(state)).toBe("monitoring");
  });

  it("latches integrity degradation for the current run", () => {
    let state = transitionMachine(connectedState(), {
      type: "PREPARE_RECORD",
      runId: "SIM-003",
    });
    state = transitionMachine(state, { type: "WRITER_ARMED" });
    state = transitionMachine(state, { type: "RECORDING_CONFIRMED" });
    state = transitionMachine(state, {
      type: "INTEGRITY_FAULT",
      message: "counter gap",
    });
    state = transitionMachine(state, { type: "SYNC_OK" });
    expect(state.integrity).toBe("degraded_latched");
  });

  it("marks an interrupted recording invalid", () => {
    let state = transitionMachine(connectedState(), {
      type: "PREPARE_RECORD",
      runId: "SIM-004",
    });
    state = transitionMachine(state, { type: "WRITER_ARMED" });
    state = transitionMachine(state, { type: "RECORDING_CONFIRMED" });
    state = transitionMachine(state, { type: "DISCONNECT" });
    expect(state.writer).toBe("failed");
    expect(state.integrity).toBe("invalid");
    expect(state.runId).toBe("SIM-004");
    state = transitionMachine(state, { type: "OPEN_REQUEST" });
    state = transitionMachine(state, { type: "OPENED", synchronized: false });
    expect(state.writer).toBe("failed");
    expect(state.runId).toBe("SIM-004");
  });
});
