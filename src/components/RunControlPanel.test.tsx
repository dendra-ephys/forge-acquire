import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { RunOutputState, RunOutputSummary } from "../core/runOutputState";
import { RunControlPanel, type RunControlPanelProps } from "./RunControlPanel";

const noop = () => undefined;

function output(state: RunOutputState, label = "Not recorded", detail = ""): RunOutputSummary {
  return {
    state,
    label,
    detail,
    phaseLabel: state.toUpperCase(),
    compactLabel: state === "nwb_saved" ? "SAVED" : state.toUpperCase(),
    urgent: state === "failed" || state === "raw_retained",
  };
}

function renderPanel(overrides: Partial<RunControlPanelProps> = {}): string {
  const props: RunControlPanelProps = {
    connected: true,
    busy: false,
    phase: "connected_idle",
    phaseLabel: "CONNECTED / IDLE",
    phaseDetail: "Preview is live",
    runId: null,
    previewState: "live",
    recordingTarget: null,
    recording: false,
    runOutput: output("idle"),
    recoveryRequired: false,
    canStartPreview: false,
    canSetupSingleRecording: true,
    canSetupMultiRecording: true,
    recordingSetupMode: "single",
    recordingDeviceCount: 1,
    previewDeviceName: "Direct Pod 1",
    canStart: true,
    paused: false,
    canPause: true,
    canStop: true,
    stopMode: "preview",
    pauseAffectsRecording: false,
    canRecover: false,
    canAcknowledgeFailed: false,
    onStartPreview: noop,
    onSetupSingleRecording: noop,
    onSetupMultiRecording: noop,
    onStart: noop,
    onTogglePause: noop,
    onStop: noop,
    onRecover: noop,
    onAcknowledgeFailed: noop,
    runStatus: <div>Device recording status</div>,
    ...overrides,
  };
  return renderToStaticMarkup(<RunControlPanel {...props} />);
}

describe("RunControlPanel", () => {
  it("separates Preview and Recording into explicit actions", () => {
    const markup = renderPanel();

    expect(markup).toContain('aria-label="Single-device setup"');
    expect(markup).toContain('aria-label="Multi-device setup"');
    expect(markup).toContain("Single-device setup · Direct Pod 1");
    expect(markup).toContain("<span>Setup</span>");
    expect(markup).toContain("<span>Multi-Pod</span>");
    expect(markup).toContain('aria-label="Start recording · 1 device"');
    expect(markup).toContain("Start Preview</span>");
    expect(markup).toContain('aria-label="Start Preview"');
    expect(markup).toContain("Preview is already running");
    expect(markup).toContain("Start Recording</button>");
    expect(markup).toContain('aria-label="Pause"');
    expect(markup).toContain('aria-label="Stop preview"');
    expect(markup.match(/instrument-button--record"/g)).toHaveLength(1);
    expect(markup).not.toContain("Recording lifecycle");
    expect(markup).not.toContain(">Connect<");
    expect(markup).not.toContain(">Disconnect<");
    expect(markup).not.toContain("Sync");
  });

  it("keeps Start Recording available when Preview has not started", () => {
    const markup = renderPanel({
      previewState: "stopped",
      canStartPreview: true,
      canStart: true,
      canPause: false,
      canStop: false,
      stopMode: null,
    });

    expect(markup).toContain('aria-label="Start Preview"');
    expect(markup).toContain('aria-label="Start recording · 1 device"');
    expect(markup).not.toContain('aria-label="Start recording · 1 device" disabled');
    expect(markup).toContain('disabled="" aria-label="Stop preview"');
  });

  it("exposes separate pause and end recording actions", () => {
    const markup = renderPanel({
      phase: "recording",
      phaseLabel: "RECORDING",
      runId: "ACTIVE-RUN",
      recording: true,
      canPause: true,
      canStop: true,
      stopMode: "recording",
      pauseAffectsRecording: true,
    });

    expect(markup).toContain('aria-label="Pause"');
    expect(markup).toContain(">Pause</button>");
    expect(markup).toContain('aria-label="Stop recording"');
    expect(markup).toContain(">Stop</button>");
    expect(markup.match(/instrument-button--stop"/g)).toHaveLength(1);
    expect(markup).toContain("End recording, drain pending data, and save the Run");
    expect(markup).not.toContain(">Finalize</button>");
    expect(markup).not.toContain("Finalize Run");
  });

  it("turns Pause into Resume after the adapter acknowledges a pause", () => {
    const markup = renderPanel({
      phase: "recording",
      phaseLabel: "RECORDING PAUSED",
      recording: true,
      paused: true,
      canPause: true,
      canStop: true,
      stopMode: "recording",
      pauseAffectsRecording: true,
    });

    expect(markup).toContain('aria-label="Resume"');
    expect(markup).toContain(">Resume</button>");
    expect(markup).toContain('aria-label="Stop recording"');
  });

  it("keeps the compound operation pending until the final NWB receipt is proven", () => {
    const saving = renderPanel({
      phase: "finalizing",
      phaseLabel: "ENDING / NWB",
      runId: "ACTIVE-RUN",
      runOutput: output("saving", "Ending and generating NWB", "Generating final NWB"),
      runStatus: <div>Ending and generating NWB · final NWB receipt arrives</div>,
    });
    expect(saving).toContain("Ending and generating NWB");
    expect(saving).toContain("final NWB receipt arrives");

    const rawRetained = renderPanel({
      phase: "finalized",
      phaseLabel: "NWB INCOMPLETE",
      runId: "INCOMPLETE-RUN",
      runOutput: output(
        "raw_retained",
        "Raw data retained · NWB incomplete",
        "Only the sealed raw journal is confirmed; there is no final NWB publication receipt.",
      ),
      runStatus: <div>Raw data retained · NWB incomplete · no final NWB publication receipt</div>,
    });
    expect(rawRetained).toContain("Raw data retained · NWB incomplete");
    expect(rawRetained).toContain("no final NWB publication receipt");
    expect(rawRetained).not.toContain("NWB saved");

    const saved = renderPanel({
      phase: "finalized",
      phaseLabel: "NWB SAVED",
      runId: "SEALED-RUN",
      runOutput: output(
        "nwb_saved",
        "NWB saved",
        "Generated, validated, and published as a new file: F:\\ForgeRuns\\FORGE-RUN-001.nwb",
      ),
      runStatus: <div>NWB saved · F:\ForgeRuns\FORGE-RUN-001.nwb</div>,
    });
    expect(saved).toContain("NWB saved");
    expect(saved).toContain("FORGE-RUN-001.nwb");
  });

  it("keeps a completed Browser mock visibly separate from a saved NWB", () => {
    const markup = renderPanel({
      phase: "finalized",
      phaseLabel: "SIMULATION COMPLETE",
      runId: "MOCK-RUN",
      runOutput: output("mock_complete", "Simulation complete", "No recording file or NWB was created."),
      runStatus: <div>Simulation complete · No recording file or NWB was created.</div>,
    });

    expect(markup).toContain("Simulation complete");
    expect(markup).toContain("No recording file or NWB was created");
    expect(markup).not.toContain("NWB SAVED");
  });

  it("offers an honest failed-Run close action without a rejected Recover button", () => {
    const markup = renderPanel({
      phase: "recovery_required",
      phaseLabel: "RECOVERY REQUIRED",
      phaseDetail: "Unsealed; generated 10 / committed 9 / durable 8",
      runId: "FAILED-RUN",
      recoveryRequired: true,
      canAcknowledgeFailed: true,
    });

    expect(markup).toContain("Acknowledge failure");
    expect(markup).toContain("partial journal is retained");
    expect(markup).toContain("fabricated seal");
    expect(markup).not.toContain(">Recover<");
  });

  it("does not render a clickable recovery command when the adapter provides none", () => {
    const markup = renderPanel({
      phase: "recovery_required",
      phaseLabel: "RECOVERY REQUIRED",
      recoveryRequired: true,
      canRecover: false,
      canAcknowledgeFailed: false,
    });

    expect(markup).toContain("current snapshot provides no GUI recovery command");
    expect(markup).not.toContain(">Recover<");
    expect(markup).not.toContain("Acknowledge failure");
  });

  it("keeps daemon connection controls and the decorative lifecycle strip out of the operator panel", () => {
    const markup = renderPanel({
      connected: false,
      runId: "ACTIVE-RUN",
      phase: "recording",
      phaseLabel: "CONTROL LOST",
    });

    expect(markup).not.toContain(">Connect<");
    expect(markup).not.toContain(">Disconnect<");
    expect(markup).not.toContain("Recording lifecycle");
    expect(markup).not.toContain(">Armed<");
    expect(markup).not.toContain(">Final NWB<");
  });
});
