import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { RecordingSetupPanel, type RecordingSetupPanelProps } from "./RecordingSetupPanel";

const noop = () => undefined;

function renderPanel(overrides: Partial<RecordingSetupPanelProps> = {}): string {
  return renderToStaticMarkup(<RecordingSetupPanel
    running={false}
    passed={false}
    armed={false}
    adapterScope="mock"
    finalOutputReady
    runLabel="FORGE-RUN"
    requestedDirectory="F:\\ForgeRuns"
    plannedDurationHours={24}
    selectionValid
    directoryBrowserAvailable
    onRunLabelChange={noop}
    onRequestedDirectoryChange={noop}
    onOpenDirectoryBrowser={noop}
    onPlannedDurationHoursChange={noop}
    onRunPreflight={noop}
    onRequestArm={noop}
    onClose={noop}
    {...overrides}
  />);
}

describe("RecordingSetupPanel", () => {
  it("renders a compact single-Pod setup surface without engineering evidence", () => {
    const markup = renderPanel();

    expect(markup).toContain('class="recording-setup-panel"');
    expect(markup).toContain("Save location");
    expect(markup).toContain("Recording name");
    expect(markup).toContain("Hours");
    expect(markup).toContain("Use demo target");
    expect(markup).not.toContain("Technical details");
    expect(markup).not.toContain("Device identities");
    expect(markup).not.toContain("Ready to check");
  });

  it("switches to the final setup action after target allocation", () => {
    const markup = renderPanel({ passed: true });

    expect(markup).toContain("Use this setup");
    expect(markup).not.toContain("Use demo target");
    expect(markup).toContain('disabled=""');
  });
});
