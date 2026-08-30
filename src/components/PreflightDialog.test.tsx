import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { RecordingTargetReservation } from "../adapters/acquireAdapter";
import type { RunDirectoryListing } from "../adapters/runDirectoryBrowser";
import { PreflightDialog, recordingSelectionProblem } from "./PreflightDialog";
import { RunDirectoryBrowserView } from "./RunDirectoryBrowserView";

const MOCK_TARGET: RecordingTargetReservation = {
  reservationId: "MOCK-TARGET-000001",
  requestedDirectory: "F:\\ForgeRuns",
  allocatedLeafName: "FORGE-RUN-001",
  resolvedRunDirectory: "F:\\ForgeRuns\\FORGE-RUN-001",
  allocationSequence: 1n,
  journalFileName: "run.forgewal",
  directoryCreateDisposition: "simulated",
  journalCreateDisposition: "simulated",
  overwritePolicy: "forbid",
  scope: "mock",
  synthetic: true,
  reasonCode: "MOCK_SESSION_RESERVATION",
  evidenceHash: "b".repeat(64),
};

const DIRECTORY_LISTING: RunDirectoryListing = {
  schema: "forge.run-directory-listing.v1",
  requestId: 1,
  currentDirectory: "F:\\ForgeRuns",
  parentDirectory: "F:\\",
  roots: [{ label: "F:", path: "F:\\" }],
  directories: [{ name: "2026-08-28", path: "F:\\ForgeRuns\\2026-08-28" }],
  truncated: false,
  entryLimit: 128,
  scannedEntries: 1,
  omittedEntries: 0,
  validationScope: "browse_only",
};

describe("PreflightDialog", () => {
  it("shows four operator conclusions and keeps mock receipts in collapsed technical details", () => {
    const markup = renderToStaticMarkup(
      <PreflightDialog
        open
        running={false}
        passed
        armed={false}
        recordingMode="single"
        adapterScope="mock"
        finalOutputReady
        finalOutputLabel="模拟流程 · 无文件"
        runLabel="FORGE-RUN"
        requestedDirectory="F:\\ForgeRuns"
        plannedDurationHours={24}
        devices={[{
          key: "MOCK-DIRECT-01",
          displayName: "Mock Direct Pod 1",
          deviceId: "MOCK-POD-SN-0001",
          routeLabel: "USB 01",
        }]}
        selectedPodKeys={new Set(["MOCK-DIRECT-01"])}
        recordingTarget={MOCK_TARGET}
        receiptId="MOCK-CMD-000001"
        checks={[{
          id: "recording-target",
          label: "新建记录目录",
          status: "pass",
          detail: "模拟名称已分配",
          evidence: MOCK_TARGET.evidenceHash,
        }]}
        directoryBrowserAvailable
        directoryBrowserOpen={false}
        directoryBrowserListing={null}
        directoryBrowserBusy={false}
        directoryBrowserError={null}
        onRunLabelChange={() => undefined}
        onRequestedDirectoryChange={() => undefined}
        onOpenDirectoryBrowser={() => undefined}
        onBrowseDirectory={() => undefined}
        onUseDirectory={() => undefined}
        onCloseDirectoryBrowser={() => undefined}
        onPlannedDurationHoursChange={() => undefined}
        onTogglePod={() => undefined}
        onRunPreflight={() => undefined}
        onRequestArm={() => undefined}
        onCancel={() => undefined}
      />,
    );

    expect(markup.match(/data-preflight-conclusion=/g)).toHaveLength(4);
    expect(markup).toContain('data-testid="preflight-operator-summary"');
    expect(markup).toContain('data-preflight-conclusion="devices"');
    expect(markup).toContain('data-preflight-conclusion="save-location" data-allocation-state="simulated"');
    expect(markup).toContain('data-preflight-conclusion="final-output" data-state="available"');
    expect(markup).toContain('data-preflight-conclusion="readiness" data-state="ready"');
    expect(markup).toContain("Mock Direct Pod 1");
    expect(markup).toContain("F:\\ForgeRuns\\FORGE-RUN-001");
    expect(markup).toContain("仅分配模拟名称 · 未创建文件");
    expect(markup).toContain("单设备记录设置");
    expect(markup).toContain("directory=simulated");
    expect(markup).toContain('<details class="preflight-technical-details">');
    expect(markup).not.toContain('<details class="preflight-technical-details" open');
    expect(markup).toContain("写入互锁回执");
    expect(markup).toContain("准备开始记录");
    expect(markup).toContain("模拟流程 · 无文件");
    expect(markup).not.toContain("Recording Arm 只是");
    expect(markup).not.toContain("Stimulation Arm");
  });

  it("shows one NWB root cause while derived target and admission checks remain waiting", () => {
    const markup = renderToStaticMarkup(
      <PreflightDialog
        open
        running={false}
        passed={false}
        armed={false}
        recordingMode="single"
        adapterScope="software"
        finalOutputReady={false}
        finalOutputLabel="NWB 输出未接入"
        runLabel="FORGE-RUN"
        requestedDirectory="F:\\ForgeRuns"
        plannedDurationHours={24}
        devices={[{ key: "MOCK-DIRECT-01", displayName: "Pod 1", deviceId: "POD-1", routeLabel: "USB 01" }]}
        selectedPodKeys={new Set(["MOCK-DIRECT-01"])}
        recordingTarget={null}
        receiptId={null}
        checks={[
          {
            id: "recording-target",
            label: "新建记录目录",
            status: "pending",
            detail: "等待创建",
            evidence: "no reservation receipt",
          },
          {
            id: "final-nwb-output",
            label: "最终文件 · NWB",
            status: "qualification_required",
            detail: "NWB 输出模块尚未接入",
            evidence: "PRODUCT_GATE_OPEN",
          },
          {
            id: "daemon-preflight",
            label: "记录准入快照",
            status: "pending",
            detail: "等待 adapter 报告",
            evidence: "snapshot-hash",
          },
        ]}
        directoryBrowserAvailable
        directoryBrowserOpen={false}
        directoryBrowserListing={null}
        directoryBrowserBusy={false}
        directoryBrowserError={null}
        onRunLabelChange={() => undefined}
        onRequestedDirectoryChange={() => undefined}
        onOpenDirectoryBrowser={() => undefined}
        onBrowseDirectory={() => undefined}
        onUseDirectory={() => undefined}
        onCloseDirectoryBrowser={() => undefined}
        onPlannedDurationHoursChange={() => undefined}
        onTogglePod={() => undefined}
        onRunPreflight={() => undefined}
        onRequestArm={() => undefined}
        onCancel={() => undefined}
      />,
    );

    expect(markup.match(/data-preflight-conclusion=/g)).toHaveLength(4);
    expect(markup).toContain("浏览文件夹…");
    expect(markup).toContain("浏览本机文件夹");
    expect(markup).not.toContain("系统文件夹选择器");
    expect(markup).toContain('data-preflight-conclusion="final-output" data-state="unavailable"');
    expect(markup).toContain('data-preflight-conclusion="readiness" data-state="blocked"');
    expect(markup.match(/data-root-cause="nwb-output-unavailable"/g)).toHaveLength(1);
    expect(markup).toContain("不可记录");
    expect(markup).toContain("当前不能开始正式记录");
    expect(markup).toContain("NWB 输出模块尚未接入");
    expect(markup.match(/preflight-check--pending/g)).toHaveLength(2);
    expect(markup).not.toContain("BLOCKED");
    expect(markup).toContain('<details class="preflight-technical-details">');
    expect(markup).toMatch(/<button[^>]*disabled=""[^>]*>[^<]*(?:<svg[\s\S]*?<\/svg>)?[^<]*检查并分配记录目标/);
  });

  it("reuses the recording dialog as a bounded Run directory browser view", () => {
    const markup = renderToStaticMarkup(
      <PreflightDialog
        open
        running={false}
        passed={false}
        armed={false}
        recordingMode="single"
        adapterScope="software"
        finalOutputReady
        finalOutputLabel="NWB 2.x · CREATE NEW"
        runLabel="FORGE-RUN"
        requestedDirectory="F:\\ForgeRuns"
        plannedDurationHours={24}
        devices={[{ key: "MOCK-DIRECT-01", displayName: "Pod 1", deviceId: "POD-1", routeLabel: "USB 01" }]}
        selectedPodKeys={new Set(["MOCK-DIRECT-01"])}
        recordingTarget={null}
        receiptId={null}
        checks={[]}
        directoryBrowserAvailable
        directoryBrowserOpen
        directoryBrowserListing={DIRECTORY_LISTING}
        directoryBrowserBusy={false}
        directoryBrowserError={null}
        onRunLabelChange={() => undefined}
        onRequestedDirectoryChange={() => undefined}
        onOpenDirectoryBrowser={() => undefined}
        onBrowseDirectory={() => undefined}
        onUseDirectory={() => undefined}
        onCloseDirectoryBrowser={() => undefined}
        onPlannedDurationHoursChange={() => undefined}
        onTogglePod={() => undefined}
        onRunPreflight={() => undefined}
        onRequestArm={() => undefined}
        onCancel={() => undefined}
      />,
    );

    const browserMarkup = renderToStaticMarkup(
      <RunDirectoryBrowserView
        initialDirectory="F:\\ForgeRuns"
        listing={DIRECTORY_LISTING}
        loading={false}
        errorMessage={null}
        onBrowse={() => undefined}
        onUseCurrent={() => undefined}
        onCancel={() => undefined}
      />,
    );

    expect(markup).toContain("选择 Run 根目录");
    expect(markup).not.toContain("记录准备摘要");
    expect(markup).not.toContain("检查并分配记录目标");
    expect(markup).not.toContain("Explorer");
    expect(browserMarkup).toContain('data-testid="run-directory-browser"');
    expect(browserMarkup).toContain('data-picker-state="ready"');
    expect(browserMarkup).toContain("F:\\ForgeRuns\\2026-08-28");
    expect(browserMarkup).toContain("使用当前文件夹");
    expect(browserMarkup).toContain("返回记录设置");
  });

  it("requires exactly one Pod for single-device setup and 2–8 explicit Pods for multi-device setup", () => {
    expect(recordingSelectionProblem("single", 0)).toContain("1 个");
    expect(recordingSelectionProblem("single", 1)).toBeNull();
    expect(recordingSelectionProblem("single", 2)).toContain("1 个");
    expect(recordingSelectionProblem("multi", 0)).toContain("至少 2 个");
    expect(recordingSelectionProblem("multi", 1)).toContain("至少 2 个");
    expect(recordingSelectionProblem("multi", 2)).toBeNull();
    expect(recordingSelectionProblem("multi", 8)).toBeNull();
    expect(recordingSelectionProblem("multi", 9)).toContain("最多记录 8 个");
  });
});
