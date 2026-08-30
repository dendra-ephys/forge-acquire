import { mkdir, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { chromium } from "playwright-core";

const url = process.env.FORGE_QA_URL ?? "http://127.0.0.1:1421/";
const outputDirectory = resolve("artifacts", "visual-qa");
const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

// QA is intentionally loopback-only. Do not let a workstation-wide HTTP/SOCKS
// proxy intercept 127.0.0.1 and turn a local navigation into a 30 s timeout.
const browser = await chromium.launch({
  executablePath: edge,
  headless: true,
  args: ["--no-proxy-server"],
});
const page = await browser.newPage({
  viewport: { width: 1440, height: 920 },
  deviceScaleFactor: 1,
  colorScheme: "light",
  reducedMotion: "reduce",
});

const errors = [];
page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
page.on("console", (message) => {
  if (message.type() === "error") {
    const location = message.location();
    errors.push(`console: ${message.text()} (${location.url || "unknown source"})`);
  }
});

async function screenshot(name) {
  await page.screenshot({ path: resolve(outputDirectory, name) });
}

async function waitForPhase(label) {
  await page.locator(".phase-chip").filter({ hasText: label }).waitFor();
}

async function requireMinimumTarget(locator, label) {
  const box = await locator.boundingBox();
  if (!box || box.width < 44 || box.height < 44) {
    throw new Error(`${label} target is ${box?.width ?? 0}x${box?.height ?? 0}px`);
  }
}

async function assertNoAcquisitionStimulationControls(label) {
  for (const selector of [".safety-panel", "#stim-arm-title", ".control-rail__stim"]) {
    if ((await page.locator(selector).count()) !== 0) {
      throw new Error(`${label}: acquisition GUI contains ${selector}`);
    }
  }
  if ((await page.getByText("Stimulation Arm", { exact: true }).count()) !== 0) {
    throw new Error(`${label}: acquisition GUI still renders Stimulation Arm`);
  }
}

try {
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await page.getByText("关闭窗口不会请求 Stop", { exact: true }).waitFor();
  await page.getByRole("heading", { name: "设备列表" }).waitFor();
  await page.getByText("直接连接 PC", { exact: true }).waitFor();

  const aggregatorDisclosure = page.getByRole("button", { name: /^Mock Aggregator A/ });
  if ((await aggregatorDisclosure.getAttribute("aria-expanded")) !== "true") {
    throw new Error("Aggregator device group should be expanded on first inspection");
  }
  const aggregatedPod = page.getByRole("button", { name: /选择 Mock Aggregated Pod 1 进行 Preview/ });
  await requireMinimumTarget(aggregatorDisclosure, "Aggregator disclosure");
  await requireMinimumTarget(aggregatedPod, "Aggregated Pod Preview");
  await aggregatorDisclosure.click();
  if ((await aggregatorDisclosure.getAttribute("aria-expanded")) !== "false") {
    throw new Error("Aggregator device group did not collapse");
  }
  await aggregatorDisclosure.click();
  await aggregatedPod.click();
  await page.getByRole("heading", { name: "Mock Aggregated Pod 1" }).waitFor();
  await assertNoAcquisitionStimulationControls("disconnected");
  await screenshot("01-device-list-disconnected.png");

  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await waitForPhase("CONNECTED / IDLE");
  const startPreview = page.getByRole("button", { name: "开始预览", exact: true });
  await requireMinimumTarget(startPreview, "Start Preview");
  await startPreview.click();
  await page.getByText("LIVE PREVIEW", { exact: true }).waitFor();
  await assertNoAcquisitionStimulationControls("preview");
  const widebandCanvas = page.getByRole("application", { name: /Live wideband bank traces/ });
  await widebandCanvas.waitFor();
  if ((await page.getByText("NO RUN", { exact: true }).count()) === 0) {
    throw new Error("Preview-before-Record should not create a Run");
  }
  const idleIntegrityRail = page.locator(".integrity-rail");
  if ((await idleIntegrityRail.getAttribute("data-run-result-state")) !== "idle"
      || (await idleIntegrityRail.locator("[data-operator-slot], [data-integrity-slot], [data-evidence-group]").count()) !== 0
      || (await idleIntegrityRail.locator('[aria-controls="integrity-technical-details"]').count()) !== 0) {
    throw new Error("No-Run footer is not one quiet Run result");
  }
  if ((await idleIntegrityRail.getByText("Preview 不创建 Run，也不会写入记录文件", { exact: true }).count()) !== 0) {
    throw new Error("No-Run recording status repeats an internal Preview contract");
  }
  await screenshot("02-preview-before-record.png");

  const directRow = page.locator('[data-pod-key="MOCK-DIRECT-01"]');
  await directRow.getByRole("button", { name: /重命名设备/ }).click();
  const renameDialog = page.getByRole("dialog", { name: "重命名 Pod" });
  await renameDialog.waitFor();
  await renameDialog.getByText("仅 mock 会话，不代表跨电脑写入设备 NVM。", { exact: true }).waitFor();
  const nameInput = renameDialog.getByLabel("设备显示名称");
  await nameInput.fill("Cortex Pod A");
  await renameDialog.getByRole("button", { name: "保存名称" }).click();
  await renameDialog.waitFor({ state: "hidden" });
  await directRow.getByText("Cortex Pod A", { exact: true }).waitFor();
  await directRow.getByText("MOCK NAME", { exact: true }).waitFor();
  await directRow.getByText("ID · MOCK-POD-SN-0001", { exact: true }).waitFor();
  await screenshot("03-device-renamed-mock-session.png");

  const widebandTab = page.getByRole("tab", { name: /WIDEBAND/ });
  const lfpTab = page.getByRole("tab", { name: /^LFP/ });
  const spikesTab = page.getByRole("tab", { name: /SPIKES/ });
  for (const target of [widebandTab, lfpTab, spikesTab]) {
    await requireMinimumTarget(target, "Signal view");
  }
  await lfpTab.click();
  await page.getByRole("application", { name: /Live LFP bank traces/ }).waitFor();
  await spikesTab.click();
  const spikeCanvas = page.locator('[data-testid="spike-raster-waveform"]');
  const spikeSummary = page.locator('[data-testid="spike-event-summary"]');
  await spikeCanvas.waitFor();
  const allWaveforms = page.getByRole("radio", { name: "全部", exact: true });
  const waveformStatistics = page.getByRole("radio", { name: "统计", exact: true });
  const latestWaveform = page.getByRole("radio", { name: "最新", exact: true });
  for (const [locator, label] of [
    [allWaveforms, "All Waveforms"],
    [waveformStatistics, "Waveform Statistics"],
    [latestWaveform, "Latest Waveform"],
  ]) {
    await requireMinimumTarget(locator, label);
  }
  await page.waitForFunction(() => {
    const canvas = document.querySelector('[data-testid="spike-raster-waveform"]');
    const observed = Number(canvas?.getAttribute("data-waveforms-observed"));
    const rendered = Number(canvas?.getAttribute("data-waveforms-rendered"));
    const omitted = Number(canvas?.getAttribute("data-waveforms-omitted"));
    const retentionSamples = Number(canvas?.getAttribute("data-waveform-retention-samples"));
    const sourceSampleSpan = Number(canvas?.getAttribute("data-source-sample-span"));
    return canvas?.getAttribute("data-waveform-mode") === "all"
      && canvas?.getAttribute("data-waveform-coverage") === "complete"
      && observed > 0
      && rendered === observed
      && omitted === 0
      && retentionSamples > 0
      && retentionSamples === sourceSampleSpan;
  });
  if ((await allWaveforms.getAttribute("aria-checked")) !== "true") {
    throw new Error("Selected-channel Spike view must default to All Waveforms");
  }

  await waveformStatistics.click();
  await page.waitForFunction(() => {
    const canvas = document.querySelector('[data-testid="spike-raster-waveform"]');
    return canvas?.getAttribute("data-waveform-mode") === "statistics"
      && canvas?.getAttribute("data-waveforms-rendered") === "1"
      && canvas?.getAttribute("data-waveforms-omitted") === "0";
  });
  await latestWaveform.click();
  await page.waitForFunction(() => {
    const canvas = document.querySelector('[data-testid="spike-raster-waveform"]');
    return canvas?.getAttribute("data-waveform-mode") === "latest"
      && canvas?.getAttribute("data-waveforms-rendered") === "1"
      && canvas?.getAttribute("data-waveforms-omitted") === "0";
  });
  await allWaveforms.click();
  await page.waitForFunction(() => {
    const canvas = document.querySelector('[data-testid="spike-raster-waveform"]');
    return canvas?.getAttribute("data-waveform-mode") === "all"
      && canvas?.getAttribute("data-waveforms-observed") === canvas?.getAttribute("data-waveforms-rendered");
  });

  await page.getByRole("button", { name: "每条 waveform 保留 2 秒", exact: true }).click();
  await page.waitForFunction(() => {
    const canvas = document.querySelector('[data-testid="spike-raster-waveform"]');
    return canvas?.getAttribute("data-window-seconds") === "2"
      && canvas?.getAttribute("data-waveform-retention-samples") === canvas?.getAttribute("data-source-sample-span")
      && Number(canvas?.getAttribute("data-waveform-retention-samples")) > 0;
  });
  await page.getByRole("button", { name: "每条 waveform 保留 1 秒", exact: true }).click();
  await page.waitForFunction(() => document.querySelector('[data-testid="spike-raster-waveform"]')
    ?.getAttribute("data-window-seconds") === "1");
  const bankEvents = Number(await spikeSummary.getAttribute("data-bank-events"));
  const renderedEvents = Number(await spikeSummary.getAttribute("data-rendered"));
  const omittedEvents = Number(await spikeSummary.getAttribute("data-preview-omitted"));
  if (bankEvents !== renderedEvents + omittedEvents || renderedEvents > 64) {
    throw new Error("Bounded Spike preview accounting is inconsistent");
  }
  for (const label of ["POD EVENTS", "BANK EVENTS", "RASTER DRAWN", "DISPLAY OMITTED", "SOURCE COVERAGE", "DETECTOR COVERAGE"]) {
    await page.getByText(label, { exact: true }).waitFor();
  }

  const recordingSetBeforeChannelSwitch = await page.locator('[data-pod-key][data-record-selected="true"]')
    .evaluateAll((elements) => elements.map((element) => element.getAttribute("data-pod-key")));
  for (const channel of [15, 16]) {
    await page.locator(`[data-testid="spike-activity-channel"][data-channel="${channel}"]`).click();
    await page.waitForFunction((selectedChannel) => {
      const button = document.querySelector(
        `[data-testid="spike-activity-channel"][data-channel="${selectedChannel}"]`,
      );
      const canvas = document.querySelector('[data-testid="spike-raster-waveform"]');
      const select = document.querySelector('select[aria-label="Waveform channel"]');
      const expectedBankStart = Math.floor(Number(selectedChannel) / 8) * 8;
      return button?.getAttribute("aria-pressed") === "true"
        && canvas?.getAttribute("data-bank-start") === String(expectedBankStart)
        && select instanceof HTMLSelectElement
        && select.value === String(selectedChannel);
    }, channel);
  }
  const recordingSetAfterChannelSwitch = await page.locator('[data-pod-key][data-record-selected="true"]')
    .evaluateAll((elements) => elements.map((element) => element.getAttribute("data-pod-key")));
  if (JSON.stringify(recordingSetAfterChannelSwitch) !== JSON.stringify(recordingSetBeforeChannelSwitch)) {
    throw new Error("Spike display-channel selection changed the Recording device set");
  }
  await screenshot("03b-spike-activity-channel-selection.png");

  const singleSetupButton = page.getByRole("button", { name: "单设备记录…", exact: true });
  const multiSetupButton = page.getByRole("button", { name: "多设备记录…", exact: true });
  await requireMinimumTarget(singleSetupButton, "Single-device Recording Setup");
  await requireMinimumTarget(multiSetupButton, "Multi-device Recording Setup");

  await singleSetupButton.click();
  const singleSetupDialog = page.getByRole("dialog", { name: "单设备记录设置" });
  await singleSetupDialog.waitFor();
  if ((await singleSetupDialog.locator('input[type="radio"]:checked').count()) !== 1) {
    throw new Error("Single-device setup did not freeze exactly the current Preview Pod");
  }
  if ((await singleSetupDialog.locator('input[type="checkbox"]').count()) !== 0) {
    throw new Error("Single-device setup unexpectedly exposed a multi-device checkbox draft");
  }
  await singleSetupDialog.getByRole("button", { name: "关闭记录设置", exact: true }).click();

  await multiSetupButton.click();
  const setupDialog = page.getByRole("dialog", { name: "多设备记录设置" });
  await setupDialog.waitFor();
  const closeSetup = setupDialog.getByRole("button", { name: "关闭记录设置", exact: true });
  if (!(await closeSetup.evaluate((element) => element === document.activeElement))) {
    throw new Error("Recording setup did not focus its non-destructive Close action");
  }
  const directoryInput = setupDialog.getByLabel("保存位置 · Run 根目录");
  const runNameInput = setupDialog.getByLabel("Run 名称前缀");
  const directoryPicker = setupDialog.getByRole("button", { name: "浏览文件夹…", exact: true });
  await requireMinimumTarget(directoryPicker, "Run directory picker");
  if (await directoryPicker.isEnabled()) {
    throw new Error("Browser mock unexpectedly enabled the desktop Run directory browser");
  }
  await directoryInput.fill("F:\\ForgeRuns");
  await runNameInput.fill("CORTEX-SESSION");
  const recordDeviceOptions = setupDialog.locator('input[type="checkbox"]');
  if ((await recordDeviceOptions.count()) !== 4
    || (await setupDialog.locator('input[type="checkbox"]:checked').count()) !== 0) {
    throw new Error("Multi-device setup must start with four available Pods and no implicit selection");
  }
  for (let index = 0; index < await recordDeviceOptions.count(); index += 1) {
    await recordDeviceOptions.nth(index).check();
  }
  if ((await setupDialog.locator('input[type="checkbox"]:checked').count()) !== 4) {
    throw new Error("Multi-device setup did not preserve four explicit operator selections");
  }
  const operatorConclusions = setupDialog.locator("[data-preflight-conclusion]");
  if ((await operatorConclusions.count()) !== 4) {
    throw new Error("Recording setup must expose exactly four operator conclusions");
  }
  for (let index = 0; index < 4; index += 1) {
    if (!(await operatorConclusions.nth(index).isVisible())) {
      throw new Error(`Operator conclusion ${index + 1} is not visible`);
    }
  }
  const technicalDetails = setupDialog.locator("details.preflight-technical-details");
  const technicalSummary = technicalDetails.locator("summary");
  await requireMinimumTarget(technicalSummary, "Preflight technical-details disclosure");
  if (await technicalDetails.evaluate((element) => element.open)) {
    throw new Error("Preflight technical details must be collapsed by default");
  }
  if (await setupDialog.locator(".preflight-check").first().isVisible()) {
    throw new Error("Engineering checks are visible in the default operator view");
  }
  await setupDialog.getByRole("button", { name: "检查并分配记录目标" }).click();
  const saveConclusion = setupDialog.locator('[data-preflight-conclusion="save-location"][data-allocation-state="simulated"]');
  await saveConclusion.waitFor();
  if (!(await saveConclusion.locator("strong").innerText()).includes("CORTEX-SESSION-001")) {
    throw new Error("Operator save-location conclusion did not expose the allocated Run name");
  }
  await setupDialog.locator('[data-preflight-conclusion="readiness"][data-state="ready"]').waitFor();
  if (await technicalDetails.evaluate((element) => element.open)) {
    throw new Error("Preflight completion unexpectedly expanded technical details");
  }
  await technicalSummary.focus();
  await page.keyboard.press("Enter");
  if (!(await technicalDetails.evaluate((element) => element.open))) {
    throw new Error("Technical details did not open from the keyboard");
  }
  await setupDialog.getByText("仅分配模拟名称 · 未创建文件", { exact: true }).waitFor();
  await page.keyboard.press("Enter");
  if (await technicalDetails.evaluate((element) => element.open)) {
    throw new Error("Technical details did not close from the keyboard");
  }
  const armRecording = setupDialog.getByRole("button", { name: "准备开始记录" });
  await armRecording.waitFor();
  await armRecording.focus();
  await screenshot("04-recording-target-preflight.png");
  await armRecording.click();
  await setupDialog.waitFor({ state: "hidden" });
  await waitForPhase("READY TO RECORD");
  await assertNoAcquisitionStimulationControls("record ready");

  const recordButtons = page.locator("button.instrument-button--record");
  if ((await recordButtons.count()) !== 1) throw new Error("Recording controls expose more than one actual Start action");
  const recordButton = page.getByRole("button", { name: "开始记录 · 4 台", exact: true });
  await requireMinimumTarget(recordButton, "Start Recording");
  await recordButton.click();
  await waitForPhase("RECORDING");
  await assertNoAcquisitionStimulationControls("recording");
  await page.getByText("LIVE PREVIEW", { exact: true }).waitFor();
  if ((await page.locator('[data-pod-key][data-record-selected="true"]').count()) !== 4) {
    throw new Error("Recording start changed the explicit device set");
  }
  await screenshot("05-recording-with-live-preview.png");

  const freezeDisplay = page.getByRole("button", { name: "冻结显示", exact: true });
  await freezeDisplay.click();
  const resumeDisplay = page.getByRole("button", { name: "恢复显示", exact: true });
  const frozenSequence = await spikeCanvas.getAttribute("data-frame-sequence");
  await page.waitForTimeout(220);
  if ((await spikeCanvas.getAttribute("data-frame-sequence")) !== frozenSequence) {
    throw new Error("Freeze Display did not freeze WebView presentation");
  }
  await resumeDisplay.click();

  await page.setViewportSize({ width: 1080, height: 720 });
  if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)) {
    throw new Error("1080x720 workspace has horizontal overflow");
  }
  const baselineWorkbench = await page.locator(".signal-workbench").boundingBox();
  await page.getByRole("button", { name: "进入信号聚焦" }).click();
  await page.waitForFunction(() => document.querySelector(".app-shell")?.getAttribute("data-signal-focus") === "true");
  for (const selector of [".pod-rack", ".control-stack", ".diagnostic-region"]) {
    if ((await page.locator(selector).getAttribute("data-collapsed")) !== "true") {
      throw new Error(`${selector} did not collapse in signal focus`);
    }
  }
  await page.evaluate(() => new Promise((resolveFrame) => requestAnimationFrame(() => requestAnimationFrame(resolveFrame))));
  const focusedWorkbench = await page.locator(".signal-workbench").boundingBox();
  const baselineArea = baselineWorkbench ? baselineWorkbench.width * baselineWorkbench.height : 0;
  const focusedArea = focusedWorkbench ? focusedWorkbench.width * focusedWorkbench.height : 0;
  if (!baselineWorkbench || !focusedWorkbench
    || focusedArea < baselineArea * 1.45) {
    throw new Error(`Signal Focus area ${focusedArea} did not exceed baseline ${baselineArea} by 1.45x`);
  }
  const compactEndAndSave = page.getByRole("button", { name: "结束并保存", exact: true });
  await requireMinimumTarget(compactEndAndSave, "Compact End and Save");
  if (!(await compactEndAndSave.isEnabled())) throw new Error("Compact End and Save is disabled while recording");
  if ((await page.locator(".control-rail__stim").count()) !== 0) {
    throw new Error("Collapsed acquisition controls still contain stimulation controls");
  }
  await screenshot("06-signal-focus-recording-1080x720.png");

  await page.getByRole("button", { name: "退出信号聚焦" }).click();
  await page.setViewportSize({ width: 1440, height: 920 });
  const sequenceBeforeEndAndSave = await spikeCanvas.getAttribute("data-frame-sequence");
  await page.getByRole("button", { name: "结束并保存", exact: true }).click();
  await waitForPhase("SIMULATION COMPLETE");
  await page.getByText("LIVE PREVIEW", { exact: true }).waitFor();
  await page.waitForFunction(
    (sequence) => document.querySelector('[data-testid="spike-raster-waveform"]')
      ?.getAttribute("data-frame-sequence") !== sequence,
    sequenceBeforeEndAndSave,
  );
  if ((await page.getByRole("button", { name: /Finalize|封存 Run/i }).count()) !== 0) {
    throw new Error("Recording controls still expose a second Finalize action");
  }
  await assertNoAcquisitionStimulationControls("finalized");
  await page.getByText("模拟流程完成", { exact: true }).first().waitFor();
  await page.getByText("未创建记录文件，也未生成 NWB。", { exact: true }).first().waitFor();
  const integrityRail = page.locator(".integrity-rail");
  const compactRailBox = await integrityRail.boundingBox();
  if (!compactRailBox || compactRailBox.height < 44 || compactRailBox.height > 53) {
    throw new Error(`Single Run result is ${compactRailBox?.height ?? "missing"}px high`);
  }
  if ((await integrityRail.getAttribute("data-run-result-state")) !== "mock_complete"
      || (await integrityRail.locator("[data-operator-slot], [data-integrity-slot], [data-evidence-group]").count()) !== 0
      || (await integrityRail.locator('[aria-controls="integrity-technical-details"]').count()) !== 0) {
    throw new Error("Final mock footer is not one simulation-only Run result");
  }
  const forbiddenResultCopy = /数据连续性|文件保存|Run 回执与输出|TECHNICAL DETAILS|外部事件|seq\s|模拟结束并保存完成|记录已结束并保存|ENDED \/ SAVED/;
  if (forbiddenResultCopy.test(await integrityRail.innerText())) {
    throw new Error("Removed evidence UI or false saved copy remains in the Run result");
  }
  await screenshot("07-simulation-complete-preview-continues.png");

  await page.setViewportSize({ width: 1080, height: 720 });
  if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)) {
    throw new Error("Single Run result causes horizontal overflow at 1080x720");
  }
  await screenshot("08-single-run-result-1080x720.png");

  if (errors.length > 0) throw new Error(errors.join("\n"));
  console.log("visual QA passed; screenshots:", outputDirectory);
} finally {
  await browser.close();
}
