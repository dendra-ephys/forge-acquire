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
  const bankEvents = Number(await spikeSummary.getAttribute("data-bank-events"));
  const renderedEvents = Number(await spikeSummary.getAttribute("data-rendered"));
  const omittedEvents = Number(await spikeSummary.getAttribute("data-preview-omitted"));
  if (bankEvents !== renderedEvents + omittedEvents || renderedEvents > 64) {
    throw new Error("Bounded Spike preview accounting is inconsistent");
  }
  for (const label of ["POD EVENTS", "BANK EVENTS", "RASTER DRAWN", "DISPLAY OMITTED", "SOURCE COVERAGE", "ANALYSIS COVERAGE"]) {
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
  await setupDialog.getByRole("button", { name: "检查并分配记录目标" }).click();
  await setupDialog.getByText("MOCK NAME ALLOCATED · NO FILE CREATED", { exact: true }).waitFor();
  await setupDialog.getByText(/CORTEX-SESSION-001/).first().waitFor();
  await setupDialog.getByText(/Recording Arm 只是 writer 写入互锁，不是刺激授权/).waitFor();
  await setupDialog.getByRole("button", { name: "准备开始记录" }).waitFor();
  await screenshot("04-recording-target-preflight.png");
  await setupDialog.getByRole("button", { name: "准备开始记录" }).click();
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
  for (const selector of [".pod-rack", ".control-stack", ".diagnostic-region", ".integrity-rail"]) {
    if ((await page.locator(selector).getAttribute("data-collapsed")) !== "true") {
      throw new Error(`${selector} did not collapse in signal focus`);
    }
  }
  const focusedWorkbench = await page.locator(".signal-workbench").boundingBox();
  if (!baselineWorkbench || !focusedWorkbench
    || focusedWorkbench.width * focusedWorkbench.height < baselineWorkbench.width * baselineWorkbench.height * 1.45) {
    throw new Error("Signal Focus did not materially enlarge the data surface");
  }
  const compactStop = page.getByRole("button", { name: "停止记录", exact: true });
  await requireMinimumTarget(compactStop, "Compact Stop Recording");
  if (!(await compactStop.isEnabled())) throw new Error("Compact Stop Recording is disabled while recording");
  if ((await page.locator(".control-rail__stim").count()) !== 0) {
    throw new Error("Collapsed acquisition controls still contain stimulation controls");
  }
  await screenshot("06-signal-focus-recording-1080x720.png");

  await page.getByRole("button", { name: "退出信号聚焦" }).click();
  await page.setViewportSize({ width: 1440, height: 920 });
  const sequenceBeforeStop = await spikeCanvas.getAttribute("data-frame-sequence");
  await page.getByRole("button", { name: "停止记录", exact: true }).click();
  await waitForPhase("RECORDING STOPPED");
  await page.getByText("LIVE PREVIEW", { exact: true }).waitFor();
  await page.waitForFunction(
    (sequence) => document.querySelector('[data-testid="spike-raster-waveform"]')
      ?.getAttribute("data-frame-sequence") !== sequence,
    sequenceBeforeStop,
  );
  await page.getByText("记录输入已停止；Preview 可继续", { exact: true }).waitFor();
  await page.getByText("已停止 · 尚未安全封存", { exact: true }).waitFor();
  await screenshot("07-recording-stopped-preview-continues.png");

  const finalizeButton = page.getByRole("button", { name: "Finalize / 封存 Run", exact: true });
  await requireMinimumTarget(finalizeButton, "Finalize");
  const sequenceBeforeFinalize = await spikeCanvas.getAttribute("data-frame-sequence");
  await finalizeButton.click();
  await waitForPhase("FINALIZED");
  await page.getByText("LIVE PREVIEW", { exact: true }).waitFor();
  await page.waitForFunction(
    (sequence) => document.querySelector('[data-testid="spike-raster-waveform"]')
      ?.getAttribute("data-frame-sequence") !== sequence,
    sequenceBeforeFinalize,
  );
  await assertNoAcquisitionStimulationControls("finalized");
  await page.getByText("模拟封存完成", { exact: true }).waitFor();
  await page.getByText("未创建真实文件；仅验证界面与回执流程", { exact: true }).waitFor();
  await page.getByRole("button", { name: "展开记录保存状态" }).click();
  for (const group of ["recording-core", "optional-results"]) {
    const groupLocator = page.locator(`[data-evidence-group="${group}"]`);
    if ((await groupLocator.count()) !== 1) throw new Error(`Evidence group ${group} is missing or duplicated`);
  }
  for (const slot of ["acquisition", "durability", "nwb", "analysis", "stimReceipt"]) {
    if ((await page.locator(`[data-integrity-slot="${slot}"]`).count()) !== 1) {
      throw new Error(`Evidence slot ${slot} is missing or duplicated`);
    }
  }
  const expectedMembership = {
    "recording-core": ["acquisition", "durability"],
    "optional-results": ["nwb", "analysis", "stimReceipt"],
  };
  for (const [group, slots] of Object.entries(expectedMembership)) {
    const groupLocator = page.locator(`[data-evidence-group="${group}"]`);
    const actual = await groupLocator.locator("[data-integrity-slot]").evaluateAll((elements) =>
      elements.map((element) => element.getAttribute("data-integrity-slot")));
    if (JSON.stringify(actual) !== JSON.stringify(slots)) {
      throw new Error(`Evidence group ${group} has ${JSON.stringify(actual)}, expected ${JSON.stringify(slots)}`);
    }
  }
  await page.getByText(/停止记录 ≠ 保存完成；只有“数据接收与采集范围”和“文件写入与封存”都确认/).waitFor();
  await page.getByText("这 5 项用来回答两个不同问题", { exact: true }).waitFor();
  await page.getByText("外部事件时间线", { exact: true }).waitFor();
  if ((await page.getByText("Stim Receipt", { exact: true }).count()) !== 0) {
    throw new Error("Recording status still presents an ambiguous Stim Receipt lane");
  }
  await screenshot("08-finalized-grouped-run-evidence.png");

  await page.setViewportSize({ width: 1080, height: 720 });
  if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)) {
    throw new Error("Expanded Run evidence causes horizontal overflow at 1080x720");
  }
  const rawGroup = await page.locator('[data-evidence-group="recording-core"]').boundingBox();
  const optionalGroup = await page.locator('[data-evidence-group="optional-results"]').boundingBox();
  if (!rawGroup || !optionalGroup || rawGroup.width < optionalGroup.width * 0.6) {
    throw new Error("The two mandatory raw-recording checks became unreadably narrow beside the three optional receipts");
  }
  await screenshot("09-finalized-evidence-1080x720.png");

  if (errors.length > 0) throw new Error(errors.join("\n"));
  console.log("visual QA passed; screenshots:", outputDirectory);
} finally {
  await browser.close();
}
