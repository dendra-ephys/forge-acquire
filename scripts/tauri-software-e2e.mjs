import { chromium } from "playwright-core";

const cdpUrl = process.env.FORGE_TAURI_CDP_URL ?? "http://127.0.0.1:9223";
const runRoot = process.env.FORGE_E2E_RUN_ROOT ?? "F:\\ForgeRuns";
const singlePrefix = process.env.FORGE_E2E_SINGLE_PREFIX ?? "FORGE-SOFTWARE-SINGLE-VERIFY";
const multiPrefix = process.env.FORGE_E2E_MULTI_PREFIX ?? "FORGE-SOFTWARE-MULTI-VERIFY";
const recordHoldMs = Number.parseInt(process.env.FORGE_E2E_RECORD_HOLD_MS ?? "300", 10);
if (!Number.isSafeInteger(recordHoldMs) || recordHoldMs < 0 || recordHoldMs > 120_000) {
  throw new Error("FORGE_E2E_RECORD_HOLD_MS must be an integer from 0 through 120000");
}

async function resolveCdpEndpoint(value) {
  if (value.startsWith("ws://") || value.startsWith("wss://")) return value;
  const response = await fetch(`${value.replace(/\/$/, "")}/json/version`);
  if (!response.ok) throw new Error(`Tauri DevTools metadata returned HTTP ${response.status}`);
  const metadata = await response.json();
  if (typeof metadata.webSocketDebuggerUrl !== "string") {
    throw new Error("Tauri DevTools metadata has no WebSocket endpoint");
  }
  return metadata.webSocketDebuggerUrl;
}

const browser = await chromium.connectOverCDP(await resolveCdpEndpoint(cdpUrl));
const context = browser.contexts()[0];
if (!context) throw new Error("Tauri WebView CDP context is unavailable");
const page = context.pages().find((candidate) => candidate.url().includes("127.0.0.1:1421"))
  ?? context.pages()[0];
if (!page) throw new Error("Tauri WebView page is unavailable");

const errors = [];
page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
page.on("console", (message) => {
  if (message.type() === "error") errors.push(`console: ${message.text()}`);
});

async function waitForPhase(label) {
  await page.getByText(label, { exact: true }).first().waitFor({ timeout: 30_000 });
}

async function expandControlRail() {
  const expand = page.getByRole("button", { name: "展开采集控制栏", exact: true });
  if (await expand.isVisible().catch(() => false)) await expand.click();
}

async function ensureConnectedPreview() {
  await page.getByText("关闭窗口不会请求 Stop", { exact: true }).waitFor({ timeout: 15_000 });
  const connect = page.getByRole("button", { name: "Connect", exact: true });
  if (await connect.isEnabled().catch(() => false)) {
    await connect.click();
    await waitForPhase("CONNECTED / IDLE");
  }
  const startPreview = page.getByRole("button", { name: "开始预览", exact: true });
  if (await startPreview.isEnabled().catch(() => false)) {
    await startPreview.click();
  }
  await page.getByText("LIVE PREVIEW", { exact: true }).waitFor({ timeout: 15_000 });
}

async function recordAndSeal(mode, deviceCount, prefix) {
  await expandControlRail();
  const setupLabel = mode === "single" ? "单设备记录…" : "多设备记录…";
  const dialogLabel = mode === "single" ? "单设备记录设置" : "多设备记录设置";
  await page.getByRole("button", { name: setupLabel, exact: true }).click();
  const dialog = page.getByTestId("recording-setup-dialog");
  await dialog.waitFor();
  await dialog.getByRole("heading", { name: dialogLabel, exact: true }).waitFor();
  const directoryPicker = dialog.getByRole("button", { name: "浏览文件夹…", exact: true });
  if (!(await directoryPicker.isEnabled())) {
    throw new Error("desktop recording setup did not enable the Run directory browser");
  }
  await directoryPicker.click();
  const directoryBrowser = dialog.getByTestId("run-directory-browser");
  await directoryBrowser.waitFor();
  await page.keyboard.press("Escape");
  await directoryBrowser.waitFor({ state: "hidden" });
  await dialog.getByRole("heading", { name: dialogLabel, exact: true }).waitFor();
  if (!(await directoryPicker.evaluate((element) => element === document.activeElement))) {
    throw new Error("closing the Run directory browser did not restore focus to its opener");
  }

  await directoryPicker.click();
  await directoryBrowser.waitFor();
  const pathInput = dialog.getByLabel("文件夹路径", { exact: true });
  await pathInput.fill(runRoot);
  await dialog.getByRole("button", { name: "转到", exact: true }).click();
  await page.waitForFunction((expected) => {
    const element = document.querySelector('[data-testid="run-directory-current-path"]');
    const actual = element?.getAttribute("data-current-path") ?? "";
    const normalize = (value) => value.replace(/[\\/]+$/, "").toLocaleLowerCase();
    return normalize(actual) === normalize(expected);
  }, runRoot);
  await dialog.getByRole("button", { name: "使用当前文件夹", exact: true }).click();
  await directoryBrowser.waitFor({ state: "hidden" });
  const selectedRoot = await dialog.getByLabel("保存位置 · Run 根目录").inputValue();
  const normalizeRoot = (value) => value.replace(/[\\/]+$/, "").toLocaleLowerCase();
  if (normalizeRoot(selectedRoot) !== normalizeRoot(runRoot)) {
    throw new Error(`Run directory confirmation returned ${selectedRoot}, expected ${runRoot}`);
  }
  await dialog.getByLabel("Run 名称前缀").fill(prefix);

  const nwbBlocked = dialog.locator('[data-preflight-conclusion="final-output"][data-state="unavailable"]');
  if (await nwbBlocked.isVisible().catch(() => false)) {
    const preflight = dialog.getByRole("button", { name: "检查并分配记录目标" });
    if (await preflight.isEnabled()) {
      throw new Error("formal software recording is enabled without an NWB materializer capability");
    }
    await dialog.locator('[data-root-cause="nwb-output-unavailable"]').waitFor();
    await dialog.getByText("当前不能开始正式记录", { exact: true }).waitFor();
    await dialog.getByRole("button", { name: "关闭", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
    return { blocked: true, resolvedRunDirectory: null };
  }

  if (mode === "single") {
    if ((await dialog.locator('input[type="radio"]:checked').count()) !== 1) {
      throw new Error("single-device setup did not freeze exactly one Preview Pod");
    }
  } else {
    const choices = dialog.locator('input[type="checkbox"]');
    if ((await choices.count()) < deviceCount) {
      throw new Error(`multi-device setup exposed fewer than ${deviceCount} selectable Pods`);
    }
    for (let index = 0; index < deviceCount; index += 1) await choices.nth(index).check();
  }

  await dialog.getByRole("button", { name: "检查并分配记录目标" }).click();
  const saveConclusion = dialog.locator('[data-preflight-conclusion="save-location"][data-allocation-state="created_new"]');
  await saveConclusion.waitFor({ timeout: 15_000 });
  const resolvedRunDirectory = await saveConclusion.locator("strong").innerText();
  await dialog.getByRole("button", { name: "准备开始记录" }).click();
  await dialog.waitFor({ state: "hidden", timeout: 15_000 });
  await waitForPhase("READY TO RECORD");

  await page.getByRole("button", { name: `开始记录 · ${deviceCount} 台`, exact: true }).click();
  await waitForPhase("RECORDING");
  if (mode === "single") {
    await page.getByRole("button", { name: "停止预览", exact: true }).click();
    await page.getByRole("button", { name: "开始预览", exact: true }).click();
    await page.getByText("LIVE PREVIEW", { exact: true }).waitFor({ timeout: 15_000 });
    await waitForPhase("RECORDING");
  }
  await page.waitForTimeout(recordHoldMs);
  await page.getByRole("button", { name: "结束并保存", exact: true }).click();
  await page.locator('[data-run-result-state="nwb_saved"]').waitFor({ timeout: 30_000 });
  await page.getByText("NWB 已保存", { exact: true }).first().waitFor();
  await waitForPhase("NWB SAVED");
  await page.getByText("LIVE PREVIEW", { exact: true }).waitFor({ timeout: 15_000 });
  if ((await page.getByRole("button", { name: /Finalize|封存 Run/i }).count()) !== 0) {
    throw new Error("software flow still exposes a second Finalize action");
  }
  return { blocked: false, resolvedRunDirectory: resolvedRunDirectory.trim() };
}

try {
  await ensureConnectedPreview();
  const single = await recordAndSeal("single", 1, singlePrefix);
  const multi = single.blocked ? null : await recordAndSeal("multi", 2, multiPrefix);
  if (errors.length) throw new Error(errors.join("\n"));
  process.stdout.write(`${JSON.stringify({
    adapter: "software",
    source: "deterministic_synthetic_canonical_sample_block",
    finalNwbAdmission: single.blocked ? "blocked_no_nwb_materializer" : "available",
    recordHoldMs,
    previewRestartedDuringSingleRecording: !single.blocked,
    singleRunDirectory: single.resolvedRunDirectory,
    multiRunDirectory: multi?.resolvedRunDirectory ?? null,
  })}\n`);
} finally {
  await browser.close();
}
