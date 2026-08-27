import { chromium } from "playwright-core";

const cdpUrl = process.env.FORGE_TAURI_CDP_URL ?? "http://127.0.0.1:9223";
const runRoot = process.env.FORGE_E2E_RUN_ROOT ?? "F:\\ForgeRuns";
const singlePrefix = process.env.FORGE_E2E_SINGLE_PREFIX ?? "FORGE-SOFTWARE-SINGLE-VERIFY";
const multiPrefix = process.env.FORGE_E2E_MULTI_PREFIX ?? "FORGE-SOFTWARE-MULTI-VERIFY";
const recordHoldMs = Number.parseInt(process.env.FORGE_E2E_RECORD_HOLD_MS ?? "300", 10);
if (!Number.isSafeInteger(recordHoldMs) || recordHoldMs < 0 || recordHoldMs > 120_000) {
  throw new Error("FORGE_E2E_RECORD_HOLD_MS must be an integer from 0 through 120000");
}

const browser = await chromium.connectOverCDP(cdpUrl);
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
  const dialog = page.getByRole("dialog", { name: dialogLabel });
  await dialog.waitFor();
  await dialog.getByLabel("保存位置 · Run 根目录").fill(runRoot);
  await dialog.getByLabel("Run 名称前缀").fill(prefix);

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
  await dialog.getByText("TARGET CREATED NEW · NO OVERWRITE", { exact: true })
    .waitFor({ timeout: 15_000 });
  const resolvedRunDirectory = await dialog.locator(".recording-reservation strong").innerText();
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
  await page.getByRole("button", { name: "停止记录", exact: true }).click();
  await page.locator('[data-recording-save-state="sealed"]').waitFor({ timeout: 30_000 });
  await page.getByText("原始记录已安全封存", { exact: true }).waitFor();

  await expandControlRail();
  await waitForPhase("RECORDING STOPPED");
  await page.getByRole("button", { name: "Finalize / 封存 Run", exact: true }).click();
  await waitForPhase("FINALIZED");
  return resolvedRunDirectory.trim();
}

try {
  await ensureConnectedPreview();
  const singleRunDirectory = await recordAndSeal("single", 1, singlePrefix);
  const multiRunDirectory = await recordAndSeal("multi", 2, multiPrefix);
  if (errors.length) throw new Error(errors.join("\n"));
  process.stdout.write(`${JSON.stringify({
    adapter: "software",
    source: "deterministic_synthetic_canonical_sample_block",
    recordHoldMs,
    previewRestartedDuringSingleRecording: true,
    singleRunDirectory,
    multiRunDirectory,
  })}\n`);
} finally {
  await browser.close();
}
