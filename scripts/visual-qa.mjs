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

async function requireMinimumTarget(locator, label, minimum = 36) {
  const box = await locator.boundingBox();
  if (!box || box.width < minimum || box.height < minimum) {
    throw new Error(`${label} target is ${box?.width ?? 0}x${box?.height ?? 0}px`);
  }
}

async function requireSlenderSurface(locator, label, maxHeight, minimumAspectRatio = 1) {
  const box = await locator.boundingBox();
  if (!box || box.height > maxHeight || box.width / box.height < minimumAspectRatio) {
    throw new Error(
      `${label} is ${box?.width ?? 0}x${box?.height ?? 0}px; expected height <= ${maxHeight}px and aspect >= ${minimumAspectRatio}`,
    );
  }
}

async function requireSharedVerticalCenter(locator, label, tolerance = 2) {
  const boxes = await locator.evaluateAll((elements) => elements.map((element) => {
    const box = element.getBoundingClientRect();
    return { top: box.top, bottom: box.bottom, center: box.top + box.height / 2 };
  }));
  if (boxes.length < 2) throw new Error(`${label} needs at least two elements to compare`);
  const centers = boxes.map((box) => box.center);
  if (Math.max(...centers) - Math.min(...centers) > tolerance) {
    throw new Error(`${label} vertical centers diverge: ${centers.join(", ")}`);
  }
}

async function requireUniformTwoRowTrack(dotLocator, labelLocator, label) {
  const dots = await dotLocator.evaluateAll((elements) => elements.map((element) => {
    const box = element.getBoundingClientRect();
    return { top: box.top, bottom: box.bottom };
  }));
  const labels = await labelLocator.evaluateAll((elements) => elements.map((element) => {
    const box = element.getBoundingClientRect();
    return { top: box.top, bottom: box.bottom };
  }));
  if (dots.length === 0 || dots.length !== labels.length) {
    throw new Error(`${label} has ${dots.length} dots and ${labels.length} labels`);
  }
  const dotTops = dots.map((box) => box.top);
  const labelTops = labels.map((box) => box.top);
  if (Math.max(...dotTops) - Math.min(...dotTops) > 1
      || Math.max(...labelTops) - Math.min(...labelTops) > 1
      || Math.max(...dots.map((box) => box.bottom)) > Math.min(...labelTops)) {
    throw new Error(`${label} dots, labels, or track rows overlap or lose their shared baseline`);
  }
}

async function requireNoHorizontalScroll(locator, label) {
  const metrics = await locator.evaluate((element) => ({
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth,
    overflowX: getComputedStyle(element).overflowX,
    scrollbarHeight: element.offsetHeight - element.clientHeight,
  }));
  // Hover tooltips may extend the element's logical scroll width, but the pane
  // must clip that extent and must never reserve a visible horizontal gutter.
  if (metrics.overflowX !== "hidden" || metrics.scrollbarHeight > 1) {
    throw new Error(
      `${label} exposes a horizontal scrollbar: ${metrics.clientWidth}/${metrics.scrollWidth}px, ${metrics.overflowX}, ${metrics.scrollbarHeight}px gutter`,
    );
  }
}

async function requireToolbarAlignment() {
  const primary = page.locator(".signal-toolbar__primary");
  const title = page.locator(".signal-title");
  const deviceName = title.locator(".signal-device-name");
  const tabs = title.locator(".signal-view-tabs");
  const displayControls = page.locator(".preview-display-controls");
  const clusters = displayControls.locator(".preview-control-cluster");
  const viewport = page.locator(".trace-stage__viewport");
  const metadata = displayControls.locator(".preview-trace-metadata");
  const traceThemeToggle = displayControls.locator(".trace-theme-toggle");
  const [primaryBox, titleBox, deviceNameBox, tabsBox, displayBox, viewportBox, metadataBox, traceThemeBox, clusterBoxes, toolbarItemBoxes] = await Promise.all([
    primary.boundingBox(),
    title.boundingBox(),
    deviceName.boundingBox(),
    tabs.boundingBox(),
    displayControls.boundingBox(),
    viewport.boundingBox(),
    metadata.boundingBox(),
    traceThemeToggle.boundingBox(),
    clusters.evaluateAll((elements) => elements.map((element) => {
      const box = element.getBoundingClientRect();
      return { x: box.x, right: box.right, y: box.y, bottom: box.bottom };
    })),
    primary.locator(":scope > *").evaluateAll((elements) => elements
      .filter((element) => getComputedStyle(element).display !== "none")
      .map((element) => {
        const box = element.getBoundingClientRect();
        return { x: box.x, right: box.right, centerY: box.y + box.height / 2 };
      })),
  ]);
  if (!primaryBox || !titleBox || !deviceNameBox || !tabsBox || !displayBox || !viewportBox || !metadataBox || !traceThemeBox || clusterBoxes.length !== 2) {
    throw new Error("Signal toolbar or trace surface is missing a required component boundary");
  }
  const clusterGap = clusterBoxes[1].x - clusterBoxes[0].right;
  const primaryCenterY = primaryBox.y + primaryBox.height / 2;
  const titleParts = [deviceNameBox, tabsBox];
  const hasToolbarOverlap = toolbarItemBoxes.some((box, index) => index > 0 && box.x < toolbarItemBoxes[index - 1].right - 1);
  if (titleParts.some((box) => Math.abs((box.y + box.height / 2) - primaryCenterY) > 3)
      || toolbarItemBoxes.some((box) => Math.abs(box.centerY - primaryCenterY) > 3)
      || hasToolbarOverlap
      || (await tabs.evaluate((element) => !element.parentElement?.classList.contains("signal-title")))
      || !(await metadata.textContent())?.includes("1.0 s")
      || (await metadata.textContent())?.includes("CH ")
      || (await metadata.textContent())?.includes("SYNTHETIC")
      || (await metadata.locator(".preview-trace-metadata__metric--range strong").textContent())?.trim() !== "±200"
      || (await metadata.locator(".preview-trace-metadata__metric--range em").textContent())?.trim() !== "µV"
      || !((await metadata.getAttribute("data-tooltip")) ?? "").includes("mock preview source")
      || Math.abs((metadataBox.y + metadataBox.height / 2) - (displayBox.y + displayBox.height / 2)) > 2
      || !(await metadata.evaluate((element) => element.parentElement?.classList.contains("preview-display-controls")))
      || Math.abs(displayBox.bottom - viewportBox.y) > 1
      || clusterBoxes.some((box) => box.y < displayBox.y || box.bottom > displayBox.bottom)
      || traceThemeBox.x - clusterBoxes[1].right < 4
      || displayBox.x + displayBox.width - traceThemeBox.x - traceThemeBox.width > 10
      || clusterGap < 4 || clusterGap > 12
      || !(await traceThemeToggle.evaluate((element) => element === element.parentElement?.lastElementChild))
      || (await page.locator(".signal-input-contract").count()) !== 0
      || (await page.locator(".signal-toolbar__controls").count()) !== 0) {
    throw new Error(`Signal toolbar or trace-top controls lost their intended grouping: ${JSON.stringify({ primaryBox, titleBox, deviceNameBox, tabsBox, displayBox, viewportBox, metadataBox, traceThemeBox, clusterBoxes, toolbarItemBoxes, clusterGap, hasToolbarOverlap })}`);
  }
}

async function requireIndependentTraceTheme() {
  const stage = page.locator(".trace-stage");
  const outerTheme = await page.locator("html").getAttribute("data-theme");
  const toggle = page.getByRole("button", { name: "Switch signal display to light theme", exact: true });
  await requireMinimumTarget(toggle, "Signal display theme", 30);
  await toggle.click();
  if ((await stage.getAttribute("data-trace-theme")) !== "light"
      || (await stage.evaluate((element) => getComputedStyle(element).filter)) === "none"
      || (await page.locator("html").getAttribute("data-theme")) !== outerTheme) {
    throw new Error("Signal display theme is not independent from the application theme");
  }
  await screenshot("00-inner-light-signal-theme.png");
  await page.getByRole("button", { name: "Switch signal display to dark theme", exact: true }).click();
  if ((await stage.getAttribute("data-trace-theme")) !== "dark") {
    throw new Error("Signal display theme did not return to dark mode");
  }
}

async function requireCompactRaisedRunButtons() {
  const panel = page.locator(".run-control");
  const preview = page.locator("button.instrument-button--preview");
  const start = page.locator("button.instrument-button--record");
  const pause = page.locator("button.instrument-button--pause");
  const stop = page.locator("button.instrument-button--stop");
  const [panelColor, previewColor, startColor, pauseColor, stopColor, previewBox, startBox, pauseBox, stopBox] = await Promise.all([
    panel.evaluate((element) => getComputedStyle(element).backgroundColor),
    preview.evaluate((element) => getComputedStyle(element).backgroundColor),
    start.evaluate((element) => getComputedStyle(element).backgroundColor),
    pause.evaluate((element) => getComputedStyle(element).backgroundColor),
    stop.evaluate((element) => getComputedStyle(element).backgroundColor),
    preview.boundingBox(),
    start.boundingBox(),
    pause.boundingBox(),
    stop.boundingBox(),
  ]);
  if (!previewBox || !startBox || !pauseBox || !stopBox
      || Math.abs(previewBox.y - startBox.y) > 1
      || Math.abs(previewBox.width - startBox.width) > 2
      || Math.abs(previewBox.height - startBox.height) > 1
      || startBox.height < 36 || pauseBox.height < 32 || stopBox.height < 32
      || Math.abs(pauseBox.height - stopBox.height) > 1
      || Math.abs(pauseBox.width - stopBox.width) > 2) {
    throw new Error(
      `Run controls lost the requested two-row hierarchy: Preview ${previewBox?.width ?? 0}x${previewBox?.height ?? 0}px, Start ${startBox?.width ?? 0}x${startBox?.height ?? 0}px, Pause ${pauseBox?.width ?? 0}x${pauseBox?.height ?? 0}px, End ${stopBox?.width ?? 0}x${stopBox?.height ?? 0}px`,
    );
  }
  if (previewColor === panelColor || startColor === panelColor || pauseColor === panelColor || stopColor === panelColor) {
    throw new Error("Run buttons do not use a raised surface distinct from the acquisition panel");
  }
}

async function requireDistinctSurface(locator, parent, label) {
  const [surfaceColor, parentColor] = await Promise.all([
    locator.evaluate((element) => getComputedStyle(element).backgroundColor),
    parent.evaluate((element) => getComputedStyle(element).backgroundColor),
  ]);
  if (surfaceColor === parentColor || surfaceColor === "rgba(0, 0, 0, 0)") {
    throw new Error(`${label} does not use a distinct raised background: ${surfaceColor}`);
  }
}

async function requireSharedWorkspaceToolbar() {
  const [toolbarBox, signalBox, controlBox] = await Promise.all([
    page.locator(".workspace-signal-toolbar").boundingBox(),
    page.locator(".signal-workbench").boundingBox(),
    page.locator(".run-control").boundingBox(),
  ]);
  if (!toolbarBox || !signalBox || !controlBox
      || Math.abs(toolbarBox.x - signalBox.x) > 1
      || Math.abs(toolbarBox.x + toolbarBox.width - (controlBox.x + controlBox.width)) > 1
      || Math.abs(toolbarBox.y + toolbarBox.height - signalBox.y) > 1
      || Math.abs(toolbarBox.y + toolbarBox.height - controlBox.y) > 1) {
    throw new Error(`Signal toolbar is not the shared upper edge: ${JSON.stringify({ toolbarBox, signalBox, controlBox })}`);
  }
}

async function requireNoOverlap(locator, label) {
  const boxes = await locator.evaluateAll((elements) => elements.map((element) => {
    const box = element.getBoundingClientRect();
    return { left: box.left, right: box.right, top: box.top, bottom: box.bottom };
  }));
  for (let first = 0; first < boxes.length; first += 1) {
    for (let second = first + 1; second < boxes.length; second += 1) {
      const a = boxes[first];
      const b = boxes[second];
      const overlaps = Math.min(a.right, b.right) - Math.max(a.left, b.left) > 0.5
        && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 0.5;
      if (overlaps) throw new Error(`${label} overlap: ${JSON.stringify({ a, b })}`);
    }
  }
}

async function requireBodyPortalTooltip(locator, label) {
  await locator.waitFor();
  const metrics = await locator.evaluate((element) => {
    const box = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    return {
      parentIsBody: element.parentElement === document.body,
      position: style.position,
      zIndex: Number(style.zIndex),
      left: box.left,
      right: box.right,
      top: box.top,
      bottom: box.bottom,
    };
  });
  if (!metrics.parentIsBody || metrics.position !== "fixed" || metrics.zIndex < 1000000
      || metrics.left < 0 || metrics.top < 0
      || metrics.right > await page.evaluate(() => window.innerWidth)
      || metrics.bottom > await page.evaluate(() => window.innerHeight)) {
    throw new Error(`${label} is not a viewport-bounded top-layer portal: ${JSON.stringify(metrics)}`);
  }
  return metrics;
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
  await page.getByRole("heading", { name: "Devices" }).waitFor();
  await page.getByText("Direct to PC", { exact: true }).waitFor();
  await page.getByRole("application", { name: /Live wideband bank traces/ }).waitFor();
  const acquisitionToggle = page.getByRole("button", { name: "Expand acquisition controls", exact: true });
  await acquisitionToggle.waitFor();
  if ((await page.locator(".bench-workspace").getAttribute("data-controls-collapsed")) !== "true"
      || (await page.locator(".run-control").count()) !== 0) {
    throw new Error("Acquisition sidebar is not closed by default");
  }
  const collapsedToolbarBox = await page.locator(".workspace-signal-toolbar").boundingBox();
  const collapsedWorkbenchBox = await page.locator(".signal-workbench").boundingBox();
  const workspaceBox = await page.locator(".bench-workspace").boundingBox();
  if (!collapsedToolbarBox || !collapsedWorkbenchBox || !workspaceBox
      || Math.abs(collapsedToolbarBox.y + collapsedToolbarBox.height - collapsedWorkbenchBox.y) > 1
      || Math.abs(collapsedToolbarBox.x + collapsedToolbarBox.width - (workspaceBox.x + workspaceBox.width)) > 1) {
    throw new Error("Collapsed acquisition layout does not leave one full-width toolbar above the signal surface");
  }
  await page.setViewportSize({ width: 1298, height: 698 });
  await screenshot("00a-default-acquisition-collapsed-1298x698.png");
  await page.setViewportSize({ width: 1440, height: 920 });
  await acquisitionToggle.click();
  await page.getByRole("heading", { name: "Acquisition", exact: true }).waitFor();
  await requireSharedWorkspaceToolbar();
  if ((await page.locator(".bench-header, .run-spine, .run-spine__steps").count()) !== 0) {
    throw new Error("Removed global header or recording lifecycle marquee remains visible");
  }
  if ((await page.getByRole("button", { name: "About the independent acquisition service", exact: true }).count()) !== 0
      || (await page.locator(".diagnostic-toggle, .diagnostic-region").count()) !== 0) {
    throw new Error("Operator workspace still exposes engineering-only information or Diagnostics controls");
  }
  const railBrand = page.locator(".pod-rack > .pod-rack-brand");
  await requireSlenderSurface(railBrand, "Devices rail brand", 40, 3);
  if (!(await railBrand.evaluate((element) => element.nextElementSibling?.classList.contains("instrument-section-heading")))) {
    throw new Error("Forge Acquire brand is not immediately above the Devices heading");
  }
  if ((await railBrand.locator(".forge-wave-mark path").count()) !== 1
      || (await railBrand.locator("svg.lucide-waves").count()) !== 0) {
    throw new Error("Devices brand does not use the waveform extracted from the application icon");
  }
  const appearanceFooter = page.locator(".pod-rack > .pod-rack-footer");
  if ((await appearanceFooter.locator(".theme-toggle").count()) !== 1
      || (await page.locator(".signal-toolbar .theme-toggle").count()) !== 0
      || !(await appearanceFooter.evaluate((element) => element === element.parentElement?.lastElementChild))) {
    throw new Error("Theme control is not isolated in the bottom Devices footer");
  }
  const [footerBackground, themeBackground] = await Promise.all([
    appearanceFooter.evaluate((element) => getComputedStyle(element).backgroundColor),
    appearanceFooter.locator(".theme-toggle").evaluate((element) => getComputedStyle(element).backgroundColor),
  ]);
  if (footerBackground !== themeBackground) {
    throw new Error("Devices theme control background does not follow the active application theme");
  }
  for (const selector of [".rack-count", ".pod-rack-compact-count", ".pod-rack-compact-routes > span"]) {
    if (await page.locator(selector).evaluateAll((elements) => elements.some((element) => !element.getAttribute("data-tooltip")?.trim()))) {
      throw new Error(`${selector} is missing a detailed hover explanation`);
    }
  }
  for (const removedSelector of [".adapter-readout", ".header-facts", ".run-spine__title"]) {
    if ((await page.locator(removedSelector).count()) !== 0) {
      throw new Error(`${removedSelector} remains in the title bar`);
    }
  }
  await requireSlenderSurface(page.locator(".signal-toolbar"), "Signal toolbar", 96, 5);
  await requireToolbarAlignment();
  await requireIndependentTraceTheme();
  await requireCompactRaisedRunButtons();
  if ((await page.locator(".recording-storage-strip, .recording-storage-item").count()) !== 0) {
    throw new Error("Recording storage still occupies a dedicated signal footer");
  }
  const runResultStatus = page.locator(".run-control__device-status .integrity-rail");
  const runResultTooltipText = await runResultStatus.getAttribute("data-tooltip") ?? "";
  if (!runResultTooltipText.includes("File size: NO FILE")
      || !runResultTooltipText.includes("Storage free: —")) {
    throw new Error(`Run result does not carry recording storage hover details: ${runResultTooltipText}`);
  }
  await runResultStatus.hover();
  const runResultTooltip = page.locator(".global-tooltip").filter({ hasText: "File size: NO FILE" });
  await requireBodyPortalTooltip(runResultTooltip, "Run result storage tooltip");
  if ((await page.locator(".signal-readout-strip, .load-indicator").count()) !== 0) {
    throw new Error("Internal signal/load telemetry remains in the operator footer");
  }
  for (const removedLabel of ["SOURCE FIFO", "WRITER QUEUE", "CONTROL LOAD", "WEBVIEW RAW", "CH EVENTS / SOURCE"]) {
    if ((await page.getByText(removedLabel, { exact: true }).count()) !== 0) {
      throw new Error(`${removedLabel} remains in the operator workspace`);
    }
  }
  await requireSharedVerticalCenter(
    page.locator(".run-control > .instrument-section-heading h2, .run-control > .instrument-section-heading .info-hint__trigger, .run-control > .instrument-section-heading .phase-chip, .run-control > .instrument-section-heading .panel-collapse-button"),
    "Acquisition heading row",
  );
  const initialWidebandCanvas = page.getByRole("application", { name: /Live wideband bank traces/ });
  await initialWidebandCanvas.waitFor();
  if ((await page.locator(".trace-empty, .run-flow").count()) !== 0) {
    throw new Error("Recognized devices still show an empty trace or decorative recording lifecycle");
  }
  if ((await page.getByRole("button", { name: /^(Connect|Disconnect)$/ }).count()) !== 0) {
    throw new Error("Acquisition panel still exposes an internal connection control");
  }
  const acquisitionPanel = page.locator(".run-control");
  if ((await page.locator(".preview-session-card").count()) !== 0) {
    throw new Error("Redundant Preview status component remains in the acquisition panel");
  }
  await requireDistinctSurface(page.getByRole("button", { name: "Single-device setup", exact: true }), acquisitionPanel, "Single-device setup button");
  await page.getByRole("button", { name: "Single-device setup", exact: true }).getByText("Setup", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Multi-device setup", exact: true }).getByText("Multi-Pod", { exact: true }).waitFor();
  const divider = await page.locator(".run-control > .instrument-section-heading").evaluate((element) => {
    const style = getComputedStyle(element, "::after");
    return { height: Number.parseFloat(style.height), color: style.backgroundColor };
  });
  if (divider.height < 3 || divider.color === "rgba(0, 0, 0, 0)") {
    throw new Error(`Acquisition heading divider is missing or too faint: ${JSON.stringify(divider)}`);
  }
  const directDisclosure = page.getByRole("button", { name: /^Direct to PC/ });
  const firstDirectRow = page.locator('[data-pod-key="MOCK-DIRECT-01"]');
  await requireSlenderSurface(directDisclosure, "Direct device group", 38, 4);
  await requireSlenderSurface(firstDirectRow.locator(".pod-leaf"), "Device navigation row", 40, 3);
  if (await firstDirectRow.evaluate((element) => getComputedStyle(element).borderTopWidth !== "0px")) {
    throw new Error("Device navigation row still renders as a bordered card");
  }
  const firstDirectActions = firstDirectRow.locator(".pod-device-actions");
  const firstDirectState = firstDirectRow.locator(".pod-leaf__state");
  if (Number(await firstDirectActions.evaluate((element) => getComputedStyle(element).opacity)) !== 0) {
    throw new Error("Secondary device actions should be hidden until hover or focus");
  }
  if (Number(await firstDirectState.evaluate((element) => getComputedStyle(element).opacity)) !== 0) {
    throw new Error("Device status affordance should be hidden until hover or focus");
  }
  await firstDirectRow.hover();
  await page.waitForFunction(() => {
    const row = document.querySelector('[data-pod-key="MOCK-DIRECT-01"]');
    const actions = row?.querySelector(".pod-device-actions");
    const state = row?.querySelector(".pod-leaf__state");
    return actions && state
      && Number(getComputedStyle(actions).opacity) === 1
      && Number(getComputedStyle(state).opacity) === 1;
  });
  if (Number(await firstDirectActions.evaluate((element) => getComputedStyle(element).opacity)) !== 1) {
    throw new Error("Secondary device actions did not appear on row hover");
  }
  if (Number(await firstDirectState.evaluate((element) => getComputedStyle(element).opacity)) !== 1) {
    throw new Error("Device status affordance did not appear on row hover");
  }
  if ((await firstDirectRow.locator(".pod-record-toggle").count()) !== 0) {
    throw new Error("Device row still duplicates multi-device recording selection");
  }
  await requireSharedVerticalCenter(
    firstDirectRow.locator(".pod-leaf__body strong, .pod-leaf__state, .pod-device-actions"),
    "Device row",
  );
  await directDisclosure.click();
  if ((await directDisclosure.getAttribute("aria-expanded")) !== "false" || await firstDirectRow.isVisible()) {
    throw new Error("Direct device group did not collapse like a project list");
  }
  await directDisclosure.click();
  await firstDirectRow.waitFor();

  const deviceResizer = page.getByRole("separator", { name: "Resize device list" });
  const initialDeviceWidth = Number(await deviceResizer.getAttribute("aria-valuenow"));
  const resizeBox = await deviceResizer.boundingBox();
  if (!resizeBox) throw new Error("Device-list resize separator has no layout box");
  await page.mouse.move(resizeBox.x + resizeBox.width / 2, resizeBox.y + 80);
  await page.mouse.down();
  await page.mouse.move(resizeBox.x + resizeBox.width / 2 + 24, resizeBox.y + 80);
  await page.mouse.up();
  if (Number(await deviceResizer.getAttribute("aria-valuenow")) !== initialDeviceWidth + 24) {
    throw new Error("Device-list resize separator did not respond to pointer drag");
  }
  const resizedBox = await deviceResizer.boundingBox();
  if (!resizedBox) throw new Error("Resized device-list separator has no layout box");
  await page.mouse.move(resizedBox.x + resizedBox.width / 2, resizedBox.y + 80);
  await page.mouse.down();
  await page.mouse.move(resizedBox.x + resizedBox.width / 2 - 24, resizedBox.y + 80);
  await page.mouse.up();
  await deviceResizer.focus();
  const widthBeforeKeyboard = Number(await deviceResizer.getAttribute("aria-valuenow"));
  await page.keyboard.press("ArrowRight");
  await page.waitForFunction(
    (expected) => Number(document.querySelector('.pod-column-resizer')?.getAttribute("aria-valuenow")) === expected,
    Math.min(360, widthBeforeKeyboard + 8),
  );
  if (Number(await deviceResizer.getAttribute("aria-valuenow")) !== Math.min(360, widthBeforeKeyboard + 8)) {
    throw new Error("Device-list resize separator did not respond to the keyboard");
  }
  await page.keyboard.press("ArrowLeft");
  for (const [selector, label] of [[".pod-topology", "Device connections"], [".run-control", "Acquisition panel"]]) {
    await requireNoHorizontalScroll(page.locator(selector), label);
  }

  await page.setViewportSize({ width: 1298, height: 698 });
  if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)) {
    throw new Error("1298x698 workspace has horizontal overflow");
  }
  await requireNoHorizontalScroll(page.locator(".pod-topology"), "Device connections at 1298x698");
  await requireNoHorizontalScroll(page.locator(".run-control"), "Acquisition panel at 1298x698");
  await requireToolbarAlignment();
  await requireCompactRaisedRunButtons();
  await screenshot("00b-browser-review-1298x698.png");

  const secondAggregatedPod = page.getByRole("button", { name: /Preview Mock Aggregated Pod 2/ });
  await secondAggregatedPod.hover();
  const deviceTooltip = page.locator(".global-tooltip");
  const deviceTooltipMetrics = await requireBodyPortalTooltip(deviceTooltip, "Device tooltip");
  const podRackBox = await page.locator(".pod-rack").boundingBox();
  if (!podRackBox || deviceTooltipMetrics.right <= podRackBox.x + podRackBox.width) {
    throw new Error("Device tooltip does not escape the device pane into the global top layer");
  }
  await screenshot("00c-device-tooltip-top-layer-1298x698.png");

  const acquisitionInfo = page.getByRole("button", { name: "About the current acquisition state", exact: true });
  await acquisitionInfo.hover();
  const acquisitionTooltip = page.locator(".info-hint__popover--portal");
  const acquisitionTooltipMetrics = await requireBodyPortalTooltip(acquisitionTooltip, "Acquisition tooltip");
  const runControlBox = await page.locator(".run-control").boundingBox();
  if (!runControlBox || acquisitionTooltipMetrics.left >= runControlBox.x) {
    throw new Error("Acquisition tooltip does not escape the control pane into the global top layer");
  }
  await screenshot("00d-acquisition-tooltip-top-layer-1298x698.png");
  await page.setViewportSize({ width: 1440, height: 920 });

  const previewInfo = page.getByRole("button", { name: "About this preview", exact: true });
  await previewInfo.hover();
  const previewTooltip = page.getByRole("tooltip").filter({ hasText: "Sampled wideband extrema" });
  await previewTooltip.waitFor();
  await screenshot("00a-contextual-help.png");
  await page.mouse.move(0, 0);
  await previewInfo.focus();
  await previewTooltip.waitFor();
  await page.keyboard.press("Tab");

  if (await page.locator("html").getAttribute("data-theme") !== "light") {
    throw new Error("first launch did not honor the light browser preference");
  }
  const darkThemeButton = page.getByRole("button", { name: "Switch to dark theme", exact: true });
  await requireMinimumTarget(darkThemeButton, "Theme toggle");
  await darkThemeButton.click();
  await page.waitForFunction(() => document.documentElement.getAttribute("data-theme") === "dark");
  await screenshot("00-dark-theme-live-preview.png");
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: "Switch to light theme", exact: true }).waitFor();
  if (await page.locator("html").getAttribute("data-theme") !== "dark") {
    throw new Error("dark theme did not persist across reload");
  }
  await page.getByRole("button", { name: "Switch to light theme", exact: true }).click();
  await page.waitForFunction(() => document.documentElement.getAttribute("data-theme") === "light");
  await page.getByRole("heading", { name: "Devices" }).waitFor();
  await page.getByText("Direct to PC", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Expand acquisition controls", exact: true }).click();
  await page.getByRole("heading", { name: "Acquisition", exact: true }).waitFor();

  const aggregatorDisclosure = page.getByRole("button", { name: /^Mock Aggregator A/ });
  if ((await aggregatorDisclosure.getAttribute("aria-expanded")) !== "true") {
    throw new Error("Aggregator device group should be expanded on first inspection");
  }
  const aggregatedPod = page.getByRole("button", { name: /Preview Mock Aggregated Pod 1/ });
  await requireSlenderSurface(aggregatorDisclosure, "Aggregator disclosure", 38, 4);
  await requireMinimumTarget(aggregatedPod, "Aggregated Pod Preview");
  await aggregatorDisclosure.click();
  if ((await aggregatorDisclosure.getAttribute("aria-expanded")) !== "false") {
    throw new Error("Aggregator device group did not collapse");
  }
  await aggregatorDisclosure.click();
  await aggregatedPod.click();
  await page.getByRole("heading", { name: "Mock Aggregated Pod 1" }).waitFor();
  await waitForPhase("READY");
  await page.getByRole("button", { name: "Stop Preview", exact: true }).waitFor();
  await assertNoAcquisitionStimulationControls("auto-connected");
  await screenshot("01-device-list-auto-connected.png");

  const stopPreview = page.getByRole("button", { name: "Stop Preview", exact: true });
  await requireMinimumTarget(stopPreview, "Stop Preview");
  await assertNoAcquisitionStimulationControls("preview");
  const widebandCanvas = page.getByRole("application", { name: /Live wideband bank traces/ });
  await widebandCanvas.waitFor();
  const widebandLanes = widebandCanvas.locator('[data-testid="trace-channel-lane"]');
  if ((await widebandLanes.count()) !== 8) {
    throw new Error(`Wideband preview is not split into eight channel components: ${await widebandLanes.count()}`);
  }
  const channelTwo = widebandCanvas.getByRole("button", { name: "Select channel 2 waveform", exact: true });
  await channelTwo.click();
  if ((await channelTwo.getAttribute("aria-pressed")) !== "true"
      || !(await widebandCanvas.getAttribute("aria-label"))?.includes("Channel 2 selected")) {
    throw new Error("Independent channel waveform component did not become the selected lane");
  }
  if ((await page.getByText("NO RUN", { exact: true }).count()) === 0) {
    throw new Error("Preview-before-Record should not create a Run");
  }
  const idleIntegrityRail = page.locator(".integrity-rail");
  if ((await idleIntegrityRail.getAttribute("data-run-result-state")) !== "idle"
      || (await idleIntegrityRail.locator("[data-operator-slot], [data-integrity-slot], [data-evidence-group]").count()) !== 0
      || (await idleIntegrityRail.locator('[aria-controls="integrity-technical-details"]').count()) !== 0) {
    throw new Error("No-Run footer is not one quiet Run result");
  }
  if ((await idleIntegrityRail.getByText("Preview does not create a Run or write a recording file", { exact: true }).count()) !== 0) {
    throw new Error("No-Run recording status repeats an internal Preview contract");
  }
  await screenshot("02-preview-before-record.png");
  await page.setViewportSize({ width: 1298, height: 698 });
  if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)) {
    throw new Error("Auto-started synthetic Preview has horizontal overflow at 1298x698");
  }
  await screenshot("02-preview-before-record-1298x698.png");
  await page.setViewportSize({ width: 1440, height: 920 });

  const directRow = page.locator('[data-pod-key="MOCK-DIRECT-01"]');
  await directRow.hover();
  await directRow.getByRole("button", { name: /Rename/ }).click();
  const renameDialog = page.getByRole("dialog", { name: "Rename Pod" });
  await renameDialog.waitFor();
  await renameDialog.getByText("Mock session only; this does not represent a cross-computer device NVM write.", { exact: true }).waitFor();
  const nameInput = renameDialog.getByLabel("Device display name");
  await nameInput.fill("Cortex Pod A");
  await renameDialog.getByRole("button", { name: "Save name" }).click();
  await renameDialog.waitFor({ state: "hidden" });
  await directRow.getByText("Cortex Pod A", { exact: true }).waitFor();
  const renamedPreviewTarget = directRow.getByRole("button", { name: /Preview Cortex Pod A/ });
  if (!(await renamedPreviewTarget.getAttribute("aria-label"))?.includes("MOCK-POD-SN-0001")) {
    throw new Error("Collapsed device metadata is missing from the accessible Preview label");
  }
  await screenshot("03-device-renamed-mock-session.png");

  const widebandTab = page.getByRole("tab", { name: /WIDEBAND/ });
  const lfpTab = page.getByRole("tab", { name: /^LFP/ });
  const spikesTab = page.getByRole("tab", { name: /SPIKES/ });
  const electrochemicalTab = page.getByRole("tab", { name: /E-CHEM/ });
  for (const target of [widebandTab, lfpTab, spikesTab]) {
    await requireMinimumTarget(target, "Signal view", 28);
  }
  if (await electrochemicalTab.isEnabled()) {
    throw new Error("Unavailable electrochemical channel is presented as an active Preview capability");
  }
  if ((await page.getByRole("group", { name: "Preview channel bank", exact: true }).count()) !== 0) {
    throw new Error("Removed Preview channel-bank control is still visible");
  }
  await lfpTab.click();
  await page.getByRole("application", { name: /Live LFP bank traces/ }).waitFor();
  await spikesTab.click();
  const spikeSummary = page.locator('[data-testid="spike-event-summary"]');
  const channelOverview = page.getByRole("listbox", { name: /Live Spike overview for all/ });
  await channelOverview.waitFor();
  if ((await page.locator(".spike-detail-panel").count()) !== 0
      || (await page.locator('[data-testid="spike-raster-waveform"]').count()) !== 0) {
    throw new Error("Spike page opened a channel detail before the operator selected a channel");
  }
  const renderedActivityChannels = Number(await channelOverview.getAttribute("data-rendered-channels"));
  const totalActivityChannels = Number(await channelOverview.getAttribute("data-total-channels"));
  if (!Number.isFinite(renderedActivityChannels) || renderedActivityChannels > 48) {
    throw new Error(`Spike activity rendered an unbounded DOM channel count: ${renderedActivityChannels}`);
  }
  if (totalActivityChannels !== 16) {
    throw new Error(`NWB-derived browser demo must expose its 16 source channels, got ${totalActivityChannels}`);
  }
  const activityMetrics = await channelOverview.evaluate((element) => ({
    clientHeight: element.clientHeight,
    scrollHeight: element.scrollHeight,
    overflowY: getComputedStyle(element).overflowY,
  }));
  if (activityMetrics.overflowY !== "scroll") {
    throw new Error(`Spike overview does not expose a native vertical channel scrollbar: ${JSON.stringify(activityMetrics)}`);
  }
  const firstChannel = page.locator('[data-testid="spike-activity-channel"][data-channel="0"]');
  const firstWaveform = firstChannel.locator('[data-testid="spike-channel-waveform"]');
  const firstWaveformPoints = await firstWaveform.locator("polyline").last().getAttribute("points") ?? "";
  if ((await firstChannel.locator("strong").textContent())?.trim() !== "CH 001"
      || (await firstWaveform.locator("polyline").count()) === 0
      || new Set(firstWaveformPoints.split(" ").map((point) => point.split(",")[1])).size < 3
      || (await channelOverview.getByText(/Hz/).count()) !== 0) {
    throw new Error("All-channel Spike overview is not showing real waveform shapes for each channel");
  }
  const matrixGeometry = await page.locator('[data-testid="spike-activity-channel"]').evaluateAll((tiles) => {
    const boxes = tiles.slice(0, 12).map((tile) => tile.getBoundingClientRect());
    const rowBuckets = new Map();
    for (const box of boxes) {
      const rowKey = Math.round(box.top);
      rowBuckets.set(rowKey, (rowBuckets.get(rowKey) ?? 0) + 1);
    }
    return {
      declaredColumns: Number(document.querySelector('[data-testid="spike-overview"]')?.getAttribute("data-grid-columns")),
      maximumTilesInRow: Math.max(0, ...rowBuckets.values()),
      visibleRows: rowBuckets.size,
      firstTileWidth: boxes[0]?.width ?? 0,
      firstTileHeight: boxes[0]?.height ?? 0,
    };
  });
  if (matrixGeometry.declaredColumns < 3
      || matrixGeometry.maximumTilesInRow < 3
      || matrixGeometry.visibleRows < 2
      || matrixGeometry.firstTileWidth <= matrixGeometry.firstTileHeight) {
    throw new Error(`Spike overview is not a multi-row waveform card matrix: ${JSON.stringify(matrixGeometry)}`);
  }
  await page.waitForFunction(() => [...document.querySelectorAll(".preview-spike-summary strong")]
    .every((element) => element.textContent?.trim() !== "—"));
  await screenshot("03a-spike-all-channel-overview.png");
  if (activityMetrics.scrollHeight > activityMetrics.clientHeight) {
    await channelOverview.evaluate((element) => { element.scrollTop = element.scrollHeight; });
    await page.waitForFunction(() => Number(document.querySelector('[data-testid="spike-overview"]')?.getAttribute("data-window-start")) > 0);
  }
  const finalChannelIndex = totalActivityChannels - 1;
  const finalChannelLabel = `CH ${String(totalActivityChannels).padStart(3, "0")}`;
  const lastChannel = page.locator(`[data-testid="spike-activity-channel"][data-channel="${finalChannelIndex}"]`);
  if ((await lastChannel.locator("strong").textContent())?.trim() !== finalChannelLabel) {
    throw new Error("Spike overview scrollbar did not reach the final Pod channel");
  }
  const detailChannelIndex = await page.locator('[data-testid="spike-activity-channel"]').evaluateAll((buttons) => {
    const ranked = buttons.map((button) => ({
      channel: Number(button.getAttribute("data-channel")),
      count: Number((button.querySelector("small")?.textContent ?? "").replace("n=", "")),
    })).sort((left, right) => right.count - left.count);
    return ranked[0]?.channel ?? -1;
  });
  if (detailChannelIndex < 0) throw new Error("NWB-derived Spike window has no active detail channel");
  await page.locator(`[data-testid="spike-activity-channel"][data-channel="${detailChannelIndex}"]`).click();
  const spikeCanvas = page.locator('[data-testid="spike-raster-waveform"]');
  const spikeDetail = page.locator(".spike-detail-panel");
  await spikeCanvas.waitFor();
  if ((await spikeDetail.count()) !== 1 || (await spikeCanvas.getAttribute("aria-hidden")) !== "true") {
    throw new Error("Selecting a Spike channel did not open exactly one compact waveform detail");
  }
  const allWaveformPane = spikeDetail.locator(".spike-detail-waveforms");
  const clusterPane = page.locator('[data-testid="spike-waveform-clusters"]');
  await clusterPane.waitFor();
  if ((await spikeDetail.getByRole("radio").count()) !== 0) {
    throw new Error("Selected-channel detail still exposes redundant All/Stats/Last modes");
  }
  const detailPaneGeometry = await Promise.all([
    allWaveformPane.boundingBox(),
    clusterPane.boundingBox(),
  ]);
  if (!detailPaneGeometry[0] || !detailPaneGeometry[1]
      || detailPaneGeometry[0].y + detailPaneGeometry[0].height > detailPaneGeometry[1].y + 1) {
    throw new Error(`Selected-channel detail is not split into upper waveforms and lower clusters: ${JSON.stringify(detailPaneGeometry)}`);
  }
  if ((await clusterPane.getAttribute("data-sorting")) !== "unsorted"
      || (await clusterPane.getByText("UNSORTED POOL", { exact: true }).count()) !== 1
      || (await clusterPane.locator("svg polyline").count()) < 2
      || (await clusterPane.locator("svg polyline.is-centroid").count()) !== 1) {
    throw new Error("Unsorted waveform pool is not represented honestly in the cluster pane");
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

  await page.getByRole("button", { name: "Retain each waveform for 2 seconds", exact: true }).click();
  await page.waitForFunction(() => {
    const canvas = document.querySelector('[data-testid="spike-raster-waveform"]');
    return canvas?.getAttribute("data-window-seconds") === "2"
      && canvas?.getAttribute("data-waveform-retention-samples") === canvas?.getAttribute("data-source-sample-span")
      && Number(canvas?.getAttribute("data-waveform-retention-samples")) > 0;
  });
  await page.getByRole("button", { name: "Retain each waveform for 1 second", exact: true }).click();
  await page.waitForFunction(() => document.querySelector('[data-testid="spike-raster-waveform"]')
    ?.getAttribute("data-window-seconds") === "1");
  const bankEvents = Number(await spikeSummary.getAttribute("data-bank-events"));
  const renderedEvents = Number(await spikeSummary.getAttribute("data-rendered"));
  const omittedEvents = Number(await spikeSummary.getAttribute("data-preview-omitted"));
  if (bankEvents !== renderedEvents + omittedEvents || renderedEvents > 64) {
    throw new Error("Bounded Spike preview accounting is inconsistent");
  }
  for (const label of ["POD EVENTS", "SELECTED 8-CH EVENTS"]) {
    await page.getByText(label, { exact: true }).waitFor();
  }
  const visibleSpikeSummary = page.locator(".preview-display-controls > .preview-spike-summary");
  if ((await visibleSpikeSummary.count()) !== 1
      || !(await visibleSpikeSummary.evaluate((element) => element.parentElement?.classList.contains("preview-display-controls")))) {
    throw new Error("Spike event summary is not merged into the Preview display controls row");
  }
  for (const removedLabel of ["BANK EVENTS", "RASTER DRAWN", "DISPLAY OMITTED", "SOURCE COVERAGE", "DETECTOR COVERAGE"]) {
    if ((await page.getByText(removedLabel, { exact: true }).count()) !== 0) {
      throw new Error(`${removedLabel} remains visible in the operator Spike summary`);
    }
  }

  for (const channel of [7, 8]) {
    await page.locator(`[data-testid="spike-activity-channel"][data-channel="${channel}"]`).click();
    await page.waitForFunction((selectedChannel) => {
      const button = document.querySelector(
        `[data-testid="spike-activity-channel"][data-channel="${selectedChannel}"]`,
      );
      const canvas = document.querySelector('[data-testid="spike-raster-waveform"]');
      const expectedBankStart = Math.floor(Number(selectedChannel) / 8) * 8;
      return button?.getAttribute("aria-selected") === "true"
        && canvas?.getAttribute("data-bank-start") === String(expectedBankStart);
    }, channel);
  }
  await screenshot("03b-spike-channel-detail.png");

  const singleSetupButton = page.getByRole("button", { name: "Single-device setup", exact: true });
  const multiSetupButton = page.getByRole("button", { name: "Multi-device setup", exact: true });
  await requireMinimumTarget(singleSetupButton, "Single-device Recording Setup", 32);
  await requireMinimumTarget(multiSetupButton, "Multi-device Recording Setup", 32);

  await singleSetupButton.click();
  const singleSetupDialog = page.getByRole("dialog", { name: "Single-device recording" });
  await singleSetupDialog.waitFor();
  await requireSlenderSurface(singleSetupDialog, "Recording setup dialog", 430, 1.8);
  if ((await singleSetupDialog.locator('input[type="radio"]:checked').count()) !== 1) {
    throw new Error("Single-device setup did not freeze exactly the current Preview Pod");
  }
  if ((await singleSetupDialog.locator('input[type="checkbox"]').count()) !== 0) {
    throw new Error("Single-device setup unexpectedly exposed a multi-device checkbox draft");
  }
  await singleSetupDialog.getByRole("button", { name: "Close recording setup", exact: true }).click();

  await multiSetupButton.click();
  const setupDialog = page.getByRole("dialog", { name: "Multi-device recording" });
  await setupDialog.waitFor();
  const closeSetup = setupDialog.getByRole("button", { name: "Close recording setup", exact: true });
  if (!(await closeSetup.evaluate((element) => element === document.activeElement))) {
    throw new Error("Recording setup did not focus its non-destructive Close action");
  }
  const directoryInput = setupDialog.getByLabel("Save location · Run root");
  const runNameInput = setupDialog.getByLabel("Run name prefix");
  const directoryPicker = setupDialog.getByRole("button", { name: "Browse…", exact: true });
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
    await requireSlenderSurface(operatorConclusions.nth(index), `Operator conclusion ${index + 1}`, 64, 2);
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
  await setupDialog.getByRole("button", { name: "Check & allocate target" }).click();
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
  await setupDialog.getByText("Simulation name allocated · no file created", { exact: true }).waitFor();
  await page.keyboard.press("Enter");
  if (await technicalDetails.evaluate((element) => element.open)) {
    throw new Error("Technical details did not close from the keyboard");
  }
  const armRecording = setupDialog.getByRole("button", { name: "Arm recording" });
  await armRecording.waitFor();
  await armRecording.focus();
  await screenshot("04-recording-target-preflight.png");
  await armRecording.click();
  await setupDialog.waitFor({ state: "hidden" });
  await waitForPhase("READY TO RECORD");
  await assertNoAcquisitionStimulationControls("record ready");

  const recordButtons = page.locator("button.instrument-button--record");
  if ((await recordButtons.count()) !== 1) throw new Error("Recording controls expose more than one actual Start action");
  const recordButton = page.getByRole("button", { name: "Start recording · 4 devices", exact: true });
  await requireMinimumTarget(recordButton, "Start Recording", 32);
  await recordButton.click();
  await waitForPhase("RECORDING");
  await assertNoAcquisitionStimulationControls("recording");
  await page.getByRole("button", { name: "Stop Preview", exact: true }).waitFor();
  await screenshot("05-recording-with-live-preview.png");

  const pauseRecording = page.getByRole("button", { name: "Pause recording", exact: true });
  await requireMinimumTarget(pauseRecording, "Pause Recording", 32);
  await pauseRecording.click();
  await waitForPhase("RECORDING PAUSED");
  const resumeRecording = page.getByRole("button", { name: "Resume recording", exact: true });
  await resumeRecording.waitFor();
  await screenshot("05b-recording-paused.png");
  await resumeRecording.click();
  await waitForPhase("RECORDING");

  const freezeDisplay = page.getByRole("button", { name: "Freeze display", exact: true });
  await freezeDisplay.click();
  const resumeDisplay = page.getByRole("button", { name: "Resume display", exact: true });
  const frozenSequence = await spikeCanvas.getAttribute("data-frame-sequence");
  await page.waitForTimeout(220);
  if ((await spikeCanvas.getAttribute("data-frame-sequence")) !== frozenSequence) {
    throw new Error("Freeze Display did not freeze WebView presentation");
  }
  await resumeDisplay.click();

  await page.setViewportSize({ width: 1298, height: 698 });
  if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)) {
    throw new Error("1298x698 focused workspace has horizontal overflow");
  }
  const baselineWorkbench = await page.locator(".signal-workbench").boundingBox();
  await page.getByRole("button", { name: "Enter signal focus" }).click();
  await page.waitForFunction(() => document.querySelector(".app-shell")?.getAttribute("data-signal-focus") === "true");
  for (const selector of [".pod-rack", ".control-stack"]) {
    if ((await page.locator(selector).getAttribute("data-collapsed")) !== "true") {
      throw new Error(`${selector} did not collapse in signal focus`);
    }
  }
  await page.getByLabel("4 Pods connected; 4 Pods in the current Run", { exact: true }).waitFor();
  if ((await page.locator(".diagnostic-region").count()) !== 0) {
    throw new Error("Diagnostics remained visible in signal focus");
  }
  await requireNoOverlap(
    page.locator(".signal-title > .signal-view-tabs, .preview-display-controls > .preview-control-cluster"),
    "Focused signal control groups",
  );
  await requireNoOverlap(
    page.locator(".pod-rack--collapsed > .panel-collapse-button, .pod-rack-compact-count, .pod-rack-compact-routes > span"),
    "Collapsed device rail",
  );
  const compactRailGeometry = await page.locator(".pod-rack--collapsed").evaluate((rail) => {
    const railBox = rail.getBoundingClientRect();
    const items = [
      rail.querySelector(":scope > .panel-collapse-button"),
      rail.querySelector(":scope > .pod-rack-compact-count"),
      ...rail.querySelectorAll(":scope > .pod-rack-compact-routes > span"),
    ].filter(Boolean).map((element) => {
      const box = element.getBoundingClientRect();
      return { left: box.left, right: box.right, center: box.left + box.width / 2 };
    });
    return {
      rail: { left: railBox.left, right: railBox.right, center: railBox.left + railBox.width / 2 },
      items,
      hasStatePill: rail.querySelector(".pod-rack-compact-state") !== null,
    };
  });
  if (compactRailGeometry.hasStatePill) {
    throw new Error("Collapsed device rail still contains the meaningless LINK/OFF state pill");
  }
  for (const item of compactRailGeometry.items) {
    if (Math.abs(item.center - compactRailGeometry.rail.center) > 1
        || item.left < compactRailGeometry.rail.left + 6
        || item.right > compactRailGeometry.rail.right - 6) {
      throw new Error(`Collapsed device rail item is clipped or off-center: ${JSON.stringify({ item, rail: compactRailGeometry.rail })}`);
    }
  }
  const compactCountShape = await page.locator(".pod-rack-compact-count").evaluate((element) => {
    const box = element.getBoundingClientRect();
    return { width: box.width, height: box.height, radius: Number.parseFloat(getComputedStyle(element).borderRadius) };
  });
  if (compactCountShape.width < 48 || compactCountShape.radius < 20) {
    throw new Error(`Collapsed device count is still cramped or square: ${JSON.stringify(compactCountShape)}`);
  }
  await page.evaluate(() => new Promise((resolveFrame) => requestAnimationFrame(() => requestAnimationFrame(resolveFrame))));
  const focusedWorkbench = await page.locator(".signal-workbench").boundingBox();
  const baselineArea = baselineWorkbench ? baselineWorkbench.width * baselineWorkbench.height : 0;
  const focusedArea = focusedWorkbench ? focusedWorkbench.width * focusedWorkbench.height : 0;
  if (!baselineWorkbench || !focusedWorkbench
    || focusedArea < baselineArea * 1.45) {
    throw new Error(`Signal Focus area ${focusedArea} did not exceed baseline ${baselineArea} by 1.45x`);
  }
  if ((await page.locator(".control-rail__stim").count()) !== 0) {
    throw new Error("Collapsed acquisition controls still contain stimulation controls");
  }
  await screenshot("06-signal-focus-recording-1298x698.png");

  await page.getByRole("button", { name: "Exit signal focus" }).click();
  await page.setViewportSize({ width: 1440, height: 920 });
  const sequenceBeforeEndAndSave = await spikeCanvas.getAttribute("data-frame-sequence");
  await page.getByRole("button", { name: "End recording", exact: true }).click();
  await waitForPhase("SIMULATION COMPLETE");
  await page.getByRole("button", { name: "Stop Preview", exact: true }).waitFor();
  await page.waitForFunction(
    (sequence) => document.querySelector('[data-testid="spike-raster-waveform"]')
      ?.getAttribute("data-frame-sequence") !== sequence,
    sequenceBeforeEndAndSave,
  );
  if ((await page.getByRole("button", { name: /Finalize Run/i }).count()) !== 0) {
    throw new Error("Recording controls still expose a second Finalize action");
  }
  await assertNoAcquisitionStimulationControls("finalized");
  await page.getByText("Simulation complete", { exact: true }).first().waitFor();
  const integrityRail = page.locator(".integrity-rail");
  if ((await integrityRail.locator(".integrity-rail__detail").textContent()) !== "No recording file or NWB was created.") {
    throw new Error("Simulation-only Run result lost its no-file/no-NWB boundary");
  }
  const compactRailBox = await integrityRail.boundingBox();
  if (!compactRailBox || compactRailBox.height < 120) {
    throw new Error(`Per-device recording status is ${compactRailBox?.height ?? "missing"}px high`);
  }
  if (!(await integrityRail.evaluate((element) => element.parentElement?.classList.contains("run-control__device-status")))) {
    throw new Error("Run result is not integrated into the selected device acquisition panel");
  }
  if ((await integrityRail.getAttribute("data-run-result-state")) !== "mock_complete"
      || (await integrityRail.locator("[data-operator-slot], [data-integrity-slot], [data-evidence-group]").count()) !== 0
      || (await integrityRail.locator('[aria-controls="integrity-technical-details"]').count()) !== 0) {
    throw new Error("Final mock footer is not one simulation-only Run result");
  }
  const forbiddenResultCopy = /DATA CONTINUITY|FILE SAVE|RUN RECEIPTS AND OUTPUT|TECHNICAL DETAILS|EXTERNAL EVENTS|seq\s|SIMULATION ENDED AND SAVED|RECORDING ENDED AND SAVED|ENDED \/ SAVED/;
  if (forbiddenResultCopy.test(await integrityRail.innerText())) {
    throw new Error("Removed evidence UI or false saved copy remains in the Run result");
  }
  await screenshot("07-simulation-complete-preview-continues.png");

  await page.setViewportSize({ width: 1080, height: 720 });
  if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)) {
    throw new Error("Single Run result causes horizontal overflow at 1080x720");
  }
  if ((await page.locator(".run-spine, .bench-header").count()) !== 0) {
    throw new Error("Removed global lifecycle header returned at 1080x720");
  }
  await screenshot("08-single-run-result-1080x720.png");

  const lightCanvas = await page.locator("body").evaluate((element) => getComputedStyle(element).backgroundColor);
  await page.getByRole("button", { name: "Switch to dark theme", exact: true }).click();
  await page.waitForFunction(() => document.documentElement.getAttribute("data-theme") === "dark");
  const darkCanvas = await page.locator("body").evaluate((element) => getComputedStyle(element).backgroundColor);
  if (lightCanvas === darkCanvas) {
    throw new Error("theme toggle did not change the rendered canvas color");
  }
  if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)) {
    throw new Error("Dark theme causes horizontal overflow at 1080x720");
  }
  await screenshot("09-dark-theme-single-run-result-1080x720.png");

  if (errors.length > 0) throw new Error(errors.join("\n"));
  console.log("visual QA passed; screenshots:", outputDirectory);
} finally {
  await browser.close();
}
