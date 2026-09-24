import { gzipSync } from "node:zlib";
import { readFile, readdir } from "node:fs/promises";
import { extname, join, resolve } from "node:path";

const dist = resolve("dist");
const startupBudgets = new Map([
  [".js", 100 * 1024],
  // The dual-theme instrument token layer and the selected Apps SDK UI
  // primitives are shipped up front so the Tauri WebView never flashes an
  // unthemed surface. Keep the increase bounded and gzip-measured.
  [".css", 16 * 1024],
]);
// Recording setup and the filesystem browser are intentional on-demand chunks.
// Keep the acquisition console's startup budget unchanged, and separately cap
// the complete offline payload so lazy loading cannot hide unbounded growth.
const totalBudgets = new Map([
  // The on-demand NWB Preview fixture includes 80 real Spike snippets and
  // 8000 compact LFP points. Keep it out of startup and cap its total cost.
  [".js", 128 * 1024],
  [".css", 18 * 1024],
]);
const totals = new Map([...totalBudgets.keys()].map((extension) => [extension, 0]));
const startupTotals = new Map([...startupBudgets.keys()].map((extension) => [extension, 0]));
const forbiddenHtmlRuntimeUrls = /https?:\/\//i;
const forbiddenCssRuntimeUrls = /(?:@import\s+(?:url\()?\s*["']?https?:\/\/|url\(\s*["']?https?:\/\/)/i;
const forbiddenProductionCspSources = /127\.0\.0\.1|(?:^|[;\s])wss?:/i;

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  return (await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? walk(path) : [path];
  }))).flat();
}

const indexHtml = await readFile(resolve(dist, "index.html"), "utf8");
const startupAssets = new Set(
  [...indexHtml.matchAll(/(?:src|href)="([^"?#]+\.(?:js|css))"/g)]
    .map((match) => resolve(dist, match[1].replace(/^\//, ""))),
);
const files = await walk(dist);
for (const path of files) {
  const extension = extname(path);
  const content = await readFile(path);
  if (totalBudgets.has(extension)) {
    const compressedBytes = gzipSync(content).byteLength;
    totals.set(extension, totals.get(extension) + compressedBytes);
    if (startupAssets.has(resolve(path))) {
      startupTotals.set(extension, startupTotals.get(extension) + compressedBytes);
    }
  }
  // React and SVG libraries embed documentation/namespace URL constants in
  // JavaScript. They are not network requests. The offline shell gate checks
  // resource-bearing HTML/CSS; production network APIs are separately denied
  // by the Tauri CSP and reviewed at the adapter boundary.
  if (extension === ".html") {
    const text = content.toString("utf8");
    if (forbiddenHtmlRuntimeUrls.test(text)) {
      throw new Error(`production shell contains a runtime network URL: ${path}`);
    }
  }
  if (extension === ".css") {
    const textWithoutComments = content.toString("utf8").replace(/\/\*[\s\S]*?\*\//g, "");
    if (forbiddenCssRuntimeUrls.test(textWithoutComments)) {
      throw new Error(`production shell contains a runtime network URL: ${path}`);
    }
  }
}

for (const [extension, maximum] of startupBudgets) {
  const actual = startupTotals.get(extension);
  if (actual > maximum) {
    throw new Error(
      `startup ${extension} gzip budget exceeded: ${actual} bytes > ${maximum} bytes`,
    );
  }
}

for (const [extension, maximum] of totalBudgets) {
  const actual = totals.get(extension);
  if (actual > maximum) {
    throw new Error(
      `total ${extension} gzip budget exceeded: ${actual} bytes > ${maximum} bytes`,
    );
  }
}

const tauriConfig = JSON.parse(
  await readFile(resolve("src-tauri", "tauri.conf.json"), "utf8"),
);
const productionCsp = tauriConfig?.app?.security?.csp;
const developmentCsp = tauriConfig?.app?.security?.devCsp;
if (typeof productionCsp !== "string" ||
    forbiddenProductionCspSources.test(productionCsp)) {
  throw new Error(
    "production Tauri CSP must not allow 127.0.0.1 or WebSocket sources",
  );
}
if (typeof developmentCsp !== "string" ||
    !developmentCsp.includes("ws://127.0.0.1:1421") ||
    !developmentCsp.includes("http://127.0.0.1:1421")) {
  throw new Error(
    "development Tauri CSP must explicitly contain the Vite loopback sources",
  );
}

console.log(
  `bundle budget passed: startup JS ${(startupTotals.get(".js") / 1024).toFixed(2)} KiB, CSS ${(startupTotals.get(".css") / 1024).toFixed(2)} KiB; total JS ${(totals.get(".js") / 1024).toFixed(2)} KiB, CSS ${(totals.get(".css") / 1024).toFixed(2)} KiB gzip`,
);
