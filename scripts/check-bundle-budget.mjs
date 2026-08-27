import { gzipSync } from "node:zlib";
import { readFile, readdir } from "node:fs/promises";
import { extname, join, resolve } from "node:path";

const dist = resolve("dist");
const budgets = new Map([
  [".js", 100 * 1024],
  [".css", 10 * 1024],
]);
const totals = new Map([...budgets.keys()].map((extension) => [extension, 0]));
const forbiddenRuntimeUrls = /https?:\/\//i;
const forbiddenProductionCspSources = /127\.0\.0\.1|(?:^|[;\s])wss?:/i;

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  return (await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? walk(path) : [path];
  }))).flat();
}

const files = await walk(dist);
for (const path of files) {
  const extension = extname(path);
  const content = await readFile(path);
  if (budgets.has(extension)) {
    totals.set(extension, totals.get(extension) + gzipSync(content).byteLength);
  }
  // React and SVG libraries embed documentation/namespace URL constants in
  // JavaScript. They are not network requests. The offline shell gate checks
  // resource-bearing HTML/CSS; production network APIs are separately denied
  // by the Tauri CSP and reviewed at the adapter boundary.
  if ([".html", ".css"].includes(extension)) {
    const text = content.toString("utf8");
    if (forbiddenRuntimeUrls.test(text)) {
      throw new Error(`production shell contains a runtime network URL: ${path}`);
    }
  }
}

for (const [extension, maximum] of budgets) {
  const actual = totals.get(extension);
  if (actual > maximum) {
    throw new Error(
      `${extension} gzip budget exceeded: ${actual} bytes > ${maximum} bytes`,
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
  `bundle budget passed: JS ${(totals.get(".js") / 1024).toFixed(2)} KiB gzip, CSS ${(totals.get(".css") / 1024).toFixed(2)} KiB gzip`,
);
