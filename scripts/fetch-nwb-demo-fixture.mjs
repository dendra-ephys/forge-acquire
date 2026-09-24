#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createReadStream, promises as fs } from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const extractor = path.join(root, "scripts", "extract-nwb-demo-fixture.py");
const output = path.join(root, "src", "fixtures", "nwb-waveform-demo.v2.json");
const source = process.argv[2] ?? "N:\\FINAL\\D10\\27-40-30-32_mouse40.nwb";
const host = process.argv[3] ?? "sw-bastion";

const child = spawn("ssh", [host, `D:\\anaconda3\\python.exe - ${source}`], {
  stdio: ["pipe", "pipe", "inherit"],
});
createReadStream(extractor).pipe(child.stdin);
const chunks = [];
for await (const chunk of child.stdout) chunks.push(chunk);
const exitCode = await new Promise((resolve, reject) => {
  child.once("error", reject);
  child.once("close", resolve);
});
if (exitCode !== 0) throw new Error(`remote extractor exited with ${exitCode}`);

const fixture = JSON.parse(Buffer.concat(chunks).toString("utf8"));
if (fixture.schemaVersion !== 2 || fixture.channels?.length !== fixture.source?.channelCount) {
  throw new Error("remote extractor returned an invalid fixture");
}
await fs.mkdir(path.dirname(output), { recursive: true });
await fs.writeFile(output, `${JSON.stringify(fixture)}\n`, "utf8");
console.log(JSON.stringify({
  output,
  sourceSha256: fixture.source.sha256,
  channels: fixture.channels.length,
  events: fixture.channels.reduce((sum, channel) => sum + channel.eventSamples.length, 0),
  templates: fixture.channels.reduce((sum, channel) => sum + channel.waveformCounts.length, 0),
  lfpPoints: fixture.channels.reduce((sum, channel) => sum + channel.lfpCounts.length, 0),
  sourceWindowStartSeconds: fixture.reconstruction.sourceWindowStartSeconds,
}));
