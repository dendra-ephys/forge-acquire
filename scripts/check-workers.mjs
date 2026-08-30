import { spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const hostRoot = resolve(scriptDirectory, "..");
const repositoryRoot = hostRoot;
const repositoryPixiManifest = resolve(hostRoot, "pixi.toml");
const pythonPath = resolve(hostRoot, "workers", "python");
const temporaryDirectory = await mkdtemp(join(tmpdir(), "forge-worker-check-"));
const executable = join(temporaryDirectory, "forge-worker-sdk-smoke.exe");
const ringFixture = join(temporaryDirectory, "forge-analysis-ring-v1.bin");
const protocolPythonPath = resolve(hostRoot, "protocol", "python");
const environment = { ...process.env };

function run(command, args, extraEnvironment = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    env: { ...environment, ...extraEnvironment },
    stdio: "inherit",
    shell: false,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} exited with ${result.status}`);
  }
}

function capture(command, args) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    env: environment,
    encoding: "utf8",
    shell: false,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} exited with ${result.status}: ${result.stderr}`);
  }
  return result.stdout.trim();
}

try {
  const pythonConfig = JSON.parse(capture("pixi", [
    "run", "--manifest-path", repositoryPixiManifest,
    "python", "-c",
    "import json,sys,sysconfig; print(json.dumps({'include':sysconfig.get_config_var('INCLUDEPY'),'prefix':sys.prefix,'suffix':sysconfig.get_config_var('EXT_SUFFIX')}))",
  ]));
  const nativeExtension = join(
    temporaryDirectory,
    `_forge_analysis_native${pythonConfig.suffix}`,
  );
  run("pixi", [
    "run", "--manifest-path", repositoryPixiManifest,
    "g++", "-std=c++20", "-shared", "-static-libgcc", "-static-libstdc++",
    "-Wall", "-Wextra", "-Werror",
    "-I", pythonConfig.include,
    "-I", "protocol/cpp/include",
    "-I", "workers/cpp/include",
    "workers/python_native/forge_analysis_native.cpp",
    "-L", join(pythonConfig.prefix, "libs"), "-lpython311",
    "-o", nativeExtension,
  ]);
  const workerPythonPath = [
    temporaryDirectory,
    pythonPath,
    protocolPythonPath,
  ].join(";");
  run("pixi", [
    "run", "--manifest-path", repositoryPixiManifest,
    "python", "-c",
    "import _forge_analysis_native; print('Forge native Python analysis bridge import passed')",
  ], { PYTHONPATH: workerPythonPath });
  run("pixi", [
    "run", "--manifest-path", repositoryPixiManifest,
    "cargo", "run", "--quiet", "--locked",
    "--manifest-path", "recording-daemon/Cargo.toml", "--",
    "analysis-ring-fixture", "--output", ringFixture,
  ]);
  run("pixi", [
    "run", "--manifest-path", repositoryPixiManifest,
    "python", "-m", "unittest", "discover",
    "-s", "workers/tests", "-v",
  ], {
    FORGE_ANALYSIS_RING_FIXTURE: ringFixture,
    PYTHONPATH: workerPythonPath,
  });
  run("pixi", [
    "run", "--manifest-path", repositoryPixiManifest,
    "python", "-m", "forge_workers.materializer", "probe",
  ], { PYTHONPATH: workerPythonPath });
  run("pixi", [
    "run", "--manifest-path", repositoryPixiManifest,
    "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
    "-I", "protocol/cpp/include",
    "-I", "workers/cpp/include",
    "workers/cpp/tests/sdk_smoke.cpp",
    "-o", executable,
  ]);
  run(executable, [
    "protocol/golden/canonical_record_envelope_v1.hex",
    "protocol/golden/stim_intent_v1.hex",
    "workers/golden/nwb_generation_validation_receipt_v1.hex",
    ringFixture,
  ], {
    PATH: `C:\\Strawberry\\c\\bin;${environment.PATH ?? ""}`,
  });

  console.log("Forge worker checks passed");
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}
