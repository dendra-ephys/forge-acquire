import { spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const hostRoot = resolve(scriptDirectory, "..");
const repositoryRoot = resolve(hostRoot, "..", "..");
const repositoryPixiManifest = resolve(repositoryRoot, "pixi.toml");
const protocolRoot = resolve(hostRoot, "protocol");
const rustManifest = resolve(protocolRoot, "rust", "Cargo.toml");
const pythonPath = resolve(protocolRoot, "python");
const temporaryDirectory = await mkdtemp(
  join(tmpdir(), "forge-protocol-v1-check-"),
);
const verifier = join(temporaryDirectory, "forge-protocol-v1-golden.exe");
const environment = {
  ...process.env,
  PYTHONPATH: pythonPath,
};

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

try {
  run("cargo", ["fmt", "--manifest-path", rustManifest, "--", "--check"]);
  run("cargo", ["test", "--locked", "--manifest-path", rustManifest]);
  run("cargo", [
    "clippy", "--locked", "--manifest-path", rustManifest,
    "--all-targets", "--", "-D", "warnings",
  ]);
  run("pixi", [
    "run", "--manifest-path", repositoryPixiManifest,
    "python", "-m", "unittest", "discover",
    "-s", "Forge/host_app/protocol/python/tests", "-v",
  ]);
  run("pixi", [
    "run", "--manifest-path", repositoryPixiManifest,
    "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
    "-I", "Forge/host_app/protocol/cpp/include",
    "Forge/host_app/protocol/cpp/tests/golden_test.cpp",
    "-o", verifier,
  ]);
  run(verifier, ["Forge/host_app/protocol/golden"], {
    PATH: `C:\\Strawberry\\c\\bin;${environment.PATH ?? ""}`,
  });

  console.log("Forge protocol v1 Rust/Python/C++ checks passed");
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}
