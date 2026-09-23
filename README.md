# Forge Acquire

Forge Acquire is the desktop acquisition interface for the modular Forge neural-recording system.

This first implementation is intentionally narrow:

- one main screen for devices, live traces, the selected channel, recording controls, and health metrics;
- explicit `Disconnected -> Ready -> Monitoring -> Recording` operator states;
- a deterministic simulator for exercising the complete UI state machine;
- a [16-channel NWB-derived browser waveform demo](docs/NWB_DERIVED_DEMO.md)
  whose real event snippets are reconstructed into a bounded mock Preview while
  remaining explicitly separate from the qualification simulator and hardware;
- a fail-closed FT601/D3XX host-adapter foundation with protected internal admission and USB-descriptor gates, an explicit SCM bootstrap binding, and an honest unavailable Aggregator/10GbE placeholder;
- an explicit [CABLINE Rev A / FT601 software migration boundary](docs/CABLINE_FT601_SOFTWARE_MIGRATION.md), including eight base Headstage profiles, fourteen Host-recognized assemblies (ten products, three options, one decode-only), and legacy-event compatibility rules;
- a frozen M0 host-internal protocol with Rust, Python, and read-only C++20 bindings;
- an independently buildable M1 protected-replay data plane with canonical records,
  durable checkpoints, recovery, sealing, and a machine-readable Run receipt;
- an optional exact-version M2 NWB profile with sealed and pull-only live
  one-generation materialization modes,
  frozen validation/publication receipts, Rust owner-side streaming verifier,
  idempotent no-overwrite publisher and Run-ledger `Finalized` binding.

The simulator is always labelled `SIMULATOR`. It does not claim that a Receiver Pod is connected and it does not write raw neural data.

## Run

```powershell
cd F:\poorsystem\Forge\host_app
pixi run install
pixi run dev
```

Desktop shell:

```powershell
pixi run desktop
```

Windows installer:

```powershell
pixi run npm run package:windows
```

The NSIS output is written under
`src-tauri/target/release/bundle/nsis/`. Distribution builds are currently
unsigned engineering/demo packages; Windows may show a SmartScreen warning
until a code-signing certificate is configured.

Validation:

```powershell
pixi run check-all
```

`check-all` is the canonical default-profile local gate. It covers the React tests and bundle,
the M0 Rust/Python/C++ protocol suite, the M1 Rust data plane, the Python/C++
worker foundations, and the Tauri Rust shell. It is engineering evidence only;
it does not satisfy the 24-hour, fault-injection, D3XX, Aggregator, NWB, or RHS
hardware release gates.

The exact-version NWB/SWMR and Python-to-Rust receipt gate is intentionally a
separate environment and must also pass for M2 changes:

```powershell
pixi run -e nwb test-nwb
```

Visual state smoke test (while `pixi run dev` is active):

```powershell
pixi run visual-qa
```

## Current backend boundary

M0 freezes the host-internal record/control contract shared by `forge-acqd`,
workers, and SDKs. It does **not** claim that the Receiver Pod FPGA, FTDI D3XX
transport, or Aggregator firmware speaks that contract. Device identity,
transport framing, hardware ACK/replay, and Aggregator discovery/control/stream
bindings remain open. Consequently the UI uses a normalized internal model and
keeps four adapter slots:

- `simulator` — implemented;
- `replay` — implemented for deterministic low-rate qualification through the
  authenticated SCM service boundary; it writes canonical records to the
  independent daemon journal and returns only low-rate state/watermarks to the
  WebView;
- `direct_d3xx` — unavailable in the current product evidence. Its host-side receipt, exact-serial,
  configuration-readback and USB-descriptor policy is frozen, but there is no
  approved production receipt, production ABI/HIL, Receiver-Pod framing or
  source-boundary/replay hardware evidence. Host-side capability and request/ACK
  identity tracking exists; a fixed-depth, exclusive-owner asynchronous D3XX
  queue preserves IN completion order while allowing acquisition-only OUT; and
  an ordered ingest session checks identity before real journal append. The
  existing Tauri hardware-status command is connected to a strict, serialized,
  read-only React inspector. It shows only daemon-authored low-rate state and opaque
  evidence, becomes stale on poll/monotonicity failure, and neither enables this backend
  nor issues Run commands or transfers raw samples. The
  transport-neutral owner scheduler replenishes that queue exactly, accepts
  only explicit hardware-global time, cancels on failure and requires a
  pending-read frontier after verified Stop. A
  frozen 208-byte companion contract binds a Stop ACK to final source records
  already journal-appended, after which durability and seal remain separate.
  A separate Pod-time companion and self-hashed 64/176/256-byte local
  hardware-service contract let the daemon translate an operator-relative
  timeout against an exact fresh hardware-state hash. The SCM host exposes this
  on a distinct protected operator pipe, while Tauri forwards only relative
  deadlines and preflight identity. A journal-bound adapter now places that
  request in the same owner/order domain as Pod OUT, replies, hardware time and
  canonical journal append. Its bounded owner thread keeps polling when every
  GUI/pipe proxy is gone; client disappearance is never translated into Stop.
  `PreRunDirectPodConnection` now owns and continuously replenishes that same
  fixed IN queue before any Run exists. It admits only the protected capability
  statement and explicit Pod-time snapshots, retains fragmented parser state,
  and promotes the still-primed transport into a policy-bound no-overwrite Run
  root. Run/config/device/state-hash or storage conflicts fail before OUT;
  Prepare intent is stable before the first write.
  Ordinary ACKs remain insufficient. A frozen same-epoch Replay companion now
  binds the exact next journal range, admission/config hashes and bounded
  `REPLAYED` records; the host makes the full range durable before accepting a
  completion ACK and persists request/result in the hardware ledger. A separate
  frozen source-offer companion now lets the owner automatically derive Replay
  only when the Pod has quiesced live output, retains the exact next suffix and
  binds the latest fresh state; offer then request are durable before OUT.
  Unannounced gaps remain fail-closed. A bounded two-slot FPGA record-store component
  is implemented, but it has no Host release/eviction wiring, FT601 scheduler or
  product integration and therefore is not yet a usable Pod replay buffer.
  An exact-hash deployment policy can now bind the protected SCM service to a
  fixed D3XX source, admitted Pod/headstage/configuration, bounded queue and
  canonical no-overwrite Run root. On service start, and only when all three
  internal-policy arguments are present, the daemon first performs a bounded,
  deterministic scan of every policy-owned Run root. It rejects malformed,
  linked, incomplete or identity-contradictory evidence and durably marks an
  unfinished hardware lifecycle failed. Only after that scan succeeds does the
  owner enter a bounded fresh-epoch reconnect cycle. Its 272-byte hash-chained
  ledger makes `ATTEMPT_STARTED` durable before loading D3XX/opening the device,
  preserves the eight-attempt budget across service restarts, repeats receipt,
  DLL, serial, configuration, descriptor and capability admission, and accepts
  only a strictly newer Pod-originated epoch. Strict deployment-policy v4 also binds the
  exact three-source DHL identity catalog, selected Descriptor/Inventory identity and an
  explicit nonzero Host channel-layout ID that is independent of the board-profile ID. After
  the first capability, the same owner admits a bounded identity capsule plus fresh Pod-time
  and CABLINE evidence before Ready; runtime capsule bytes are rejected and every reconnect
  repeats that admission. After capsule admission and before identity storage/Ready, the
  capability is cross-checked for sufficient acquisition channels, signed-I16 support and
  the admitted exact rational rate range. Before Replay staging or journal append, canonical records must
  match the approved layout, acquisition-channel count and signed-I16 format; SampleBlock
  records must also match the exact approved rational sample rate, and the journal freezes
  the first numerator/denominator representation per Pod. FT601 receipt device
  identity remains distinct from the protected Headstage identity in the Descriptor. A
  transport fault first cancels
  the old owner and durably fails an unfinished Run; it never resumes that Run.
  The same primed connection then promotes into the journal-bound Run owner.
  There is still no issued production policy/receipt, qualified DLL/device,
  Receiver-Pod FPGA implementation, installed-SCM reconnect or HIL evidence;
- `aggregator_10gbe` — unavailable until discovery/control/stream APIs are frozen.

High-rate raw samples, integrity accounting, and the record writer will remain backend-owned. The frontend will receive only decimated display traces and immutable status snapshots.

The production **hardware** recording path remains unavailable. `forge-acqd`
now contains an SCM-hosted protected-replay service path: a persistent
local-only named-pipe listener, service-SID/operator-SID authorization, bounded
transport I/O, a daemon-owned fixed-capacity replay source/journal writer,
durable Run ledger, Stop/drain/seal, SCM-shutdown failure latching, and a Tauri
adapter that never transfers raw samples. The three private default endpoints
are `\\.\pipe\forge-acqd-v2`, `\\.\pipe\forge-acqd-hardware-v2` and
`\\.\pipe\forge-acqd-analysis-v2`; the exact retired v1 names are rejected, with
no compatibility fallback. The GUI can reconnect to an active or failed daemon
Run and explicitly acknowledge a failed Run without deleting its ledger
evidence. The 400-byte local response contract remains frozen at SHA-256
`1dccd163d6179b69adde2dbb738d1cfc3c0e471820338f36f9ffe2fb2bbf62ed`, and the
separate hardware companion remains frozen at SHA-256
`b1dd877cf9b9558352473f8458802a188919fb5a3865884c00a8eb83059e9b54`.
Transport v2 does not change those IDL bytes or hashes: it follows each response
frame with a fresh 16-byte challenge and requires `FACK || challenge` before the
transaction is counted complete. Every service-side pipe operation is
overlapped; cancellation has a finite drain and quarantines unconfirmed state.
These bounds cover named-pipe transport I/O only. A synchronous handler,
dispatcher, persistence call or hardware-owner call can still delay shutdown
without bound and remains a release-blocking qualification gap.
With no direct-Pod policy configured, status and Run submissions return an
evidence-bearing explicit `Unavailable`; they never fall through to replay and
perform no D3XX or device I/O. An explicit all-or-none policy triple binds the
SCM host to the bootstrapping direct-Pod owner described above. Any policy,
bootstrap, first-message or later transport failure keeps hardware unavailable
while the same owner performs the bounded durable reconnect cycle; it never
invents an epoch, resumes an old Run or switches to simulation.
On an orderly service shutdown, the owner cancels the transport and durably
marks every unfinished hardware Run failed before its thread exits. That local
fault is not a Pod Stop ACK and cannot seal or resume the old Run.
After an abrupt prior exit, the next explicitly configured service start performs
the same fail-closed lifecycle reconciliation before any D3XX DLL/device open.
It never truncates, seals, resumes or silently reuses an old journal. This is a
bounded host-software reconnect/recovery implementation, not installed-SCM
restart qualification or real D3XX/Receiver-Pod evidence.

This is not deployment or release evidence. The service is not installed or
started by the repository checks; its installer requires an exact confirmation
token, creates an on-demand service, and does not start it. The data-plane suite
terminates real child processes at active-Run and unbarriered-journal-tail cut
points and verifies durable-prefix recovery plus evidence-preserving failure
acknowledgement. Focused pipe tests additionally prove cancellation of truly
pending prefix/body/ACK reads and per-client recovery after malformed or missing
ACKs.

The historical v1 same-supervisor 1,000-kill run remains evidence only. A later
`forge.gui-kill-qualification.v2` local engineering-stress run at
`E:\temp\forge-acqd-gui-kill-1000-independent-v2-20260826-085443-f1cda93eff53`
used distinct supervisor/owner PIDs 6584/29984, `owner_process_isolated=true` and
`owner_job_assigned=true`. It completed 1,000/1,000 real GUI kills: 500 after ACK
plus reaccept and 500 pending `AckRead`; raw GUI sample bytes and GUI Stop/Abort
were zero, while one supervisor Stop sealed 18,882 records (`0..18881`) at the
durable frontier. The Rust verifier, recomputed file hashes and audit statistics
passed: journal 7,024,168 bytes SHA-256 `428781...9ef467`; audit 5,009 events
(`0..5008`), 4,222,855 bytes SHA-256 `7e2809...7111fa`, including 1,000 valid
`ReapProven` exit/bounded-wait/signaled records. Its Job-method label was selected by
the supervisor and did not persist Job active/empty queries. The retained executable is
`747809...9fb2ef`; receipt evidence hash is `1d47e1...4df1fa`. This remains
`scm_emulated=true`, `service_deployed=false`, hardware/NWB false, and is a local
engineering stress pass—not deployed SCM, M1/product-release, or hardware evidence.

Current receipt/audit v3 creates every owner/GUI child suspended, configures and assigns
`KILL_ON_JOB_CLOSE`, reverifies the stable retained executable, then resumes. Typed
containment/reap evidence reaches the owner, which independently waits the retained process
handle and cross-checks exit/deadline; Job active-zero/empty remains supervisor-observed.
Fresh software evidence is 446/446 qualification unit plus 4/4 GUI-loss integration and
4/4 crash tests; the 1,000-kill test is ignored, so the v2 artifact is not v3 evidence.

The `qualification-harness` feature is default-off; the formal default release at
`recording-daemon\target\formal-default-release\x86_64-pc-windows-msvc\release\forge-acqd.exe`
is a local build check (SHA-256 `4cf1e0...8db1dd`, 2,082,304 bytes), rejects all GUI-kill
commands and contains no harness token. Installed SCM/ACL/restart/blocked-handler shutdown,
mapped-image/path-ancestor ABA, abnormal same-account early Resume, qualification-root
ACL/WDAC/Authenticode, owner-independent Job queries, pending-AckRead request/challenge
binding, listener/observer joins, D3XX/NWB/endurance/HIL and release remain open.
Deployed ACL/SCM policy, hostile-client qualification, target-storage endurance,
and the 190.08 MB/s/24-hour dual-write gates remain open. The GUI replay profile
is about 60 kB/s with one synthetic channel and cannot stand in for those gates.
The SafetyArbiter is not restart-persistent and cannot reach hardware. No D3XX,
10GbE, or RHS hardware path is opened. The legacy `serve` command remains
fail-closed; the authenticated listener is reachable only from the SCM service
entry point. See
[recording architecture](docs/RECORDING_ARCHITECTURE.md)
and [NWB storage profile](docs/NWB_STORAGE_PROFILE.md).

Control-plane loading and trace-update budgets are defined in the [performance budget](docs/PERFORMANCE_BUDGET.md). The shell has no runtime font/network dependency; raw samples are forbidden from the WebView.

Rust data-plane checks:

```powershell
cd F:\poorsystem\Forge\host_app\recording-daemon
pixi run --manifest-path ..\pixi.toml test-data-plane
pixi run --manifest-path ..\pixi.toml self-check-data-plane
```

The direct-Pod probe is read-only: it does not open or configure a device and
always reports `hardware_transport_available=false` and
`approved_admission_receipt_present=false`. It is useful for checking whether a
supported D3XX library and FT601 descriptor are present without enabling
hardware acquisition:

```powershell
cd F:\poorsystem\Forge\host_app
pixi run cargo run --locked --manifest-path recording-daemon/Cargo.toml -- d3xx-probe
```

An unpacked official FTDI application DLL can be probed without copying it to
System32 or enabling acquisition. The path must be absolute; the loader uses
only that DLL directory plus System32 for dependencies and reports the loaded
module path and SHA-256:

```powershell
pixi run cargo run --locked --manifest-path recording-daemon/Cargo.toml -- d3xx-probe --library C:\absolute\official-ftdi-package\FTD3XX.dll
```

The operator must separately inspect the official package provenance and
Windows Authenticode status. A successful explicit-path probe still reports
`hardware_transport_available=false` and creates no admission receipt.

The default SCM Run path remains protected-replay plus an explicitly unavailable
hardware companion. A driver or device appearing in the probe is not sufficient
to enable D3XX recording. Hardware bootstrap also requires the exact protected
320-byte FT601 admission receipt, policy file and their independently configured
hashes, including an **internal Forge approval-authority identifier**. This is
an internal verification binding, not an FTDI licence, activation server or
external authorization. No production policy or per-unit receipt currently
exists. The gates in
[`docs/D3XX_ADAPTER_BOUNDARY.md`](docs/D3XX_ADAPTER_BOUNDARY.md) still apply.

Journal-only eight-Pod release-build qualification is an explicit, no-overwrite
command. The output paths must not already exist:

```powershell
cd F:\poorsystem\Forge\host_app
pixi run cargo run --release --locked --manifest-path recording-daemon/Cargo.toml -- journal-qualification --journal <new.wal> --receipt <new-receipt.json> --duration-seconds 1800 --target-bytes-per-second 190080000 --durability-batch 1024
pixi run cargo run --release --locked --manifest-path recording-daemon/Cargo.toml -- verify-journal-qualification --receipt <new-receipt.json>
```

The receipt binds the protocol hash, executable hash/build mode, eight-Pod
profile, target volume identity, record watermarks, latencies, CPU/RAM, journal
hash and duration/throughput gates. A run shorter than 30 minutes is always
`smoke_only`; 24 hours is required for its journal release-duration flag. This
runner does not enable D3XX, 10GbE or NWB dual-write and therefore cannot satisfy
the product release gate by itself. A fresh one-second release smoke on
2026-08-13 reached 287.22 MB/s canonical input and was independently reopened
and verified, but correctly remained `smoke_only` with both duration gates false.

M0 protocol checks can be run alone with `pixi run test-protocol`; temporary
C++ verifier binaries are created under the system temporary directory and
removed by the checker.

## Interaction provenance

The information hierarchy was independently designed after reviewing Open Ephys GUI, SpikeGLX, and Intan RHX. No source code, screenshots, icons, branding, or pixel layouts were copied. See `DESIGN_NOTES.md` for the specific interaction ideas and license boundary.

## License

Forge Acquire is licensed under the GNU General Public License version 3 only
(`GPL-3.0-only`). See [LICENSE](LICENSE).
