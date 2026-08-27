# Forge Acquire implementation status

Status date: 2026-08-26
Evidence rule: a source file or passing unit test is not a hardware, endurance,
scientific, animal-safety, or product-release claim.

| Milestone | Implemented in this tree | Still fail-closed / unavailable |
|---|---|---|
| M0 — protocol and safety boundary | Host-internal little-endian record/control IDL, protocol hash, CRC-32C codecs, golden/illegal vectors, Rust/Python/C++ verification, `SafetyProfileV1`, intent/command/receipt and single-controller-token model. A self-hashed companion event-payload IDL freezes Marker/Fault/Gap/OnlineAnalysis bodies without changing the parent protocol bytes/hash. The Rust CRC implementation uses runtime SSE4.2 acceleration with an exact portable table fallback | Receiver Pod FPGA, D3XX and Aggregator bindings; authenticated device identity; approved real-electrode Safety Profile; formal/HIL evidence |
| M1 — Protected Replay Run v0 | Independent `forge-acqd` crate, deterministic daemon replay source, fixed-capacity pool/queue, version-bound journal, durable checkpoint/seal/recovery primitives, bounded no-overwrite Run command/journal-seal/fault ledger, restart fail-closed reconstruction, persistent SCM listener/control handler, and private control/hardware/analysis named-pipe transport v2 with exact retired-v1 rejection. Every service transport operation is overlapped; stop/deadline cancellation has a finite drain and unconfirmed completion is quarantined/poisoned. A fresh 16-byte challenge plus `FACK || challenge` proves response consumption without changing frozen IDL bytes/hash or claiming exactly-once. The retained v2 SCM-emulated stress artifact completed 1,000 real GUI kills with a separate owner/supervisor and append-only audit; its Job method label was supervisor-command-derived and it did not persist Job active/empty proof. Current v3 code closes the ordinary parent-controlled spawn-to-Job window by creating each child suspended, configuring `KILL_ON_JOB_CLOSE`, assigning it to the Job, reverifying the retained executable and only then resuming. Typed v3 control/audit/receipt evidence carries all containment facts plus bounded reap evidence; the owner independently waits its retained primary-process handle and cross-checks exit/deadline evidence. V3 has software tests and a four-case integration smoke only, not a new 1,000-kill run. `qualification-harness` is default-off; the fresh formal-default build rejects all harness commands and contains no harness token | This is not installed SCM or production M1 qualification: `service_deployed=false`, `scm_emulated=true`, hardware/NWB false. Synchronous handler/dispatcher/persistence/hardware-owner work is outside transport deadlines. Installed identity/ACL/restart/blocked-handler shutdown, mapped-image/path-ancestor ABA, abnormal same-account early Resume, qualification-root ACL/WDAC/Authenticode, owner-independent Job active/empty observation, pending-AckRead request/challenge binding, listener/observer joins, response-write/quarantine faults, hostile clients, PLP/ENOSPC, NWB dual-write, 190.08 MB/s/24-hour, hardware/HIL and release remain unavailable |
| M2 — NWB and analysis platform | Frozen `ForgeAnalysisRingV1` layout; bounded Rust SPSC reference core; pagefile-backed local Windows named mapping with service-token gate, explicit SID DACL, first-instance/identity checks and real child-process consume evidence; independently protected SCM worker-registration pipe with authenticated process-instance-bound idempotence and mapping-name handoff; journal-after-commit replay fan-out with forced-full no-backpressure seal evidence; Rust-generated Python/C++ snapshot validation plus C++20 Interlocked and CPython-native live consumers; bounded Python/C++ worker SDK foundations; deterministic reference threshold/template/LFP algorithms; durable-prefix journal reader; canonical payload materializer; exact-version optional PyNWB/HDF5 uncompressed SWMR generation writer; required session/subject metadata; one `ElectricalSeries` per Pod; numeric provenance; six typed event append/reconciliation paths; independent sealed/live one-generation `forge-nwbd` with a 1..2000-ms bounded poll scheduler; exact per-block canonical/HDF5 raw-byte equality with per-Pod digests; frozen CRC32C validation/publication receipts; closed-generation validator; Rust streaming owner verifier; idempotent same-directory no-overwrite publisher and restart-persistent Run `Finalized` binding; generation-isolation/cross-reader/schema/Inspector/tamper tests plus a deterministic checkpoint/EOF race and one real subprocess-kill/fresh-generation rebuild | Installed-service evidence, multi-worker/restart supervision, adversarial same-account isolation, deployed DACL/order and target-load qualification, production `forge-nwbd` service supervision, qualified worker executable/ACL/stable-handle trust or independent Rust HDF5 decoding, hardware-originated event producers, measured two-second visibility under load, directory-metadata/PLP proof, 100-kill/NTFS/endurance/190.08 MB/s evidence and scientific algorithm validation |
| M3 — one-Pod D3XX | Read-only probe; search-hardened dynamic D3XX loader; 320-byte FT601-only admission receipt (`8a6c…b992`) binding DLL/serial/configuration/descriptor/Host protocol/hardware build; exact `FT_DEVICE_601=601`, unique-serial/SuperSpeed selection and FT600 rejection; exact configuration/USB-descriptor gates; fixed-depth asynchronous duplex I/O; strict record/control/time/Replay/CABLINE/identity-capsule demultiplexing; journal-bound lifecycle; Stop/Replay/time companions; protected deployment/reconnect owner. The Host catalog understands 14 exact identities as 10 `active_product`, 3 `active_option` and 1 `decode_only`; the added graph-closed `rhs2116x2_imu` tuple is `(3,2,6,32)` with instances `[0,1,100]`, while current Headstage/Pod RTL remains frozen at 13 identities. Its three exact source hashes and bundle `8493dc…9ee4c` are policy-bound, and catalog status is not hardware, Run, release or stimulation authority; Host v1 stimulation remains false for the new 32-channel RHS option. The Python bridge has an exact 8-byte ACK codec, explicit Descriptor/Inventory/Neural/ACK dispositions, one pending CTRL, successful-QUERY Inventory-replay-before-ACK ordering, exact approved assembly/channel-map hashes and instance IDs, poison-until-relock semantics, and deterministic Descriptor-derived 1-ms Neural aggregation. The 360-byte `ForgeDirectPodCablineStatusV1` (`40670b…cad0`) binds device/Pod/headstage/epoch, source/boot, fault-free link state and five source hashes. Strict deployment policy v4 separately approves that composite plus the exact selected Descriptor/Inventory/config/rate/assembly/channel-map/ordered-instance identity and an explicit nonzero Host channel-layout ID independent of board profile ID; v1/v2/v3 and malformed v4 files fail closed. The 472-952-byte `ForgeDirectPodDhlIdentityCapsuleV1` (`346b02…a3ae8`) carries the exact 140-byte Descriptor and 152-632-byte Inventory; its FT601 receipt device ID remains distinct from the protected Headstage ID in the Descriptor. Capability must be first; capsule, fresh Pod time and CABLINE evidence may then be arbitrarily split/ordered but all are required before Ready. Exact duplicate capsule is idempotent; mutation, runtime capsule arrival or identity/hash/source/boot/sequence contradiction poisons the epoch, and reconnect repeats identity admission. The daemon measures freshness with its own monotonic clock and captures the wall origin at owner request/poll entry, so planning, translation, IN parsing and journal work consume the same budget. Every Run-command and automatic-Replay path checks before durable intent and immediately before OUT; promotion also spans artifact creation. Service evidence binds the time/CABLINE companions while admitted identity remains Rust-data-plane owned. Before Replay staging or journal append, every protected canonical record is checked against the approved layout, catalog/Descriptor channel count and signed-I16 format; SampleBlock also binds the exact rational rate, and mismatch poisons the session before record count advances. At the decoded-symbol seam, portable Receiver-Pod RTL now supplies atomic packet CDC, a structural parser, an Arm-context bank, exact payload SHA/startup match components, Descriptor/Inventory semantic parsers, an atomic startup fanout wrapper, a registered terminal contract guard, a committed-SYS-to-contract component pipeline, a standalone Neural semantic parser and a Phase-2A two-slot atomic canonical-record store | Active Receiver-Pod hardware integration is still missing: ECP5 receive PCS/8b10b decoder and physical top, attachment of the portable startup/Neural/store components to the product CDC/runtime path, product 1-ms aggregation and DHL-to-canonical packetizer, identity-capsule/CABLINE-status emission, FT601 bidirectional scheduler, CTRL execution, Stop ACK/completion, Host-authoritative release/eviction wiring for the two-slot store, persistent epoch, MG285 LPF/SDC/routed STA and HIL. DHL Status/Error/Stim/IMU/Chem Host mappings remain unfrozen even though ACK is typed. VID/PID/serial/descriptor/config values are not released, and no supported D3XX DLL, FT601 unit, approved policy-v4 file, approved CABLINE binding or per-unit receipt is installed. No 24-hour hardware journal+NWB evidence exists. The 2.5-V VCCIO and 32-bit wiring remain board-build evidence. Hardware and stimulation therefore stay unavailable |
| M4 — RHS closed loop | Hard-disabled UI, host protocol, preflight/release-gate evaluators and an in-memory Rust SafetyArbiter foundation for replay/dummy-load tests | Persistent authenticated controller/nonce ledger, physical ENABLE/e-stop/power gate/watchdog, headstage fixed-template safety engine, hardware communication, compliance and exactly-once physical receipts, dummy-load/HIL and animal approval |
| M5 — eight-Pod Aggregator | Shared interface and two-path release-gate model only | 10GbE discovery/control/stream, global-time epoch, partial-Pod recovery, eight-Pod endurance and physical latency gates |

M2 additionally revokes a process-instance-bound controller lease on rejected
registration, final-owner drop and runtime health/data faults before offering a
fault event to a concrete capacity-16 process-local `try_send` queue. Queue loss
is visible and never backpressures the journal, but no durable fault-evidence
consumer is qualified. NWB publication retains `.nwb.inprogress` and has no
caller-input deletion authority; retention remains a separate fail-closed gate.

The current retention implementation streams large journal/final-NWB hashes through a
fixed 64 KiB buffer, bounds small evidence before allocation, caps a journal at eight Pods
and read-only ledger proof at 1,024 events, and never creates/appends state while proving an
old Run. It still always returns `Retain/UnqualifiedBackupAcl`; no cleanup authority exists.
Direct-Pod Ready additionally cross-checks admitted identity against capability channel
capacity, signed-I16 support and exact rational-rate range before storing the identity.
Protected records bind layout/count/format/rate before staging or append, and the journal
freezes each Pod's exact numerator/denominator representation.

## Current reference implementation evidence (not product M3 closure)

The Python `DhlToHostBridge` now derives a deterministic integral 1-ms block from
the admitted Descriptor rate. At 30 kHz, one block is 30 full-channel rows (one
row is one frame); arbitrary Neural packet boundaries are supported, one packet
may produce 0..N canonical records, and `record_sequence` is independent of DHL
`sequence`. The first sample counter and 25-MHz timestamp establish the rational
absolute-time anchor. A successful `NEURAL_STOP` ACK alone flushes the pending
1..N-1-row tail as an unpadded, structurally complete `SampleBlockV1` carrying
`COMPLETE | HARDWARE_TIMESTAMPED`; failed or other ACKs do not flush. This is the
reference “last record before ACK” semantic and does not equate Stop with saving.

The portable canonical builder is record-atomic in EBR and emits the exact
176-byte `CanonicalRecordEnvelopeV1` header plus 32-byte `SampleBlockV1` header,
CRC32C, 32-bit words with BE/SOP/LAST. It formats explicit external
`record_sequence_i` and does not own Run sequence allocation. Pre-built abort discards
only the incomplete prefix; after `record_built_o`, immutable output drains to the
distinct `record_transferred_o` boundary. Five variants execute 17 tests with 58
filter-only skips. Wide parameter guards close EBR/1-MiB payload limits, and invalid/X/Z
beats cannot create unproven state effects. The per-Run sequence owner and record-store
commit are separate from the builder. An explicit 128-channel/30-row/
`RAM_ADDR_W=11` generic resource probe proves the 1,920-word sample image fits in 2,048
addresses and reports 4 DP16KD, zero MULT18X18D, 3,119 LUT4, 1,356 FF, 252 CCU2C
and 250 PFUMX with 0 problems. Exact-device out-of-context pack-only reports 3,773
TRELLIS_COMB, 1,356 FF, 4/56 DP16KD and zero DSP. Pack-only establishes
device resource legality, not placement, routing, timing closure or hardware behavior.
The separate Phase-2A two-slot store now owns sequence and atomic complete-record commit;
it passes 8/8 focused tests, including Abort cancellation of an active replay and an
explicit forensic restart, and exact-device pack-only at 93 total LUT4s,
99 TRELLIS_COMB, 23 FF,
8/56 DP16KD and zero DSP. It has no Host release/eviction input, so two committed records
remain retained and backpressure capture. The 312-byte durable-release companion is
codec-tested but not wired to the store or FT601 path.
The RHD2132x1 producer reference has 125-MHz/30-kHz 4166/4167/4167 launch cadence,
25-MHz 833/833/834 timestamp cadence, a 64-bit sample counter, epoch-sticky
overrun handling, and in-flight drain before Stop ACK eligibility; its targeted
result is 7/7.

At the decoded-symbol seam, Receiver-Pod CDC now latches the first fault code,
counts only the first failed in-flight packet once, rejects sequence u64 MAX
wraparound, and separates RX committed from SYS delivered packet counts. The
latest targeted results are guard 7/7, CDC 18/18 and FIFO 1/1. The CDC Yosys
result is 19 DP16KD, 1670 LUT4, 1737 TRELLIS_FF, 347 CCU2C and 214 PFUMX with
0 problems. The CDC now also exposes the retained first RX fault as a stable
SYS-domain snapshot.

The SYS structural parser has 10/10 focused tests for exact metadata, payload/CRC
separation, BE/SOP/LAST, arbitrary backpressure, reset-held valid and transport/input
X/Z fail-closed behavior; generic synthesis is 606 LUT4, 690 TRELLIS_FF, 28 CCU2C
  and 27 PFUMX with 0 problems. The Arm-frozen Run-context bank has 17/17 focused
  tests for atomic capture, canonical 1..16 instance sets, exact duplicate idempotence,
  conflict rejection, quiescent Disarm and frozen legal `target_rows`; it synthesizes to
  5,179 LUT4 and 1,947 FF with 0 problems. These results are component/reference
evidence, not evidence that the product M3 path is closed.

The registered startup/runtime phase dispatcher passes 15/15 focused tests, including
metadata backpressure with a held first payload byte, exact count/LAST/done, early and
missing LAST, unknown sink ready and epoch X/Z masking. Generic ECP5 synthesis is 430
LUT4, 321 FF, 22 CCU2C and 8 PFUMX with zero problems. It remains a standalone seam:
the current startup pipeline and product top do not instantiate it, and no runtime
Neural/ACK/Stop/replay semantics are implied.

The standalone Neural payload parser passes 24/24 focused tests with strict single-file
lint clean. It validates frozen running/channel context, exact prefix/outer length and the
1-MiB ceiling, signed little-endian sample-major rows, LAST/done structure, counter
continuity, X/Z boundaries and the legal case where packet done pends behind a
backpressured final sample. It retains a sequence/exclusive-end completion transaction
until consumed; this is not rollback. Fresh generic synthesis is 1,035 LUT4, 480 FF,
299 CCU2C, 50 PFUMX and zero DSP; exact-device pack-only uses 1,743 TRELLIS_COMB,
  480 FF, zero EBR and zero DSP. The portable Neural-to-canonical pipeline attaches it to
  time mapping, blockization, canonical construction and the two-slot store. The dispatcher,
  committed CDC/runtime output, product top and FT601 remain unattached.

The standalone bounded Neural blockizer passes 12/12 top-level tests containing 65 real
assertion-bearing subcases. Its default 30-row/128-channel, two-bank instance performs
cross-packet sample-major aggregation, supports packets spanning multiple blocks, holds
metadata/data stable under sink stalls, and drains three full blocks plus an unpadded tail
after Stop. Stop blocks new metadata but does not truncate the accepted packet, and a fault
withdraws quiescent status. Combined strict lint is clean; exact-device pack-only uses
  5,525 TRELLIS_COMB, 1,616 FF, 8 EBR and zero DSP. The portable pipeline attaches it to
  the parser, rational mapper, canonical builder and replay store. Stop ACK authority,
  dispatcher/CDC, FT601 and product top remain outside the seam. Only the default product
  instance is tested; the wider parameter guard and defensive 1-MiB branch are not qualified variants.

The standalone rational Neural time guard passes 21/21 focused tests. It implements one
transport-epoch anchor, exact rational floor mapping, strict `<40 ns` timestamp admission,
u64/u128 overflow rejection, metadata-before-sample gating and counter queries while the
sample proxy is open. Unified strict lint is clean; generic synthesis reports 1,315
LUT4, 1,044 FF, 254 CCU2C, 143 PFUMX and four DSP; exact-device pack-only uses
  1,865 TRELLIS_COMB, 1,044 FF, zero EBR and four DSP. The portable pipeline now
  connects it to parser/blockizer/adapter/builder/store; this is still not product
  attachment, routed timing or hardware evidence.

The standalone block-to-canonical adapter passes 25/25 focused tests. It freezes the Arm
identity/layout/rate context, obtains both canonical block boundaries from the rational
guard, maps every builder field, and keeps the first-packet timestamp as provenance only.
Known descending end time, stale results, context mutation and X/Z inputs are masked before
  handshake. Unified strict lint is clean; fresh generic synthesis reports 2,088 LUT4,
  826 FF and zero DSP; exact-device pack-only uses 2,666 TRELLIS_COMB, 826 FF,
  zero EBR and zero DSP. The portable pipeline connects it to parser, time guard,
  blockizer, builder and replay store; FT601 and product attachment remain open.

Fresh component-wise exact-device pack-only evidence attributes zero DSP to the parser,
blockizer, adapter and 128-channel builder and four DSP to the rational time guard.
The prior co-resident 22-DSP report predates the multiplier removal and is stale. A fresh
flattened aggregate attempt stopped at the high-memory AUTONAME phase and emitted no new
JSON/pack report. Therefore no current aggregate fit, LUT/FF/EBR total or four-DSP product
claim is made. SYS parser/dispatcher, startup/Arm, CDC/PCS, store/release, FT601 scheduler,
product P&R, timing and HIL remain open.

The exact startup-validation seam now has SHA core 5/5, startup hasher 4/4 and
hash-match gate 5/5 focused results. The one-pass Descriptor parser covers the frozen 13
wire-level RTL tuples at 6/6; it does not yet admit the Host-only
`rhs2116x2_imu` tuple and therefore cannot make that option hardware Ready. It
synthesizes to 507 LUT4, 787 FF, 4 CCU2C and 18
PFUMX. The Inventory parser covers board profiles 1..8, strict entries and stable
backpressure at 5/5 and synthesizes to 1,626 LUT4, 997 FF, 179 CCU2C and 57
PFUMX. All generic checks report zero problems. Decode coverage is not product
admission, and none of these standalone blocks is connected to the product top.

The portable startup wrapper composes exact hashing with the two semantic parsers,
requires Descriptor type 1 then Inventory type 9, stalls both fanout consumers
atomically, and blanks admission in the same cycle as a post-admission wrapper fault.
Its focused result is 6/6 and generic ECP5 synthesis is 9,021 LUT4, 5,551 FF,
609 CCU2C, 344 PFUMX and 3 L6MUX21 with zero problems. This remains component
evidence; it is not connected to the active product top.

The terminal startup guard passes 8/8 and the committed-SYS component pipeline passes
6/6, including registered-Arm provenance, Descriptor/Inventory/Arm/exact-instance
cross-checks, transport 1/X/Z same-cycle withdrawal, quiescent Disarm and epoch recovery.
Unified synthesis reports 17,546 LUT4, 9,270 FF, 818 CCU2C, 825 PFUMX and 25
L6MUX21 with zero problems. The strict open boundary is now product attachment: this
  startup component pipeline and portable Neural-to-canonical pipeline are still not connected
  to each other, the registered dispatcher, committed CDC runtime output or FT601 scheduler.
  The Neural pipeline itself now composes parser, rational guard, 1-ms blockizer, adapter,
  builder and two-slot store and passes 18/18 focused tests, including persistent Stop drain,
  preparatory/running/stopping Abort, immutable/prebuilt cut points, full-store backpressure,
  store-fault termination and forensic replay. The Phase-2B release guard passes 11/11 but
  is not an authenticator or store evictor. CDC still begins at the
vendor PCS decoded-symbol seam;
the ECP5UM PCS/physical top, MG285 LPF/SDC/P&R/HIL, RHD2164/RHS exact cadence and
product integration are not closed. The current machine has no supported D3XX
DLL, FT601 device or approved receipt, so hardware remains unavailable.

Fresh unified verification runs 50 CABLINE logical targets expanding to 56 simulations.
Their XML records 299 actually executed testcases plus 58 filter-excluded skips; every
simulation executes at least one test and there are zero failures/errors. Critical
parser, dispatcher, Neural-parser, startup-pipeline and canonical variants also enforce
exact executed counts. The argument-free local runner now derives its all-target list
from the complete 69-target registry instead of a stale hand-maintained subset.
DHL Python passes 38/38. The Host surface passes 52/52 UI tests, production build and a
77.65 KiB gzip JS / 5.16 KiB gzip CSS budget; the default data plane passes 434/434 unit
plus 4/4 process-crash tests, while the qualification feature passes 446/446 unit,
4/4 GUI-loss integration tests with the 1,000-kill case explicitly ignored, the same 4/4
crash tests, warning-denied clippy, and 32 worker tests. The isolated exact-version
NWB profile separately passes 12/12 synthetic tests, including one real worker kill and
fresh-generation rebuild; that result is not a production kill/endurance gate.

The production UI must derive availability from evidence-bearing daemon and
hardware receipts. It must never turn a row in this table, a simulator value,
or a locally passing software test into a green hardware capability.

## Current operator surface

- The control surface is an offline Tauri/React bench instrument.
- The Run integrity rail separates reception, journal, durability, NWB,
  analysis, stimulation receipts and validated publication.
- The simulator is always marked synthetic and writes zero raw bytes.
- Recording and stimulation use separate Arm concepts; stimulation remains
  hard-disabled because there is no authenticated Arm IPC or hardware receipt.
- New-Run preflight exposes Headstage catalog identity and electrical-graph status and
  rejects a missing, decode-only, or `graph_closed=false` identity; Protected Replay is exempt because it creates no hardware Run.
  The synthetic backend can display `rhd2132x2` for compatibility but cannot start a
  new synthetic Run with it.
- Stimulation preflight now binds the reported Headstage profile to electrical-graph
  closure and the separate Host v1 stimulation-capability flag. A physical 16-channel
  shape from an electrochem, mixed, or open-graph profile is insufficient to request Arm.
- Raw samples are prohibited from React/WebView state. The current Canvas path
  is a bounded UI prototype, not the production shared-memory/binary channel.
- The existing Tauri `hardware_snapshot` bridge now feeds a dedicated 500-ms,
  serialized, read-only status adapter and compact inspector section. It validates the
  exact response shape, request echo, enums, availability bits, evidence hashes and
  same-epoch sequence/time/counter monotonicity. All protection `u64` values cross Tauri
  as canonical decimal strings and remain TypeScript `bigint`; numeric/noncanonical or
  out-of-range values and extra raw fields fail closed. An error or regression immediately
  becomes stale rather than retaining a green state. Polling state is local to the
  inspector, so it does not rerender the trace workspace. It sends no Run command,
  creates no hardware backend and carries no raw sample bytes; `direct_d3xx` remains
  statically unavailable. The current frontend gate is 52/52 tests and production build;
  Vite reports 79.51 kB gzip JavaScript / 5.28 kB gzip CSS, while the independent budget
  check reports 77.65 KiB / 5.16 KiB because it uses a different compressor/units.
- Protected Replay can be selected only when an authenticated SCM response
  advertises the capability. It is a roughly 60 kB/s synthetic M1 lifecycle
  profile, not D3XX, storage-throughput or 24-hour evidence.
- `journal-qualification` is a separate synthetic journal-only profile. Its
  receipt binds either active `8×128ch` geometry (7,888-byte canonical / 7,992-byte
  journal record) or the default conservative `8×256ch` protocol envelope
  (15,568 / 15,672 bytes). Only the conservative profile, a release build, 24 hours,
  sealed/reopened reconciliation and `max(caller target, 190.08 MB/s)` can expose a
  conservative journal flag; the 128ch profile cannot. It never advertises hardware
  or NWB dual-write. Verification rescans decoded record geometry and requires the exact
  current executable. The receipt remains unkeyed local-integrity evidence, not a
  signature or independent clock attestation. The 2026-08-13 one-second release smoke reached 287.22 MB/s
  canonical input and independently verified its receipt, but remains
  `smoke_only`; it is not the 30–60-minute engineering gate.

## Release receipt floor

`src/core/release.ts` encodes the approved minimum evidence as a fail-closed
receipt preflight: both direct and Aggregator paths, 24-hour/126.72 MB/s normal
load, 190.08 MB/s stress load, journal plus uncompressed NWB, all listed fault
injections, GUI/worker kill counts, five target operators, and one million
dummy-load stimuli per path with zero duplicate, unreceipted or late physical
execution. A passing preflight permits an independent signer to create a
receipt; it is not itself a signed release receipt.

## M2 NWB process-boundary checkpoint (2026-08-26)

- The owner-internal supervisor now compiles outside tests, but production launch remains
  disabled until a handle-relative generation-root proof exists.
- A Windows one-shot launcher verifies a dedicated executable, image manifest and bounded
  session manifest, supplies an explicit environment/working directory, and reuses the
  existing suspended-Job-rehash-resume containment path.
- A fixed binary attempt audit and receipt cover pre/post-launch failure, worker identity,
  terminal Job evidence, CRC/hash-chain tamper and create-new behavior.
- Default builds keep `verify-nwb-generation` but omit mutating publication; the old
  publication fixture is available only with `qualification-harness`.
- Current software evidence is 452/452 Rust unit tests, 4/4 process-crash tests and 12/12
  isolated NWB tests. It is not production Supervisor V2, installed SCM/ACL, 100-kill,
  throughput/endurance/PLP, FT601/D3XX/Aggregator or HIL evidence.
