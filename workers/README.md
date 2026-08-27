# Forge worker and NWB materializer foundation

Status: SDK/reference implementation plus synthetic NWB SWMR generation and
cross-language validation evidence. This subtree is not hardware, production
recording, stimulation, final publication, or scientific-validation evidence.

This isolated foundation defines two boundaries that must remain outside the GUI and outside the acquisition critical path:

1. bounded analysis consumers operating on immutable views adapted from M0
   `CanonicalRecordEnvelopeV1` + `SampleBlockV1`; and
2. a regenerable, one-Run/one-generation journal-to-NWB materializer contract.

The host-internal `ForgeAnalysisRingV1` layout is frozen at version 1. It gives
each analysis consumer an independent fixed-capacity SPSC ring carrying one
complete canonical record per slot. Full rings reject the newest downstream
copy, increment a branch-specific drop count and never wait for the journal;
any drop on a closed-loop branch requires stimulation disarm. The Rust core
now also owns a pagefile-backed, local-session, first-instance Windows mapping
with explicit SYSTEM/service/worker SID DACL construction and immutable
Run/consumer/epoch checks. A real child process opens and consumes that mapping;
the protected-replay writer publishes only after journal append, and a forced
full analysis branch latches its own drop/fault while the journal still seals.
Controller registration and final-owner drop revoke the exact process-bound
lease before any evidence work. Runtime faults then use a concrete capacity-16
process-local `try_send` queue; queue loss is visible but neither enqueue nor
drain is durable evidence, and no persistence worker is qualified yet.
The C++20 SDK has a Windows live consumer using Interlocked operations and an
owned-record copy before slot release. Python uses that same consumer through a
CPython C++20 extension; it never performs shared-memory atomics through the
GIL or reads a mutable slot after release. The optional SCM host has an
independently ACL-protected worker-registration pipe that binds exact retries to
the authenticated client process instance and returns the daemon-created
mapping contract. Multi-worker restart supervision, deployed service evidence,
adversarial same-account isolation and target-load qualification remain
unavailable.

The Python reference algorithms include threshold crossing, fixed-template classification, and configurable LFP band-power/phase estimates. They are deterministic benchmark/reference implementations. They have not been validated for spike sorting, biomarker inference, closed-loop control, diagnosis, or any other scientific or clinical use.

Stimulation is data-only here. Python workers may construct only the normative
M0 `StimIntentV1`; C++ workers can only inspect/forward the M0 read-only view.
Authorization and `StimCommandV1` generation belong to the Rust SafetyArbiter.
Neither worker SDK exposes register addresses, device writes, a local
authorization shortcut, or a stimulation execution API.

## NWB availability boundary

The default Forge pixi environment intentionally omits PyNWB and NWB
Inspector, so the ordinary worker check remains fail-closed and creates no
NWB. The isolated `nwb` pixi environment locks h5py 3.16.0, HDF5 2.1.0,
PyNWB 4.1.0, and NWB Inspector 0.7.2. In that profile,
`PyNwbSwmrBackend` can create a new generation-specific, uncompressed
`.nwb.inprogress` file; it never overwrites, resumes, renames, or publishes an
artifact.

`forge_workers.materializer` and the one-generation `forge_workers.forge_nwbd`
executable provide sealed and pull-only live modes. The live mode creates a
fresh generation immediately, follows only the A/B durable watermark, and
waits for a matching seal without sending control or backpressure to
acquisition. It defaults to a 250 ms poll interval and rejects configured
intervals outside 1..2000 ms:

- an exact, A/B-durable-watermark-bounded parser for `FORGEWAL`;
- canonical-record decoding for SampleBlocks and the frozen typed
  Marker/Fault/Gap/OnlineAnalysis/StimIntent/StimReceipt bodies, while separately preserving global
  `journal_sequence`, per-Pod `record_sequence`, authoritative 16-byte Pod ID,
  16-bit `pod_slot` projection, and end-exclusive ranges;
- a one-Run/one-generation manifest and progress checkpoint;
- a schema plan with one `ElectricalSeries` per Pod;
- required experiment/session/subject identity rather than fabricated animal
  metadata;
- predeclared and appendable marker, fault, gap, analysis-result,
  stimulation-intent, and stimulation-receipt table contracts, with closed-generation journal-to-table reconciliation;
- a real optional SWMR generation writer with numeric per-block provenance;
- exact per-block raw-byte comparison between canonical SampleBlock sample bytes
  and HDF5 `<i2`, C-order `[sample, channel]` slices, plus per-Pod digests;
- an executable fail-closed preflight with explicit unavailable reasons; and
- a frozen 544-byte CRC32C validation receipt binding the journal, seal, A/B
  checkpoints, manifest, schema/dependency/build identities, closed NWB,
  validation report, per-Pod sample counts, and Run-ledger seal evidence; and
- a Rust owner-side streaming SHA-256 verifier exposed by
  `forge-acqd verify-nwb-generation`; and
- an owner-only same-directory no-overwrite hard-link publisher with a frozen
  352-byte publication receipt. It returns `published_unledgered` until that
  receipt is durably bound into the matching Run ledger; caller-supplied
  positive booleans cannot rename an artifact. The publisher retains the
  `.nwb.inprogress` source and never deletes caller-supplied inputs.

The M0 host-internal canonical decoder is frozen and implemented. This is not a
claim that Receiver Pod FPGA/D3XX/Aggregator bytes already use that format. The
NWB worker reads only records proven by M1's durable checkpoint and can lag
without applying backpressure. If it exits or crashes, Forge retains that
generation as evidence, increments generation, and rebuilds a new
generation-specific `.nwb.inprogress` from journal sequence zero.

## Scoped checks

From `F:\poorsystem`:

```powershell
$env:PYTHONPATH='Forge/host_app/workers/python'
pixi run python -m unittest discover -s Forge/host_app/workers/tests -v
pixi run python -m forge_workers.materializer probe
pixi run g++ -std=c++20 -Wall -Wextra -Werror `
  -I Forge/host_app/protocol/cpp/include `
  -I Forge/host_app/workers/cpp/include `
  Forge/host_app/workers/cpp/tests/sdk_smoke.cpp `
  -o Forge/host_app/workers/cpp/tests/sdk_smoke.exe
pixi run cmd /c "set PATH=C:\Strawberry\c\bin;%PATH%&& Forge\host_app\workers\cpp\tests\sdk_smoke.exe Forge\host_app\protocol\golden\canonical_record_envelope_v1.hex Forge\host_app\protocol\golden\stim_intent_v1.hex"
cd Forge\host_app
pixi run -e nwb test-nwb
```

The default worker check currently compiles the native CPython bridge in a
disposable directory and runs 32 Python tests plus the C++ snapshot, live
mapping and protocol smoke against a Rust-generated disposable fixture. All twelve
NWB-profile tests use only synthetic `int16` records; one uses one SampleBlock
plus all six typed event record/table paths. Together they prove
schema, SWMR reader visibility, exact small-fixture replay, closed-generation
hash/provenance/count reconciliation with tamper rejection, two-Pod per-block
canonical/HDF5 raw-byte equality and targeted HDF5 tamper rejection, generation isolation,
durable-checkpoint/EOF race handling, and one real child-process kill followed by
a new-generation rebuild whose prior artifact remains byte-identical;
the independent-process test additionally passes the Python-produced bundle to
the Rust owner verifier and publisher, checks idempotent no-overwrite
publication/receipt behavior, and proves that later NWB tampering is rejected.
The Rust verifier hash-binds these artifacts and checks the reported per-Pod
geometry/count/digest maps, but does not independently decode HDF5. These tests
do not prove the production worker ACL/stable-handle trust boundary, the
100-kill gate, measured two-second visibility under sustained
load, 190.08 MB/s, 24-hour operation, NTFS/PLP crash durability, scientific
validity, or production service supervision. The generated smoke executable is a
disposable local build artifact and is not required by the source tree.
