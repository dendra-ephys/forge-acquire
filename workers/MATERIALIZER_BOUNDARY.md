# Forge worker/materializer boundary

Status: M0/M1 canonical decoder, sealed and pull-only live SWMR generation writer, frozen
validation/publication receipts, independent Rust verification, same-directory
no-overwrite publication and Run-ledger binding implemented as software
foundations; production publication qualification unavailable

## State machines

The analysis consumer is downstream and disposable:

```text
STOPPED -> STARTING -> RUNNING -> DRAINING -> STOPPED
                         |
                         +-> FAILED
```

A full analysis queue rejects the newest analysis block, increments that worker's drop counter, and remains `RUNNING`. It never slows the acquisition journal and never turns an analysis drop into an acquisition-gap claim.

The NWB materializer is regenerable and one-writer:

```text
UNAVAILABLE
   |
   | frozen payload decoder + exact dependency lock + validated backend
   v
PREFLIGHT -> SCHEMA_PLANNED -> INPROGRESS_OPEN -> CATCHING_UP
                                                   |
                                                   v
                                              CHECKPOINTED
                                                   |
                         journal sealed -----------+
                                                   v
                                              CAUGHT_UP
                                                   v
                                                CLOSED
                                                   v
                                              VALIDATING
                                                   v
                                              RECONCILED
                                                   v
                                      VALIDATED_UNPUBLISHED
                                                   |
                                         owner publish
                                                   v
                                               PUBLISHED
```

Any identity, CRC, decoder, append, flush, validation, reconciliation, or rename error enters a latched failure state outside this foundation. Recovery keeps the same Run UUID but increments generation, uses a new checkpoint and generation-specific `.nwb.inprogress`, and replays the journal from sequence zero. It never reopens the prior HDF5 artifact.

## File lifecycle

1. A manifest binds one Run UUID, one generation, one protocol-contract hash, one journal, one `.nwb.inprogress`, one final `.nwb`, and exactly one `ElectricalSeries` plan per Pod.
2. The schema plan predeclares all continuous datasets and typed marker/fault/gap/analysis/stimulation intent/receipt tables before the backend enters HDF5 SWMR. IDs and hashes are stored as fixed lowercase hex, bounded UTF-8 remains bounded, and event rows never increment neural sample counts.
3. The materializer reads only journal records within a valid M1 A/B durable
   watermark, then validates chunk/footer CRCs, canonical envelope/payload CRCs,
   Pod projection, both sequence domains, and every cached exclusive range.
4. It pulls a bounded batch, dispatches SampleBlocks to per-Pod `ElectricalSeries` and typed events to their predeclared tables, flushes, then atomically advances a Run/generation/schema-bound checkpoint.
5. A torn live-journal tail is not consumed. Committed corruption is fatal and cannot be relabeled a torn tail.
6. `.nwb.inprogress` remains an incomplete forensic artifact after any worker crash. It is never reopened. Recovery increments `generation`, creates a new generation-specific output/checkpoint, and rebuilds from journal sequence zero.
7. `forge_workers.forge_nwbd` retains a sealed default mode and provides a
   pull-only live mode. Live mode creates a fresh generation, consumes only the
   current A/B durable prefix in bounded batches, and waits without busy-looping
   until the immutable seal is observed and the cursor has consumed its exact
   record count. Both modes then close and validate the generation and write a
   canonical JSON report followed by a frozen 544-byte CRC32C validation receipt
   as the commit marker. Neither mode publishes.
8. `forge-acqd verify-nwb-generation` independently streams and checks every
   bound artifact hash, the canonical A/B checkpoint-set hash, journal seal,
   Run-ledger seal evidence, identities, sequences, error arrays, per-Pod
   sample/block totals, manifest channel geometry, exact raw-byte totals and
   per-Pod canonical/HDF5 digest-map keys. Success is explicitly
   `verified_unpublished`. Rust binds the worker report and artifacts; it does
   not independently decode HDF5.
9. The owner publisher atomically creates the final `.nwb` as a same-directory
   no-overwrite hard link, flushes the file through a write-capable Windows
   handle, commits a frozen 352-byte publication receipt, and verifies it. It
   deliberately retains the `.inprogress` alias and has no input-artifact
   deletion authority. A crash after link creation is idempotently recoverable.
10. Only a matching journal-sealed Run ledger may record the publication
    receipt hash and expose that Run as `Finalized`. Publication may complete
    after a newer Run starts, so the ledger binds immutable Run ID rather than
    active context.

The journal remains the acquisition truth source until the separately owned Run receipt and retention policy close. This subtree does not delete journals.

## IPC and ownership

```text
forge-acqd journal writer
       |
       | append-only file visibility; no worker queue or RPC backpressure
       v
durable JournalCursor -> M0 canonical decoder -> sole NWB backend -> .nwb.inprogress
       |
       +-> bounded analysis consumers -> annotations / stimulation intents

GUI <- low-rate status only
Python/C++ worker -> M0 StimIntentV1 -> Rust SafetyArbiter
external actuator boundary -> eventual stimulation receipt
```

- `forge-acqd` does not call worker code and does not wait for materialization.
- The materializer does not send Start, Stop, ACK, register, or retry commands to hardware.
- Analysis workers receive immutable canonical SampleBlock adapters and emit
  annotations or protocol `StimIntentV1` values only.
- Workers never authorize stimulation. The Rust SafetyArbiter owns the frozen
  token/profile/interlock/deadline checks and command generation. This SDK has
  no actuator implementation.
- Raw data never enters React/WebView state.

## Failure matrix

| Fault | Required behavior | Current evidence |
|---|---|---|
| GUI exit/crash | no effect on acquisition or worker service | outside this subtree; not release-proven |
| analysis worker stalls | bounded queue drops analysis blocks only; counter increments | Python/C++ smoke coverage |
| analysis worker crashes | daemon/journal unaffected; worker may restart from a chosen sequence | lifecycle skeleton only |
| materializer stalls/crashes | journal continues; old `.nwb.inprogress` remains unpublished; increment generation and rebuild from sequence zero | one real synthetic child-process kill proves fresh-generation replay and byte-identical retention of the old artifact; 100-kill/endurance evidence remains open |
| live committed/torn but non-durable journal tail | consume only the proven A/B durable prefix | parser tests |
| committed journal corruption | stop fail-closed | parser test |
| Run/generation/schema mismatch | refuse checkpoint/output reuse | checkpoint test |
| missing PyNWB/Inspector or unpinned dependencies | report unavailable; create no NWB | default-environment preflight plus exact-version NWB-profile tests |
| canonical record/cache mismatch | stop fail-closed | parser/decoder tests |
| validation/reconciliation failure | retain `.nwb.inprogress`; refuse final publication | publication-gate test |
| exit after final link but before receipt/ledger | retry verifies the exact final hash, commits the no-overwrite receipt, then binds the sealed Run | idempotent publication path; process-kill matrix still open |
| analysis requests stimulation | emit only protocol `StimIntentV1`; no execution | SDK tests |
| receipt/report/NWB/manifest/checkpoint tamper | Rust owner rejects; final path remains absent | Rust bundle test plus Python-to-Rust process test |
| caller reports all publication booleans true | receipt parser requires the publication bit clear; worker never renames | receipt mutation and NWB process tests |
| disk full, short write, I/O stall, power loss | acquisition-owned controlled-stop/journal recovery policy | outside this subtree; open release gate |

## Availability and release gates

Implemented today as a foundation:

- immutable Python canonical `SampleBlock` adapter and non-blocking bounded consumer;
- reference threshold, fixed-template, and LFP band-power/phase algorithms;
- C++20 read-only M0 SampleBlock adapter and SPSC bounded consumer;
- exact read-only M1 journal parsing bounded by the durable watermark;
- manifest, schema plan, atomic progress checkpoint, bounded pull coordinator,
  runtime probe, sealed/live one-generation `forge-nwbd` executable, frozen validation
  receipt, and a qualification-only fail-closed publication fixture; the default
  library/CLI exposes verification but no publication mutation;
- an optional exact-version PyNWB 4.1.0/h5py 3.16.0/NWB Inspector 0.7.2
  profile that creates a new uncompressed `.nwb.inprogress` generation, one
  `ElectricalSeries` per Pod, a numeric provenance `DynamicTable`, and six
  appendable typed event tables before enabling HDF5 SWMR;
- synthetic cross-reader evidence for incremental append/flush, exact sample
  replay, all six typed event append/read/reconciliation paths, PyNWB
  validation, NWB Inspector with no critical findings, closed generation
  hash/provenance/count reconciliation with tamper rejection, exact per-block
  canonical-to-HDF5 raw-byte equality for an interleaved two-Pod fixture, and mandatory
  new-generation rebuild after an interrupted writer; one real subprocess kill
  additionally proves that the old generation is not reopened, and a deterministic
  concurrent append/checkpoint test closes the stale-EOF reader race;
- independent Rust streaming verification of Python-produced sealed-generation
  artifacts and rejection after artifact tamper;
- qualification-only no-overwrite publication receipt and restart-persistent
  journal-sealed-to-Finalized Run-ledger fixture; ACL-enforced owner-only publication
  remains unavailable;
- hardware-free unit and C++ smoke tests.

Must remain unavailable:

- D3XX/10GbE acquisition and the device-to-M0 translation while hardware wire contracts are unfrozen;
- production NWB publication and recording claims until service supervision,
  qualified worker executable/ACL/stable-handle ownership, independent HDF5
  verification or an equivalently qualified trust boundary, directory-metadata/PLP qualification,
  the 100-kill qualification, measured two-second visibility under load, and
  target-storage throughput/endurance evidence exist;
- live analysis or stimulation claims until algorithms, timing, safety policy, and actuator receipts have independent evidence;
- any protected/zero-loss claim until the parent recording architecture's 190.08 MB/s, 24-hour, kill/restart, ENOSPC/stall/corruption, ACK/replay, power, media, and validation gates pass.
