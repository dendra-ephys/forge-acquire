# Forge Acquire recording architecture

Status: implementation baseline, not hardware-release evidence  
Scope: PC control plane, acquisition data plane, crash recovery, and NWB publication

## Safety claim

Forge must not claim that a Run is safe merely because the UI says “recording” or the operator clicked Stop. The intended, testable guarantee is narrower:

- closing or crashing the Tauri/React control plane does not stop an active acquisition;
- crashing or stalling the NWB materializer does not block hardware ingest;
- every transport gap, CRC error, counter discontinuity, overflow, journal failure, and finalize failure is latched into the Run integrity record;
- data at or before the last reported durable journal sequence is recoverable after a process restart;
- a final `.nwb` is published only after journal drain, file close, schema validation, semantic inspection, and independent counter reconciliation.

Power loss, media failure, host-controller failure, and a transport that has no replay/acknowledgement path cannot honestly be covered by an absolute zero-loss promise. UPS, power-loss-protected NVMe, source-side buffering, a frozen ACK/replay protocol, and hardware-in-the-loop fault testing are separate release gates.

## Process boundary

```text
Tauri / React control plane
  low-rate immutable status; raw sample bytes = 0
  idempotent operator commands with bounded deadlines
                    │ authenticated local SCM named pipe (M1 replay)
                    ▼
forge-acqd — independent Rust process; SCM service host implemented, not deployed
  deterministic M1 source → validation → fixed-capacity pool/queue
                                  │
                                  ▼
                   append-only checksummed journal
                                  │ committed chunks only
                                  ▼
forge-nwbd — current one-generation executable; future supervised service
  durable journal → pull-only live SWMR append → seal/catch-up → validate → receipt
forge-acqd owner verifier
  stream-hash bound artifacts → verified_unpublished
  → same-directory no-overwrite publish → publication receipt → Run ledger
```

Raw samples never enter React state, Tauri JSON events, or the WebView. Tauri events are unsuitable for the high-rate path; the eventual display path should use an ordered binary channel carrying pre-decimated min/max envelopes. GUI heartbeat loss never implies Stop.

The M0 host-internal protocol is frozen and is shared by the Rust daemon,
Python workers, and read-only C++20 SDK parser. That contract is not yet a
Receiver Pod or Aggregator wire protocol.

The current M1 `forge-acqd` crate implements deterministic canonical replay,
fixed-capacity buffering, an idempotent Run state machine backed by a bounded
CRC32C-framed no-overwrite event ledger, CRC-protected journal commits, A/B
durable checkpoints, recovery to the proven durable boundary, an explicit
seal/receipt, and a fail-closed in-memory
SafetyArbiter foundation for replay/dummy-load work. The arbiter freezes and
independently hashes fixed stimulation templates, allows one command awaiting
one receipt, bounds nonce ledgers, and fault-latches on contradictions,
deadline or runtime-health loss. Its command/nonce state is not restart
persistent and it has no hardware transport, so it cannot authorize production
stimulation. Command receipts, journal-seal evidence and fail-closed
events survive process restart; reopening a ledger left Prepared, Armed or
Recording appends a restart fault and restores Failed. Directory metadata and
PLP power-loss behavior are not yet qualified. The crate now includes an SCM
service dispatcher/control handler and persistent protected-DACL, local-only,
first-instance pipe listener. Binding requires the configured production NT
SERVICE SID in the process token; each client is impersonated, matched by exact
TokenUser SID, and reverted before application logic. The three default endpoints
use private transport v2: `\\.\pipe\forge-acqd-v2`,
`\\.\pipe\forge-acqd-hardware-v2` and `\\.\pipe\forge-acqd-analysis-v2`; the
exact retired v1 names are rejected. Connect, request reads, response/challenge
writes and ACK reads are overlapped. Stop is observed every 25 ms, each transaction
has a five-second transport-I/O deadline, and cancellation has a finite one-second
drain; an operation whose terminal completion cannot be proven is quarantined and
the server is poisoned. The unchanged response IDL frame is followed by a fresh
nonzero 16-byte CSPRNG challenge and a required `FACK || challenge`. This proves
that a client consumed the response bytes through the challenge, not that it
semantically understood them and not exactly-once execution. The service owns a
fixed-capacity deterministic replay
producer and journal consumer; Stop drains and seals, while SCM shutdown of an
unsealed Run durably latches Failed. A frozen 400-byte response returns
authenticated service state, active frozen Run context and real queue/journal
watermarks to the Tauri adapter without raw samples. The GUI can reconstruct a
failed Run after restart and issue a durable `AcknowledgeFailure` before a
fresh epoch.

The pipe deadline does not cover synchronous application handling. A handler,
dispatcher mutex, persistence call or hardware owner that blocks can still delay
listener join and service shutdown without bound. Handler isolation/deadlines,
response-write-pending coverage and cancel-drain quarantine fault injection remain
release gates; the current claim is only that named-pipe transport I/O is bounded.

This service path is implemented but not installed or deployment-qualified.
The repository's installer is on-demand, confirmation-gated and never starts
the service. Deployed data-root/operator ACL policy, hostile multi-client and
SCM restart behavior, directory/PLP evidence and the 190.08 MB/s/24-hour gate
remain open. Focused integration tests terminate real child processes in two
states: after a durable record plus an unbarriered tail, and during an active
Run. They prove recovery exposes only the proven durable prefix and that an
interrupted active Run reopens `Failed` until explicit acknowledgement.

The bounded GUI-loss v2 harness retains one 1,000-child SCM-emulated engineering-stress
run. It uses separate supervisor/owner OS processes (PIDs 6584/29984), alternates 500
after-ACK/reaccept and 500 pending-`AckRead` kills, and records owner-exclusive append-only
audit facts. Its 18,882-record journal, five-event ledger, receipt, retained executable and
5,009-event audit were independently reopened/rehashed. Every `ReapProven` contains an exit
code, bounded wait and signaled result, but the v2 `job_object_termination` label was derived
from the supervisor command; v2 did not persist the queried Job active count or empty state.

The current v3 qualification path creates every owner/GUI child suspended, configures
`KILL_ON_JOB_CLOSE`, assigns it to the Job, reverifies the stable retained executable and
only then resumes it. Its private control v2 and audit/receipt v3 carry the four typed
containment facts and the complete bounded reap evidence. The owner independently waits its
retained primary process handle, cross-checks the exit code and deadline, and persists the
evidence; Job active-zero/empty remains explicitly supervisor-observed. Old receipt/audit
schemas fail closed. Fresh software evidence is 446/446 qualification unit tests plus four
integration cases; the 1,000-kill case remains ignored, so the historical v2 stress artifact
is not promoted to v3 evidence.

Both versions prove only their stated local synthetic topology: `scm_emulated=true`,
`service_deployed=false`, no hardware/NWB and no raw GUI samples. The historical v1
owner-thread run remains historical. The default product binary excludes the default-off
`qualification-harness` feature. Installed SCM/ACL/restart, blocked handlers, mapped-image/
path-ancestor ABA, abnormal same-account early Resume, qualification-root ACL/WDAC/
Authenticode, owner-independent Job queries, pending-AckRead request/challenge attribution,
listener joins, long-rate/endurance and hardware/HIL remain open; M1 and product release are
not closed.
The legacy `serve` endpoint remains unavailable; only the SCM entry exposes the
production listener. D3XX, Aggregator/10GbE and RHS transports remain closed.

The M3 host foundation now has composed but hardware-unbound pieces. The D3XX
device owns a fixed queue of stable-address asynchronous IN requests, polls the
oldest request without blocking and permits acquisition-only OUT from that same
exclusive owner while reads are pending. `DirectPodIngestSession` then consumes
completed bytes in order and composes admission, capabilities, lifecycle ACKs,
identity validation, actual journal append receipts, the source Stop boundary,
durability and seal. `DirectPodRuntime` enforces the fixed queue depth, requires
the service to supply hardware-global time, cancels all reads on failure and
requires a pending oldest-read frontier after verified Stop before tail cancel
and seal. `HardwareRunCoordinator` adds a separate CRC32C/no-overwrite hardware
lifecycle, and `DurableDirectPodRuntime` makes that ledger part of the same
owner: requested intent precedes OUT, ACK/NACK is separate evidence, Start ACK
precedes but does not imply Recording, the first journaled record is the third
Start gate, and verified Stop precedes the later seal. Any unfinished phase is
failed on restart, while an exact completed retry is answered from retained
evidence without reissuing the command. This closes a software
scheduling/ordering/lifecycle gap; it does not create an SCM hardware source.
`PreRunDirectPodConnection` now closes the in-process ownership gap before that
Run-specific session exists. It keeps the admitted transport's exact bounded IN
queue primed, accepts only the exact capability statement and Pod-time
snapshots, and preserves a fragmented message, queue slots and counters while
moving into `DirectPodIngestSession`. A protected `DirectPodRunPlan`, rather
than the operator request, fixes Run/Pod/headstage/config identities and the
absolute storage root. One no-overwrite directory reservation precedes journal
and lifecycle creation; mismatched Run/device/epoch/config/state evidence or an
existing root fails before any OUT. The translated Prepare intent is then
durable before the first hardware write.
The self-hashed `DirectPodTimeSnapshotV1` companion also gives that owner an
explicit pre-Run Pod clock: host monotonic time enforces only a 100-ms freshness
limit, and no host/USB arrival time is interpolated into hardware time. A
separate local `ForgeHardwareServiceV1` contract is frozen at
`b1dd877cf9b9558352473f8458802a188919fb5a3865884c00a8eb83059e9b54`: the
operator first observes an exact hardware-state hash, then submits only a
100–5000-ms relative timeout; the daemon alone checks freshness and creates the
absolute M0 Pod deadline. The SCM host has a distinct protected
`\\.\pipe\forge-acqd-hardware-v2` listener and Tauri bridge. With no explicit
direct-Pod policy its backend is evidence-bearing `Unavailable`, so no request
can fall through to protected replay or advertise hardware. An all-or-none
protected policy reference can instead bind service startup to the exact policy
file hash, internal approval-authority identifier hash and canonical data-root
hash. `JournalBoundDirectPodBackend` now
binds an already admitted, primed, Run-specific runtime to that operator
contract: Run identity is rejected before OUT, the translated intent is stable
before transport write, and snapshots come from the same explicit Pod time and
lifecycle owner. A bounded `HardwareServiceOwner` thread owns the only mutable
backend and polls independently of GUI/pipe presence using one shared
host-monotonic origin. Dropping every client proxy does not emit Stop or Abort.
Before an orderly service exit, a mandatory backend hook cancels the transport
and durably marks every unfinished hardware lifecycle failed; it does not forge
a Pod Stop/Abort ACK, seal, or defer the failure until a later reopen. On the
next explicitly policy-bound service start, a bounded deterministic scan opens
every canonical prior hardware lifecycle before D3XX can be loaded. It rejects
malformed/reparse/incomplete/identity-contradictory roots, appends the existing
daemon-restart failure for unfinished lifecycles and binds the recovery report
into deployment evidence. It never truncates, seals, resumes or reuses an old
Run. The policy loader verifies the
data-root/receipt/DLL/device/configuration/queue/Run-plan bindings; service start
then enters a bounded reconnect owner. Its frozen 272-byte CRC32C/hash-chained
ledger records each attempt before any DLL/device open, carries the attempt
budget across service restarts, and repeats the full admission path. A candidate
is promoted only after a strictly newer Pod-originated epoch; a timeout, stale
epoch or fault consumes one attempt. No simulator fallback or old-Run resume is
permitted. This remains software-only evidence:
no production policy/receipt, supported DLL/device, Receiver-Pod product implementation,
installed-SCM restart/reconnect qualification, integrated release-capable Pod replay buffer
or HIL evidence exists. The host can automatically plan same-epoch Replay only
from the frozen source-authored offer: the Pod must quiesce live output, retain
the exact next suffix and bind a fresh state/deadline. Offer evidence and Replay
intent are durable before OUT. Unannounced transport loss is still fail-closed;
the host never guesses a gap after accepting a future append-only record.

The separate `journal-qualification` path now has two machine-distinct v2 source
profiles. `active_receiver_pod_128` models the current eight-Pod active-product
ceiling but can never receive the conservative release flag. The default
`protocol_max_256` profile drives eight deterministic 256-channel stress streams
through the canonical validator and fixed-capacity journal path; only this profile,
an exact current release executable, requested and measured active durations of at
least 24 hours, and achieved throughput at least
`max(caller_target, 190080000 B/s)` may satisfy the journal release flag. The
no-overwrite receipt binds protocol and executable identity, target volume,
watermarks, latency summaries and journal SHA-256. Its verifier reopens the journal,
decodes every record to establish actual Pod IDs/count and frozen geometry, checks
balanced distribution, durability/seal/file hashes and recomputes rates and gates.
Receipt v1 is rejected by the v2 verifier. Short qualification tests remain smoke
evidence only; neither the 30–60-minute journal engineering gate nor the 24-hour
journal-plus-uncompressed-NWB release gate has been executed here. The v2 receipt is
unkeyed local engineering evidence, not a signature, attested clock or standalone
product-release authority.

The M2 worker subtree now contains an exact-version optional PyNWB/HDF5
backend that materializes canonical durable journal records into a new
uncompressed generation-specific `.nwb.inprogress`, with one
`ElectricalSeries` per Pod, per-block numeric provenance and all planned event
tables created before SWMR. Synthetic cross-reader, schema, Inspector, exact
replay, closed-generation hash/provenance/count reconciliation with tamper
rejection, and generation-isolation tests pass. The one-generation
`forge-nwbd` executable preserves its sealed default and also has a pull-only
live mode that follows only the durable watermark, flushes each non-empty
bounded batch, and closes only after observing a matching seal while caught up.
A real synthetic subprocess test kills generation 1 after SWMR visibility and
proves generation 2 replays from sequence zero while generation 1 remains
byte-identical forensic evidence. The worker remains outside acquisition and
has no publication authority. `forge-acqd verify-nwb-generation` independently stream-hashes
the receipt-bound journal/seal/checkpoints/NWB/manifest/report and returns only
`verified_unpublished`. Its owner-only publisher then creates a no-overwrite
same-directory final link, flushes it, commits a frozen publication receipt and
can bind that receipt to the matching sealed Run ledger. Typed host-internal
event append and closed-generation reconciliation are implemented for all six
predeclared tables. Per-block canonical/HDF5 raw-byte equality is implemented
inside the hash-bound worker bundle; independent Rust HDF5 decoding or a
qualified worker executable/ACL/stable-handle boundary remains open, together
with the supervised service, hardware-originated event producers,
directory-metadata/PLP proof and release-scale storage evidence.
Publication retains the source `.nwb.inprogress` forensic artifact and has no
authority to delete caller-supplied inputs; later retention/cleanup is a
separate fail-closed policy gate.

## Run lifecycle

```text
IDLE
  → PREFLIGHT
  → JOURNAL_HEADER_DURABLE
  → WRITER_ARMED
  → SOURCE_START_REQUESTED
  → FIRST_VALID_RUN_FRAME
  → RECORDING
  → STOP_REQUESTED
  → SOURCE_STOP_BOUNDARY_RECEIPT(last_record/sample/global_time)
  → DRAINING_TO_LAST_SEQUENCE
  → JOURNAL_SEALED
  → NWB_MATERIALIZING
  → NWB_VALIDATING
  → NWB_VALIDATED_UNPUBLISHED
  → FINALIZED
```

`SOURCE_STOP_BOUNDARY_RECEIPT` now has a host-side frozen companion contract:
the exact 208-byte `DirectPodStopBoundaryV1` is reconstructed only from final
source records already appended to the journal, and its SHA-256 must appear in
the matching Stop `AckV1` with the exact stopped state. An ordinary transport
ACK still cannot advance the Run. This is software-contract evidence only;
Receiver-Pod same-stream ordering, SCM integration and HIL remain open, so no
hardware Run can yet advance to draining or journal seal.

Acquisition, journal durability, NWB materialization, hardware synchronization,
and Run integrity remain independent state dimensions. `JOURNAL_SEALED` means
the acquisition truth source is closed. `NWB_VALIDATED_UNPUBLISHED` means the
Rust owner has independently verified the worker receipt and all bound files,
but no final experiment file exists. `published_unledgered` is a recoverable
intermediate if the final link and publication receipt exist but the Run-ledger
event has not committed. `FINALIZED` requires that ledger binding and is now
implemented for the software path. A failed Run cannot be silently re-armed;
the operator must acknowledge its durable failure first. The acknowledgement
retains the old ledger/journal evidence, clears only the active context and
requires a strictly newer epoch. M1 exercises
`Prepare -> Arm -> Start -> Stop -> seal`, persists every command receipt and
the journal-seal transition, then reopens the protected-replay ledger in
`JournalSealed`. A crash with an active Run is reconstructed as an auditable
`Failed` state rather than resumed silently.

## Journal contract

The acquisition journal is the truth source during a Run. Each append contains:

- format magic/version and a monotonically increasing chunk sequence;
- Run identity and the active protocol-contract hash in the durable file header;
- Pod identity;
- frame, sample, and hardware-global-time ranges;
- payload length and CRC-32C;
- a commit footer written after the payload.

A structural commit is not the same as stable-media durability. `forge-acqd`
reports separate committed and durable sequences; a future hardware source will
also report received sequence. A batched `sync_data` durability barrier advances
the persisted A/B durable checkpoint. Recovery validates the file header,
sequence order, header CRC, payload CRC, commit footer, canonical-envelope
identity, and per-Pod continuity. Corruption inside the durable prefix is fatal;
an explicit recovery action truncates only to the proven durable byte boundary
and follows it with another durability barrier.

One Run always creates a new journal and, eventually, one new NWB file. Existing journals are never overwritten or reused for a different Run.

## Backpressure priority

Priority is fixed:

1. hardware ingest and frame integrity accounting;
2. journal append and durability checkpoints;
3. NWB materialization;
4. live display.

The NWB worker may lag, pause, or restart. It never backpressures acquisition. Display frames are disposable and their drops are counted separately from sample loss. If free space falls below the amount required to stop at a complete frame and seal the journal, the daemon requests a controlled source stop; a missing stop acknowledgement makes the Run invalid rather than silently incomplete.

Online analysis uses one independent `ForgeAnalysisRingV1` SPSC ring per
consumer. A slot carries one complete canonical record, not a second sample
format. Ring full rejects the newest downstream copy and increments a
branch-specific counter; it never blocks journal append. A controller-ring drop
is a data gap and therefore disarms stimulation. The frozen byte layout now has
a pagefile-backed local Windows mapping with explicit SID DACL construction,
first-instance and Run/consumer/epoch checks, real Rust child-process open and
consume evidence, and a C++20 Interlocked live consumer. Protected replay fans
out only after journal append; a deliberately full branch latches analysis
drop/fault while journal Stop/drain/seal still succeeds. Authenticated
named-pipe worker registration and mapping-name handoff, Python native atomic
consumption, multi-worker restart supervision, deployed ACL/adversarial tests
and target-load ordering/drop qualification remain release-blocked.

Controller registration now holds the minted controller lease behind a
fail-closed guard until one live mapping owns it. Every rejected registration,
last-owner drop, heartbeat/process-instance failure, ring overflow, data gap,
CRC fault or deadline miss revokes the controller lease before attempting any
evidence handoff. That handoff is a concrete capacity-16 process-local queue
using only `try_send`; full, disconnected or poisoned receiver state is exposed
as `fault_evidence_lost` and cannot backpressure journal append. A successful
enqueue is not durable evidence. A qualified consumer that persists and
reconciles those fault events remains open.

The NWB validator treats raw equality as a byte-level invariant, not only a
shape/count check: for every Pod and SampleBlock it compares the canonical
sample payload with the HDF5 `<i2`, C-order `[sample, channel]` slice and binds
per-Pod digests into the validation report. The Rust owner rechecks artifact
hashes, manifest channel geometry, count/byte arithmetic and digest-map keys,
but does not independently decode HDF5; qualified worker identity and ACL/
stable-handle supervision therefore remain part of the production trust gate.

## Publication receipt

A final Run receipt must retain, at minimum:

- Run UUID and protocol-contract hash;
- source start/stop acknowledgement and last expected sequence;
- received, committed, durable, and NWB sequence ranges;
- sample/frame/global-time ranges per Pod;
- all latched integrity events and first affected sequence;
- journal and NWB paths, sizes, and cryptographic hashes;
- PyNWB schema-validation result;
- NWB Inspector result;
- independent dataset-shape/counter reconciliation result;
- finalize timestamp and software/build identities.

The journal is retained until this receipt is committed. A `.nwb.inprogress` name is never presented as a completed experiment file.

## Release gates

- 1.5× the planned 126.72 MB/s input rate (190.08 MB/s) for 24 hours with no unexplained gap;
- representative real `int16` neural data, hot and nearly-full target NVMe, periodic durability barriers, antivirus enabled;
- repeated GUI termination with zero impact on acquisition sequence;
- repeated NWB-worker termination followed by deterministic rebuild from the journal;
- injected short writes, I/O stalls, ENOSPC, permission errors, corrupt chunks, and publish/rename failures;
- acquisition-process termination and machine restart with exact recovery to the last durable sequence;
- final NWB schema validation, NWB Inspector, and independent frame/sample reconciliation;
- all queues bounded, all overflow counters Run-latched, and no unbounded retry loop;
- frozen host ACK/replay semantics and fresh D3XX/10GbE hardware recovery evidence before any “protected recording” claim appears in the production UI.

## Primary references

- [AqNWB recording workflow](https://nwb.org/aqnwb/workflow.html)
- [AqNWB HDF5, chunking, compression, and SWMR](https://nwb.org/aqnwb/hdf5io.html)
- [HDF5/h5py SWMR](https://docs.h5py.org/en/stable/swmr.html)
- [Tauri channels and IPC performance](https://v2.tauri.app/develop/calling-rust/)
- [Windows synchronous and asynchronous I/O](https://learn.microsoft.com/en-us/windows/win32/fileio/synchronous-and-asynchronous-i-o)
- [Windows synchronous and overlapped pipe I/O](https://learn.microsoft.com/en-us/windows/win32/ipc/synchronous-and-overlapped-input-and-output)
- [Windows `CancelIoEx`](https://learn.microsoft.com/en-us/windows/win32/fileio/cancelioex-func)
