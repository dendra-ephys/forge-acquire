# forge-acqd M1 protected-replay boundary

This crate implements a crash-auditable **protected replay** slice of the
independent Forge acquisition data plane, including an SCM service host. The
service is not installed, started, deployment-qualified, or a production
hardware acquisition service. Its D3XX module can read-only probe
an installed vendor DLL and contains a protected-receipt/serial/configuration/
USB-descriptor-gated FT601 duplex adapter plus strict record/control stream
demultiplexer, one-in-flight control transaction tracker and ordered
journal/Stop composition. The default SCM hardware backend opens no device;
only an explicitly configured, exact-hash internal deployment policy can select
the direct-Pod bootstrap. The service never opens 10GbE Aggregator, RHS, or an
unsecured local pipe.

Implemented and testable now:

- every journal payload is an M0 `CanonicalRecordEnvelopeV1`; the journal file
  identity and each record are pinned to `forge_protocol_v1::PROTOCOL_HASH`;
- CRC32C header/payload/footer commits, global journal append order, exact
  per-Pod record sequence, and SampleBlock frame/sample/global-time continuity;
- A/B CRC-protected durable-watermark sidecars. A commit footer is structural,
  not durable. Readers stop at the persisted durable watermark;
- explicit recovery to the last durable byte boundary; corruption inside the
  durable prefix is fatal;
- writer poison after any partial write/barrier/checkpoint failure;
- an explicit seal sidecar binding expected-last, durable length, generation,
  and record count;
- fixed-capacity, non-waiting buffer pool; idempotent bounded Run lifecycle
  consuming the normative M0 `RunCommandV1` body and binding Run, device,
  frozen-config, epoch and deadline identities;
- a bounded no-overwrite Run event ledger. Every accepted or rejected command
  receipt is CRC32C framed, flushed and atomically renamed before return;
  Stop-to-`JournalSealed` and explicit fail-closed transitions are separately
  evidenced. Reopening an active Prepared/Armed/Recording ledger durably
  records a daemon-restart fault and restores the Run as Failed;
- frozen validation/publication receipt parsers, a bounded streaming owner-side
  NWB bundle verifier, an idempotent same-directory no-overwrite publisher, and
  a restart-persistent publication event that alone advances the sealed Run to
  `Finalized`;
- bounded retention evidence: large journal/final-NWB hashes use a fixed 64 KiB
  buffer, small evidence is bounded before allocation and exact-read, journals
  admit at most eight Pods, and read-only ledger proof admits at most 1,024
  events for the exact requested Run. The result remains unconditionally
  `Retain/UnqualifiedBackupAcl`; no deletion or cleanup token exists;
- deterministic canonical SampleBlock replay with a machine-readable receipt;
- replay/dummy-load Rust SafetyArbiter foundation with independently hashed
  fixed templates, one outstanding command/receipt, bounded nonce ledgers,
  deadline/duplicate rejection and runtime-health fault latching;
- private Windows named-pipe transport v2 on the default control, hardware and
  analysis endpoints; the exact retired v1 names fail closed. It retains the
  protected explicit DACL, local-only/first-instance flags, bounded framing,
  production NT SERVICE SID token-membership enforcement, client impersonation
  plus exact TokenUser SID comparison, and guaranteed reversion before
  application handling;
- a persistent first-instance SCM listener with Stop/Shutdown/Interrogate
  handling. Connect, request reads, response/challenge writes and ACK reads use
  overlapped I/O with 25-ms stop observation, a five-second transaction-I/O
  deadline and a finite one-second cancel drain. Unconfirmed completion
  quarantines the operation state and poisons the server rather than reusing a
  possibly live buffer or pipe handle;
- a v2 response-consumption handshake: after the unchanged frozen response
  frame the server writes a fresh nonzero 16-byte CSPRNG challenge, and the
  client returns `FACK || challenge`. Expected disconnect/framing/authentication
  races fault only that client and the listener accepts again; system, handler
  and response-contract failures remain fatal;
- a daemon-owned deterministic low-rate replay producer, fixed-capacity buffer
  pool/queue, journal writer, periodic durability barriers and Stop/drain/seal;
  queue overflow, writer failure or consumer loss fails the Run closed;
- a frozen 400-byte local response contract at LF-normalized SHA-256
  `1dccd163d6179b69adde2dbb738d1cfc3c0e471820338f36f9ffe2fb2bbf62ed`,
  including active frozen Run context, real journal/queue watermarks and the
  latest sealed Run identity so a restarted GUI can recover status safely;
- a Tauri/React adapter that receives only low-rate status, can perform
  Prepare/Arm/Start/Stop, and requires explicit `AcknowledgeFailure` before a
  fresh epoch. Raw sample bytes crossing this interface remain zero.
- process-level integration fixtures that terminate real child processes with
  deterministic persisted header/payload/footer/before-barrier tail states,
  durable-prefix CRC corruption, and an active Run. Every tail cut recovers
  only the proven durable prefix; corruption inside that prefix is fatal; an
  interrupted Run requires explicit evidence-preserving failure acknowledgement;
- the frozen `ForgeAnalysisRingV1` reference core plus a pagefile-backed,
  local-session, first-instance Windows named mapping with explicit
  SYSTEM/service/worker SID DACL construction. A real child process opens and
  consumes it, and protected replay can fan out a record only after journal
  append. Ring-full tests prove downstream drop/fault latching does not prevent
  journal seal. Authenticated worker registration/name handoff, deployed ACL
  qualification, multi-worker supervision and target-load evidence remain open;
- a receipt-bound synthetic journal-only qualification runner with two frozen
  source profiles: `active_receiver_pod_128` (8 × 128ch, 7,888-byte canonical /
  7,992-byte journal record) and the default `protocol_max_256` conservative
  stress profile (8 × 256ch, 15,568-byte canonical / 15,672-byte journal record).
  Only the latter may pass the 24-hour conservative journal flag, and only at
  `max(caller target, 190.08 MB/s)` with sealed/reopened watermark agreement;
  four-buffer pooling, periodic barriers, terminal metrics, hashes and an
  independent verifier that rescans decoded Pod/record geometry and requires the
  exact current executable remain journal-only evidence. The receipt is unkeyed:
  it is local integrity evidence, not a signature, remote attestation or independent
  clock witness.
- a frozen 312-byte `DirectPodRecordReleaseV1` request/reply companion at
  LF-normalized SHA-256
  `512d2fb554d4bc9bb2d56f46c3e25bd8d12548c93fa3eec62ae98800af067285`.
  It binds a one- or two-record release to the exact device/Run/Pod/Headstage,
  transport epoch, durable journal/checkpoint frontiers and retained store-state
  hashes. Rust, Python and C++ codecs plus request/reply/store-state goldens pass;
  the daemon does not yet send it and the Pod RTL does not yet consume it.
- a frozen 320-byte `Ft601AdmissionReceiptV1` parser at LF-normalized SHA-256
  `8a6c6fb4905466be086781f1f2aef2901b6d092524b6b3609b7a02974cbdb992`.
  Exact out-of-band receipt-file and internal approval-authority hashes bind the admitted
  D3XX DLL, unique serial, FT601 configuration, approved 66-MHz-bring-up or
  100-MHz-release profile, hardware/SKiDL build, official USB descriptor topology
  and M0 protocol hash. The adapter additionally requires a self-powered USB 3
  configuration with data interface 1 and Bulk `0x02/0x82` pipes. No approved
  production receipt or real-device descriptor evidence exists yet; the
  receipt is not a digital signature, device attestation, FTDI licence or
  external authorization.
- a fixed-depth D3XX asynchronous IN queue with stable `OVERLAPPED`/buffer
  addresses, nonblocking oldest-first polling, bounded allocation, exact
  release on completion and abort/release on cancellation. The same exclusive
  owner may issue acquisition-only OUT while reads are pending; no FT601 handle
  is shared between Rust threads. Any impossible length, transfer error or
  release contradiction poisons the device I/O epoch.
- a receipt-bound capability and transport-reply gate. It requires direct-D3XX
  identity, the exact M0 hardware-protocol hash and acquisition ACK/replay/Stop
  capabilities before permitting one increasing-ID request at a time. Exact
  duplicates are idempotent; contradictions, timeout or unresolved close poison
  the epoch. Stop additionally requires the frozen 208-byte
  `DirectPodStopBoundaryV1` contract at LF-normalized SHA-256
  `231b5c78e39fb871119d96d5bc5fe8aa57803e211950785194244bba79c3c09c`.
  Its boundary is updated only after exact journal append receipts, and the
  matching Stop ACK must bind its hash, stopped state, request ID and epoch.
  Replay additionally requires the frozen 280-byte request context/296-byte
  completion companion (`f6efaca7...f92f7d5`): it binds the current Run,
  device/Pod/headstage, admission/config hashes and exact next journal range;
  admits at most 65,536 records/256 MiB with `REPLAYED`; crosses a durability
  barrier before ACK; and persists request/completion in the same hardware
  ledger before OUT/after proof. The production FPGA does not yet implement
  these contracts, so the
  host verifier alone cannot mark a hardware Run safe or seal it.
- automatic Replay planning accepts only the exact 280-byte
  `DirectPodReplayOfferV1` source companion
  (`01f5c69d...d3bdd55b5`). It binds the active identities/epoch, latest fresh
  hardware-state hash, next journal sequence, replayable window and deadline,
  and requires live output to remain quiesced. The owner persists the offer,
  persists the derived request, then writes OUT. Live-data interleaving,
  mismatch, expiry or restart with an unresolved offer fails closed. It does
  not infer a gap from USB timing or from a later record.
- an ordered `DirectPodIngestSession` that composes protected admission,
  byte-stream reassembly, control transitions, journal append receipts and the
  source Stop boundary. It rejects data before a verified Start ACK, checks
  Run/Pod/headstage identity before writing, and when protected DHL identity is
  present it checks the explicit policy-approved Host layout, catalog/Descriptor
  channel count, signed-I16 format and exact SampleBlock rational rate before
  Replay staging or journal append. A mismatch poisons the session before the
  journal receives a record. The first SampleBlock also freezes the exact rate
  numerator and denominator for that Pod; an equivalent-but-different fraction
  is rejected. It rejects data after verified Stop,
  keeps append and stable-media durability separate, and seals only after the
  stream/control/Stop/journal terminal conditions all agree. It is tested with
  deterministic transport bytes. `DirectPodRuntime` binds it to the real D3XX
  trait implementation or a fake transport, maintains exact queue depth,
  requires explicit hardware-global time, cancels reads on failure and requires
  a pending-read frontier after verified Stop.
- a separate persistent real-hardware lifecycle. `HardwareRunCoordinator`
  writes bounded CRC32C/no-overwrite Run and Replay requested/reply,
  first-record, failure and seal events. `DurableDirectPodRuntime` composes it with the ordered transport:
  Start ACK reaches only `StartAcknowledged`, the first successful journal
  append reaches `Recording`, and verified Stop plus the journal seal are later
  gates. Restart fails every unfinished phase and exact completed retries are
  returned without hardware reissue. The owner is wired into the SCM host only
  through the explicit policy bootstrap and has not been exercised by a real
  Pod.
- `PreRunDirectPodConnection` owns the admitted transport before a Run exists,
  keeps its fixed asynchronous IN queue full, and requires an exact capability first,
  followed by the current epoch's bounded DHL identity capsule, Pod-time and CABLINE-status
  evidence. The latter three may be arbitrarily split/coalesced and ordered. Strict policy
  v4 binds all embedded catalog-source hashes, the exact Descriptor/Inventory identity and
  an explicit nonzero Host channel-layout ID that is independent of board profile ID;
  exact duplicate capsule bytes are idempotent, while mutation or contradiction poisons and
  cancels the epoch. `DirectPodRunPlan` is supplied by protected policy and
  fixes the Run/Pod/headstage/config identities plus a normalized absolute Run
  root. Promotion atomically reserves that root without overwrite, creates the
  journal and hardware ledger, moves the same parser (including a partial
  message), queue and counters into `DurableDirectPodRuntime`, persists Prepare,
  and only then writes OUT. Deterministic tests cover fragmented capability,
  partial time state across promotion, exact queue preservation, coalesced
  ACK/first-record ingest, and pre-OUT rejection of stale state or existing
  storage. After capsule admission but before the identity is stored or Ready is
  possible, the capability must independently cover the admitted acquisition
  channel count, signed-I16 format and exact rational rate range using checked
  integer comparison. The protected deployment policy now supplies the governed plan and
  SCM binding; production policy issuance and real-device evidence remain
  unavailable.
- an exact 152-byte `DirectPodTimeSnapshotV1` companion. It binds device,
  transport epoch, monotonic hardware time/counters, readiness/fault flags and
  a hardware-state hash. The host monotonic clock only rejects snapshots older
  than 100 ms; it never becomes sample time. This closes the host-side clock
  source for pre-Run deadline checks, but the Pod does not emit it yet and the
  replay response remains unchanged.
- a separate `ForgeHardwareServiceV1` local contract at SHA-256
  `b1dd877cf9b9558352473f8458802a188919fb5a3865884c00a8eb83059e9b54`.
  The exact 64/176/256-byte frames require a preflight hardware-state hash and
  bounded relative timeout; only the daemon translates the request using a
  fresh Pod clock. The SCM host binds a distinct SID-protected hardware pipe
  and Tauri has status/command bridges. With no policy its backend is explicitly
  unavailable and performs no D3XX I/O. With the complete protected policy
  triple it loads the exact D3XX source, opens the one admitted FT601, verifies
  configuration/descriptors and waits for the exact Pod capability/epoch plus admitted
  identity capsule, fresh Pod time and matching CABLINE status before promotion. The
  Descriptor device ID is the protected Headstage ID, distinct from the FT601 receipt
  device ID. Runtime capsule bytes are rejected and reconnect repeats identity admission.
  Failure latches unavailable and never falls through to replay.
- the Host catalog now recognizes 14 identities (10 active products, three
  active options and one decode-only profile), including graph-closed
  `rhs2116x2_imu` as `(3,2,6,32)` with instances `[0,1,100]`. Its 32 physical
  stimulation channels do not pass Host v1 stimulation preflight. Current
  Headstage/Receiver-Pod RTL still implements only the prior 13 identities, so
  this Host understanding is not hardware Ready evidence.
- the owner thread invokes a mandatory shutdown hook on both normal exit and a
  preceding poll error. Bootstrap/pre-Run owners cancel all queued reads without
  inventing a hardware command. A journal-bound owner cancels transport and
  durably records `HARDWARE_FAULT_OWNER_SHUTDOWN` for every unfinished Run before
  exit; this is neither a Pod Stop/Abort ACK nor permission to seal or resume.
- before an explicitly policy-bound SCM start may open D3XX, it scans at most
  4096 canonical `hardware-run-<RunID>` roots in deterministic order. Regular
  journal files and lifecycle directories must exist under the protected data
  root with matching Run identities; links/reparse points, malformed names,
  incomplete evidence or corruption abort startup. Opening an unfinished
  lifecycle appends the existing daemon-restart failure before D3XX open. A
  second scan is idempotent. Recovery never truncates, seals, resumes or reuses
  an old Run.

The SafetyArbiter state and nonce ledgers are not durable across process
restart, and no hardware transport consumes its commands. It cannot authorize
production stimulation until authenticated IPC, durable exactly-once state,
the physical safety engine and HIL evidence exist.

An accepted Stop does not by itself permit a new Run. The lifecycle first moves
to `JournalSealed` and releases its active identity only after the owning
journal has durably sealed and the no-overwrite seal event has persisted. A new
epoch may then begin while the earlier generation materializes. That earlier
Run becomes `Finalized` only after owner verification, no-overwrite publication,
a frozen publication receipt and its Run-ledger event. Exact command
idempotence is scoped to `(epoch, request_id)` and survives a process restart in
protected replay. This is process-crash evidence, not a power-loss guarantee:
directory metadata durability, service-owned ACLs and PLP-media behavior remain
release gates.

The replay receipt reports elapsed time, journal bytes, effective journal
write rate, Run-ledger path/event count and a successful `JournalSealed` reopen
so short engineering smokes can be compared. That number is not a storage
qualification receipt: it does not bind a physical volume/profile and does not
replace the required 190.08 MB/s long-duration dual-write gate.

The 16-bit `pod_slot` stored in the legacy 80-byte chunk cache is only a
CRC32C-derived projection used to catch mismatches/collisions. The canonical
16-byte `pod_id` in the M0 envelope is authoritative. The chunk's global
`journal_sequence` and the envelope's per-Pod `record_sequence` are distinct,
explicitly validated counters.

Run from this directory:

```powershell
pixi run --manifest-path ..\pixi.toml test-data-plane
pixi run --manifest-path ..\pixi.toml self-check-data-plane
pixi run --manifest-path ..\pixi.toml cargo run --locked --manifest-path Cargo.toml -- d3xx-probe
pixi run --manifest-path ..\pixi.toml cargo run --release --locked --manifest-path Cargo.toml -- journal-qualification --source-profile protocol_max_256 --journal <new.wal> --receipt <new-receipt.json> --duration-seconds 1800 --target-bytes-per-second 190080000 --durability-batch 1024
pixi run --manifest-path ..\pixi.toml cargo run --release --locked --manifest-path Cargo.toml -- verify-journal-qualification --receipt <new-receipt.json>
pixi run --manifest-path ..\pixi.toml cargo build --release --locked --manifest-path Cargo.toml --features qualification-harness --target-dir target\qualification-harness
pixi run --manifest-path ..\pixi.toml .\target\qualification-harness\release\forge-acqd.exe gui-kill-qualification --root <new-run-root> --receipt <new-receipt.json> --build-artifact <separate-release-exe-copy> --kill-count 1000
```

`serve` intentionally returns an unavailable boundary; the listener is exposed
only by the SCM `service-dispatch` entry. `service-install-plan` is read-only.
`d3xx-probe` is also read-only and always keeps hardware transport unavailable;
it never opens or configures a Pod. The default SCM hardware backend is likewise
unavailable. The direct-Pod adapter is selected only when service arguments
contain the all-or-none `--direct-pod-policy`, exact policy hash and
`--internal-approval-authority-sha256`; repository checks supply none of them.
See `../docs/D3XX_ADAPTER_BOUNDARY.md` for the remaining gates.
`service-install` requires the exact token
`INSTALL-FORGE-ACQUIRE-SERVICE`, refuses to replace an existing service,
configures an on-demand LocalSystem service with an unrestricted service SID
and bounded restart actions, and never starts it. Repository validation does
not call the mutating command.

The host now also has a bounded hash-chained fresh-epoch reconnect ledger and
owner state machine. It records an attempt before opening D3XX, preserves the
eight-attempt limit across service restarts, rejects stale Pod epochs, times out
silent candidates and fails the prior Run before a new connection is admitted.
This is deterministic host-software evidence only.

The transport deadline deliberately excludes synchronous application handling.
A blocked handler, dispatcher mutex, persistence call or hardware owner can still
delay listener join and service shutdown without bound; that is an open P1 and a
release-blocking process-isolation/deadline gate. Dedicated response-write-pending
and cancel-drain quarantine injection tests also remain open.

The historical v1 same-supervisor run remains retained evidence. The retained local
engineering-stress evidence is v2 at
`E:\temp\forge-acqd-gui-kill-1000-independent-v2-20260826-085443-f1cda93eff53`:
distinct supervisor/owner PIDs 6584/29984, owner exit 0, `owner_process_isolated=true`
and `owner_job_assigned=true`. Its 1,000 real GUI terminations split 500 after ACK plus
reaccept and 500 at pending `AckRead`; every post-kill snapshot stayed Recording, GUI
raw bytes and Stop/Abort were zero, and one supervisor Stop sealed 18,882 records
(`0..18881`) at durable 18,882. The independent Rust verifier, rehashed retained
executable (`747809...9fb2ef`), journal (7,024,168 bytes, `428781...9ef467`) and audit
(5,009 events `0..5008`, 4,222,855 bytes, `7e2809...7111fa`) pass. Every fixed
five-event attempt has owner-observed exit-code, bounded wait and `signaled_reaped`;
invalid count is zero. Its `job_object_termination` value records the supervisor's selected
termination method, not an owner query of Job active/empty state. Receipt v2 evidence hash is
`1d47e1...4df1fa`, unkeyed/not an attestation. This is still
`scm_emulated=true`, `service_deployed=false`, hardware/NWB false, so it is not an
installed-SCM or product M1 qualification.

The current v3 path removes the ordinary parent-controlled spawn-to-Job window. It creates
each owner/GUI child suspended, configures `KILL_ON_JOB_CLOSE`, assigns the child, reverifies
the stable retained executable and resumes only after every gate passes. Private control v2
delivers four typed containment facts and full reap evidence into audit/receipt v3. The owner
validates those facts, independently waits its retained primary-process handle and
cross-checks exit code and deadline; Job active-zero/empty remains supervisor-observed because
the owner deliberately has no duplicate Job handle. Old v1/v2 receipts and audit v2 fail
closed on the v3 verifier. Fresh evidence is 446/446 qualification unit tests and four
integration cases; the 1,000-kill test is still ignored, so no v3 endurance claim is made.

`qualification-harness` is an explicit default-off engineering feature. The fresh local,
gitignored formal-default release check at
`target\formal-default-release\x86_64-pc-windows-msvc\release\forge-acqd.exe`
(2,082,304 bytes, SHA-256
`4cf1e09744bef0b6875bed3b1492eb22ef578c0679086c3c04c76e1c9c8db1dd`) rejects all three
GUI-kill commands and contains neither the v3 receipt token nor the command token. It is not
a distributable release artifact. Installed SCM identity/ACL/restart and blocked-handler
shutdown, synchronous handler bounds, mapped-image/path-ancestor ABA, abnormal same-account
early Resume, qualification-root ACL/WDAC/Authenticode, owner-independent Job active/empty
queries, pending-AckRead request/challenge binding, listener/observer joins, hardware/
endurance/HIL and release remain open.

Directory metadata/PLP durability, 190.08 MB/s/24-hour load and hardware
transports also remain unqualified. No production policy/receipt, supported
DLL/Pod or firmware/HIL evidence is present. The current daemon replay is
deliberately one synthetic channel at roughly 60 kB/s. It is M1 lifecycle
evidence, not a storage or acquisition release receipt. A fresh one-second
optimized journal-only smoke on 2026-08-13 reached 287.22 MB/s and independently
verified, but its 30-minute and 24-hour duration gates remained false and NWB
dual-write was disabled.
