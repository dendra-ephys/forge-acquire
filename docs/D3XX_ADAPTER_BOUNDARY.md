# Forge direct-Pod D3XX adapter boundary

Status: host adapter foundation; hardware acquisition unavailable

The implementation spans `recording-daemon/src/d3xx*.rs`,
`direct_pod_stream.rs`, `direct_pod_cabline.rs` and their frozen schemas. Its
ABI and status constants follow FTDI AN_379 D3XX Programmer's Guide revision
1.7. The FTDI Windows driver is not redistributed by this tree, and no driver
or FT601 device was present during the latest probe. The current machine has no
supported D3XX DLL, FT601 unit or approved admission receipt; hardware is
therefore unavailable.

Official references:

- <https://ftdichip.com/wp-content/uploads/2020/08/AN_379-D3xx-Programmers-Guide.pdf>
- <https://ftdichip.com/drivers/d3xx-drivers/>
- <https://ftdichip.com/wp-content/uploads/2020/07/AN_370-FT60X-Configuration-Programmer-User-Guide.pdf>

## Current source-to-canonical reference boundary

The Python `DhlToHostBridge` is the reference software mapping behind this
adapter. It derives an integral 1-ms block from the admitted Descriptor rate;
30 kHz means 30 full-channel rows per block, with one full-channel row equal to
one frame. Neural packets may be split or combined arbitrarily: one packet can
produce 0..N canonical records. DHL `sequence` and Host `record_sequence` remain
independent, and the first sample counter plus 25-MHz timestamp establish the
rational absolute-time anchor.

Before a successful `NEURAL_STOP` ACK, the reference retains a 1..N-1-row tail.
That successful ACK emits the tail as an unpadded, structurally complete
`SampleBlockV1` with `COMPLETE | HARDWARE_TIMESTAMPED`; failed or other ACKs do
not flush it. This is the reference “last record before ACK” semantic, not a
claim that Stop means the record has been saved.

The portable canonical builder is record-atomic in EBR and produces the exact
176-byte `CanonicalRecordEnvelopeV1` header plus 32-byte `SampleBlockV1` header,
CRC32C, 32-bit words with byte enables, SOP and LAST. It formats the explicit
external `record_sequence_i` and does not allocate or increment the Run sequence.
Its five variants execute 17 tests with 58 filter-only skips. The current explicit
128-channel/30-row/11-bit-address generic probe reports 4 DP16KD, zero
MULT18X18D, 3,119 LUT4, 1,356 FF, 252 CCU2C and 250 PFUMX with 0 problems;
exact-device out-of-context pack-only reports 3,773 TRELLIS_COMB, 1,356 FF,
4/56 DP16KD and zero DSP.
It rejects insufficient EBR or a configured Host payload above 1 MiB at elaboration;
pre-built abort discards only the incomplete prefix, while a built immutable record
drains through a separate transfer boundary. The builder remains separate from the
sequence owner and record-store commit. The Phase-2A two-slot store now owns those
two responsibilities and passes 8/8 focused tests, including Abort cancellation of
an active replay followed by an explicit forensic restart; exact-device pack-only
reports 93 total LUT4s, 99 TRELLIS_COMB, 23 FF, 8/56 DP16KD and zero DSP. It deliberately has no Host
release/eviction input, so both committed records remain retained after transfer and
then backpressure capture. These pack-only results do not prove placement, routing,
timing closure or hardware behavior.
The RHD2132x1 producer reference has 125-MHz/30-kHz 4166/4167/4167 launch
cadence, 25-MHz 833/833/834 timestamp cadence, a 64-bit counter, epoch-sticky
overrun handling and in-flight drain before Stop ACK eligibility; its targeted
result is 7/7.

At the portable decoded-symbol seam, CDC now latches the first fault, drops a
failed in-flight packet once, rejects u64 sequence MAX wraparound, and keeps RX
committed and SYS delivered counts separate. Latest targeted results are guard
7/7, CDC 18/18 and FIFO 1/1; the CDC Yosys result is 19 DP16KD, 1,670 LUT4,
1,737 TRELLIS_FF, 347 CCU2C and 214 PFUMX with 0 problems.

These are reference/component results, not a claim that the D3XX product path
is integrated. A portable SYS seam now connects the Neural parser, rational mapper,
blockizer, adapter, builder and Phase-2A store behind an Arm-frozen Run context. It is not
connected to the registered dispatcher, committed CDC/runtime output, startup admission,
Host-authoritative eviction or FT601 scheduler. The Phase-2B release guard validates
already verified fields but does not decode/authenticate the companion or evict slots;
neither Host nor FPGA exchanges the release bytes. CDC begins at the vendor PCS decoded-symbol seam; ECP5UM
PCS/physical top, MG285 LPF/SDC/P&R/HIL, RHD2164/RHS exact cadence and product
integration remain open.

## Implemented fail-closed policy

- Load `FTD3XXWU.dll` or `FTD3XX.dll` only from System32, or load an explicitly
  configured absolute file with dependency search limited to its directory and
  System32. The ordinary DLL search path and current directory are never used.
- Resolve the exact enumeration, serial-open, configuration-readback, stream,
  timeout, USB-descriptor, pipe-information, abort, overlapped-read/write and
  close entry points before accepting the library. Hash the loaded DLL for
  evidence binding.
- Parse the exact 320-byte `Ft601AdmissionReceiptV1`, whose LF-normalized
  contract SHA-256 is
  `8a6c6fb4905466be086781f1f2aef2901b6d092524b6b3609b7a02974cbdb992`.
  Require an exact nonzero out-of-band receipt-file hash, the protected
  service configuration's internal approval-authority identifier hash, a valid issue/expiry
  interval and the exact M0 protocol hash. The receipt binds the device ID,
  serial, D3XX library, FT601 configuration, canonical USB descriptors,
  approved Receiver-Pod hardware/SKiDL-build hash and exactly one FIFO clock
  profile (`bringup_66_mhz` or `release_100_mhz`).
  It is Forge deployment admission evidence, not a digital signature,
  device-generated attestation, FTDI licence or external authorization.
- Enumerate at most 64 devices. Select only type `FT_DEVICE_601=601` by one
  exact, unique, printable 1–15-byte serial number. Production never falls back
  to index, description or location. Already-open, non-SuperSpeed, non-FT601 and
  duplicate-serial devices fail closed.
- Read the exact 152-byte `FT_60XCONFIGURATION` structure and require the
  released per-unit readback hash plus the receipt-selected FIFO clock raw
  value 1 (66-MHz bring-up) or 0 (100-MHz release), FIFO mode raw value 0
  (245 synchronous) and channel configuration raw value 2 (one channel). A
  missing/zero expected hash or a clock value from the other profile cannot
  open the device. The 32-bit data width and 2.5-V VCCIO are hardware-build
  evidence; D3XX cannot measure VCCIO, so the driver never reports a runtime
  voltage verification.
- Read the official device, configuration, interface and pipe descriptors
  after opening. Require USB 3 or newer, one self-powered configuration, two
  interfaces, data interface 1 alternate 0 with two Bulk pipes, exact OUT
  `0x02` and IN `0x82`, and matching nonzero VID/PID between the device
  descriptor and configuration readback. Hash the canonical logical descriptor
  fields and require the receipt's exact descriptor hash.
- Configure the one-channel IN endpoint `0x82` with bounded stream size and
  timeout. Configure bounded timeouts for both `0x82` and the one-channel OUT
  endpoint `0x02`. Both directions use the D3XX overlapped API. The IN side now
  owns a fixed-depth queue of stable-address `OVERLAPPED` and byte-buffer
  allocations, polls the oldest request with `FT_GetOverlappedResult(...,
  FALSE)`, treats `FT_IO_INCOMPLETE` as pending, and returns completions only in
  submission order. A single owning thread may send OUT control while IN reads
  are pending, matching AN_379's duplex asynchronous example; no device handle
  is shared concurrently between Rust threads. Queue, transfer-size and total
  allocation bounds are fixed, and any transfer/release contradiction poisons
  the I/O epoch. Cancellation aborts the IN pipe and releases every initialized
  overlapped resource. The M3 OUT gate
  accepts only exact protocol-v1 acquisition-scope `RunCommandV1` and
  `ReplayRequestV1` messages; arbitrary bytes, replies, worker messages,
  stimulation scope and short writes fail closed. Explicit shutdown aborts
  both pipes, clears the IN stream and closes while returning the first failure.
- `DirectPodStreamReassembler` holds at most one maximum-size M0 message and
  demultiplexes exact canonical records, low-speed replies, time snapshots,
  Replay offers and CABLINE source status across arbitrary USB chunk
  boundaries. The production ingest uses the explicit CABLINE-aware API; the
  legacy API rejects that new frame rather than silently dropping it. It
  validates the complete message before emit, rejects
  implicit byte-scanning resynchronization, poisons the current transport epoch
  on malformed/partial input or consumer failure and requires a fresh epoch for
  recovery. The older canonical-only parser remains a record-path test utility,
  not the full direct-Pod stream boundary.
- `DirectPodControlTracker` requires one capability statement matching the
  protected admission device ID, direct-D3XX transport, M0 protocol hash and
  `ACK_REPLAY | GLOBAL_TIME | STOP_ACK`. It then permits one in-flight request,
  strictly increasing request IDs, and exact outer/body request-ID and epoch
  matching for ACK/NACK. Exact duplicate bytes are idempotent; changed
  capabilities, contradictory reuse, timeout, unresolved close or transport
  failure poisons the epoch. Host-only `GetSnapshot` and
  `AcknowledgeFailure` never reach the hardware OUT pipe.
- A Stop command has a stricter success path. The frozen 208-byte
  `DirectPodStopBoundaryV1` companion contract has LF-normalized SHA-256
  `231b5c78e39fb871119d96d5bc5fe8aa57803e211950785194244bba79c3c09c`.
  The Pod must emit every final canonical record before its Stop `AckV1` on the
  same ordered IN stream. The host updates the boundary only after each record
  receives an exact journal append receipt. Stop succeeds only when ACK code 1,
  state code 4, request ID, epoch and `receipt_hash` all match the SHA-256 of
  that exact boundary. A normal matched ACK or a mismatched boundary poisons
  the epoch.
- Replay has its own stricter same-epoch path. The frozen
  `ForgeDirectPodReplayBoundaryV1` companion at LF-normalized SHA-256
  `f6efaca7514196deb3089aeca92752f11702c62050eb21f6b24a4019627eb8b2`
  defines an exact 280-byte request context and 296-byte completion. The
  request context binds the active Run/device/Pod/headstage, transport epoch,
  next journal record sequence, bounded half-open range, deadline/reason,
  FT601 admission-receipt file hash, frozen Run configuration and a 65,536
  record/256-MiB ceiling. While Replay is active no other control or ordinary
  source record may interleave. Every returned canonical record must be in
  sequence with `REPLAYED` set, validate before append, agree with the exact
  append receipt, and contribute to a rolling SHA-256. The final range crosses
  a journal durability barrier before an ACK is eligible; that ACK must bind
  the exact completion hash in RECORDING state. A NACK is accepted only before
  any replay data and fails a durable hardware Run closed.
- Automatic Replay planning is admitted only from the source-authored
  `DirectPodReplayOfferV1` companion. Its exact 280-byte contract has
  LF-normalized SHA-256
  `01f5c69d43623d746b76b0bd04873b03d0870b8ce2e42bb4153e3c9d3bdd55b5`.
  The Pod must declare that live output is quiesced, the exact missing suffix
  remains replayable through a hardware-time deadline, and no later live
  record will be emitted meanwhile. The offer must start at the host journal's
  next record sequence and bind the latest fresh Pod state. The owner persists
  the offer, then the derived Replay intent, then writes OUT. A live record
  between offer and Replay, a stale/changed state, an expired offer, a range
  mismatch or a restart with only an unresolved offer fails the Run closed.
  The host never infers an omitted record from USB arrival or from a future
  record that the append-only journal could no longer insert before.
- Host-authoritative replay-slot eviction is separately frozen by the 312-byte
  `DirectPodRecordReleaseV1` companion at LF-normalized SHA-256
  `512d2fb554d4bc9bb2d56f46c3e25bd8d12548c93fa3eec62ae98800af067285`.
  It binds an exact one- or two-record range to durable journal/checkpoint evidence,
  the retained two-slot store state and an idempotent request/reply identity. Rust,
  Python and C++ codecs plus three golden vectors pass, but the daemon, FT601 path
  and FPGA store do not exchange it yet; transfer or Stop completion alone therefore
  cannot release a slot.
- `DirectPodIngestSession` composes the protected FT601 admission, exact stream
  reassembler, control tracker, CABLINE source tracker, source Stop tracker and the real
  `JournalWriter` in one ordered host domain. It accepts canonical records only
  after a verified Start ACK, checks Run/Pod/headstage identity plus the policy-approved
  layout, catalog/Descriptor/envelope channel count, signed-I16 format and exact rational
  SampleBlock rate before Replay staging or append, freezes the first exact rate
  numerator/denominator per Pod,
  advances the Stop boundary only from the returned journal append receipt,
  rejects any record after the verified Stop ACK, and keeps committed,
  stable-media durable and sealed states distinct. Seal requires no partial
  stream, no pending control, a verified source boundary and matching journal
  last sequence.
- `DirectPodRuntime` is the transport-neutral single-owner scheduler used by
  the real D3XX implementation and deterministic test transport. It primes an
  exact fixed queue depth, replaces exactly one read per completion, requires
  an explicit current hardware-global time rather than USB arrival time,
  cancels all reads on a transport/control/ingest contradiction, and after a
  verified Stop requires the oldest remaining read to report pending before it
  cancels the tail and permits seal.
- `HardwareRunCoordinator` persists real-hardware lifecycle evidence in a
  separate bounded no-overwrite ledger. `DurableDirectPodRuntime` writes the
  requested event before OUT, records the matched reply hash, keeps Start at
  `StartAcknowledged` until the first canonical record has an actual journal
  append receipt, requires the Stop boundary before `Stopped`, and binds its
  terminal event to the journal seal evidence. Restart in any unfinished phase
  is durably failed; exact completed retries are not reissued. This does not
  change the frozen replay response or advertise hardware availability.
  Replay request/reply events share the same ordered ledger: intent is durable
  before OUT, accepted completion requires the verified durable Replay
  boundary, exact retries survive restart without retransmission, and an
  unresolved/rejected Replay makes the Run fail closed.
- `DirectPodTimeSnapshotV1` is a separate exact 152-byte companion at
  LF-normalized SHA-256
  `32c7f4a546b19c3de9eeff4444c95579eebff31b879a2967d9d77d25f4e4706d`.
  It binds device, epoch, increasing status/hardware time, non-regressing
  sample/frame counters, readiness/fault/synchronization flags and hardware
  state. `DirectPodTimeTracker` allows the host monotonic clock only to enforce
  a 100-ms freshness limit. It returns the last explicit Pod time unchanged;
  USB/host arrival time is never converted into a sample or hardware timestamp.
- `ForgeDirectPodCablineStatusV1` is a separate exact 360-byte companion at
  LF-normalized SHA-256
  `40670b2feff4580e96a475c8f0aad83eab8bc3b267b19dc380d3dd1bf372cad0`.
  It binds device/Pod/headstage/epoch, Headstage boot/source identity, next DHL
  sequence, readiness/fault flags, zero link/drop/overflow/relock counters and
  the Headstage-config/Descriptor/Inventory/assembly/channel-map hashes. The
  tracker requires strict status sequence, non-regressing source time/DHL
  state, stable identities/hashes and 100-ms host freshness. It also rejects a
  source status more than 100 ms behind explicit Pod time. Deployment policy
  v4 must approve the domain-separated five-hash composite, the exact embedded
  identity-catalog source hashes and one full Descriptor/Inventory identity policy before
  Run artifacts or OUT. It also approves one explicit nonzero Host
  `dhl_channel_layout_id`; that value is independent of `board_profile_id` and
  is never inferred from it. First-seen stable values are not authority.
- `ForgeHardwareServiceV1` is the separate local operator/daemon companion at
  LF-normalized SHA-256
  `b1dd877cf9b9558352473f8458802a188919fb5a3865884c00a8eb83059e9b54`.
  Its exact 64-byte status request, 176-byte operator Run request and 256-byte
  snapshot bind an observed hardware-state hash, device and epoch. The operator
  supplies a bounded relative timeout; only the daemon may translate it using a
  fresh Pod snapshot. The distinct SCM-hosted hardware pipe is SID protected
  and cannot fall through to replay. With no explicit direct-Pod policy its
  backend returns evidence-bearing `Unavailable` and performs no hardware I/O.
  A Ready/available snapshot additionally requires fresh CABLINE source
  evidence matching the policy's Pod/headstage/approved-binding authority, and
  its evidence hash binds both the time and CABLINE companions. First-seen source
  hashes cannot make the pre-Run connection Ready.
- `direct_pod_deployment.rs` defines the only SCM production-selection path.
  The three service arguments `--direct-pod-policy`,
  `--direct-pod-policy-sha256` and
  `--internal-approval-authority-sha256` are all-or-none. The exact JSON policy
  is strict schema `forge.direct-pod-deployment-policy.v4` and additionally
  binds the canonical Windows data-root hash, receipt path/hash, D3XX source,
  Pod/headstage/Run-configuration identities, the independent
  `approved_cabline_binding_sha256`, all three embedded identity-catalog source hashes,
  their domain-separated bundle hash, exact Descriptor/Inventory/config/rate/assembly/
  channel-map/ordered-instance authority, the independent nonzero Host channel-layout
  identity, fixed queue depth, transfer size and bounded timeouts. Old v1/v2/v3 policy
  files, v4 files missing the layout, and zero/unknown fields fail closed. The deployment
  evidence hash includes the approved layout as little-endian `u32`. It derives a no-overwrite
  Run directory; the operator cannot choose another journal or lifecycle path.
- Only service startup with that complete policy calls the D3XX bootstrap. It
  first scans at most 4096 exact `hardware-run-<RunID>` roots under the
  canonical policy data root in deterministic order. Every root must be a
  contained non-reparse directory with a regular `run.forgewal`, a regular
  `hardware-ledger` directory and matching directory/journal/lifecycle Run
  identity. Malformed names, links/reparse points, incomplete evidence,
  corruption or a nonterminal result abort startup. Reopening an unfinished
  lifecycle durably appends the daemon-restart fault; a repeated scan is
  idempotent. This gate never truncates, seals, resumes or reuses an old Run.
  Its evidence hash is bound into the service deployment evidence. Only after
  successful reconciliation does startup open the one admitted FT601, repeat
  configuration/descriptor admission, prime the fixed queue and require the
  first complete Pod message to be the
  exact `DeviceCapabilitiesV1`; the bounded `ForgeDirectPodDhlIdentityCapsuleV1`, fresh
  Pod-time and approved CABLINE-status companions are then required before Ready or
  promotion. Capsule, time and status may arrive at arbitrary D3XX completion splits and
  in any order after capability. The exact duplicate capsule is idempotent; mutation,
  malformed evidence or a CABLINE identity/hash/source/boot/sequence contradiction poisons
  and cancels that epoch. The capsule's FT601 device ID remains distinct from the protected
  Headstage ID carried by its immutable Descriptor. The transport epoch
  comes from the Pod's outer low-speed header, not the host. Completion bytes, original host-monotonic
  arrival times, partial parser state and the already primed queue move into the
  same pre-Run/Run owner without a second open. Bootstrap or later transport
  failure keeps status unavailable while the owner follows the frozen
  `ForgeDirectPodReconnectEventV1` cycle. The old transport is cancelled and an
  unfinished Run is durably Failed before `TRANSPORT_FAULT`; `ATTEMPT_STARTED`
  is durable before each open; each candidate repeats receipt/DLL/serial/config/
  descriptor/capability/identity-capsule admission and must provide a strictly newer Pod epoch.
  After capsule admission and before identity storage/Ready, capability channel capacity,
  signed-I16 format support and the admitted exact rational rate range are cross-checked
  with checked integer arithmetic.
  Eight attempts, exponential backoff and a bounded capability deadline survive
  service restart. Exhaustion is durable. No epoch invention, old-Run resume or
  simulator fallback is allowed.
- The Host catalog understands 14 exact identities: 10 active products, three
  graph-closed active options and one decode-only profile. The added
  `rhs2116x2_imu` identity is `(variant=3, chip_count=2, flags=6, channels=32)`
  with expected instances `[0,1,100]`. Catalog/graph admission is not hardware
  Ready or stimulation authority; Host v1 deliberately rejects stimulation Arm
  for this 32-physical-stimulation-channel assembly.
- The exclusive owner uses its own monotonic clock when it processes requests;
  a timestamp captured by a queued caller cannot extend evidence lifetime. Its
  wall origin is captured at request/poll entry, so planning, translation, IN
  parsing and journal work all consume the same source budget. It
  validates coherent fresh Pod-time and CABLINE status on every poll, even when
  no control request is pending. During promotion it captures the remaining
  freshness budget before no-overwrite Run artifacts are created, then checks
  it again after artifact creation and after durable command intent immediately
  before hardware OUT. Expiry retains the forensic Run root, fails the lifecycle
  closed and sends no command. Active-Run commands and source-triggered automatic
  Replay requests repeat the same check before intent and immediately before OUT;
  they cannot rely only on the watchdog that runs after a poll.
- Every orderly hardware-owner exit invokes one shutdown hook even after a poll
  error. Bootstrap and pre-Run owners cancel queued reads without sending a Pod
  command. A Run-bound owner cancels transport and durably appends
  `HARDWARE_FAULT_OWNER_SHUTDOWN` if its lifecycle is unfinished. This local
  evidence cannot substitute for an exact Pod Stop/Abort ACK, cannot seal the
  Run and cannot authorize resumption after a new connection.

This is a supervised software binding, not production hardware qualification.
Installed-SCM restart/reconnect qualification and real device evidence remain
unavailable. A two-slot FPGA record-store component exists, but it has no integrated
release/eviction path or product scheduler. The implemented Host Replay planner covers only a
same-epoch, source-declared, quiesced and explicitly replayable suffix. It is
not a heuristic USB-gap detector and is not proof that current Receiver-Pod
product firmware stores, offers or emits replay data.

`forge-acqd d3xx-probe` is read-only. It may report a loaded driver and enumerated
device list, but it always reports `hardware_transport_available=false` and
`approved_admission_receipt_present=false`; it does not open a Pod, change
FT601 configuration, start a Run or install a driver/service.

## Still unavailable

- An independently governed receipt-issuance process, checked-in approved FT601
  configuration image and real per-board programming/readback/admission
  receipt. No production receipt is currently approved or installed.
- Runtime ABI and descriptor evidence against the chosen production D3XX
  package and a real FT601 device, plus Authenticode/package provenance policy.
  The current descriptor checks use exact local ABI layouts and synthetic
  structures; they are not D3XX/USB HIL evidence.
- Active Receiver-Pod FPGA integration for the ECP5UM receive PCS/product top.
  The current Headstage manifest and Receiver-Pod semantic RTL remain frozen at
  13 identities and do not emit/admit the Host-only `rhs2116x2_imu` tuple; a
  separate RTL/HIL execution round is required. Remaining work includes attachment of the
  startup and portable Neural-to-canonical pipelines to the dispatcher/committed CDC,
  DHL identity-capsule/CABLINE-status emission and remaining DHL Status/Error
  production, CTRL request execution, FT601 32-bit bidirectional arbitration,
  persistent reconnect epoch, Stop boundary, protected release/eviction and Replay
  completion. The
  preserved Host-side companion contracts and synthetic candidate tests are
  not evidence that the current CABLINE Pod emits those bytes. The portable
  decoded-symbol atomic CDC core is source/simulation evidence only.
- Issuing and installing a production deployment policy/receipt after the DLL,
  device, firmware and HIL gates pass. The default service configuration must
  continue to omit the policy, and therefore stay unavailable, until that
  controlled internal issuance occurs.
- Short-write/stall/disconnect/USB-reset fault injection, sustained one-Pod
  throughput, exact journal byte reconciliation and 24-hour hardware evidence.

Until every item above closes, product deployment must not install the
direct-Pod policy; the GUI and default service therefore keep D3XX recording
unavailable even if a DLL loads or a USB device enumerates.
