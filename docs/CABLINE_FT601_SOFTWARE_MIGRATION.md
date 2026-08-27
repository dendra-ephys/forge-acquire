# CABLINE Rev A / FT601 software migration

Status: Host-side migration implemented; physical hardware path unavailable

## Active hardware facts consumed by software

- Receiver-Pod FPGA: `LFE5UM-25F-8MG285I`.
- Headstage→Pod DATA: 1.25-Gbit/s continuous 8b/10b DHL v1.
- Pod→Headstage CTRL: 20-Mbaud Manchester; ACK returns over DATA.
- Headstage source timebase: 25 MHz. USB arrival time is never sample time.
- Uplink: FT601Q-B-T, 32 data bits, four byte enables, synchronous 245 FIFO,
  2.5-V VCCIO and one D3XX channel.
- Receipt-selected FIFO profile: 66.666667-MHz bring-up or 100-MHz release.

The D3XX layer can read the FT60x configuration and USB descriptors. It cannot
measure VCCIO or prove board routing, so 32-bit wiring and 2.5-V VCCIO are bound
to an approved hardware/SKiDL-build hash rather than reported as runtime
telemetry.

## Driver admission

The active driver accepts only `FT_DEVICE_601=601`, one exact unique serial,
SuperSpeed enumeration, an exact approved D3XX DLL hash, configuration-readback
hash, descriptor hash, Host protocol hash and hardware-build hash. The 320-byte
`Ft601AdmissionReceiptV1` contract hash is
`8a6c6fb4905466be086781f1f2aef2901b6d092524b6b3609b7a02974cbdb992`.
Exactly one clock-profile bit is required. An FT600 (`device_type=600`) or the
historical `FGRD3A01` receipt fails closed.

This is an internal Forge evidence gate. It is not an FTDI licence, paid
authorization, activation service or device attestation.

## Headstage profiles

The control-plane model and Python DHL codec retain this exact decode catalog:

| ID | DHL tuple `(variant, chips, flags, channels)` | Admission | Stim policy |
|---|---|---|---|
| `rhd2132x1` | `(1,1,0,32)` | active-product | none |
| `rhd2132x2` | `(1,2,0,64)` | decode-only | none |
| `rhd2164x1` | `(2,1,0,64)` | active-product | none |
| `rhd2164x2` | `(2,2,0,128)` | active-product | none |
| `rhs2116x1` | `(3,1,4,16)` | active-product | M0 representable, still hard-disabled |
| `rhs2116x2` | `(3,2,4,32)` | active-product | acquisition only until capability v2 |
| `rhd2132x1_imu` | `(1,1,2,32)` | active-option | none |
| `rhd2132x1_echem` | `(1,1,1,32)` | active-product | none |
| `rhd2132x1_imu_echem` | `(1,1,3,32)` | active-option | none |
| `rhd2164x1_echem` | `(2,1,1,64)` | active-product | none |
| `rhs2116x1_echem` | `(3,1,5,16)` | active-product | hard-disabled |
| `rhd2132x1_rhs2116x1` | `(4,2,4,48)` | active-product | hard-disabled |
| `rhd2164x1_rhs2116x1` | `(5,2,4,80)` | active-product | hard-disabled |

The current `DeviceCapabilitiesV1` represents exactly 16 RHS channels. The
32-channel RHS build must not advertise a false 16-channel stimulation shape.
IMU/electrochem readiness is profile metadata, not stimulation authority and
not evidence that either payload has a frozen Host/NWB persistence mapping.
Decode/catalog support preserves replay and forward compatibility. `Active-product` and
`active-option` identify the frozen matrix; they do not mean a board is electrically
closed or released. Only an independently approved deployment/Arm policy plus current
hardware evidence can admit a real Run. `decode-only` cannot start a new Run, and no
catalog label alone can authorize stimulation.
The GUI new-Run preflight rejects a missing, decode-only, or
`graph_closed=false` identity, while Protected Replay remains readable without
inventing a live profile. Stimulation preflight additionally requires graph
closure and the profile's explicit Host v1 capability; a 16-channel physical
count alone cannot promote electrochem, mixed, or open-graph products into
stimulation authority.

## Sequence and time mapping

DHL `sequence` counts every packet, including Status/ACK/Error. Canonical
`record_sequence` counts only emitted Host records and starts at zero per Pod.
The bridge keeps these counters separate. It also uses one first-Neural
`(sample_counter, timestamp_25mhz)` anchor and evaluates all canonical time
boundaries from the Descriptor's rational sample rate. A sample gap or source
timestamp disagreement of 40 ns or more is rejected. The exact mapping is
`T0*40 + floor((C-C0)*1_000_000_000*D/N)` with widened overflow checks; Stop/Start
preserves the transport-epoch anchor and expected next counter.

The ACK payload is exactly eight little-endian bytes
`{ctrl_sequence:u32, opcode:u8, status:u8, reserved:u16=0}`. The bridge returns
explicit Descriptor, Inventory, Neural or ACK dispositions, allows one pending
CTRL and requires a byte-exact Inventory replay before a matching successful
`QUERY_INVENTORY` ACK. A failed QUERY ACK clears the request without requiring
replay. The first Inventory must exactly match the Run-approved assembly-manifest
hash, channel-map hash and sorted unique component-instance IDs; arbitrary
nonzero hashes or profile-shaped substitute IDs are rejected. An unfrozen mapping
or post-admission contradiction poisons the bridge until explicit link relock.
A successful `NEURAL_START` ACK must be admitted before the first Neural packet;
after a successful `NEURAL_STOP` ACK, another Neural packet is rejected until a new
successful Start ACK.

The bridge derives a deterministic integral 1-ms block from the Descriptor rate.
At 30 kHz, a block has 30 full-channel rows, with one row equal to one frame.
Neural packet boundaries may occur anywhere: one packet can yield 0..N canonical
records. `record_sequence` is independent of DHL `sequence`, and the first sample
counter plus 25-MHz timestamp establishes the rational absolute-time mapping.
On a successful `NEURAL_STOP` ACK only, a pending 1..N-1-row tail is emitted as
an unpadded, structurally complete `SampleBlockV1` with
`COMPLETE | HARDWARE_TIMESTAMPED`; failed or other ACKs do not flush. This is the
reference “last record before ACK” rule and does not mean Stop equals saving.

## Portable component evidence

The canonical builder is record-atomic in EBR and emits the exact 176-byte
`CanonicalRecordEnvelopeV1` header plus 32-byte `SampleBlockV1` header, CRC32C,
32-bit words with byte enables, SOP and LAST. It is a formatter, not the Run sequence
owner: explicit `record_sequence_i` is encoded verbatim. Exact abort discards only an
incomplete pre-built prefix; a record that has reached `record_built_o` remains immutable
and drains to the distinct `record_transferred_o` boundary. Five variants execute 17
tests with 58 filter-only skips. The historical pre-optimization resource result used
two multipliers and is obsolete. Its parameter guard rejects
insufficient EBR or a configured Host payload above 1 MiB, while invalid/X/Z beats cannot
create unproven record state. The per-Run sequence allocator, atomic record-store commit
and Host-authoritative eviction ACK remain separate seams. The current explicit
128-channel/30-row/11-bit-address generic probe reports 4 DP16KD, zero
MULT18X18D, 3,119 LUT4, 1,356 FF, 252 CCU2C and 250 PFUMX with 0 problems.
Its exact LFE5UM-25F-8/csfBGA285 out-of-context pack-only run reports 3,773
TRELLIS_COMB, 1,356 FF, 4/56 DP16KD and zero DSP. The Phase-2A two-slot store
now owns sequence and atomic complete-record commit; it passes 8/8 focused tests,
including Abort cancellation of an active replay plus an explicit forensic restart,
and exact-device pack-only at 93 total LUT4s, 99 TRELLIS_COMB, 23 FF,
8/56 DP16KD and zero DSP.
It has no Host release/eviction input, so both committed records stay retained and
then backpressure capture. These are component resource-legality results, not
placement, routing, timing closure or hardware behavior.
The RHD2132x1 producer reference has 125-MHz/30-kHz 4166/4167/4167 cadence,
25-MHz 833/833/834 timestamp cadence, a 64-bit counter, epoch-sticky overrun
handling and in-flight drain before Stop ACK eligibility; targeted evidence is
7/7.

The decoded-symbol CDC seam now latches the first fault, counts only one failed
in-flight packet, rejects u64 sequence MAX wraparound, and separates RX committed
from SYS delivered packet counts. Latest targeted results are guard 7/7, CDC 18/18
and FIFO 1/1; CDC Yosys reports 19 DP16KD, 1,670 LUT4, 1,737 TRELLIS_FF,
347 CCU2C and 214 PFUMX with 0 problems.

The standalone SYS-domain Neural payload parser passes 24/24 focused tests with strict
single-file lint clean. It validates type 2 under frozen running/channel context, the
exact prefix and outer length through the 1-MiB ceiling, signed little-endian sample-major
rows, counter continuity, LAST/done and X/Z behavior. A legal done may pend behind the
backpressured final sample, and continuity commits only after both complete. A retained
sequence/exclusive-end completion transaction blocks the next packet until consumed.
Fresh generic ECP5 synthesis reports 1,035 LUT4, 480 FF, 299 CCU2C, 50 PFUMX
and zero DSP; exact-device pack-only reports 1,743 TRELLIS_COMB, 480 FF,
  zero EBR and zero DSP. The portable Neural-to-canonical pipeline attaches the parser to
  time mapping, blockization, canonical construction and the two-slot store; the registered
  dispatcher, committed CDC/runtime output and product top remain unattached.

The standalone bounded Neural blockizer uses two 4096 x 16-bit EBR banks and the default
Rev-A ceiling of 30 rows by 128 channels. Its 12/12 top-level tests contain 65 executed
assertion-bearing subcases for cross-packet and packet-over-multiple-block aggregation,
sample/counter/order failures, two-bank backpressure, Stop spanning three full blocks plus
an unpadded tail, repeated Stop and X/Z/fault closure. Strict combined lint is clean;
fresh exact-device pack-only reports 5,525 TRELLIS_COMB, 1,616 FF, 8 EBR and
zero DSP. The component preserves the first contributing
  DHL sequence/timestamp but does not map rational nanoseconds by itself. The portable
  pipeline attaches parser, rational mapper, builder and replay store. Stop ACK, dispatcher,
  committed CDC/runtime, FT601 and product top remain open, and no nondefault parameter or
defensive 1-MiB boundary configuration is qualified.

The standalone rational Neural time guard passes 21/21 focused tests for the exact
transport-epoch anchor and floor formula, `<40 ns` later-packet admission, arithmetic
overflow, metadata/sample/query backpressure, epoch/interval lifetime and query service
during an open sample proxy. Unified strict lint is clean; generic ECP5 synthesis is
1,315 LUT4, 1,044 FF, 254 CCU2C, 143 PFUMX and 4 MULT18X18D with zero problems.
Exact-device pack-only reports 1,865 TRELLIS_COMB, 1,044 FF, zero EBR and four
  DSP. The portable pipeline attaches it to parser, blockizer, adapter, canonical builder
  and store; product attachment remains open.

The standalone block-to-canonical adapter passes 25/25 focused tests. It freezes the Arm
identity/layout/rate context, queries the rational mapper for both block boundaries and maps
all builder fields without using the preserved packet timestamp as canonical time. Unified
  strict lint is clean; fresh generic ECP5 synthesis is 2,088 LUT4, 826 FF and zero DSP;
  exact-device pack-only reports 2,666 TRELLIS_COMB, 826 FF, zero EBR and zero DSP.
  Portable parser/time-guard/blockizer/builder/store integration is closed; product
  dispatcher/CDC, release, replay scheduling over FT601 and hardware remain open.

Fresh component-wise exact-device pack-only evidence attributes zero DSP to the
  parser, blockizer, adapter and 128-channel builder and four DSP to the rational
time guard. The prior co-resident 22-DSP report predates the multiplier removal
and is stale. A fresh flattened aggregate attempt stopped at the high-memory
AUTONAME phase and emitted no new JSON or pack report. Therefore no current
aggregate fit, LUT/FF/EBR total or four-DSP product claim is made. The probe also
excludes SYS parse/dispatch, startup/Arm, CDC/PCS, sequence/release integration,
  FT601 and the physical product top; product P&R, timing and HIL remain open.

The portable Neural-to-canonical Run seam passes 18/18 focused tests. It freezes and fans
out legal context, preserves the Run sequence across transport refanout, consumes retained
packet completion, aggregates across packet boundaries, drains a Stop-held tail, propagates
two-slot backpressure and coordinates Abort/fault to an inactive store. Normal Abort drains
a built immutable record; a faulted store explicitly abandons only a suffix it cannot
accept, without commit or sequence advance. Active replay is withdrawn and retained slots
require a later explicit forensic replay from SOP. Strict lint and Yosys hierarchy checks
pass, but no aggregate fit, product-top attachment, P&R, timing, FT601 or HIL is implied.

The Phase-2B durable-record release guard passes 11/11 and checks already decoded,
authenticated and completion-verified fields against exact retained geometry and monotonic
durability frontiers. It emits authorization only; protected decoding, per-slot binding,
atomic eviction and daemon/FT601 exchange remain open.

Portable startup validation also has exact raw-payload SHA (5/5), startup hasher
(4/4), expected/actual hash gate (5/5), Descriptor semantics (6/6 across all 13
decode tuples) and Inventory semantics (5/5 across board profiles 1..8). Descriptor
generic synthesis is 507 LUT4/787 FF/4 CCU2C/18 PFUMX; Inventory is 1,626
LUT4/997 FF/179 CCU2C/57 PFUMX, both with 0 problems. These are standalone
component results, not product-integration or hardware-admission evidence.

The startup fanout wrapper now accepts exactly type 1 then type 9, transfers each
payload byte to SHA and semantic parsing atomically, preserves entry/summary
backpressure, explicitly rejects type 5 in the Inventory slot, and drops wrapper-level
admission in the same cycle as an upstream or terminal-protocol fault. It passes 6/6;
generic ECP5 synthesis reports 9,021 LUT4, 5,551 FF, 609 CCU2C, 344 PFUMX and
3 L6MUX21 with 0 problems. It remains component evidence, not a product-top result.

The terminal contract guard passes 8/8 and the committed-SYS startup component pipeline
passes 6/6, including registered-Arm provenance, exact-instance cross-checks, transport
1/X/Z same-cycle withdrawal, quiescent Disarm and epoch recovery. Unified synthesis
reports 17,546 LUT4, 9,270 FF, 818 CCU2C, 825 PFUMX and 25 L6MUX21 with zero
  problems. This closes the portable startup component seam only. The separate portable
  Neural-to-canonical seam is also integrated, but startup/dispatcher/committed CDC/product
  attachment and FT601 remain open.

## Compatibility boundary

`CanonicalRecordEnvelopeV1`, `SampleBlockV1`, journal, replay and NWB remain the
Host storage boundary and are independent of the FT601 bus width. Historical
event-payload-v1 ordinals named `POD_FT600` and `FT600_BACKPRESSURE` remain
unchanged solely so archived records retain their frozen hash and meaning. The
active CABLINE/FT601 path must not emit new events under those names. Its
source-health companion is the exact 360-byte
`ForgeDirectPodCablineStatusV1`, contract hash
`40670b2feff4580e96a475c8f0aad83eab8bc3b267b19dc380d3dd1bf372cad0`.
It requires link/Descriptor/Inventory/CTRL readiness, zero error/drop/overflow/
relock counters, stable identities and stable source hashes with 100-ms
freshness. Deployment-policy v4 separately approves the five-hash composite, the
exact embedded identity-catalog sources, one Descriptor/Inventory identity policy and an
explicit nonzero Host channel-layout ID independent of the board-profile ID;
first-observed stable values alone cannot authorize a Run. The current transport epoch's
admitted `ForgeDirectPodDhlIdentityCapsuleV1` is required in addition to capability,
Pod-time and CABLINE status before a pre-Run Ready snapshot. The exclusive owner revalidates
time/CABLINE freshness on every poll, even with no command pending, using its own
monotonic time rather than a caller-supplied queue timestamp. The wall origin is
captured at owner request/poll entry, so planning, translation, IN parsing and
journal work cannot reset the budget. Promotion captures the remaining evidence
lifetime before creating Run artifacts and rechecks it
after artifact creation and durable command intent immediately before Pod OUT.
Every later Run command and automatic Replay request uses the same before-intent/
before-OUT guard, so the post-poll watchdog is not the first stale-source check.
The Host catalog recognizes fourteen identities, including graph-closed
`rhs2116x2_imu` as tuple `(3,2,6,32)` with instances `[0,1,100]`, but Host v1
stimulation remains disabled for that 32-channel RHS option. After capsule admission and
before identity storage/Ready, DeviceCapabilities must cover the acquisition-channel count,
signed-I16 format and admitted exact rational rate range. Every protected canonical
record is checked against the approved layout, acquisition-channel count and signed-I16
format before Replay staging or journal append; SampleBlock also binds the exact rational
sample rate, whose first numerator/denominator representation is frozen per Pod. The current
Headstage manifest and Receiver-Pod semantic RTL still implement
only the preceding thirteen identities, so this Host-side closure is not hardware Ready.

## Hardware availability gate

The GUI continues to report direct hardware unavailable until USB identity and
configuration evidence are released and active Receiver-Pod RTL supplies the ECP5UM
receive PCS/product top, attachment of the portable committed-SYS startup pipeline and
standalone Neural parser/blockizer, product 1-ms DHL-to-canonical packetizer and
CABLINE source-status emission, remaining Status/Error mappings, FT601 scheduler,
Stop ACK, Replay, persistent epoch, routed timing and physical HIL evidence. The
CDC still begins at the vendor PCS decoded-symbol seam; RHD2164/RHS exact cadence
and product integration are also open. The portable decoded-symbol atomic CDC core,
SYS structural parser, unattached registered phase dispatcher and Neural parser/blockizer, startup
wrapper, Arm-context bank, terminal cross-checker, component startup pipeline, typed ACK
software and Host source-status gate do not prove that the Pod emits the required Host
bytes. The current machine has no
supported D3XX DLL, FT601 device or approved receipt, so hardware remains unavailable;
loading a DLL or seeing a USB device is insufficient.

The React control plane does now consume the frozen low-rate
`HardwareServiceSnapshotV1` through the existing Tauri status command. Its strict
read-only adapter keeps command reachability separate from the four daemon availability
bits, rejects unknown fields/bits, request mismatches and same-epoch sequence/time/counter
regression, and marks any failed poll stale. This evidence panel does not call the Run
command bridge, does not populate `SystemSnapshot.pods`, does not infer receipt/profile/
USB/build/CABLINE details, and does not enable `direct_d3xx` or send raw samples to the
WebView.
