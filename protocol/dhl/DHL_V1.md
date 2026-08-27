# DHL v1 wire contract

DHL v1 is the inner Headstage-to-Pod protocol carried by the 1.25 Gbit/s 8b/10b DATA
lane. The SerDes PCS owns 8b/10b encoding and comma alignment. Logic on either side of
the PCS exchanges `{is_control, byte}` symbols.

## Symbols

- `K28.5`: comma and idle.
- `K27.7`: start of packet (SOP).
- `K29.7`: end of packet (EOP).

The first accepted packet after every link lock shall be a Descriptor and the second
shall be Component Inventory. Sequence values are global within a boot and increase by
exactly one for every accepted packet.

## Packet

```text
K27.7 | 40-byte header | payload | CRC32C little-endian | K29.7
```

CRC32C uses polynomial `0x1EDC6F41` (reflected implementation `0x82F63B78`), initial
and final XOR `0xFFFFFFFF`, over the header and payload only.

### Header (40 bytes, little-endian)

| Offset | Width | Field |
|---:|---:|---|
| 0 | 1 | version (`1`) |
| 1 | 1 | type |
| 2 | 2 | flags |
| 4 | 2 | header length (`40`) |
| 6 | 2 | reserved (`0`) |
| 8 | 4 | payload length |
| 12 | 4 | source ID |
| 16 | 8 | boot ID |
| 24 | 8 | sequence |
| 32 | 8 | timestamp in the 25 MHz Headstage timebase |

Packet type values are Descriptor=1, Neural=2, Chem=3, IMU=4, Stim Event=5,
Status=6, ACK=7, Error=8, Inventory=9, and Electrode Impedance=10.

All DHL v1 header flag bits are reserved and shall be zero. `source_id` and
`boot_id` shall both be nonzero. Once the first Descriptor of a recovered-link
epoch is accepted, both identifiers remain fixed for that epoch; a change is a
protocol fault and requires a new link epoch rather than an in-place relock.

For a Neural packet, `timestamp_25mhz` is the timestamp of the first sample in the
payload. Other packet types use the time at which the event/status was committed.

### Descriptor payload (96 bytes)

| Offset | Width | Field |
|---:|---:|---|
| 0 | 2 | descriptor version (`1`) |
| 2 | 2 | descriptor length (`96`) |
| 4 | 1 | variant: RHD2132=1, RHD2164=2, RHS2116=3, RHD2132+RHS2116=4, RHD2164+RHS2116=5 |
| 5 | 1 | populated Intan chip count (`1` or `2`) |
| 6 | 2 | feature flags: CHEM=1, IMU=2, STIM=4 |
| 8 | 2 | channel count |
| 10 | 2 | sample format (`1` = signed int16 LE) |
| 12 | 4 | sample-rate numerator in Hz |
| 16 | 4 | sample-rate denominator |
| 20 | 4 | timestamp frequency (`25000000`) |
| 24 | 4 | reserved (`0`) |
| 28 | 16 | immutable Headstage device ID |
| 44 | 32 | frozen acquisition/configuration SHA-256 |
| 76 | 16 | firmware-build hash prefix |
| 92 | 4 | reserved (`0`) |

The wire-level decode catalog contains eight neural board profiles and thirteen exact
Descriptor tuples: the ten active product identities frozen by `DEC-HEADSTAGE-003`, two
active IMU/DNP assembly options, and decode-only `rhd2132x2`. Keeping the historical
tuple decodable preserves replay compatibility. A frozen product identity or active
option does not authorize a Run, stimulation, or a hardware-ready GUI state; each still
requires its own exact assets, deployment receipt and release evidence. IMU is an
orthogonal DNP option rather than a new neural board profile. Feature flags describe
devices that completed boot detection and are callable; a footprint or assembly option
by itself is not an advertised feature.

### Component Inventory payload

The Inventory binds the immutable assembly manifest, actual boot detection and Neural
channel identity. It is emitted automatically as packet two and may be requested again
with `QUERY_INVENTORY`. The canonical header is 76 bytes:

| Offset | Width | Field |
|---:|---:|---|
| 0 | 2 | inventory version (`1`) |
| 2 | 2 | header length (`76`) |
| 4 | 2 | entry size (`32`) |
| 6 | 2 | entry count (`1..16`) |
| 8 | 4 | board profile: RHD2132x1=1, RHD2132x2=2 (decode-only), RHD2164x1=3, RHD2164x2=4, RHS2116x1=5, RHS2116x2=6, RHD2132x1+RHS2116x1=7, RHD2164x1+RHS2116x1=8 |
| 12 | 32 | exact assembly-manifest SHA-256 |
| 44 | 32 | exact channel-map SHA-256 |

Each 32-byte entry is:

| Offset | Width | Field |
|---:|---:|---|
| 0 | 2 | stable instance ID |
| 2 | 1 | class: Neural AFE=1, IMU=2, electrochem AFE=3 |
| 3 | 1 | status: expected/unprobed=1, detected/ready=2, degraded=3, expected/missing=4, unexpected/present=5 |
| 4 | 4 | model ID: RHD2132=`0x00010001`, RHD2164=`0x00010002`, RHS2116=`0x00010003`, ICM-42670-P=`0x00020001`, AD5940=`0x00030001` |
| 8 | 2 | first Neural global channel, or `0xFFFF` for a non-Neural component |
| 10 | 2 | Neural channel count, or zero |
| 12 | 2 | native channel base (`0` in v1) |
| 14 | 2 | driver ABI version (`1`) |
| 16 | 4 | capabilities: Neural=bit0, IMU=bit1, amperometry=bit2, FSCV=bit3, stimulation=bit4, RHD electrode impedance=bit5 |
| 20 | 12 | component configuration-hash prefix |

Entries are sorted by instance ID. Neural entries must be contiguous from global
channel zero and must agree with Descriptor model, chip count, total channels and
features. RHD/RHS mixing is admitted only by the explicit ordered mixed profiles 7
and 8; mixing under profiles 1-6 is rejected. The exact logical and connector mappings
are defined by [`CHANNEL_MAP_V1.md`](CHANNEL_MAP_V1.md).

### Neural payload

The fixed 16-byte prefix is followed by signed little-endian int16 samples in
sample-major order.

| Offset | Width | Field |
|---:|---:|---|
| 0 | 2 | channel count |
| 2 | 2 | sample count |
| 4 | 2 | sample format (`1` = signed int16 LE) |
| 6 | 2 | reserved (`0`) |
| 8 | 8 | first-sample counter |

### Neural-to-Host reference aggregation

The Python `DhlToHostBridge` derives a deterministic integral 1-ms aggregation
size from the admitted Descriptor sample rate. For the 30-kHz reference profile,
each block contains 30 full-channel rows; one full-channel row is one frame.
Neural packet boundaries are not aggregation boundaries: a stream may span any
number of DHL Neural packets, and one packet may produce 0..N canonical records.
Host `record_sequence` is independent of DHL `sequence`. The first sample counter
and its 25-MHz `timestamp_25mhz` establish the anchor for a rational absolute-time
mapping; later packet timestamps and counters are checked against that mapping.

Normatively, let the first time-admitted Neural packet provide counter `C0` and timestamp
`T0`, and let the admitted Descriptor rate be numerator `N` and denominator `D`.
For every `C >= C0` in that transport epoch, canonical nanoseconds are

```text
T0 * 40 + floor((C - C0) * 1_000_000_000 * D / N)
```

Both a block's start and exclusive end use this equation independently. A later Neural
packet is accepted only when `abs(packet.timestamp_25mhz * 40 - mapped(first_counter)) <
40`; equality at 40 ns is a fault. All terms are widened before multiplication and any
u64 canonical-time, counter-end, product, quotient or addition overflow is rejected.
Stop/Start does not replace the anchor or relax sample-counter continuity. Only a new
transport epoch may establish a new anchor.

The Headstage shall serialize a successful `NEURAL_START` ACK before the first
Neural packet of that acquisition interval. A Neural packet before that ACK is a
protocol fault. On `NEURAL_STOP`, the producer first stops launching new samples,
drains any in-flight sweep and held Neural frame, then serializes the successful
ACK. No later Neural packet is permitted until another successful `NEURAL_START` ACK.

On a successful `NEURAL_STOP` ACK, and only then, the reference bridge emits a
pending 1..N-1-row tail as an unpadded, structurally complete `SampleBlockV1`
with `COMPLETE | HARDWARE_TIMESTAMPED`. A failed ACK or any other ACK does not
flush the tail. This is the reference “last record before ACK” rule, not a claim
that acknowledgement alone means the record has been saved.

### Chem payload

The exact `Chem=3` payload, simultaneous Ephys artifact-window semantics and accepted
amperometry/FSCV modes are frozen in [`CHEM_V1.md`](CHEM_V1.md). A Chem packet never
deletes, interpolates or rewrites Neural samples.

### Electrode-impedance payload

The exact pre-recording-only RHD diagnostic, fixed 88-byte raw-phase payload and
calibration boundary are frozen in [`IMPEDANCE_V1.md`](IMPEDANCE_V1.md). It is
mutually exclusive with Neural acquisition and is never a continuous measurement.

## CTRL frame

CTRL is an independent Pod-to-Headstage 20 Mbaud Manchester link. Logical zero is
encoded as chips `01`; logical one is encoded as `10`.
Bytes are serialized most-significant bit first; 20 Mbaud is the chip rate and therefore
the uncoded logical bit rate is 10 Mbit/s.

```text
55 55 55 55 D5 | version:u8 | opcode:u8 | flags:u16 | sequence:u32 |
payload_length:u16 | reserved:u16 | payload | CRC16-CCITT:u16 big-endian
```

CRC16-CCITT uses polynomial `0x1021`, initial value `0xFFFF`, no reflection, and no
final XOR over the 12-byte header plus payload. ACK is returned as a DHL ACK packet on
DATA; CTRL has no reverse electrical lane.

The DHL ACK payload is exactly 8 bytes, little-endian: the originating CTRL
`sequence:u32`, `opcode:u8`, `status:u8`, and `reserved:u16=0`. Status values are
OK=0, BAD_LENGTH=1, UNSUPPORTED=2 and NOT_READY=3. Receiving a valid CTRL frame is
not itself success: the command result becomes committed only when this ACK packet is
accepted on DATA.

The callable v1 command surface is high-level and capability-gated:

| Opcode | Command |
|---:|---|
| `0x60` | `QUERY_INVENTORY` |
| `0x61` | `GET_STATUS` |
| `0x70/71/72` | `NEURAL_CONFIG/START/STOP` |
| `0x73` | `ELECTRODE_IMPEDANCE_SCAN` (zero payload, pre-recording only) |
| `0x78/79/7A` | `IMU_CONFIG/START/STOP` |
| `0x80/81/82/83` | `CHEM_CONFIG_AMPEROMETRY/CHEM_CONFIG_FSCV/CHEM_START/CHEM_STOP` |

The Pod/Host shall expose only commands supported by a detected-ready Inventory entry.
Arbitrary remote register reads/writes are not part of DHL v1.

## Clock-domain boundary

The Pod accepts decoded DATA in the recovered SerDes clock domain, validates symbol
framing and CRC there, and crosses complete packet records through an asynchronous FIFO
into a system-side domain that may later feed FT601. USB arrival time is never a sample
timestamp.

The portable Receiver-Pod boundary captures a packet speculatively and makes no byte
visible to the next clock domain until header, ordering, CRC32C and EOP checks all pass.
It exports accepted bytes as `data[31:0]`, `byte_enable[3:0]`, SOP and LAST. A malformed
stream, PCS error, post-lock link loss or capacity failure latches the transport epoch
fault; the two clock domains must be reset together before another packet is admitted.
The implementation latches the first RX fault code, reports one drop for the first
failed in-flight packet, rejects any packet after u64 sequence MAX without wrapping,
and keeps RX committed and SYS delivered packet counts distinct. Its first RX fault
code is transferred as a stable SYS-domain snapshot. Targeted evidence is guard 7/7,
CDC 18/18 and FIFO 1/1; the CDC Yosys result is 19 DP16KD, 1670 LUT4, 1737
TRELLIS_FF, 347 CCU2C, 214 PFUMX and 0 problems.
This boundary begins after PCS decoding and therefore does not itself prove the ECP5UM
receiver PCS, pin constraints, routed timing or physical link.

The portable SYS structural parser reparses the 40-byte header, enforces low-lane byte
enables plus exact SOP/LAST length, presents stable metadata before payload, and strips
the already-verified four CRC bytes. It does not reinterpret type-specific payloads or
recalculate CRC32C. Epoch reset/transport controls that are not exactly zero close all
ready/valid boundaries, and accepted X/Z words fault without packet-state side effects.
Its targeted result is 10/10; generic ECP5 synthesis reports 606 LUT4, 690 TRELLIS_FF,
28 CCU2C, 27 PFUMX and 0 problems. A separate 15/15 Arm-context
bank atomically freezes nonzero Run/Pod/Headstage identity, layout, expected hashes,
rate, channel count and the canonical sorted 1..16 component-instance set. Exact replay
is idempotent, quiescent Disarm retains replay identity, and only the authoritative
transport-epoch reset clears it. Generic ECP5 synthesis reports 4,475 LUT4, 1,915 FF,
136 CCU2C, 130 PFUMX and zero problems.

A separate registered phase dispatcher freezes each packet's startup/runtime target.
Before startup completion it accepts only Descriptor and Inventory; after exact
complete/admitted/armed authority it routes types 2 through 10 to runtime and rejects a
repeated Descriptor. Metadata and payload backpressure cannot retarget, duplicate or
expose a held first byte, and exact count/LAST/done plus epoch/input X/Z behavior pass
15/15 focused tests. Generic ECP5 synthesis reports 430 LUT4, 321 FF, 22 CCU2C, 8
PFUMX and zero problems. It does not yet parse runtime payload semantics or constitute a
Receiver-Pod product attachment.

The portable runtime Neural semantic parser accepts type 2 only under exact frozen
running/channel context. It validates zero flags, the 16-byte prefix, exact outer length,
the 1-MiB ceiling, signed little-endian int16 sample-major ordering, LAST/done structure
and cross-packet sample-counter continuity, then emits stable packet metadata and indexed
samples under ready/valid backpressure. A legal packet done may pend behind the final
sample because the structural parser can finish the trailing CRC independently; continuity
commits only after both done and final-sample handshakes. A retained packet sequence and
exclusive-end commit transaction then blocks following metadata until consumed; it is not
rollback authority. Its focused result is 24/24 with strict single-file lint clean. Generic
ECP5 synthesis reports 775 LUT4, 480 FF, 164 CCU2C, 43 PFUMX, 1 MULT18X18D and zero problems. It is not attached to the dispatcher or product
top and does not implement rational timestamp mapping, cross-packet 1-ms aggregation,
Stop-tail ordering, replay or FT601 scheduling.

The separate portable Neural blockizer implements the bounded aggregation part of this
contract for the default Rev-A product instance: 30 rows, 128 channels and two 4096 x
16-bit EBR banks. Context admission requires the exact rational-rate identity
`rate_num = 1000 * rate_den * target_rows`. It preserves sample-counter order while a
packet spans blocks or a block spans packets. Stop blocks new packet metadata immediately,
finishes the accepted packet, drains every full block and then one nonempty unpadded tail;
its quiescent output is not a CTRL ACK. Focused evidence is 12/12 top-level tests with 65
assertion-bearing subcases, strict combined lint is clean, and generic ECP5 synthesis is
8 DP16KD, 4 MULT18X18D, 4,120 LUT4, 1,643 FF, 621 CCU2C and 689 PFUMX with zero
problems. This block remains unattached and does not implement rational nanosecond mapping,
canonical encoding, persistent record sequence, replay, FT601 or product-top behavior.

The standalone rational Neural time guard implements the one-transport-epoch `(C0,T0)`
anchor, exact floor mapping, strict `<40 ns` later-packet timestamp check and widened
overflow rejection. It commits the first anchor only on downstream metadata acceptance,
gates samples until metadata admission and permits independent counter queries while the
sample proxy is open. Stop/Start and idle interval reset preserve the anchor; authoritative
epoch reset clears it. Focused evidence is 21/21 with strict unified lint clean. Generic
ECP5 synthesis reports 1,315 LUT4, 1,044 FF, 254 CCU2C, 143 PFUMX and 4
MULT18X18D with zero problems. Its sample packet-LAST is not the parser's retained
CRC-atomic completion, and parser/blockizer/adapter/product attachment remains open.

The standalone block-to-canonical adapter freezes the Arm identity/layout/rate context,
queries that same rational guard for a block's start and exclusive end, and emits complete
builder metadata plus signed sample-major data without treating the first-packet timestamp
as canonical time. Its 23/23 focused tests include all builder fields, backpressure, every
context mutation, stale/unsolicited results, valid/data X/Z and same-cycle rejection of a
known end time below the start. Generic ECP5 synthesis reports 1,787 LUT4, 826 FF, 227
CCU2C, 50 PFUMX and 10 MULT18X18D with zero problems. It remains unattached to the parser,
time guard, blockizer, canonical builder, replay store and product top.

Portable startup-validation components now compute exact SHA-256 over the raw payload,
retain actual and Arm-expected digests across either arrival order, and fail closed on
zero, mismatch, mutation or epoch fault. Focused results are SHA core 5/5, startup
hasher 4/4 and hash-match gate 5/5. Generic ECP5 synthesis reports respectively 4,355
LUT4/2,386 FF, 4,956 LUT4/3,236 FF and 1,790 LUT4/515 FF, each with zero check
problems. Separate one-pass semantic parsers validate the exact 96-byte Descriptor and
`76 + 32*n`-byte Inventory. Descriptor covers all thirteen decode tuples at 6/6 and
507 LUT4/787 FF/4 CCU2C/18 PFUMX; Inventory covers board profiles 1 through 8,
strict entry order/content and backpressure at 5/5 and 1,626 LUT4/997 FF/179
CCU2C/57 PFUMX, all with zero check problems. These parsers recognize the wire
catalog; they do not grant product admission.

`receiver_pod_startup_admission` now composes those blocks at the portable SYS seam.
It accepts only Descriptor type 1 followed by Inventory type 9, atomically fans every
payload byte to the SHA and matching semantic branch, preserves Inventory-entry and
summary backpressure, and latches the first upstream, routing, child or hash fault until
epoch reset. Type 5 remains Stim Event and is explicitly rejected in the Inventory slot.
The wrapper blanks `admitted_o` in the same cycle as a post-admission upstream or
terminal-protocol fault. Its focused result is 6/6; generic ECP5 synthesis reports 9,021
LUT4, 5,551 TRELLIS_FF, 609 CCU2C, 344 PFUMX, 3 L6MUX21 and zero check problems.

A portable component pipeline connects that wrapper to committed SYS parsing, the epoch
guard, registered Arm bank and a terminal Descriptor/Inventory/Arm/exact-instance guard.
The guard passes 8/8; the pipeline passes 6/6, including transport 1/X/Z same-cycle
withdrawal and quiescent Disarm. Unified generic synthesis reports 17,546 LUT4, 9,270
TRELLIS_FF, 818 CCU2C, 825 PFUMX, 25 L6MUX21 and zero check problems. This remains a
component seam and is not the Receiver-Pod physical top.

The Pod maps a Neural first-sample timestamp to nanoseconds using the 25 MHz timebase,
validates Descriptor plus Inventory and channel/rate contracts, and then creates the existing Forge Host
`SampleBlockV1` and canonical record envelope. DHL bytes are never persisted directly as
a replacement for the Host contract. The portable canonical builder is record-atomic
in EBR and emits the exact 176-byte `CanonicalRecordEnvelopeV1` header plus 32-byte
`SampleBlockV1` header, CRC32C, 32-bit words with byte enables, SOP and LAST. Under
`DEC-RTL-010` it formats an explicit external `record_sequence_i`; it neither allocates
nor advances the per-Run sequence. Exact abort discards only a prefix that has not reached
`record_built_o`; a built record remains immutable and drains to `record_transferred_o`.
Five variants execute 17 tests with 58 filter-only skips. Generic ECP5 synthesis of the
default 256-channel formatter reports 8 DP16KD, 2 MULT18X18D, 3153 LUT4, 1358 FF,
306 CCU2C, 306 PFUMX and 0 problems. It rejects insufficient EBR or a configured Host
payload above 1 MiB and prevents invalid/X/Z control or data from creating unproven
RAM/CRC/counter side effects. An explicit 128-channel/30-row/11-bit-address generic
probe reports 4 DP16KD, 2 MULT18X18D, 3152 LUT4, 1356 FF, 305 CCU2C and 325 PFUMX
with 0 problems; it is not an exact-device fit. These are seam/reference results only: product attachment
of the startup pipeline and standalone Neural parser/time guard, 1-ms aggregator-to-
builder integration, external sequence owner, committed replay store, Host eviction ACK,
FT601 scheduler, ECP5UM PCS/physical top and product integration remain outside this contract.
