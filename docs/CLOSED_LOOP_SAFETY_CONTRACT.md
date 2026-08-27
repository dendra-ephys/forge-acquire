# Forge Acquire closed-loop safety contract

Status: host-side contract and fail-closed UI guard; no animal-stimulation release evidence  
First potentially representable profile: `CL-RHS2116X1-01` — one RHS2116×1 Headstage, one Receiver Pod, direct FT601/D3XX path

## Capability boundary

The active Headstage matrix defines ten product identities. RHD and RHS coexist only
in the explicit mixed profiles 7 and 8; no implicit family mixture is admitted:

| Profile | Acquisition channels | Physical stimulation channels | Host stimulation status |
|---|---:|---:|---|
| `rhd2132x1` | 32 | 0 | unavailable |
| `rhd2132x2` | 64 | 0 | decode-only compatibility |
| `rhd2164x1` | 64 | 0 | unavailable |
| `rhd2164x2` | 128 | 0 | unavailable |
| `rhs2116x1` | 16 | 16 | representable by M0 v1, still hard-disabled |
| `rhs2116x2` | 32 | 32 | acquisition profile only until capability v2 |
| `rhd2132x1_rhs2116x1` | 48 | 16 | unavailable pending mixed Host/capability contract |
| `rhd2164x1_rhs2116x1` | 80 | 16 | unavailable pending mixed Host/capability contract |

`DeviceCapabilitiesV1` intentionally admits exactly 16 RHS stimulation
channels. Therefore `rhs2116x2` must not lie by advertising 16; its stimulation
capability remains unavailable until a versioned capability contract supports
32 and passes its own safety review. A model name never grants stimulation
permission.

The current Receiver Pod uses CABLINE Rev A and an FT601 32-bit D3XX uplink.
The production Pod FPGA DHL-to-Host/CTRL/ACK path, physical ENABLE, emergency
stop, independently proven watchdog behavior, compliance readback, approved
Safety Profile and HIL evidence are incomplete. Production stimulation is
therefore hard-disabled.

## Four isolation boundaries

1. Tauri/React is a control surface. It never schedules a pulse and never owns acquisition or stimulation lifecycle.
2. `forge-acqd` owns acquisition truth, hardware communication, Run continuity and the authoritative Rust SafetyArbiter. The current replay/dummy-load foundation hashes fixed templates, validates the profile/capability/token contract, allows one outstanding command, rejects duplicate nonces and late intents, validates receipts and fault-latches on runtime-health loss. There is still no authenticated controller/arbiter production boundary, persistent nonce ledger, active hardware communication or qualified physical executor.
3. C++ and Python workers receive independent bounded sample rings. They may emit only `StimIntentV1`; they cannot write RHS registers or construct arbitrary current waveforms.
4. The future Headstage FPGA safety engine owns the final boundary: fixed reviewed biphasic templates, hard limits, deduplication, deadline rejection, hardware-time execution, compliance checks and forced disable on any safety fault.

Only one authenticated worker may hold the controller token for an arm epoch.
Changing the algorithm build/config, channel map, template set or Safety Profile
invalidates the epoch and requires explicit disarm then re-arm.

## Evidence required before an Arm request

The control plane may ask the SafetyArbiter to arm only when all fields are
independently reported and mutually hash-bound:

- an active, integrity-clean streaming Run;
- an admitted `rhs2116x1` Descriptor and matching 16-channel capability hash;
- an approved `SafetyProfileV1` hash plus approval identifier;
- frozen template-set, channel-map and algorithm build/config hashes;
- exactly one authenticated controller-token owner;
- independently proven Pod and Headstage safety barriers, physical ENABLE,
  emergency stop and watchdogs;
- healthy compliance preflight and positive hardware-time deadline budget;
- closed-loop qualification receipts for both direct and Aggregator paths.

The React helper `evaluateStimArmRequest` is only a request preflight. A passing
result never sets `armed`. The UI may display `armed` only after a matching
daemon/hardware receipt names the arm epoch and every frozen hash.

## Forced-disarm conditions

Acquisition continues, but stimulation must immediately enter a latched
disarmed/fault state after GUI/control-session loss, worker loss or overflow,
CABLINE/USB/Ethernet loss, reset, protocol mismatch, sample/frame gap, CRC or
overflow fault, synchronization loss, deadline miss, duplicate nonce, unknown
template, out-of-range target, missing receipt, compliance failure, either
safety barrier/watchdog failure, emergency stop, physical ENABLE open or any
mutation of the frozen arm context.

A late command is rejected before execution. It is never converted into a late
pulse. Hardware execution without one unique matching receipt is a
release-blocking fault even if acquisition data remains valid.

## Physical latency definitions

- Spike: newest source sample hardware time to dummy-load shunt current crossing 10% of target; release target p99 ≤20 ms.
- LFP: final hardware sample in the analysis window to analysis event ≤100 ms; if it triggers stimulation, physical 10% current crossing must also be ≤100 ms.

Software timestamps, USB arrival time and GUI animation cannot close these
gates. Both direct and Aggregator paths require instrumented physical evidence.

## Real-animal prohibition

RHS2116 electrical capability does not define an electrode-tissue safety
window. Real-animal stimulation remains prohibited until electrode material,
wire diameter, exposed geometry/area, surface condition, impedance, current,
phase width, interphase interval, frequency, train, duty cycle, per-phase
charge, charge density, compliance and recovery are reviewed in an approved
Safety Profile. Until then, only simulator, protocol fuzzing, resistive dummy
loads and controlled HIL are allowed.
