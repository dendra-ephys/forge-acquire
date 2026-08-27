# Forge Acquire GUI architecture

Status: control-plane design and mock-adapter contract. This document is not daemon,
hardware, HIL, endurance, NWB-publication, or product-release evidence.

## Product intent

Forge Acquire is a single-workspace acquisition instrument for a neuroscientist operating
one to eight Receiver Pods for runs lasting up to 24 hours. The visual language is **Bench
Instrument / 实验台精密仪器**:

- state, evidence, and the next safe action take priority over decoration;
- neutral instrument surfaces carry structure; blue identifies ordinary control, amber
  means attention or qualification, and red is reserved for faults and destructive action;
- controls keep visible verb labels and large hit areas suitable for gloves and time pressure;
- system figures use tabular numerals; status never depends on color alone;
- no marketing metrics, card-grid dashboard, glassmorphism, broad gradients, decorative
  animation, or network font dependency;
- one signature interaction, **Recording save status**, gives a plain-language overall verdict
  while keeping raw Recording closure separate from downstream outputs and optional events.

The UI is a control plane. It may summarize evidence, but it may not infer a capability,
invent a successful transition, or promote an unavailable function.

## Single-workspace information architecture

The application has one acquisition workspace rather than route-level operating screens.
Settings and diagnostics are progressive disclosure, never replacements for the live Run.

| Region | Responsibility |
|---|---|
| Top command bar | Source identity, daemon freshness, current lifecycle phase, Run clock, and the next valid acquisition action |
| Left device list | Independently collapsible devices grouped by Direct-to-PC or expandable Aggregator paths; display name, immutable ID, Preview selection, and REC membership remain distinct |
| Central preview | Primary and largest working surface: stable Wideband/LFP/Spikes views using bounded eight-channel banks, clickable full-Pod Spike channel activity, and selected-channel waveform summaries |
| Diagnostics | Independently collapsible fault/recovery details; compact by default and never a replacement for visible fault state |
| Right control column | Independently collapsible Connect, Preview, Recording setup/Arm/Record/Stop/Finalize controls and current Run target; no stimulation control appears in this acquisition surface |
| Bottom Recording save status | Independently collapsible, compact by default; always answers whether raw Recording is safely sealed, with expanded required Recording, later-processing, and optional-event receipts |

Source-range continuity plus file durability/seal form the raw Recording closure. Stop alone is
never a safe-save verdict. NWB and Analysis are downstream outputs. External events are an
optional Run-bound timeline and do not grant stimulation authority. Each expanded slot shows
text, an icon, and receipt sequence/hash without inheriting success from another group. A mock
finalized receipt explicitly states that it created no real file.

Detailed hardware hashes, service fields, and long fault history belong in a collapsible
Diagnostics drawer. Current Preview and Recording controls remain visible without scrolling
through those details.

### Data-first collapse contract

The layout allocates surplus width and height to the signal display. The device list and Run
controls collapse independently, as do Diagnostics and Recording save status. Both are compact
on startup. `Signal Focus` collapses all four secondary regions
with one action; leaving it restores the exact independent collapse states that were active
before focus mode.

Collapse is local presentation state. It sends no `AcquireIntent`, changes no snapshot or
receipt, and must not reset the selected Pod, view, channel bank, channel, time window, or
bounded preview frame. The adapter boundary is therefore unchanged.

When Run controls are compact during recording, an explicit text-labelled `Stop Recording`
control remains visible. It detaches writer input while Preview remains live; it never means
data is durable, sealed, materialized, or safe to remove. Stimulation controls are absent.
Compact Recording save status retains a plain-language overall verdict, so no save state is
encoded by color alone.

## RHX interaction reference and Forge adaptation

The operating logic explicitly studies the official
[Intan RHX user guide](https://intantech.com/files/Intan_RHX_user_guide.pdf) and the
[Intan RHX repository](https://github.com/Intan-Technologies/Intan-RHX). RHX keeps Run,
Stop, Record, record time, sample rate, and hardware/software/CPU load indicators in a
stable toolbar; Record is disabled until a save target is selected; waveform time and
vertical scales remain beside the display; and stopped acquisition can still be reviewed
from a bounded RAM history. Its demonstration mode is also unmistakably synthetic.

Forge borrows those interaction principles, not RHX source code, assets, icons, branding,
or pixel layout. The RHX repository is GPL-3.0, so this implementation remains original.
The mapping is deliberate:

| RHX operating idea | Forge Acquire adaptation |
|---|---|
| Controller selection and demo mode | Adapter capability snapshot plus permanently labelled mock scope |
| Fixed Run/Stop/Record transport controls | Fixed Connect, Start/Stop Preview, Recording setup/Arm, Start/Stop Recording, and Finalize positions |
| Record disabled before filename/save preparation | Record disabled until adapter-authored Preflight and Recording Arm snapshots arrive |
| HW buffer, SW buffer, CPU load bars | Snapshot-authored Source FIFO, Writer Queue, and Control Load indicators; stale values are labelled stale |
| Record clock and fixed sample-rate readout | Run epoch/plan clock and Pod sample-rate fields, only when provided by snapshots |
| Time/vertical scale beside waveform | Explicit `显示时窗` 1/2/5 s requests and amplitude controls local to the bounded Canvas preview |
| Stop followed by RAM review | Stop Recording leaves live bounded Preview available while Forge separately waits for durability and seal |

Forge must go further than RHX where its independent daemon and derived-data contract
require it: a command acknowledgement is not a state transition, Preview is not Recording,
Stop is not safe storage, and the evidence groups remain independently evidenced.

### Device list and connection paths

The UI section is called a device list. Its adapter snapshot still carries a connection tree
because the PC has no universal numbered Pod bay. Every leaf receives an opaque `PodKey`,
an immutable device ID, an editable display name, and one explicit route:

```text
PC
├─ Direct USB 3
│  ├─ PodKey A
│  └─ PodKey B
└─ Aggregator (expandable)
   ├─ USB Host port 1 -> PodKey C
   └─ USB Host port 2 -> PodKey D
```

Run plans freeze each selected Pod key together with its immutable device ID, identity evidence
hash, neural-input evidence hash, and the connection-tree evidence hash. UI labels, USB numbers,
or Aggregator port numbers are never used to infer immutable identity. Mock rename receipts have
`mock_session` persistence only. Cross-PC naming requires device-side nonvolatile storage, CAS
revision, power-loss-safe commit, reconnect/power-cycle/cross-PC read-back, and matching device
receipts in a future adapter. A host cache can never be promoted to device identity. In this
round the Aggregator tree is a synthetic mock fixture for exercising the interaction; the
same parent row simultaneously says `SYNTHETIC PATH` and `HW UNAVAILABLE`. It does not
claim discovery, 10GbE streaming, synchronization, or hardware qualification.

## Evidence-driven lifecycle

Transport, Preview, Recording, writer, materialization, analysis, and external events are
orthogonal state domains. A concise operator phase may summarize them, but the underlying
states remain independently visible.

The recording lifecycle is deliberately fine-grained:

```text
Disconnected -> Connected / idle
Preview: stopped -> start requested -> live -> stop requested -> stopped
Recording:
  No Run
  -> Preflight running
  -> Preflight blocked | Preflight passed
  -> Recording arming
  -> Recording armed
  -> Starting
  -> Recording
  -> Stop requested
  -> Recording stopped (Preview may remain live)
  -> Draining
  -> Durability confirmed
  -> Sealing / Finalizing
  -> Finalized | Recovery required | Failed
```

Every forward transition requires a new adapter snapshot or command receipt. Button press,
elapsed animation time, a green Pod row, or a successful WebView callback is not evidence.
Unknown, stale, regressing, or contradictory snapshot state fails closed and exposes its
recovery path.

Preview is an adapter-authored session independent of Recording. `Freeze display` is local
WebView presentation state. Neither display freeze nor a bounded preview-frame replacement
changes Recording or Run evidence. Live Preview is required to enter Recording setup and
Preflight, but once that plan is accepted the operator may stop or restart Preview during Arm,
Recording, Stop, finalization, or failure handling. Those Preview commands never send a Run
Stop/Abort and never alter the Recording lifecycle.

### Recording Arm and external stimulation boundary

Recording Arm remains an explicit Recording control:

- Recording Arm binds the admitted source, Pods, Run/config identity, storage preflight,
  writer readiness, and a bounded Arm receipt before Record can be requested.
- The acquisition GUI exposes no Stimulation Arm command.
- A future external Python stimulation module needs a separately governed API and safety
  contract. This mock GUI neither defines nor qualifies that protocol.
- Optional external-event receipts may be displayed in the Run timeline, but an external
  report can never turn hardware stimulation capability green.

### Stop, safe, and GUI close

`Stop Recording` means that a Stop request was issued and, only after receipt, that the
writer no longer accepts new Run input. Preview may continue. It does **not** mean the Run is
safe.

```text
Stop receipt
  != journal drained
  != stable-media durability confirmed
  != journal sealed
  != NWB materialized/validated/published
```

While finalization is incomplete, the UI simultaneously states both truths, for example:
`Acquisition stopped` and `Data still draining; do not remove storage`. Only the applicable
daemon-authored durability/seal receipt may change that wording. NWB and publication remain
separate lanes after acquisition storage is safe.

Closing, minimizing, reloading, or losing the GUI must never be translated into Stop. During
an active or recovering Run, the UI says that the independent daemon owns acquisition and
that closing the window does not stop it. Any future external stimulation module owns its own
client-loss and safety policy; the acquisition GUI does not infer or synthesize such a transition.

`Recover` is shown only when the current adapter explicitly reports a recoverable fault. A
software recording-pipeline failure is not presented as recoverable: the available action is
`Acknowledge failure and close Run`, which requires an accepted daemon receipt in `New` state,
preserves the partial journal, creates no seal, and makes no claim that missing or uncommitted
data was repaired. A lost control pipe is not proof that the daemon failed and therefore cannot
authorize that acknowledgement. While a Run exists, pipe loss preserves the last known Run
lifecycle as stale, disables a fake manual Connect action, and waits for bounded automatic
snapshot polling to re-establish control.

Explicit `Disconnect` is disabled and rejected after a Recording setup has opened a Run
context, until that Run is finalized or its failure is acknowledged. This preserves the
operator's Stop/Finalize command path while the independent daemon may still be writing. It
does not change the window-close rule: closing the GUI still sends no implicit Stop command.

## Adapter boundary

Page components depend only on normalized TypeScript snapshots and receipts. They do not
import Tauri APIs, named-pipe framing, Rust command names, or transport-specific error codes.

The implemented boundary is:

```ts
interface AcquireAdapter {
  readonly adapterId: string;
  readonly scope: "mock" | "software" | "hardware";
  readonly previewSource: PreviewSource;
  readCapabilities(): Promise<CapabilitySnapshot>;
  readSnapshot(): Promise<DaemonSnapshot>;
  subscribeSnapshots(listener: (snapshot: DaemonSnapshot) => void): () => void;
  execute(intent: AcquireIntent): Promise<CommandReceipt>;
  renameDevice(request: RenameDeviceRequest): Promise<DeviceNameReceipt>;
  dispose(): void;
}

interface PreviewSource {
  readonly maxFramesPerSecond: number;
  setRequest(request: PreviewRequest): void;
  getLatest(): PreviewFrame | null;
  subscribe(listener: (frame: PreviewFrame) => void): () => void;
}

interface MockFaultController {
  inject(fault: MockFault): Promise<void>;
  clear(code: FaultCode): Promise<void>;
}
```

`DaemonSnapshot` carries capability scope, Preview state, Recording lifecycle, device
identity, target reservation, grouped evidence, faults, and freshness with monotonic
identity. Receipts carry the command
identity and resulting evidence; command resolution alone does not mutate the visible state.

`createAcquireRuntime()` is the composition root: React receives `AcquireAdapter`, while the
mock-only diagnostics port remains separate. A future named-pipe runtime is selected there,
not inside page components.

Device naming is a separate adapter operation because it is not a Run transition. The mock
uses an in-memory compare-and-swap revision and returns `mock_session`; it cannot claim that
the name follows hardware to another PC. A production `device_nonvolatile` result requires
immutable identity evidence, device write acknowledgement, a committed name-record hash,
power-loss qualification, and a matching read-back receipt after reconnect on another host.

The Recording target request contains a root, name prefix,
`create_new_incrementing_suffix`, and `overwritePolicy=forbid`. Preflight returns the
adapter-authored final Run directory, sequence, canonical `run.forgewal` name, and receipt
hash. The mock returns `directoryCreateDisposition=simulated`, allocates only a name in memory,
and writes no file. A real daemon may return `created_new` only after atomically creating both
the directory and journal with create-new semantics and revalidating volume/path identity;
the React path string is never storage evidence.

The mock implementation may exercise all UI states deterministically. `MockFaultController`
is mock-only, is visually labelled `SIMULATOR / TEST ONLY`, and is never exposed by the future
production adapter. Fault controls live in a separate test drawer and cannot be confused with
Run controls.

A future Tauri named-pipe adapter may implement `AcquireAdapter` internally, but replacing
the adapter must not change page components. The named-pipe implementation is responsible
for authentication, framing, monotonicity, freshness, retries, and translation of daemon
receipts into the normalized model.

## WebView data boundary

Raw neural samples, acquisition queues, integrity accounting, and durable writers remain in
the independent Rust data plane. Raw sample bytes in the WebView budget are exactly zero.

Every `PodSnapshot` carries one receipt-authored `HeadstageInputSnapshot`. Profile identity,
neural channel count, per-channel sample rate, source encoding, amplitude unit, and evidence
hash therefore come from the adapter rather than a UI hardware catalogue. The default mock
receipt is `MOCK-RHD2132X1-32CH-30K`: a 32-channel, 30 kS/s/channel synthetic shape, not a
physical descriptor or Inventory receipt. It is labelled `SYNTHETIC µV`; a future hardware
adapter without scale evidence must return `ADC counts` and a null volts-per-count scale.

Signal type and display encoding are separate concepts:

- **Wideband** may receive production `min_max_envelope_v1` only when every bucket is fully
  aggregated in the data plane. The current mock instead emits
  `sampled_extrema_preview_v1`; its three representative probes plus known fixture-spike
  support are deliberately not described as complete bucket min/max.
- **LFP** production data also requires a bounded envelope plus backend-authored filter
  profile, configuration hash, passband, output rate, and delay. The current mock does not
  claim a filter ran: it displays the frozen 8 Hz truth component of the shared synthetic
  formula as `MOCK TRUTH`.
- **Spikes** receives `spike_preview_v2`: full-Pod per-channel activity, a bounded raster for
  the requested eight-channel bank, and one selected-channel mean/p10/p90 waveform summary.
  It does not send per-event raw snippets, and events remain `UNSORTED` unless a qualified
  receipt says otherwise.

Spike accounting exposes full-Pod events, current-bank events, raster events actually drawn,
and events intentionally omitted from the picture. Separate `SOURCE COVERAGE` and
`ANALYSIS COVERAGE` states must both be complete for those counts to be valid. A gap is
reported by exact source-sample ranges and latches a fault; the UI does not offer
`DETECTOR LOST = N` because an unprocessed range cannot reveal how many biological events
were missed. The mock uses `channel_stratified_rotating_v1`, not a low-channel-biased
`slice(0, N)`. Wideband and LFP also request explicit eight-channel banks, so a four-row
preview can never imply that a Pod has only four inputs.

The current repository contains a deterministic composite Rust source and Python
threshold/template/windowed-LFP reference algorithms. The streaming detector and LFP
accumulator latch a hard error on any unexpected sample boundary and require explicit reset.
They are not a production real-time preview worker and are not scientifically validated. The
GUI therefore exposes only synthetic versions in this round. A future real path must run in
the daemon/worker data plane and feed an ordered bounded preview channel; React never
performs filtering, spike detection, or sorting.

The present mock has an explicit Preview session before Recording. `Connect` does not
silently start it. `start_preview` and `stop_preview` have independent request/snapshot
states; Preview frames carry no Run identity outside a source-confirmed Recording capture
window. Starting Recording leaves
Preview live, and Stop Recording does not stop it.

The preview retains only the requested visible window and may replace an obsolete queued
picture with the newest complete picture. Presentation freshness is shown as a state, never
as permission to lose source or analysis coverage. React receives immutable low-rate status
and selected-channel summaries; DOM size is independent of sample count and Run duration.

## Capability presentation matrix

This matrix describes what the GUI may claim in this mock-adapter round. Repository software
work outside the GUI does not silently upgrade these rows.

| Capability | GUI presentation in this round | Claim boundary |
|---|---|---|
| Deterministic mock, 1–8 synthetic Pods | Available, permanently labelled `SIMULATOR` | UI and mock-interaction evidence only; no neural hardware data |
| Mock lifecycle/receipts/fault injection | Available, labelled `TEST ONLY` | Does not qualify the daemon, storage, hardware, or release path |
| Mock device rename | Available, labelled `MOCK SESSION` | In-memory CAS/read-back only; not device NVM or cross-PC persistence |
| Mock Run target name allocation | Available, labelled `MOCK NAME ALLOCATED / NO FILE CREATED` | In-memory sequence only; creates no directory or journal file |
| Mock Wideband/LFP/Spike preview | Available, labelled `MOCK`, `MOCK TRUTH`, or `MOCK ORACLE` | Synthetic envelope/raster/waveform-summary interaction only; no production extractor or scientific-validity claim |
| Tauri named-pipe daemon adapter | Not connected in this round | Future replacement behind `AcquireAdapter`; no real-daemon claim |
| Protected replay | `QUALIFICATION REQUIRED` unless a fresh adapter receipt explicitly reports it | Low-rate replay is not D3XX, endurance, or hardware evidence |
| Direct FT601/D3XX Pod acquisition | `UNAVAILABLE` / `QUALIFICATION REQUIRED` | No approved production receipt, qualified device/ABI/HIL, or product integration |
| Aggregator / 10GbE / 1–8 real-Pod aggregation | `UNAVAILABLE` | Discovery, control, stream, global time, recovery, and HIL remain open |
| Real cross-Pod synchronization | `QUALIFICATION REQUIRED` | Never inferred from Pod count or mock clock alignment |
| RHS stimulation | Not controlled by this acquisition GUI; capability remains `UNAVAILABLE` | External Python/module interface is not designed or qualified in this round |
| Closed-loop control | `UNAVAILABLE` | Reference algorithms or mock workers are not scientific or hardware validation |
| NWB lane | `QUALIFICATION REQUIRED`; real adapter receipt not connected in this round | GUI state is not materialization, validation, publication, or release evidence |
| Online analysis lane | `UNAVAILABLE` unless a fresh worker receipt reports otherwise | No scientific-validity claim |
| 24-hour acquisition/product release | `QUALIFICATION REQUIRED` | Frontend tests, screenshots, short runs, or journal-only evidence cannot pass it |

## Keyboard, accessibility, and minimum-window contract

- Minimum supported workspace is 1080 × 720 with no document-level horizontal scroll.
- At 1080 px, source, Preview, phase, Record/Stop text, recovery action, and grouped evidence
  remain available. Secondary diagnostics collapse before critical labels do.
- Critical controls provide at least a 44 × 44 px hit area with at least 8 px separation.
- `Tab` order follows top command bar -> device list -> preview -> right controls -> Run evidence
  details; `F6` may cycle these major regions.
- Enter/Space activates focused controls. `Escape` closes non-destructive dialogs and restores
  focus.
- Left/Right/Home/End move among the Wideband/LFP/Spikes tabs; Up/Down/Home/End select a
  visible channel inside the active Canvas. Separate 44 px bank controls expose later
  channels without changing acquisition or the Headstage sample rate.
- No global single-key shortcut may Arm, Record, Stop, inject a fault, or acknowledge data
  loss. Destructive actions require a visibly focused control and explicit consequence text.
- Focus rings remain visible. Dialogs trap and restore focus. Persistent faults use an
  appropriate live region and never disappear only because a toast timer elapsed.
- State includes icon and text, not color alone. Normal text meets 4.5:1 contrast; status
  graphics and focus indicators meet 3:1. Windows scaling is checked at 100%, 125%, 150%,
  and 200%.

## Startup and long-run performance budget

The normative budgets remain in `PERFORMANCE_BUDGET.md`:

- no network request or runtime font download is needed to render the shell;
- first meaningful instrument shell target is under 500 ms after WebView warm-up on the
  reference acquisition PC;
- initial production bundle budgets are 100 kB gzip JavaScript and 10 kB gzip CSS;
- machine/status and health updates are 5 Hz normally and 10 Hz maximum;
- display envelopes are at most 30 frames/s; React commits outside the trace surface are at
  most 10/s while streaming;
- raw WebView sample bytes and unbounded UI arrays/queues are both zero;
- the 30-minute display gate requires bounded memory and no long task above 50 ms at p99;
- an eventual 24-hour mock soak must show bounded retained histories and no Run-duration-
  proportional DOM, timer, listener, or heap growth.

The presentation lane may coalesce an obsolete queued picture into the newest complete
picture, but it does not report that as tolerated data loss. If the WebView cannot present a
current picture it becomes `STALE`. Source and analysis coverage remain independent hard
states; any sample counter gap latches Run failure with exact boundaries.

## Delivery evidence layers

Each handoff reports these layers independently:

1. **Visual prototype complete** — source, responsive screenshots, focus/contrast review,
   and visual QA for required states.
2. **Mock interaction complete** — deterministic adapter tests cover the lifecycle, receipts,
   one-to-eight Pod states, failure injection, recovery, and stale/contradictory snapshots.
3. **Real daemon connected** — requires fresh evidence from the production adapter boundary;
   this mock round does not provide it.
4. **Hardware verified** — requires fresh D3XX/Pod/Aggregator/RHS/HIL evidence; frontend checks
   do not provide it.
5. **Release gates passed** — requires the governed endurance, storage, NWB, hardware, fault,
   and product-release receipts; this document and the mock GUI do not provide them.

`npm test`, `npm run build`, `npm run check:bundle`, and `npm run visual:qa` are frontend
engineering evidence only. Passing them may establish layers 1–2 when their artifacts and
coverage support the claim; it cannot establish layers 3–5.
