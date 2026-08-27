# Forge Acquire interaction contract

## Operator path

The normal path must remain visible without opening settings:

1. choose a device and connect;
2. explicitly start a low-rate derived Preview and inspect signals;
3. choose `Single-device recording` (freezes the current Preview Pod) or
   `Multi-device recording` (explicitly select 2–8 Pods), then set the Run root,
   name prefix, and planned duration;
4. run recording preflight and receive an adapter-authored target allocation receipt;
5. request and receive an independent Recording Arm receipt;
6. attach the writer with `Start Recording`;
7. use `Stop Recording` without stopping Preview;
8. stop Preview separately when it is no longer needed;
9. wait for the daemon's durability and seal receipts before declaring the journal safe;
10. use Finalize only to close the GUI Run workflow or start optional derived outputs.

Preview and Recording are orthogonal adapter states. Preview never creates a Run or writes a
file. A live Preview is required only when the operator enters Recording setup and submits
Preflight, so the intended source can be inspected and frozen into the admitted plan. After
Preflight is accepted, Preview may be stopped or restarted independently and does not gate
Recording Arm, Start Recording, an active Recording, Stop, or failure acknowledgement. The
bounded mock waveform is not the source written to disk: an independent Rust process writes a
separate deterministic canonical SampleBlock stream. The browser QA adapter remains fully mock.
Freezing the display is a third, WebView-only action that sends no adapter command.

Preflight is recording admission, not a generic hardware qualification screen. It verifies the
adapter/evidence scope, a live Preview, the explicitly selected Recording device set, immutable
identity and neural-input receipts, an absolute safe root/name request,
create-new/forbid-overwrite policy, and the subsequent adapter snapshot. In Tauri software
scope it launches a current-user-authenticated independent Rust process, atomically reserves
the numbered Run directory, and creates `run.forgewal` during accepted Prepare. In browser
mock scope it allocates a display name only and creates no disk object. Neither path pretends
to measure qualified free-space endurance or open FT601/Aggregator hardware. Preflight does
not begin sample generation. Recording Arm remains a separate writer interlock and is unrelated
to stimulation.

Before recording can be reported as active, the control model passes through writer opening, writer armed, and source-confirmed states. The UI may animate those transitions quickly in the simulator, but the production backend cannot skip them.

## State separation

The UI must never collapse these into one green/red lamp:

- transport connection;
- acquisition state;
- writer state;
- run integrity;
- hardware synchronization;
- per-device health.

Stopping acquisition is not equivalent to saving successfully. The acquisition truth source is safe only after the journal is drained, durability-confirmed, and sealed. The final NWB is complete only after close, schema/semantic validation, counter reconciliation, and publication receipt. CRC errors, counter gaps, or any data-path overflow latch the current Run as failed and block ordinary Finalize.

The signature component is **Recording save status**, not a generic health dashboard or a
serial progress arrow. Its compact verdict directly states whether the current Recording is
not started, recording but unsealed, stopped but not safely sealed, finalizing, safely sealed,
or recovery-required. The expanded **Required raw recording** group contains source-range
continuity and file durability/seal; both are required to close a Recording. **Later
processing** contains NWB and Analysis and may lag or remain unqualified without changing
raw-journal truth. **Optional external events** is a read-only event-receipt summary. It grants
no stimulation capability and is not a Stimulation Arm. An unavailable slot stays neutral and
never inherits green state from another group. `synthetic` describes the signal source, not the
storage disposition: only `created_new` directory/journal receipts plus acquisition and seal
evidence may support a real-file safe verdict. Browser mock receipts must still say that no real
file was created.

The fixed transport controls borrow interaction principles from the official Intan RHX user
guide: keep Preview/Record/Stop positions stable, disable Record until save preparation is
complete, keep load indicators and scale controls near the waveform, and keep synthetic
demonstration mode explicit. Forge does not copy RHX source, assets, or pixel layout. Forge
additionally requires Recording Arm, daemon independence, Stop-versus-safe separation, and
grouped receipt evidence.

The React/Tauri surface is a control plane. The independent Rust data plane owns transport ingest and the acquisition journal; the NWB materializer is restartable and may lag without backpressuring acquisition. Raw samples never enter React state.

## Data-first collapsible workspace

The signal display is the primary and largest working surface. The device list and Run controls
collapse independently; Diagnostics and Recording save status also collapse.
Diagnostics and Recording save status start compact so the waveform/raster surface receives the
available height without hiding the normal Connect-to-Finalize path.

`Signal Focus` is a view-only shortcut: it collapses all four secondary regions together and
restores their prior independent collapse states when exited. Collapsing a region sends no
adapter command, changes no acquisition state, and must not reset the selected Pod, signal
mode, channel bank, channel, time window, or latest bounded preview frame.

During recording, the compact Run-control rail keeps one explicit text action,
`Stop Recording`, visible. It stops writer input but leaves Preview live and does not mean the
journal is durable, sealed, or safe to remove. Stimulation controls do not appear in the
acquisition GUI. A future external Python stimulation module needs its own governed interface;
the acquisition surface may only display optional Run-bound event receipts. Compact Recording
save status retains a plain-language overall verdict; color alone never carries meaning.

## Device list, identity, and signal views

The left rail is a device list with connection-path grouping, not a panel titled “topology”.
Direct USB 3 Pods are listed under the PC; Pods attached through an optional Aggregator are
children of that Aggregator and carry its port number. Every leaf separates an adapter-authored
immutable device ID, an opaque route/selection `PodKey`, and an editable display name. The
mock rename receipt is explicitly `mock_session`; it does not claim that the name follows the
hardware to another PC. Real cross-PC naming requires a device-side nonvolatile write,
revision/CAS, power-loss-safe commit, and reconnect/power-cycle/cross-PC read-back receipts
behind the future adapter. The device list keeps a visible `MOCK NAME`, `THIS PC ONLY`, or
qualified `DEVICE NVM` scope beside the name. Each leaf also carries a
`HeadstageInputSnapshot`; channel count, per-channel
sample rate, source encoding, value unit, and profile label are therefore receipt-authored
facts rather than UI catalogue guesses. Preflight freezes each route key with its immutable
device ID, identity evidence, input evidence, and topology evidence hash so two different
`port 1` labels cannot collide or be rebound after a topology change. The mock Aggregator is always marked
`SYNTHETIC PATH / HW UNAVAILABLE`.

The operator selects a Run root and name prefix, not a journal filename. Preflight asks the
adapter/data plane to allocate a final Run directory name with
`create_new_incrementing_suffix + overwritePolicy=forbid`; the directory contains the
canonical `run.forgewal` and later sidecars/derived outputs. The mock returns
`FORGE-RUN-001`, `-002`, and so on in session order with `simulated` create dispositions, but
creates no disk object. The Tauri software adapter now asks the independent Rust process to
atomically create `FORGE-RUN-001`, `-002`, and so on and returns `created_new` receipts; Stop
drains, applies the durability barrier, and seals the WAL before returning a sealed snapshot.
This is real software-file evidence for a synthetic stream, not hardware acquisition evidence.
A temporarily full software replay queue applies bounded producer backpressure. It does not
drop a record, skip a sample range, truncate a multi-Pod round, or grow memory without bound.
Only a real producer, consumer, journal, or durability error fails the Run closed; such a Run
remains unsealed and its partial journal is retained for operator acknowledgement and diagnosis.
An explicit control disconnect is rejected while a Run context is active, so the operator
cannot strand an independently writing daemon without a Stop/Finalize path. GUI close remains
orthogonal and never synthesizes Stop.
A future hardware adapter must additionally return its canonical path, volume identity,
qualified space check, and receipt; a UI preview of a path is never a reservation.

The center workbench separates scientific view from display encoding:

- `WIDEBAND` is a bounded display preview, not a continuous raw stream. The current mock
  returns sampled extrema and must not call them complete bucket min/max; a future data-plane
  adapter may claim exact min/max only with a matching aggregation receipt.
- `LFP` production data requires backend filter/decimation metadata. The mock instead
  exposes the frozen 8 Hz truth component of the same composite fixture and labels it as
  such; it must not pretend that a production filter ran.
- `SPIKES` is a three-level inspection surface: full-Pod channel activity, an eight-channel
  raster bank, and one selected-channel mean/p10/p90 waveform. It does not stream every
  detected raw snippet into the WebView and does not claim sorting.

The default mock input receipt is `MOCK-RHD2132X1-32CH-30K`: a 32-neural-channel,
30 kS/s/channel synthetic generator shaped like the current software RHD2132×1 profile.
It is not a hardware descriptor, Inventory receipt, calibrated ADC claim, HIL result, or
statement that an attached Headstage was enumerated. Its amplitude label is always
`SYNTHETIC µV`; a future hardware adapter without scale evidence must use `ADC counts`
and leave `microvoltsPerCount` null.

Wideband and LFP frames carry only the selected eight-channel bank. Spike frames carry
all-channel event counts, a bounded raster for the selected bank, and only the selected
channel's aggregate waveform. Bank changes are preview requests; they do not change the
Headstage sample rate or omit channels from recording.

Spike accounting separates detector scope from WebView drawing scope without normalizing
data loss:

- `POD EVENTS`: oracle/detector events across every Pod channel in the window;
- `BANK EVENTS`: the subset belonging to the displayed eight-channel bank;
- `RASTER DRAWN`: the bounded raster subset returned to the WebView;
- `DISPLAY OMITTED`: events deliberately not drawn because of the display budget;
- `SOURCE COVERAGE`: whether the declared source sample range is complete;
- `ANALYSIS COVERAGE`: whether that same range was completely processed.

For a valid frame, `BANK EVENTS = RASTER CANDIDATES` and `RASTER CANDIDATES =
RASTER DRAWN + DISPLAY OMITTED`, while both coverage states are `COMPLETE` and both gap
range lists are empty. An input or analysis discontinuity is a latched coverage fault with
exact sample boundaries; Forge never fabricates `lost spike = N`. The mock uses
`channel_stratified_rotating_v1` so a flat `slice(0, N)` cannot starve high channel numbers.

`1 s`, `2 s`, and `5 s` mean “show this much history ending now.” They change the preview
request and returned frame window; they are not sample rates, recording chunks, or filter
constants. Mode, Pod, window, gain, and display pause changes never alter Recording Arm,
writer state, or Run integrity.

The repository now has a deterministic composite Rust SampleBlock source and Python
threshold/LFP reference oracles. Streaming reference analyzers hard-fail on a sample gap and
require an explicit reset. No real daemon-to-GUI LFP waveform or Spike preview extractor is
connected in this mock round. A production implementation belongs in the Rust/worker data
plane and must provide bounded preview metadata and receipts; React never performs
scientific signal processing.

The mock generator makes the eventual adapter shape testable, but it is not the real-time
extractor. In particular, this GUI work does not prove a physical RHD/RHS code format,
register programming, volts-per-count conversion, FT601 admission, Aggregator streaming,
or a daemon SampleBlock-to-preview pipeline.

## Time boundary

USB or Ethernet arrival time is not sample time. A software marker captures host monotonic time immediately and may additionally carry the nearest hardware sample/global time when the backend can provide it. The UI must show the timestamp source.

## Inspiration and licenses

- Open Ephys GUI: separate acquisition and recording, pause display without stopping acquisition, visible buffer/disk health. GPL-3.0 project.
- SpikeGLX: pre-run validation and quantitative FIFO/writer metrics. Janelia license; bundled components have separate licenses.
- Intan RHX: device discovery, clear Run/Stop/Record controls, live notes tied to sample position, visible hardware/software buffers. GPL-3.0 project.

Forge uses these interaction concepts only. Its implementation, visual language, assets, and copy are original so that a future project license is not accidentally constrained by copied GPL code.
