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
7. use the single `End and Save` action without stopping Preview;
8. let the adapter/data plane stop Run input, drain queued records, seal the journal,
   materialize and validate the final NWB, and publish it with no-overwrite semantics;
9. call the Recording ended and saved only after the matching NWB publication receipt;
10. stop Preview separately when it is no longer needed. There is no second operator-facing
    Finalize action.

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
create-new/forbid-overwrite policy, final-NWB output readiness for non-mock recording, and the
subsequent adapter snapshot. In Tauri software
scope it launches a current-user-authenticated independent Rust process, atomically reserves
the numbered Run directory, and creates `run.forgewal` during accepted Prepare. In browser
mock scope it allocates a display name only and creates no disk object. Neither path pretends
to measure qualified free-space endurance or open FT601/Aggregator hardware. Preflight does
not begin sample generation. A mock may exercise the flow while explicitly declaring that it
will not create NWB; a non-mock adapter that cannot provide a final NWB publication receipt is
not admitted as a successful product recording path. Recording Arm remains a separate writer
interlock and is unrelated to stimulation.

Preflight uses progressive disclosure. Its default operator layer answers only four questions:
which devices will be recorded, where the Run will be saved, what the final file is, and whether
recording can proceed. Adapter scope, identity/input receipts, reservation hashes, snapshot state,
and command receipts remain available under a default-collapsed `Technical details` disclosure.
Collapsing them changes presentation only; it removes no validation and does not weaken fail-closed
behavior. When one prerequisite causes dependent steps to wait, the operator layer names the one
upstream cause. For example, an unavailable NWB output keeps target allocation and admission in
`waiting`; it does not render all three as separate faults. A target that has not yet been allocated
is a lifecycle state, not an error.

The save-root field remains editable and, in the Tauri desktop shell, also opens Forge's bounded
`RunDirectoryBrowser`. It is an in-dialog filesystem view, not a Windows Shell/Explorer chooser:
the Rust boundary lists logical-drive letters and at most 128 direct child directories, performs
no recursion, loads no files or thumbnails, and permits only one directory request at a time.
React never constructs parent/child paths; it navigates only with paths returned by the adapter.
Cancel preserves the current requested root, and only `Use current folder` writes the canonical
path back to Recording setup. Browsing does not create a Run directory, prove writability, or
produce storage evidence. Browser mock QA leaves the desktop-only action disabled and continues
to accept explicit path text.

Before recording can be reported as active, the control model passes through writer opening, writer armed, and source-confirmed states. The UI may animate those transitions quickly in the simulator, but the production backend cannot skip them.

## State separation

The UI must never collapse these into one green/red lamp:

- transport connection;
- acquisition state;
- writer state;
- run integrity;
- hardware synchronization;
- per-device health.

The label `End and Save` names the requested end-to-end operation; pressing it is not itself
evidence that saving succeeded. The acquisition journal becomes a recoverable intermediate
only after input has stopped, the queue is drained, durability is confirmed, and the journal
is sealed. Until the final NWB has been closed, has passed schema and semantic validation,
has been reconciled, and has been published with no-overwrite semantics, the UI says
`Ending / Saving`, never `Saved`. CRC
errors, sample-counter gaps, or any data-path overflow are hard Run faults. They are not a
normal status lane and they prevent a successful saved verdict.

The signature component is one compact **Run result strip**, not a generic health dashboard,
serial progress arrow, or five-slot evidence report. It presents exactly one operator outcome:
not started, recording, ending/saving, saved, simulation complete, NWB incomplete, or failed.
Receipt sequence/hash and intermediate journal states stay out of the normal workspace; an
actionable fault reason appears only when a fault exists.

`raw_sealed` means only `Raw journal retained; NWB incomplete`. It can support recovery but
cannot produce a saved verdict. A non-mock `Saved` verdict requires the matching final NWB
artifact receipt proving generation, validation, reconciliation, and no-overwrite publication.
A browser-mock completion says `Simulation complete; no NWB file created`. Analysis and
external-event controls/status are hidden until corresponding adapter interfaces actually
exist; the GUI does not advertise unavailable interfaces as empty evidence slots.

The fixed transport controls borrow interaction principles from the official Intan RHX user
guide: keep Preview/Record/End-and-Save positions stable, disable Record until save preparation is
complete, keep load indicators and scale controls near the waveform, and keep synthetic
demonstration mode explicit. Forge does not copy RHX source, assets, or pixel layout. Forge
additionally requires Recording Arm, daemon independence, Stop-versus-safe separation, and
receipt-backed final output.

The React/Tauri surface is a control plane. The independent Rust data plane owns transport ingest and the acquisition journal; the NWB materializer is restartable and may lag without backpressuring acquisition. Raw samples never enter React state.

## Data-first collapsible workspace

The signal display is the primary and largest working surface. The device list, Run controls, and
Diagnostics collapse independently. The single Run result always occupies one compact fixed
strip and never expands into a technical drawer, so it cannot take waveform height.

`Signal Focus` is a view-only shortcut: it collapses the side regions and Diagnostics, and restores
their prior independent states when exited. Collapsing a region sends no
adapter command, changes no acquisition state, and must not reset the selected Pod, signal
mode, channel bank, channel, time window, or latest bounded preview frame.

During recording, the compact Run-control rail keeps one explicit text action,
`End and Save`, visible. That single request leaves Preview live while the adapter/data plane
stops writer input, drains, applies its durability barrier, seals the journal, and completes the
final NWB. The rail remains `SAVING` until a matching NWB publication receipt proves completion;
there is no second Finalize button.
Stimulation controls do not appear in the acquisition GUI. A future external Python
stimulation module needs its own governed interface;
until that interface exists the acquisition surface displays no external-event control or status.
The compact Run result retains a plain-language overall verdict; color alone never carries meaning.

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
recoverable internal `run.forgewal` and, after successful finalization, the final NWB. The mock returns
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
cannot strand an independently writing daemon without an End-and-Save or failed-Run
acknowledgement path. GUI close remains
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
  raster bank, and the selected channel's complete rolling window of bounded event-aligned
  waveform snippets. `全部波形` is the daily-use default; `统计` renders mean/p10/p90 from
  that same event set, and `最新` renders only the newest event. It does not send the
  continuous acquisition stream into the WebView and does not claim sorting.

The default mock input receipt is `MOCK-RHD2132X1-32CH-30K`: a 32-neural-channel,
30 kS/s/channel synthetic generator shaped like the current software RHD2132×1 profile.
It is not a hardware descriptor, Inventory receipt, calibrated ADC claim, HIL result, or
statement that an attached Headstage was enumerated. Its amplitude label is always
`SYNTHETIC µV`; a future hardware adapter without scale evidence must use `ADC counts`
and leave `microvoltsPerCount` null.

Wideband and LFP frames carry only the selected eight-channel bank. `spike_preview_v3`
frames carry all-channel event counts, a bounded raster for the selected bank, every
event-aligned waveform from the selected channel's declared rolling source-sample window,
and statistics computed from exactly that same set. Bank changes are preview requests; they do not change the
Headstage sample rate or omit channels from recording.

The selected-channel waveform window is complete-or-fault: its observed count must equal its
returned count, event IDs must be unique, and every center must fall within the declared
`retentionSamples` interval. A capacity overrun is a coverage fault, not an invisible display
omission and not a fabricated estimate of missed spikes. The three waveform modes share one
bounded frame and one Canvas; switching modes never creates a second retained history.

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

For Wideband and LFP, `1 s`, `2 s`, and `5 s` mean “show this much history ending now.” For
Spikes they are the source-sample TTL for every selected-channel waveform: a newly arrived
event appears on the next bounded Preview frame and expires when it leaves that same 1/2/5 s
window. They are not sample rates, recording chunks, or filter constants. Mode, Pod, window,
gain, and display pause changes never alter Recording Arm, writer state, or Run integrity.

The repository now has a deterministic composite Rust SampleBlock source and Python
threshold/LFP reference oracles. Streaming reference analyzers hard-fail on a sample gap and
require an explicit reset. No real daemon-to-GUI LFP waveform or Spike preview extractor is
connected in this mock round. The v3 rolling waveform window is a deterministic mock-oracle
contract, not a qualified detector. A production implementation belongs in the Rust/worker
data plane and must provide bounded preview metadata and receipts; React never performs
scientific signal processing.

The mock generator makes the eventual adapter shape testable, but it is not the real-time
extractor. In particular, this GUI work does not prove a physical RHD/RHS code format,
register programming, volts-per-count conversion, FT601 admission, Aggregator streaming,
or a daemon SampleBlock-to-preview pipeline.

## Time boundary

USB or Ethernet arrival time is not sample time. Any future external-event interface must capture
host monotonic time immediately and may additionally carry the nearest hardware sample/global
time when the backend can provide it. That future UI must show the timestamp source; the current
GUI exposes no marker control or event-status slot.

## Inspiration and licenses

- Open Ephys GUI: separate acquisition and recording, pause display without stopping acquisition, visible buffer/disk health. GPL-3.0 project.
- SpikeGLX: pre-run validation and quantitative FIFO/writer metrics. Janelia license; bundled components have separate licenses.
- Intan RHX: device discovery, clear Run/Stop/Record controls, live notes tied to sample position, visible hardware/software buffers. GPL-3.0 project.

Forge uses these interaction concepts only. Its implementation, visual language, assets, and copy are original so that a future project license is not accidentally constrained by copied GPL code.
