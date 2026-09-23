# Forge Acquire performance budget

Status: control-plane baseline

## Architectural rule

The UI is not the data path. FT601/10GbE samples remain inside the Rust acquisition process and durable journal pipeline. React receives only:

- immutable status snapshots at 5–10 Hz;
- bounded event/marker pages;
- already-decimated display envelopes over an ordered binary IPC channel;
- bounded selected-channel event-aligned waveform windows and statistics, never the
  continuous acquisition stream;
- explicit display-drop counters that never masquerade as acquisition loss.

Tauri JSON commands/events are reserved for low-rate control and state. They are not used for raw samples. The final trace path is Rust min/max decimation → binary Tauri channel → Canvas (and, if profiling justifies it, `OffscreenCanvas` in a worker). React owns controls and semantics; Canvas owns pixels.

## Startup and bundle

- no network request is required to render the shell;
- system fonts are used, with no Google Fonts dependency;
- one acquisition workspace loads eagerly; future settings, NWB inspection, and maintenance screens load lazily;
- no chart framework is included for live traces;
- production JS gzip budget: 100 kB for the initial control surface;
- production CSS gzip budget: 16 KiB for the dual-theme semantic instrument layer;
- complete lazy-loaded payload budgets: 112 KiB JS and 18 KiB CSS gzip;
- first meaningful instrument shell target: under 500 ms on the reference acquisition PC after WebView warm-up.

Current measured bundle-gate output on 2026-09-23 is 99.16 KiB startup JS and
14.41 KiB startup CSS; complete lazy-loaded totals are 108.28 KiB JS and 15.90 KiB CSS.
The CSS increase is the bounded cost of the light/dark token layer and selected Apps SDK UI
primitive styling. The default Apps SDK UI KaTeX/CDN stylesheet is excluded, and the gate still
rejects remote CSS `url()`/`@import` resources. This is build-size evidence only, not a
startup-latency measurement.

## Runtime budgets

| Path | Budget |
|---|---:|
| machine/status snapshots | 5 Hz normal, 10 Hz maximum |
| health counters | 5 Hz |
| bounded preview frames, including selected-channel event windows | up to 30 frames/s |
| React commits while streaming | no more than 10/s outside the trace surface |
| trace history retained by UI | bounded visible window only |
| continuous raw acquisition-stream bytes in WebView | 0 |
| selected-channel waveform retention | one source-sample TTL window (1/2/5 s), fixed capacity, complete-or-fault |
| unbounded arrays/queues | 0 |

Presentation cadence is not a data-integrity counter. If the WebView cannot present the
current bounded aggregate, the preview must become visibly `STALE` or pause and later resume
from a newly identified complete source range. The UI must not report a reassuring
`FRAME DROPS = N` value. Source and analysis coverage remain independently receipt-bound;
any sample-range gap is a latched Run-integrity failure, never a presentation statistic.

`spike_preview_v3` stores one bounded selected-channel event set per latest frame. The
`全部波形`, `统计`, and `最新` controls change only the Canvas draw policy; they do not clone
event arrays or accumulate another history. New event snippets are visible on the next bounded
frame and expire by source-sample age. If the fixed capacity cannot return every observed
selected-channel event, coverage fails visibly instead of silently omitting waveforms.

## Profiling gates

- cold and warm Tauri launch timings on the target Windows PC;
- bundle-size regression check;
- React Profiler while 8-Pod status is updating;
- 30-minute display run with bounded memory and no long task above 50 ms at p99;
- resize, pause-display, channel selection, marker entry, and modal use during maximum-rate synthetic status replay;
- keyboard-only and 100%, 125%, 150%, and 200% Windows scaling checks;
- at 1080 × 720 the compact verdict, data-continuity state, file-save state, and any recovery fault remain visible; opening technical details neither resizes the waveform workbench nor causes document-level horizontal scroll.

The current simulator still uses React state to exercise the UI contract. It is not evidence that the production binary trace channel or performance gates have passed.

## Journal qualification profile

`forge-acqd journal-qualification` is a separate release-build, synthetic
journal-only runner. Its machine-readable source profile is receipt-bound:
`active_receiver_pod_128` is eight Pods × 128 channels × 30 rows at 30 kS/s,
with a 7,888-byte canonical record and 7,992-byte journal record (63.104 MB/s
canonical, 63.936 MB/s journal). `protocol_max_256` is eight Pods × 256 channels,
with 15,568-byte canonical and 15,672-byte journal records. The CLI defaults to
`protocol_max_256`; only that profile may ever satisfy the conservative journal
release flag. The 256-channel stream is a protocol stress envelope, not a claim
about active Headstage SKUs, whose current maximum is 128 acquisition channels per
Pod. Real Run bandwidth is derived from the admitted Descriptor.
Each invocation receives a fresh operating-system-generated Run ID; the profile
hash describes the immutable load/build/volume configuration and is not reused
as experiment identity.
The receipt binds the executable and protocol hashes, target-volume identity,
committed/durable counts, active-write rate, periodic-barrier latency, seal
latency, CPU time, peak working set and journal SHA-256. The independent
`verify-journal-qualification` command reopens and rescans the sealed journal,
derives the actual Pod/record geometry from decoded canonical records, requires
the exact current executable identity, recomputes receipt/profile hashes and
rejects semantic or file tampering.

Gate semantics are deliberately asymmetric:

- less than 30 minutes: `smoke_only`, even if instantaneous throughput exceeds
  190.08 MB/s;
- at least 30 minutes, release build and at least `max(caller target, selected
  profile floor)`: journal engineering-duration gate only;
- at least 24 hours, release build, `protocol_max_256`, reconciled sealed/reopened
  watermarks, and at least `max(caller target, 190.08 MB/s)`: conservative journal
  release-duration flag only. A caller may raise but never lower this floor;
  `active_receiver_pod_128` is never a conservative release result;
- no journal-only result satisfies the journal-plus-NWB, D3XX, Aggregator,
  target-PLP-storage, fault-injection or product release gates.

The receipt and its hashes are unkeyed local engineering-integrity evidence. They
are not a signature, remote attestation or independent clock witness. The verifier
detects ordinary/stale/tampered evidence against the current executable and journal;
it does not defend against an actor able to replace the executable, journal and receipt
together. A 24-hour flag therefore remains one input to the governed release gate, not
standalone product authorization.

A fresh one-second release smoke on 2026-08-13 reached 287.22 MB/s canonical
input with zero raw WebView bytes and an independently verified receipt. Its
duration gates remained false. The active write interval and terminal sealing
interval are reported separately so a short smoke cannot hide final durability
cost or have that cost misreported as steady-state ingress speed.
