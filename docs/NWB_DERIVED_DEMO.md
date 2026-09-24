# NWB-derived browser demo

Status: browser-only mock Preview data. The event times, waveform snippets, and
compact LFP window come from a real NWB artifact; the wideband trace between
events is a deterministic reconstruction and is not a copied raw recording.

## Source receipt

| Field | Value |
|---|---|
| Remote source | `N:/FINAL/D10/27-40-30-32_mouse40.nwb` |
| SHA-256 | `d9bb7a521a107d6f408186e28c2c2ebd5826b6cee2eb971d79c89ee643769343` |
| Byte length | `147311211` |
| Source duration | `3681.862833 s` |
| Source channels | `16` |
| Waveform rows | one 32-point row per `units/spike_times` event |
| LFP source | `acquisition/LFP/data`, 16 channels at 1000 Hz |

The compact checked-in fixture is
`src/fixtures/nwb-waveform-demo.v3.json`. It contains no broadband continuous
source recording. The source has 16 physical channels; the demo exposes 128
channels by pairing those 16 source channels with eight distinct 10-second
windows (`0`, `308`, `560`, `845`, `1104`, `2045`, `2513`, and `3671 s`). Each
demo channel retains five deterministic snippets and its aligned LFP window,
block-averaged to 50 Hz (500 points per channel). The fixture totals 640 Spike
templates and 64000 LFP points, plus source counts, rates, extraction
parameters, and the source hash. This is a bounded demo mapping, not a claim
that the source NWB has 128 independent electrodes.

## Unit interpretation

This legacy file reports `unit=raw, conversion=1`. The owning conversion tools
state that PLX spike waveforms have already been converted to physical
millivolts; the stored step size and amplitudes are consistent with that path.
The extractor therefore baseline-corrects each Spike snippet and converts
`mV -> µV`. Spike snippets quantize at `0.125 µV/count`. The LFP window follows
the same documented interpretation, is median-centered per channel, and
quantizes at `0.5 µV/count`. These corrections are recorded in the fixture
rather than silently pretending the stale NWB attributes are authoritative.

## Reconstruction

`NwbDerivedDemoModel` loops each channel's assigned real 10-second event schedule
on a 30 kHz sample timeline. Each event injects one of the real, channel-specific
32-point snippets. The corresponding real LFP window is linearly interpolated
onto that 30 kHz timeline and looped at the same 10-second boundary. Only the
between-event broadband noise is synthetic. Wideband, LFP, Spike raster,
all-channel waveform cards, and selected-channel waveforms are generated from
this one reconstructed timeline.

The browser composition root uses this bounded 128-channel-per-Pod model. The
Spike matrix virtualizes its cards and Wideband/LFP render only the selected
8-channel bank, so the additional demo channels do not create 128 live plots at
once. The Tauri software
adapter and protected replay keep the canonical
`forge.synthetic.neural.integer.v1` model unchanged.

## Refreshing the fixture

The extractor reads the remote NWB through stdin and writes only the compact JSON
fixture locally:

```powershell
cd F:\poorsystem\Forge\host_app
node scripts/fetch-nwb-demo-fixture.mjs
```

`scripts/extract-nwb-demo-fixture.py` performs the read-only extraction on the
SSH host. `scripts/inspect-nwb-demo-source.py` is a read-only schema/unit audit.
Any refreshed fixture must update the pinned source hash test and pass `npm test`,
`npm run build`, `npm run check:bundle`, and `npm run visual:qa`.

## Evidence boundary

- `scope=mock`, `synthetic=true`, and `containsContinuousRawSamples=false` remain
  mandatory on every Preview frame.
- The UI label `NWB µV` means real NWB Spike snippets and real downsampled LFP
  with corrected physical units; it does not mean live hardware, a broadband
  raw-data replay, or a scientifically validated detector/sorter.
- This fixture cannot qualify Intan, CABLINE, Receiver Pod, FT601/D3XX, daemon,
  journal, NWB publication, storage throughput, or release readiness.
