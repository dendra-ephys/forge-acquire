# NWB-derived browser demo

Status: browser-only mock Preview data. The event times and waveform snippets
come from a real NWB artifact; the continuous trace between events is a
deterministic reconstruction and is not a copied raw recording.

## Source receipt

| Field | Value |
|---|---|
| Remote source | `N:/FINAL/D10/27-40-30-32_mouse40.nwb` |
| SHA-256 | `d9bb7a521a107d6f408186e28c2c2ebd5826b6cee2eb971d79c89ee643769343` |
| Byte length | `147311211` |
| Source duration | `3681.862833 s` |
| Source channels | `16` |
| Waveform rows | one 32-point row per `units/spike_times` event |

The compact checked-in fixture is
`src/fixtures/nwb-waveform-demo.v1.json`. It contains no continuous source
recording. It retains a representative 10-second event-time window beginning at
source time `507 s`, three deterministic snippets per channel, source counts and
rates, extraction parameters, and the source hash.

## Unit interpretation

This legacy file reports `unit=raw, conversion=1`. The owning conversion tools
state that PLX spike waveforms have already been converted to physical
millivolts; the stored step size and amplitudes are consistent with that path.
The extractor therefore baseline-corrects each snippet and converts
`mV -> µV`. The fixture quantizes at `0.125 µV/count`. The correction is recorded
in the fixture rather than silently pretending the stale NWB attribute is
authoritative.

## Reconstruction

`NwbDerivedDemoModel` loops the real 10-second event schedule on a 30 kHz sample
timeline. Each event injects one of the real, channel-specific 32-point snippets.
Only the between-event low-frequency baseline and low-amplitude noise are
synthetic. Wideband, Spike raster, all-channel waveform cards, and selected
channel waveforms are generated from this one reconstructed timeline. The LFP
view is the paired synthetic low-frequency baseline; it is not source LFP from
the NWB.

The browser composition root uses this 16-channel model. The Tauri software
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
- The UI label `NWB µV` means real NWB snippets with corrected physical units; it
  does not mean live hardware, a raw-data replay, or a scientifically validated
  detector/sorter.
- This fixture cannot qualify Intan, CABLINE, Receiver Pod, FT601/D3XX, daemon,
  journal, NWB publication, storage throughput, or release readiness.
