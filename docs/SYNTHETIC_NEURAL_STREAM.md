# Forge synthetic neural stream v1

Status: software-only deterministic fixture. It is not Intan, FT601, Receiver
Pod, HIL, scientific-validity, or release evidence.

Scenario identifier: `forge.synthetic.neural.integer.v1`.

## Purpose

Forge uses one continuous synthetic neural ADC stream to test that acquisition,
durability, derived analysis, and preview stay tied to the same absolute sample
timeline. Wideband, LFP, spike events, and spike waveforms must not be fabricated
as unrelated GUI products.

The fixture supports two independent acceptance questions:

1. **Raw conservation:** did every expected signed-16 sample reach the canonical
   journal and any materialized raw dataset without omission, duplication,
   reordering, or mutation?
2. **Analysis correctness:** over the declared fixture domain, did the reference
   LFP and spike algorithms produce the expected sample-indexed results?

Passing the second question never substitutes for passing the first.

## Deterministic signal

For channel `c` and absolute sample counter `n`, the canonical fixture computes

```text
wideband(c, n) = clamp_i16(lfp(c, n) + spike(c, n) + noise(c, n))
```

All terms are integer and random-access. They do not depend on wall-clock time,
record boundaries, USB fragmentation, worker scheduling, or GUI refresh cadence.
The shared coordinate domain is unsigned-64 sample counter and seed,
unsigned-16 channel ID, and unsigned-32 sample rate. Implementations reject
out-of-domain values rather than wrap them silently.

Synthetic `SampleBlock` records set only the `COMPLETE` flag. Their global time
is computed from sample counter and rate for deterministic testing; the
`HARDWARE_TIMESTAMPED` flag is forbidden because no hardware clock produced it.

### LFP component

The baseline component is an 8 Hz integer triangle with a peak magnitude of
2048 counts. At sample rate `fs`:

```text
phase = ((n mod fs) * 8 + c * floor(fs / 32)) mod fs

phase < fs/2:
  lfp = -2048 + floor(8192 * phase / fs)
otherwise:
  lfp =  6144 - floor(8192 * phase / fs)
```

### Spike component

Each channel has deterministic event centers:

```text
period       = max(floor(fs / 10), 64)
first_center = 29 + 53 * c
center(k)    = first_center + k * period
```

The signed-count template, indexed from `center - 5` through `center + 5`, is:

```text
[0, -256, -1024, -4096, -16000, -40000,
 -16000, -4096, -1024, -256, 0]
```

The final sum is saturated to the signed-16 range. Channel 0's first waveform
crosses the nominal 30-row SampleBlock boundary intentionally.

Event queries include a center when `sample_start <= center < sample_end`.
Waveform support is reported separately and may extend outside that query
range; consumers that require a complete waveform must check the support range.

### Noise component

Noise is a bounded `[-64, 64]` count value derived from a specified 64-bit seed,
the full absolute sample counter, and channel number through fixed 32-bit
wrapping arithmetic and xorshift32. Implementations must publish golden tests
before changing any mix constant or shift.

The shared seed-9 cross-language sentinels are:

| Sample | Channel | LFP | Spike | Noise | Sum | ADC int16 |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 0 | -2048 | 0 | 59 | -1989 | -1989 |
| 29 | 0 | -1985 | -40000 | -46 | -42031 | -32768 |
| 82 | 1 | -1614 | -40000 | -44 | -41658 | -32768 |
| 4294967303 | 1 | 858 | 0 | 38 | 896 | 896 |

## Oracle and receipts

A qualification result must bind at least:

- fixture schema/version, seed, sample-rate rational, channel layout, and sample
  range;
- expected record and per-channel sample ranges;
- expected spike centers and waveform support ranges;
- expected raw sample digests or byte-for-byte golden samples;
- LFP window range, frequency resolution, passband, and numeric tolerance;
- detector configuration, required sentinel events, TP/FN/FP counts, and
  analysis coverage end;
- software build/config hashes used to produce the result.

The protected-replay receipt binds the scenario ID, seed, rate, layout, channel
count, exact sample range, source-config SHA-256, and length-delimited canonical
record-stream SHA-256. Its journal test reopens the sealed file, recomputes that
digest, decodes every sample, and compares it with the random-access oracle.

Raw acceptance requires the union of recorded ranges to equal the requested
`[sample_start, sample_end)` exactly. A missing, duplicated, reordered, or
mutated sample is a failed Run-integrity check, not a warning.

If analysis is required by the Run plan, the governed downstream analysis receipt may succeed
only when the durable analysis cursor covers the acquisition end. The operator-facing
Recording action remains one `End and Save`; it completes raw Recording closure through
stop, drain, durability, and journal seal without a second Finalize click. Backlog is visible
and may be recovered from the journal; silently skipping a range is forbidden.

The reference streaming detector and LFP accumulator therefore raise a latched
coverage error when `observed_sample_start != expected_sample_start`. The error
contains the exact missing or overlapping sample boundary, never a guessed
number of missed spikes, and processing cannot resume until an explicit reset.

## Injection layers and evidence limits

| Injection layer | What it can test | What it cannot prove |
|---|---|---|
| GUI mock adapter | bounded preview semantics, selection, keyboard flow, long-lived DOM behavior | daemon, journal, NWB, hardware |
| Canonical SampleBlock source | canonical decode, daemon, journal, replay, raw materialization, reference analysis | DHL/RTL, FT601, Intan analog behavior |
| DHL/RTL simulation | framing, counters, aggregation, canonical builder | physical links, USB, populated boards |
| Signal generator through Intan/Pod HIL | measured behavior for the exercised physical conditions | all electrodes, all biological signals, release readiness |

The React/WebView side never receives the continuous raw acquisition stream. It receives only
bounded sampled-extrema previews (or future receipt-proven bucket aggregates), LFP summaries,
spike raster subsets, and `spike_preview_v3` selected-channel event windows derived from the
same synthetic sample timeline. Each v3 window contains every event-aligned waveform snippet
whose center remains inside the declared source-sample TTL, plus statistics computed from that
exact set, explicit coverage, and evidence identifiers.

`全部波形` is the default display mode and draws all returned snippets in one Canvas pass as
soon as the next bounded Preview frame arrives. `统计` draws mean/p10/p90 and `最新` draws the
newest snippet without changing the retained event set. A snippet disappears when its center
leaves the common 1/2/5 s `retentionSamples` window. The mock contract requires observed and
returned counts to match; exceeding its fixed waveform capacity is a coverage fault rather
than silent sampling. This software-oracle behavior does not qualify a production detector,
Intan input, or hardware data path.
