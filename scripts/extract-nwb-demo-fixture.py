#!/usr/bin/env python3
"""Extract a compact, deterministic NWB spike-waveform demo fixture as JSON.

The source file is only read. The output contains a short real event-time window
and baseline-corrected waveform snippets; it never contains a continuous source
recording. Forge reconstructs the browser-only continuous demo from this data.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any

import h5py
import numpy as np


SCHEMA_VERSION = 3
FIXTURE_ID = "forge.demo.nwb-waveform-reconstruction.v3"
SAMPLE_RATE_HZ = 30_000
LOOP_SECONDS = 10
MICROVOLTS_PER_COUNT = 0.125
TEMPLATES_PER_CHANNEL = 5
DEMO_CHANNEL_COUNT = 128
LFP_PATH = "acquisition/LFP/data"
LFP_OUTPUT_RATE_HZ = 50
LFP_MICROVOLTS_PER_COUNT = 0.5


def source_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def unit_slices(nwb: h5py.File) -> list[tuple[int, int]]:
    indices = np.asarray(nwb["units/spike_times_index"][:], dtype=np.int64)
    starts = np.concatenate(([0], indices[:-1]))
    return [(int(start), int(end)) for start, end in zip(starts, indices)]


def choose_windows(spike_times: list[np.ndarray], duration_seconds: float) -> list[int]:
    latest_start = max(0, int(np.floor(duration_seconds - LOOP_SECONDS)))
    candidates: list[tuple[int, int, int]] = []
    for start in range(latest_start + 1):
        end = start + LOOP_SECONDS
        counts = [int(np.count_nonzero((times >= start) & (times < end))) for times in spike_times]
        candidates.append((start, sum(count > 0 for count in counts), sum(counts)))
    maximum_active = max(active for _, active, _ in candidates)
    complete = [(start, total) for start, active, total in candidates if active == maximum_active]
    windows_needed = DEMO_CHANNEL_COUNT // len(spike_times)
    if DEMO_CHANNEL_COUNT % len(spike_times) != 0:
        raise ValueError("demo channel count must be a multiple of source channels")
    if len(complete) < windows_needed:
        raise ValueError("source does not contain enough complete channel windows")
    # Spread the bounded fixture across the recording instead of duplicating one
    # 10-second excerpt eight times. Every selected window still has the maximum
    # number of active source channels.
    positions = np.linspace(0, len(complete) - 1, windows_needed, dtype=np.int64)
    return [complete[int(position)][0] for position in positions]


def template_indices(
    times: np.ndarray,
    waveforms: np.ndarray,
    window_start: float,
) -> np.ndarray:
    in_window = np.flatnonzero((times >= window_start) & (times < window_start + LOOP_SECONDS))
    candidate = in_window if in_window.size >= TEMPLATES_PER_CHANNEL else np.arange(len(times))
    values = waveforms[candidate]
    baseline = values[:, :4].mean(axis=1, keepdims=True)
    peak_to_peak = np.ptp(values - baseline, axis=1)
    lower, upper = np.percentile(peak_to_peak, [2, 98])
    accepted = candidate[(peak_to_peak >= lower) & (peak_to_peak <= upper)]
    if accepted.size < TEMPLATES_PER_CHANNEL:
        accepted = candidate
    positions = np.linspace(0, accepted.size - 1, TEMPLATES_PER_CHANNEL, dtype=np.int64)
    return accepted[positions]


def emit_fixture(path: str) -> dict[str, Any]:
    with h5py.File(path, "r") as nwb:
        spike_times_all = np.asarray(nwb["units/spike_times"][:], dtype=np.float64)
        slices = unit_slices(nwb)
        spike_times = [spike_times_all[start:end] for start, end in slices]
        duration_seconds = max(float(times[-1]) for times in spike_times if times.size)
        window_starts = choose_windows(spike_times, duration_seconds)
        lfp = nwb[LFP_PATH]
        lfp_group = lfp.parent
        lfp_rate_hz = int(lfp_group.attrs["rate"])
        lfp_starting_time = float(lfp_group.attrs.get("starting_time", 0.0))
        if lfp.ndim != 2 or lfp.shape[1] != len(slices):
            raise ValueError("LFP channel count does not match spike-waveform units")
        if lfp_rate_hz % LFP_OUTPUT_RATE_HZ != 0:
            raise ValueError("LFP source rate is not an integer multiple of the fixture rate")
        lfp_decimation = lfp_rate_hz // LFP_OUTPUT_RATE_HZ
        channels = []
        peak_indices: list[int] = []
        source_waveforms = []
        for channel, (start, end) in enumerate(slices):
            dataset = nwb[f"processing/spike_waveforms/unit_{channel}"]
            if dataset.shape[0] != end - start:
                raise ValueError(f"unit_{channel} waveform/timestamp row mismatch")
            source_waveforms.append(np.asarray(dataset[:], dtype=np.float64))
        for bank, window_start in enumerate(window_starts):
            lfp_start = int(round((window_start - lfp_starting_time) * lfp_rate_hz))
            lfp_stop = lfp_start + LOOP_SECONDS * lfp_rate_hz
            if lfp_start < 0 or lfp_stop > lfp.shape[0]:
                raise ValueError("selected spike window is outside the LFP source extent")
            lfp_source = np.asarray(lfp[lfp_start:lfp_stop], dtype=np.float64)
            lfp_microvolts = lfp_source.reshape(
                LOOP_SECONDS * LFP_OUTPUT_RATE_HZ,
                lfp_decimation,
                lfp.shape[1],
            ).mean(axis=1) * 1_000.0
            lfp_microvolts -= np.median(lfp_microvolts, axis=0, keepdims=True)
            lfp_counts = np.rint(lfp_microvolts / LFP_MICROVOLTS_PER_COUNT).clip(
                -32_768,
                32_767,
            ).astype(np.int16)
            for source_channel, (times, waveforms) in enumerate(zip(spike_times, source_waveforms)):
                selected_indices = template_indices(times, waveforms, window_start)
                selected = waveforms[selected_indices]
                selected -= selected[:, :4].mean(axis=1, keepdims=True)
                waveform_counts = np.rint(
                    selected * 1_000.0 / MICROVOLTS_PER_COUNT
                ).clip(-32_768, 32_767).astype(np.int16)
                peak_indices.extend(np.argmax(np.abs(waveform_counts), axis=1).tolist())
                relative = times[
                    (times >= window_start) & (times < window_start + LOOP_SECONDS)
                ] - window_start
                event_samples = np.rint(relative * SAMPLE_RATE_HZ).astype(np.int64)
                event_samples = event_samples[
                    (event_samples >= 0) & (event_samples < LOOP_SECONDS * SAMPLE_RATE_HZ)
                ]
                channels.append({
                    "demoChannel": bank * len(spike_times) + source_channel,
                    "sourceUnitId": source_channel,
                    "sourceWindowStartSeconds": window_start,
                    "recordingEventCount": int(len(times)),
                    "recordingRateHz": round(float(len(times) / duration_seconds), 4),
                    "eventSamples": event_samples.tolist(),
                    "waveformCounts": waveform_counts.astype(int).tolist(),
                    "lfpCounts": lfp_counts[:, source_channel].astype(int).tolist(),
                })
        waveform_point_count = int(nwb["processing/spike_waveforms/unit_0"].shape[1])
        pretrigger = int(np.median(peak_indices))
        source_attrs = nwb["processing/spike_waveforms/unit_0"].attrs
        source_unit = source_attrs.get("unit", "unknown")
        if isinstance(source_unit, bytes):
            source_unit = source_unit.decode("utf-8", errors="replace")
        return {
            "schemaVersion": SCHEMA_VERSION,
            "fixtureId": FIXTURE_ID,
            "source": {
                "relativePath": "FINAL/D10/27-40-30-32_mouse40.nwb",
                "sha256": source_sha256(path),
                "byteLength": os.path.getsize(path),
                "channelCount": len(slices),
                "sourceChannelCount": len(slices),
                "demoChannelCount": len(channels),
                "durationSeconds": round(duration_seconds, 6),
                "waveformPointCount": waveform_point_count,
                "storedUnit": str(source_unit),
                "storedConversion": float(source_attrs.get("conversion", 1.0)),
                "interpretedUnit": "millivolt",
                "unitInterpretation": (
                    "Legacy PLX conversion output stores physical millivolts while this file retains "
                    "unit=raw and conversion=1; extraction converts those stored values to microvolts."
                ),
                "lfpPath": LFP_PATH,
                "lfpStoredUnit": str(lfp.attrs.get("unit", "unknown")),
                "lfpStoredConversion": float(lfp.attrs.get("conversion", 1.0)),
                "lfpInterpretedUnit": "millivolt",
                "lfpSourceRateHz": lfp_rate_hz,
            },
            "reconstruction": {
                "sampleRateHz": SAMPLE_RATE_HZ,
                "loopSeconds": LOOP_SECONDS,
                "sourceWindowStartSeconds": window_starts,
                "microvoltsPerCount": MICROVOLTS_PER_COUNT,
                "waveformPretriggerSamples": pretrigger,
                "waveformSelection": (
                    "Five deterministic event-aligned snippets per demo channel, baseline corrected using "
                    "the first four points and excluding the outer 2 percent peak-to-peak amplitudes."
                ),
                "lfpSampleRateHz": LFP_OUTPUT_RATE_HZ,
                "lfpMicrovoltsPerCount": LFP_MICROVOLTS_PER_COUNT,
                "lfpSelection": (
                    "Eight source-aligned 10-second LFP windows are block-averaged from 1000 Hz to "
                    "50 Hz, median centered per channel, converted from millivolts to microvolts, "
                    "and mapped to 128 bounded demo channels."
                ),
            },
            "channels": channels,
        }


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: extract-nwb-demo-fixture.py SOURCE.nwb", file=sys.stderr)
        return 2
    print(json.dumps(emit_fixture(sys.argv[1]), ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
