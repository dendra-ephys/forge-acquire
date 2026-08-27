"""Deterministic reference algorithms for worker integration and benchmarks.

These implementations intentionally favor clarity, bounded inputs, and stable
test behavior over scientific sophistication. They are not validated spike
sorters, LFP biomarkers, closed-loop controllers, or clinical algorithms.
Block-edge handling and every parameter must be validated on representative
Forge data before any scientific interpretation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import ceil
from typing import Literal, Mapping, Sequence
from uuid import UUID

import numpy as np
from numpy.typing import NDArray

from .sdk import SampleBlock


Polarity = Literal["negative", "positive", "both"]


class AnalysisContinuityError(RuntimeError):
    """Latched analysis coverage fault; the caller must reset explicitly.

    A missing or overlapping sample interval invalidates streaming detector and
    filter state.  This exception reports exact expected/observed sample
    boundaries instead of inventing a count of neural events that might have
    occurred in the uncovered interval.
    """

    def __init__(
        self,
        *,
        algorithm_id: str,
        expected_sample_start: int | None,
        observed_sample_start: int,
        identity_changed: bool = False,
    ) -> None:
        self.algorithm_id = algorithm_id
        self.expected_sample_start = expected_sample_start
        self.observed_sample_start = observed_sample_start
        self.identity_changed = identity_changed
        if identity_changed:
            detail = "stream identity changed"
        elif expected_sample_start is None:
            detail = "sample continuity is unknown"
        elif observed_sample_start > expected_sample_start:
            detail = (
                f"unprocessed sample range [{expected_sample_start}, "
                f"{observed_sample_start})"
            )
        else:
            detail = (
                f"overlapping/replayed samples: expected {expected_sample_start}, "
                f"observed {observed_sample_start}"
            )
        super().__init__(
            f"{algorithm_id} coverage fault: {detail}; explicit reset required"
        )


@dataclass(frozen=True, slots=True)
class ThresholdConfig:
    """Threshold-crossing parameters in the numeric units of `SampleBlock`."""

    threshold: float | None = None
    mad_multiplier: float | None = 5.0
    polarity: Polarity = "negative"
    refractory_seconds: float = 0.001

    def __post_init__(self) -> None:
        if (self.threshold is None) == (self.mad_multiplier is None):
            raise ValueError("set exactly one of threshold or mad_multiplier")
        selected = self.threshold if self.threshold is not None else self.mad_multiplier
        if selected is None or not np.isfinite(selected) or selected <= 0:
            raise ValueError("threshold selection must be finite and positive")
        if self.polarity not in ("negative", "positive", "both"):
            raise ValueError("unsupported threshold polarity")
        if not np.isfinite(self.refractory_seconds) or self.refractory_seconds < 0:
            raise ValueError("refractory_seconds must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class SpikeEvent:
    run_id: UUID
    generation: int
    canonical_pod_id: bytes
    pod_slot: int
    channel_id: int
    sample_index: int
    amplitude: float
    polarity: Literal["negative", "positive"]
    threshold: float
    reference_only: bool = True


class ThresholdCrossingDetector:
    """Streaming crossing detector with per-channel refractory state.

    A sample discontinuity latches a hard coverage fault. The detector will not
    resume until the caller explicitly resets it, so a transport gap cannot be
    hidden as a harmless state reset or represented as a fabricated spike-loss
    count. MAD is estimated independently in each block; this is deterministic
    but not a validated adaptive threshold.
    """

    algorithm_id = "forge.reference.threshold_crossing"
    algorithm_version = "1"

    def __init__(self, config: ThresholdConfig) -> None:
        self.config = config
        self._last_sample: dict[tuple[UUID, int, bytes, int], float] = {}
        self._last_event: dict[tuple[UUID, int, bytes, int], int] = {}
        self._expected_sample_start: dict[tuple[UUID, int, bytes], int] = {}
        self._faulted_streams: set[tuple[UUID, int, bytes]] = set()

    def reset(self) -> None:
        self._last_sample.clear()
        self._last_event.clear()
        self._expected_sample_start.clear()
        self._faulted_streams.clear()

    def process(self, block: SampleBlock) -> tuple[SpikeEvent, ...]:
        stream_key = (block.run_id, block.generation, block.canonical_pod_id)
        expected = self._expected_sample_start.get(stream_key)
        if stream_key in self._faulted_streams:
            raise AnalysisContinuityError(
                algorithm_id=self.algorithm_id,
                expected_sample_start=expected,
                observed_sample_start=block.sample_start,
            )
        if expected is not None and expected != block.sample_start:
            self._faulted_streams.add(stream_key)
            raise AnalysisContinuityError(
                algorithm_id=self.algorithm_id,
                expected_sample_start=expected,
                observed_sample_start=block.sample_start,
            )

        values = np.asarray(block.samples, dtype=np.float64)
        thresholds = self._thresholds(values)
        refractory = int(ceil(self.config.refractory_seconds * block.sample_rate_hz))
        events: list[SpikeEvent] = []

        for column, channel_id in enumerate(block.channel_ids):
            key = (*stream_key, channel_id)
            threshold = float(thresholds[column])
            previous = self._last_sample.get(key)
            last_event = self._last_event.get(key)
            for offset, current_value in enumerate(values[:, column]):
                current = float(current_value)
                if previous is None:
                    previous = current
                    continue
                absolute_sample = block.sample_start + offset
                polarity = self._crossing(previous, current, threshold)
                outside_refractory = last_event is None or absolute_sample - last_event > refractory
                if polarity is not None and outside_refractory:
                    events.append(
                        SpikeEvent(
                            run_id=block.run_id,
                            generation=block.generation,
                            canonical_pod_id=block.canonical_pod_id,
                            pod_slot=block.pod_slot,
                            channel_id=channel_id,
                            sample_index=absolute_sample,
                            amplitude=current,
                            polarity=polarity,
                            threshold=threshold,
                        )
                    )
                    last_event = absolute_sample
                previous = current
            self._last_sample[key] = float(values[-1, column])
            if last_event is not None:
                self._last_event[key] = last_event

        self._expected_sample_start[stream_key] = block.sample_end_exclusive
        return tuple(events)

    def _thresholds(self, values: NDArray[np.float64]) -> NDArray[np.float64]:
        if self.config.threshold is not None:
            return np.full(values.shape[1], self.config.threshold, dtype=np.float64)
        median = np.median(values, axis=0)
        mad = np.median(np.abs(values - median), axis=0)
        robust_sigma = 1.4826 * mad
        # A constant channel must not turn zero numerical noise into events.
        robust_sigma = np.maximum(robust_sigma, np.finfo(np.float64).eps)
        return robust_sigma * float(self.config.mad_multiplier)

    def _crossing(
        self, previous: float, current: float, threshold: float
    ) -> Literal["negative", "positive"] | None:
        negative = previous > -threshold and current <= -threshold
        positive = previous < threshold and current >= threshold
        if self.config.polarity in ("negative", "both") and negative:
            return "negative"
        if self.config.polarity in ("positive", "both") and positive:
            return "positive"
        return None


@dataclass(frozen=True, slots=True)
class TemplateConfig:
    pre_samples: int
    post_samples: int
    minimum_correlation: float = 0.8

    def __post_init__(self) -> None:
        if self.pre_samples < 0 or self.post_samples < 0:
            raise ValueError("template windows must be non-negative")
        if not 0 <= self.minimum_correlation <= 1:
            raise ValueError("minimum_correlation must be in [0, 1]")

    @property
    def length(self) -> int:
        return self.pre_samples + self.post_samples + 1


@dataclass(frozen=True, slots=True)
class SpikeClassification:
    event: SpikeEvent
    label: str | None
    correlation: float | None
    reason: str | None
    reference_only: bool = True


class FixedTemplateClassifier:
    """Classifies complete within-block waveforms by centered correlation."""

    algorithm_id = "forge.reference.fixed_template_correlation"
    algorithm_version = "1"

    def __init__(
        self,
        templates: Mapping[str, Sequence[float]],
        config: TemplateConfig,
    ) -> None:
        if not templates:
            raise ValueError("at least one fixed template is required")
        normalized: dict[str, NDArray[np.float64]] = {}
        for label, template in templates.items():
            array = np.asarray(template, dtype=np.float64)
            if array.ndim != 1 or array.size != config.length:
                raise ValueError(f"template {label!r} must have length {config.length}")
            centered = array - np.mean(array)
            norm = float(np.linalg.norm(centered))
            if not np.isfinite(norm) or norm == 0:
                raise ValueError(f"template {label!r} must contain finite non-constant values")
            frozen = centered / norm
            frozen.setflags(write=False)
            normalized[label] = frozen
        self.config = config
        self._templates = normalized

    def process(
        self, block: SampleBlock, events: Sequence[SpikeEvent]
    ) -> tuple[SpikeClassification, ...]:
        channel_columns = {channel_id: index for index, channel_id in enumerate(block.channel_ids)}
        results: list[SpikeClassification] = []
        for event in events:
            if (
                event.run_id != block.run_id
                or event.generation != block.generation
                or event.canonical_pod_id != block.canonical_pod_id
                or event.pod_slot != block.pod_slot
            ):
                results.append(SpikeClassification(event, None, None, "event_block_identity_mismatch"))
                continue
            column = channel_columns.get(event.channel_id)
            if column is None:
                results.append(SpikeClassification(event, None, None, "channel_not_in_block"))
                continue
            center = event.sample_index - block.sample_start
            start = center - self.config.pre_samples
            stop = center + self.config.post_samples + 1
            if start < 0 or stop > block.sample_count:
                results.append(SpikeClassification(event, None, None, "waveform_crosses_block_edge"))
                continue
            waveform = np.asarray(block.samples[start:stop, column], dtype=np.float64)
            centered = waveform - np.mean(waveform)
            norm = float(np.linalg.norm(centered))
            if norm == 0 or not np.isfinite(norm):
                results.append(SpikeClassification(event, None, None, "constant_or_nonfinite_waveform"))
                continue
            unit = centered / norm
            scores = {label: float(np.dot(unit, template)) for label, template in self._templates.items()}
            label, score = max(scores.items(), key=lambda item: item[1])
            if score < self.config.minimum_correlation:
                results.append(SpikeClassification(event, None, score, "below_minimum_correlation"))
            else:
                results.append(SpikeClassification(event, label, score, None))
        return tuple(results)


@dataclass(frozen=True, slots=True)
class LfpBand:
    name: str
    low_hz: float
    high_hz: float

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("band name cannot be empty")
        if not 0 <= self.low_hz < self.high_hz:
            raise ValueError("band edges must satisfy 0 <= low < high")


@dataclass(frozen=True, slots=True)
class LfpConfig:
    bands: tuple[LfpBand, ...]
    phase_sample: Literal["center", "last"] = "center"
    detrend_mean: bool = True
    taper: Literal["hann", "none"] = "hann"

    def __post_init__(self) -> None:
        if not self.bands:
            raise ValueError("at least one LFP band is required")
        if len({band.name for band in self.bands}) != len(self.bands):
            raise ValueError("LFP band names must be unique")
        if self.phase_sample not in ("center", "last"):
            raise ValueError("phase_sample must be center or last")
        if self.taper not in ("hann", "none"):
            raise ValueError("unsupported taper")


@dataclass(frozen=True, slots=True)
class BandMeasurement:
    run_id: UUID
    generation: int
    canonical_pod_id: bytes
    pod_slot: int
    channel_id: int
    band_name: str
    sample_index: int
    band_power_input_units_squared: float
    phase_radians: float | None
    reference_only: bool = True


@dataclass(frozen=True, slots=True)
class WindowedBandMeasurement:
    """Reference LFP estimate with its exact sample-counter coverage."""

    run_id: UUID
    generation: int
    canonical_pod_id: bytes
    pod_slot: int
    channel_id: int
    band_name: str
    coverage_sample_start: int
    coverage_sample_end_exclusive: int
    sample_index: int
    band_power_input_units_squared: float
    phase_radians: float | None
    reference_only: bool = True


class LfpBandAnalyzer:
    """Already-windowed FFT band-power and analytic phase reference core.

    Phase is sampled from an FFT-domain analytic band reconstruction. It has
    block-edge artifacts and is not suitable for closed-loop timing without a
    separately validated causal filter and latency contract. Do not call this
    core on each 1 ms acquisition block: use ``StreamingLfpBandAnalyzer`` to
    assemble a sample-counter-contiguous analysis window first.
    """

    algorithm_id = "forge.reference.lfp_fft_band_power_phase"
    algorithm_version = "1"

    def __init__(self, config: LfpConfig) -> None:
        self.config = config

    def process(self, block: SampleBlock) -> tuple[BandMeasurement, ...]:
        raw = np.asarray(block.samples, dtype=np.float64)
        phase_offset, estimates = _lfp_spectral_estimates(
            self.config, raw, block.sample_rate_hz
        )
        results: list[BandMeasurement] = []

        for band, band_power, phase_values in estimates:
            for column, channel_id in enumerate(block.channel_ids):
                value = phase_values[column]
                phase = None if abs(value) <= np.finfo(float).eps else float(np.angle(value))
                results.append(
                    BandMeasurement(
                        run_id=block.run_id,
                        generation=block.generation,
                        canonical_pod_id=block.canonical_pod_id,
                        pod_slot=block.pod_slot,
                        channel_id=channel_id,
                        band_name=band.name,
                        sample_index=block.sample_start + phase_offset,
                        band_power_input_units_squared=float(band_power[column]),
                        phase_radians=phase,
                    )
                )
        return tuple(results)


class StreamingLfpBandAnalyzer:
    """Sample-counter-windowed, stateful LFP FFT reference analyzer.

    The accumulator binds to one exact Run/generation/Pod/layout/rate signature
    at a time. An identity change or non-contiguous ``sample_start`` latches a
    hard coverage fault and raises ``AnalysisContinuityError``. Processing may
    resume only after an explicit reset, so no window can silently bridge or
    skip a sample interval. Window and hop lengths are integer sample counts,
    not wall-clock timer durations.

    This remains a non-causal, reference-only FFT benchmark. It is not a
    validated LFP biomarker or a closed-loop filter/latency contract.
    """

    algorithm_id = "forge.reference.streaming_lfp_window_fft_band_power_phase"
    algorithm_version = "1"
    reference_only = True

    def __init__(
        self,
        config: LfpConfig,
        *,
        window_samples: int,
        hop_samples: int | None = None,
    ) -> None:
        if window_samples < 8:
            raise ValueError("window_samples must be at least eight")
        selected_hop = window_samples if hop_samples is None else hop_samples
        if not 1 <= selected_hop <= window_samples:
            raise ValueError("hop_samples must be in [1, window_samples]")
        self.config = config
        self.window_samples = window_samples
        self.hop_samples = selected_hop
        self.reset()

    def reset(self) -> None:
        self._signature: tuple[object, ...] | None = None
        self._expected_sample_start: int | None = None
        self._buffer_start: int | None = None
        self._chunks: list[NDArray[np.int16]] = []
        self._buffered_samples = 0
        self._faulted = False

    def process(self, block: SampleBlock) -> tuple[WindowedBandMeasurement, ...]:
        signature = (
            block.run_id,
            block.generation,
            block.canonical_pod_id,
            block.headstage_id,
            block.pod_slot,
            block.channel_layout_id,
            block.channel_ids,
            block.sample_rate_numerator_hz,
            block.sample_rate_denominator,
        )
        if self._faulted:
            raise AnalysisContinuityError(
                algorithm_id=self.algorithm_id,
                expected_sample_start=self._expected_sample_start,
                observed_sample_start=block.sample_start,
            )
        if self._signature is None:
            self._signature = signature
        elif self._signature != signature:
            self._discard_pending()
            self._faulted = True
            raise AnalysisContinuityError(
                algorithm_id=self.algorithm_id,
                expected_sample_start=self._expected_sample_start,
                observed_sample_start=block.sample_start,
                identity_changed=True,
            )
        if self._expected_sample_start is not None and self._expected_sample_start != block.sample_start:
            self._discard_pending()
            self._faulted = True
            raise AnalysisContinuityError(
                algorithm_id=self.algorithm_id,
                expected_sample_start=self._expected_sample_start,
                observed_sample_start=block.sample_start,
            )

        if self._buffer_start is None:
            self._buffer_start = block.sample_start
        self._chunks.append(np.asarray(block.samples, dtype=np.int16))
        self._buffered_samples += block.sample_count
        self._expected_sample_start = block.sample_end_exclusive

        if self._buffered_samples < self.window_samples:
            return ()

        joined = np.concatenate(self._chunks, axis=0)
        window_offset = 0
        results: list[WindowedBandMeasurement] = []
        assert self._buffer_start is not None
        while joined.shape[0] - window_offset >= self.window_samples:
            coverage_start = self._buffer_start + window_offset
            coverage_end = coverage_start + self.window_samples
            window = np.asarray(
                joined[window_offset : window_offset + self.window_samples, :],
                dtype=np.float64,
            )
            phase_offset, estimates = _lfp_spectral_estimates(
                self.config, window, block.sample_rate_hz
            )
            for band, band_power, phase_values in estimates:
                for column, channel_id in enumerate(block.channel_ids):
                    value = phase_values[column]
                    phase = (
                        None
                        if abs(value) <= np.finfo(float).eps
                        else float(np.angle(value))
                    )
                    results.append(
                        WindowedBandMeasurement(
                            run_id=block.run_id,
                            generation=block.generation,
                            canonical_pod_id=block.canonical_pod_id,
                            pod_slot=block.pod_slot,
                            channel_id=channel_id,
                            band_name=band.name,
                            coverage_sample_start=coverage_start,
                            coverage_sample_end_exclusive=coverage_end,
                            sample_index=coverage_start + phase_offset,
                            band_power_input_units_squared=float(band_power[column]),
                            phase_radians=phase,
                        )
                    )
            window_offset += self.hop_samples

        remaining = np.array(joined[window_offset:, :], dtype=np.int16, copy=True)
        self._chunks = [remaining] if remaining.shape[0] else []
        self._buffered_samples = int(remaining.shape[0])
        self._buffer_start += window_offset
        if not self._chunks:
            self._buffer_start = self._expected_sample_start
        return tuple(results)

    def _discard_pending(self) -> None:
        self._buffer_start = None
        self._chunks = []
        self._buffered_samples = 0


def _lfp_spectral_estimates(
    config: LfpConfig,
    raw: NDArray[np.float64],
    sample_rate_hz: float,
) -> tuple[
    int,
    tuple[tuple[LfpBand, NDArray[np.float64], NDArray[np.complex128]], ...],
]:
    """Return deterministic reference spectra for one complete sample window."""

    sample_count = int(raw.shape[0])
    if sample_count < 8:
        raise ValueError("LFP reference analysis requires at least eight samples")
    nyquist = sample_rate_hz / 2.0
    frequency_step = sample_rate_hz / sample_count
    for band in config.bands:
        if band.high_hz >= nyquist:
            raise ValueError(f"band {band.name!r} must remain below Nyquist ({nyquist:g} Hz)")
        if frequency_step > band.high_hz - band.low_hz:
            raise ValueError(
                f"band {band.name!r} is narrower than the {frequency_step:g} Hz FFT "
                "resolution; accumulate a longer sample window"
            )

    centered = raw - np.mean(raw, axis=0, keepdims=True) if config.detrend_mean else raw
    taper = np.hanning(sample_count) if config.taper == "hann" else np.ones(sample_count)
    tapered = centered * taper[:, None]
    positive_fft = np.fft.rfft(tapered, axis=0)
    frequencies = np.fft.rfftfreq(sample_count, d=1.0 / sample_rate_hz)
    normalization = sample_rate_hz * float(np.sum(taper**2))
    psd = (np.abs(positive_fft) ** 2) / normalization
    if sample_count > 2:
        upper = -1 if sample_count % 2 == 0 else None
        psd[1:upper, :] *= 2.0
    phase_offset = sample_count // 2 if config.phase_sample == "center" else sample_count - 1
    full_fft = np.fft.fft(centered, axis=0)
    full_frequencies = np.fft.fftfreq(sample_count, d=1.0 / sample_rate_hz)
    estimates: list[tuple[LfpBand, NDArray[np.float64], NDArray[np.complex128]]] = []

    for band in config.bands:
        mask = (frequencies >= band.low_hz) & (frequencies <= band.high_hz)
        if not np.any(mask):
            raise ValueError(
                f"band {band.name!r} contains no FFT bin for this window length/sample rate"
            )
        band_power = np.sum(psd[mask, :], axis=0) * frequency_step

        analytic_spectrum = np.zeros_like(full_fft, dtype=np.complex128)
        positive_mask = (full_frequencies >= band.low_hz) & (
            full_frequencies <= band.high_hz
        )
        analytic_spectrum[positive_mask, :] = 2.0 * full_fft[positive_mask, :]
        if band.low_hz == 0:
            analytic_spectrum[0, :] = full_fft[0, :]
        analytic = np.fft.ifft(analytic_spectrum, axis=0)
        estimates.append((band, band_power, analytic[phase_offset, :]))
    return phase_offset, tuple(estimates)
