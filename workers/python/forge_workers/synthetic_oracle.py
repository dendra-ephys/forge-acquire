"""Cross-language deterministic composite neural-stream reference fixture.

The formulas in this module intentionally use only explicitly bounded integer
operations over absolute sample counters and channel IDs. They do not use a
wall clock, a process-global pseudo-random generator, or floating-point signal
generation. Rust, TypeScript, and Python implementations can therefore share
byte-for-byte int16 goldens.

This is test infrastructure only. It is not a physiological signal model or a
validated scientific simulator.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

import numpy as np

from .journal import pod_slot_for
from .sdk import SampleBlock


U32_MASK = 0xFFFF_FFFF
U64_MASK = 0xFFFF_FFFF_FFFF_FFFF
SYNTHETIC_SCENARIO_ID = "forge.synthetic.neural.integer.v1"
SYNTHETIC_SAMPLE_RATE_HZ = 30_000
SYNTHETIC_LFP_HZ = 8
SYNTHETIC_LFP_PEAK = 2_048
SYNTHETIC_NOISE_MODULUS = 129
SYNTHETIC_NOISE_HALF_RANGE = 64
DEFAULT_SYNTHETIC_SEED = 9
SYNTHETIC_SPIKE_TEMPLATE = (
    0,
    -256,
    -1_024,
    -4_096,
    -16_000,
    -40_000,
    -16_000,
    -4_096,
    -1_024,
    -256,
    0,
)
SYNTHETIC_SPIKE_CENTER_OFFSET = 5
SYNTHETIC_SPIKE_FIRST_CENTER = 29
SYNTHETIC_SPIKE_CHANNEL_STRIDE = 53
SYNTHETIC_RUN_ID = UUID("94f4477e-7983-4b52-a7ef-2ea5da99ea5e")
SYNTHETIC_POD_ID = bytes.fromhex("303132333435363738393a3b3c3d3e3f")
SYNTHETIC_HEADSTAGE_ID = bytes.fromhex("404142434445464748494a4b4c4d4e4f")


@dataclass(frozen=True, slots=True)
class SyntheticSpikeTruth:
    channel_id: int
    center_sample: int
    template_start_sample: int
    template_end_exclusive: int
    reference_only: bool = True


@dataclass(frozen=True, slots=True)
class SyntheticThresholdCrossingTruth:
    channel_id: int
    sample_index: int
    amplitude: int
    threshold: int
    reference_only: bool = True


@dataclass(frozen=True, slots=True)
class SyntheticOracle:
    """Independent truth for a fully covered synthetic sample-counter range."""

    scenario_id: str
    seed: int
    sample_rate_hz: int
    channel_ids: tuple[int, ...]
    coverage_sample_start: int
    coverage_sample_end_exclusive: int
    spikes: tuple[SyntheticSpikeTruth, ...]
    reference_only: bool = True


@dataclass(frozen=True, slots=True)
class SyntheticCompositeFixture:
    blocks: tuple[SampleBlock, ...]
    oracle: SyntheticOracle
    reference_only: bool = True


def lfp_triangle_sample(
    absolute_sample: int,
    channel_id: int,
    *,
    sample_rate_hz: int = SYNTHETIC_SAMPLE_RATE_HZ,
) -> int:
    """Return the frozen 8 Hz integer triangle component.

    ``phase = ((sample % fs) * 8 + channel * floor(fs / 32)) % fs``
    and all divisions below are floors over non-negative integers.
    """

    _validate_coordinates(absolute_sample, channel_id, sample_rate_hz)
    phase = (
        (absolute_sample % sample_rate_hz) * SYNTHETIC_LFP_HZ
        + channel_id * (sample_rate_hz // 32)
    ) % sample_rate_hz
    if phase * 2 < sample_rate_hz:
        return -SYNTHETIC_LFP_PEAK + (8_192 * phase) // sample_rate_hz
    return 6_144 - (8_192 * phase) // sample_rate_hz


def xorshift_noise_sample(
    absolute_sample: int,
    channel_id: int,
    *,
    seed: int = DEFAULT_SYNTHETIC_SEED,
) -> int:
    """Return frozen bounded noise in [-64, 64] using unsigned u32 math."""

    _validate_coordinates(absolute_sample, channel_id, SYNTHETIC_SAMPLE_RATE_HZ)
    if not 0 <= seed <= U64_MASK:
        raise ValueError("seed must fit unsigned 64-bit")
    seed_lo = seed & U32_MASK
    seed_hi = (seed >> 32) & U32_MASK
    sample_lo = absolute_sample & U32_MASK
    sample_hi = (absolute_sample >> 32) & U32_MASK
    x = (
        seed_lo
        ^ _rotl32(seed_hi, 16)
        ^ ((sample_lo * 0x9E37_79B9) & U32_MASK)
        ^ ((sample_hi * 0x85EB_CA6B) & U32_MASK)
        ^ ((channel_id * 0xC2B2_AE35) & U32_MASK)
        ^ 0xA341_316C
    ) & U32_MASK
    x ^= (x << 13) & U32_MASK
    x &= U32_MASK
    x ^= x >> 17
    x &= U32_MASK
    x ^= (x << 5) & U32_MASK
    x &= U32_MASK
    return int(x % SYNTHETIC_NOISE_MODULUS) - SYNTHETIC_NOISE_HALF_RANGE


def spike_template_sample(
    absolute_sample: int,
    channel_id: int,
    *,
    sample_rate_hz: int = SYNTHETIC_SAMPLE_RATE_HZ,
) -> int:
    """Return the fixed 11-point negative spike component for one sample."""

    _validate_coordinates(absolute_sample, channel_id, sample_rate_hz)
    period = max(sample_rate_hz // 10, 64)
    first_center = SYNTHETIC_SPIKE_FIRST_CENTER + SYNTHETIC_SPIKE_CHANNEL_STRIDE * channel_id
    first_start = first_center - SYNTHETIC_SPIKE_CENTER_OFFSET
    if absolute_sample < first_start:
        return 0
    template_index = (absolute_sample - first_start) % period
    if template_index >= len(SYNTHETIC_SPIKE_TEMPLATE):
        return 0
    return SYNTHETIC_SPIKE_TEMPLATE[template_index]


def composite_int16_sample(
    absolute_sample: int,
    channel_id: int,
    *,
    seed: int = DEFAULT_SYNTHETIC_SEED,
    sample_rate_hz: int = SYNTHETIC_SAMPLE_RATE_HZ,
) -> int:
    """Sum LFP, spike, and noise in i32 and saturate to signed int16."""

    value = (
        lfp_triangle_sample(absolute_sample, channel_id, sample_rate_hz=sample_rate_hz)
        + spike_template_sample(absolute_sample, channel_id, sample_rate_hz=sample_rate_hz)
        + xorshift_noise_sample(absolute_sample, channel_id, seed=seed)
    )
    return min(32_767, max(-32_768, value))


def build_synthetic_composite_fixture(
    *,
    sample_start: int,
    sample_end_exclusive: int,
    block_samples: int = 30,
    channel_ids: tuple[int, ...] = (0,),
    seed: int = DEFAULT_SYNTHETIC_SEED,
    run_id: UUID = SYNTHETIC_RUN_ID,
    generation: int = 1,
) -> SyntheticCompositeFixture:
    """Build deterministic canonical analysis blocks plus independent truth.

    Oracle event centers follow the same end-exclusive range rule as Rust and
    TypeScript. Template support may extend beyond that range and remains
    explicit in each truth item. ``block_samples`` changes transport chunking
    only; it cannot change any generated sample value.
    """

    if not 0 <= sample_start < sample_end_exclusive <= U64_MASK:
        raise ValueError("sample coverage must be a nonempty unsigned 64-bit range")
    if block_samples <= 0:
        raise ValueError("block_samples must be positive")
    if not channel_ids or len(set(channel_ids)) != len(channel_ids):
        raise ValueError("channel_ids must be nonempty and unique")
    if any(not 0 <= channel <= 0xFFFF for channel in channel_ids):
        raise ValueError("channel IDs must fit the shared unsigned 16-bit domain")
    if not 0 <= seed <= U64_MASK:
        raise ValueError("seed must fit unsigned 64-bit")
    if generation < 0:
        raise ValueError("generation must be non-negative")

    blocks: list[SampleBlock] = []
    cursor = sample_start
    sequence = 0
    while cursor < sample_end_exclusive:
        block_end = min(cursor + block_samples, sample_end_exclusive)
        values = np.empty((block_end - cursor, len(channel_ids)), dtype=np.int16)
        for offset, absolute_sample in enumerate(range(cursor, block_end)):
            for column, channel_id in enumerate(channel_ids):
                values[offset, column] = composite_int16_sample(
                    absolute_sample,
                    channel_id,
                    seed=seed,
                    sample_rate_hz=SYNTHETIC_SAMPLE_RATE_HZ,
                )
        blocks.append(
            SampleBlock(
                run_id=run_id,
                generation=generation,
                canonical_pod_id=SYNTHETIC_POD_ID,
                headstage_id=SYNTHETIC_HEADSTAGE_ID,
                pod_slot=pod_slot_for(SYNTHETIC_POD_ID),
                journal_sequence=sequence,
                record_sequence=sequence,
                frame_start=sequence,
                frame_end_exclusive=sequence + 1,
                sample_start=cursor,
                sample_end_exclusive=block_end,
                global_time_start_ns=(cursor * 1_000_000_000) // SYNTHETIC_SAMPLE_RATE_HZ,
                global_time_end_exclusive_ns=(
                    block_end * 1_000_000_000
                )
                // SYNTHETIC_SAMPLE_RATE_HZ,
                channel_layout_id=1,
                channel_ids=channel_ids,
                sample_rate_numerator_hz=SYNTHETIC_SAMPLE_RATE_HZ,
                sample_rate_denominator=1,
                record_flags=0,
                # Complete software fixture; never claim hardware timestamping.
                sample_block_flags=0x01,
                samples=values,
            )
        )
        cursor = block_end
        sequence += 1

    oracle = SyntheticOracle(
        scenario_id=SYNTHETIC_SCENARIO_ID,
        seed=seed,
        sample_rate_hz=SYNTHETIC_SAMPLE_RATE_HZ,
        channel_ids=channel_ids,
        coverage_sample_start=sample_start,
        coverage_sample_end_exclusive=sample_end_exclusive,
        spikes=_spike_truth_for_coverage(sample_start, sample_end_exclusive, channel_ids),
    )
    return SyntheticCompositeFixture(tuple(blocks), oracle)


def negative_threshold_crossings(
    oracle: SyntheticOracle,
    *,
    threshold: int,
    refractory_samples: int = 0,
) -> tuple[SyntheticThresholdCrossingTruth, ...]:
    """Derive detector truth for an explicit negative threshold configuration."""

    if threshold <= 0:
        raise ValueError("threshold must be positive")
    if refractory_samples < 0:
        raise ValueError("refractory_samples must be non-negative")
    results: list[SyntheticThresholdCrossingTruth] = []
    for channel_id in oracle.channel_ids:
        previous: int | None = None
        last_event: int | None = None
        for absolute_sample in range(
            oracle.coverage_sample_start, oracle.coverage_sample_end_exclusive
        ):
            current = composite_int16_sample(
                absolute_sample,
                channel_id,
                seed=oracle.seed,
                sample_rate_hz=oracle.sample_rate_hz,
            )
            if (
                previous is not None
                and previous > -threshold
                and current <= -threshold
                and (
                    last_event is None
                    or absolute_sample - last_event > refractory_samples
                )
            ):
                results.append(
                    SyntheticThresholdCrossingTruth(
                        channel_id=channel_id,
                        sample_index=absolute_sample,
                        amplitude=current,
                        threshold=threshold,
                    )
                )
                last_event = absolute_sample
            previous = current
    return tuple(sorted(results, key=lambda event: (event.sample_index, event.channel_id)))


def _spike_truth_for_coverage(
    sample_start: int,
    sample_end_exclusive: int,
    channel_ids: tuple[int, ...],
) -> tuple[SyntheticSpikeTruth, ...]:
    period = max(SYNTHETIC_SAMPLE_RATE_HZ // 10, 64)
    truths: list[SyntheticSpikeTruth] = []
    for channel_id in channel_ids:
        first_center = SYNTHETIC_SPIKE_FIRST_CENTER + SYNTHETIC_SPIKE_CHANNEL_STRIDE * channel_id
        event_index = max(0, (sample_start - first_center + period - 1) // period)
        center = first_center + event_index * period
        while center < sample_end_exclusive:
            template_start = center - SYNTHETIC_SPIKE_CENTER_OFFSET
            template_end = template_start + len(SYNTHETIC_SPIKE_TEMPLATE)
            truths.append(
                SyntheticSpikeTruth(
                    channel_id=channel_id,
                    center_sample=center,
                    template_start_sample=template_start,
                    template_end_exclusive=template_end,
                )
            )
            center += period
    return tuple(sorted(truths, key=lambda truth: (truth.center_sample, truth.channel_id)))


def _rotl32(value: int, count: int) -> int:
    count &= 31
    return ((value << count) | (value >> ((32 - count) & 31))) & U32_MASK


def _validate_coordinates(absolute_sample: int, channel_id: int, sample_rate_hz: int) -> None:
    if not 0 <= absolute_sample <= U64_MASK:
        raise ValueError("absolute_sample must fit unsigned 64-bit")
    if not 0 <= channel_id <= 0xFFFF:
        raise ValueError("channel_id must fit the shared unsigned 16-bit domain")
    if not 0 < sample_rate_hz <= U32_MASK:
        raise ValueError("sample_rate_hz must fit unsigned 32-bit")
