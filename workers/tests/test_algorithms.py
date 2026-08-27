from __future__ import annotations

import dataclasses
import unittest
from uuid import UUID

import numpy as np

from forge_workers.algorithms import (
    AnalysisContinuityError,
    FixedTemplateClassifier,
    LfpBand,
    LfpBandAnalyzer,
    LfpConfig,
    StreamingLfpBandAnalyzer,
    TemplateConfig,
    ThresholdConfig,
    ThresholdCrossingDetector,
)
from forge_workers.sdk import AnalysisAnnotation, SampleBlock
from forge_workers.journal import pod_slot_for
from forge_workers.synthetic_oracle import (
    DEFAULT_SYNTHETIC_SEED,
    SYNTHETIC_SPIKE_TEMPLATE,
    build_synthetic_composite_fixture,
    composite_int16_sample,
    lfp_triangle_sample,
    negative_threshold_crossings,
    spike_template_sample,
    xorshift_noise_sample,
)

from helpers import POD_ID, make_analysis_block


RUN_ID = UUID("11111111-2222-3333-4444-555555555555")
FORBIDDEN_COMMAND_FIELDS = {
    "register",
    "register_address",
    "device_command",
    "command_bytes",
    "write_register",
}


def keys_recursively(value: object) -> set[str]:
    if dataclasses.is_dataclass(value):
        return keys_recursively(dataclasses.asdict(value))
    if isinstance(value, dict):
        result = {str(key).casefold() for key in value}
        for item in value.values():
            result.update(keys_recursively(item))
        return result
    if isinstance(value, (tuple, list)):
        result: set[str] = set()
        for item in value:
            result.update(keys_recursively(item))
        return result
    return set()


class ReferenceAlgorithmTests(unittest.TestCase):
    def test_threshold_and_fixed_template_are_deterministic_reference_outputs(self) -> None:
        waveform = np.array([0, 0, -1, -4, -10, -4, -1, 0, 0], dtype=np.int16)
        block = make_analysis_block(
            tuple((int(value),) for value in waveform),
            run_id=RUN_ID,
            generation=3,
            sample_start=100,
            channel_ids=(7,),
        )
        detector = ThresholdCrossingDetector(
            ThresholdConfig(threshold=5.0, mad_multiplier=None, refractory_seconds=0)
        )
        events = detector.process(block)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].sample_index, 104)
        self.assertTrue(events[0].reference_only)

        classifier = FixedTemplateClassifier(
            {"fixture_spike": [-1, -4, -10, -4, -1]},
            TemplateConfig(pre_samples=2, post_samples=2, minimum_correlation=0.99),
        )
        classified = classifier.process(block, events)
        self.assertEqual(classified[0].label, "fixture_spike")
        self.assertAlmostEqual(classified[0].correlation or 0, 1.0, places=12)
        self.assertTrue(classified[0].reference_only)
        self.assertFalse(keys_recursively((events, classified)) & FORBIDDEN_COMMAND_FIELDS)

    def test_detector_latches_hard_fault_at_sample_gap(self) -> None:
        detector = ThresholdCrossingDetector(
            ThresholdConfig(threshold=5.0, mad_multiplier=None, refractory_seconds=0)
        )
        first = make_analysis_block(
            ((0,), (0,)), run_id=RUN_ID, generation=1, record_sequence=0
        )
        gap = make_analysis_block(
            ((-10,), (-10,)),
            run_id=RUN_ID,
            generation=1,
            record_sequence=1,
            sample_start=10,
        )
        self.assertEqual(detector.process(first), ())
        # A gap invalidates detector coverage. It cannot be converted into a
        # guessed event-loss count or a silent state reset.
        with self.assertRaisesRegex(
            AnalysisContinuityError, r"unprocessed sample range \[2, 10\)"
        ):
            detector.process(gap)
        with self.assertRaises(AnalysisContinuityError):
            detector.process(gap)
        detector.reset()
        self.assertEqual(detector.process(gap), ())

    def test_lfp_band_power_separates_fixture_tone_and_phase_is_finite(self) -> None:
        sample_rate = 1_000.0
        time = np.arange(2_000) / sample_rate
        values = np.rint(1_000 * np.sin(2 * np.pi * 10 * time)).astype(np.int16)
        block = make_analysis_block(
            tuple((int(value),) for value in values),
            run_id=RUN_ID,
            generation=1,
            sample_rate_numerator_hz=1_000,
            channel_ids=(4,),
        )
        analyzer = LfpBandAnalyzer(
            LfpConfig(
                bands=(LfpBand("alpha_fixture", 8, 12), LfpBand("off_fixture", 30, 40)),
                phase_sample="center",
            )
        )
        measurements = analyzer.process(block)
        by_band = {measurement.band_name: measurement for measurement in measurements}
        self.assertGreater(
            by_band["alpha_fixture"].band_power_input_units_squared,
            by_band["off_fixture"].band_power_input_units_squared * 1_000,
        )
        self.assertIsNotNone(by_band["alpha_fixture"].phase_radians)
        self.assertTrue(np.isfinite(by_band["alpha_fixture"].phase_radians))
        self.assertFalse(keys_recursively(measurements) & FORBIDDEN_COMMAND_FIELDS)

    def test_streaming_lfp_accumulates_1ms_blocks_and_is_chunking_invariant(self) -> None:
        fine = build_synthetic_composite_fixture(
            sample_start=0,
            sample_end_exclusive=30_000,
            block_samples=30,
            channel_ids=(0,),
        )
        coarse = build_synthetic_composite_fixture(
            sample_start=0,
            sample_end_exclusive=30_000,
            block_samples=997,
            channel_ids=(0,),
        )
        self.assertEqual(len(fine.blocks), 1_000)
        self.assertTrue(all(block.sample_count == 30 for block in fine.blocks))
        np.testing.assert_array_equal(
            np.concatenate([block.samples for block in fine.blocks], axis=0),
            np.concatenate([block.samples for block in coarse.blocks], axis=0),
        )

        config = LfpConfig(
            bands=(LfpBand("eight_hz", 7.5, 8.5), LfpBand("ten_hz", 9.5, 10.5)),
            phase_sample="center",
        )
        with self.assertRaisesRegex(ValueError, "accumulate a longer sample window"):
            LfpBandAnalyzer(config).process(fine.blocks[0])
        fine_analyzer = StreamingLfpBandAnalyzer(config, window_samples=30_000)
        fine_measurements = []
        for block in fine.blocks[:-1]:
            self.assertEqual(fine_analyzer.process(block), ())
        fine_measurements.extend(fine_analyzer.process(fine.blocks[-1]))

        coarse_analyzer = StreamingLfpBandAnalyzer(config, window_samples=30_000)
        coarse_measurements = tuple(
            measurement
            for block in coarse.blocks
            for measurement in coarse_analyzer.process(block)
        )
        self.assertEqual(tuple(fine_measurements), coarse_measurements)
        by_band = {measurement.band_name: measurement for measurement in fine_measurements}
        self.assertEqual(set(by_band), {"eight_hz", "ten_hz"})
        self.assertGreater(
            by_band["eight_hz"].band_power_input_units_squared,
            by_band["ten_hz"].band_power_input_units_squared * 100,
        )
        for measurement in fine_measurements:
            self.assertEqual(measurement.coverage_sample_start, 0)
            self.assertEqual(measurement.coverage_sample_end_exclusive, 30_000)
            self.assertEqual(measurement.sample_index, 15_000)
            self.assertTrue(measurement.reference_only)
            self.assertIsNotNone(measurement.phase_radians)
            self.assertTrue(np.isfinite(measurement.phase_radians))

    def test_streaming_lfp_latches_hard_fault_at_sample_gap(self) -> None:
        before_gap = build_synthetic_composite_fixture(
            sample_start=0,
            sample_end_exclusive=15_000,
            block_samples=30,
        )
        after_gap = build_synthetic_composite_fixture(
            sample_start=20_000,
            sample_end_exclusive=35_000,
            block_samples=30,
        )
        analyzer = StreamingLfpBandAnalyzer(
            LfpConfig(bands=(LfpBand("eight_hz", 7.5, 8.5),)),
            window_samples=30_000,
        )
        for block in before_gap.blocks:
            self.assertEqual(analyzer.process(block), ())
        with self.assertRaisesRegex(
            AnalysisContinuityError, r"unprocessed sample range \[15000, 20000\)"
        ):
            analyzer.process(after_gap.blocks[0])
        with self.assertRaises(AnalysisContinuityError):
            analyzer.process(after_gap.blocks[0])
        analyzer.reset()
        self.assertEqual(analyzer.process(after_gap.blocks[0]), ())

    def test_integer_composite_oracle_detects_cross_block_spikes_and_gap_fault(self) -> None:
        fixture = build_synthetic_composite_fixture(
            sample_start=0,
            sample_end_exclusive=90,
            block_samples=30,
            channel_ids=(0, 1),
        )
        self.assertEqual(
            (
                fixture.oracle.coverage_sample_start,
                fixture.oracle.coverage_sample_end_exclusive,
            ),
            (0, 90),
        )
        self.assertEqual(fixture.oracle.scenario_id, "forge.synthetic.neural.integer.v1")
        self.assertEqual(tuple(block.sample_count for block in fixture.blocks), (30, 30, 30))
        first_truth = fixture.oracle.spikes[0]
        self.assertLess(first_truth.template_start_sample, 30)
        self.assertGreater(first_truth.template_end_exclusive, 30)

        threshold = 20_000
        detector = ThresholdCrossingDetector(
            ThresholdConfig(threshold=threshold, mad_multiplier=None, refractory_seconds=0)
        )
        observed = tuple(
            event
            for block in fixture.blocks
            for event in detector.process(block)
        )
        self.assertEqual(
            tuple(sorted((event.sample_index, event.channel_id) for event in observed)),
            tuple(
                (truth.sample_index, truth.channel_id)
                for truth in negative_threshold_crossings(
                    fixture.oracle, threshold=threshold
                )
            ),
        )
        self.assertTrue(
            all(
                fixture.oracle.coverage_sample_start
                <= event.sample_index
                < fixture.oracle.coverage_sample_end_exclusive
                for event in observed
            )
        )

        detector.reset()
        before_gap = build_synthetic_composite_fixture(
            sample_start=0,
            sample_end_exclusive=24,
            block_samples=24,
        )
        starts_on_spike_center = build_synthetic_composite_fixture(
            sample_start=29,
            sample_end_exclusive=36,
            block_samples=7,
        )
        self.assertEqual(detector.process(before_gap.blocks[0]), ())
        with self.assertRaisesRegex(
            AnalysisContinuityError, r"unprocessed sample range \[24, 29\)"
        ):
            detector.process(starts_on_spike_center.blocks[0])

    def test_integer_composite_formula_has_stable_cross_language_goldens(self) -> None:
        self.assertEqual(DEFAULT_SYNTHETIC_SEED, 9)
        self.assertEqual(
            SYNTHETIC_SPIKE_TEMPLATE,
            (0, -256, -1_024, -4_096, -16_000, -40_000, -16_000, -4_096, -1_024, -256, 0),
        )
        expected = (
            (0, 0, -2_048, 59, 0, -1_989),
            (1, 0, -2_046, 52, 0, -1_994),
            (29, 0, -1_985, -46, -40_000, -32_768),
            (30, 0, -1_983, 23, -16_000, -17_960),
            (82, 1, -1_614, -44, -40_000, -32_768),
            (3_000, 0, -409, 53, 0, -356),
            (4_294_967_303, 1, 858, 38, 0, 896),
        )
        observed = tuple(
            (
                sample,
                channel,
                lfp_triangle_sample(sample, channel),
                xorshift_noise_sample(sample, channel),
                spike_template_sample(sample, channel),
                composite_int16_sample(sample, channel),
            )
            for sample, channel, *_ in expected
        )
        self.assertEqual(observed, expected)

        boundary = build_synthetic_composite_fixture(
            sample_start=29,
            sample_end_exclusive=30,
            block_samples=1,
        )
        self.assertEqual(boundary.blocks[0].sample_block_flags, 0x01)
        self.assertEqual(
            tuple((event.center_sample, event.template_start_sample, event.template_end_exclusive)
                  for event in boundary.oracle.spikes),
            ((29, 24, 35),),
        )

    def test_annotation_rejects_direct_device_command_fields(self) -> None:
        with self.assertRaises(ValueError):
            AnalysisAnnotation(
                worker_id="fixture",
                algorithm_id="fixture",
                algorithm_version="1",
                run_id=RUN_ID,
                generation=1,
                canonical_pod_id=POD_ID,
                pod_slot=pod_slot_for(POD_ID),
                sample_index=0,
                channel_id=0,
                kind="fixture",
                values={"register_address": 42},
            )


if __name__ == "__main__":
    unittest.main()
