from __future__ import annotations

import unittest
from uuid import UUID

from forge_workers._protocol import protocol
from forge_workers.sdk import BoundedConsumer, FrozenStimIntentContext

from helpers import make_analysis_block


RUN_ID = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


def frozen_context(run_id: UUID = RUN_ID) -> FrozenStimIntentContext:
    return FrozenStimIntentContext(
        run_id=run_id.bytes,
        source_worker_id=b"W" * 16,
        control_token_id=b"T" * 16,
        algorithm_hash=b"A" * 32,
        config_hash=b"C" * 32,
        template_hash=b"P" * 32,
        channel_map_hash=b"M" * 32,
    )


class SdkSafetyTests(unittest.TestCase):
    def test_bounded_consumer_rejects_newest_without_waiting(self) -> None:
        queue = BoundedConsumer[int](capacity=2)
        self.assertTrue(queue.offer(1))
        self.assertTrue(queue.offer(2))
        self.assertFalse(queue.offer(3))
        self.assertEqual(queue.dropped, 1)
        self.assertEqual(queue.poll(), 1)
        self.assertEqual(queue.poll(), 2)
        self.assertIsNone(queue.poll())

    def test_intent_factory_rejects_sample_outside_canonical_block(self) -> None:
        block = make_analysis_block(((1,), (2,)), run_id=RUN_ID, sample_start=100)
        with self.assertRaisesRegex(ValueError, "outside"):
            frozen_context().propose(
                block,
                source_sample_counter=99,
                source_global_time_ns=500,
                target_channel=4,
                template_id=1,
                deadline_global_time_ns=1_000,
                intent_nonce=b"N" * 16,
            )

    def test_worker_emits_only_protocol_stim_intent_v1(self) -> None:
        block = make_analysis_block(((1,), (2,)), run_id=RUN_ID, sample_start=100)
        intent = frozen_context().propose(
            block,
            source_sample_counter=101,
            source_global_time_ns=500,
            target_channel=4,
            template_id=1,
            deadline_global_time_ns=1_000,
            intent_nonce=b"N" * 16,
        )
        self.assertIsInstance(intent, protocol.StimIntentV1)
        self.assertEqual(intent.source_record_sequence, block.record_sequence)
        self.assertEqual(protocol.StimIntentV1.from_bytes(intent.to_bytes()), intent)
        self.assertFalse(hasattr(intent, "execute"))
        self.assertFalse(hasattr(intent, "write_register"))
        import forge_workers.sdk as sdk

        self.assertFalse(hasattr(sdk, "StimulationSafetyGate"))
        self.assertFalse(hasattr(sdk, "AuthorizedStimulationIntent"))


if __name__ == "__main__":
    unittest.main()
