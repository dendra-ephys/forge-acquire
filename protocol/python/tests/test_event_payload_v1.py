from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

import forge_protocol_v1 as wire


def fixtures() -> tuple[object, ...]:
    return (
        wire.MarkerPayloadV1(bytes([1]) * 16, 7, wire.MARKER_FLAG_OPERATOR, "baseline", "awake"),
        wire.FaultPayloadV1(
            bytes([2]) * 16,
            wire.FaultCode.ANALYSIS_DROP,
            wire.FaultSeverity.ERROR,
            wire.FaultLayer.ANALYSIS_WORKER,
            wire.EVENT_FAULT_FLAG_RUN_LATCHED | wire.EVENT_FAULT_FLAG_STIM_DISARMING,
            1,
            "consumer ring full",
        ),
        wire.GapPayloadV1(
            bytes([3]) * 16,
            wire.GapReason.COUNTER_DISCONTINUITY,
            wire.FaultLayer.RECEIVER_CAPTURE,
            3,
            1,
            1,
            30,
        ),
        wire.OnlineAnalysisPayloadV1(
            bytes([4]) * 16,
            bytes([5]) * 16,
            bytes([6]) * 32,
            bytes([7]) * 32,
            bytes([8]) * 32,
            bytes([9]) * 32,
            11,
            2,
            wire.ANALYSIS_FLAG_REFERENCE_ONLY,
            b'{"score":1}',
        ),
    )


class EventPayloadV1Tests(unittest.TestCase):
    def test_idl_hash_is_frozen(self) -> None:
        idl = Path(__file__).parents[2] / "schema" / "forge_event_payload_v1.idl"
        normalized = idl.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
        self.assertEqual(hashlib.sha256(normalized.encode()).digest(), wire.EVENT_PAYLOAD_HASH)

    def test_all_payloads_round_trip_and_reject_every_truncation(self) -> None:
        names = ("marker", "fault", "gap", "online_analysis")
        golden_root = Path(__file__).parents[2] / "golden"
        for name, value in zip(names, fixtures(), strict=True):
            encoded = value.to_bytes()
            golden = bytes.fromhex((golden_root / f"{name}_payload_v1.hex").read_text())
            self.assertEqual(encoded, golden)
            self.assertEqual(wire.decode_event_payload(encoded), value)
            for length in range(len(encoded)):
                with self.assertRaises(wire.EventPayloadError):
                    wire.decode_event_payload(encoded[:length])

    def test_hash_flags_utf8_and_reserved_mutations_are_rejected(self) -> None:
        marker = bytearray(fixtures()[0].to_bytes())
        for offset, expected in ((24, "contract_hash"), (96, "reserved"), (104, "utf8")):
            corrupted = marker.copy()
            corrupted[offset] ^= 0xFF if offset == 104 else 1
            with self.assertRaises(wire.EventPayloadError) as caught:
                wire.decode_event_payload(bytes(corrupted))
            self.assertEqual(caught.exception.code, expected)


if __name__ == "__main__":
    unittest.main()
