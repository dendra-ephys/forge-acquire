from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

import forge_protocol_v1 as wire


VECTORS = {
    "marker_payload_v1": wire.MarkerPayloadV1(
        bytes([1]) * 16, 7, wire.MARKER_FLAG_OPERATOR, "baseline", "awake"
    ),
    "fault_payload_v1": wire.FaultPayloadV1(
        bytes([2]) * 16,
        wire.FaultCode.ANALYSIS_DROP,
        wire.FaultSeverity.ERROR,
        wire.FaultLayer.ANALYSIS_WORKER,
        wire.EVENT_FAULT_FLAG_RUN_LATCHED | wire.EVENT_FAULT_FLAG_STIM_DISARMING,
        1,
        "consumer ring full",
    ),
    "gap_payload_v1": wire.GapPayloadV1(
        bytes([3]) * 16,
        wire.GapReason.COUNTER_DISCONTINUITY,
        wire.FaultLayer.RECEIVER_CAPTURE,
        3,
        1,
        1,
        30,
    ),
    "online_analysis_payload_v1": wire.OnlineAnalysisPayloadV1(
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
}


def main() -> None:
    for name, value in VECTORS.items():
        path = ROOT / "golden" / f"{name}.hex"
        encoded = value.to_bytes().hex()
        text = "\n".join(encoded[index : index + 96] for index in range(0, len(encoded), 96)) + "\n"
        path.write_text(text, encoding="ascii", newline="\n")


if __name__ == "__main__":
    main()
