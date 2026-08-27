from __future__ import annotations

import struct
import unittest
from pathlib import Path

from forge_workers._protocol import protocol
from forge_workers.nwb_receipt import (
    NWB_RECEIPT_LEN,
    PUBLICATION_AUTHORIZED,
    NwbGenerationValidationReceiptV1,
    NwbReceiptError,
)


GOLDEN = (
    Path(__file__).resolve().parents[1]
    / "golden"
    / "nwb_generation_validation_receipt_v1.hex"
)


def _golden() -> bytes:
    return bytes.fromhex(GOLDEN.read_text(encoding="ascii"))


def _with_crc(mutated: bytearray) -> bytes:
    struct.pack_into("<I", mutated, 540, protocol.crc32c(mutated[:540]))
    return bytes(mutated)


class NwbReceiptContractTests(unittest.TestCase):
    def test_golden_receipt_round_trips_exactly(self) -> None:
        encoded = _golden()
        self.assertEqual(len(encoded), NWB_RECEIPT_LEN)
        receipt = NwbGenerationValidationReceiptV1.from_bytes(encoded)
        self.assertEqual(receipt.to_bytes(), encoded)
        self.assertEqual(receipt.checked_blocks, 4)
        self.assertEqual(receipt.total_samples, 240)
        self.assertFalse(receipt.validation_flags & PUBLICATION_AUTHORIZED)

    def test_every_truncation_and_byte_mutation_is_rejected(self) -> None:
        encoded = _golden()
        for length in range(len(encoded)):
            with self.subTest(length=length), self.assertRaises(NwbReceiptError):
                NwbGenerationValidationReceiptV1.from_bytes(encoded[:length])
        for offset in range(len(encoded)):
            mutated = bytearray(encoded)
            mutated[offset] ^= 0x80
            with self.subTest(offset=offset), self.assertRaises(NwbReceiptError):
                NwbGenerationValidationReceiptV1.from_bytes(bytes(mutated))

    def test_crc_valid_semantic_mutations_remain_fail_closed(self) -> None:
        cases: list[tuple[str, int, bytes]] = []
        flags = bytearray(_golden())
        struct.pack_into(
            "<I",
            flags,
            12,
            struct.unpack_from("<I", flags, 12)[0] | PUBLICATION_AUTHORIZED,
        )
        cases.append(("publication", 12, _with_crc(flags)))

        errors = bytearray(_golden())
        struct.pack_into("<I", errors, 88, 1)
        cases.append(("schema_error", 88, _with_crc(errors)))

        protocol_hash = bytearray(_golden())
        protocol_hash[104] ^= 1
        cases.append(("protocol_hash", 104, _with_crc(protocol_hash)))

        contract_hash = bytearray(_golden())
        contract_hash[136] ^= 1
        cases.append(("contract_hash", 136, _with_crc(contract_hash)))

        reserved = bytearray(_golden())
        reserved[528] = 1
        cases.append(("reserved", 528, _with_crc(reserved)))

        for name, _, encoded in cases:
            with self.subTest(name=name), self.assertRaises(NwbReceiptError):
                NwbGenerationValidationReceiptV1.from_bytes(encoded)


if __name__ == "__main__":
    unittest.main()
