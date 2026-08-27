"""Frozen binary receipt for a successfully validated NWB generation.

This contract is separate from the M0 host/device protocol so existing journal
records keep their frozen protocol hash.  A validation receipt is evidence for
the Rust publisher to verify; it never authorizes publication by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

from ._protocol import protocol


RECEIPT_MAGIC = b"FGRNWB01"
RECEIPT_VERSION = 1
NWB_RECEIPT_LEN = 544
RECEIPT_CONTRACT_HASH_HEX = (
    "6dfd2230e735b844c6d031aa9a19aa86a14efb98ec54e2076627a76eb4f72f93"
)
RECEIPT_CONTRACT_HASH = bytes.fromhex(RECEIPT_CONTRACT_HASH_HEX)

JOURNAL_SEALED = 0x0000_0001
JOURNAL_DURABLE_TO_EXPECTED_LAST = 0x0000_0002
NWB_CLOSED = 0x0000_0004
UNCOMPRESSED = 0x0000_0008
SCHEMA_VALID = 0x0000_0010
INSPECTOR_NO_CRITICAL = 0x0000_0020
PROVENANCE_RECONCILED = 0x0000_0040
NEW_GENERATION_ONLY = 0x0000_0080
PUBLICATION_AUTHORIZED = 0x0000_0100
VALIDATION_FLAGS_ALL = 0x0000_01FF
REQUIRED_VALIDATION_FLAGS = 0x0000_00FF
EMPTY_EXPECTED_LAST = 0xFFFF_FFFF_FFFF_FFFF


class NwbReceiptError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class NwbGenerationValidationReceiptV1:
    validation_flags: int
    run_id: bytes
    generation: int
    pod_count: int
    expected_last_journal_sequence: int
    checked_blocks: int
    total_samples: int
    validated_at_unix_ns: int
    journal_bytes: int
    nwb_bytes: int
    schema_error_count: int
    inspector_critical_count: int
    reconciliation_error_count: int
    host_protocol_hash: bytes
    receipt_contract_hash: bytes
    journal_sha256: bytes
    journal_seal_sha256: bytes
    durable_checkpoint_set_sha256: bytes
    nwb_sha256: bytes
    schema_plan_sha256: bytes
    dependency_lock_sha256: bytes
    materializer_build_sha256: bytes
    validation_report_sha256: bytes
    samples_manifest_sha256: bytes
    session_manifest_sha256: bytes
    run_ledger_seal_evidence_sha256: bytes
    validation_sequence: int

    def validate(self) -> None:
        hashes = (
            self.host_protocol_hash,
            self.receipt_contract_hash,
            self.journal_sha256,
            self.journal_seal_sha256,
            self.durable_checkpoint_set_sha256,
            self.nwb_sha256,
            self.schema_plan_sha256,
            self.dependency_lock_sha256,
            self.materializer_build_sha256,
            self.validation_report_sha256,
            self.samples_manifest_sha256,
            self.session_manifest_sha256,
            self.run_ledger_seal_evidence_sha256,
        )
        if len(self.run_id) != 16 or not any(self.run_id):
            raise NwbReceiptError("run_id")
        if any(len(value) != 32 or not any(value) for value in hashes):
            raise NwbReceiptError("hash")
        if self.host_protocol_hash != protocol.PROTOCOL_HASH:
            raise NwbReceiptError("host_protocol_hash")
        if self.receipt_contract_hash != RECEIPT_CONTRACT_HASH:
            raise NwbReceiptError("receipt_contract_hash")
        if (
            self.validation_flags & ~VALIDATION_FLAGS_ALL
            or self.validation_flags != REQUIRED_VALIDATION_FLAGS
            or self.validation_flags & PUBLICATION_AUTHORIZED
        ):
            raise NwbReceiptError("validation_flags")
        if not 1 <= self.pod_count <= 8:
            raise NwbReceiptError("pod_count")
        expected_blocks = (
            0
            if self.expected_last_journal_sequence == EMPTY_EXPECTED_LAST
            else self.expected_last_journal_sequence + 1
        )
        if self.checked_blocks != expected_blocks:
            raise NwbReceiptError("checked_blocks")
        if min(
            self.validated_at_unix_ns,
            self.journal_bytes,
            self.nwb_bytes,
            self.validation_sequence,
        ) <= 0:
            raise NwbReceiptError("positive_field")
        if any(
            value != 0
            for value in (
                self.schema_error_count,
                self.inspector_critical_count,
                self.reconciliation_error_count,
            )
        ):
            raise NwbReceiptError("validation_error_count")
        for value, maximum, name in (
            (self.generation, 0xFFFF_FFFF, "generation"),
            (self.pod_count, 0xFFFF, "pod_count"),
            (self.schema_error_count, 0xFFFF_FFFF, "schema_error_count"),
            (
                self.inspector_critical_count,
                0xFFFF_FFFF,
                "inspector_critical_count",
            ),
            (
                self.reconciliation_error_count,
                0xFFFF_FFFF,
                "reconciliation_error_count",
            ),
        ):
            if not 0 <= value <= maximum:
                raise NwbReceiptError(name)
        for value in (
            self.expected_last_journal_sequence,
            self.checked_blocks,
            self.total_samples,
            self.validated_at_unix_ns,
            self.journal_bytes,
            self.nwb_bytes,
            self.validation_sequence,
        ):
            if not 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF:
                raise NwbReceiptError("u64_range")

    def to_bytes(self) -> bytes:
        self.validate()
        output = bytearray(NWB_RECEIPT_LEN)
        struct.pack_into(
            "<8sHHI16sIHHQQQQQQIIII",
            output,
            0,
            RECEIPT_MAGIC,
            RECEIPT_VERSION,
            NWB_RECEIPT_LEN,
            self.validation_flags,
            self.run_id,
            self.generation,
            self.pod_count,
            0,
            self.expected_last_journal_sequence,
            self.checked_blocks,
            self.total_samples,
            self.validated_at_unix_ns,
            self.journal_bytes,
            self.nwb_bytes,
            self.schema_error_count,
            self.inspector_critical_count,
            self.reconciliation_error_count,
            0,
        )
        offset = 104
        for value in (
            self.host_protocol_hash,
            self.receipt_contract_hash,
            self.journal_sha256,
            self.journal_seal_sha256,
            self.durable_checkpoint_set_sha256,
            self.nwb_sha256,
            self.schema_plan_sha256,
            self.dependency_lock_sha256,
            self.materializer_build_sha256,
            self.validation_report_sha256,
            self.samples_manifest_sha256,
            self.session_manifest_sha256,
            self.run_ledger_seal_evidence_sha256,
        ):
            output[offset : offset + 32] = value
            offset += 32
        struct.pack_into("<Q", output, 520, self.validation_sequence)
        struct.pack_into("<I", output, 540, protocol.crc32c(output[:540]))
        return bytes(output)

    @classmethod
    def from_bytes(cls, data: bytes) -> "NwbGenerationValidationReceiptV1":
        if len(data) != NWB_RECEIPT_LEN:
            raise NwbReceiptError("length")
        if data[:8] != RECEIPT_MAGIC:
            raise NwbReceiptError("magic")
        if struct.unpack_from("<H", data, 8)[0] != RECEIPT_VERSION:
            raise NwbReceiptError("version")
        if struct.unpack_from("<H", data, 10)[0] != NWB_RECEIPT_LEN:
            raise NwbReceiptError("length")
        if struct.unpack_from("<H", data, 38)[0] != 0:
            raise NwbReceiptError("reserved")
        if struct.unpack_from("<I", data, 100)[0] != 0 or any(data[528:540]):
            raise NwbReceiptError("reserved")
        if struct.unpack_from("<I", data, 540)[0] != protocol.crc32c(data[:540]):
            raise NwbReceiptError("crc32c")

        hashes = tuple(data[offset : offset + 32] for offset in range(104, 520, 32))
        value = cls(
            validation_flags=struct.unpack_from("<I", data, 12)[0],
            run_id=data[16:32],
            generation=struct.unpack_from("<I", data, 32)[0],
            pod_count=struct.unpack_from("<H", data, 36)[0],
            expected_last_journal_sequence=struct.unpack_from("<Q", data, 40)[0],
            checked_blocks=struct.unpack_from("<Q", data, 48)[0],
            total_samples=struct.unpack_from("<Q", data, 56)[0],
            validated_at_unix_ns=struct.unpack_from("<Q", data, 64)[0],
            journal_bytes=struct.unpack_from("<Q", data, 72)[0],
            nwb_bytes=struct.unpack_from("<Q", data, 80)[0],
            schema_error_count=struct.unpack_from("<I", data, 88)[0],
            inspector_critical_count=struct.unpack_from("<I", data, 92)[0],
            reconciliation_error_count=struct.unpack_from("<I", data, 96)[0],
            host_protocol_hash=hashes[0],
            receipt_contract_hash=hashes[1],
            journal_sha256=hashes[2],
            journal_seal_sha256=hashes[3],
            durable_checkpoint_set_sha256=hashes[4],
            nwb_sha256=hashes[5],
            schema_plan_sha256=hashes[6],
            dependency_lock_sha256=hashes[7],
            materializer_build_sha256=hashes[8],
            validation_report_sha256=hashes[9],
            samples_manifest_sha256=hashes[10],
            session_manifest_sha256=hashes[11],
            run_ledger_seal_evidence_sha256=hashes[12],
            validation_sequence=struct.unpack_from("<Q", data, 520)[0],
        )
        value.validate()
        return value
