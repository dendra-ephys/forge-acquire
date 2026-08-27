"""ForgeAnalysisRingV1 snapshot validation and native Windows consumption.

The pure-Python path only validates immutable Rust fixtures.  The optional
CPython C++20 extension owns live mapping handles and performs every shared
sequence/fault update with Windows interlocked operations.  Neither path has
stimulation authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

try:
    import _forge_analysis_native as _native
except ImportError:
    _native = None

from ._protocol import protocol


MAGIC = b"FGRRNG01"
VERSION = 1
GLOBAL_HEADER_BYTES = 256
SLOT_HEADER_BYTES = 64
SCHEMA_HASH_HEX = "96a5c4e07794b2ea7be3001e07436b5e3a3cd72d6e679098ba27771c640cb36e"
SCHEMA_HASH = bytes.fromhex(SCHEMA_HASH_HEX)
EMPTY_SLOT = (1 << 64) - 1
KNOWN_FAULT_FLAGS = 0x03


@dataclass(frozen=True, slots=True)
class RingSnapshotRecord:
    ring_sequence: int
    journal_sequence: int
    encoded_record: bytes
    canonical: object


@dataclass(frozen=True, slots=True)
class RingSnapshot:
    run_id: bytes
    consumer_id: bytes
    producer_epoch: int
    slot_count: int
    payload_capacity: int
    slot_stride: int
    published_sequence: int
    consumed_sequence: int
    dropped_records: int
    producer_heartbeat_monotonic_ns: int
    consumer_heartbeat_monotonic_ns: int
    fault_flags: int
    records: tuple[RingSnapshotRecord, ...]
    snapshot_only: bool = True


class RingSnapshotError(ValueError):
    pass


class LiveRingError(RuntimeError):
    pass


def native_live_available() -> bool:
    return _native is not None


class WindowsMappedRingConsumer:
    """Validated single-consumer view over a protected Windows mapping.

    The native layer copies each canonical record before releasing its slot.
    Python never reads mutable ring storage directly and cannot publish or
    exercise a stimulation-control lease.
    """

    __slots__ = ("_handle", "_run_id")

    def __init__(
        self,
        mapping_name: str,
        run_id: bytes,
        consumer_id: bytes,
        producer_epoch: int,
    ) -> None:
        if _native is None:
            raise LiveRingError("native Windows analysis consumer is unavailable")
        if len(run_id) != 16 or len(consumer_id) != 16:
            raise ValueError("run_id and consumer_id must contain exactly 16 bytes")
        try:
            self._handle = _native.open_mapping(
                mapping_name, run_id, consumer_id, producer_epoch
            )
        except (RuntimeError, ValueError) as error:
            raise LiveRingError(str(error)) from error
        self._run_id = bytes(run_id)

    @property
    def closed(self) -> bool:
        return self._handle is None

    @property
    def dropped_records(self) -> int:
        return self._call_native(_native.dropped_records)

    @property
    def fault_flags(self) -> int:
        return self._call_native(_native.fault_flags)

    def try_consume(self, consumer_heartbeat_monotonic_ns: int) -> RingSnapshotRecord | None:
        if not 0 <= consumer_heartbeat_monotonic_ns < (1 << 64):
            raise ValueError("consumer heartbeat is outside uint64")
        result = self._call_native(
            _native.try_consume, consumer_heartbeat_monotonic_ns
        )
        if result is None:
            return None
        ring_sequence, journal_sequence, encoded = result
        try:
            canonical = protocol.decode_record(encoded)
        except protocol.CodecError as error:
            raise LiveRingError(f"native record decode failed: {error.code}") from error
        if (
            canonical.envelope.record_kind != protocol.RecordKind.SAMPLE_BLOCK
            or canonical.envelope.run_id != self._run_id
        ):
            raise LiveRingError("native record identity contradiction")
        return RingSnapshotRecord(
            ring_sequence, journal_sequence, encoded, canonical
        )

    def close(self) -> None:
        if self._handle is not None:
            try:
                _native.close_mapping(self._handle)
            finally:
                self._handle = None

    def __enter__(self) -> WindowsMappedRingConsumer:
        if self.closed:
            raise LiveRingError("analysis mapping consumer is closed")
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def _call_native(self, function: object, *args: object) -> object:
        if self._handle is None:
            raise LiveRingError("analysis mapping consumer is closed")
        try:
            return function(self._handle, *args)
        except RuntimeError as error:
            raise LiveRingError(str(error)) from error


def parse_ring_snapshot(data: bytes) -> RingSnapshot:
    if len(data) < GLOBAL_HEADER_BYTES:
        raise RingSnapshotError("truncated global header")
    if data[:8] != MAGIC:
        raise RingSnapshotError("bad ring magic")
    version, global_bytes, slot_header, reserved = struct.unpack_from("<HHHH", data, 8)
    if (version, global_bytes, slot_header, reserved) != (VERSION, 256, 64, 0):
        raise RingSnapshotError("unsupported header layout")
    slot_count, payload_capacity, static_flags, reserved32 = struct.unpack_from(
        "<IIII", data, 16
    )
    if not 2 <= slot_count <= 65_536:
        raise RingSnapshotError("invalid slot count")
    if not protocol.RECORD_HEADER_LEN <= payload_capacity <= (
        protocol.RECORD_HEADER_LEN + protocol.MAX_RECORD_PAYLOAD_LEN
    ):
        raise RingSnapshotError("invalid payload capacity")
    if static_flags != 0 or reserved32 != 0 or any(data[116:128]) or any(data[176:256]):
        raise RingSnapshotError("nonzero reserved header bytes")
    if data[32:64] != protocol.PROTOCOL_HASH:
        raise RingSnapshotError("protocol hash mismatch")
    run_id, consumer_id = data[64:80], data[80:96]
    if not any(run_id) or not any(consumer_id):
        raise RingSnapshotError("zero identity")
    producer_epoch, slot_stride = struct.unpack_from("<QQ", data, 96)
    if producer_epoch == 0 or slot_stride < SLOT_HEADER_BYTES + payload_capacity:
        raise RingSnapshotError("invalid epoch or stride")
    if slot_stride % 64:
        raise RingSnapshotError("unaligned stride")
    if struct.unpack_from("<I", data, 112)[0] != protocol.crc32c(data[:112]):
        raise RingSnapshotError("header CRC mismatch")

    expected_bytes = GLOBAL_HEADER_BYTES + slot_count * slot_stride
    if len(data) != expected_bytes:
        raise RingSnapshotError("snapshot size mismatch")
    (
        published,
        consumed,
        dropped,
        producer_heartbeat,
        consumer_heartbeat,
        fault_flags,
    ) = struct.unpack_from("<QQQQQQ", data, 128)
    if fault_flags & ~KNOWN_FAULT_FLAGS:
        raise RingSnapshotError("unknown fault flags")
    if consumed > published or published - consumed > slot_count:
        raise RingSnapshotError("invalid sequence window")

    records: list[RingSnapshotRecord] = []
    for sequence in range(consumed, published):
        base = GLOBAL_HEADER_BYTES + (sequence % slot_count) * slot_stride
        committed, encoded_bytes, encoded_crc = struct.unpack_from("<QII", data, base)
        journal_sequence, record_sequence, global_time, record_flags = struct.unpack_from(
            "<QQQI", data, base + 16
        )
        reserved_slot = struct.unpack_from("<I", data, base + 44)[0]
        complement, reserved64 = struct.unpack_from("<QQ", data, base + 48)
        if (
            committed != sequence
            or complement != ((~sequence) & EMPTY_SLOT)
            or reserved_slot != 0
            or reserved64 != 0
            or not protocol.RECORD_HEADER_LEN <= encoded_bytes <= payload_capacity
        ):
            raise RingSnapshotError("slot contradiction")
        encoded = data[base + SLOT_HEADER_BYTES : base + SLOT_HEADER_BYTES + encoded_bytes]
        if protocol.crc32c(encoded) != encoded_crc:
            raise RingSnapshotError("slot CRC mismatch")
        try:
            canonical = protocol.decode_record(encoded)
        except protocol.CodecError as error:
            raise RingSnapshotError(f"canonical record invalid: {error.code}") from error
        envelope = canonical.envelope
        if (
            envelope.record_kind != protocol.RecordKind.SAMPLE_BLOCK
            or envelope.run_id != run_id
            or envelope.record_sequence != record_sequence
            or envelope.global_time_start_ns != global_time
            or envelope.flags != record_flags
        ):
            raise RingSnapshotError("slot cache mismatch")
        records.append(
            RingSnapshotRecord(sequence, journal_sequence, encoded, canonical)
        )

    return RingSnapshot(
        run_id,
        consumer_id,
        producer_epoch,
        slot_count,
        payload_capacity,
        slot_stride,
        published,
        consumed,
        dropped,
        producer_heartbeat,
        consumer_heartbeat,
        fault_flags,
        tuple(records),
    )
