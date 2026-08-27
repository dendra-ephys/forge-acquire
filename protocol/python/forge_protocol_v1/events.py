"""Self-hashed event payload extension for canonical Forge records."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import struct


EVENT_PAYLOAD_MAGIC = b"FGREVT01"
EVENT_PAYLOAD_VERSION = 1
EVENT_PAYLOAD_COMMON_HEADER_LEN = 80
EVENT_PAYLOAD_MAX_BODY_LEN = 65_536
EVENT_PAYLOAD_HASH_HEX = "68ad1bf0c16c57ddcad79cc8e5a950513d8e54a2c874cbe4b56cea054b7dd6d8"
EVENT_PAYLOAD_HASH = bytes.fromhex(EVENT_PAYLOAD_HASH_HEX)

MARKER_FLAG_OPERATOR = 1
MARKER_FLAG_EXTERNAL = 2
EVENT_FAULT_FLAG_RUN_LATCHED = 1
EVENT_FAULT_FLAG_STIM_DISARMING = 2
ANALYSIS_FLAG_REFERENCE_ONLY = 1
ANALYSIS_FLAG_CONTROLLER_CANDIDATE = 2
ANALYSIS_CHANNEL_NONE = 0xFFFF_FFFF


class EventPayloadError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class EventPayloadKind(IntEnum):
    MARKER = 1
    FAULT = 2
    GAP = 3
    ONLINE_ANALYSIS = 4


class FaultSeverity(IntEnum):
    INFO = 1
    WARNING = 2
    ERROR = 3
    FATAL = 4


class FaultLayer(IntEnum):
    RECEIVER_CAPTURE = 1
    POD_FT600 = 2
    D3XX_HOST = 3
    AGGREGATOR_RING = 4
    NETWORK_SOCKET = 5
    RECORD_WRITER = 6
    ANALYSIS_WORKER = 7
    MATERIALIZER = 8
    SYNCHRONIZATION = 9
    STIMULATION = 10


class FaultCode(IntEnum):
    SOURCE_CRC = 1
    COUNTER_GAP = 2
    CAPTURE_OVERFLOW = 3
    FT600_BACKPRESSURE = 4
    D3XX_QUEUE = 5
    AGGREGATOR_OVERFLOW = 6
    SOCKET_DROP = 7
    WRITER_IO = 8
    SYNC_LOST = 9
    ANALYSIS_DROP = 10
    MATERIALIZER_FAILURE = 11
    DEADLINE_MISS = 12
    RECEIPT_CONTRADICTION = 13
    COMPLIANCE_FAULT = 14
    INTERLOCK_FAULT = 15
    TRANSPORT_DISCONNECT = 16


class GapReason(IntEnum):
    SOURCE_CRC = 1
    COUNTER_DISCONTINUITY = 2
    CAPTURE_OVERFLOW = 3
    TRANSPORT_DISCONNECT = 4
    REPLAY_UNAVAILABLE = 5
    CLOCK_LOSS = 6


def _id(value: bytes) -> bytes:
    if len(value) != 16 or not any(value):
        raise EventPayloadError("identity")
    return value


def _hash(value: bytes) -> bytes:
    if len(value) != 32 or not any(value):
        raise EventPayloadError("identity")
    return value


def _text(value: str, minimum: int, maximum: int) -> bytes:
    encoded = value.encode("utf-8", errors="strict")
    if not minimum <= len(encoded) <= maximum or b"\0" in encoded:
        raise EventPayloadError("invariant")
    return encoded


def _header(kind: EventPayloadKind, header_bytes: int, body_bytes: int, event_id: bytes) -> bytearray:
    if not 0 <= body_bytes <= EVENT_PAYLOAD_MAX_BODY_LEN:
        raise EventPayloadError("length_limit")
    total = header_bytes + body_bytes
    output = bytearray(header_bytes)
    struct.pack_into(
        "<8sHHHHII32s16s8s",
        output,
        0,
        EVENT_PAYLOAD_MAGIC,
        EVENT_PAYLOAD_VERSION,
        int(kind),
        header_bytes,
        0,
        total,
        body_bytes,
        EVENT_PAYLOAD_HASH,
        _id(event_id),
        b"\0" * 8,
    )
    return output


@dataclass(frozen=True, slots=True)
class MarkerPayloadV1:
    event_id: bytes
    marker_sequence: int
    marker_flags: int
    label: str
    note: str

    def to_bytes(self) -> bytes:
        label = _text(self.label, 1, 256)
        note = _text(self.note, 0, 2_048)
        if self.marker_flags not in (MARKER_FLAG_OPERATOR, MARKER_FLAG_EXTERNAL):
            raise EventPayloadError("unknown_flags")
        output = _header(EventPayloadKind.MARKER, 104, len(label) + len(note), self.event_id)
        struct.pack_into("<QHHI8s", output, 80, self.marker_sequence, len(label), len(note), self.marker_flags, b"\0" * 8)
        return bytes(output) + label + note


@dataclass(frozen=True, slots=True)
class FaultPayloadV1:
    event_id: bytes
    fault_code: FaultCode
    severity: FaultSeverity
    layer: FaultLayer
    fault_flags: int
    occurrence_count: int
    detail: str

    def to_bytes(self) -> bytes:
        detail = _text(self.detail, 0, 2_048)
        if self.fault_flags & ~3:
            raise EventPayloadError("unknown_flags")
        if self.occurrence_count <= 0:
            raise EventPayloadError("invariant")
        output = _header(EventPayloadKind.FAULT, 104, len(detail), self.event_id)
        struct.pack_into(
            "<HBBIQH6s",
            output,
            80,
            int(self.fault_code),
            int(self.severity),
            int(self.layer),
            self.fault_flags,
            self.occurrence_count,
            len(detail),
            b"\0" * 6,
        )
        return bytes(output) + detail


@dataclass(frozen=True, slots=True)
class GapPayloadV1:
    event_id: bytes
    reason: GapReason
    layer: FaultLayer
    gap_flags: int
    missing_record_count: int
    missing_frame_count: int
    missing_sample_count: int

    def to_bytes(self) -> bytes:
        if self.gap_flags & ~3:
            raise EventPayloadError("unknown_flags")
        if not any((self.missing_record_count, self.missing_frame_count, self.missing_sample_count)):
            raise EventPayloadError("invariant")
        output = _header(EventPayloadKind.GAP, 112, 0, self.event_id)
        struct.pack_into(
            "<HBBIQQQ",
            output,
            80,
            int(self.reason),
            int(self.layer),
            0,
            self.gap_flags,
            self.missing_record_count,
            self.missing_frame_count,
            self.missing_sample_count,
        )
        return bytes(output)


@dataclass(frozen=True, slots=True)
class OnlineAnalysisPayloadV1:
    event_id: bytes
    worker_id: bytes
    worker_build_hash: bytes
    algorithm_hash: bytes
    config_hash: bytes
    result_schema_hash: bytes
    source_record_sequence: int
    channel_id: int
    analysis_flags: int
    result: bytes

    def to_bytes(self) -> bytes:
        if not self.result or len(self.result) > 4_096 or b"\0" in self.result:
            raise EventPayloadError("length_limit")
        try:
            self.result.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise EventPayloadError("utf8") from error
        if self.analysis_flags & ~3:
            raise EventPayloadError("unknown_flags")
        output = _header(EventPayloadKind.ONLINE_ANALYSIS, 248, len(self.result), self.event_id)
        struct.pack_into(
            "<16s32s32s32s32sQIIII",
            output,
            80,
            _id(self.worker_id),
            _hash(self.worker_build_hash),
            _hash(self.algorithm_hash),
            _hash(self.config_hash),
            _hash(self.result_schema_hash),
            self.source_record_sequence,
            self.channel_id,
            self.analysis_flags,
            len(self.result),
            0,
        )
        return bytes(output) + bytes(self.result)


EventPayload = MarkerPayloadV1 | FaultPayloadV1 | GapPayloadV1 | OnlineAnalysisPayloadV1


def decode_event_payload(data: bytes) -> EventPayload:
    if len(data) < EVENT_PAYLOAD_COMMON_HEADER_LEN:
        raise EventPayloadError("length")
    magic, version, raw_kind, header_bytes, reserved, total_bytes, body_bytes, contract_hash, event_id, reserved8 = struct.unpack_from(
        "<8sHHHHII32s16s8s", data, 0
    )
    if magic != EVENT_PAYLOAD_MAGIC:
        raise EventPayloadError("bad_magic")
    if version != EVENT_PAYLOAD_VERSION:
        raise EventPayloadError("version")
    try:
        kind = EventPayloadKind(raw_kind)
    except ValueError as error:
        raise EventPayloadError("unknown_kind") from error
    if reserved != 0 or any(reserved8):
        raise EventPayloadError("reserved")
    if total_bytes != len(data) or header_bytes + body_bytes != len(data) or body_bytes > EVENT_PAYLOAD_MAX_BODY_LEN:
        raise EventPayloadError("length")
    if contract_hash != EVENT_PAYLOAD_HASH:
        raise EventPayloadError("contract_hash")
    _id(event_id)

    if kind is EventPayloadKind.MARKER:
        if header_bytes != 104:
            raise EventPayloadError("length")
        marker_sequence, label_bytes, note_bytes, marker_flags, tail = struct.unpack_from("<QHHI8s", data, 80)
        if any(tail):
            raise EventPayloadError("reserved")
        if not 1 <= label_bytes <= 256 or note_bytes > 2_048 or label_bytes + note_bytes != body_bytes:
            raise EventPayloadError("invariant")
        if marker_flags not in (MARKER_FLAG_OPERATOR, MARKER_FLAG_EXTERNAL):
            raise EventPayloadError("unknown_flags")
        label = _decode_text(data[104 : 104 + label_bytes])
        note = _decode_text(data[104 + label_bytes :])
        return MarkerPayloadV1(event_id, marker_sequence, marker_flags, label, note)

    if kind is EventPayloadKind.FAULT:
        if header_bytes != 104:
            raise EventPayloadError("length")
        raw_code, raw_severity, raw_layer, fault_flags, occurrence_count, detail_bytes, tail = struct.unpack_from(
            "<HBBIQH6s", data, 80
        )
        if any(tail):
            raise EventPayloadError("reserved")
        if fault_flags & ~3:
            raise EventPayloadError("unknown_flags")
        if occurrence_count == 0 or detail_bytes != body_bytes or detail_bytes > 2_048:
            raise EventPayloadError("invariant")
        try:
            code, severity, layer = FaultCode(raw_code), FaultSeverity(raw_severity), FaultLayer(raw_layer)
        except ValueError as error:
            raise EventPayloadError("unknown_enum") from error
        return FaultPayloadV1(event_id, code, severity, layer, fault_flags, occurrence_count, _decode_text(data[104:]))

    if kind is EventPayloadKind.GAP:
        if header_bytes != 112 or body_bytes != 0:
            raise EventPayloadError("length")
        raw_reason, raw_layer, reserved8, gap_flags, missing_records, missing_frames, missing_samples = struct.unpack_from(
            "<HBBIQQQ", data, 80
        )
        if reserved8 != 0:
            raise EventPayloadError("reserved")
        if gap_flags & ~3:
            raise EventPayloadError("unknown_flags")
        if not any((missing_records, missing_frames, missing_samples)):
            raise EventPayloadError("invariant")
        try:
            reason, layer = GapReason(raw_reason), FaultLayer(raw_layer)
        except ValueError as error:
            raise EventPayloadError("unknown_enum") from error
        return GapPayloadV1(event_id, reason, layer, gap_flags, missing_records, missing_frames, missing_samples)

    if header_bytes != 248:
        raise EventPayloadError("length")
    worker_id, build_hash, algorithm_hash, config_hash, schema_hash, source_record, channel_id, flags, result_bytes, reserved32 = struct.unpack_from(
        "<16s32s32s32s32sQIIII", data, 80
    )
    if reserved32 != 0:
        raise EventPayloadError("reserved")
    _id(worker_id)
    for value in (build_hash, algorithm_hash, config_hash, schema_hash):
        _hash(value)
    if flags & ~3:
        raise EventPayloadError("unknown_flags")
    if result_bytes != body_bytes or not 1 <= result_bytes <= 4_096:
        raise EventPayloadError("invariant")
    _decode_text(data[248:])
    return OnlineAnalysisPayloadV1(
        event_id,
        worker_id,
        build_hash,
        algorithm_hash,
        config_hash,
        schema_hash,
        source_record,
        channel_id,
        flags,
        data[248:],
    )


def _decode_text(data: bytes) -> str:
    if b"\0" in data:
        raise EventPayloadError("utf8")
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise EventPayloadError("utf8") from error
