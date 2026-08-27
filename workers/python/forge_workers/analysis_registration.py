"""Observer-only analysis worker registration contract and Windows client.

The daemon authenticates the caller's Windows process token.  This client also
verifies every returned identity, hash, geometry and CRC before opening the
mapping.  Version 1 cannot request a controller token or stimulation authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import hashlib
import re
import struct

from ._protocol import protocol
from .shared_ring import (
    GLOBAL_HEADER_BYTES,
    SCHEMA_HASH,
    SLOT_HEADER_BYTES,
    LiveRingError,
    WindowsMappedRingConsumer,
)

try:
    import _forge_analysis_native as _native
except ImportError:
    _native = None


REQUEST_BYTES = 256
RESPONSE_BYTES = 384
REQUEST_MAGIC = b"FGANRQ01"
RESPONSE_MAGIC = b"FGANRS01"
VERSION = 1
REGISTER_OBSERVER = 1
ROLE_OBSERVER = 1
RESULT_ACCEPTED = 1
RESULT_REJECTED = 2
LIVE_MAPPING = 1
OBSERVER_ONLY = 2
KNOWN_FLAGS = LIVE_MAPPING | OBSERVER_ONLY
CONTRACT_HASH_HEX = "53b8b86e417dd12ab82d5b9ce5226e9e0e81a3b45e3ad8f9bf3f9c682d2069ca"
_MAPPING_NAME = re.compile(r"Local\\ForgeAnalysisRing-[A-Za-z0-9-]+\Z")


class RegistrationCodecError(ValueError):
    pass


class RegistrationError(IntEnum):
    NONE = 0
    INVALID = 1
    UNAVAILABLE = 2
    CONFLICT = 3
    INTERNAL = 4


class RegistrationRejected(LiveRingError):
    def __init__(self, error: RegistrationError) -> None:
        self.error = error
        super().__init__(f"analysis worker registration rejected: {error.name.lower()}")


def _nonzero(value: bytes, expected: int, field: str) -> bytes:
    value = bytes(value)
    if len(value) != expected or not any(value):
        raise RegistrationCodecError(f"invalid {field}")
    return value


def _u64(value: int, field: str) -> int:
    if not 0 < value < (1 << 64):
        raise RegistrationCodecError(f"invalid {field}")
    return value


def _layout(slot_count: int, payload_capacity: int) -> tuple[int, int]:
    if not 2 <= slot_count <= 65_536:
        raise RegistrationCodecError("invalid slot_count")
    maximum = protocol.RECORD_HEADER_LEN + protocol.MAX_RECORD_PAYLOAD_LEN
    if not protocol.RECORD_HEADER_LEN <= payload_capacity <= maximum:
        raise RegistrationCodecError("invalid payload_capacity")
    stride = (SLOT_HEADER_BYTES + payload_capacity + 63) & ~63
    total = GLOBAL_HEADER_BYTES + slot_count * stride
    if total > 1024 * 1024 * 1024:
        raise RegistrationCodecError("analysis mapping exceeds 1 GiB")
    return stride, total


@dataclass(frozen=True, slots=True)
class AnalysisWorkerRegisterRequestV1:
    request_id: int
    producer_epoch: int
    run_id: bytes
    consumer_id: bytes
    worker_build_hash: bytes
    slot_count: int
    payload_capacity: int

    def encode(self) -> bytes:
        _u64(self.request_id, "request_id")
        _u64(self.producer_epoch, "producer_epoch")
        run_id = _nonzero(self.run_id, 16, "run_id")
        consumer_id = _nonzero(self.consumer_id, 16, "consumer_id")
        build_hash = _nonzero(self.worker_build_hash, 32, "worker_build_hash")
        _layout(self.slot_count, self.payload_capacity)
        output = bytearray(REQUEST_BYTES)
        struct.pack_into(
            "<I8sHHHHQQ", output, 0, REQUEST_BYTES, REQUEST_MAGIC, VERSION,
            REQUEST_BYTES, REGISTER_OBSERVER, ROLE_OBSERVER, self.request_id,
            self.producer_epoch,
        )
        output[36:52] = run_id
        output[52:68] = consumer_id
        output[68:100] = build_hash
        struct.pack_into("<II", output, 100, self.slot_count, self.payload_capacity)
        output[108:140] = protocol.PROTOCOL_HASH
        output[140:172] = SCHEMA_HASH
        struct.pack_into("<I", output, 252, protocol.crc32c(output[:252]))
        return bytes(output)

    @classmethod
    def decode(cls, encoded: bytes) -> AnalysisWorkerRegisterRequestV1:
        if len(encoded) != REQUEST_BYTES:
            raise RegistrationCodecError("invalid request length")
        total, magic, version, header, operation, role, request_id, epoch = (
            struct.unpack_from("<I8sHHHHQQ", encoded, 0)
        )
        if (
            (total, magic, version, header, operation, role)
            != (
                REQUEST_BYTES,
                REQUEST_MAGIC,
                VERSION,
                REQUEST_BYTES,
                REGISTER_OBSERVER,
                ROLE_OBSERVER,
            )
            or encoded[108:140] != protocol.PROTOCOL_HASH
            or encoded[140:172] != SCHEMA_HASH
            or any(encoded[172:252])
            or struct.unpack_from("<I", encoded, 252)[0]
            != protocol.crc32c(encoded[:252])
        ):
            raise RegistrationCodecError("invalid request frame")
        slot_count, capacity = struct.unpack_from("<II", encoded, 100)
        value = cls(
            request_id,
            epoch,
            encoded[36:52],
            encoded[52:68],
            encoded[68:100],
            slot_count,
            capacity,
        )
        if value.encode() != encoded:
            raise RegistrationCodecError("noncanonical request")
        return value


@dataclass(frozen=True, slots=True)
class AnalysisWorkerRegisterResponseV1:
    accepted: bool
    error: RegistrationError
    request_id: int
    producer_epoch: int
    run_id: bytes
    consumer_id: bytes
    mapping_name: str
    slot_count: int
    payload_capacity: int
    slot_stride: int
    total_mapping_bytes: int
    request_hash: bytes
    worker_build_hash: bytes

    @classmethod
    def decode(cls, encoded: bytes) -> AnalysisWorkerRegisterResponseV1:
        if len(encoded) != RESPONSE_BYTES:
            raise RegistrationCodecError("invalid response length")
        total, magic, version, header, result, raw_error = struct.unpack_from(
            "<I8sHHHH", encoded, 0
        )
        try:
            error = RegistrationError(raw_error)
        except ValueError as cause:
            raise RegistrationCodecError("unknown registration error") from cause
        name_length, reserved = struct.unpack_from("<HH", encoded, 68)
        flags = struct.unpack_from("<I", encoded, 352)[0]
        if (
            (total, magic, version, header)
            != (RESPONSE_BYTES, RESPONSE_MAGIC, VERSION, RESPONSE_BYTES)
            or result not in (RESULT_ACCEPTED, RESULT_REJECTED)
            or reserved != 0
            or name_length > 128
            or any(encoded[72 + name_length : 200])
            or encoded[224:256] != protocol.PROTOCOL_HASH
            or encoded[256:288] != SCHEMA_HASH
            or any(encoded[356:380])
            or struct.unpack_from("<I", encoded, 380)[0]
            != protocol.crc32c(encoded[:380])
        ):
            raise RegistrationCodecError("invalid response frame")
        try:
            mapping_name = encoded[72 : 72 + name_length].decode("ascii")
        except UnicodeDecodeError as cause:
            raise RegistrationCodecError("mapping name is not ASCII") from cause
        accepted = result == RESULT_ACCEPTED
        request_id, epoch = struct.unpack_from("<QQ", encoded, 20)
        slot_count, capacity = struct.unpack_from("<II", encoded, 200)
        stride, total_bytes = struct.unpack_from("<QQ", encoded, 208)
        value = cls(
            accepted,
            error,
            request_id,
            epoch,
            encoded[36:52],
            encoded[52:68],
            mapping_name,
            slot_count,
            capacity,
            stride,
            total_bytes,
            encoded[288:320],
            encoded[320:352],
        )
        value._validate(flags)
        return value

    def _validate(self, flags: int) -> None:
        _u64(self.request_id, "request_id")
        _u64(self.producer_epoch, "producer_epoch")
        _nonzero(self.run_id, 16, "run_id")
        _nonzero(self.consumer_id, 16, "consumer_id")
        _nonzero(self.request_hash, 32, "request_hash")
        _nonzero(self.worker_build_hash, 32, "worker_build_hash")
        if self.accepted:
            if self.error is not RegistrationError.NONE or flags != KNOWN_FLAGS:
                raise RegistrationCodecError("accepted response has invalid result")
            if not _MAPPING_NAME.fullmatch(self.mapping_name):
                raise RegistrationCodecError("invalid mapping name")
            expected_stride, expected_total = _layout(
                self.slot_count, self.payload_capacity
            )
            if (self.slot_stride, self.total_mapping_bytes) != (
                expected_stride,
                expected_total,
            ):
                raise RegistrationCodecError("mapping geometry contradiction")
        elif (
            self.error is RegistrationError.NONE
            or flags != 0
            or self.mapping_name
            or self.slot_count
            or self.payload_capacity
            or self.slot_stride
            or self.total_mapping_bytes
        ):
            raise RegistrationCodecError("rejected response advertises capability")


@dataclass(slots=True)
class RegisteredObserver:
    response: AnalysisWorkerRegisterResponseV1
    consumer: WindowsMappedRingConsumer

    def close(self) -> None:
        self.consumer.close()

    def __enter__(self) -> RegisteredObserver:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def register_observer(
    pipe_name: str,
    request: AnalysisWorkerRegisterRequestV1,
    timeout_ms: int = 5_000,
) -> RegisteredObserver:
    if _native is None:
        raise LiveRingError("native Windows analysis registration is unavailable")
    encoded_request = request.encode()
    try:
        encoded_response = _native.transact_pipe(
            pipe_name, encoded_request, timeout_ms
        )
    except (RuntimeError, ValueError) as error:
        raise LiveRingError(str(error)) from error
    response = AnalysisWorkerRegisterResponseV1.decode(encoded_response)
    if (
        response.request_id != request.request_id
        or response.producer_epoch != request.producer_epoch
        or response.run_id != request.run_id
        or response.consumer_id != request.consumer_id
        or response.worker_build_hash != request.worker_build_hash
        or response.request_hash != hashlib.sha256(encoded_request).digest()
    ):
        raise RegistrationCodecError("registration response does not bind request")
    if not response.accepted:
        raise RegistrationRejected(response.error)
    consumer = WindowsMappedRingConsumer(
        response.mapping_name,
        response.run_id,
        response.consumer_id,
        response.producer_epoch,
    )
    return RegisteredObserver(response, consumer)
