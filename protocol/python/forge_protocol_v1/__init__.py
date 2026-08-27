"""Dependency-free Python binding for Forge host-internal protocol v1.

This module is an SDK/worker contract. It is not a device wire-format claim.
All integer fields are range checked by ``struct`` and all received frames are
bounded and CRC-32C checked before a body is exposed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import hashlib
import struct
from typing import ClassVar, TypeVar

from .events import (
    ANALYSIS_CHANNEL_NONE,
    ANALYSIS_FLAG_CONTROLLER_CANDIDATE,
    ANALYSIS_FLAG_REFERENCE_ONLY,
    EVENT_FAULT_FLAG_RUN_LATCHED,
    EVENT_FAULT_FLAG_STIM_DISARMING,
    EVENT_PAYLOAD_HASH,
    EVENT_PAYLOAD_HASH_HEX,
    MARKER_FLAG_EXTERNAL,
    MARKER_FLAG_OPERATOR,
    EventPayloadError,
    EventPayloadKind,
    FaultCode,
    FaultLayer,
    FaultPayloadV1,
    FaultSeverity,
    GapPayloadV1,
    GapReason,
    MarkerPayloadV1,
    OnlineAnalysisPayloadV1,
    decode_event_payload,
)

PROTOCOL_VERSION = 1
PROTOCOL_HASH_HEX = "4e3db23e15a1480707132d28bdc820f36fdabbb5d20d9d84850ae89166b3efa0"
PROTOCOL_HASH = bytes.fromhex(PROTOCOL_HASH_HEX)
RECORD_MAGIC = b"FGRREC01"
CONTROL_MAGIC = b"FGRCTL01"
RECORD_HEADER_LEN = 176
SAMPLE_BLOCK_HEADER_LEN = 32
LOW_SPEED_HEADER_LEN = 80
MAX_LOW_SPEED_MESSAGE_LEN = 1_048_576
MAX_RECORD_PAYLOAD_LEN = 1_048_576

RECORD_FLAGS_ALL = 0x3F
SAMPLE_BLOCK_FLAGS_ALL = 0x03
CAP_FLAGS_ALL = 0x3FF
RUNTIME_FLAGS_ALL = 0x7F

CAP_ACK_REPLAY = 0x01
CAP_GLOBAL_TIME = 0x02
CAP_STOP_ACK = 0x04
CAP_STIM_RECEIPTS = 0x08
CAP_PHYSICAL_ENABLE_INTERLOCK = 0x10
CAP_PHYSICAL_INTERLOCK = CAP_PHYSICAL_ENABLE_INTERLOCK  # compatibility alias
CAP_HARDWARE_WATCHDOG = 0x20
CAP_NONCE_DEDUP = 0x40
CAP_NO_OVERLAP_STIM = 0x80
CAP_EMERGENCY_STOP_LOOP = 0x100
CAP_DEFAULT_OFF_STIM_POWER_GATE = 0x200
REQUIRED_STIM_CAPS = 0x3FF

RUNTIME_PHYSICAL_ENABLE_ASSERTED = 0x01
RUNTIME_INTERLOCK_CLOSED = RUNTIME_PHYSICAL_ENABLE_ASSERTED  # compatibility alias
RUNTIME_STIM_POWER_ENABLED = 0x02
RUNTIME_WATCHDOG_HEALTHY = 0x04
RUNTIME_COMPLIANCE_READY = 0x08
RUNTIME_CLOCK_LOCKED = 0x10
RUNTIME_LINK_HEALTHY = 0x20
RUNTIME_EMERGENCY_STOP_HEALTHY = 0x40
REQUIRED_STIM_RUNTIME = 0x7F


class CodecError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class SafetyError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class RecordKind(IntEnum):
    SAMPLE_BLOCK = 1
    MARKER = 2
    FAULT = 3
    ONLINE_ANALYSIS = 4
    STIM_INTENT = 5
    STIM_RECEIPT = 6


class MessageKind(IntEnum):
    DEVICE_CAPABILITIES = 1
    RUN_COMMAND = 2
    SAFETY_PROFILE = 3
    STIM_INTENT = 4
    STIM_COMMAND = 5
    STIM_RECEIPT = 6
    WORKER_TOKEN_LEASE = 7
    ACK = 8
    NACK = 9
    REPLAY_REQUEST = 10


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def _id(value: bytes) -> bytes:
    if len(value) != 16:
        raise CodecError("id_length")
    return value


def _hash(value: bytes) -> bytes:
    if len(value) != 32:
        raise CodecError("hash_length")
    return value


def _nonzero(value: bytes) -> bool:
    return any(value)


def safety_profile_hash(profile: "SafetyProfileV1") -> bytes:
    """SHA-256 over the exact canonical 288-byte profile body."""

    return hashlib.sha256(profile.to_bytes()).digest()


def _check_prefix(data: bytes, expected: int) -> None:
    if len(data) != expected:
        raise CodecError("length")
    version, body_len = struct.unpack_from("<HH", data)
    if version != 1:
        raise CodecError("version")
    if body_len != expected:
        raise CodecError("length")


@dataclass(frozen=True)
class SampleBlockV1:
    flags: int
    samples_per_channel: int
    channel_count: int
    sample_rate_numerator_hz: int
    sample_rate_denominator: int
    first_sample_counter: int
    samples: tuple[int, ...]
    sample_format: int = 1

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<HHIIHHIIQ")

    def to_bytes(self) -> bytes:
        expected = self.samples_per_channel * self.channel_count
        if (
            self.flags & ~SAMPLE_BLOCK_FLAGS_ALL
            or self.samples_per_channel <= 0
            or self.channel_count <= 0
            or self.sample_format != 1
            or self.sample_rate_numerator_hz <= 0
            or self.sample_rate_denominator <= 0
            or len(self.samples) != expected
        ):
            raise CodecError("invariant")
        try:
            return self._HEADER.pack(
                1, 32, self.flags, self.samples_per_channel, self.channel_count,
                self.sample_format, self.sample_rate_numerator_hz,
                self.sample_rate_denominator, self.first_sample_counter,
            ) + struct.pack(f"<{expected}h", *self.samples)
        except struct.error as exc:
            raise CodecError("range") from exc

    @classmethod
    def from_bytes(cls, data: bytes) -> "SampleBlockV1":
        if len(data) < 32:
            raise CodecError("length")
        fields = cls._HEADER.unpack_from(data)
        version, header_len, flags, count, channels, sample_format, rate_n, rate_d, first = fields
        if version != 1:
            raise CodecError("version")
        if header_len != 32:
            raise CodecError("length")
        total = count * channels
        if len(data) != 32 + total * 2:
            raise CodecError("length")
        samples = struct.unpack_from(f"<{total}h", data, 32)
        value = cls(flags, count, channels, rate_n, rate_d, first, samples, sample_format)
        value.to_bytes()
        return value


@dataclass(frozen=True)
class CanonicalRecordEnvelopeV1:
    record_kind: RecordKind
    flags: int
    run_id: bytes
    pod_id: bytes
    headstage_id: bytes
    record_sequence: int
    frame_start: int
    frame_end_exclusive: int
    sample_start: int
    sample_end_exclusive: int
    global_time_start_ns: int
    global_time_end_exclusive_ns: int
    channel_layout_id: int
    channel_count: int
    sample_format: int = 1


_RECORD_HEADER = struct.Struct("<8sHHHHII16s16s16sQQQQQQQIHH32sII")


def encode_record(envelope: CanonicalRecordEnvelopeV1, payload: bytes) -> bytes:
    ids = tuple(map(_id, (envelope.run_id, envelope.pod_id, envelope.headstage_id)))
    if (
        len(payload) > MAX_RECORD_PAYLOAD_LEN
        or not all(map(_nonzero, ids))
        or envelope.flags & ~RECORD_FLAGS_ALL
        or envelope.frame_start >= envelope.frame_end_exclusive
        or envelope.sample_start >= envelope.sample_end_exclusive
        or envelope.global_time_start_ns >= envelope.global_time_end_exclusive_ns
        or envelope.channel_layout_id == 0 or envelope.channel_count == 0
        or envelope.sample_format != 1
    ):
        raise CodecError("invariant")
    if envelope.record_kind == RecordKind.SAMPLE_BLOCK:
        block = SampleBlockV1.from_bytes(payload)
        if (
            block.channel_count != envelope.channel_count
            or block.sample_format != envelope.sample_format
            or block.first_sample_counter != envelope.sample_start
            or block.samples_per_channel != envelope.sample_end_exclusive - envelope.sample_start
        ):
            raise CodecError("invariant")
    elif not payload:
        raise CodecError("length")
    try:
        prefix = _RECORD_HEADER.pack(
            RECORD_MAGIC, 1, 176, int(envelope.record_kind), 0, envelope.flags, len(payload),
            envelope.run_id, envelope.pod_id, envelope.headstage_id,
            envelope.record_sequence, envelope.frame_start, envelope.frame_end_exclusive,
            envelope.sample_start, envelope.sample_end_exclusive,
            envelope.global_time_start_ns, envelope.global_time_end_exclusive_ns,
            envelope.channel_layout_id, envelope.channel_count, envelope.sample_format,
            PROTOCOL_HASH, crc32c(payload), 0,
        )
    except struct.error as exc:
        raise CodecError("range") from exc
    return prefix[:172] + struct.pack("<I", crc32c(prefix[:172])) + payload


@dataclass(frozen=True)
class DecodedRecord:
    envelope: CanonicalRecordEnvelopeV1
    payload: bytes


def decode_record(data: bytes) -> DecodedRecord:
    if len(data) < 176:
        raise CodecError("length")
    fields = _RECORD_HEADER.unpack_from(data)
    (magic, version, header_len, kind, reserved, flags, payload_len, run_id, pod_id,
     headstage_id, sequence, frame_start, frame_end, sample_start, sample_end,
     global_start, global_end, layout, channels, sample_format, protocol_hash,
     payload_crc, header_crc) = fields
    if magic != RECORD_MAGIC: raise CodecError("bad_magic")
    if version != 1: raise CodecError("version")
    if payload_len > MAX_RECORD_PAYLOAD_LEN: raise CodecError("length_limit")
    if header_len != 176 or len(data) != 176 + payload_len: raise CodecError("length")
    try: record_kind = RecordKind(kind)
    except ValueError as exc: raise CodecError("unknown_kind") from exc
    if reserved: raise CodecError("reserved")
    if flags & ~RECORD_FLAGS_ALL: raise CodecError("unknown_flags")
    if protocol_hash != PROTOCOL_HASH: raise CodecError("protocol_hash")
    if header_crc != crc32c(data[:172]): raise CodecError("header_crc")
    payload = data[176:]
    if payload_crc != crc32c(payload): raise CodecError("payload_crc")
    envelope = CanonicalRecordEnvelopeV1(
        record_kind, flags, run_id, pod_id, headstage_id, sequence, frame_start,
        frame_end, sample_start, sample_end, global_start, global_end, layout,
        channels, sample_format,
    )
    encode_record(envelope, payload)
    return DecodedRecord(envelope, payload)


TBody = TypeVar("TBody", bound="FixedBody")


class FixedBody:
    KIND: ClassVar[MessageKind]
    SIZE: ClassVar[int]
    def to_bytes(self) -> bytes: raise NotImplementedError
    @classmethod
    def from_bytes(cls: type[TBody], data: bytes) -> TBody: raise NotImplementedError


@dataclass(frozen=True)
class DeviceCapabilitiesV1(FixedBody):
    device_id: bytes; transport: int; max_pods: int; max_channels_per_pod: int
    sample_format_mask: int; min_sample_rate_hz: int; max_sample_rate_hz: int
    stim_kind: int; stim_channels: int; max_sample_block_us: int
    capability_flags: int; runtime_safety_flags: int; hardware_protocol_hash: bytes
    KIND=MessageKind.DEVICE_CAPABILITIES; SIZE=84
    _S=struct.Struct("<HH16sBBHIIIHHIII32s")
    def to_bytes(self)->bytes:
        if not 1<=self.transport<=3 or not 1<=self.max_pods<=8 or (self.transport==1 and self.max_pods!=1) or not 1<=self.max_channels_per_pod<=256 or self.sample_format_mask!=1 or self.min_sample_rate_hz<=0 or self.min_sample_rate_hz>self.max_sample_rate_hz or self.stim_kind not in (0,1) or (self.stim_kind==0 and self.stim_channels!=0) or (self.stim_kind==1 and self.stim_channels!=16) or self.max_sample_block_us<=0 or self.capability_flags&~CAP_FLAGS_ALL or self.runtime_safety_flags&~RUNTIME_FLAGS_ALL: raise CodecError("invariant")
        return self._S.pack(1,84,_id(self.device_id),self.transport,self.max_pods,self.max_channels_per_pod,self.sample_format_mask,self.min_sample_rate_hz,self.max_sample_rate_hz,self.stim_kind,self.stim_channels,self.max_sample_block_us,self.capability_flags,self.runtime_safety_flags,_hash(self.hardware_protocol_hash))
    @classmethod
    def from_bytes(cls,data:bytes): _check_prefix(data,84); v=cls(*cls._S.unpack(data)[2:]); v.to_bytes(); return v


@dataclass(frozen=True)
class RunCommandV1(FixedBody):
    command:int; scope:int; run_id:bytes; target_device_id:bytes; deadline_global_time_ns:int; frozen_config_hash:bytes
    KIND=MessageKind.RUN_COMMAND;SIZE=80;_S=struct.Struct("<HHHH16s16sQ32s")
    def to_bytes(self)->bytes:
        if not 1<=self.command<=7 or self.scope not in (1,2) or not _nonzero(_id(self.run_id)) or not _nonzero(_id(self.target_device_id)) or self.deadline_global_time_ns<=0 or not _nonzero(_hash(self.frozen_config_hash)):raise CodecError("invariant")
        return self._S.pack(1,80,self.command,self.scope,self.run_id,self.target_device_id,self.deadline_global_time_ns,self.frozen_config_hash)
    @classmethod
    def from_bytes(cls,data):_check_prefix(data,80);v=cls(*cls._S.unpack(data)[2:]);v.to_bytes();return v


@dataclass(frozen=True)
class SafetyProfileV1(FixedBody):
    profile_id:bytes; approval_state:int; electrode_material:int; recovery_policy:int
    wire_diameter_nm:int; exposed_area_um2:int; impedance_min_ohm:int; impedance_max_ohm:int
    max_current_na:int; max_phase_width_us:int; min_interphase_us:int; max_frequency_millihz:int
    max_train_pulses:int; max_train_duration_ms:int; max_duty_cycle_ppm:int
    max_charge_per_phase_pc:int; max_charge_density_pc_per_mm2:int
    compliance_min_uv:int; compliance_max_uv:int; experiment_protocol_hash:bytes
    electrode_geometry_hash:bytes; hardware_build_hash:bytes; software_build_hash:bytes
    approved_limits_hash:bytes; approval_authority_hash:bytes
    KIND=MessageKind.SAFETY_PROFILE;SIZE=288
    _S=struct.Struct("<HH16sBBH12IQQii32s32s32s32s32s32s")
    def to_bytes(self)->bytes:
        if self.approval_state not in (0,1,2) or self.electrode_material not in (0,1,2,3,4,5,255) or self.recovery_policy not in (1,2) or self.impedance_min_ohm>self.impedance_max_ohm:raise CodecError("invariant")
        return self._S.pack(1,288,_id(self.profile_id),self.approval_state,self.electrode_material,self.recovery_policy,self.wire_diameter_nm,self.exposed_area_um2,self.impedance_min_ohm,self.impedance_max_ohm,self.max_current_na,self.max_phase_width_us,self.min_interphase_us,self.max_frequency_millihz,self.max_train_pulses,self.max_train_duration_ms,self.max_duty_cycle_ppm,0,self.max_charge_per_phase_pc,self.max_charge_density_pc_per_mm2,self.compliance_min_uv,self.compliance_max_uv,*map(_hash,(self.experiment_protocol_hash,self.electrode_geometry_hash,self.hardware_build_hash,self.software_build_hash,self.approved_limits_hash,self.approval_authority_hash)))
    def validate_approved(self)->None:
        hashes=(self.experiment_protocol_hash,self.electrode_geometry_hash,self.hardware_build_hash,self.software_build_hash,self.approved_limits_hash,self.approval_authority_hash)
        if self.approval_state!=1 or not _nonzero(self.profile_id) or self.electrode_material==0 or self.recovery_policy not in (1,2) or min(self.wire_diameter_nm,self.exposed_area_um2,self.impedance_min_ohm,self.max_current_na,self.max_phase_width_us,self.min_interphase_us,self.max_frequency_millihz,self.max_train_pulses,self.max_train_duration_ms,self.max_duty_cycle_ppm,self.max_charge_per_phase_pc,self.max_charge_density_pc_per_mm2)<=0 or self.impedance_min_ohm>self.impedance_max_ohm or self.max_duty_cycle_ppm>1_000_000 or self.compliance_min_uv>=self.compliance_max_uv or not all(_nonzero(h) for h in hashes):raise CodecError("profile_not_approved")
    @classmethod
    def from_bytes(cls,data):_check_prefix(data,288);u=cls._S.unpack(data); 
    

# SafetyProfile has one reserved u32 in its packed tuple; keep its decoder explicit.
def _decode_safety_profile(data:bytes)->SafetyProfileV1:
    _check_prefix(data,288);u=SafetyProfileV1._S.unpack(data)
    if u[17]!=0:raise CodecError("reserved")
    v=SafetyProfileV1(*(u[2:17]+u[18:]));v.to_bytes();return v
SafetyProfileV1.from_bytes=classmethod(lambda cls,data:_decode_safety_profile(data))


@dataclass(frozen=True)
class StimIntentV1(FixedBody):
    run_id:bytes;source_worker_id:bytes;control_token_id:bytes;source_record_sequence:int;source_sample_counter:int;source_global_time_ns:int;algorithm_hash:bytes;config_hash:bytes;template_hash:bytes;channel_map_hash:bytes;target_channel:int;template_id:int;intent_flags:int;deadline_global_time_ns:int;intent_nonce:bytes
    KIND=MessageKind.STIM_INTENT;SIZE=240;_S=struct.Struct("<HH16s16s16sQQQ32s32s32s32sHHIIQ16s")
    def to_bytes(self)->bytes:
        ids=tuple(map(_id,(self.run_id,self.source_worker_id,self.control_token_id,self.intent_nonce)));hashes=tuple(map(_hash,(self.algorithm_hash,self.config_hash,self.template_hash,self.channel_map_hash)))
        if not all(map(_nonzero,ids+hashes)) or self.template_id<=0 or self.intent_flags!=0 or self.deadline_global_time_ns<=self.source_global_time_ns:raise CodecError("invariant")
        return self._S.pack(1,240,*ids[:3],self.source_record_sequence,self.source_sample_counter,self.source_global_time_ns,*hashes,self.target_channel,self.template_id,self.intent_flags,0,self.deadline_global_time_ns,ids[3])
    @classmethod
    def from_bytes(cls,data):_check_prefix(data,240);u=cls._S.unpack(data); 

def _decode_intent(data:bytes)->StimIntentV1:
    _check_prefix(data,240);u=StimIntentV1._S.unpack(data)
    if u[15]!=0:raise CodecError("reserved")
    v=StimIntentV1(*(u[2:15]+u[16:]));v.to_bytes();return v
StimIntentV1.from_bytes=classmethod(lambda cls,data:_decode_intent(data))


@dataclass(frozen=True)
class StimCommandV1(FixedBody):
    run_id:bytes;command_id:bytes;intent_nonce:bytes;device_id:bytes;safety_profile_hash:bytes;template_hash:bytes;channel_map_hash:bytes;target_channel:int;template_id:int;current_na:int;cathodic_phase_us:int;interphase_us:int;anodic_phase_us:int;frequency_millihz:int;pulse_count:int;deadline_global_time_ns:int;execute_not_before_global_time_ns:int;arm_epoch:int;command_nonce:bytes
    KIND=MessageKind.STIM_COMMAND;SIZE=232;_S=struct.Struct("<HH16s16s16s16s32s32s32sHH6IQQQ16s")
    def to_bytes(self)->bytes:
        ids=tuple(map(_id,(self.run_id,self.command_id,self.intent_nonce,self.device_id,self.command_nonce)));hashes=tuple(map(_hash,(self.safety_profile_hash,self.template_hash,self.channel_map_hash)))
        if not all(map(_nonzero,ids+hashes)) or self.template_id<=0 or min(self.current_na,self.cathodic_phase_us,self.interphase_us,self.anodic_phase_us,self.frequency_millihz,self.pulse_count,self.deadline_global_time_ns,self.execute_not_before_global_time_ns,self.arm_epoch)<=0 or self.execute_not_before_global_time_ns>self.deadline_global_time_ns:raise CodecError("invariant")
        return self._S.pack(1,232,*ids[:4],*hashes,self.target_channel,self.template_id,self.current_na,self.cathodic_phase_us,self.interphase_us,self.anodic_phase_us,self.frequency_millihz,self.pulse_count,self.deadline_global_time_ns,self.execute_not_before_global_time_ns,self.arm_epoch,ids[4])
    @classmethod
    def from_bytes(cls,data):_check_prefix(data,232);v=cls(*cls._S.unpack(data)[2:]);v.to_bytes();return v


@dataclass(frozen=True)
class StimReceiptV1(FixedBody):
    run_id:bytes;command_id:bytes;intent_nonce:bytes;device_id:bytes;result:int;fault_code:int;target_channel:int;template_id:int;actual_start_global_time_ns:int;actual_end_global_time_ns:int;measured_compliance_uv:int;peak_current_na:int;receipt_flags:int;delivered_phase_charge_pc:int;arm_epoch:int;receipt_nonce:bytes;hardware_state_hash:bytes
    KIND=MessageKind.STIM_RECEIPT;SIZE=168;_S=struct.Struct("<HH16s16s16s16sHHHHQQiIIQQ16s32s")
    def to_bytes(self)->bytes:
        ids=tuple(map(_id,(self.run_id,self.command_id,self.intent_nonce,self.device_id,self.receipt_nonce)));h=_hash(self.hardware_state_hash)
        if not all(map(_nonzero,ids+(h,))) or self.result not in range(1,9) or self.template_id<=0 or self.receipt_flags!=0 or self.arm_epoch<=0 or (self.result==1 and (self.actual_start_global_time_ns<=0 or self.actual_end_global_time_ns<self.actual_start_global_time_ns)):raise CodecError("invariant")
        return self._S.pack(1,168,*ids[:4],self.result,self.fault_code,self.target_channel,self.template_id,self.actual_start_global_time_ns,self.actual_end_global_time_ns,self.measured_compliance_uv,self.peak_current_na,self.receipt_flags,self.delivered_phase_charge_pc,self.arm_epoch,ids[4],h)
    @classmethod
    def from_bytes(cls,data):_check_prefix(data,168);v=cls(*cls._S.unpack(data)[2:]);v.to_bytes();return v


@dataclass(frozen=True)
class WorkerTokenLeaseV1(FixedBody):
    run_id:bytes;worker_id:bytes;token_id:bytes;role:int;state:int;arm_epoch:int;issued_global_time_ns:int;expires_global_time_ns:int;safety_profile_id:bytes;safety_profile_hash:bytes;algorithm_hash:bytes;config_hash:bytes;template_hash:bytes;channel_map_hash:bytes;worker_build_hash:bytes
    KIND=MessageKind.WORKER_TOKEN_LEASE;SIZE=288;_S=struct.Struct("<HH16s16s16sBBHQQQ16s32s32s32s32s32s32s")
    def to_bytes(self)->bytes:
        ids=tuple(map(_id,(self.run_id,self.worker_id,self.token_id,self.safety_profile_id)));hashes=tuple(map(_hash,(self.safety_profile_hash,self.algorithm_hash,self.config_hash,self.template_hash,self.channel_map_hash,self.worker_build_hash)))
        if not all(map(_nonzero,ids+hashes)) or self.role not in (1,2) or self.state not in (1,2,3) or self.arm_epoch<=0 or self.issued_global_time_ns>=self.expires_global_time_ns:raise CodecError("invariant")
        return self._S.pack(1,288,*ids[:3],self.role,self.state,0,self.arm_epoch,self.issued_global_time_ns,self.expires_global_time_ns,ids[3],*hashes)
    @classmethod
    def from_bytes(cls,data):_check_prefix(data,288);u=cls._S.unpack(data); 

def _decode_token(data:bytes)->WorkerTokenLeaseV1:
    _check_prefix(data,288);u=WorkerTokenLeaseV1._S.unpack(data)
    if u[7]!=0:raise CodecError("reserved")
    v=WorkerTokenLeaseV1(*(u[2:7]+u[8:]));v.to_bytes();return v
WorkerTokenLeaseV1.from_bytes=classmethod(lambda cls,data:_decode_token(data))


@dataclass(frozen=True)
class AckV1(FixedBody):
    acknowledged_request_id:int;applied_epoch:int;ack_code:int;state_code:int;receipt_hash:bytes
    KIND=MessageKind.ACK;SIZE=60;_S=struct.Struct("<HHQQHHI32s")
    def to_bytes(self):
        if min(self.acknowledged_request_id,self.applied_epoch)<=0 or not _nonzero(_hash(self.receipt_hash)):raise CodecError("invariant")
        return self._S.pack(1,60,self.acknowledged_request_id,self.applied_epoch,self.ack_code,self.state_code,0,self.receipt_hash)
    @classmethod
    def from_bytes(cls,data):_check_prefix(data,60);u=cls._S.unpack(data); 

def _decode_ack(data):
    _check_prefix(data,60);u=AckV1._S.unpack(data)
    if u[6]!=0:raise CodecError("reserved")
    v=AckV1(*(u[2:6]+u[7:]));v.to_bytes();return v
AckV1.from_bytes=classmethod(lambda cls,data:_decode_ack(data))


@dataclass(frozen=True)
class NackV1(FixedBody):
    rejected_request_id:int;current_epoch:int;error_code:int;retryable:int;detail_code:int;state_hash:bytes
    KIND=MessageKind.NACK;SIZE=60;_S=struct.Struct("<HHQQHBBI32s")
    def to_bytes(self):
        if min(self.rejected_request_id,self.current_epoch,self.error_code)<=0 or self.retryable not in (0,1) or not _nonzero(_hash(self.state_hash)):raise CodecError("invariant")
        return self._S.pack(1,60,self.rejected_request_id,self.current_epoch,self.error_code,self.retryable,0,self.detail_code,self.state_hash)
    @classmethod
    def from_bytes(cls,data):_check_prefix(data,60);u=cls._S.unpack(data); 

def _decode_nack(data):
    _check_prefix(data,60);u=NackV1._S.unpack(data)
    if u[6]!=0:raise CodecError("reserved")
    v=NackV1(*(u[2:6]+u[7:]));v.to_bytes();return v
NackV1.from_bytes=classmethod(lambda cls,data:_decode_nack(data))


@dataclass(frozen=True)
class ReplayRequestV1(FixedBody):
    run_id:bytes;pod_id:bytes;first_record_sequence:int;last_record_sequence_exclusive:int;deadline_global_time_ns:int;reason_code:int;request_context_hash:bytes
    KIND=MessageKind.REPLAY_REQUEST;SIZE=96;_S=struct.Struct("<HH16s16sQQQHH32s")
    def to_bytes(self):
        if not _nonzero(_id(self.run_id)) or not _nonzero(_id(self.pod_id)) or self.first_record_sequence>=self.last_record_sequence_exclusive or self.deadline_global_time_ns<=0 or self.reason_code<=0 or not _nonzero(_hash(self.request_context_hash)):raise CodecError("invariant")
        return self._S.pack(1,96,self.run_id,self.pod_id,self.first_record_sequence,self.last_record_sequence_exclusive,self.deadline_global_time_ns,self.reason_code,0,self.request_context_hash)
    @classmethod
    def from_bytes(cls,data):_check_prefix(data,96);u=cls._S.unpack(data); 

def _decode_replay(data):
    _check_prefix(data,96);u=ReplayRequestV1._S.unpack(data)
    if u[8]!=0:raise CodecError("reserved")
    v=ReplayRequestV1(*(u[2:8]+u[9:]));v.to_bytes();return v
ReplayRequestV1.from_bytes=classmethod(lambda cls,data:_decode_replay(data))


_BODY_TYPES={c.KIND:c for c in (DeviceCapabilitiesV1,RunCommandV1,SafetyProfileV1,StimIntentV1,StimCommandV1,StimReceiptV1,WorkerTokenLeaseV1,AckV1,NackV1,ReplayRequestV1)}
_LOW_HEADER=struct.Struct("<I8sHHHHIQQ32sII")


@dataclass(frozen=True)
class LowSpeedMessageV1:
    kind:MessageKind;flags:int;request_id:int;epoch:int;body:FixedBody


def encode_low_speed(body:FixedBody,request_id:int,epoch:int,flags:int=0)->bytes:
    if flags or request_id<=0 or epoch<=0:raise CodecError("invariant")
    raw=body.to_bytes();expected=_BODY_TYPES[body.KIND].SIZE
    if len(raw)!=expected:raise CodecError("length")
    total=80+len(raw)
    if total>MAX_LOW_SPEED_MESSAGE_LEN:raise CodecError("length_limit")
    header=_LOW_HEADER.pack(total,CONTROL_MAGIC,1,80,int(body.KIND),flags,len(raw),request_id,epoch,PROTOCOL_HASH,crc32c(raw),0)
    return header[:76]+struct.pack("<I",crc32c(header[:76]))+raw


def decode_low_speed(data:bytes)->LowSpeedMessageV1:
    if len(data)<80:raise CodecError("length")
    total,magic,version,header_len,kind,flags,body_len,request_id,epoch,protocol_hash,body_crc,header_crc=_LOW_HEADER.unpack_from(data)
    if total>MAX_LOW_SPEED_MESSAGE_LEN:raise CodecError("length_limit")
    if total!=len(data):raise CodecError("length")
    if magic!=CONTROL_MAGIC:raise CodecError("bad_magic")
    if version!=1:raise CodecError("version")
    if header_len!=80:raise CodecError("length")
    try:message_kind=MessageKind(kind)
    except ValueError as exc:raise CodecError("unknown_kind") from exc
    if flags:raise CodecError("unknown_flags")
    cls=_BODY_TYPES[message_kind]
    if body_len!=cls.SIZE or total!=80+body_len:raise CodecError("length")
    if request_id<=0 or epoch<=0:raise CodecError("invariant")
    if protocol_hash!=PROTOCOL_HASH:raise CodecError("protocol_hash")
    if header_crc!=crc32c(data[:76]):raise CodecError("header_crc")
    raw=data[80:]
    if body_crc!=crc32c(raw):raise CodecError("body_crc")
    return LowSpeedMessageV1(message_kind,flags,request_id,epoch,cls.from_bytes(raw))


def validate_stim_intent(capabilities:DeviceCapabilitiesV1,profile:SafetyProfileV1|None,profile_hash:bytes,token:WorkerTokenLeaseV1|None,intent:StimIntentV1,message_epoch:int,now_global_time_ns:int)->None:
    if capabilities.hardware_protocol_hash!=PROTOCOL_HASH:raise SafetyError("protocol_hash")
    if not _nonzero(capabilities.device_id):raise SafetyError("device_identity")
    if capabilities.stim_kind!=1 or capabilities.stim_channels!=16:raise SafetyError("stim_not_capable")
    if capabilities.capability_flags&REQUIRED_STIM_CAPS!=REQUIRED_STIM_CAPS:raise SafetyError("missing_safety_feature")
    if capabilities.runtime_safety_flags&REQUIRED_STIM_RUNTIME!=REQUIRED_STIM_RUNTIME:raise SafetyError("interlock_or_runtime_health")
    if profile is None:raise SafetyError("missing_profile")
    try:profile.validate_approved()
    except CodecError as exc:raise SafetyError("profile_not_approved") from exc
    if not _nonzero(_hash(profile_hash)) or safety_profile_hash(profile)!=profile_hash:raise SafetyError("profile_hash")
    if token is None:raise SafetyError("missing_token")
    if token.role!=2:raise SafetyError("token_not_controller")
    if token.state!=1:raise SafetyError("token_not_granted")
    if now_global_time_ns<token.issued_global_time_ns or now_global_time_ns>=token.expires_global_time_ns:raise SafetyError("token_expired")
    if message_epoch<=0 or message_epoch!=token.arm_epoch:raise SafetyError("epoch")
    if intent.run_id!=token.run_id:raise SafetyError("run_identity")
    if intent.source_worker_id!=token.worker_id:raise SafetyError("worker_identity")
    if intent.control_token_id!=token.token_id:raise SafetyError("token_identity")
    if profile.profile_id!=token.safety_profile_id or profile_hash!=token.safety_profile_hash:raise SafetyError("profile_hash")
    if (intent.algorithm_hash,intent.config_hash,intent.template_hash,intent.channel_map_hash)!=(token.algorithm_hash,token.config_hash,token.template_hash,token.channel_map_hash) or not _nonzero(token.worker_build_hash):raise SafetyError("frozen_hash")
    if intent.source_global_time_ns>now_global_time_ns:raise SafetyError("source_time")
    if now_global_time_ns>=intent.deadline_global_time_ns or intent.deadline_global_time_ns<=intent.source_global_time_ns:raise SafetyError("deadline")
    if intent.target_channel>=capabilities.stim_channels:raise SafetyError("target_channel")


def validate_stim_command(capabilities:DeviceCapabilitiesV1,profile:SafetyProfileV1,profile_hash:bytes,token:WorkerTokenLeaseV1,intent:StimIntentV1,command:StimCommandV1,now_global_time_ns:int)->None:
    validate_stim_intent(capabilities,profile,profile_hash,token,intent,command.arm_epoch,now_global_time_ns)
    if command.run_id!=intent.run_id or command.intent_nonce!=intent.intent_nonce or command.device_id!=capabilities.device_id:raise SafetyError("command_identity")
    if command.safety_profile_hash!=profile_hash or command.template_hash!=intent.template_hash or command.channel_map_hash!=intent.channel_map_hash:raise SafetyError("frozen_hash")
    if command.target_channel!=intent.target_channel or command.template_id!=intent.template_id:raise SafetyError("target_channel")
    if command.deadline_global_time_ns!=intent.deadline_global_time_ns or command.execute_not_before_global_time_ns>command.deadline_global_time_ns or now_global_time_ns>=command.deadline_global_time_ns:raise SafetyError("deadline")
    if command.current_na<=0 or command.current_na>profile.max_current_na or command.cathodic_phase_us<=0 or command.cathodic_phase_us>profile.max_phase_width_us or command.anodic_phase_us<=0 or command.anodic_phase_us>profile.max_phase_width_us or command.cathodic_phase_us!=command.anodic_phase_us or command.interphase_us<profile.min_interphase_us or command.frequency_millihz<=0 or command.frequency_millihz>profile.max_frequency_millihz or command.pulse_count<=0 or command.pulse_count>profile.max_train_pulses:raise SafetyError("safety_limit")
    charge_pc=(command.current_na*max(command.cathodic_phase_us,command.anodic_phase_us)+999)//1000
    density=(charge_pc*1_000_000+profile.exposed_area_um2-1)//profile.exposed_area_um2
    pulse_us=command.cathodic_phase_us+command.interphase_us+command.anodic_phase_us
    duty=(pulse_us*command.frequency_millihz+999)//1000
    waveform_ms=(pulse_us+999)//1000;period_ms=(1_000_000+command.frequency_millihz-1)//command.frequency_millihz
    train_ms=(command.pulse_count-1)*period_ms+waveform_ms
    if charge_pc>profile.max_charge_per_phase_pc or density>profile.max_charge_density_pc_per_mm2 or duty>profile.max_duty_cycle_ppm or train_ms>profile.max_train_duration_ms:raise SafetyError("safety_limit")
