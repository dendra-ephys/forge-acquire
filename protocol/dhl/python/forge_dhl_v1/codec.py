"""Normative Python reference model for the Forge DHL v1 inner link."""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass
from typing import Iterable, Sequence


DHL_VERSION = 1
DHL_HEADER_SIZE = 40
DHL_HEADER = struct.Struct("<BBHHHIIQQQ")
DHL_TRAILER = struct.Struct("<I")
NEURAL_PREFIX = struct.Struct("<HHHHQ")
IMPEDANCE_PREFIX = struct.Struct("<HHHHIII4BHH")
CHEM_PREFIX = struct.Struct("<HHBBHIIIHHIIQiiIIQQ32s")
DESCRIPTOR_PAYLOAD = struct.Struct("<HHBBHHHIIII16s32s16sI")
INVENTORY_HEADER = struct.Struct("<HHHHI32s32s")
INVENTORY_ENTRY = struct.Struct("<HBBIHHHHI12s")
CTRL_PREAMBLE = bytes((0x55, 0x55, 0x55, 0x55, 0xD5))
CTRL_HEADER = struct.Struct("<BBHIHH")
CTRL_TRAILER = struct.Struct(">H")
ACK_PAYLOAD = struct.Struct("<IBBH")


class ProtocolError(ValueError):
    """Wire data violates the frozen DHL v1 contract."""


class PacketType(enum.IntEnum):
    DESCRIPTOR = 1
    NEURAL = 2
    CHEM = 3
    IMU = 4
    STIM_EVENT = 5
    STATUS = 6
    ACK = 7
    ERROR = 8
    INVENTORY = 9
    ELECTRODE_IMPEDANCE = 10


class ComponentClass(enum.IntEnum):
    NEURAL_AFE = 1
    IMU = 2
    ELECTROCHEM_AFE = 3


class ComponentStatus(enum.IntEnum):
    EXPECTED_NOT_PROBED = 1
    DETECTED_READY = 2
    DETECTED_DEGRADED = 3
    EXPECTED_MISSING = 4
    UNEXPECTED_PRESENT = 5


class ComponentModel(enum.IntEnum):
    RHD2132 = 0x00010001
    RHD2164 = 0x00010002
    RHS2116 = 0x00010003
    ICM42670P = 0x00020001
    AD5940 = 0x00030001


class ComponentCapability(enum.IntFlag):
    STREAM_NEURAL = 1 << 0
    STREAM_IMU = 1 << 1
    AMPEROMETRY = 1 << 2
    FSCV = 1 << 3
    STIMULATION = 1 << 4
    ELECTRODE_IMPEDANCE = 1 << 5


class BoardProfile(enum.IntEnum):
    RHD2132_X1 = 1
    RHD2132_X2 = 2
    RHD2164_X1 = 3
    RHD2164_X2 = 4
    RHS2116_X1 = 5
    RHS2116_X2 = 6
    RHD2132_X1_RHS2116_X1 = 7
    RHD2164_X1_RHS2116_X1 = 8


class CtrlOpcode(enum.IntEnum):
    QUERY_INVENTORY = 0x60
    GET_STATUS = 0x61
    NEURAL_CONFIG = 0x70
    NEURAL_START = 0x71
    NEURAL_STOP = 0x72
    ELECTRODE_IMPEDANCE_SCAN = 0x73
    IMU_CONFIG = 0x78
    IMU_START = 0x79
    IMU_STOP = 0x7A
    CHEM_CONFIG_AMPEROMETRY = 0x80
    CHEM_CONFIG_FSCV = 0x81
    CHEM_START = 0x82
    CHEM_STOP = 0x83


class AckStatus(enum.IntEnum):
    OK = 0
    BAD_LENGTH = 1
    UNSUPPORTED = 2
    NOT_READY = 3


class ChemMode(enum.IntEnum):
    AMPEROMETRY = 1
    FSCV = 2
    CV = 3
    EIS = 4


class ElectrodeConfiguration(enum.IntEnum):
    TWO_ELECTRODE = 1
    THREE_ELECTRODE = 2
    FOUR_WIRE = 3
    FOUR_ELECTRODE_AUX = 4


CHEM_FLAG_COMPLETE = 0x00000001
CHEM_FLAG_HARDWARE_TIMESTAMPED = 0x00000002
CHEM_FLAG_EPHYS_ARTIFACT_WINDOW_VALID = 0x00000004
CHEM_FLAG_FAST_SETTLE_USED = 0x00000008
CHEM_FLAGS_ALL = 0x0000000F


@dataclass(frozen=True, slots=True)
class DhlPacket:
    packet_type: PacketType
    flags: int
    source_id: int
    boot_id: int
    sequence: int
    timestamp_25mhz: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class CtrlFrame:
    opcode: int
    flags: int
    sequence: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class AckPayload:
    ctrl_sequence: int
    opcode: CtrlOpcode
    status: AckStatus


@dataclass(frozen=True, slots=True)
class DescriptorPayload:
    variant: int
    chip_count: int
    feature_flags: int
    channel_count: int
    sample_rate_numerator_hz: int
    sample_rate_denominator: int
    device_id: bytes
    config_hash: bytes
    firmware_hash_prefix: bytes


@dataclass(frozen=True, slots=True)
class ComponentInventoryEntry:
    instance_id: int
    component_class: ComponentClass
    status: ComponentStatus
    model_id: ComponentModel
    first_global_channel: int
    channel_count: int
    native_channel_base: int
    driver_abi: int
    capability_flags: int
    component_config_hash_prefix: bytes


@dataclass(frozen=True, slots=True)
class InventoryPayload:
    board_profile_id: BoardProfile
    assembly_manifest_hash: bytes
    channel_map_hash: bytes
    entries: tuple[ComponentInventoryEntry, ...]


@dataclass(frozen=True, slots=True)
class ChemPayload:
    mode: ChemMode
    electrode_configuration: ElectrodeConfiguration
    flags: int
    acquisition_sequence: int
    sample_rate_numerator_hz: int
    sample_rate_denominator: int
    first_sample_counter: int
    holding_potential_uv: int
    switching_potential_uv: int
    scan_rate_mv_per_s: int
    repetition_rate_millihz: int
    artifact_start_25mhz: int
    artifact_end_25mhz_exclusive: int
    config_hash: bytes
    samples: tuple[tuple[int, ...], ...]


@dataclass(frozen=True, slots=True)
class ImpedancePayload:
    channel_index: int
    channel_count: int
    test_frequency_hz: int
    phase_sample_rate_hz: int
    ctrl_sequence: int
    zcheck_scale_code: int
    dac_amplitude_code: int
    warmup_cycles: int
    measurement_cycles: int
    clip_count: int
    flags: int
    phase_samples: tuple[int, ...]


IMPEDANCE_FLAG_COMPLETE = 0x0001
IMPEDANCE_FLAG_PRE_RECORDING = 0x0002
IMPEDANCE_FLAG_RAW_PHASE_AVERAGES = 0x0004
IMPEDANCE_FLAGS_ALL = 0x0007


# Active neural profiles plus admitted electrochem/IMU assemblies.  Mixed-family
# boards have their own descriptor variant and BoardProfile; they never impersonate
# a pure RHD or RHS build.
HEADSTAGE_PROFILE_CONTRACTS = frozenset(
    {
        (1, 1, 0, 32),   # RHD2132 x1
        (1, 2, 0, 64),   # RHD2132 x2
        (2, 1, 0, 64),   # RHD2164 x1
        (2, 2, 0, 128),  # RHD2164 x2
        (3, 1, 4, 16),   # RHS2116 x1
        (3, 2, 4, 32),   # RHS2116 x2
        (3, 2, 6, 32),   # RHS2116 x2 + IMU
        (4, 2, 4, 48),   # RHD2132 x1 + RHS2116 x1
        (5, 2, 4, 80),   # RHD2164 x1 + RHS2116 x1
        (1, 1, 1, 32),   # RHD2132 x1 + electrochem
        (2, 1, 1, 64),   # RHD2164 x1 + electrochem
        (3, 1, 5, 16),   # RHS2116 x1 + electrochem
        (1, 1, 2, 32),   # RHD2132 x1 + IMU
        (1, 1, 3, 32),   # RHD2132 x1 + IMU + electrochem
    }
)

_PROFILE_NEURAL_MODELS = {
    BoardProfile.RHD2132_X1: (ComponentModel.RHD2132,),
    BoardProfile.RHD2132_X2: (ComponentModel.RHD2132, ComponentModel.RHD2132),
    BoardProfile.RHD2164_X1: (ComponentModel.RHD2164,),
    BoardProfile.RHD2164_X2: (ComponentModel.RHD2164, ComponentModel.RHD2164),
    BoardProfile.RHS2116_X1: (ComponentModel.RHS2116,),
    BoardProfile.RHS2116_X2: (ComponentModel.RHS2116, ComponentModel.RHS2116),
    BoardProfile.RHD2132_X1_RHS2116_X1: (
        ComponentModel.RHD2132,
        ComponentModel.RHS2116,
    ),
    BoardProfile.RHD2164_X1_RHS2116_X1: (
        ComponentModel.RHD2164,
        ComponentModel.RHS2116,
    ),
}
_MODEL_CLASS = {
    ComponentModel.RHD2132: ComponentClass.NEURAL_AFE,
    ComponentModel.RHD2164: ComponentClass.NEURAL_AFE,
    ComponentModel.RHS2116: ComponentClass.NEURAL_AFE,
    ComponentModel.ICM42670P: ComponentClass.IMU,
    ComponentModel.AD5940: ComponentClass.ELECTROCHEM_AFE,
}
_MODEL_CHANNEL_COUNT = {
    ComponentModel.RHD2132: 32,
    ComponentModel.RHD2164: 64,
    ComponentModel.RHS2116: 16,
}
_PROFILE_ID = {
    (1, 1): BoardProfile.RHD2132_X1,
    (1, 2): BoardProfile.RHD2132_X2,
    (2, 1): BoardProfile.RHD2164_X1,
    (2, 2): BoardProfile.RHD2164_X2,
    (3, 1): BoardProfile.RHS2116_X1,
    (3, 2): BoardProfile.RHS2116_X2,
    (4, 2): BoardProfile.RHD2132_X1_RHS2116_X1,
    (5, 2): BoardProfile.RHD2164_X1_RHS2116_X1,
}
_CAPABILITIES_ALL = int(
    ComponentCapability.STREAM_NEURAL
    | ComponentCapability.STREAM_IMU
    | ComponentCapability.AMPEROMETRY
    | ComponentCapability.FSCV
    | ComponentCapability.STIMULATION
    | ComponentCapability.ELECTRODE_IMPEDANCE
)


def _bounded(name: str, value: int, bits: int) -> int:
    if not 0 <= value < (1 << bits):
        raise ProtocolError(f"{name} does not fit in u{bits}: {value}")
    return value


def crc32c(data: bytes, initial: int = 0xFFFFFFFF) -> int:
    """CRC-32C/Castagnoli, reflected, init/xorout FFFFFFFF."""

    crc = initial & 0xFFFFFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def crc16_ccitt(data: bytes, initial: int = 0xFFFF) -> int:
    crc = initial & 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def encode_dhl_packet(packet: DhlPacket) -> bytes:
    payload = bytes(packet.payload)
    if packet.flags != 0:
        raise ProtocolError("DHL v1 header flags must be zero")
    if packet.source_id == 0 or packet.boot_id == 0:
        raise ProtocolError("DHL source_id and boot_id must be nonzero")
    header = DHL_HEADER.pack(
        DHL_VERSION,
        int(packet.packet_type),
        _bounded("flags", packet.flags, 16),
        DHL_HEADER_SIZE,
        0,
        _bounded("payload length", len(payload), 32),
        _bounded("source_id", packet.source_id, 32),
        _bounded("boot_id", packet.boot_id, 64),
        _bounded("sequence", packet.sequence, 64),
        _bounded("timestamp_25mhz", packet.timestamp_25mhz, 64),
    )
    body = header + payload
    return body + DHL_TRAILER.pack(crc32c(body))


def decode_dhl_packet(wire: bytes, *, max_payload: int = 1 << 24) -> DhlPacket:
    if len(wire) < DHL_HEADER_SIZE + DHL_TRAILER.size:
        raise ProtocolError("truncated DHL packet")
    (
        version,
        packet_type,
        flags,
        header_length,
        reserved,
        payload_length,
        source_id,
        boot_id,
        sequence,
        timestamp,
    ) = DHL_HEADER.unpack_from(wire)
    if version != DHL_VERSION:
        raise ProtocolError(f"unsupported DHL version {version}")
    if header_length != DHL_HEADER_SIZE or reserved != 0:
        raise ProtocolError("non-canonical DHL header")
    if flags != 0:
        raise ProtocolError("DHL v1 header flags must be zero")
    if source_id == 0 or boot_id == 0:
        raise ProtocolError("DHL source_id and boot_id must be nonzero")
    if payload_length > max_payload:
        raise ProtocolError("DHL payload exceeds configured bound")
    expected = DHL_HEADER_SIZE + payload_length + DHL_TRAILER.size
    if len(wire) != expected:
        raise ProtocolError(f"DHL length mismatch: expected {expected}, got {len(wire)}")
    expected_crc = DHL_TRAILER.unpack_from(wire, expected - DHL_TRAILER.size)[0]
    actual_crc = crc32c(wire[:-DHL_TRAILER.size])
    if actual_crc != expected_crc:
        raise ProtocolError("DHL CRC32C mismatch")
    try:
        typed = PacketType(packet_type)
    except ValueError as exc:
        raise ProtocolError(f"unknown DHL packet type {packet_type}") from exc
    return DhlPacket(
        packet_type=typed,
        flags=flags,
        source_id=source_id,
        boot_id=boot_id,
        sequence=sequence,
        timestamp_25mhz=timestamp,
        payload=wire[DHL_HEADER_SIZE:-DHL_TRAILER.size],
    )


class DhlStreamState:
    """Fail-closed Descriptor/Inventory/boot/sequence state for one lock epoch."""

    def __init__(self) -> None:
        self.reset_lock()

    def reset_lock(self) -> None:
        self._accepted = 0
        self._source_id: int | None = None
        self._boot_id: int | None = None
        self._next_sequence: int | None = None

    def admit(self, packet: DhlPacket) -> None:
        if packet.flags != 0:
            raise ProtocolError("DHL v1 header flags must be zero")
        if packet.source_id == 0 or packet.boot_id == 0:
            raise ProtocolError("DHL source_id and boot_id must be nonzero")
        if self._accepted == 0:
            if packet.packet_type is not PacketType.DESCRIPTOR:
                raise ProtocolError("first packet after lock is not Descriptor")
            self._source_id = packet.source_id
            self._boot_id = packet.boot_id
            self._next_sequence = packet.sequence + 1
            self._accepted = 1
            return
        if self._accepted == 1 and packet.packet_type is not PacketType.INVENTORY:
            raise ProtocolError("second packet after lock is not Inventory")
        if packet.boot_id != self._boot_id:
            raise ProtocolError("boot ID changed without link relock")
        if packet.source_id != self._source_id:
            raise ProtocolError("source ID changed without link relock")
        if packet.sequence != self._next_sequence:
            raise ProtocolError(
                f"sequence discontinuity: expected {self._next_sequence}, got {packet.sequence}"
            )
        self._next_sequence += 1
        self._accepted += 1


def encode_neural_payload(
    samples: Sequence[Sequence[int]], *, first_sample_counter: int
) -> bytes:
    sample_count = len(samples)
    channel_count = len(samples[0]) if samples else 0
    if channel_count == 0 or sample_count == 0:
        raise ProtocolError("Neural payload requires at least one sample and channel")
    flat: list[int] = []
    for row in samples:
        if len(row) != channel_count:
            raise ProtocolError("Neural sample rows have inconsistent channel count")
        for value in row:
            if not -32768 <= int(value) <= 32767:
                raise ProtocolError(f"sample outside signed int16: {value}")
            flat.append(int(value))
    prefix = NEURAL_PREFIX.pack(
        _bounded("channel_count", channel_count, 16),
        _bounded("sample_count", sample_count, 16),
        1,
        0,
        _bounded("first_sample_counter", first_sample_counter, 64),
    )
    return prefix + struct.pack(f"<{len(flat)}h", *flat)


def decode_neural_payload(payload: bytes) -> tuple[int, list[list[int]]]:
    if len(payload) < NEURAL_PREFIX.size:
        raise ProtocolError("truncated Neural payload")
    channel_count, sample_count, sample_format, reserved, first_counter = NEURAL_PREFIX.unpack_from(payload)
    if not channel_count or not sample_count or sample_format != 1 or reserved != 0:
        raise ProtocolError("non-canonical Neural prefix")
    expected = NEURAL_PREFIX.size + 2 * channel_count * sample_count
    if len(payload) != expected:
        raise ProtocolError("Neural payload length mismatch")
    values = struct.unpack_from(f"<{channel_count * sample_count}h", payload, NEURAL_PREFIX.size)
    rows = [list(values[index : index + channel_count]) for index in range(0, len(values), channel_count)]
    return first_counter, rows


def encode_impedance_payload(payload: ImpedancePayload) -> bytes:
    samples = tuple(int(value) for value in payload.phase_samples)
    if payload.channel_count not in (32, 64):
        raise ProtocolError("Rev A impedance scan requires 32 or 64 channels")
    if not 0 <= payload.channel_index < payload.channel_count:
        raise ProtocolError("impedance channel index is outside the scan")
    if len(samples) != 30:
        raise ProtocolError("Rev A impedance payload requires exactly 30 phase samples")
    if any(not 0 <= value <= 0xFFFF for value in samples):
        raise ProtocolError("impedance phase sample is outside unsigned int16")
    if (
        payload.test_frequency_hz != 1_000
        or payload.phase_sample_rate_hz != 30_000
        or payload.zcheck_scale_code != 1
        or payload.dac_amplitude_code != 127
        or payload.warmup_cycles != 2
        or payload.measurement_cycles != 8
        or payload.flags != IMPEDANCE_FLAGS_ALL
    ):
        raise ProtocolError("impedance payload differs from the frozen Rev A baseline")
    if not 0 <= payload.clip_count <= 30 * payload.measurement_cycles:
        raise ProtocolError("impedance clip count exceeds the measured sample count")
    prefix = IMPEDANCE_PREFIX.pack(
        1,
        _bounded("impedance channel index", payload.channel_index, 16),
        _bounded("impedance channel count", payload.channel_count, 16),
        len(samples),
        payload.test_frequency_hz,
        payload.phase_sample_rate_hz,
        _bounded("impedance CTRL sequence", payload.ctrl_sequence, 32),
        payload.zcheck_scale_code,
        payload.dac_amplitude_code,
        payload.warmup_cycles,
        payload.measurement_cycles,
        payload.clip_count,
        payload.flags,
    )
    return prefix + struct.pack("<30H", *samples)


def decode_impedance_payload(payload: bytes) -> ImpedancePayload:
    if len(payload) != IMPEDANCE_PREFIX.size + 60:
        raise ProtocolError("impedance payload length is not the canonical 88 bytes")
    (
        version,
        channel_index,
        channel_count,
        sample_count,
        test_frequency_hz,
        phase_sample_rate_hz,
        ctrl_sequence,
        zcheck_scale_code,
        dac_amplitude_code,
        warmup_cycles,
        measurement_cycles,
        clip_count,
        flags,
    ) = IMPEDANCE_PREFIX.unpack_from(payload)
    if version != 1 or sample_count != 30:
        raise ProtocolError("non-canonical impedance prefix")
    value = ImpedancePayload(
        channel_index=channel_index,
        channel_count=channel_count,
        test_frequency_hz=test_frequency_hz,
        phase_sample_rate_hz=phase_sample_rate_hz,
        ctrl_sequence=ctrl_sequence,
        zcheck_scale_code=zcheck_scale_code,
        dac_amplitude_code=dac_amplitude_code,
        warmup_cycles=warmup_cycles,
        measurement_cycles=measurement_cycles,
        clip_count=clip_count,
        flags=flags,
        phase_samples=tuple(struct.unpack_from("<30H", payload, IMPEDANCE_PREFIX.size)),
    )
    if encode_impedance_payload(value) != payload:
        raise ProtocolError("non-canonical impedance payload")
    return value


def encode_chem_payload(payload: ChemPayload) -> bytes:
    rows = tuple(tuple(int(value) for value in row) for row in payload.samples)
    sample_count = len(rows)
    channel_count = len(rows[0]) if rows else 0
    if sample_count == 0 or not 1 <= channel_count <= 2:
        raise ProtocolError("Chem payload requires samples with one or two channels")
    flat: list[int] = []
    for row in rows:
        if len(row) != channel_count:
            raise ProtocolError("Chem sample rows have inconsistent channel count")
        for value in row:
            if not -32768 <= value <= 32767:
                raise ProtocolError(f"Chem sample outside signed int16: {value}")
            flat.append(value)
    try:
        mode = ChemMode(payload.mode)
        electrode_configuration = ElectrodeConfiguration(payload.electrode_configuration)
    except ValueError as exc:
        raise ProtocolError("unknown Chem mode or electrode configuration") from exc
    if payload.flags & ~CHEM_FLAGS_ALL:
        raise ProtocolError("Chem flags contain reserved bits")
    if payload.sample_rate_numerator_hz <= 0 or payload.sample_rate_denominator <= 0:
        raise ProtocolError("invalid Chem sample rate")
    if len(payload.config_hash) != 32 or not any(payload.config_hash):
        raise ProtocolError("Chem config_hash must be a nonzero SHA-256")
    artifact_valid = bool(payload.flags & CHEM_FLAG_EPHYS_ARTIFACT_WINDOW_VALID)
    if artifact_valid != (payload.artifact_end_25mhz_exclusive > payload.artifact_start_25mhz):
        raise ProtocolError("Chem artifact flag and interval disagree")
    if payload.flags & CHEM_FLAG_FAST_SETTLE_USED and not artifact_valid:
        raise ProtocolError("Chem Fast Settle requires a valid artifact interval")
    if mode is ChemMode.AMPEROMETRY:
        if (
            payload.holding_potential_uv != payload.switching_potential_uv
            or payload.scan_rate_mv_per_s != 0
            or payload.repetition_rate_millihz != 0
        ):
            raise ProtocolError("non-canonical amperometry parameters")
    elif mode is ChemMode.FSCV:
        if (
            payload.holding_potential_uv == payload.switching_potential_uv
            or payload.scan_rate_mv_per_s <= 0
            or payload.repetition_rate_millihz <= 0
            or not artifact_valid
        ):
            raise ProtocolError("non-canonical FSCV parameters")
    elif mode is ChemMode.EIS:
        raise ProtocolError("EIS requires a future Chem sample format")
    prefix = CHEM_PREFIX.pack(
        1,
        CHEM_PREFIX.size,
        int(mode),
        int(electrode_configuration),
        1,
        _bounded("Chem flags", payload.flags, 32),
        _bounded("Chem acquisition_sequence", payload.acquisition_sequence, 32),
        _bounded("Chem sample_count", sample_count, 32),
        _bounded("Chem channel_count", channel_count, 16),
        0,
        _bounded("Chem sample-rate numerator", payload.sample_rate_numerator_hz, 32),
        _bounded("Chem sample-rate denominator", payload.sample_rate_denominator, 32),
        _bounded("Chem first_sample_counter", payload.first_sample_counter, 64),
        payload.holding_potential_uv,
        payload.switching_potential_uv,
        _bounded("Chem scan_rate_mv_per_s", payload.scan_rate_mv_per_s, 32),
        _bounded("Chem repetition_rate_millihz", payload.repetition_rate_millihz, 32),
        _bounded("Chem artifact_start_25mhz", payload.artifact_start_25mhz, 64),
        _bounded("Chem artifact_end_25mhz_exclusive", payload.artifact_end_25mhz_exclusive, 64),
        payload.config_hash,
    )
    try:
        return prefix + struct.pack(f"<{len(flat)}h", *flat)
    except struct.error as exc:
        raise ProtocolError("Chem field outside wire range") from exc


def decode_chem_payload(payload: bytes) -> ChemPayload:
    if len(payload) < CHEM_PREFIX.size:
        raise ProtocolError("truncated Chem payload")
    (
        version,
        prefix_length,
        mode,
        electrode_configuration,
        sample_format,
        flags,
        acquisition_sequence,
        sample_count,
        channel_count,
        reserved,
        rate_n,
        rate_d,
        first_counter,
        holding_uv,
        switching_uv,
        scan_rate,
        repetition_rate,
        artifact_start,
        artifact_end,
        config_hash,
    ) = CHEM_PREFIX.unpack_from(payload)
    if version != 1 or prefix_length != CHEM_PREFIX.size or sample_format != 1 or reserved != 0:
        raise ProtocolError("non-canonical Chem prefix")
    expected = CHEM_PREFIX.size + 2 * sample_count * channel_count
    if len(payload) != expected:
        raise ProtocolError("Chem payload length mismatch")
    values = struct.unpack_from(f"<{sample_count * channel_count}h", payload, CHEM_PREFIX.size)
    rows = tuple(
        tuple(values[index : index + channel_count])
        for index in range(0, len(values), channel_count)
    )
    value = ChemPayload(
        ChemMode(mode),
        ElectrodeConfiguration(electrode_configuration),
        flags,
        acquisition_sequence,
        rate_n,
        rate_d,
        first_counter,
        holding_uv,
        switching_uv,
        scan_rate,
        repetition_rate,
        artifact_start,
        artifact_end,
        config_hash,
        rows,
    )
    encode_chem_payload(value)
    return value


def encode_descriptor_payload(descriptor: DescriptorPayload) -> bytes:
    profile = (
        descriptor.variant,
        descriptor.chip_count,
        descriptor.feature_flags,
        descriptor.channel_count,
    )
    if profile not in HEADSTAGE_PROFILE_CONTRACTS:
        raise ProtocolError("Descriptor does not match an active Rev A Headstage profile")
    if descriptor.sample_rate_numerator_hz <= 0 or descriptor.sample_rate_denominator <= 0:
        raise ProtocolError("invalid Descriptor sample rate")
    if len(descriptor.device_id) != 16 or not any(descriptor.device_id):
        raise ProtocolError("Descriptor device_id must be a nonzero 16-byte value")
    if len(descriptor.config_hash) != 32 or not any(descriptor.config_hash):
        raise ProtocolError("Descriptor config_hash must be a nonzero SHA-256")
    if len(descriptor.firmware_hash_prefix) != 16 or not any(descriptor.firmware_hash_prefix):
        raise ProtocolError("Descriptor firmware hash prefix must be nonzero")
    return DESCRIPTOR_PAYLOAD.pack(
        1,
        96,
        descriptor.variant,
        descriptor.chip_count,
        descriptor.feature_flags,
        descriptor.channel_count,
        1,
        descriptor.sample_rate_numerator_hz,
        descriptor.sample_rate_denominator,
        25_000_000,
        0,
        descriptor.device_id,
        descriptor.config_hash,
        descriptor.firmware_hash_prefix,
        0,
    )


def decode_descriptor_payload(payload: bytes) -> DescriptorPayload:
    if len(payload) != DESCRIPTOR_PAYLOAD.size:
        raise ProtocolError("Descriptor payload length mismatch")
    (
        version,
        length,
        variant,
        chip_count,
        flags,
        channel_count,
        sample_format,
        rate_n,
        rate_d,
        timestamp_hz,
        reserved0,
        device_id,
        config_hash,
        firmware_hash_prefix,
        reserved1,
    ) = DESCRIPTOR_PAYLOAD.unpack(payload)
    if version != 1 or length != 96 or sample_format != 1 or timestamp_hz != 25_000_000 or reserved0 or reserved1:
        raise ProtocolError("non-canonical Descriptor payload")
    value = DescriptorPayload(
        variant,
        chip_count,
        flags,
        channel_count,
        rate_n,
        rate_d,
        device_id,
        config_hash,
        firmware_hash_prefix,
    )
    encode_descriptor_payload(value)
    return value


def _validate_inventory_entry(entry: ComponentInventoryEntry) -> None:
    try:
        component_class = ComponentClass(entry.component_class)
        status = ComponentStatus(entry.status)
        model_id = ComponentModel(entry.model_id)
    except ValueError as exc:
        raise ProtocolError("unknown Inventory component class, status, or model") from exc
    if _MODEL_CLASS[model_id] is not component_class:
        raise ProtocolError("Inventory component model/class mismatch")
    _bounded("Inventory instance_id", entry.instance_id, 16)
    _bounded("Inventory first_global_channel", entry.first_global_channel, 16)
    _bounded("Inventory channel_count", entry.channel_count, 16)
    _bounded("Inventory native_channel_base", entry.native_channel_base, 16)
    if not 1 <= entry.driver_abi <= 0xFFFF:
        raise ProtocolError("Inventory driver_abi must be nonzero")
    if entry.capability_flags & ~_CAPABILITIES_ALL:
        raise ProtocolError("Inventory capability flags contain reserved bits")
    if len(entry.component_config_hash_prefix) != 12 or not any(
        entry.component_config_hash_prefix
    ):
        raise ProtocolError("Inventory component config hash prefix must be nonzero")

    capabilities = ComponentCapability(entry.capability_flags)
    if component_class is ComponentClass.NEURAL_AFE:
        expected_channels = _MODEL_CHANNEL_COUNT[model_id]
        if (
            entry.first_global_channel == 0xFFFF
            or entry.channel_count != expected_channels
            or entry.native_channel_base != 0
        ):
            raise ProtocolError("non-canonical neural-AFE channel range")
        if not capabilities & ComponentCapability.STREAM_NEURAL:
            raise ProtocolError("neural AFE lacks STREAM_NEURAL capability")
        if model_id is ComponentModel.RHS2116:
            if not capabilities & ComponentCapability.STIMULATION:
                raise ProtocolError("RHS2116 lacks STIMULATION capability")
        else:
            if capabilities & ComponentCapability.STIMULATION:
                raise ProtocolError("recording-only RHD AFE advertises stimulation")
            if not capabilities & ComponentCapability.ELECTRODE_IMPEDANCE:
                raise ProtocolError("RHD AFE lacks ELECTRODE_IMPEDANCE capability")
    else:
        if (
            entry.first_global_channel != 0xFFFF
            or entry.channel_count != 0
            or entry.native_channel_base != 0
        ):
            raise ProtocolError("non-neural Inventory entry carries Neural channels")
        if component_class is ComponentClass.IMU:
            if capabilities != ComponentCapability.STREAM_IMU:
                raise ProtocolError("non-canonical IMU capabilities")
        elif capabilities != (
            ComponentCapability.AMPEROMETRY | ComponentCapability.FSCV
        ):
            raise ProtocolError("non-canonical electrochem capabilities")

def encode_inventory_payload(inventory: InventoryPayload) -> bytes:
    try:
        board_profile_id = BoardProfile(inventory.board_profile_id)
    except ValueError as exc:
        raise ProtocolError("unknown Inventory board profile") from exc
    if len(inventory.assembly_manifest_hash) != 32 or not any(inventory.assembly_manifest_hash):
        raise ProtocolError("Inventory assembly manifest hash must be nonzero")
    if len(inventory.channel_map_hash) != 32 or not any(inventory.channel_map_hash):
        raise ProtocolError("Inventory channel map hash must be nonzero")
    entries = tuple(inventory.entries)
    if not 1 <= len(entries) <= 16:
        raise ProtocolError("Inventory requires 1..16 component entries")
    if tuple(entry.instance_id for entry in entries) != tuple(
        sorted(entry.instance_id for entry in entries)
    ):
        raise ProtocolError("Inventory entries are not sorted by instance_id")
    if len({entry.instance_id for entry in entries}) != len(entries):
        raise ProtocolError("Inventory instance_id values are not unique")
    encoded_entries: list[bytes] = []
    for entry in entries:
        _validate_inventory_entry(entry)
        encoded_entries.append(
            INVENTORY_ENTRY.pack(
                entry.instance_id,
                int(entry.component_class),
                int(entry.status),
                int(entry.model_id),
                entry.first_global_channel,
                entry.channel_count,
                entry.native_channel_base,
                entry.driver_abi,
                entry.capability_flags,
                entry.component_config_hash_prefix,
            )
        )
    return INVENTORY_HEADER.pack(
        1,
        INVENTORY_HEADER.size,
        INVENTORY_ENTRY.size,
        len(entries),
        int(board_profile_id),
        inventory.assembly_manifest_hash,
        inventory.channel_map_hash,
    ) + b"".join(encoded_entries)


def decode_inventory_payload(payload: bytes) -> InventoryPayload:
    if len(payload) < INVENTORY_HEADER.size:
        raise ProtocolError("truncated Inventory payload")
    (
        version,
        header_length,
        entry_size,
        entry_count,
        board_profile_id,
        assembly_manifest_hash,
        channel_map_hash,
    ) = INVENTORY_HEADER.unpack_from(payload)
    expected = INVENTORY_HEADER.size + entry_count * INVENTORY_ENTRY.size
    if (
        version != 1
        or header_length != INVENTORY_HEADER.size
        or entry_size != INVENTORY_ENTRY.size
        or len(payload) != expected
    ):
        raise ProtocolError("non-canonical Inventory header or length")
    entries = []
    for index in range(entry_count):
        fields = INVENTORY_ENTRY.unpack_from(
            payload, INVENTORY_HEADER.size + index * INVENTORY_ENTRY.size
        )
        try:
            entry = ComponentInventoryEntry(
                instance_id=fields[0],
                component_class=ComponentClass(fields[1]),
                status=ComponentStatus(fields[2]),
                model_id=ComponentModel(fields[3]),
                first_global_channel=fields[4],
                channel_count=fields[5],
                native_channel_base=fields[6],
                driver_abi=fields[7],
                capability_flags=fields[8],
                component_config_hash_prefix=fields[9],
            )
        except ValueError as exc:
            raise ProtocolError("unknown Inventory component class, status, or model") from exc
        entries.append(entry)
    try:
        value = InventoryPayload(
            board_profile_id=BoardProfile(board_profile_id),
            assembly_manifest_hash=assembly_manifest_hash,
            channel_map_hash=channel_map_hash,
            entries=tuple(entries),
        )
    except ValueError as exc:
        raise ProtocolError("unknown Inventory board profile") from exc
    if encode_inventory_payload(value) != payload:
        raise ProtocolError("non-canonical Inventory payload")
    return value


def validate_inventory_against_descriptor(
    inventory: InventoryPayload, descriptor: DescriptorPayload
) -> None:
    expected_profile = _PROFILE_ID.get((descriptor.variant, descriptor.chip_count))
    if expected_profile is None or inventory.board_profile_id is not expected_profile:
        raise ProtocolError("Inventory board profile differs from Descriptor")
    if any(
        entry.status
        in (ComponentStatus.EXPECTED_NOT_PROBED, ComponentStatus.UNEXPECTED_PRESENT)
        for entry in inventory.entries
    ):
        raise ProtocolError("Inventory contains an unresolved probe or unexpected component")
    expected_models = _PROFILE_NEURAL_MODELS[inventory.board_profile_id]
    neural_entries = [
        entry
        for entry in inventory.entries
        if entry.component_class is ComponentClass.NEURAL_AFE
    ]
    if len(neural_entries) != descriptor.chip_count:
        raise ProtocolError("Inventory neural-AFE count differs from Descriptor")
    if tuple(entry.model_id for entry in neural_entries) != expected_models:
        raise ProtocolError("Inventory neural-AFE model order differs from board profile")
    if any(entry.status is not ComponentStatus.DETECTED_READY for entry in neural_entries):
        raise ProtocolError("Inventory primary neural AFE is not ready")
    next_channel = 0
    for entry in neural_entries:
        if entry.first_global_channel != next_channel:
            raise ProtocolError("Inventory Neural channel ranges are not contiguous")
        next_channel += entry.channel_count
    if next_channel != descriptor.channel_count:
        raise ProtocolError("Inventory Neural channel total differs from Descriptor")

    detected_features = 0
    for entry in inventory.entries:
        if entry.status is not ComponentStatus.DETECTED_READY:
            continue
        if entry.component_class is ComponentClass.IMU:
            detected_features |= 2
        elif entry.component_class is ComponentClass.ELECTROCHEM_AFE:
            detected_features |= 1
        elif entry.model_id is ComponentModel.RHS2116:
            detected_features |= 4
    if detected_features != descriptor.feature_flags:
        raise ProtocolError("Inventory detected features differ from Descriptor")


def encode_ack_payload(ack: AckPayload) -> bytes:
    try:
        opcode = CtrlOpcode(ack.opcode)
        status = AckStatus(ack.status)
    except ValueError as exc:
        raise ProtocolError("ACK contains an unknown CTRL opcode or status") from exc
    return ACK_PAYLOAD.pack(
        _bounded("ACK ctrl_sequence", ack.ctrl_sequence, 32),
        int(opcode),
        int(status),
        0,
    )


def decode_ack_payload(payload: bytes) -> AckPayload:
    if len(payload) != ACK_PAYLOAD.size:
        raise ProtocolError("ACK payload length mismatch")
    ctrl_sequence, opcode, status, reserved = ACK_PAYLOAD.unpack(payload)
    if reserved != 0:
        raise ProtocolError("ACK reserved field is nonzero")
    try:
        value = AckPayload(
            ctrl_sequence=ctrl_sequence,
            opcode=CtrlOpcode(opcode),
            status=AckStatus(status),
        )
    except ValueError as exc:
        raise ProtocolError("ACK contains an unknown CTRL opcode or status") from exc
    if encode_ack_payload(value) != payload:
        raise ProtocolError("non-canonical ACK payload")
    return value


def encode_ctrl_frame(frame: CtrlFrame) -> bytes:
    payload = bytes(frame.payload)
    header = CTRL_HEADER.pack(
        DHL_VERSION,
        _bounded("opcode", frame.opcode, 8),
        _bounded("flags", frame.flags, 16),
        _bounded("sequence", frame.sequence, 32),
        _bounded("payload length", len(payload), 16),
        0,
    )
    body = header + payload
    return CTRL_PREAMBLE + body + CTRL_TRAILER.pack(crc16_ccitt(body))


def decode_ctrl_frame(wire: bytes, *, max_payload: int = 4096) -> CtrlFrame:
    minimum = len(CTRL_PREAMBLE) + CTRL_HEADER.size + CTRL_TRAILER.size
    if len(wire) < minimum or not wire.startswith(CTRL_PREAMBLE):
        raise ProtocolError("CTRL preamble missing or frame truncated")
    body = wire[len(CTRL_PREAMBLE) : -CTRL_TRAILER.size]
    version, opcode, flags, sequence, payload_length, reserved = CTRL_HEADER.unpack_from(body)
    if version != DHL_VERSION or reserved != 0:
        raise ProtocolError("non-canonical CTRL header")
    if payload_length > max_payload:
        raise ProtocolError("CTRL payload exceeds configured bound")
    if len(body) != CTRL_HEADER.size + payload_length:
        raise ProtocolError("CTRL length mismatch")
    expected_crc = CTRL_TRAILER.unpack_from(wire, len(wire) - CTRL_TRAILER.size)[0]
    if crc16_ccitt(body) != expected_crc:
        raise ProtocolError("CTRL CRC16 mismatch")
    return CtrlFrame(opcode=opcode, flags=flags, sequence=sequence, payload=body[CTRL_HEADER.size:])


def encode_manchester(bits: Iterable[int]) -> tuple[int, ...]:
    chips: list[int] = []
    for bit in bits:
        if bit not in (0, 1):
            raise ProtocolError(f"Manchester input is not a bit: {bit}")
        chips.extend((0, 1) if bit == 0 else (1, 0))
    return tuple(chips)


def decode_manchester(chips: Sequence[int]) -> tuple[int, ...]:
    if len(chips) % 2:
        raise ProtocolError("odd Manchester chip count")
    bits: list[int] = []
    for index in range(0, len(chips), 2):
        pair = tuple(chips[index : index + 2])
        if pair == (0, 1):
            bits.append(0)
        elif pair == (1, 0):
            bits.append(1)
        else:
            raise ProtocolError(f"invalid Manchester symbol {pair}")
    return tuple(bits)
