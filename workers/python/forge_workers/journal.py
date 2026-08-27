"""Durability-bounded reader for ``forge-acqd`` journal format version 1.

The journal chunk header is a redundant cache.  The embedded M0
``CanonicalRecordEnvelopeV1`` is authoritative.  This reader validates both,
including the distinction between global ``journal_sequence`` and per-Pod
``record_sequence``, and never exposes bytes beyond the latest valid A/B
durable checkpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from struct import unpack_from
from typing import BinaryIO
from uuid import UUID

from ._protocol import protocol


FILE_MAGIC = b"FORGEWAL"
CHUNK_MAGIC = b"FRGCHNK1"
COMMIT_MAGIC = b"FRGCMIT1"
CHECKPOINT_MAGIC = b"FRGCKP01"
SEAL_MAGIC = b"FRGSEAL1"
FORMAT_VERSION = 1
FILE_HEADER_LEN = 64
CHUNK_HEADER_LEN = 80
COMMIT_FOOTER_LEN = 24
CHECKPOINT_LEN = 128
SEAL_LEN = 128
MAX_ENCODED_RECORD_LEN = protocol.MAX_RECORD_PAYLOAD_LEN + protocol.RECORD_HEADER_LEN
DISCONTINUITY_BEFORE = 0x0000_0001


class JournalFormatError(ValueError):
    """A journal, durable checkpoint, seal, or canonical record is invalid."""


def crc32c(data: bytes | bytearray | memoryview) -> int:
    """Use the protocol binding's normative CRC-32C implementation."""

    return protocol.crc32c(bytes(data))


def pod_slot_for(canonical_pod_id: bytes) -> int:
    if len(canonical_pod_id) != 16:
        raise ValueError("canonical Pod ID must contain 16 bytes")
    return crc32c(canonical_pod_id) & 0xFFFF


@dataclass(frozen=True, slots=True)
class JournalIdentity:
    run_id: UUID
    protocol_contract_hash: str

    @property
    def run_id_bytes(self) -> bytes:
        return self.run_id.bytes


@dataclass(frozen=True, slots=True)
class DurableCheckpoint:
    generation: int
    durable_journal_sequence: int | None
    durable_valid_len: int
    durable_record_count: int


@dataclass(frozen=True, slots=True)
class SealReceipt:
    expected_last_journal_sequence: int | None
    expected_valid_len: int
    checkpoint_generation: int
    record_count: int


@dataclass(frozen=True, slots=True)
class JournalChunkMetadata:
    journal_sequence: int
    pod_slot: int
    record_sequence: int
    frame_start: int
    frame_end_exclusive: int
    sample_start: int
    sample_end_exclusive: int
    global_time_start_ns: int
    global_time_end_exclusive_ns: int
    encoded_record_crc32c: int


@dataclass(frozen=True, slots=True)
class JournalChunk:
    metadata: JournalChunkMetadata
    canonical: protocol.DecodedRecord
    encoded_record: bytes
    file_offset: int
    next_file_offset: int


@dataclass(frozen=True, slots=True)
class JournalScan:
    identity: JournalIdentity
    complete_chunks: int
    last_journal_sequence: int | None
    valid_len: int
    file_len: int
    torn_tail: bool
    durable: DurableCheckpoint
    seal: SealReceipt | None


@dataclass(frozen=True, slots=True)
class JournalPoll:
    chunks: tuple[JournalChunk, ...]
    unproven_tail: bool
    cursor_offset: int
    next_journal_sequence: int
    durable_checkpoint_generation: int


@dataclass(slots=True)
class _PodContinuity:
    last_record_sequence: int
    last_frame_end_exclusive: int | None = None
    last_sample_end_exclusive: int | None = None
    last_global_time_end_exclusive_ns: int | None = None
    channel_layout_id: int | None = None
    channel_count: int | None = None
    sample_format: int | None = None


class _ContinuityTracker:
    def __init__(self) -> None:
        self._pods: dict[bytes, _PodContinuity] = {}
        self._slots: dict[int, bytes] = {}

    def validate_and_advance(
        self,
        identity: JournalIdentity,
        cache: tuple[int, int, int, int, int, int, int],
        canonical: protocol.DecodedRecord,
    ) -> None:
        _validate_typed_record_payload(canonical)
        (
            pod_slot,
            frame_start,
            frame_end_exclusive,
            sample_start,
            sample_end_exclusive,
            global_time_start_ns,
            global_time_end_exclusive_ns,
        ) = cache
        envelope = canonical.envelope
        if envelope.run_id != identity.run_id_bytes:
            raise JournalFormatError("canonical record run_id does not match journal run_id")
        expected_slot = pod_slot_for(envelope.pod_id)
        if pod_slot != expected_slot:
            raise JournalFormatError("journal Pod projection does not match canonical record")
        known_pod = self._slots.get(expected_slot)
        if known_pod is not None and known_pod != envelope.pod_id:
            raise JournalFormatError("16-bit Pod projection collision in one Run")
        self._slots[expected_slot] = envelope.pod_id
        if (
            frame_start != envelope.frame_start
            or frame_end_exclusive != envelope.frame_end_exclusive
            or sample_start != envelope.sample_start
            or sample_end_exclusive != envelope.sample_end_exclusive
            or global_time_start_ns != envelope.global_time_start_ns
            or global_time_end_exclusive_ns != envelope.global_time_end_exclusive_ns
        ):
            raise JournalFormatError(
                "journal range cache does not match canonical record envelope"
            )

        state = self._pods.get(envelope.pod_id)
        if state is None:
            if envelope.record_sequence != 0:
                raise JournalFormatError(
                    "first canonical record sequence for a Pod is not zero"
                )
            state = _PodContinuity(last_record_sequence=0)
        elif envelope.record_sequence != state.last_record_sequence + 1:
            raise JournalFormatError(
                "canonical per-Pod record sequence is not contiguous"
            )
        state.last_record_sequence = envelope.record_sequence

        if envelope.record_kind == protocol.RecordKind.SAMPLE_BLOCK:
            discontinuity = bool(envelope.flags & DISCONTINUITY_BEFORE)
            for name, previous, current in (
                ("frame", state.last_frame_end_exclusive, envelope.frame_start),
                ("sample", state.last_sample_end_exclusive, envelope.sample_start),
                (
                    "global-time",
                    state.last_global_time_end_exclusive_ns,
                    envelope.global_time_start_ns,
                ),
            ):
                if previous is not None and current < previous:
                    raise JournalFormatError(
                        f"canonical {name} range overlaps prior SampleBlock"
                    )
                if previous is not None and current != previous and not discontinuity:
                    raise JournalFormatError(
                        f"canonical {name} gap lacks DISCONTINUITY_BEFORE"
                    )
            for name, previous, current in (
                ("channel layout", state.channel_layout_id, envelope.channel_layout_id),
                ("channel count", state.channel_count, envelope.channel_count),
                ("sample format", state.sample_format, envelope.sample_format),
            ):
                if previous is not None and current != previous:
                    raise JournalFormatError(
                        f"{name} changed within an armed Pod stream"
                    )
            state.last_frame_end_exclusive = envelope.frame_end_exclusive
            state.last_sample_end_exclusive = envelope.sample_end_exclusive
            state.last_global_time_end_exclusive_ns = (
                envelope.global_time_end_exclusive_ns
            )
            state.channel_layout_id = envelope.channel_layout_id
            state.channel_count = envelope.channel_count
            state.sample_format = envelope.sample_format
        self._pods[envelope.pod_id] = state


def _validate_typed_record_payload(canonical: protocol.DecodedRecord) -> None:
    envelope = canonical.envelope
    if envelope.record_kind == protocol.RecordKind.SAMPLE_BLOCK:
        return
    if envelope.record_kind in (
        protocol.RecordKind.MARKER,
        protocol.RecordKind.FAULT,
        protocol.RecordKind.ONLINE_ANALYSIS,
    ):
        try:
            event = protocol.decode_event_payload(canonical.payload)
        except protocol.EventPayloadError as error:
            raise JournalFormatError(f"invalid typed event payload: {error.code}") from error
        expected = {
            protocol.RecordKind.MARKER: (protocol.MarkerPayloadV1,),
            protocol.RecordKind.FAULT: (protocol.FaultPayloadV1, protocol.GapPayloadV1),
            protocol.RecordKind.ONLINE_ANALYSIS: (protocol.OnlineAnalysisPayloadV1,),
        }[envelope.record_kind]
        if not isinstance(event, expected):
            raise JournalFormatError("event payload kind contradicts outer RecordKind")
        if isinstance(event, protocol.GapPayloadV1):
            if event.gap_flags != (
                protocol.EVENT_FAULT_FLAG_RUN_LATCHED
                | protocol.EVENT_FAULT_FLAG_STIM_DISARMING
            ):
                raise JournalFormatError("Gap payload must latch Run and stimulation disarm")
            frame_count = envelope.frame_end_exclusive - envelope.frame_start
            sample_count = envelope.sample_end_exclusive - envelope.sample_start
            if event.missing_frame_count not in (0, frame_count):
                raise JournalFormatError("Gap frame count contradicts outer range")
            if event.missing_sample_count not in (0, sample_count):
                raise JournalFormatError("Gap sample count contradicts outer range")
        if isinstance(event, protocol.OnlineAnalysisPayloadV1):
            if event.source_record_sequence >= envelope.record_sequence:
                raise JournalFormatError("analysis source must precede event record")
        return
    if envelope.record_kind == protocol.RecordKind.STIM_INTENT:
        try:
            intent = protocol.StimIntentV1.from_bytes(canonical.payload)
        except protocol.CodecError as error:
            raise JournalFormatError(f"invalid StimIntent payload: {error.code}") from error
        if (
            intent.run_id != envelope.run_id
            or not envelope.sample_start
            <= intent.source_sample_counter
            < envelope.sample_end_exclusive
            or not envelope.global_time_start_ns
            <= intent.source_global_time_ns
            < envelope.global_time_end_exclusive_ns
            or intent.source_record_sequence >= envelope.record_sequence
        ):
            raise JournalFormatError("StimIntent contradicts outer envelope")
        return
    if envelope.record_kind == protocol.RecordKind.STIM_RECEIPT:
        try:
            receipt = protocol.StimReceiptV1.from_bytes(canonical.payload)
        except protocol.CodecError as error:
            raise JournalFormatError(f"invalid StimReceipt payload: {error.code}") from error
        if receipt.run_id != envelope.run_id:
            raise JournalFormatError("StimReceipt Run contradicts outer envelope")
        if receipt.result == 1 and not (
            envelope.global_time_start_ns
            <= receipt.actual_start_global_time_ns
            <= receipt.actual_end_global_time_ns
            < envelope.global_time_end_exclusive_ns
        ):
            raise JournalFormatError("executed StimReceipt time contradicts outer range")


def _read_identity(file: BinaryIO) -> JournalIdentity:
    file.seek(0)
    header = file.read(FILE_HEADER_LEN)
    if len(header) != FILE_HEADER_LEN:
        raise JournalFormatError("empty or torn Forge journal header")
    if header[:8] != FILE_MAGIC:
        raise JournalFormatError("invalid Forge journal magic")
    version, header_len = unpack_from("<HH", header, 8)
    if version != FORMAT_VERSION:
        raise JournalFormatError(f"unsupported Forge journal version {version}")
    if header_len != FILE_HEADER_LEN:
        raise JournalFormatError("invalid Forge journal header length")
    if crc32c(header[:60]) != unpack_from("<I", header, 60)[0]:
        raise JournalFormatError("Forge journal header CRC32C mismatch")
    run_id_bytes = bytes(header[12:28])
    if not any(run_id_bytes):
        raise JournalFormatError("Forge journal run_id is zero")
    contract_hash = bytes(header[28:60])
    if contract_hash != protocol.PROTOCOL_HASH:
        raise JournalFormatError(
            "Forge journal protocol hash is not host protocol v1"
        )
    return JournalIdentity(UUID(bytes=run_id_bytes), contract_hash.hex())


def _sidecar_path(path: Path, suffix: str) -> Path:
    return Path(f"{path}{suffix}")


def _read_fixed(path: Path, size: int) -> bytes:
    data = path.read_bytes()
    if len(data) != size:
        raise JournalFormatError(f"{path.name} has an invalid length")
    return data


def _decode_checkpoint(data: bytes, identity: JournalIdentity) -> DurableCheckpoint:
    if (
        data[:8] != CHECKPOINT_MAGIC
        or unpack_from("<H", data, 8)[0] != FORMAT_VERSION
        or unpack_from("<H", data, 10)[0] != CHECKPOINT_LEN
    ):
        raise JournalFormatError("invalid durable checkpoint header")
    if data[20:36] != identity.run_id_bytes or data[36:68].hex() != identity.protocol_contract_hash:
        raise JournalFormatError("durable checkpoint identity mismatch")
    if any(data[92:124]):
        raise JournalFormatError("durable checkpoint reserved bytes are nonzero")
    if unpack_from("<I", data, 124)[0] != crc32c(data[:124]):
        raise JournalFormatError("durable checkpoint CRC32C mismatch")
    raw_sequence = unpack_from("<Q", data, 76)[0]
    checkpoint = DurableCheckpoint(
        generation=unpack_from("<Q", data, 12)[0],
        durable_journal_sequence=(None if raw_sequence == 0xFFFF_FFFF_FFFF_FFFF else raw_sequence),
        durable_valid_len=unpack_from("<Q", data, 68)[0],
        durable_record_count=unpack_from("<Q", data, 84)[0],
    )
    if (
        checkpoint.durable_valid_len < FILE_HEADER_LEN
        or (checkpoint.durable_record_count == 0)
        != (checkpoint.durable_journal_sequence is None)
        or checkpoint.durable_journal_sequence
        != (
            None
            if checkpoint.durable_record_count == 0
            else checkpoint.durable_record_count - 1
        )
    ):
        raise JournalFormatError("durable checkpoint invariants failed")
    return checkpoint


def _load_checkpoint(path: Path, identity: JournalIdentity) -> DurableCheckpoint:
    valid: list[DurableCheckpoint] = []
    existed = False
    for suffix in (".checkpoint-a", ".checkpoint-b"):
        slot = _sidecar_path(path, suffix)
        if not slot.exists():
            continue
        existed = True
        try:
            valid.append(_decode_checkpoint(_read_fixed(slot, CHECKPOINT_LEN), identity))
        except (OSError, JournalFormatError):
            continue
    if valid:
        by_generation: dict[int, DurableCheckpoint] = {}
        for checkpoint in valid:
            prior = by_generation.get(checkpoint.generation)
            if prior is not None and prior != checkpoint:
                raise JournalFormatError(
                    "conflicting durable checkpoints share one generation"
                )
            by_generation[checkpoint.generation] = checkpoint
        return max(valid, key=lambda item: item.generation)
    if existed:
        raise JournalFormatError("no valid A/B durable checkpoint remains")
    return DurableCheckpoint(0, None, FILE_HEADER_LEN, 0)


def _decode_seal(data: bytes, identity: JournalIdentity) -> SealReceipt:
    if (
        data[:8] != SEAL_MAGIC
        or unpack_from("<H", data, 8)[0] != FORMAT_VERSION
        or unpack_from("<H", data, 10)[0] != SEAL_LEN
    ):
        raise JournalFormatError("invalid journal seal header")
    if data[12:28] != identity.run_id_bytes or data[28:60].hex() != identity.protocol_contract_hash:
        raise JournalFormatError("journal seal identity mismatch")
    if any(data[92:124]) or unpack_from("<I", data, 124)[0] != crc32c(data[:124]):
        raise JournalFormatError("journal seal CRC/reserved validation failed")
    raw_sequence = unpack_from("<Q", data, 60)[0]
    seal = SealReceipt(
        expected_last_journal_sequence=(
            None if raw_sequence == 0xFFFF_FFFF_FFFF_FFFF else raw_sequence
        ),
        expected_valid_len=unpack_from("<Q", data, 68)[0],
        checkpoint_generation=unpack_from("<Q", data, 76)[0],
        record_count=unpack_from("<Q", data, 84)[0],
    )
    if (seal.record_count == 0) != (seal.expected_last_journal_sequence is None) or (
        seal.expected_last_journal_sequence
        != (None if seal.record_count == 0 else seal.record_count - 1)
    ):
        raise JournalFormatError("journal seal sequence/count invariants failed")
    return seal


def _load_seal(path: Path, identity: JournalIdentity) -> SealReceipt | None:
    seal_path = _sidecar_path(path, ".seal")
    if not seal_path.exists():
        return None
    return _decode_seal(_read_fixed(seal_path, SEAL_LEN), identity)


def _decode_complete_chunk(
    file: BinaryIO,
    *,
    identity: JournalIdentity,
    tracker: _ContinuityTracker,
    boundary: int,
    offset: int,
    expected_journal_sequence: int,
    allow_incomplete: bool,
) -> tuple[JournalChunk | None, bool]:
    """Return ``(chunk, incomplete_tail)`` without waiting for bytes."""

    if offset == boundary:
        return None, False
    if boundary - offset < CHUNK_HEADER_LEN:
        if allow_incomplete:
            return None, True
        raise JournalFormatError("durable boundary cuts through a chunk header")
    file.seek(offset)
    header = file.read(CHUNK_HEADER_LEN)
    if header[:8] != CHUNK_MAGIC:
        raise JournalFormatError("invalid journal chunk magic")
    if header[18:20] != b"\x00\x00":
        raise JournalFormatError("journal chunk reserved bytes are nonzero")
    if crc32c(header[:76]) != unpack_from("<I", header, 76)[0]:
        raise JournalFormatError("journal chunk header CRC32C mismatch")

    journal_sequence = unpack_from("<Q", header, 8)[0]
    pod_slot = unpack_from("<H", header, 16)[0]
    encoded_record_len = unpack_from("<I", header, 20)[0]
    if not 0 < encoded_record_len <= MAX_ENCODED_RECORD_LEN:
        raise JournalFormatError("journal encoded record length exceeds safety bounds")
    if journal_sequence != expected_journal_sequence:
        raise JournalFormatError(
            "non-monotonic journal sequence: "
            f"expected {expected_journal_sequence}, got {journal_sequence}"
        )
    record_len = CHUNK_HEADER_LEN + encoded_record_len + COMMIT_FOOTER_LEN
    if boundary - offset < record_len:
        if allow_incomplete:
            return None, True
        raise JournalFormatError("durable boundary cuts through a committed record")

    encoded_record = file.read(encoded_record_len)
    encoded_record_crc = unpack_from("<I", header, 72)[0]
    if crc32c(encoded_record) != encoded_record_crc:
        raise JournalFormatError("journal encoded record CRC32C mismatch")
    footer = file.read(COMMIT_FOOTER_LEN)
    if footer[:8] != COMMIT_MAGIC:
        raise JournalFormatError("invalid journal commit magic")
    footer_sequence, footer_record_crc = unpack_from("<QI", footer, 8)
    if footer_sequence != journal_sequence or footer_record_crc != encoded_record_crc:
        raise JournalFormatError("journal commit does not match chunk")
    if crc32c(footer[:20]) != unpack_from("<I", footer, 20)[0]:
        raise JournalFormatError("journal commit CRC32C mismatch")
    try:
        canonical = protocol.decode_record(encoded_record)
    except protocol.CodecError as error:
        raise JournalFormatError(
            f"invalid CanonicalRecordEnvelopeV1: {error.code}"
        ) from error

    cache = (
        pod_slot,
        unpack_from("<Q", header, 24)[0],
        unpack_from("<Q", header, 32)[0],
        unpack_from("<Q", header, 40)[0],
        unpack_from("<Q", header, 48)[0],
        unpack_from("<Q", header, 56)[0],
        unpack_from("<Q", header, 64)[0],
    )
    tracker.validate_and_advance(identity, cache, canonical)
    metadata = JournalChunkMetadata(
        journal_sequence=journal_sequence,
        pod_slot=pod_slot,
        record_sequence=canonical.envelope.record_sequence,
        frame_start=cache[1],
        frame_end_exclusive=cache[2],
        sample_start=cache[3],
        sample_end_exclusive=cache[4],
        global_time_start_ns=cache[5],
        global_time_end_exclusive_ns=cache[6],
        encoded_record_crc32c=encoded_record_crc,
    )
    next_offset = offset + record_len
    return (
        JournalChunk(metadata, canonical, encoded_record, offset, next_offset),
        False,
    )


def _scan_prefix(
    file: BinaryIO,
    *,
    identity: JournalIdentity,
    boundary: int,
    allow_incomplete: bool,
) -> tuple[int, int | None, int, bool]:
    tracker = _ContinuityTracker()
    offset = FILE_HEADER_LEN
    next_sequence = 0
    while True:
        chunk, incomplete = _decode_complete_chunk(
            file,
            identity=identity,
            tracker=tracker,
            boundary=boundary,
            offset=offset,
            expected_journal_sequence=next_sequence,
            allow_incomplete=allow_incomplete,
        )
        if chunk is None:
            return next_sequence, (next_sequence - 1 if next_sequence else None), offset, incomplete
        offset = chunk.next_file_offset
        next_sequence += 1


def _validate_durable_prefix(
    file: BinaryIO,
    identity: JournalIdentity,
    checkpoint: DurableCheckpoint,
    file_len: int,
) -> None:
    if checkpoint.durable_valid_len > file_len:
        raise JournalFormatError("durable checkpoint extends beyond journal file")
    count, last_sequence, valid_len, incomplete = _scan_prefix(
        file,
        identity=identity,
        boundary=checkpoint.durable_valid_len,
        allow_incomplete=False,
    )
    if incomplete or valid_len != checkpoint.durable_valid_len:
        raise JournalFormatError("durable checkpoint is not an exact record boundary")
    if (
        count != checkpoint.durable_record_count
        or last_sequence != checkpoint.durable_journal_sequence
    ):
        raise JournalFormatError("durable checkpoint count/sequence mismatch")


def scan_journal(path: str | Path) -> JournalScan:
    journal_path = Path(path)
    with journal_path.open("rb") as file:
        identity = _read_identity(file)
        file.seek(0, 2)
        file_len = file.tell()
        durable = _load_checkpoint(journal_path, identity)
        _validate_durable_prefix(file, identity, durable, file_len)
        complete, last, valid_len, torn_tail = _scan_prefix(
            file,
            identity=identity,
            boundary=file_len,
            allow_incomplete=True,
        )
    seal = _load_seal(journal_path, identity)
    if seal is not None and (
        torn_tail
        or valid_len != file_len
        or seal.expected_valid_len != valid_len
        or seal.expected_last_journal_sequence != last
        or seal.record_count != complete
        or seal.checkpoint_generation != durable.generation
        or durable.durable_valid_len != valid_len
        or durable.durable_journal_sequence != last
    ):
        raise JournalFormatError("journal seal does not match durable journal contents")
    return JournalScan(
        identity=identity,
        complete_chunks=complete,
        last_journal_sequence=last,
        valid_len=valid_len,
        file_len=file_len,
        torn_tail=torn_tail,
        durable=durable,
        seal=seal,
    )


class JournalCursor:
    """Bounded, non-waiting cursor over newly *durable* canonical records."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        with self.path.open("rb") as file:
            self.identity = _read_identity(file)
            checkpoint = _load_checkpoint(self.path, self.identity)
            # Select the durable checkpoint first, then observe EOF from the
            # same open descriptor. A writer may append+fsync+advance its
            # checkpoint between either operation; validating a newly selected
            # checkpoint against a stale EOF would falsely reject that legal
            # update.
            file.seek(0, 2)
            file_len = file.tell()
            _validate_durable_prefix(file, self.identity, checkpoint, file_len)
        seal = _load_seal(self.path, self.identity)
        if seal is not None:
            sealed_scan = scan_journal(self.path)
            checkpoint = sealed_scan.durable
        self._checkpoint = checkpoint
        self._seal = seal
        self._offset = FILE_HEADER_LEN
        self._next_journal_sequence = 0
        self._tracker = _ContinuityTracker()

    @property
    def next_journal_sequence(self) -> int:
        return self._next_journal_sequence

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def durable_checkpoint(self) -> DurableCheckpoint:
        return self._checkpoint

    @property
    def seal(self) -> SealReceipt | None:
        """The immutable seal observed by the cursor, if one is durable."""

        return self._seal

    @property
    def caught_up_to_durable(self) -> bool:
        """Whether every byte admitted by the durable checkpoint was consumed."""

        return self._offset == self._checkpoint.durable_valid_len

    @property
    def caught_up_to_seal(self) -> bool:
        """Whether this cursor consumed exactly the sealed durable journal."""

        seal = self._seal
        if seal is None or not self.caught_up_to_durable:
            return False
        return self._next_journal_sequence == seal.record_count

    def _refresh_durable_boundary(self, file: BinaryIO) -> int:
        if _read_identity(file) != self.identity:
            raise JournalFormatError("journal identity changed while cursor was active")
        checkpoint = _load_checkpoint(self.path, self.identity)
        if checkpoint.generation < self._checkpoint.generation:
            raise JournalFormatError("durable checkpoint generation moved backwards")
        if checkpoint.generation == self._checkpoint.generation and checkpoint != self._checkpoint:
            raise JournalFormatError("durable checkpoint changed without a new generation")
        if (
            checkpoint.durable_valid_len < self._checkpoint.durable_valid_len
            or checkpoint.durable_record_count < self._checkpoint.durable_record_count
        ):
            raise JournalFormatError("durable checkpoint watermark moved backwards")
        if checkpoint.durable_valid_len < self._offset:
            raise JournalFormatError("durable checkpoint moved behind the active cursor")
        seal = _load_seal(self.path, self.identity)
        if self._seal is not None and seal != self._seal:
            raise JournalFormatError("journal seal changed while cursor was active")
        if seal is not None and self._seal is None:
            sealed_scan = scan_journal(self.path)
            checkpoint = sealed_scan.durable
            self._seal = seal
        # Observe EOF only after selecting the checkpoint (and any seal-bound
        # checkpoint). This preserves the A/B monotonicity checks above while
        # avoiding a false "checkpoint extends past file" failure when a legal
        # append+fsync+checkpoint update races this polling iteration.
        file.seek(0, 2)
        file_len = file.tell()
        if checkpoint != self._checkpoint:
            _validate_durable_prefix(file, self.identity, checkpoint, file_len)
            self._checkpoint = checkpoint
        return file_len

    def poll(
        self,
        *,
        max_chunks: int = 8,
        max_encoded_record_bytes: int = MAX_ENCODED_RECORD_LEN,
    ) -> JournalPoll:
        if max_chunks <= 0 or max_encoded_record_bytes <= 0:
            raise ValueError("poll bounds must be positive")
        result: list[JournalChunk] = []
        total_bytes = 0
        with self.path.open("rb") as file:
            file_len = self._refresh_durable_boundary(file)
            boundary = self._checkpoint.durable_valid_len
            while len(result) < max_chunks and self._offset < boundary:
                file.seek(self._offset + 20)
                raw_length = file.read(4)
                if len(raw_length) != 4:
                    raise JournalFormatError("durable chunk length field is torn")
                next_size = unpack_from("<I", raw_length)[0]
                if not 0 < next_size <= MAX_ENCODED_RECORD_LEN:
                    raise JournalFormatError(
                        "journal encoded record length exceeds safety bounds"
                    )
                if next_size > max_encoded_record_bytes:
                    raise ValueError(
                        "max_encoded_record_bytes is smaller than the next durable record"
                    )
                # Decide the bounded-batch cutoff before decoding: decoding
                # advances the per-Pod continuity tracker and must never be
                # performed speculatively for a record left at the cursor.
                if result and total_bytes + next_size > max_encoded_record_bytes:
                    break
                chunk, incomplete = _decode_complete_chunk(
                    file,
                    identity=self.identity,
                    tracker=self._tracker,
                    boundary=boundary,
                    offset=self._offset,
                    expected_journal_sequence=self._next_journal_sequence,
                    allow_incomplete=False,
                )
                if incomplete or chunk is None:
                    raise JournalFormatError("validated durable boundary became incomplete")
                size = len(chunk.encoded_record)
                result.append(chunk)
                total_bytes += size
                self._offset = chunk.next_file_offset
                self._next_journal_sequence += 1
        return JournalPoll(
            chunks=tuple(result),
            unproven_tail=file_len > self._checkpoint.durable_valid_len,
            cursor_offset=self._offset,
            next_journal_sequence=self._next_journal_sequence,
            durable_checkpoint_generation=self._checkpoint.generation,
        )
