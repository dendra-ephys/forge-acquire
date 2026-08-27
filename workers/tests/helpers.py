from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from struct import pack
from typing import Sequence
from uuid import UUID

from forge_workers._protocol import protocol
from forge_workers.journal import FILE_HEADER_LEN, crc32c, pod_slot_for
from forge_workers.journal import JournalChunk, JournalChunkMetadata
from forge_workers.sdk import SampleBlock


POD_ID = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
HEADSTAGE_ID = bytes.fromhex("202122232425262728292a2b2c2d2e2f")


@dataclass(frozen=True)
class FixtureJournal:
    run_id: UUID
    pod_id: bytes
    encoded_records: tuple[bytes, ...]
    durable_count: int
    durable_valid_len: int


def make_sample_record(
    *,
    run_id: UUID,
    record_sequence: int,
    sample_start: int,
    pod_id: bytes = POD_ID,
    channel_layout_id: int = 7,
    channel_count: int = 2,
    samples_per_channel: int = 4,
    record_flags: int = 0,
) -> bytes:
    samples = tuple(
        record_sequence * 100 + sample * 10 + channel
        for sample in range(samples_per_channel)
        for channel in range(channel_count)
    )
    payload = protocol.SampleBlockV1(
        flags=0x03,
        samples_per_channel=samples_per_channel,
        channel_count=channel_count,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        first_sample_counter=sample_start,
        samples=samples,
    ).to_bytes()
    envelope = protocol.CanonicalRecordEnvelopeV1(
        record_kind=protocol.RecordKind.SAMPLE_BLOCK,
        flags=record_flags,
        run_id=run_id.bytes,
        pod_id=pod_id,
        headstage_id=HEADSTAGE_ID,
        record_sequence=record_sequence,
        frame_start=record_sequence,
        frame_end_exclusive=record_sequence + 1,
        sample_start=sample_start,
        sample_end_exclusive=sample_start + samples_per_channel,
        global_time_start_ns=record_sequence * 1_000_000,
        global_time_end_exclusive_ns=(record_sequence + 1) * 1_000_000,
        channel_layout_id=channel_layout_id,
        channel_count=channel_count,
    )
    return protocol.encode_record(envelope, payload)


def make_analysis_block(
    values: tuple[tuple[int, ...], ...],
    *,
    run_id: UUID,
    generation: int = 1,
    record_sequence: int = 0,
    journal_sequence: int | None = None,
    sample_start: int = 0,
    sample_rate_numerator_hz: int = 1_000,
    sample_rate_denominator: int = 1,
    channel_ids: tuple[int, ...] | None = None,
) -> SampleBlock:
    if not values or not values[0]:
        raise ValueError("values must contain samples and channels")
    channel_count = len(values[0])
    if any(len(row) != channel_count for row in values):
        raise ValueError("all sample rows must have the same channel count")
    if channel_ids is None:
        channel_ids = tuple(range(channel_count))
    payload = protocol.SampleBlockV1(
        flags=0x03,
        samples_per_channel=len(values),
        channel_count=channel_count,
        sample_rate_numerator_hz=sample_rate_numerator_hz,
        sample_rate_denominator=sample_rate_denominator,
        first_sample_counter=sample_start,
        samples=tuple(value for row in values for value in row),
    ).to_bytes()
    envelope = protocol.CanonicalRecordEnvelopeV1(
        record_kind=protocol.RecordKind.SAMPLE_BLOCK,
        flags=0,
        run_id=run_id.bytes,
        pod_id=POD_ID,
        headstage_id=HEADSTAGE_ID,
        record_sequence=record_sequence,
        frame_start=record_sequence,
        frame_end_exclusive=record_sequence + 1,
        sample_start=sample_start,
        sample_end_exclusive=sample_start + len(values),
        global_time_start_ns=record_sequence * 1_000_000,
        global_time_end_exclusive_ns=(record_sequence + 1) * 1_000_000,
        channel_layout_id=7,
        channel_count=channel_count,
    )
    encoded = protocol.encode_record(envelope, payload)
    canonical = protocol.decode_record(encoded)
    journal_sequence = record_sequence if journal_sequence is None else journal_sequence
    metadata = JournalChunkMetadata(
        journal_sequence=journal_sequence,
        pod_slot=pod_slot_for(POD_ID),
        record_sequence=record_sequence,
        frame_start=envelope.frame_start,
        frame_end_exclusive=envelope.frame_end_exclusive,
        sample_start=envelope.sample_start,
        sample_end_exclusive=envelope.sample_end_exclusive,
        global_time_start_ns=envelope.global_time_start_ns,
        global_time_end_exclusive_ns=envelope.global_time_end_exclusive_ns,
        encoded_record_crc32c=crc32c(encoded),
    )
    chunk = JournalChunk(metadata, canonical, encoded, 0, len(encoded))
    return SampleBlock.from_journal_chunk(
        chunk, generation=generation, channel_ids=channel_ids
    )


def _checkpoint_bytes(
    *,
    run_id: UUID,
    generation: int,
    durable_count: int,
    durable_valid_len: int,
) -> bytes:
    checkpoint = bytearray(128)
    checkpoint[0:8] = b"FRGCKP01"
    checkpoint[8:10] = pack("<H", 1)
    checkpoint[10:12] = pack("<H", 128)
    checkpoint[12:20] = pack("<Q", generation)
    checkpoint[20:36] = run_id.bytes
    checkpoint[36:68] = protocol.PROTOCOL_HASH
    checkpoint[68:76] = pack("<Q", durable_valid_len)
    checkpoint[76:84] = pack(
        "<Q", 0xFFFF_FFFF_FFFF_FFFF if durable_count == 0 else durable_count - 1
    )
    checkpoint[84:92] = pack("<Q", durable_count)
    checkpoint[124:128] = pack("<I", crc32c(checkpoint[:124]))
    return bytes(checkpoint)


def write_fixture_journal(
    path: Path,
    *,
    run_id: UUID,
    record_count: int = 2,
    durable_count: int | None = None,
    torn_tail: bytes = b"",
) -> FixtureJournal:
    if record_count < 0:
        raise ValueError("record_count must be non-negative")
    if durable_count is None:
        durable_count = record_count
    if not 0 <= durable_count <= record_count:
        raise ValueError("durable_count must be within the structural record count")

    encoded_records: list[bytes] = []
    sample_start = 0
    for journal_sequence in range(record_count):
        encoded = make_sample_record(
            run_id=run_id,
            record_sequence=journal_sequence,
            sample_start=sample_start,
        )
        sample_start += 4
        encoded_records.append(encoded)
    return write_encoded_records_journal(
        path,
        run_id=run_id,
        encoded_records=encoded_records,
        durable_count=durable_count,
        torn_tail=torn_tail,
    )


def write_encoded_records_journal(
    path: Path,
    *,
    run_id: UUID,
    encoded_records: Sequence[bytes],
    durable_count: int | None = None,
    torn_tail: bytes = b"",
) -> FixtureJournal:
    if durable_count is None:
        durable_count = len(encoded_records)
    if not 0 <= durable_count <= len(encoded_records):
        raise ValueError("durable_count must be within the structural record count")

    header = bytearray(FILE_HEADER_LEN)
    header[0:8] = b"FORGEWAL"
    header[8:10] = pack("<H", 1)
    header[10:12] = pack("<H", FILE_HEADER_LEN)
    header[12:28] = run_id.bytes
    header[28:60] = protocol.PROTOCOL_HASH
    header[60:64] = pack("<I", crc32c(header[:60]))

    records = bytearray(header)
    record_ends = [FILE_HEADER_LEN]
    normalized_records = tuple(bytes(encoded) for encoded in encoded_records)
    for journal_sequence, encoded in enumerate(normalized_records):
        decoded = protocol.decode_record(encoded)
        if decoded.envelope.run_id != run_id.bytes:
            raise ValueError("encoded record Run ID differs from journal Run ID")
        envelope = decoded.envelope
        encoded_crc = crc32c(encoded)
        chunk = bytearray(80)
        chunk[0:8] = b"FRGCHNK1"
        chunk[8:16] = pack("<Q", journal_sequence)
        chunk[16:18] = pack("<H", pod_slot_for(envelope.pod_id))
        chunk[20:24] = pack("<I", len(encoded))
        chunk[24:32] = pack("<Q", envelope.frame_start)
        chunk[32:40] = pack("<Q", envelope.frame_end_exclusive)
        chunk[40:48] = pack("<Q", envelope.sample_start)
        chunk[48:56] = pack("<Q", envelope.sample_end_exclusive)
        chunk[56:64] = pack("<Q", envelope.global_time_start_ns)
        chunk[64:72] = pack("<Q", envelope.global_time_end_exclusive_ns)
        chunk[72:76] = pack("<I", encoded_crc)
        chunk[76:80] = pack("<I", crc32c(chunk[:76]))
        footer = bytearray(24)
        footer[0:8] = b"FRGCMIT1"
        footer[8:16] = pack("<Q", journal_sequence)
        footer[16:20] = pack("<I", encoded_crc)
        footer[20:24] = pack("<I", crc32c(footer[:20]))
        records.extend(chunk)
        records.extend(encoded)
        records.extend(footer)
        record_ends.append(len(records))
    records.extend(torn_tail)
    path.write_bytes(records)

    durable_valid_len = record_ends[durable_count]
    Path(f"{path}.checkpoint-a").write_bytes(
        _checkpoint_bytes(
            run_id=run_id,
            generation=2,
            durable_count=durable_count,
            durable_valid_len=durable_valid_len,
        )
    )
    Path(f"{path}.checkpoint-b").write_bytes(
        _checkpoint_bytes(
            run_id=run_id,
            generation=1,
            durable_count=0,
            durable_valid_len=FILE_HEADER_LEN,
        )
    )
    return FixtureJournal(
        run_id,
        POD_ID,
        normalized_records,
        durable_count,
        durable_valid_len,
    )


def advance_fixture_durable_watermark(
    path: Path,
    fixture: FixtureJournal,
    *,
    durable_count: int,
    checkpoint_generation: int,
) -> FixtureJournal:
    """Advance a fixture's A/B durable watermark without rewriting its WAL.

    This models a writer making previously appended bytes durable.  Callers must
    provide a strictly newer checkpoint generation, which exercises the same
    monotonicity rule as the production cursor.
    """

    if not fixture.durable_count <= durable_count <= len(fixture.encoded_records):
        raise ValueError("durable_count must advance within the fixture record count")
    if checkpoint_generation <= 2:
        raise ValueError("checkpoint_generation must exceed the fixture's generation 2")

    scan_offset = FILE_HEADER_LEN
    record_ends = [scan_offset]
    for encoded in fixture.encoded_records:
        scan_offset += 80 + len(encoded) + 24
        record_ends.append(scan_offset)
    durable_valid_len = record_ends[durable_count]
    Path(f"{path}.checkpoint-b").write_bytes(
        _checkpoint_bytes(
            run_id=fixture.run_id,
            generation=checkpoint_generation,
            durable_count=durable_count,
            durable_valid_len=durable_valid_len,
        )
    )
    return FixtureJournal(
        fixture.run_id,
        fixture.pod_id,
        fixture.encoded_records,
        durable_count,
        durable_valid_len,
    )
