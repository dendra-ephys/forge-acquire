from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from struct import pack
from uuid import UUID

from forge_workers.journal import (
    JournalCursor,
    JournalFormatError,
    crc32c,
    scan_journal,
)

from helpers import write_fixture_journal


class JournalReaderTests(unittest.TestCase):
    def test_crc32c_standard_vector(self) -> None:
        self.assertEqual(crc32c(b"123456789"), 0xE3069283)

    def test_scan_and_cursor_expose_canonical_durable_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "run.wal")
            run_id = UUID("12345678-1234-5678-9abc-def012345678")
            fixture = write_fixture_journal(path, run_id=run_id)
            scan = scan_journal(path)
            self.assertEqual(scan.identity.run_id, run_id)
            self.assertEqual(scan.complete_chunks, 2)
            self.assertEqual(scan.last_journal_sequence, 1)
            self.assertEqual(scan.durable.durable_journal_sequence, 1)
            self.assertFalse(scan.torn_tail)

            cursor = JournalCursor(path)
            first = cursor.poll(max_chunks=1)
            second = cursor.poll(max_chunks=1)
            self.assertEqual(first.chunks[0].encoded_record, fixture.encoded_records[0])
            self.assertEqual(first.chunks[0].metadata.journal_sequence, 0)
            self.assertEqual(first.chunks[0].metadata.record_sequence, 0)
            self.assertEqual(first.chunks[0].metadata.sample_end_exclusive, 4)
            self.assertEqual(second.chunks[0].metadata.journal_sequence, 1)
            self.assertEqual(second.chunks[0].metadata.record_sequence, 1)
            self.assertEqual(cursor.poll().chunks, ())

    def test_unproven_committed_tail_is_not_exposed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "run.wal")
            fixture = write_fixture_journal(
                path, run_id=UUID(int=2), record_count=2, durable_count=1
            )
            scan = scan_journal(path)
            self.assertEqual(scan.complete_chunks, 2)
            self.assertEqual(scan.durable.durable_record_count, 1)
            cursor = JournalCursor(path)
            polled = cursor.poll(max_chunks=8)
            self.assertEqual(len(polled.chunks), 1)
            self.assertEqual(polled.chunks[0].encoded_record, fixture.encoded_records[0])
            self.assertTrue(polled.unproven_tail)
            self.assertEqual(cursor.poll().chunks, ())

    def test_byte_bounded_poll_does_not_advance_continuity_past_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "run.wal")
            fixture = write_fixture_journal(path, run_id=UUID(int=22), record_count=2)
            cursor = JournalCursor(path)
            first = cursor.poll(
                max_chunks=8,
                max_encoded_record_bytes=len(fixture.encoded_records[0]),
            )
            self.assertEqual(len(first.chunks), 1)
            second = cursor.poll(
                max_chunks=8,
                max_encoded_record_bytes=len(fixture.encoded_records[1]),
            )
            self.assertEqual(len(second.chunks), 1)
            self.assertEqual(second.chunks[0].metadata.record_sequence, 1)

    def test_torn_tail_is_not_exposed_as_durable_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "run.wal")
            write_fixture_journal(
                path,
                run_id=UUID(int=3),
                record_count=1,
                durable_count=1,
                torn_tail=b"FRG",
            )
            scan = scan_journal(path)
            self.assertEqual(scan.complete_chunks, 1)
            self.assertTrue(scan.torn_tail)
            polled = JournalCursor(path).poll()
            self.assertEqual(len(polled.chunks), 1)
            self.assertTrue(polled.unproven_tail)

    def test_durable_encoded_record_corruption_is_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "run.wal")
            write_fixture_journal(path, run_id=UUID(int=4), record_count=1)
            data = bytearray(path.read_bytes())
            data[64 + 80 + 10] ^= 0xFF
            path.write_bytes(data)
            with self.assertRaisesRegex(JournalFormatError, "encoded record CRC32C"):
                JournalCursor(path)

    def test_range_cache_mismatch_is_rejected_after_valid_chunk_crc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "run.wal")
            write_fixture_journal(path, run_id=UUID(int=5), record_count=1)
            data = bytearray(path.read_bytes())
            header_offset = 64
            data[header_offset + 48 : header_offset + 56] = pack("<Q", 5)
            data[header_offset + 76 : header_offset + 80] = pack(
                "<I", crc32c(data[header_offset : header_offset + 76])
            )
            path.write_bytes(data)
            with self.assertRaisesRegex(JournalFormatError, "range cache"):
                JournalCursor(path)


if __name__ == "__main__":
    unittest.main()
