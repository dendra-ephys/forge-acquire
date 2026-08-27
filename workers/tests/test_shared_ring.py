from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest
import uuid

from forge_workers.shared_ring import (
    LiveRingError,
    RingSnapshotError,
    WindowsMappedRingConsumer,
    native_live_available,
    parse_ring_snapshot,
)


class SharedRingSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = os.environ.get("FORGE_ANALYSIS_RING_FIXTURE")
        if not fixture:
            raise RuntimeError("FORGE_ANALYSIS_RING_FIXTURE is required")
        cls.raw = Path(fixture).read_bytes()

    def test_cross_language_fixture_contains_two_canonical_records(self) -> None:
        snapshot = parse_ring_snapshot(self.raw)
        self.assertTrue(snapshot.snapshot_only)
        self.assertEqual(snapshot.published_sequence, 2)
        self.assertEqual(snapshot.consumed_sequence, 0)
        self.assertEqual([record.journal_sequence for record in snapshot.records], [41, 42])
        self.assertEqual([record.canonical.envelope.record_sequence for record in snapshot.records], [0, 1])

    def test_header_crc_mutation_is_rejected(self) -> None:
        corrupted = bytearray(self.raw)
        corrupted[80] ^= 1
        with self.assertRaisesRegex(RingSnapshotError, "header CRC"):
            parse_ring_snapshot(bytes(corrupted))

    def test_slot_crc_mutation_is_rejected(self) -> None:
        corrupted = bytearray(self.raw)
        corrupted[256 + 64 + 180] ^= 1
        with self.assertRaisesRegex(RingSnapshotError, "slot CRC"):
            parse_ring_snapshot(bytes(corrupted))

    def test_redundant_cache_mutation_is_rejected(self) -> None:
        corrupted = bytearray(self.raw)
        corrupted[256 + 24] ^= 1
        with self.assertRaisesRegex(RingSnapshotError, "cache mismatch"):
            parse_ring_snapshot(bytes(corrupted))

    @unittest.skipUnless(sys.platform == "win32", "Windows mapping contract")
    def test_native_consumer_opens_named_mapping_and_consumes_fixture(self) -> None:
        self.assertTrue(native_live_available())
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_mapping = kernel32.CreateFileMappingW
        create_mapping.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPCWSTR,
        ]
        create_mapping.restype = wintypes.HANDLE
        map_view = kernel32.MapViewOfFile
        map_view.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_size_t,
        ]
        map_view.restype = ctypes.c_void_p
        unmap_view = kernel32.UnmapViewOfFile
        unmap_view.argtypes = [ctypes.c_void_p]
        unmap_view.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        snapshot = parse_ring_snapshot(self.raw)
        name = f"Local\\ForgeAnalysisRing-Python-{os.getpid()}-{uuid.uuid4().hex}"
        invalid_handle = ctypes.c_void_p(-1).value
        handle = create_mapping(invalid_handle, None, 0x04, 0, len(self.raw), name)
        self.assertTrue(handle, ctypes.get_last_error())
        view = map_view(handle, 0x000F001F, 0, 0, len(self.raw))
        self.assertTrue(view, ctypes.get_last_error())
        try:
            ctypes.memmove(view, self.raw, len(self.raw))
            consumer = WindowsMappedRingConsumer(
                name,
                snapshot.run_id,
                snapshot.consumer_id,
                snapshot.producer_epoch,
            )
            try:
                first = consumer.try_consume(101)
                second = consumer.try_consume(102)
                self.assertIsNotNone(first)
                self.assertIsNotNone(second)
                self.assertEqual(first.ring_sequence, 0)
                self.assertEqual(first.journal_sequence, 41)
                self.assertEqual(second.ring_sequence, 1)
                self.assertEqual(second.journal_sequence, 42)
                self.assertIsNone(consumer.try_consume(103))
                self.assertEqual(consumer.dropped_records, 0)
                self.assertEqual(consumer.fault_flags, 0)
            finally:
                consumer.close()
            self.assertTrue(consumer.closed)
            with self.assertRaisesRegex(LiveRingError, "closed"):
                consumer.try_consume(104)
        finally:
            self.assertTrue(unmap_view(view))
            self.assertTrue(close_handle(handle))


if __name__ == "__main__":
    unittest.main()
