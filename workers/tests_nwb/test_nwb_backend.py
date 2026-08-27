from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from struct import pack
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID

import h5py
import numpy as np
import pynwb
from nwbinspector import Importance, inspect_nwbfile

from forge_workers._protocol import protocol
from forge_workers.forge_nwbd import (
    materialize_live_generation,
    materialize_sealed_generation,
)
from forge_workers.journal import JournalCursor, crc32c, pod_slot_for, scan_journal
from forge_workers.materializer import (
    CanonicalSampleBlockDecoder,
    JournalToNwbMaterializer,
    NwbSessionMetadata,
    NwbUnavailableError,
    PodNwbPlan,
    RunMaterializationManifest,
    preflight_materializer,
    save_manifest,
)
from forge_workers.nwb_backend import (
    BLOCK_INDEX_COLUMNS,
    LOCKED_HDF5_RUNTIME,
    LOCKED_NWB_VERSIONS,
    PyNwbSwmrBackend,
)
from forge_workers.nwb_validation import validate_closed_generation
from forge_workers.nwb_receipt import NwbGenerationValidationReceiptV1
from helpers import (
    HEADSTAGE_ID,
    POD_ID,
    advance_fixture_durable_watermark,
    make_sample_record,
    write_encoded_records_journal,
    write_fixture_journal,
)


POD_ID_TWO = bytes.fromhex("303132333435363738393a3b3c3d3e3f")


def _typed_record(
    *,
    run_id: UUID,
    kind: protocol.RecordKind,
    record_sequence: int,
    payload: bytes,
    frame_start: int = 0,
    frame_end_exclusive: int = 1,
    sample_start: int = 0,
    sample_end_exclusive: int = 1,
    global_time_start_ns: int,
    global_time_end_exclusive_ns: int,
) -> bytes:
    return protocol.encode_record(
        protocol.CanonicalRecordEnvelopeV1(
            record_kind=kind,
            flags=0,
            run_id=run_id.bytes,
            pod_id=POD_ID,
            headstage_id=HEADSTAGE_ID,
            record_sequence=record_sequence,
            frame_start=frame_start,
            frame_end_exclusive=frame_end_exclusive,
            sample_start=sample_start,
            sample_end_exclusive=sample_end_exclusive,
            global_time_start_ns=global_time_start_ns,
            global_time_end_exclusive_ns=global_time_end_exclusive_ns,
            channel_layout_id=7,
            channel_count=2,
        ),
        payload,
    )


def _typed_event_records(run_id: UUID) -> tuple[bytes, ...]:
    id16 = lambda value: bytes([value]) * 16
    hash32 = lambda value: bytes([value]) * 32
    sample = make_sample_record(run_id=run_id, record_sequence=0, sample_start=0)
    marker = _typed_record(
        run_id=run_id,
        kind=protocol.RecordKind.MARKER,
        record_sequence=1,
        payload=protocol.MarkerPayloadV1(
            id16(0x41), 1, protocol.MARKER_FLAG_OPERATOR, "基线", "operator note"
        ).to_bytes(),
        sample_start=3,
        sample_end_exclusive=4,
        global_time_start_ns=900_000,
        global_time_end_exclusive_ns=900_001,
    )
    fault = _typed_record(
        run_id=run_id,
        kind=protocol.RecordKind.FAULT,
        record_sequence=2,
        payload=protocol.FaultPayloadV1(
            id16(0x42),
            protocol.FaultCode.SOURCE_CRC,
            protocol.FaultSeverity.ERROR,
            protocol.FaultLayer.RECEIVER_CAPTURE,
            protocol.EVENT_FAULT_FLAG_RUN_LATCHED
            | protocol.EVENT_FAULT_FLAG_STIM_DISARMING,
            1,
            "CRC mismatch",
        ).to_bytes(),
        sample_start=3,
        sample_end_exclusive=4,
        global_time_start_ns=2_000_000,
        global_time_end_exclusive_ns=2_000_001,
    )
    gap = _typed_record(
        run_id=run_id,
        kind=protocol.RecordKind.FAULT,
        record_sequence=3,
        payload=protocol.GapPayloadV1(
            id16(0x43),
            protocol.GapReason.COUNTER_DISCONTINUITY,
            protocol.FaultLayer.RECEIVER_CAPTURE,
            protocol.EVENT_FAULT_FLAG_RUN_LATCHED
            | protocol.EVENT_FAULT_FLAG_STIM_DISARMING,
            1,
            2,
            4,
        ).to_bytes(),
        frame_start=10,
        frame_end_exclusive=12,
        sample_start=100,
        sample_end_exclusive=104,
        global_time_start_ns=3_000_000,
        global_time_end_exclusive_ns=3_000_001,
    )
    analysis = _typed_record(
        run_id=run_id,
        kind=protocol.RecordKind.ONLINE_ANALYSIS,
        record_sequence=4,
        payload=protocol.OnlineAnalysisPayloadV1(
            id16(0x44),
            id16(0x45),
            hash32(0x51),
            hash32(0x52),
            hash32(0x53),
            hash32(0x54),
            0,
            1,
            protocol.ANALYSIS_FLAG_REFERENCE_ONLY,
            b'{"score":1}',
        ).to_bytes(),
        sample_start=3,
        sample_end_exclusive=4,
        global_time_start_ns=4_000_000,
        global_time_end_exclusive_ns=4_000_001,
    )
    intent_body = protocol.StimIntentV1(
        run_id.bytes,
        id16(0x46),
        id16(0x47),
        0,
        2,
        500_000,
        hash32(0x61),
        hash32(0x62),
        hash32(0x63),
        hash32(0x64),
        4,
        1,
        0,
        10_000_000,
        id16(0x48),
    )
    intent = _typed_record(
        run_id=run_id,
        kind=protocol.RecordKind.STIM_INTENT,
        record_sequence=5,
        payload=intent_body.to_bytes(),
        sample_start=2,
        sample_end_exclusive=3,
        global_time_start_ns=500_000,
        global_time_end_exclusive_ns=500_001,
    )
    receipt = _typed_record(
        run_id=run_id,
        kind=protocol.RecordKind.STIM_RECEIPT,
        record_sequence=6,
        payload=protocol.StimReceiptV1(
            run_id.bytes,
            id16(0x49),
            intent_body.intent_nonce,
            id16(0x4A),
            1,
            0,
            4,
            1,
            6_000_010,
            6_000_020,
            2_000_000,
            25_000,
            0,
            125,
            7,
            id16(0x4B),
            hash32(0x65),
        ).to_bytes(),
        sample_start=3,
        sample_end_exclusive=4,
        global_time_start_ns=6_000_000,
        global_time_end_exclusive_ns=7_000_000,
    )
    return sample, marker, fault, gap, analysis, intent, receipt


def _write_seal(journal: Path) -> None:
    scan = scan_journal(journal)
    seal = bytearray(128)
    seal[0:8] = b"FRGSEAL1"
    seal[8:10] = pack("<H", 1)
    seal[10:12] = pack("<H", 128)
    seal[12:28] = scan.identity.run_id.bytes
    seal[28:60] = protocol.PROTOCOL_HASH
    seal[60:68] = pack(
        "<Q",
        0xFFFF_FFFF_FFFF_FFFF
        if scan.last_journal_sequence is None
        else scan.last_journal_sequence,
    )
    seal[68:76] = pack("<Q", scan.valid_len)
    seal[76:84] = pack("<Q", scan.durable.generation)
    seal[84:92] = pack("<Q", scan.complete_chunks)
    seal[124:128] = pack("<I", crc32c(seal[:124]))
    Path(f"{journal}.seal").write_bytes(seal)


def _manifest(directory: Path, *, generation: int = 1) -> RunMaterializationManifest:
    run_id = UUID("01234567-89ab-cdef-0123-456789abcdef")
    journal = directory / "run.wal"
    if not journal.exists():
        write_fixture_journal(journal, run_id=run_id, record_count=2)
        _write_seal(journal)
    final = directory / "run.nwb"
    return RunMaterializationManifest(
        run_id=run_id,
        generation=generation,
        protocol_contract_hash=protocol.PROTOCOL_HASH_HEX,
        journal_path=journal,
        inprogress_path=directory / f"run.g{generation:04d}.nwb.inprogress",
        final_path=final,
        pods=(
            PodNwbPlan(
                canonical_pod_id=POD_ID,
                pod_slot=pod_slot_for(POD_ID),
                channel_layout_id=7,
                channel_count=2,
                sample_rate_numerator_hz=30_000,
                sample_rate_denominator=1,
                conversion_volts_per_count=0.195e-6,
                channel_ids=(0, 1),
                channel_labels=("A-000", "A-001"),
            ),
        ),
        session_metadata=NwbSessionMetadata(
            session_description="Synthetic Forge NWB backend qualification fixture",
            session_start_time_utc="2024-01-01T00:00:00+00:00",
            experimenter=("Forge automated qualification",),
            lab="Forge development",
            institution="Forge local qualification fixture",
            subject_id="synthetic-subject-001",
            subject_species="Mus musculus",
            subject_sex="U",
            subject_age="P90D",
            experiment_description="Synthetic signed-int16 continuity fixture; not animal data.",
            session_id="forge-synthetic-nwb-v1",
            protocol="software-only synthetic materializer verification",
        ),
        dependency_lock=LOCKED_NWB_VERSIONS,
        materializer_build_sha256=(
            "fb3e010aaec30cbf4bb007037e5fb05efeb74331f05bf3d31f97c7d0f1d337c1"
        ),
    )


def _two_pod_interleaved_manifest(directory: Path) -> RunMaterializationManifest:
    """A compact two-Pod fixture with distinct channel geometry.

    The second block for Pod 1 intentionally has a discontinuous sample start
    together with the canonical gap/discontinuity record flag.  Validation must
    retain this explicit condition rather than silently requiring fake
    continuity.
    """

    run_id = UUID("01234567-89ab-cdef-0123-456789abcdef")
    journal = directory / "run.wal"
    write_encoded_records_journal(
        journal,
        run_id=run_id,
        encoded_records=(
            make_sample_record(
                run_id=run_id,
                record_sequence=0,
                sample_start=0,
                samples_per_channel=2,
            ),
            make_sample_record(
                run_id=run_id,
                record_sequence=0,
                sample_start=0,
                pod_id=POD_ID_TWO,
                channel_layout_id=8,
                channel_count=3,
                samples_per_channel=3,
            ),
            make_sample_record(
                run_id=run_id,
                record_sequence=1,
                sample_start=6,
                samples_per_channel=2,
                record_flags=1,
            ),
            make_sample_record(
                run_id=run_id,
                record_sequence=1,
                sample_start=3,
                pod_id=POD_ID_TWO,
                channel_layout_id=8,
                channel_count=3,
                samples_per_channel=1,
            ),
        ),
    )
    _write_seal(journal)
    base = _manifest(directory)
    second = PodNwbPlan(
        canonical_pod_id=POD_ID_TWO,
        pod_slot=pod_slot_for(POD_ID_TWO),
        channel_layout_id=8,
        channel_count=3,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        conversion_volts_per_count=0.195e-6,
        channel_ids=(0, 1, 2),
        channel_labels=("B-000", "B-001", "B-002"),
    )
    return replace(base, pods=(base.pods[0], second))


def _wait_for_swmr_samples(
    path: Path,
    series_name: str,
    *,
    expected_samples: int,
    timeout_seconds: float = 15.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if path.exists():
            try:
                with h5py.File(path, "r", swmr=True) as reader:
                    dataset = reader[f"acquisition/{series_name}/data"]
                    dataset.refresh()
                    if dataset.shape[0] >= expected_samples:
                        return
            except OSError as error:
                # The writer may be between create and SWMR enablement.
                last_error = error
        time.sleep(0.025)
    detail = "" if last_error is None else f"; last reader error: {last_error}"
    raise AssertionError(
        f"SWMR reader did not observe {expected_samples} samples within "
        f"{timeout_seconds}s{detail}"
    )


class PyNwbSwmrBackendTests(unittest.TestCase):
    def test_journal_cursor_reobserves_eof_after_checkpoint_advances(self) -> None:
        """A legal append+fsync+checkpoint race must not use stale EOF."""

        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            journal = directory / "run.wal"
            fixture = write_fixture_journal(
                journal,
                run_id=UUID("01234567-89ab-cdef-0123-456789abcdef"),
                record_count=2,
                durable_count=1,
            )
            complete_bytes = journal.read_bytes()
            appended_tail = complete_bytes[fixture.durable_valid_len :]
            journal.write_bytes(complete_bytes[: fixture.durable_valid_len])
            cursor = JournalCursor(journal)

            from forge_workers import journal as journal_module

            original_load_checkpoint = journal_module._load_checkpoint
            injected = False

            def advance_between_eof_and_checkpoint(*args: object) -> object:
                nonlocal injected, fixture
                if not injected:
                    injected = True
                    with journal.open("ab") as stream:
                        stream.write(appended_tail)
                        stream.flush()
                        os.fsync(stream.fileno())
                    fixture = advance_fixture_durable_watermark(
                        journal,
                        fixture,
                        durable_count=2,
                        checkpoint_generation=3,
                    )
                return original_load_checkpoint(*args)

            with patch.object(
                journal_module,
                "_load_checkpoint",
                side_effect=advance_between_eof_and_checkpoint,
            ):
                poll = cursor.poll(max_chunks=8)
            self.assertTrue(injected)
            self.assertEqual(len(poll.chunks), 2)
            self.assertEqual(poll.durable_checkpoint_generation, 3)
            self.assertEqual(cursor.next_journal_sequence, 2)
            self.assertEqual(fixture.durable_count, 2)

    def test_live_nwbd_rejects_poll_intervals_outside_swmr_flush_bound(self) -> None:
        for interval in (0, -1, 2_001):
            with self.subTest(interval=interval):
                with self.assertRaises(ValueError):
                    materialize_live_generation(
                        "nonexistent-manifest.json", poll_interval_ms=interval
                    )

    def test_typed_events_are_appended_and_reconciled_from_the_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            run_id = UUID("01234567-89ab-cdef-0123-456789abcdef")
            journal = directory / "run.wal"
            write_encoded_records_journal(
                journal,
                run_id=run_id,
                encoded_records=_typed_event_records(run_id),
            )
            _write_seal(journal)
            manifest = _manifest(directory)
            materializer = JournalToNwbMaterializer(
                manifest,
                directory / "run.g0001.checkpoint.json",
                CanonicalSampleBlockDecoder(),
                PyNwbSwmrBackend(target_chunk_bytes=256 * 1024),
            )
            self.assertEqual(materializer.step(max_chunks=16), 7)
            self.assertEqual(
                materializer.checkpoint.samples_per_canonical_pod[POD_ID.hex()], 4
            )

            table_names = (
                "forge_markers",
                "forge_faults",
                "forge_gaps",
                "forge_analysis_results",
                "forge_stimulation_intents",
                "forge_stimulation_receipts",
            )
            with h5py.File(manifest.inprogress_path, "r", swmr=True) as reader:
                for table_name in table_names:
                    identifiers = reader[f"intervals/{table_name}/id"]
                    identifiers.refresh()
                    self.assertEqual(identifiers.shape, (1,), table_name)
                self.assertEqual(
                    bytes(reader["intervals/forge_markers/label"][0]).decode("utf-8"),
                    "基线",
                )
                self.assertEqual(
                    bytes(
                        reader["intervals/forge_analysis_results/result_text"][0]
                    ).decode("utf-8"),
                    '{"score":1}',
                )
                self.assertEqual(
                    reader[
                        "processing/forge_provenance/forge_block_index/id"
                    ].shape,
                    (1,),
                )

            receipt = materializer.finish_generation()
            self.assertEqual(receipt.expected_last_journal_sequence, 6)
            self.assertEqual(receipt.samples_per_canonical_pod[POD_ID.hex()], 4)
            observation = validate_closed_generation(manifest, receipt)
            self.assertTrue(observation.passed, observation.to_json_dict())
            self.assertEqual(observation.checked_journal_records, 7)
            self.assertEqual(observation.checked_sample_blocks, 1)
            self.assertEqual(observation.samples_per_canonical_pod[POD_ID.hex()], 4)

            receipt_manifest = _manifest(directory, generation=2)
            receipt_manifest_path = directory / "run.g0002.materialization.json"
            save_manifest(receipt_manifest_path, receipt_manifest)
            committed = materialize_sealed_generation(receipt_manifest_path)
            binary = NwbGenerationValidationReceiptV1.from_bytes(
                Path(committed["validation_receipt_path"]).read_bytes()
            )
            self.assertEqual(binary.checked_blocks, 7)
            self.assertEqual(committed["checked_journal_records"], 7)
            self.assertEqual(committed["checked_sample_blocks"], 1)


    def test_independent_nwbd_writes_one_unpublished_validation_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            manifest = _manifest(directory)
            manifest_path = directory / "run.materialization.json"
            save_manifest(manifest_path, manifest)

            command = (
                sys.executable,
                "-m",
                "forge_workers.forge_nwbd",
                "--manifest",
                str(manifest_path),
            )
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["status"], "validated_generation_unpublished")
            self.assertFalse(result["publication_authorized"])

            report_path = Path(result["validation_report_path"])
            receipt_path = Path(result["validation_receipt_path"])
            report_bytes = report_path.read_bytes()
            report = json.loads(report_bytes)
            receipt = NwbGenerationValidationReceiptV1.from_bytes(
                receipt_path.read_bytes()
            )
            self.assertEqual(
                receipt.validation_report_sha256,
                hashlib.sha256(report_bytes).digest(),
            )
            self.assertEqual(receipt.nwb_sha256.hex(), result["nwb_sha256"])
            self.assertEqual(receipt.generation, manifest.generation)
            self.assertEqual(receipt.run_id, manifest.run_id.bytes)
            self.assertTrue(report["raw_sample_byte_equality_checked"])
            observation = report["observation"]
            self.assertTrue(observation["raw_sample_byte_equality_checked"])
            self.assertEqual(observation["raw_sample_bytes_checked"], 32)
            self.assertEqual(
                observation["raw_sample_blocks_per_canonical_pod"], {POD_ID.hex(): 2}
            )
            self.assertFalse(report["publication_authorized"])
            self.assertTrue(manifest.inprogress_path.exists())
            self.assertFalse(manifest.final_path.exists())

            host_app = Path(__file__).resolve().parents[2]
            owner_check = subprocess.run(
                (
                    "cargo",
                    "run",
                    "--quiet",
                    "--locked",
                    "--manifest-path",
                    str(host_app / "recording-daemon" / "Cargo.toml"),
                    "--",
                    "verify-nwb-generation",
                    "--receipt",
                    str(receipt_path),
                    "--journal",
                    str(manifest.journal_path),
                    "--nwb-inprogress",
                    str(manifest.inprogress_path),
                    "--manifest",
                    str(manifest_path),
                    "--report",
                    str(report_path),
                ),
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=host_app,
            )
            self.assertEqual(owner_check.returncode, 0, owner_check.stderr)
            owner_result = json.loads(owner_check.stdout)
            self.assertEqual(owner_result["status"], "verified_unpublished")
            self.assertFalse(owner_result["publication_authorized"])
            self.assertEqual(owner_result["generation"], manifest.generation)
            self.assertFalse(manifest.final_path.exists())

            publication_receipt_path = directory / "run.publication.bin"
            publication_command = (
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "--manifest-path",
                str(host_app / "recording-daemon" / "Cargo.toml"),
                "--features",
                "qualification-harness",
                "--",
                "publish-nwb-generation",
                "--receipt",
                str(receipt_path),
                "--journal",
                str(manifest.journal_path),
                "--nwb-inprogress",
                str(manifest.inprogress_path),
                "--manifest",
                str(manifest_path),
                "--report",
                str(report_path),
                "--publication-receipt",
                str(publication_receipt_path),
            )
            publication = subprocess.run(
                publication_command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=host_app,
            )
            self.assertEqual(publication.returncode, 0, publication.stderr)
            publication_result = json.loads(publication.stdout)
            self.assertEqual(publication_result["status"], "published_unledgered")
            self.assertFalse(publication_result["run_finalized"])
            self.assertTrue(publication_result["inprogress_retained"])
            self.assertTrue(manifest.final_path.exists())
            self.assertTrue(manifest.inprogress_path.exists())
            publication_bytes = publication_receipt_path.read_bytes()
            self.assertEqual(len(publication_bytes), 352)
            self.assertEqual(publication_bytes[:8], b"FGRPUB01")
            self.assertEqual(
                int.from_bytes(publication_bytes[348:352], "little"),
                crc32c(publication_bytes[:348]),
            )

            repeated_publication = subprocess.run(
                publication_command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=host_app,
            )
            self.assertEqual(
                repeated_publication.returncode, 0, repeated_publication.stderr
            )
            self.assertTrue(
                json.loads(repeated_publication.stdout)["inprogress_retained"]
            )
            self.assertTrue(manifest.inprogress_path.exists())
            self.assertEqual(publication_receipt_path.read_bytes(), publication_bytes)

            repeated = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(repeated.returncode, 1)
            failure = json.loads(repeated.stderr)
            self.assertEqual(failure["status"], "failed_closed")
            self.assertEqual(failure["error_type"], "FileExistsError")
            self.assertFalse(failure["publication_authorized"])
            self.assertTrue(manifest.final_path.exists())

            with manifest.final_path.open("ab") as stream:
                stream.write(b"tamper")
            rejected = subprocess.run(
                publication_command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=host_app,
            )
            self.assertEqual(rejected.returncode, 1)
            # Cargo may emit compile-time warnings before the owner's single
            # JSON error line; the executable contract is the final nonempty
            # stderr line, not Cargo's build diagnostics.
            owner_failure = json.loads(
                next(
                    line
                    for line in reversed(rejected.stderr.splitlines())
                    if line.strip()
                )
            )
            self.assertEqual(owner_failure["status"], "error")
            self.assertIn("publication failed", owner_failure["message"])
            self.assertTrue(manifest.final_path.exists())

    def test_typed_event_row_count_mismatches_reject_closed_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            run_id = UUID("01234567-89ab-cdef-0123-456789abcdef")
            journal = directory / "run.wal"
            write_encoded_records_journal(
                journal,
                run_id=run_id,
                encoded_records=_typed_event_records(run_id),
            )
            _write_seal(journal)
            manifest = _manifest(directory)
            materializer = JournalToNwbMaterializer(
                manifest,
                directory / "run.g0001.checkpoint.json",
                CanonicalSampleBlockDecoder(),
                PyNwbSwmrBackend(target_chunk_bytes=256 * 1024),
            )
            self.assertEqual(materializer.step(max_chunks=16), 7)
            receipt = materializer.finish_generation()
            with h5py.File(manifest.inprogress_path, "r+") as file:
                file["intervals/forge_markers/id"].resize((0,))
                file["intervals/forge_faults/id"].resize((2,))
                file.flush()
            # This assertion targets journal/event reconciliation; bypass the
            # third-party schema readers, which may keep malformed HDF5 files
            # open on Windows after reporting their own errors.
            with (
                patch("pynwb.validate", return_value=[]),
                patch("nwbinspector.inspect_nwbfile", return_value=[]),
            ):
                observation = validate_closed_generation(manifest, receipt)
            self.assertFalse(observation.passed)
            self.assertFalse(observation.raw_sample_byte_equality_checked)
            self.assertTrue(
                any(
                    "event table forge_markers id count differs from journal" in error
                    for error in observation.reconciliation_errors
                )
            )
            self.assertTrue(
                any(
                    "event table forge_faults id count differs from journal" in error
                    for error in observation.reconciliation_errors
                )
            )

    def test_empty_run_inspector_critical_never_claims_raw_equality(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            journal = directory / "run.wal"
            write_fixture_journal(
                journal,
                run_id=UUID("01234567-89ab-cdef-0123-456789abcdef"),
                record_count=0,
            )
            _write_seal(journal)
            manifest = _manifest(directory)
            materializer = JournalToNwbMaterializer(
                manifest,
                directory / "run.g0001.checkpoint.json",
                CanonicalSampleBlockDecoder(),
                PyNwbSwmrBackend(target_chunk_bytes=256 * 1024),
            )
            self.assertEqual(materializer.step(max_chunks=16), 0)
            receipt = materializer.finish_generation()
            critical = SimpleNamespace(
                importance=Importance.CRITICAL,
                check_function_name="synthetic_inspector_critical",
                location="acquisition",
                message="fixture critical",
            )
            with patch("nwbinspector.inspect_nwbfile", return_value=[critical]):
                observation = validate_closed_generation(manifest, receipt)
            self.assertFalse(observation.passed)
            self.assertFalse(observation.raw_sample_byte_equality_checked)
            self.assertEqual(observation.raw_sample_bytes_checked, 0)
            self.assertEqual(observation.checked_journal_records, 0)
            self.assertEqual(observation.checked_sample_blocks, 0)

    def test_uncompressed_swmr_materialization_close_and_cross_reader_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            manifest = _manifest(directory)
            backend = PyNwbSwmrBackend(target_chunk_bytes=256 * 1024)
            self.assertEqual(h5py.version.hdf5_version, LOCKED_HDF5_RUNTIME)
            report = preflight_materializer(manifest, backend=backend)
            self.assertTrue(report.available, report.reasons)

            materializer = JournalToNwbMaterializer(
                manifest,
                directory / "run.g0001.checkpoint.json",
                CanonicalSampleBlockDecoder(),
                backend,
            )
            self.assertEqual(materializer.step(max_chunks=1), 1)
            with h5py.File(manifest.inprogress_path, "r", swmr=True) as reader:
                dataset = reader[
                    f"acquisition/{manifest.pods[0].electrical_series_name}/data"
                ]
                dataset.refresh()
                self.assertEqual(dataset.shape, (4, 2))
                self.assertIsNone(dataset.compression)
            self.assertEqual(materializer.step(max_chunks=8), 1)
            self.assertEqual(materializer.step(max_chunks=8), 0)
            receipt = materializer.finish_generation()
            self.assertEqual(receipt.expected_last_journal_sequence, 1)
            self.assertEqual(receipt.materialized_last_journal_sequence, 1)
            self.assertEqual(receipt.samples_per_canonical_pod[POD_ID.hex()], 8)
            self.assertTrue(receipt.uncompressed)
            self.assertTrue(receipt.validation_pending)
            self.assertFalse(receipt.publication_authorized)

            with pynwb.NWBHDF5IO(manifest.inprogress_path, "r") as io:
                nwbfile = io.read()
                samples = np.asarray(
                    nwbfile.acquisition[manifest.pods[0].electrical_series_name].data[:]
                )
                np.testing.assert_array_equal(
                    samples,
                    np.asarray(
                        [
                            [0, 1],
                            [10, 11],
                            [20, 21],
                            [30, 31],
                            [100, 101],
                            [110, 111],
                            [120, 121],
                            [130, 131],
                        ],
                        dtype=np.int16,
                    ),
                )
                block_index = nwbfile.processing["forge_provenance"]["forge_block_index"]
                self.assertEqual(len(block_index), 2)
                self.assertEqual(set(block_index.colnames), set(BLOCK_INDEX_COLUMNS))
                self.assertEqual(
                    tuple(block_index["journal_sequence"].data[:]), (0, 1)
                )

            self.assertEqual(pynwb.validate(path=manifest.inprogress_path), [])
            severe = list(
                inspect_nwbfile(
                    manifest.inprogress_path,
                    skip_validate=False,
                    importance_threshold=Importance.CRITICAL,
                )
            )
            self.assertEqual(severe, [])
            observation = validate_closed_generation(manifest, receipt)
            self.assertTrue(observation.passed, observation.to_json_dict())
            self.assertEqual(observation.checked_journal_records, 2)
            self.assertEqual(observation.checked_sample_blocks, 2)
            self.assertEqual(observation.samples_per_canonical_pod[POD_ID.hex()], 8)
            self.assertTrue(observation.raw_sample_byte_equality_checked)
            self.assertEqual(observation.raw_sample_bytes_checked, 32)
            self.assertEqual(
                observation.raw_sample_blocks_per_canonical_pod, {POD_ID.hex(): 2}
            )
            self.assertEqual(
                observation.raw_sample_sha256_per_canonical_pod[POD_ID.hex()],
                hashlib.sha256(
                    np.asarray(
                        [
                            [0, 1],
                            [10, 11],
                            [20, 21],
                            [30, 31],
                            [100, 101],
                            [110, 111],
                            [120, 121],
                            [130, 131],
                        ],
                        dtype=np.dtype("<i2"),
                    ).tobytes(order="C")
                ).hexdigest(),
            )
            self.assertFalse(observation.publication_authorized)
            self.assertFalse(manifest.final_path.exists())

    def test_interleaved_two_pod_raw_equality_uses_each_pod_geometry(self) -> None:
        """Each ElectricalSeries is reconciled independently, including a flagged gap."""

        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            manifest = _two_pod_interleaved_manifest(directory)
            materializer = JournalToNwbMaterializer(
                manifest,
                directory / "run.g0001.checkpoint.json",
                CanonicalSampleBlockDecoder(),
                PyNwbSwmrBackend(target_chunk_bytes=256 * 1024),
            )
            self.assertEqual(materializer.step(max_chunks=16), 4)
            receipt = materializer.finish_generation()

            first, second = manifest.pods
            expected_first = np.asarray(
                [[0, 1], [10, 11], [100, 101], [110, 111]], dtype=np.int16
            )
            expected_second = np.asarray(
                [
                    [0, 1, 2],
                    [10, 11, 12],
                    [20, 21, 22],
                    [100, 101, 102],
                ],
                dtype=np.int16,
            )
            with h5py.File(manifest.inprogress_path, "r", swmr=True) as reader:
                np.testing.assert_array_equal(
                    reader[f"acquisition/{first.electrical_series_name}/data"][:],
                    expected_first,
                )
                np.testing.assert_array_equal(
                    reader[f"acquisition/{second.electrical_series_name}/data"][:],
                    expected_second,
                )

            observation = validate_closed_generation(manifest, receipt)
            self.assertTrue(observation.passed, observation.to_json_dict())
            self.assertTrue(observation.raw_sample_byte_equality_checked)
            self.assertEqual(observation.checked_sample_blocks, 4)
            self.assertEqual(
                observation.samples_per_canonical_pod,
                {POD_ID.hex(): 4, POD_ID_TWO.hex(): 4},
            )
            self.assertEqual(
                observation.raw_sample_blocks_per_canonical_pod,
                {POD_ID.hex(): 2, POD_ID_TWO.hex(): 2},
            )
            self.assertEqual(observation.raw_sample_bytes_checked, 40)
            self.assertEqual(
                observation.raw_sample_sha256_per_canonical_pod,
                {
                    POD_ID.hex(): hashlib.sha256(
                        np.asarray(expected_first, dtype=np.dtype("<i2")).tobytes(order="C")
                    ).hexdigest(),
                    POD_ID_TWO.hex(): hashlib.sha256(
                        np.asarray(expected_second, dtype=np.dtype("<i2")).tobytes(order="C")
                    ).hexdigest(),
                },
            )

            # This is a real HDF5 mutation of only Pod 2.  The direct validator
            # must withdraw raw equality, and this test path has not created a
            # binary validation receipt that could be mistaken for publication.
            with h5py.File(manifest.inprogress_path, "r+") as writer:
                dataset = writer[f"acquisition/{second.electrical_series_name}/data"]
                dataset[2, 1] = int(dataset[2, 1]) ^ 1
                writer.flush()
            tampered = validate_closed_generation(manifest, receipt)
            self.assertFalse(tampered.passed)
            self.assertFalse(tampered.raw_sample_byte_equality_checked)
            self.assertFalse((directory / "run.g0001.validation.bin").exists())
            self.assertFalse(manifest.final_path.exists())

    def test_closed_generation_tamper_is_detected_without_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            manifest = _manifest(directory)
            materializer = JournalToNwbMaterializer(
                manifest,
                directory / "run.g0001.checkpoint.json",
                CanonicalSampleBlockDecoder(),
                PyNwbSwmrBackend(target_chunk_bytes=256 * 1024),
            )
            self.assertEqual(materializer.step(max_chunks=8), 2)
            receipt = materializer.finish_generation()
            with h5py.File(manifest.inprogress_path, "r+") as file:
                dataset = file[
                    "processing/forge_provenance/forge_block_index/record_flags"
                ]
                dataset[0] = int(dataset[0]) ^ 1
                file.flush()

            observation = validate_closed_generation(manifest, receipt)
            self.assertFalse(observation.passed)
            self.assertFalse(observation.publication_authorized)
            self.assertIn(
                ".nwb.inprogress hash differs from close receipt",
                observation.reconciliation_errors,
            )
            self.assertTrue(
                any(
                    "block-index provenance mismatch" in error
                    for error in observation.reconciliation_errors
                )
            )
            self.assertFalse(manifest.final_path.exists())

    def test_raw_sample_byte_equality_rejects_value_layout_dtype_and_shape_tamper(self) -> None:
        """Every case mutates actual HDF5 sample storage, never a mocked flag."""

        for mutation in (
            "bit",
            "channel-order",
            "truncated",
            "extra",
            "big-endian",
            "pod-index",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory_name:
                directory = Path(directory_name)
                manifest = _manifest(directory)
                materializer = JournalToNwbMaterializer(
                    manifest,
                    directory / "run.g0001.checkpoint.json",
                    CanonicalSampleBlockDecoder(),
                    PyNwbSwmrBackend(target_chunk_bytes=256 * 1024),
                )
                self.assertEqual(materializer.step(max_chunks=8), 2)
                receipt = materializer.finish_generation()
                dataset_path = f"acquisition/{manifest.pods[0].electrical_series_name}/data"
                with h5py.File(manifest.inprogress_path, "r+") as file:
                    dataset = file[dataset_path]
                    if mutation == "bit":
                        dataset[1, 0] = int(dataset[1, 0]) ^ 1
                    elif mutation == "channel-order":
                        dataset[...] = np.asarray(dataset[:])[:, ::-1]
                    elif mutation == "truncated":
                        dataset.resize((dataset.shape[0] - 1, dataset.shape[1]))
                    elif mutation == "extra":
                        original = dataset.shape[0]
                        dataset.resize((original + 1, dataset.shape[1]))
                        dataset[original, :] = 0
                    elif mutation == "pod-index":
                        index = file[
                            "processing/forge_provenance/forge_block_index/pod_id_low_u64"
                        ]
                        index[0] = int(index[0]) ^ 1
                    else:
                        values = dataset[:]
                        del file[dataset_path]
                        file.create_dataset(
                            dataset_path,
                            data=np.asarray(values, dtype=np.dtype(">i2")),
                            maxshape=(None, values.shape[1]),
                            chunks=(values.shape[0], values.shape[1]),
                        )
                    file.flush()

                observation = validate_closed_generation(manifest, receipt)
                self.assertFalse(observation.passed)
                self.assertFalse(observation.raw_sample_byte_equality_checked)
                self.assertGreaterEqual(
                    observation.raw_sample_bytes_checked,
                    0,
                )
                self.assertTrue(
                    any(
                        "raw sample" in error
                        or "ElectricalSeries shape" in error
                        or "block-index provenance mismatch" in error
                        for error in observation.reconciliation_errors
                    ),
                    observation.reconciliation_errors,
                )

    def test_interrupted_generation_is_never_reopened_and_new_generation_replays(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            first = _manifest(directory, generation=1)
            backend = PyNwbSwmrBackend(target_chunk_bytes=256 * 1024)
            materializer = JournalToNwbMaterializer(
                first,
                directory / "run.g0001.checkpoint.json",
                CanonicalSampleBlockDecoder(),
                backend,
            )
            self.assertEqual(materializer.step(max_chunks=1), 1)
            backend.close()  # simulated writer exit; artifact remains forensic
            self.assertTrue(first.inprogress_path.exists())
            with self.assertRaises(NwbUnavailableError):
                JournalToNwbMaterializer(
                    first,
                    directory / "another-checkpoint.json",
                    CanonicalSampleBlockDecoder(),
                    PyNwbSwmrBackend(target_chunk_bytes=256 * 1024),
                )

            second = _manifest(directory, generation=2)
            rebuilt = JournalToNwbMaterializer(
                second,
                directory / "run.g0002.checkpoint.json",
                CanonicalSampleBlockDecoder(),
                PyNwbSwmrBackend(target_chunk_bytes=256 * 1024),
            )
            self.assertEqual(rebuilt.step(max_chunks=8), 2)
            receipt = rebuilt.finish_generation()
            self.assertEqual(receipt.materialized_last_journal_sequence, 1)
            self.assertTrue(first.inprogress_path.exists())
            self.assertTrue(second.inprogress_path.exists())

    def test_live_nwbd_kill_leaves_generation_forensic_and_new_generation_rebuilds(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            run_id = UUID("01234567-89ab-cdef-0123-456789abcdef")
            journal = directory / "run.wal"
            fixture = write_fixture_journal(
                journal,
                run_id=run_id,
                record_count=2,
                durable_count=1,
            )
            first = _manifest(directory, generation=1)
            first_manifest = directory / "run.g0001.materialization.json"
            save_manifest(first_manifest, first)

            command = (
                sys.executable,
                "-m",
                "forge_workers.forge_nwbd",
                "--mode",
                "live",
                "--poll-interval-ms",
                "25",
                "--manifest",
                str(first_manifest),
            )
            first_worker = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                _wait_for_swmr_samples(
                    first.inprogress_path,
                    first.pods[0].electrical_series_name,
                    expected_samples=4,
                )
                self.assertIsNone(
                    first_worker.poll(), "unsealed live worker exited before kill"
                )
            finally:
                if first_worker.poll() is None:
                    first_worker.kill()
                first_stdout, first_stderr = first_worker.communicate(timeout=15)
            self.assertNotEqual(
                first_worker.returncode,
                0,
                f"unsealed live worker unexpectedly completed: {first_stdout}\n{first_stderr}",
            )
            self.assertTrue(first.inprogress_path.exists())
            self.assertTrue(Path(f"{first.inprogress_path}.checkpoint.json").exists())
            self.assertFalse(Path(f"{first.inprogress_path}.validation.json").exists())
            self.assertFalse(Path(f"{first.inprogress_path}.validation.bin").exists())
            self.assertFalse(first.final_path.exists())
            first_size = first.inprogress_path.stat().st_size
            first_sha256 = hashlib.sha256(first.inprogress_path.read_bytes()).hexdigest()
            first_scan = scan_journal(journal)
            self.assertEqual(first_scan.durable.durable_record_count, 1)
            self.assertEqual(first_scan.durable.durable_journal_sequence, 0)

            second = _manifest(directory, generation=2)
            second_manifest = directory / "run.g0002.materialization.json"
            save_manifest(second_manifest, second)
            second_command = (
                sys.executable,
                "-m",
                "forge_workers.forge_nwbd",
                "--mode",
                "live",
                "--poll-interval-ms",
                "25",
                "--manifest",
                str(second_manifest),
            )
            second_worker = subprocess.Popen(
                second_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                _wait_for_swmr_samples(
                    second.inprogress_path,
                    second.pods[0].electrical_series_name,
                    expected_samples=4,
                )
                fixture = advance_fixture_durable_watermark(
                    journal,
                    fixture,
                    durable_count=2,
                    checkpoint_generation=3,
                )
                _write_seal(journal)
                sealed_scan = scan_journal(journal)
                self.assertEqual(sealed_scan.durable.durable_record_count, 2)
                self.assertEqual(sealed_scan.durable.durable_journal_sequence, 1)
                self.assertIsNotNone(sealed_scan.seal)
                self.assertEqual(sealed_scan.seal.expected_last_journal_sequence, 1)
                second_stdout, second_stderr = second_worker.communicate(timeout=45)
            finally:
                if second_worker.poll() is None:
                    second_worker.kill()
                    second_worker.communicate(timeout=15)
            self.assertEqual(second_worker.returncode, 0, second_stderr)
            result = json.loads(second_stdout)
            self.assertEqual(result["status"], "validated_generation_unpublished")
            self.assertEqual(result["generation"], 2)
            self.assertEqual(result["materialized_chunks"], 2)
            self.assertEqual(result["checked_journal_records"], 2)
            self.assertEqual(result["checked_sample_blocks"], 2)
            self.assertEqual(fixture.durable_count, 2)
            with h5py.File(second.inprogress_path, "r", swmr=True) as reader:
                samples = reader[
                    f"acquisition/{second.pods[0].electrical_series_name}/data"
                ]
                samples.refresh()
                self.assertEqual(samples.shape, (8, 2))
            self.assertTrue(Path(result["validation_report_path"]).exists())
            self.assertTrue(Path(result["validation_receipt_path"]).exists())
            self.assertTrue(first.inprogress_path.exists())
            self.assertEqual(first.inprogress_path.stat().st_size, first_size)
            self.assertEqual(
                hashlib.sha256(first.inprogress_path.read_bytes()).hexdigest(),
                first_sha256,
            )
            self.assertFalse(second.final_path.exists())


if __name__ == "__main__":
    unittest.main()
