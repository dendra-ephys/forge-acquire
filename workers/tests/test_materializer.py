from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from uuid import UUID

from forge_workers._protocol import protocol
from forge_workers.journal import JournalCursor, pod_slot_for
from forge_workers.materializer import (
    CanonicalSampleBlockDecoder,
    MaterializedEvent,
    MaterializationCheckpoint,
    MaterializationIdentityError,
    NwbSchemaPlan,
    NwbUnavailableError,
    PodNwbPlan,
    PublicationValidationReceipt,
    RunMaterializationManifest,
    atomic_publish_validated_nwb,
    load_checkpoint,
    preflight_materializer,
    save_checkpoint,
    sha256_file,
)

from helpers import (
    HEADSTAGE_ID,
    POD_ID,
    make_sample_record,
    write_encoded_records_journal,
    write_fixture_journal,
)


POD_2 = bytes.fromhex("303132333435363738393a3b3c3d3e3f")


def pod_plan(pod_id: bytes, first_channel: int) -> PodNwbPlan:
    return PodNwbPlan(
        canonical_pod_id=pod_id,
        pod_slot=pod_slot_for(pod_id),
        channel_layout_id=7,
        channel_count=2,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        conversion_volts_per_count=0.195e-6,
        channel_ids=(first_channel, first_channel + 1),
    )


class MaterializerBoundaryTests(unittest.TestCase):
    def make_manifest(self, directory: Path) -> RunMaterializationManifest:
        run_id = UUID("01234567-89ab-cdef-0123-456789abcdef")
        journal = directory / "run.wal"
        write_fixture_journal(journal, run_id=run_id)
        final = directory / "run.nwb"
        return RunMaterializationManifest(
            run_id=run_id,
            generation=7,
            protocol_contract_hash=protocol.PROTOCOL_HASH_HEX,
            journal_path=journal,
            inprogress_path=directory / "run.g0007.nwb.inprogress",
            final_path=final,
            pods=(pod_plan(POD_ID, 0), pod_plan(POD_2, 2)),
            dependency_lock={},
        )

    def test_schema_predeclares_one_series_per_canonical_pod(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            manifest = self.make_manifest(Path(directory_name))
            schema = NwbSchemaPlan.from_manifest(manifest)
            self.assertEqual(
                [series.canonical_pod_id for series in schema.electrical_series],
                [POD_ID.hex(), POD_2.hex()],
            )
            self.assertEqual(
                {table.name for table in schema.event_tables},
                {
                    "forge_markers",
                    "forge_faults",
                    "forge_gaps",
                    "forge_analysis_results",
                    "forge_stimulation_intents",
                    "forge_stimulation_receipts",
                },
            )

    def test_canonical_decoder_preserves_both_sequences_and_exclusive_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            manifest = self.make_manifest(Path(directory_name))
            chunk = JournalCursor(manifest.journal_path).poll(max_chunks=1).chunks[0]
            block = CanonicalSampleBlockDecoder().decode(chunk, manifest)
            self.assertEqual(block.canonical_pod_id, POD_ID)
            self.assertEqual(block.pod_slot, pod_slot_for(POD_ID))
            self.assertEqual(block.journal_sequence, 0)
            self.assertEqual(block.record_sequence, 0)
            self.assertEqual(block.sample_start, 0)
            self.assertEqual(block.sample_end_exclusive, 4)
            self.assertEqual(block.samples.shape, (4, 2))
            self.assertFalse(block.samples.flags.writeable)

    def test_canonical_decoder_maps_typed_marker_without_sample_counting(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            run_id = UUID("01234567-89ab-cdef-0123-456789abcdef")
            sample = make_sample_record(
                run_id=run_id, record_sequence=0, sample_start=0
            )
            marker_payload = protocol.MarkerPayloadV1(
                event_id=bytes.fromhex("41414141414141414141414141414141"),
                marker_sequence=9,
                marker_flags=protocol.MARKER_FLAG_OPERATOR,
                label="baseline",
                note="operator note",
            ).to_bytes()
            marker = protocol.encode_record(
                protocol.CanonicalRecordEnvelopeV1(
                    record_kind=protocol.RecordKind.MARKER,
                    flags=0,
                    run_id=run_id.bytes,
                    pod_id=POD_ID,
                    headstage_id=HEADSTAGE_ID,
                    record_sequence=1,
                    frame_start=0,
                    frame_end_exclusive=1,
                    sample_start=3,
                    sample_end_exclusive=4,
                    global_time_start_ns=900_000,
                    global_time_end_exclusive_ns=900_001,
                    channel_layout_id=7,
                    channel_count=2,
                ),
                marker_payload,
            )
            journal = directory / "typed.wal"
            write_encoded_records_journal(
                journal, run_id=run_id, encoded_records=(sample, marker)
            )
            manifest = RunMaterializationManifest(
                run_id=run_id,
                generation=1,
                protocol_contract_hash=protocol.PROTOCOL_HASH_HEX,
                journal_path=journal,
                inprogress_path=directory / "typed.g0001.nwb.inprogress",
                final_path=directory / "typed.nwb",
                pods=(pod_plan(POD_ID, 0),),
            )
            chunks = JournalCursor(journal).poll(max_chunks=2).chunks
            decoded = CanonicalSampleBlockDecoder().decode(chunks[1], manifest)
            self.assertIsInstance(decoded, MaterializedEvent)
            assert isinstance(decoded, MaterializedEvent)
            self.assertEqual(decoded.table_name, "forge_markers")
            self.assertEqual(decoded.values["marker_sequence"], 9)
            self.assertEqual(decoded.values["sample_index"], 3)
            self.assertEqual(decoded.values["label"], "baseline")
            self.assertEqual(decoded.values["canonical_pod_id"], POD_ID.hex())

    def test_preflight_is_explicitly_unavailable_and_writes_no_nwb(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            manifest = self.make_manifest(Path(directory_name))
            report = preflight_materializer(manifest)
            self.assertFalse(report.available)
            self.assertFalse(report.creates_nwb)
            self.assertTrue(any("dependency" in reason for reason in report.reasons))
            self.assertTrue(any("NWB writer unavailable" in reason for reason in report.reasons))
            self.assertFalse(
                any("payload decoder unavailable" in reason for reason in report.reasons)
            )
            self.assertFalse(manifest.inprogress_path.exists())
            self.assertFalse(manifest.final_path.exists())

    def test_progress_checkpoint_is_atomic_and_bound_to_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            manifest = self.make_manifest(directory)
            schema = NwbSchemaPlan.from_manifest(manifest)
            checkpoint = MaterializationCheckpoint(
                run_id=manifest.run_id,
                generation=manifest.generation,
                schema_plan_sha256=schema.sha256,
                last_materialized_journal_sequence=1,
                samples_per_canonical_pod={POD_ID.hex(): 8, POD_2.hex(): 0},
            )
            path = directory / "checkpoint.json"
            save_checkpoint(path, checkpoint)
            restored = load_checkpoint(path)
            restored.assert_matches(manifest, schema)

            wrong_generation = RunMaterializationManifest(
                run_id=manifest.run_id,
                generation=8,
                protocol_contract_hash=manifest.protocol_contract_hash,
                journal_path=manifest.journal_path,
                inprogress_path=directory / "run.g0008.nwb.inprogress",
                final_path=manifest.final_path,
                pods=manifest.pods,
            )
            with self.assertRaises(MaterializationIdentityError):
                restored.assert_matches(
                    wrong_generation, NwbSchemaPlan.from_manifest(wrong_generation)
                )

    def test_preflight_refuses_to_reopen_an_existing_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            manifest = self.make_manifest(Path(directory_name))
            manifest.inprogress_path.write_bytes(b"unknown interrupted writer state")
            report = preflight_materializer(manifest)
            self.assertFalse(report.available)
            self.assertTrue(any("new generation" in reason for reason in report.reasons))

    def test_positive_caller_booleans_cannot_publish_without_trusted_seal(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            manifest = self.make_manifest(directory)
            manifest.inprogress_path.write_bytes(b"not an NWB file")
            receipt = PublicationValidationReceipt(
                run_id=manifest.run_id,
                generation=manifest.generation,
                journal_sealed=True,
                schema_validator_name="pynwb-validate",
                schema_exit_code=0,
                inspector_name="nwbinspector",
                inspector_exit_code=0,
                reconciliation_passed=True,
                expected_last_journal_sequence=1,
                materialized_last_journal_sequence=1,
                inprogress_sha256=sha256_file(manifest.inprogress_path),
            )
            with self.assertRaisesRegex(NwbUnavailableError, "trusted daemon seal"):
                atomic_publish_validated_nwb(manifest, receipt)
            self.assertTrue(manifest.inprogress_path.exists())
            self.assertFalse(manifest.final_path.exists())


if __name__ == "__main__":
    unittest.main()
