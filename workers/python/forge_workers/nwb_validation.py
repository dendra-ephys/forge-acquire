"""Closed-generation NWB validation without publication authority.

The validator derives observations from the durable journal, its CRC-bound
seal, the close receipt, and the closed ``.nwb.inprogress`` artifact.  It does
not trust caller-supplied success booleans and it never renames or publishes a
file.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

import numpy as np

from .journal import JournalCursor, scan_journal
from .materializer import (
    CANONICAL_RAW_SAMPLE_DTYPE,
    CanonicalSampleBlockDecoder,
    MaterializedEvent,
    NwbGenerationCloseReceipt,
    NwbSchemaPlan,
    RunMaterializationManifest,
    canonical_raw_sample_bytes,
    canonical_raw_sample_matrix,
    sha256_file,
)
from .nwb_backend import BLOCK_INDEX_COLUMNS, PyNwbSwmrBackend
from .sdk import SampleBlock


@dataclass(frozen=True, slots=True)
class NwbValidationObservation:
    run_id: str
    generation: int
    nwb_sha256: str
    expected_last_journal_sequence: int | None
    checked_journal_records: int
    checked_sample_blocks: int
    samples_per_canonical_pod: Mapping[str, int]
    schema_errors: tuple[str, ...]
    inspector_critical: tuple[str, ...]
    reconciliation_errors: tuple[str, ...]
    raw_sample_byte_equality_checked: bool
    raw_sample_bytes_checked: int
    raw_sample_blocks_per_canonical_pod: Mapping[str, int]
    raw_sample_sha256_per_canonical_pod: Mapping[str, str]
    publication_authorized: bool = False

    @property
    def passed(self) -> bool:
        return not (
            self.schema_errors
            or self.inspector_critical
            or self.reconciliation_errors
        )

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "generation": self.generation,
            "nwb_sha256": self.nwb_sha256,
            "expected_last_journal_sequence": self.expected_last_journal_sequence,
            "checked_journal_records": self.checked_journal_records,
            "checked_sample_blocks": self.checked_sample_blocks,
            "samples_per_canonical_pod": dict(self.samples_per_canonical_pod),
            "schema_errors": list(self.schema_errors),
            "inspector_critical": list(self.inspector_critical),
            "reconciliation_errors": list(self.reconciliation_errors),
            "raw_sample_byte_equality_checked": self.raw_sample_byte_equality_checked,
            "raw_sample_bytes_checked": self.raw_sample_bytes_checked,
            "raw_sample_blocks_per_canonical_pod": dict(
                self.raw_sample_blocks_per_canonical_pod
            ),
            "raw_sample_sha256_per_canonical_pod": dict(
                self.raw_sample_sha256_per_canonical_pod
            ),
            "passed": self.passed,
            "publication_authorized": self.publication_authorized,
        }


@dataclass(slots=True)
class _RawSampleEqualityEvidence:
    """Streaming raw-byte evidence; never contains a full Run sample array."""

    bytes_checked: int
    blocks_per_pod: dict[str, int]
    digests: dict[str, Any]
    failures: int = 0

    @classmethod
    def empty(cls, manifest: RunMaterializationManifest) -> "_RawSampleEqualityEvidence":
        return cls(
            bytes_checked=0,
            blocks_per_pod={pod.canonical_pod_id.hex(): 0 for pod in manifest.pods},
            digests={pod.canonical_pod_id.hex(): hashlib.sha256() for pod in manifest.pods},
        )

    @property
    def checked(self) -> bool:
        return self.failures == 0

    def digest_hex(self) -> dict[str, str]:
        return {key: self.digests[key].hexdigest() for key in sorted(self.digests)}


def validate_closed_generation(
    manifest: RunMaterializationManifest,
    close_receipt: NwbGenerationCloseReceipt,
    *,
    max_chunks_per_pull: int = 256,
) -> NwbValidationObservation:
    """Validate one closed generation with bounded journal/HDF5 reads.

    Each durable canonical SampleBlock is decoded to the writer's exact
    little-endian int16 C-order byte view and compared with the corresponding
    ElectricalSeries slice. No record envelope/header and no whole-Run array
    participates in this comparison.
    """

    if max_chunks_per_pull <= 0:
        raise ValueError("max_chunks_per_pull must be positive")
    runtime_error = PyNwbSwmrBackend().unavailable_reason
    if runtime_error is not None:
        raise RuntimeError(runtime_error)

    reconciliation: list[str] = []
    if close_receipt.run_id != manifest.run_id:
        reconciliation.append("close receipt Run UUID does not match manifest")
    if close_receipt.generation != manifest.generation:
        reconciliation.append("close receipt generation does not match manifest")
    if close_receipt.schema_plan_sha256 != NwbSchemaPlan.from_manifest(manifest).sha256:
        reconciliation.append("close receipt schema hash does not match manifest")
    if close_receipt.validation_pending is not True:
        reconciliation.append("close receipt did not retain validation_pending")
    if close_receipt.publication_authorized:
        reconciliation.append("close receipt illegally claims publication authority")
    if manifest.final_path.exists():
        reconciliation.append("final NWB path exists before publication authority")
    if not manifest.inprogress_path.is_file():
        reconciliation.append("closed .nwb.inprogress artifact is missing")
        return _observation(
            manifest,
            close_receipt,
            nwb_sha256="",
            checked_journal_records=0,
            checked_sample_blocks=0,
            samples={},
            schema_errors=(),
            inspector_critical=(),
            reconciliation=reconciliation,
            raw_equality=_RawSampleEqualityEvidence.empty(manifest),
        )

    artifact_sha256 = sha256_file(manifest.inprogress_path)
    if artifact_sha256 != close_receipt.inprogress_sha256:
        reconciliation.append(".nwb.inprogress hash differs from close receipt")
    if manifest.inprogress_path.stat().st_size != close_receipt.inprogress_bytes:
        reconciliation.append(".nwb.inprogress size differs from close receipt")

    scan = scan_journal(manifest.journal_path)
    expected_last = None if scan.seal is None else scan.seal.expected_last_journal_sequence
    if scan.seal is None:
        reconciliation.append("journal has no valid seal")
    if expected_last != close_receipt.expected_last_journal_sequence:
        reconciliation.append("journal seal expected-last differs from close receipt")
    if scan.durable.durable_journal_sequence != expected_last:
        reconciliation.append("journal durable watermark does not reach its seal")

    checked_journal_records = 0
    checked_sample_blocks = 0
    observed_samples: dict[str, int] = {}
    raw_equality = _RawSampleEqualityEvidence.empty(manifest)
    try:
        (
            checked_journal_records,
            checked_sample_blocks,
            observed_samples,
            raw_equality,
        ) = _reconcile_hdf5(
            manifest,
            expected_last=expected_last,
            max_chunks_per_pull=max_chunks_per_pull,
            errors=reconciliation,
        )
    except Exception as error:  # fail closed and retain an auditable observation
        raw_equality.failures += 1
        reconciliation.append(f"HDF5/journal reconciliation raised {type(error).__name__}: {error}")

    if dict(close_receipt.samples_per_canonical_pod) != observed_samples:
        reconciliation.append("per-Pod sample counts differ from close receipt")

    import pynwb
    from nwbinspector import Importance, inspect_nwbfile

    schema_errors = tuple(str(error) for error in pynwb.validate(path=manifest.inprogress_path))
    inspector_critical = tuple(
        _format_inspector_message(message)
        for message in inspect_nwbfile(manifest.inprogress_path)
        if message.importance == Importance.CRITICAL
    )
    return _observation(
        manifest,
        close_receipt,
        nwb_sha256=artifact_sha256,
        checked_journal_records=checked_journal_records,
        checked_sample_blocks=checked_sample_blocks,
        samples=observed_samples,
        schema_errors=schema_errors,
        inspector_critical=inspector_critical,
        reconciliation=reconciliation,
        raw_equality=raw_equality,
    )


def _reconcile_hdf5(
    manifest: RunMaterializationManifest,
    *,
    expected_last: int | None,
    max_chunks_per_pull: int,
    errors: list[str],
) -> tuple[int, int, dict[str, int], _RawSampleEqualityEvidence]:
    import h5py

    expected_records = 0 if expected_last is None else expected_last + 1
    observed_samples = {pod.canonical_pod_id.hex(): 0 for pod in manifest.pods}
    schema = NwbSchemaPlan.from_manifest(manifest)
    decoder = CanonicalSampleBlockDecoder()
    cursor = JournalCursor(manifest.journal_path)
    checked_records = 0
    checked_sample_blocks = 0
    pod_sample_offsets: dict[str, int | None] = {
        pod.canonical_pod_id.hex(): None for pod in manifest.pods
    }
    event_rows = {table.name: 0 for table in schema.event_tables}
    raw_equality = _RawSampleEqualityEvidence.empty(manifest)

    with h5py.File(manifest.inprogress_path, "r", libver="latest", swmr=True) as h5file:
        root = "processing/forge_provenance/forge_block_index"
        block_ids = h5file[f"{root}/id"]
        columns = {name: h5file[f"{root}/{name}"] for name in BLOCK_INDEX_COLUMNS}
        event_handles = {
            table.name: (
                h5file[f"intervals/{table.name}/id"],
                {
                    name: h5file[f"intervals/{table.name}/{name}"]
                    for name, _ in table.columns
                },
                dict(table.columns),
            )
            for table in schema.event_tables
        }
        series = {
            pod.canonical_pod_id.hex(): h5file[
                f"acquisition/{pod.electrical_series_name}/data"
            ]
            for pod in manifest.pods
        }

        while True:
            batch = cursor.poll(max_chunks=max_chunks_per_pull)
            if not batch.chunks:
                break
            for chunk in batch.chunks:
                decoded = decoder.decode(chunk, manifest)
                if checked_records >= expected_records:
                    errors.append("journal exposes records beyond sealed expected-last")
                    break
                if isinstance(decoded, SampleBlock):
                    if checked_sample_blocks >= block_ids.shape[0]:
                        errors.append("block-index has fewer rows than journal SampleBlocks")
                    else:
                        stored = tuple(
                            int(columns[name][checked_sample_blocks])
                            for name in BLOCK_INDEX_COLUMNS
                        )
                        expected = _block_index_values(decoded)
                        if stored != expected:
                            errors.append(
                                "block-index provenance mismatch at journal sequence "
                                f"{chunk.metadata.journal_sequence}"
                            )
                        if int(block_ids[checked_sample_blocks]) != checked_sample_blocks:
                            errors.append(
                                f"block-index id mismatch at row {checked_sample_blocks}"
                            )
                    key = decoded.canonical_pod_id.hex()
                    if key not in observed_samples:
                        errors.append(f"journal block references unplanned Pod {key}")
                    else:
                        _compare_raw_sample_block(
                            decoded,
                            series[key],
                            sample_offset=observed_samples[key],
                            errors=errors,
                            evidence=raw_equality,
                        )
                        previous = pod_sample_offsets[key]
                        if (
                            previous is not None
                            and decoded.sample_start != previous
                            and not (decoded.record_flags & 1)
                        ):
                            errors.append(
                                f"Pod {key} sample offset is discontinuous at journal sequence "
                                f"{chunk.metadata.journal_sequence}"
                            )
                        pod_sample_offsets[key] = decoded.sample_end_exclusive
                        observed_samples[key] += decoded.sample_count
                    checked_sample_blocks += 1
                else:
                    _reconcile_event_row(
                        decoded,
                        event_handles,
                        event_rows,
                        errors,
                        chunk.metadata.journal_sequence,
                    )
                checked_records += 1
            if checked_records > expected_records:
                break

        if checked_records != expected_records:
            errors.append("validated journal record count differs from sealed expected-last")
        if block_ids.shape != (checked_sample_blocks,):
            errors.append("block-index row count differs from journal SampleBlock count")
        for name, dataset in columns.items():
            if dataset.shape != (checked_sample_blocks,):
                errors.append(f"block-index column {name} has wrong row count")
        for table_name, (identifiers, event_columns, _) in event_handles.items():
            expected_event_rows = event_rows[table_name]
            if identifiers.shape != (expected_event_rows,):
                errors.append(f"event table {table_name} id count differs from journal")
            for name, dataset in event_columns.items():
                if dataset.shape != (expected_event_rows,):
                    errors.append(
                        f"event table {table_name}/{name} count differs from journal"
                    )
        for pod in manifest.pods:
            key = pod.canonical_pod_id.hex()
            dataset = series[key]
            expected_shape = (observed_samples[key], pod.channel_count)
            if dataset.shape != expected_shape:
                raw_equality.failures += 1
                errors.append(f"ElectricalSeries shape mismatch for Pod {key}")
            if dataset.dtype != CANONICAL_RAW_SAMPLE_DTYPE or dataset.compression is not None:
                raw_equality.failures += 1
                errors.append(f"ElectricalSeries storage profile mismatch for Pod {key}")

    return checked_records, checked_sample_blocks, observed_samples, raw_equality


def _compare_raw_sample_block(
    block: SampleBlock,
    dataset: Any,
    *,
    sample_offset: int,
    errors: list[str],
    evidence: _RawSampleEqualityEvidence,
) -> None:
    """Compare one bounded durable block against its exact HDF5 data slice."""

    key = block.canonical_pod_id.hex()
    journal_matrix = canonical_raw_sample_matrix(block.samples)
    journal_bytes = canonical_raw_sample_bytes(journal_matrix)
    evidence.bytes_checked += len(journal_bytes)
    evidence.blocks_per_pod[key] += 1
    evidence.digests[key].update(journal_bytes)
    if (
        dataset.dtype != CANONICAL_RAW_SAMPLE_DTYPE
        or dataset.ndim != 2
        or dataset.shape[1] != block.channel_count
    ):
        evidence.failures += 1
        errors.append(
            f"raw sample storage mismatch for Pod {key} at journal sequence "
            f"{block.journal_sequence}"
        )
        return
    stop = sample_offset + block.sample_count
    if stop > dataset.shape[0]:
        evidence.failures += 1
        errors.append(
            f"raw sample dataset truncated for Pod {key} at journal sequence "
            f"{block.journal_sequence}; expected sample end {stop}, got {dataset.shape[0]}"
        )
        return
    stored_matrix = canonical_raw_sample_matrix(dataset[sample_offset:stop, :])
    stored_bytes = canonical_raw_sample_bytes(stored_matrix)
    if len(stored_bytes) != len(journal_bytes) or hashlib.sha256(
        stored_bytes
    ).digest() != hashlib.sha256(journal_bytes).digest():
        evidence.failures += 1
        differing = np.argwhere(journal_matrix != stored_matrix)
        if differing.size:
            row, channel = (int(value) for value in differing[0])
            errors.append(
                f"raw sample byte mismatch for Pod {key} at journal sequence "
                f"{block.journal_sequence}, sample offset {sample_offset + row}, "
                f"channel offset {channel}"
            )
        else:
            errors.append(
                f"raw sample byte length mismatch for Pod {key} at journal sequence "
                f"{block.journal_sequence}"
            )


def _reconcile_event_row(
    event: MaterializedEvent,
    handles: Mapping[str, tuple[Any, Mapping[str, Any], Mapping[str, str]]],
    row_counts: dict[str, int],
    errors: list[str],
    journal_sequence: int,
) -> None:
    identifiers, columns, descriptions = handles[event.table_name]
    row = row_counts[event.table_name]
    if row >= identifiers.shape[0]:
        errors.append(
            f"event table {event.table_name} has fewer rows than journal events"
        )
        row_counts[event.table_name] = row + 1
        return
    if int(identifiers[row]) != row:
        errors.append(f"event table {event.table_name} id mismatch at row {row}")
    for name, expected in event.values.items():
        observed = _read_event_value(columns[name][row], descriptions[name])
        if observed != expected:
            errors.append(
                f"event table {event.table_name}/{name} mismatch at journal sequence "
                f"{journal_sequence}"
            )
    row_counts[event.table_name] = row + 1


def _read_event_value(value: Any, description: str) -> int | float | str:
    if description.startswith(("hex[", "utf8[")):
        return bytes(value).decode("utf-8", errors="strict")
    if description.startswith("float64"):
        return float(value)
    return int(value)


def _block_index_values(block: Any) -> tuple[int, ...]:
    return (
        int.from_bytes(block.canonical_pod_id[:8], "little"),
        int.from_bytes(block.canonical_pod_id[8:], "little"),
        block.journal_sequence,
        block.record_sequence,
        block.frame_start,
        block.frame_end_exclusive,
        block.sample_start,
        block.sample_end_exclusive,
        block.global_time_start_ns,
        block.global_time_end_exclusive_ns,
        block.record_flags,
    )


def _format_inspector_message(message: Any) -> str:
    return (
        f"{message.check_function_name} at {message.location}: "
        f"{message.message}"
    )


def _observation(
    manifest: RunMaterializationManifest,
    close_receipt: NwbGenerationCloseReceipt,
    *,
    nwb_sha256: str,
    checked_journal_records: int,
    checked_sample_blocks: int,
    samples: Mapping[str, int],
    schema_errors: tuple[str, ...],
    inspector_critical: tuple[str, ...],
    reconciliation: list[str],
    raw_equality: _RawSampleEqualityEvidence,
) -> NwbValidationObservation:
    return NwbValidationObservation(
        run_id=str(manifest.run_id),
        generation=manifest.generation,
        nwb_sha256=nwb_sha256,
        expected_last_journal_sequence=close_receipt.expected_last_journal_sequence,
        checked_journal_records=checked_journal_records,
        checked_sample_blocks=checked_sample_blocks,
        samples_per_canonical_pod=dict(sorted(samples.items())),
        schema_errors=schema_errors,
        inspector_critical=inspector_critical,
        reconciliation_errors=tuple(dict.fromkeys(reconciliation)),
        raw_sample_byte_equality_checked=(
            raw_equality.checked
            and not reconciliation
            and not schema_errors
            and not inspector_critical
        ),
        raw_sample_bytes_checked=raw_equality.bytes_checked,
        raw_sample_blocks_per_canonical_pod=dict(sorted(raw_equality.blocks_per_pod.items())),
        raw_sample_sha256_per_canonical_pod=raw_equality.digest_hex(),
        publication_authorized=False,
    )
