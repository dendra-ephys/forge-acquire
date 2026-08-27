"""Independent one-generation Forge NWB materializer executable.

``sealed`` mode consumes an already sealed durable journal. ``live`` mode is
a pull-only follower of the durable watermark: it creates a fresh generation
immediately, appends bounded batches, and closes only after a durable seal.
Neither mode publishes or renames the NWB file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time
from typing import Any, Mapping, Sequence

from ._protocol import protocol
from .journal import JournalScan, scan_journal
from .materializer import (
    CanonicalSampleBlockDecoder,
    JournalToNwbMaterializer,
    NwbUnavailableError,
    RunMaterializationManifest,
    load_manifest,
    sha256_file,
)
from .nwb_backend import (
    LOCKED_HDF5_RUNTIME,
    LOCKED_NWB_VERSIONS,
    PyNwbSwmrBackend,
)
from .nwb_receipt import (
    EMPTY_EXPECTED_LAST,
    REQUIRED_VALIDATION_FLAGS,
    RECEIPT_CONTRACT_HASH_HEX,
    NwbGenerationValidationReceiptV1,
)
from .nwb_validation import NwbValidationObservation, validate_closed_generation


REPORT_SCHEMA = "forge.nwb-generation-validation-report.v1"
COMMAND_SCHEMA = "forge.forge-nwbd-result.v1"


def materialize_sealed_generation(
    manifest_path: str | Path,
    *,
    checkpoint_path: str | Path | None = None,
    report_path: str | Path | None = None,
    receipt_path: str | Path | None = None,
    validation_sequence: int = 1,
) -> dict[str, Any]:
    manifest_file = Path(manifest_path).resolve()
    manifest = load_manifest(manifest_file)
    checkpoint = _default_path(manifest, checkpoint_path, ".checkpoint.json")
    report = _default_path(manifest, report_path, ".validation.json")
    receipt = _default_path(manifest, receipt_path, ".validation.bin")
    _validate_owned_paths(manifest, checkpoint, report, receipt)
    if validation_sequence <= 0:
        raise ValueError("validation_sequence must be positive")
    for path in (report, receipt):
        if path.exists():
            raise FileExistsError(f"validation output already exists: {path}")

    initial_scan = scan_journal(manifest.journal_path)
    if initial_scan.seal is None:
        raise NwbUnavailableError("forge-nwbd sealed-generation mode requires a journal seal")
    if initial_scan.torn_tail:
        raise NwbUnavailableError("sealed journal has a torn tail")
    if initial_scan.durable.durable_journal_sequence != (
        initial_scan.seal.expected_last_journal_sequence
    ):
        raise NwbUnavailableError("journal durable watermark does not reach its seal")

    backend = PyNwbSwmrBackend()
    materializer = JournalToNwbMaterializer(
        manifest,
        checkpoint,
        CanonicalSampleBlockDecoder(),
        backend,
    )
    materialized_chunks = 0
    while True:
        count = materializer.step(max_chunks=256)
        materialized_chunks += count
        if count == 0:
            break
    close_receipt = materializer.finish_generation()
    final_scan = scan_journal(manifest.journal_path)
    if final_scan != initial_scan:
        raise NwbUnavailableError("sealed journal identity changed during materialization")
    return _validate_and_commit_generation(
        manifest_file,
        manifest,
        final_scan,
        close_receipt=close_receipt,
        materialized_chunks=materialized_chunks,
        validation_sequence=validation_sequence,
        report=report,
        receipt=receipt,
    )


def materialize_live_generation(
    manifest_path: str | Path,
    *,
    checkpoint_path: str | Path | None = None,
    report_path: str | Path | None = None,
    receipt_path: str | Path | None = None,
    validation_sequence: int = 1,
    poll_interval_ms: int = 250,
) -> dict[str, Any]:
    """Follow a journal's durable watermark until a sealed close is proven.

    The worker is read-only with respect to acquisition: it has no producer
    control, acknowledgement, or backpressure channel. A killed worker leaves
    its in-progress generation as forensic evidence; a higher manifest
    generation must rebuild the run from journal sequence zero.
    """

    if not 0 < poll_interval_ms <= 2_000:
        raise ValueError("poll_interval_ms must be within 1..2000")
    manifest_file = Path(manifest_path).resolve()
    manifest = load_manifest(manifest_file)
    checkpoint = _default_path(manifest, checkpoint_path, ".checkpoint.json")
    report = _default_path(manifest, report_path, ".validation.json")
    receipt = _default_path(manifest, receipt_path, ".validation.bin")
    _validate_owned_paths(manifest, checkpoint, report, receipt)
    if validation_sequence <= 0:
        raise ValueError("validation_sequence must be positive")
    for path in (report, receipt):
        if path.exists():
            raise FileExistsError(f"validation output already exists: {path}")

    materializer = JournalToNwbMaterializer(
        manifest,
        checkpoint,
        CanonicalSampleBlockDecoder(),
        PyNwbSwmrBackend(),
    )
    materialized_chunks = 0
    while True:
        count = materializer.step(max_chunks=256)
        materialized_chunks += count
        if materializer.cursor.caught_up_to_seal:
            close_receipt = materializer.finish_generation()
            final_scan = scan_journal(manifest.journal_path)
            return _validate_and_commit_generation(
                manifest_file,
                manifest,
                final_scan,
                close_receipt=close_receipt,
                materialized_chunks=materialized_chunks,
                validation_sequence=validation_sequence,
                report=report,
                receipt=receipt,
            )
        if count == 0:
            # Avoid busy-looping. Existing ``step`` flushes each appended
            # batch; the cap maintains the at-most-two-second flush cadence.
            time.sleep(poll_interval_ms / 1_000)


def _validate_and_commit_generation(
    manifest_file: Path,
    manifest: RunMaterializationManifest,
    final_scan: JournalScan,
    *,
    close_receipt: Any,
    materialized_chunks: int,
    validation_sequence: int,
    report: Path,
    receipt: Path,
) -> dict[str, Any]:
    observation = validate_closed_generation(manifest, close_receipt)
    if not observation.passed:
        raise NwbUnavailableError(
            "closed NWB generation failed validation: "
            + "; ".join(
                observation.schema_errors
                + observation.inspector_critical
                + observation.reconciliation_errors
            )
        )
    if not observation.raw_sample_byte_equality_checked:
        raise NwbUnavailableError(
            "closed NWB generation did not complete raw sample byte equality validation"
        )
    report_value = _validation_report(
        manifest_file,
        manifest,
        observation,
        final_scan,
        materialized_chunks=materialized_chunks,
        validation_sequence=validation_sequence,
    )
    report_bytes = _canonical_json_bytes(report_value)
    binary = _binary_receipt(
        manifest_file,
        manifest,
        observation,
        final_scan,
        report_bytes=report_bytes,
        validation_sequence=validation_sequence,
    ).to_bytes()

    _atomic_write_no_overwrite(report, report_bytes)
    try:
        _atomic_write_no_overwrite(receipt, binary)
    except Exception:
        # The report intentionally remains as incomplete forensic evidence.
        # Absence of the binary commit marker means validation is uncommitted.
        raise
    decoded = NwbGenerationValidationReceiptV1.from_bytes(receipt.read_bytes())
    if decoded.validation_report_sha256 != hashlib.sha256(report.read_bytes()).digest():
        raise NwbUnavailableError("persisted validation report hash does not match receipt")
    return {
        "schema": COMMAND_SCHEMA,
        "status": "validated_generation_unpublished",
        "run_id": str(manifest.run_id),
        "generation": manifest.generation,
        "materialized_chunks": materialized_chunks,
        "checked_journal_records": observation.checked_journal_records,
        "checked_sample_blocks": observation.checked_sample_blocks,
        "nwb_inprogress_path": str(manifest.inprogress_path),
        "validation_report_path": str(report),
        "validation_receipt_path": str(receipt),
        "nwb_sha256": observation.nwb_sha256,
        "receipt_contract_hash": RECEIPT_CONTRACT_HASH_HEX,
        "publication_authorized": False,
    }


def _validation_report(
    manifest_file: Path,
    manifest: RunMaterializationManifest,
    observation: NwbValidationObservation,
    scan: JournalScan,
    *,
    materialized_chunks: int,
    validation_sequence: int,
) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "receipt_contract_hash": RECEIPT_CONTRACT_HASH_HEX,
        "host_protocol_hash": protocol.PROTOCOL_HASH_HEX,
        "run_id": str(manifest.run_id),
        "generation": manifest.generation,
        "validation_sequence": validation_sequence,
        "manifest_path": str(manifest_file),
        "manifest_sha256": sha256_file(manifest_file),
        "journal_path": str(manifest.journal_path),
        "journal_sha256": sha256_file(manifest.journal_path),
        "journal_seal_sha256": sha256_file(f"{manifest.journal_path}.seal"),
        "nwb_inprogress_path": str(manifest.inprogress_path),
        "materialized_chunks": materialized_chunks,
        "expected_last_journal_sequence": (
            None if scan.seal is None else scan.seal.expected_last_journal_sequence
        ),
        "dependency_lock": _dependency_identity(),
        "materializer_build_sha256": manifest.materializer_build_sha256,
        "schema_plan_sha256": _schema_plan_sha256_from_report_context(manifest),
        "observation": observation.to_json_dict(),
        "raw_sample_byte_equality_checked": observation.raw_sample_byte_equality_checked,
        "publication_authorized": False,
    }


def _binary_receipt(
    manifest_file: Path,
    manifest: RunMaterializationManifest,
    observation: NwbValidationObservation,
    scan: JournalScan,
    *,
    report_bytes: bytes,
    validation_sequence: int,
) -> NwbGenerationValidationReceiptV1:
    if scan.seal is None:
        raise NwbUnavailableError("cannot create validation receipt without a seal")
    samples_bytes = _canonical_json_bytes(
        dict(sorted(observation.samples_per_canonical_pod.items()))
    )
    dependency_bytes = _canonical_json_bytes(_dependency_identity())
    expected_last = (
        EMPTY_EXPECTED_LAST
        if scan.seal.expected_last_journal_sequence is None
        else scan.seal.expected_last_journal_sequence
    )
    return NwbGenerationValidationReceiptV1(
        validation_flags=REQUIRED_VALIDATION_FLAGS,
        run_id=manifest.run_id.bytes,
        generation=manifest.generation,
        pod_count=len(manifest.pods),
        expected_last_journal_sequence=expected_last,
        # The frozen receipt field is journal-record coverage, not the number
        # of raw SampleBlocks. The latter remains report-only evidence.
        checked_blocks=observation.checked_journal_records,
        total_samples=sum(observation.samples_per_canonical_pod.values()),
        validated_at_unix_ns=time.time_ns(),
        journal_bytes=manifest.journal_path.stat().st_size,
        nwb_bytes=manifest.inprogress_path.stat().st_size,
        schema_error_count=len(observation.schema_errors),
        inspector_critical_count=len(observation.inspector_critical),
        reconciliation_error_count=len(observation.reconciliation_errors),
        host_protocol_hash=protocol.PROTOCOL_HASH,
        receipt_contract_hash=bytes.fromhex(RECEIPT_CONTRACT_HASH_HEX),
        journal_sha256=bytes.fromhex(sha256_file(manifest.journal_path)),
        journal_seal_sha256=bytes.fromhex(sha256_file(f"{manifest.journal_path}.seal")),
        durable_checkpoint_set_sha256=_checkpoint_set_hash(manifest.journal_path),
        nwb_sha256=bytes.fromhex(observation.nwb_sha256),
        schema_plan_sha256=bytes.fromhex(
            _schema_plan_sha256_from_report_context(manifest)
        ),
        dependency_lock_sha256=hashlib.sha256(dependency_bytes).digest(),
        materializer_build_sha256=bytes.fromhex(manifest.materializer_build_sha256),
        validation_report_sha256=hashlib.sha256(report_bytes).digest(),
        samples_manifest_sha256=hashlib.sha256(samples_bytes).digest(),
        session_manifest_sha256=bytes.fromhex(sha256_file(manifest_file)),
        run_ledger_seal_evidence_sha256=_run_ledger_seal_evidence_hash(manifest, scan),
        validation_sequence=validation_sequence,
    )


def _schema_plan_sha256_from_report_context(manifest: RunMaterializationManifest) -> str:
    from .materializer import NwbSchemaPlan

    return NwbSchemaPlan.from_manifest(manifest).sha256


def _run_ledger_seal_evidence_hash(
    manifest: RunMaterializationManifest, scan: JournalScan
) -> bytes:
    if scan.seal is None:
        raise NwbUnavailableError("journal seal is absent")
    seal = scan.seal
    value = bytearray(b"FGRSEAL1")
    value.extend(manifest.run_id.bytes)
    value.extend(
        (
            EMPTY_EXPECTED_LAST
            if seal.expected_last_journal_sequence is None
            else seal.expected_last_journal_sequence
        ).to_bytes(8, "little")
    )
    value.extend(seal.expected_valid_len.to_bytes(8, "little"))
    value.extend(seal.checkpoint_generation.to_bytes(8, "little"))
    value.extend(seal.record_count.to_bytes(8, "little"))
    return hashlib.sha256(value).digest()


def _checkpoint_set_hash(journal_path: Path) -> bytes:
    digest = hashlib.sha256()
    digest.update(b"ForgeDurableCheckpointSetV1\0")
    for label in ("checkpoint-a", "checkpoint-b"):
        path = Path(f"{journal_path}.{label}")
        data = path.read_bytes()
        digest.update(label.encode("ascii"))
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.digest()


def _dependency_identity() -> dict[str, str]:
    return {
        **dict(sorted(LOCKED_NWB_VERSIONS.items())),
        "HDF5-runtime": LOCKED_HDF5_RUNTIME,
    }


def _canonical_json_bytes(value: Mapping[str, Any] | dict[str, int]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _default_path(
    manifest: RunMaterializationManifest,
    supplied: str | Path | None,
    suffix: str,
) -> Path:
    return (
        Path(supplied).resolve()
        if supplied is not None
        else Path(f"{manifest.inprogress_path}{suffix}")
    )


def _validate_owned_paths(
    manifest: RunMaterializationManifest,
    checkpoint: Path,
    report: Path,
    receipt: Path,
) -> None:
    parent = manifest.inprogress_path.parent
    if any(path.parent != parent for path in (checkpoint, report, receipt)):
        raise ValueError("checkpoint/report/receipt must share the NWB generation directory")
    if len({checkpoint, report, receipt, manifest.inprogress_path, manifest.final_path}) != 5:
        raise ValueError("materializer output paths must be distinct")


def _atomic_write_no_overwrite(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(
        f".{path.name}.pending-{os.getpid()}-{secrets.token_hex(8)}"
    )
    try:
        with pending.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(pending, path)
    finally:
        try:
            pending.unlink()
        except FileNotFoundError:
            pass


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--mode", choices=("sealed", "live"), default="sealed")
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--validation-sequence", type=int, default=1)
    parser.add_argument("--poll-interval-ms", type=int, default=250)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        common = {
            "checkpoint_path": arguments.checkpoint,
            "report_path": arguments.report,
            "receipt_path": arguments.receipt,
            "validation_sequence": arguments.validation_sequence,
        }
        if arguments.mode == "sealed":
            result = materialize_sealed_generation(arguments.manifest, **common)
        else:
            result = materialize_live_generation(
                arguments.manifest,
                poll_interval_ms=arguments.poll_interval_ms,
                **common,
            )
    except Exception as error:
        print(
            json.dumps(
                {
                    "schema": COMMAND_SCHEMA,
                    "status": "failed_closed",
                    "error_type": type(error).__name__,
                    "error": str(error),
                    "publication_authorized": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
