"""Regenerable, fail-closed Forge journal-to-NWB materializer boundary.

The default Forge environment intentionally has no PyNWB/NWB Inspector runtime;
the isolated ``nwb`` profile supplies the exact-version backend. The frozen M0
host-internal canonical sample/typed-event decoder is implemented, and this module
provides no fallback that writes an arbitrary HDF5 file and calls it NWB.

An interrupted writer is never reopened in place. Recovery increments the
generation and rebuilds a new ``.nwb.inprogress`` artifact from the journal.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence
from uuid import UUID

import numpy as np

from ._protocol import protocol
from .journal import (
    MAX_ENCODED_RECORD_LEN,
    JournalChunk,
    JournalCursor,
    JournalFormatError,
    JournalScan,
    pod_slot_for,
    scan_journal,
)
from .sdk import SampleBlock


MANIFEST_VERSION = 1
CHECKPOINT_VERSION = 1
REQUIRED_NWB_MODULES = ("h5py", "pynwb", "nwbinspector")


class NwbUnavailableError(RuntimeError):
    """The fail-closed NWB boundary is not available in this environment."""


class MaterializationIdentityError(ValueError):
    """A Run, generation, journal, checkpoint, or output identity mismatched."""


CANONICAL_RAW_SAMPLE_DTYPE = np.dtype("<i2")


def canonical_raw_sample_matrix(samples: Any) -> np.ndarray[Any, Any]:
    """Return the sole raw-sample byte view used by writer and validator.

    The canonical view excludes the journal envelope and every metadata field:
    it is a C-contiguous `[sample, channel]` matrix of little-endian signed
    int16 values.  Its byte order and row-major order are exactly the layout
    appended to each ElectricalSeries dataset.
    """

    matrix = np.asarray(samples, dtype=CANONICAL_RAW_SAMPLE_DTYPE, order="C")
    if matrix.ndim != 2 or 0 in matrix.shape:
        raise MaterializationIdentityError(
            "canonical raw sample matrix must be nonempty [sample, channel]"
        )
    return matrix


def canonical_raw_sample_bytes(samples: Any) -> bytes:
    """Encode the canonical raw sample matrix without envelope/header bytes."""

    return canonical_raw_sample_matrix(samples).tobytes(order="C")


@dataclass(frozen=True, slots=True)
class NwbSessionMetadata:
    """Required scientific session identity; never synthesized from USB arrival time."""

    session_description: str
    session_start_time_utc: str
    experimenter: tuple[str, ...]
    lab: str
    institution: str
    subject_id: str
    subject_species: str
    subject_sex: str
    subject_age: str
    experiment_description: str = ""
    session_id: str = ""
    protocol: str = ""
    notes: str = ""
    subject_description: str = ""
    subject_genotype: str = ""
    subject_strain: str = ""
    subject_weight: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "experimenter", tuple(self.experimenter))
        required = (
            self.session_description,
            self.session_start_time_utc,
            self.lab,
            self.institution,
            self.subject_id,
            self.subject_species,
            self.subject_sex,
            self.subject_age,
        )
        if any(not value.strip() for value in required) or not self.experimenter:
            raise ValueError("NWB session identity fields and experimenter are required")
        if any(not value.strip() for value in self.experimenter):
            raise ValueError("NWB experimenter entries must be nonempty")
        try:
            timestamp = datetime.fromisoformat(self.session_start_time_utc)
        except ValueError as error:
            raise ValueError("session_start_time_utc must be ISO-8601") from error
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("session_start_time_utc must include a UTC offset")

    @property
    def session_start_time(self) -> datetime:
        return datetime.fromisoformat(self.session_start_time_utc)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "session_description": self.session_description,
            "session_start_time_utc": self.session_start_time_utc,
            "experimenter": list(self.experimenter),
            "lab": self.lab,
            "institution": self.institution,
            "subject_id": self.subject_id,
            "subject_species": self.subject_species,
            "subject_sex": self.subject_sex,
            "subject_age": self.subject_age,
            "experiment_description": self.experiment_description,
            "session_id": self.session_id,
            "protocol": self.protocol,
            "notes": self.notes,
            "subject_description": self.subject_description,
            "subject_genotype": self.subject_genotype,
            "subject_strain": self.subject_strain,
            "subject_weight": self.subject_weight,
        }

    @classmethod
    def from_json_dict(cls, data: Mapping[str, Any]) -> "NwbSessionMetadata":
        return cls(
            session_description=str(data["session_description"]),
            session_start_time_utc=str(data["session_start_time_utc"]),
            experimenter=tuple(str(value) for value in data["experimenter"]),
            lab=str(data["lab"]),
            institution=str(data["institution"]),
            subject_id=str(data["subject_id"]),
            subject_species=str(data["subject_species"]),
            subject_sex=str(data["subject_sex"]),
            subject_age=str(data["subject_age"]),
            experiment_description=str(data.get("experiment_description", "")),
            session_id=str(data.get("session_id", "")),
            protocol=str(data.get("protocol", "")),
            notes=str(data.get("notes", "")),
            subject_description=str(data.get("subject_description", "")),
            subject_genotype=str(data.get("subject_genotype", "")),
            subject_strain=str(data.get("subject_strain", "")),
            subject_weight=str(data.get("subject_weight", "")),
        )


@dataclass(frozen=True, slots=True)
class PodNwbPlan:
    canonical_pod_id: bytes
    pod_slot: int
    channel_layout_id: int
    channel_count: int
    sample_rate_numerator_hz: int
    sample_rate_denominator: int
    conversion_volts_per_count: float
    channel_ids: tuple[int, ...]
    channel_labels: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if len(self.canonical_pod_id) != 16 or not any(self.canonical_pod_id):
            raise ValueError("canonical_pod_id must be a nonzero 16-byte ID")
        if self.pod_slot != pod_slot_for(self.canonical_pod_id):
            raise ValueError("pod_slot does not match the canonical Pod ID projection")
        if self.channel_layout_id <= 0:
            raise ValueError("channel_layout_id must be positive")
        if self.channel_count <= 0:
            raise ValueError("channel_count must be positive")
        if self.sample_rate_numerator_hz <= 0 or self.sample_rate_denominator <= 0:
            raise ValueError("sample rate ratio must be positive")
        if self.conversion_volts_per_count <= 0:
            raise ValueError("conversion_volts_per_count must be positive")
        if len(self.channel_ids) != self.channel_count or len(set(self.channel_ids)) != len(
            self.channel_ids
        ):
            raise ValueError("channel_ids must be a unique frozen mapping for every channel")
        if any(channel < 0 for channel in self.channel_ids):
            raise ValueError("channel_ids must be non-negative")
        if self.channel_labels and len(self.channel_labels) != self.channel_count:
            raise ValueError("channel_labels must be empty or match channel_count")

    @property
    def electrical_series_name(self) -> str:
        return f"pod_{self.pod_slot:04x}_{self.canonical_pod_id.hex()[:8]}_raw"

    @property
    def sample_rate_hz(self) -> float:
        return self.sample_rate_numerator_hz / self.sample_rate_denominator

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "canonical_pod_id": self.canonical_pod_id.hex(),
            "pod_slot": self.pod_slot,
            "channel_layout_id": self.channel_layout_id,
            "channel_count": self.channel_count,
            "sample_rate_numerator_hz": self.sample_rate_numerator_hz,
            "sample_rate_denominator": self.sample_rate_denominator,
            "conversion_volts_per_count": self.conversion_volts_per_count,
            "channel_ids": list(self.channel_ids),
            "channel_labels": list(self.channel_labels),
        }


@dataclass(frozen=True, slots=True)
class RunMaterializationManifest:
    run_id: UUID
    generation: int
    protocol_contract_hash: str
    journal_path: Path
    inprogress_path: Path
    final_path: Path
    pods: tuple[PodNwbPlan, ...]
    session_metadata: NwbSessionMetadata | None = None
    dependency_lock: Mapping[str, str] = field(default_factory=dict)
    materializer_build_sha256: str = ""
    manifest_version: int = MANIFEST_VERSION
    created_at_utc: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def __post_init__(self) -> None:
        object.__setattr__(self, "journal_path", Path(self.journal_path).resolve())
        object.__setattr__(self, "inprogress_path", Path(self.inprogress_path).resolve())
        object.__setattr__(self, "final_path", Path(self.final_path).resolve())
        object.__setattr__(self, "pods", tuple(self.pods))
        object.__setattr__(self, "dependency_lock", dict(self.dependency_lock))
        if self.manifest_version != MANIFEST_VERSION:
            raise ValueError("unsupported materialization manifest version")
        if self.generation < 0:
            raise ValueError("generation must be non-negative")
        if len(self.protocol_contract_hash) != 64:
            raise ValueError("protocol_contract_hash must contain 32 bytes as lowercase hex")
        try:
            bytes.fromhex(self.protocol_contract_hash)
        except ValueError as error:
            raise ValueError("protocol_contract_hash is not hexadecimal") from error
        if self.protocol_contract_hash != self.protocol_contract_hash.lower():
            raise ValueError("protocol_contract_hash must be lowercase")
        if self.protocol_contract_hash != protocol.PROTOCOL_HASH_HEX:
            raise ValueError("manifest protocol hash is not Forge host protocol v1")
        if not self.pods:
            raise ValueError("at least one Pod plan is required")
        canonical_ids = [pod.canonical_pod_id for pod in self.pods]
        slots = [pod.pod_slot for pod in self.pods]
        if len(set(canonical_ids)) != len(canonical_ids):
            raise ValueError("exactly one plan is permitted per canonical Pod ID")
        if len(set(slots)) != len(slots):
            raise ValueError("16-bit Pod projection collision in materialization manifest")
        if self.final_path.suffix.casefold() != ".nwb":
            raise ValueError("final_path must end in .nwb")
        expected_inprogress = (
            f"{self.final_path.stem}.g{self.generation:04d}.nwb.inprogress"
        )
        if self.inprogress_path.name != expected_inprogress:
            raise ValueError(
                "inprogress_path must be a generation-specific "
                f"'{expected_inprogress}' artifact"
            )
        if self.inprogress_path.parent != self.final_path.parent:
            raise ValueError("in-progress and final NWB paths must share one directory/volume")
        for module, version in self.dependency_lock.items():
            if module not in REQUIRED_NWB_MODULES or not version or any(
                operator in version for operator in "<>=~!* "
            ):
                raise ValueError("dependency_lock must map required module names to exact versions")
        if self.materializer_build_sha256:
            if (
                len(self.materializer_build_sha256) != 64
                or self.materializer_build_sha256 != self.materializer_build_sha256.lower()
            ):
                raise ValueError("materializer_build_sha256 must be 32-byte lowercase hex")
            try:
                decoded_build_hash = bytes.fromhex(self.materializer_build_sha256)
            except ValueError as error:
                raise ValueError("materializer_build_sha256 is not hexadecimal") from error
            if not any(decoded_build_hash):
                raise ValueError("materializer_build_sha256 must be nonzero")

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "run_id": str(self.run_id),
            "generation": self.generation,
            "protocol_contract_hash": self.protocol_contract_hash,
            "journal_path": str(self.journal_path),
            "inprogress_path": str(self.inprogress_path),
            "final_path": str(self.final_path),
            "pods": [pod.to_json_dict() for pod in self.pods],
            "session_metadata": (
                None
                if self.session_metadata is None
                else self.session_metadata.to_json_dict()
            ),
            "dependency_lock": dict(sorted(self.dependency_lock.items())),
            "materializer_build_sha256": self.materializer_build_sha256,
            "created_at_utc": self.created_at_utc,
        }

    @classmethod
    def from_json_dict(cls, data: Mapping[str, Any]) -> "RunMaterializationManifest":
        return cls(
            manifest_version=int(data["manifest_version"]),
            run_id=UUID(str(data["run_id"])),
            generation=int(data["generation"]),
            protocol_contract_hash=str(data["protocol_contract_hash"]),
            journal_path=Path(str(data["journal_path"])),
            inprogress_path=Path(str(data["inprogress_path"])),
            final_path=Path(str(data["final_path"])),
            pods=tuple(
                PodNwbPlan(
                    canonical_pod_id=bytes.fromhex(str(pod["canonical_pod_id"])),
                    pod_slot=int(pod["pod_slot"]),
                    channel_layout_id=int(pod["channel_layout_id"]),
                    channel_count=int(pod["channel_count"]),
                    sample_rate_numerator_hz=int(pod["sample_rate_numerator_hz"]),
                    sample_rate_denominator=int(pod["sample_rate_denominator"]),
                    conversion_volts_per_count=float(pod["conversion_volts_per_count"]),
                    channel_ids=tuple(int(value) for value in pod["channel_ids"]),
                    channel_labels=tuple(pod.get("channel_labels", ())),
                )
                for pod in data["pods"]
            ),
            session_metadata=(
                None
                if data.get("session_metadata") is None
                else NwbSessionMetadata.from_json_dict(data["session_metadata"])
            ),
            dependency_lock={str(key): str(value) for key, value in data.get("dependency_lock", {}).items()},
            materializer_build_sha256=str(data.get("materializer_build_sha256", "")),
            created_at_utc=str(data["created_at_utc"]),
        )


@dataclass(frozen=True, slots=True)
class ElectricalSeriesPlan:
    canonical_pod_id: str
    pod_slot: int
    channel_layout_id: int
    name: str
    shape: tuple[None, int]
    dtype: str
    unit: str
    conversion_volts_per_count: float
    starting_time_seconds: float
    rate_hz: float


@dataclass(frozen=True, slots=True)
class EventTablePlan:
    name: str
    description: str
    columns: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class MaterializedEvent:
    table_name: str
    values: Mapping[str, int | float | str | bool]

    def __post_init__(self) -> None:
        if not self.table_name.startswith("forge_") or not self.values:
            raise ValueError("invalid materialized event")
        object.__setattr__(self, "values", dict(self.values))


def _event_table_plans() -> tuple[EventTablePlan, ...]:
    common = (("start_time", "float64 seconds"), ("stop_time", "float64 seconds"))
    return (
        EventTablePlan(
            "forge_markers",
            "Operator and external markers tied to sample/global time, not USB arrival time.",
            common
            + (
                ("marker_id", "text"),
                ("canonical_pod_id", "16-byte ID or null"),
                ("pod_slot", "uint16 projection or null"),
                ("sample_index", "uint64 or null"),
                ("global_time", "uint64 or null"),
                ("label", "text"),
                ("note", "text"),
            ),
        ),
        EventTablePlan(
            "forge_faults",
            "Run-latched transport, CRC, overflow, writer, synchronization, and materializer faults.",
            common
            + (
                ("fault_code", "text"),
                ("severity", "text"),
                ("canonical_pod_id", "16-byte ID or null"),
                ("pod_slot", "uint16 projection or null"),
                ("first_sequence", "uint64 or null"),
                ("first_sample", "uint64 or null"),
                ("detail_json", "canonical JSON text"),
            ),
        ),
        EventTablePlan(
            "forge_gaps",
            "Explicit missing or rejected sample/frame intervals.",
            common
            + (
                ("canonical_pod_id", "16-byte ID"),
                ("pod_slot", "uint16 projection"),
                ("sample_start", "uint64"),
                ("sample_end_exclusive", "uint64"),
                ("frame_start", "uint64 or null"),
                ("frame_end_exclusive", "uint64 or null"),
                ("reason", "text"),
            ),
        ),
        EventTablePlan(
            "forge_analysis_results",
            "Versioned downstream worker annotations; reference algorithms remain explicitly unvalidated.",
            common
            + (
                ("worker_id", "text"),
                ("algorithm_id", "text"),
                ("algorithm_version", "text"),
                ("canonical_pod_id", "16-byte ID"),
                ("pod_slot", "uint16 projection"),
                ("channel_id", "uint32 or null"),
                ("sample_index", "uint64"),
                ("kind", "text"),
                ("values_json", "canonical JSON text"),
                ("reference_only", "bool"),
            ),
        ),
        EventTablePlan(
            "forge_stimulation_intents",
            "Worker proposals only; an intent is not a hardware command or proof of execution.",
            common
            + (
                ("intent_nonce", "16-byte ID"),
                ("source_worker_id", "16-byte ID"),
                ("source_record_sequence", "uint64"),
                ("source_sample_counter", "uint64"),
                ("source_global_time_ns", "uint64"),
                ("algorithm_hash", "SHA-256"),
                ("config_hash", "SHA-256"),
                ("template_hash", "SHA-256"),
                ("channel_map_hash", "SHA-256"),
                ("target_channel", "uint16"),
                ("template_id", "uint16"),
                ("deadline_global_time_ns", "uint64"),
            ),
        ),
        EventTablePlan(
            "forge_stimulation_receipts",
            "Receipts returned by an external safety/actuator boundary; absence means no execution claim.",
            common
            + (
                ("intent_nonce", "16-byte ID"),
                ("command_id", "16-byte ID"),
                ("device_id", "16-byte ID"),
                ("result", "StimResult enum"),
                ("actual_start_global_time_ns", "uint64"),
                ("actual_end_global_time_ns", "uint64"),
                ("measured_compliance_uv", "int32"),
                ("peak_current_na", "uint32"),
                ("delivered_phase_charge_pc", "uint64"),
                ("arm_epoch", "uint64"),
            ),
        ),
    )


def _typed_event_table_plans_v1() -> tuple[EventTablePlan, ...]:
    common = (
        ("start_time", "float64 seconds"),
        ("stop_time", "float64 seconds"),
        ("canonical_pod_id", "hex[32]"),
        ("pod_slot", "uint16"),
        ("event_record_sequence", "uint64"),
    )
    return (
        EventTablePlan(
            "forge_markers",
            "Typed MarkerPayloadV1 rows on hardware sample/global time.",
            common
            + (
                ("event_id", "hex[32]"),
                ("marker_sequence", "uint64"),
                ("sample_index", "uint64"),
                ("global_time_ns", "uint64"),
                ("marker_flags", "uint32"),
                ("label", "utf8[256]"),
                ("note", "utf8[2048]"),
            ),
        ),
        EventTablePlan(
            "forge_faults",
            "Typed FaultPayloadV1 rows with independent integrity/disarm flags.",
            common
            + (
                ("event_id", "hex[32]"),
                ("fault_code", "uint16"),
                ("severity", "uint8"),
                ("layer", "uint8"),
                ("fault_flags", "uint32"),
                ("occurrence_count", "uint64"),
                ("detail", "utf8[2048]"),
            ),
        ),
        EventTablePlan(
            "forge_gaps",
            "Typed GapPayloadV1 rows; end fields are exclusive.",
            common
            + (
                ("event_id", "hex[32]"),
                ("gap_reason", "uint16"),
                ("layer", "uint8"),
                ("gap_flags", "uint32"),
                ("missing_record_count", "uint64"),
                ("missing_frame_count", "uint64"),
                ("missing_sample_count", "uint64"),
                ("frame_start", "uint64"),
                ("frame_end_exclusive", "uint64"),
                ("sample_start", "uint64"),
                ("sample_end_exclusive", "uint64"),
            ),
        ),
        EventTablePlan(
            "forge_analysis_results",
            "Typed OnlineAnalysisPayloadV1 UTF-8 results bound to worker/schema hashes.",
            common
            + (
                ("event_id", "hex[32]"),
                ("worker_id", "hex[32]"),
                ("worker_build_hash", "hex[64]"),
                ("algorithm_hash", "hex[64]"),
                ("config_hash", "hex[64]"),
                ("result_schema_hash", "hex[64]"),
                ("source_record_sequence", "uint64"),
                ("channel_id", "uint32"),
                ("analysis_flags", "uint32"),
                ("result_text", "utf8[4096]"),
            ),
        ),
        EventTablePlan(
            "forge_stimulation_intents",
            "Exact StimIntentV1 bodies; proposals are not execution proof.",
            common
            + (
                ("intent_nonce", "hex[32]"),
                ("source_worker_id", "hex[32]"),
                ("control_token_id", "hex[32]"),
                ("source_record_sequence", "uint64"),
                ("source_sample_counter", "uint64"),
                ("source_global_time_ns", "uint64"),
                ("algorithm_hash", "hex[64]"),
                ("config_hash", "hex[64]"),
                ("template_hash", "hex[64]"),
                ("channel_map_hash", "hex[64]"),
                ("target_channel", "uint16"),
                ("template_id", "uint16"),
                ("deadline_global_time_ns", "uint64"),
            ),
        ),
        EventTablePlan(
            "forge_stimulation_receipts",
            "Exact StimReceiptV1 bodies; only executed receipts prove physical execution.",
            common
            + (
                ("intent_nonce", "hex[32]"),
                ("command_id", "hex[32]"),
                ("device_id", "hex[32]"),
                ("result", "uint16"),
                ("fault_code", "uint16"),
                ("target_channel", "uint16"),
                ("template_id", "uint16"),
                ("actual_start_global_time_ns", "uint64"),
                ("actual_end_global_time_ns", "uint64"),
                ("measured_compliance_uv", "int32"),
                ("peak_current_na", "uint32"),
                ("delivered_phase_charge_pc", "uint64"),
                ("arm_epoch", "uint64"),
                ("receipt_nonce", "hex[32]"),
                ("hardware_state_hash", "hex[64]"),
            ),
        ),
    )


@dataclass(frozen=True, slots=True)
class NwbSchemaPlan:
    run_id: UUID
    generation: int
    electrical_series: tuple[ElectricalSeriesPlan, ...]
    event_tables: tuple[EventTablePlan, ...]

    @classmethod
    def from_manifest(cls, manifest: RunMaterializationManifest) -> "NwbSchemaPlan":
        series = tuple(
            ElectricalSeriesPlan(
                canonical_pod_id=pod.canonical_pod_id.hex(),
                pod_slot=pod.pod_slot,
                channel_layout_id=pod.channel_layout_id,
                name=pod.electrical_series_name,
                shape=(None, pod.channel_count),
                dtype="int16",
                unit="volts",
                conversion_volts_per_count=pod.conversion_volts_per_count,
                starting_time_seconds=0.0,
                rate_hz=pod.sample_rate_hz,
            )
            for pod in sorted(manifest.pods, key=lambda item: item.pod_slot)
        )
        if len(series) != len({item.canonical_pod_id for item in series}):
            raise ValueError("schema must contain exactly one ElectricalSeries per Pod")
        return cls(
            manifest.run_id,
            manifest.generation,
            series,
            _typed_event_table_plans_v1(),
        )

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "run_id": str(self.run_id),
            "generation": self.generation,
            "electrical_series": [asdict(item) for item in self.electrical_series],
            "event_tables": [asdict(item) for item in self.event_tables],
        }

    @property
    def sha256(self) -> str:
        encoded = json.dumps(
            self.to_json_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class MaterializationCheckpoint:
    run_id: UUID
    generation: int
    schema_plan_sha256: str
    last_materialized_journal_sequence: int | None
    samples_per_canonical_pod: Mapping[str, int]
    checkpoint_version: int = CHECKPOINT_VERSION

    def __post_init__(self) -> None:
        if self.checkpoint_version != CHECKPOINT_VERSION:
            raise ValueError("unsupported materializer checkpoint version")
        if self.generation < 0:
            raise ValueError("generation must be non-negative")
        if (
            self.last_materialized_journal_sequence is not None
            and self.last_materialized_journal_sequence < 0
        ):
            raise ValueError("last_materialized_journal_sequence must be non-negative")
        if len(self.schema_plan_sha256) != 64:
            raise ValueError("schema_plan_sha256 must be a SHA-256 hex digest")
        object.__setattr__(
            self, "samples_per_canonical_pod", dict(self.samples_per_canonical_pod)
        )
        for pod_id, count in self.samples_per_canonical_pod.items():
            try:
                raw = bytes.fromhex(pod_id)
            except ValueError as error:
                raise ValueError("checkpoint canonical Pod ID is not hex") from error
            if len(raw) != 16 or not any(raw) or count < 0:
                raise ValueError("checkpoint Pod IDs/counts are invalid")

    def assert_matches(
        self, manifest: RunMaterializationManifest, schema: NwbSchemaPlan
    ) -> None:
        if (
            self.run_id != manifest.run_id
            or self.generation != manifest.generation
            or self.schema_plan_sha256 != schema.sha256
        ):
            raise MaterializationIdentityError(
                "checkpoint does not match the manifest Run/generation/schema"
            )

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_version": self.checkpoint_version,
            "run_id": str(self.run_id),
            "generation": self.generation,
            "schema_plan_sha256": self.schema_plan_sha256,
            "last_materialized_journal_sequence": (
                self.last_materialized_journal_sequence
            ),
            "samples_per_canonical_pod": {
                key: value
                for key, value in sorted(self.samples_per_canonical_pod.items())
            },
        }

    @classmethod
    def from_json_dict(cls, data: Mapping[str, Any]) -> "MaterializationCheckpoint":
        return cls(
            checkpoint_version=int(data["checkpoint_version"]),
            run_id=UUID(str(data["run_id"])),
            generation=int(data["generation"]),
            schema_plan_sha256=str(data["schema_plan_sha256"]),
            last_materialized_journal_sequence=(
                None
                if data.get("last_materialized_journal_sequence") is None
                else int(data["last_materialized_journal_sequence"])
            ),
            samples_per_canonical_pod={
                str(key): int(value)
                for key, value in data["samples_per_canonical_pod"].items()
            },
        )


def _atomic_json_write(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def save_manifest(path: str | Path, manifest: RunMaterializationManifest) -> None:
    _atomic_json_write(Path(path), manifest.to_json_dict())


def load_manifest(path: str | Path) -> RunMaterializationManifest:
    with Path(path).open("r", encoding="utf-8") as stream:
        return RunMaterializationManifest.from_json_dict(json.load(stream))


def save_checkpoint(path: str | Path, checkpoint: MaterializationCheckpoint) -> None:
    _atomic_json_write(Path(path), checkpoint.to_json_dict())


def load_checkpoint(path: str | Path) -> MaterializationCheckpoint:
    with Path(path).open("r", encoding="utf-8") as stream:
        return MaterializationCheckpoint.from_json_dict(json.load(stream))


class JournalPayloadDecoder(Protocol):
    @property
    def available(self) -> bool:
        ...

    @property
    def unavailable_reason(self) -> str | None:
        ...

    def decode(
        self, chunk: JournalChunk, manifest: RunMaterializationManifest
    ) -> SampleBlock | MaterializedEvent:
        ...


class CanonicalSampleBlockDecoder:
    """Decode frozen canonical sample and event records, never device USB bytes."""

    available = True
    unavailable_reason = None

    def decode(
        self, chunk: JournalChunk, manifest: RunMaterializationManifest
    ) -> SampleBlock | MaterializedEvent:
        envelope = chunk.canonical.envelope
        plan = next(
            (
                item
                for item in manifest.pods
                if item.canonical_pod_id == envelope.pod_id
            ),
            None,
        )
        if plan is None:
            raise MaterializationIdentityError(
                "canonical Pod ID has no frozen materialization plan"
            )
        if envelope.record_kind != protocol.RecordKind.SAMPLE_BLOCK:
            return self._decode_event(chunk, plan)
        block = SampleBlock.from_journal_chunk(
            chunk,
            generation=manifest.generation,
            channel_ids=plan.channel_ids,
        )
        if (
            block.pod_slot != plan.pod_slot
            or block.channel_layout_id != plan.channel_layout_id
            or block.channel_count != plan.channel_count
            or block.sample_rate_numerator_hz != plan.sample_rate_numerator_hz
            or block.sample_rate_denominator != plan.sample_rate_denominator
        ):
            raise MaterializationIdentityError(
                "canonical SampleBlock does not match frozen Pod/channel/sample-rate plan"
            )
        return block

    @staticmethod
    def _decode_event(chunk: JournalChunk, plan: PodNwbPlan) -> MaterializedEvent:
        envelope = chunk.canonical.envelope
        common: dict[str, int | float | str | bool] = {
            "start_time": envelope.global_time_start_ns / 1_000_000_000,
            "stop_time": envelope.global_time_end_exclusive_ns / 1_000_000_000,
            "canonical_pod_id": envelope.pod_id.hex(),
            "pod_slot": plan.pod_slot,
            "event_record_sequence": envelope.record_sequence,
        }
        table_name: str
        values: dict[str, int | float | str | bool]

        if envelope.record_kind in (
            protocol.RecordKind.MARKER,
            protocol.RecordKind.FAULT,
            protocol.RecordKind.ONLINE_ANALYSIS,
        ):
            try:
                event = protocol.decode_event_payload(chunk.canonical.payload)
            except protocol.EventPayloadError as error:
                raise MaterializationIdentityError(
                    f"typed event payload failed validation: {error.code}"
                ) from error
            if envelope.record_kind == protocol.RecordKind.MARKER:
                if not isinstance(event, protocol.MarkerPayloadV1):
                    raise MaterializationIdentityError(
                        "Marker record contains a different event payload kind"
                    )
                table_name = "forge_markers"
                values = common | {
                    "event_id": event.event_id.hex(),
                    "marker_sequence": event.marker_sequence,
                    "sample_index": envelope.sample_start,
                    "global_time_ns": envelope.global_time_start_ns,
                    "marker_flags": event.marker_flags,
                    "label": event.label,
                    "note": event.note,
                }
            elif envelope.record_kind == protocol.RecordKind.FAULT:
                if isinstance(event, protocol.FaultPayloadV1):
                    table_name = "forge_faults"
                    values = common | {
                        "event_id": event.event_id.hex(),
                        "fault_code": int(event.fault_code),
                        "severity": int(event.severity),
                        "layer": int(event.layer),
                        "fault_flags": event.fault_flags,
                        "occurrence_count": event.occurrence_count,
                        "detail": event.detail,
                    }
                elif isinstance(event, protocol.GapPayloadV1):
                    table_name = "forge_gaps"
                    values = common | {
                        "event_id": event.event_id.hex(),
                        "gap_reason": int(event.reason),
                        "layer": int(event.layer),
                        "gap_flags": event.gap_flags,
                        "missing_record_count": event.missing_record_count,
                        "missing_frame_count": event.missing_frame_count,
                        "missing_sample_count": event.missing_sample_count,
                        "frame_start": envelope.frame_start,
                        "frame_end_exclusive": envelope.frame_end_exclusive,
                        "sample_start": envelope.sample_start,
                        "sample_end_exclusive": envelope.sample_end_exclusive,
                    }
                else:
                    raise MaterializationIdentityError(
                        "Fault record contains a different event payload kind"
                    )
            else:
                if not isinstance(event, protocol.OnlineAnalysisPayloadV1):
                    raise MaterializationIdentityError(
                        "OnlineAnalysis record contains a different event payload kind"
                    )
                table_name = "forge_analysis_results"
                values = common | {
                    "event_id": event.event_id.hex(),
                    "worker_id": event.worker_id.hex(),
                    "worker_build_hash": event.worker_build_hash.hex(),
                    "algorithm_hash": event.algorithm_hash.hex(),
                    "config_hash": event.config_hash.hex(),
                    "result_schema_hash": event.result_schema_hash.hex(),
                    "source_record_sequence": event.source_record_sequence,
                    "channel_id": event.channel_id,
                    "analysis_flags": event.analysis_flags,
                    "result_text": event.result.decode("utf-8", errors="strict"),
                }
        elif envelope.record_kind == protocol.RecordKind.STIM_INTENT:
            try:
                intent = protocol.StimIntentV1.from_bytes(chunk.canonical.payload)
            except protocol.CodecError as error:
                raise MaterializationIdentityError(
                    f"StimIntent payload failed validation: {error.code}"
                ) from error
            table_name = "forge_stimulation_intents"
            values = common | {
                "intent_nonce": intent.intent_nonce.hex(),
                "source_worker_id": intent.source_worker_id.hex(),
                "control_token_id": intent.control_token_id.hex(),
                "source_record_sequence": intent.source_record_sequence,
                "source_sample_counter": intent.source_sample_counter,
                "source_global_time_ns": intent.source_global_time_ns,
                "algorithm_hash": intent.algorithm_hash.hex(),
                "config_hash": intent.config_hash.hex(),
                "template_hash": intent.template_hash.hex(),
                "channel_map_hash": intent.channel_map_hash.hex(),
                "target_channel": intent.target_channel,
                "template_id": intent.template_id,
                "deadline_global_time_ns": intent.deadline_global_time_ns,
            }
        elif envelope.record_kind == protocol.RecordKind.STIM_RECEIPT:
            try:
                receipt = protocol.StimReceiptV1.from_bytes(chunk.canonical.payload)
            except protocol.CodecError as error:
                raise MaterializationIdentityError(
                    f"StimReceipt payload failed validation: {error.code}"
                ) from error
            table_name = "forge_stimulation_receipts"
            values = common | {
                "intent_nonce": receipt.intent_nonce.hex(),
                "command_id": receipt.command_id.hex(),
                "device_id": receipt.device_id.hex(),
                "result": receipt.result,
                "fault_code": receipt.fault_code,
                "target_channel": receipt.target_channel,
                "template_id": receipt.template_id,
                "actual_start_global_time_ns": receipt.actual_start_global_time_ns,
                "actual_end_global_time_ns": receipt.actual_end_global_time_ns,
                "measured_compliance_uv": receipt.measured_compliance_uv,
                "peak_current_na": receipt.peak_current_na,
                "delivered_phase_charge_pc": receipt.delivered_phase_charge_pc,
                "arm_epoch": receipt.arm_epoch,
                "receipt_nonce": receipt.receipt_nonce.hex(),
                "hardware_state_hash": receipt.hardware_state_hash.hex(),
            }
        else:
            raise MaterializationIdentityError(
                f"unsupported canonical record kind {int(envelope.record_kind)}"
            )

        schema = next(
            table for table in _typed_event_table_plans_v1() if table.name == table_name
        )
        expected_columns = {name for name, _ in schema.columns}
        if set(values) != expected_columns:
            raise MaterializationIdentityError(
                f"typed event mapping for {table_name} does not match the frozen schema"
            )
        return MaterializedEvent(table_name, values)


class MaterializationBackend(Protocol):
    """One-writer backend that must create, never reopen, a generation."""

    @property
    def available(self) -> bool:
        ...

    @property
    def unavailable_reason(self) -> str | None:
        ...

    def create_new(
        self,
        manifest: RunMaterializationManifest,
        schema: NwbSchemaPlan,
        checkpoint: MaterializationCheckpoint,
    ) -> None:
        ...

    def append(self, block: SampleBlock) -> None:
        ...

    def append_event(self, event: MaterializedEvent) -> None:
        ...

    def flush(self) -> None:
        ...

    def close(self) -> None:
        ...


class UnavailableNwbBackend:
    available = False
    unavailable_reason = (
        "NWB writer unavailable: no exact PyNWB/h5py/NWB Inspector lock is installed and "
        "no validated backend implementation is present"
    )

    def create_new(
        self,
        manifest: RunMaterializationManifest,
        schema: NwbSchemaPlan,
        checkpoint: MaterializationCheckpoint,
    ) -> None:
        del manifest, schema, checkpoint
        raise NwbUnavailableError(self.unavailable_reason)

    def append(self, block: SampleBlock) -> None:
        del block
        raise NwbUnavailableError(self.unavailable_reason)

    def append_event(self, event: MaterializedEvent) -> None:
        del event
        raise NwbUnavailableError(self.unavailable_reason)

    def flush(self) -> None:
        raise NwbUnavailableError(self.unavailable_reason)

    def close(self) -> None:
        raise NwbUnavailableError(self.unavailable_reason)


@dataclass(frozen=True, slots=True)
class RuntimeProbe:
    python: str
    installed_versions: Mapping[str, str | None]

    @property
    def missing_modules(self) -> tuple[str, ...]:
        return tuple(name for name, version in self.installed_versions.items() if version is None)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "python": self.python,
            "installed_versions": dict(self.installed_versions),
            "missing_modules": list(self.missing_modules),
            "creates_nwb": False,
        }


def probe_runtime() -> RuntimeProbe:
    versions: dict[str, str | None] = {}
    for module in REQUIRED_NWB_MODULES:
        if importlib.util.find_spec(module) is None:
            versions[module] = None
            continue
        try:
            versions[module] = importlib.metadata.version(module)
        except importlib.metadata.PackageNotFoundError:
            versions[module] = "importable-version-unknown"
    return RuntimeProbe(sys.version.split()[0], versions)


@dataclass(frozen=True, slots=True)
class MaterializerPreflight:
    available: bool
    reasons: tuple[str, ...]
    schema_plan_sha256: str
    runtime: RuntimeProbe
    journal_scan: JournalScan | None
    creates_nwb: bool = False

    def to_json_dict(self) -> dict[str, Any]:
        scan = None
        if self.journal_scan is not None:
            scan = {
                "run_id": str(self.journal_scan.identity.run_id),
                "protocol_contract_hash": self.journal_scan.identity.protocol_contract_hash,
                "complete_chunks": self.journal_scan.complete_chunks,
                "last_journal_sequence": self.journal_scan.last_journal_sequence,
                "valid_len": self.journal_scan.valid_len,
                "file_len": self.journal_scan.file_len,
                "torn_tail": self.journal_scan.torn_tail,
                "durable_checkpoint_generation": self.journal_scan.durable.generation,
                "durable_valid_len": self.journal_scan.durable.durable_valid_len,
                "durable_last_journal_sequence": (
                    self.journal_scan.durable.durable_journal_sequence
                ),
                "sealed": self.journal_scan.seal is not None,
            }
        return {
            "available": self.available,
            "creates_nwb": self.creates_nwb,
            "reasons": list(self.reasons),
            "schema_plan_sha256": self.schema_plan_sha256,
            "runtime": self.runtime.to_json_dict(),
            "journal_scan": scan,
        }


def preflight_materializer(
    manifest: RunMaterializationManifest,
    *,
    decoder: JournalPayloadDecoder | None = None,
    backend: MaterializationBackend | None = None,
) -> MaterializerPreflight:
    decoder = CanonicalSampleBlockDecoder() if decoder is None else decoder
    backend = UnavailableNwbBackend() if backend is None else backend
    schema = NwbSchemaPlan.from_manifest(manifest)
    runtime = probe_runtime()
    reasons: list[str] = []
    scan: JournalScan | None = None

    try:
        scan = scan_journal(manifest.journal_path)
        if scan.identity.run_id != manifest.run_id:
            reasons.append("journal Run UUID does not match manifest")
        if scan.identity.protocol_contract_hash != manifest.protocol_contract_hash:
            reasons.append("journal protocol-contract hash does not match manifest")
    except (OSError, JournalFormatError) as error:
        reasons.append(f"journal unavailable or invalid: {error}")

    if manifest.final_path.exists():
        reasons.append("final NWB path already exists; overwrite is forbidden")
    if manifest.inprogress_path.exists():
        reasons.append(
            "generation output already exists; interrupted writers require a new generation"
        )

    if manifest.session_metadata is None:
        reasons.append("required NWB scientific session metadata is absent")
    if not manifest.materializer_build_sha256:
        reasons.append("materializer build SHA-256 is absent")

    if set(manifest.dependency_lock) != set(REQUIRED_NWB_MODULES):
        reasons.append(
            "NWB dependency set is not exactly pinned for h5py, pynwb, and nwbinspector"
        )
    for module in REQUIRED_NWB_MODULES:
        installed = runtime.installed_versions[module]
        expected = manifest.dependency_lock.get(module)
        if installed is None:
            reasons.append(f"required NWB module is not installed: {module}")
        elif expected is not None and installed != expected:
            reasons.append(
                f"installed {module} version {installed} does not match locked version {expected}"
            )

    if not decoder.available:
        reasons.append(decoder.unavailable_reason or "journal payload decoder unavailable")
    if not backend.available:
        reasons.append(backend.unavailable_reason or "NWB backend unavailable")

    available = not reasons
    return MaterializerPreflight(
        available=available,
        reasons=tuple(dict.fromkeys(reasons)),
        schema_plan_sha256=schema.sha256,
        runtime=runtime,
        journal_scan=scan,
        # This foundation never claims an output was created during preflight.
        creates_nwb=False,
    )


class JournalToNwbMaterializer:
    """Bounded pull consumer; it has no acquisition-producer control channel."""

    def __init__(
        self,
        manifest: RunMaterializationManifest,
        checkpoint_path: str | Path,
        decoder: JournalPayloadDecoder,
        backend: MaterializationBackend,
    ) -> None:
        self.manifest = manifest
        self.schema = NwbSchemaPlan.from_manifest(manifest)
        self.checkpoint_path = Path(checkpoint_path)
        self.decoder = decoder
        self.backend = backend
        report = preflight_materializer(manifest, decoder=decoder, backend=backend)
        if not report.available:
            raise NwbUnavailableError("; ".join(report.reasons))

        if self.checkpoint_path.exists():
            raise MaterializationIdentityError(
                "generation checkpoint already exists; never resume an interrupted "
                "NWB artifact in place—increment generation and rebuild from the journal"
            )
        checkpoint = MaterializationCheckpoint(
            run_id=manifest.run_id,
            generation=manifest.generation,
            schema_plan_sha256=self.schema.sha256,
            last_materialized_journal_sequence=None,
            samples_per_canonical_pod={
                pod.canonical_pod_id.hex(): 0 for pod in manifest.pods
            },
        )
        save_checkpoint(self.checkpoint_path, checkpoint)
        self.checkpoint = checkpoint
        self.cursor = JournalCursor(manifest.journal_path)
        backend.create_new(manifest, self.schema, checkpoint)

    def step(
        self,
        *,
        max_chunks: int = 8,
        max_encoded_record_bytes: int = MAX_ENCODED_RECORD_LEN,
    ) -> int:
        """Pull a bounded batch; never waits for or signals the journal producer."""

        polled = self.cursor.poll(
            max_chunks=max_chunks,
            max_encoded_record_bytes=max_encoded_record_bytes,
        )
        if not polled.chunks:
            return 0
        counts = dict(self.checkpoint.samples_per_canonical_pod)
        last_journal_sequence = self.checkpoint.last_materialized_journal_sequence
        for chunk in polled.chunks:
            decoded = self.decoder.decode(chunk, self.manifest)
            if isinstance(decoded, SampleBlock):
                self._validate_block_identity(decoded, chunk)
                self.backend.append(decoded)
                pod_key = decoded.canonical_pod_id.hex()
                counts[pod_key] = counts.get(pod_key, 0) + decoded.sample_count
            else:
                self._validate_event_identity(decoded, chunk)
                self.backend.append_event(decoded)
            last_journal_sequence = chunk.metadata.journal_sequence
        self.backend.flush()
        checkpoint = MaterializationCheckpoint(
            run_id=self.manifest.run_id,
            generation=self.manifest.generation,
            schema_plan_sha256=self.schema.sha256,
            last_materialized_journal_sequence=last_journal_sequence,
            samples_per_canonical_pod=counts,
        )
        save_checkpoint(self.checkpoint_path, checkpoint)
        self.checkpoint = checkpoint
        return len(polled.chunks)

    def _validate_block_identity(self, block: SampleBlock, chunk: JournalChunk) -> None:
        pod_plan = next(
            (
                pod
                for pod in self.manifest.pods
                if pod.canonical_pod_id == block.canonical_pod_id
            ),
            None,
        )
        if (
            block.run_id != self.manifest.run_id
            or block.generation != self.manifest.generation
            or block.pod_slot != chunk.metadata.pod_slot
            or block.journal_sequence != chunk.metadata.journal_sequence
            or block.record_sequence != chunk.metadata.record_sequence
            or pod_plan is None
            or block.channel_layout_id != pod_plan.channel_layout_id
            or block.channel_count != pod_plan.channel_count
            or block.sample_rate_numerator_hz != pod_plan.sample_rate_numerator_hz
            or block.sample_rate_denominator != pod_plan.sample_rate_denominator
        ):
            raise MaterializationIdentityError(
                "decoded SampleBlock does not match Run/generation/chunk/Pod schema"
            )

    def _validate_event_identity(
        self, event: MaterializedEvent, chunk: JournalChunk
    ) -> None:
        schema = next(
            (table for table in self.schema.event_tables if table.name == event.table_name),
            None,
        )
        values = event.values
        if (
            schema is None
            or set(values) != {name for name, _ in schema.columns}
            or values.get("canonical_pod_id") != chunk.canonical.envelope.pod_id.hex()
            or values.get("pod_slot") != chunk.metadata.pod_slot
            or values.get("event_record_sequence")
            != chunk.canonical.envelope.record_sequence
        ):
            raise MaterializationIdentityError(
                "decoded typed event does not match chunk/Pod/frozen NWB schema"
            )

    def finish_generation(self) -> "NwbGenerationCloseReceipt":
        """Close a caught-up sealed generation; validation/publication remain separate."""

        scan = scan_journal(self.manifest.journal_path)
        if scan.seal is None:
            raise MaterializationIdentityError("cannot close NWB generation before journal seal")
        expected_last = scan.seal.expected_last_journal_sequence
        if self.checkpoint.last_materialized_journal_sequence != expected_last:
            raise MaterializationIdentityError(
                "NWB generation is not caught up to the journal seal expected-last"
            )
        self.backend.flush()
        self.backend.close()
        return NwbGenerationCloseReceipt(
            run_id=self.manifest.run_id,
            generation=self.manifest.generation,
            schema_plan_sha256=self.schema.sha256,
            expected_last_journal_sequence=expected_last,
            materialized_last_journal_sequence=(
                self.checkpoint.last_materialized_journal_sequence
            ),
            samples_per_canonical_pod=dict(
                sorted(self.checkpoint.samples_per_canonical_pod.items())
            ),
            inprogress_bytes=self.manifest.inprogress_path.stat().st_size,
            inprogress_sha256=sha256_file(self.manifest.inprogress_path),
            uncompressed=True,
            validation_pending=True,
            publication_authorized=False,
        )


@dataclass(frozen=True, slots=True)
class NwbGenerationCloseReceipt:
    run_id: UUID
    generation: int
    schema_plan_sha256: str
    expected_last_journal_sequence: int | None
    materialized_last_journal_sequence: int | None
    samples_per_canonical_pod: Mapping[str, int]
    inprogress_bytes: int
    inprogress_sha256: str
    uncompressed: bool
    validation_pending: bool
    publication_authorized: bool


@dataclass(frozen=True, slots=True)
class PublicationValidationReceipt:
    """Untrusted validation observations; this is not publication authority."""

    run_id: UUID
    generation: int
    journal_sealed: bool
    schema_validator_name: str
    schema_exit_code: int
    inspector_name: str
    inspector_exit_code: int
    reconciliation_passed: bool
    expected_last_journal_sequence: int | None
    materialized_last_journal_sequence: int | None
    inprogress_sha256: str


def sha256_file(path: str | Path, *, chunk_size: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(chunk_size):
            digest.update(block)
    return digest.hexdigest()


def atomic_publish_validated_nwb(
    manifest: RunMaterializationManifest,
    receipt: PublicationValidationReceipt,
) -> Path:
    """Refuse publication until a trusted daemon-seal verifier is implemented.

    Every field in ``receipt`` is supplied by the caller and therefore cannot
    prove that the daemon's CRC-bound seal, durable checkpoint, journal hash,
    and final expected-last record were independently verified.  Keeping this
    function hard-disabled prevents positive booleans from publishing a file.
    """

    del manifest, receipt
    raise NwbUnavailableError(
        "publication refused: trusted daemon seal/hash-bound publication "
        "verification is not implemented"
    )


def _parse_pod(value: str) -> PodNwbPlan:
    try:
        pod_hex, layout, channels, rate_n, rate_d, conversion, channel_ids = value.split(
            ":", 6
        )
        canonical_pod_id = bytes.fromhex(pod_hex)
        return PodNwbPlan(
            canonical_pod_id=canonical_pod_id,
            pod_slot=pod_slot_for(canonical_pod_id),
            channel_layout_id=int(layout),
            channel_count=int(channels),
            sample_rate_numerator_hz=int(rate_n),
            sample_rate_denominator=int(rate_d),
            conversion_volts_per_count=float(conversion),
            channel_ids=tuple(int(item) for item in channel_ids.split(",")),
        )
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError(
            "Pod must be POD_ID_HEX:LAYOUT_ID:CHANNELS:RATE_NUMERATOR:"
            "RATE_DENOMINATOR:VOLTS_PER_COUNT:CHANNEL_IDS_CSV"
        ) from error


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("probe", help="report NWB runtime availability without writing files")

    schema = subparsers.add_parser("schema", help="print the predeclared schema plan")
    schema.add_argument("--manifest", required=True, type=Path)

    preflight = subparsers.add_parser("preflight", help="fail-closed materializer preflight")
    preflight.add_argument("--manifest", required=True, type=Path)

    create = subparsers.add_parser("create-manifest", help="write a one-Run/generation manifest")
    create.add_argument("--output", required=True, type=Path)
    create.add_argument("--run-id", required=True, type=UUID)
    create.add_argument("--generation", required=True, type=int)
    create.add_argument("--protocol-contract-hash", required=True)
    create.add_argument("--journal", required=True, type=Path)
    create.add_argument("--nwb", required=True, type=Path)
    create.add_argument("--pod", action="append", required=True, type=_parse_pod)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    if arguments.command == "probe":
        print(json.dumps(probe_runtime().to_json_dict(), indent=2, sort_keys=True))
        return 0
    if arguments.command == "create-manifest":
        final = arguments.nwb.resolve()
        manifest = RunMaterializationManifest(
            run_id=arguments.run_id,
            generation=arguments.generation,
            protocol_contract_hash=arguments.protocol_contract_hash,
            journal_path=arguments.journal,
            inprogress_path=final.with_name(
                f"{final.stem}.g{arguments.generation:04d}.nwb.inprogress"
            ),
            final_path=final,
            pods=tuple(arguments.pod),
            # Deliberately empty until exact packages and hashes are frozen.
            dependency_lock={},
        )
        save_manifest(arguments.output, manifest)
        print(json.dumps(manifest.to_json_dict(), indent=2, sort_keys=True))
        return 0

    manifest = load_manifest(arguments.manifest)
    if arguments.command == "schema":
        print(
            json.dumps(
                NwbSchemaPlan.from_manifest(manifest).to_json_dict(),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    report = preflight_materializer(manifest)
    print(json.dumps(report.to_json_dict(), indent=2, sort_keys=True))
    return 0 if report.available else 2


if __name__ == "__main__":
    raise SystemExit(main())
