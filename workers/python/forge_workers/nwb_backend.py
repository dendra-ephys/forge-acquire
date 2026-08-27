"""Exact-version PyNWB/HDF5 SWMR backend for Forge journal materialization.

This module is intentionally optional. It creates a new generation-specific
``.nwb.inprogress`` file, prebuilds every group/dataset before enabling SWMR,
and appends uncompressed signed-int16 SampleBlocks plus a numeric block index
and frozen typed-event rows. It never publishes, renames, overwrites, or
reopens an interrupted generation.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import Any

import numpy as np

from ._protocol import protocol
from .materializer import (
    CANONICAL_RAW_SAMPLE_DTYPE,
    canonical_raw_sample_matrix,
    MaterializedEvent,
    MaterializationCheckpoint,
    MaterializationIdentityError,
    NwbSchemaPlan,
    NwbUnavailableError,
    RunMaterializationManifest,
)
from .sdk import SampleBlock


LOCKED_NWB_VERSIONS = {
    "h5py": "3.16.0",
    "pynwb": "4.1.0",
    "nwbinspector": "0.7.2",
}
LOCKED_HDF5_RUNTIME = "2.1.0"

BLOCK_INDEX_COLUMNS = (
    "pod_id_low_u64",
    "pod_id_high_u64",
    "journal_sequence",
    "record_sequence",
    "frame_start",
    "frame_end_exclusive",
    "sample_start",
    "sample_end_exclusive",
    "global_time_start_ns",
    "global_time_end_exclusive_ns",
    "record_flags",
)


class PyNwbSwmrBackend:
    """One-writer uncompressed SWMR backend; no publication authority."""

    def __init__(self, *, target_chunk_bytes: int = 1_048_576) -> None:
        if not 256 * 1024 <= target_chunk_bytes <= 8 * 1024 * 1024:
            raise ValueError("target_chunk_bytes must be within 256 KiB..8 MiB")
        self.target_chunk_bytes = target_chunk_bytes
        self._h5: Any | None = None
        self._manifest: RunMaterializationManifest | None = None
        self._series: dict[bytes, Any] = {}
        self._sample_counts: dict[bytes, int] = {}
        self._block_columns: dict[str, Any] = {}
        self._block_ids: Any | None = None
        self._event_handles: dict[str, tuple[Any, dict[str, Any]]] = {}
        self._event_descriptions: dict[str, dict[str, str]] = {}

    @property
    def available(self) -> bool:
        return self.unavailable_reason is None

    @property
    def unavailable_reason(self) -> str | None:
        mismatches = []
        for package, expected in LOCKED_NWB_VERSIONS.items():
            try:
                installed = importlib.metadata.version(package)
            except importlib.metadata.PackageNotFoundError:
                mismatches.append(f"{package} is not installed")
                continue
            if installed != expected:
                mismatches.append(f"{package}={installed}, expected {expected}")
        if not any(message.startswith("h5py") for message in mismatches):
            import h5py

            if h5py.version.hdf5_version != LOCKED_HDF5_RUNTIME:
                mismatches.append(
                    "HDF5 runtime="
                    f"{h5py.version.hdf5_version}, expected {LOCKED_HDF5_RUNTIME}"
                )
        return None if not mismatches else "NWB runtime mismatch: " + "; ".join(mismatches)

    def create_new(
        self,
        manifest: RunMaterializationManifest,
        schema: NwbSchemaPlan,
        checkpoint: MaterializationCheckpoint,
    ) -> None:
        if self._h5 is not None:
            raise MaterializationIdentityError("NWB backend already owns an open generation")
        if not self.available:
            raise NwbUnavailableError(self.unavailable_reason or "NWB runtime unavailable")
        if dict(manifest.dependency_lock) != LOCKED_NWB_VERSIONS:
            raise NwbUnavailableError("manifest dependency lock is not the Forge NWB v1 lock")
        if manifest.session_metadata is None:
            raise MaterializationIdentityError("NWB session metadata is required before file creation")
        checkpoint.assert_matches(manifest, schema)
        if manifest.inprogress_path.exists() or manifest.final_path.exists():
            raise FileExistsError("NWB generation/final path already exists; overwrite is forbidden")
        manifest.inprogress_path.parent.mkdir(parents=True, exist_ok=True)

        import h5py
        from hdmf.backends.hdf5.h5_utils import H5DataIO
        from hdmf.common import DynamicTable, ElementIdentifiers, VectorData
        from pynwb import NWBHDF5IO, NWBFile
        from pynwb.ecephys import ElectricalSeries
        from pynwb.epoch import TimeIntervals
        from pynwb.file import Subject

        metadata = manifest.session_metadata
        nwb_kwargs: dict[str, Any] = {
            "session_description": metadata.session_description,
            "identifier": str(manifest.run_id),
            "session_start_time": metadata.session_start_time,
            "experimenter": list(metadata.experimenter),
            "lab": metadata.lab,
            "institution": metadata.institution,
            "session_id": metadata.session_id or str(manifest.run_id),
            "keywords": ["electrophysiology", "Forge Acquire", "raw neural data"],
            "data_collection": (
                "Forge CanonicalRecordEnvelopeV1 SampleBlocks; hardware global time and "
                "sequence ranges are retained in forge_block_index."
            ),
            "was_generated_by": [
                ["Forge Acquire journal materializer", "M2 foundation"],
                *(
                    [name, version]
                    for name, version in sorted(LOCKED_NWB_VERSIONS.items())
                ),
                ["HDF5", LOCKED_HDF5_RUNTIME],
            ],
        }
        for name, value in (
            ("experiment_description", metadata.experiment_description),
            ("protocol", metadata.protocol),
            ("notes", metadata.notes),
        ):
            if value:
                nwb_kwargs[name] = value
        nwbfile = NWBFile(**nwb_kwargs)
        subject_kwargs = {
            "subject_id": metadata.subject_id,
            "species": metadata.subject_species,
            "sex": metadata.subject_sex,
            "age": metadata.subject_age,
        }
        for name, value in (
            ("description", metadata.subject_description),
            ("genotype", metadata.subject_genotype),
            ("strain", metadata.subject_strain),
            ("weight", metadata.subject_weight),
        ):
            if value:
                subject_kwargs[name] = value
        nwbfile.subject = Subject(**subject_kwargs)
        nwbfile.add_electrode_column(
            name="forge_channel_id", description="Frozen Forge channel-map identifier"
        )
        nwbfile.add_electrode_column(
            name="forge_pod_id", description="Canonical 16-byte Forge Pod ID as lowercase hex"
        )
        nwbfile.add_electrode_column(
            name="forge_channel_label", description="Frozen optional operator channel label"
        )

        electrode_offset = 0
        for pod in manifest.pods:
            pod_hex = pod.canonical_pod_id.hex()
            device = nwbfile.create_device(
                name=f"forge_pod_{pod_hex}",
                description="Forge Receiver Pod canonical acquisition source",
                serial_number=pod_hex,
            )
            group = nwbfile.create_electrode_group(
                name=f"forge_pod_{pod_hex}_electrodes",
                description="Frozen Forge acquisition channel layout",
                location="unknown; must be supplied by experiment metadata before release",
                device=device,
            )
            for index, channel_id in enumerate(pod.channel_ids):
                label = pod.channel_labels[index] if pod.channel_labels else f"ch{channel_id}"
                nwbfile.add_electrode(
                    group=group,
                    location="unknown; must be supplied by experiment metadata before release",
                    forge_channel_id=channel_id,
                    forge_pod_id=pod_hex,
                    forge_channel_label=label,
                )
            region = nwbfile.create_electrode_table_region(
                region=list(range(electrode_offset, electrode_offset + pod.channel_count)),
                description=f"All frozen channels for Forge Pod {pod_hex}",
            )
            electrode_offset += pod.channel_count
            chunk_rows = max(
                1,
                self.target_chunk_bytes
                // (pod.channel_count * CANONICAL_RAW_SAMPLE_DTYPE.itemsize),
            )
            data = H5DataIO(
                data=None,
                shape=(0, pod.channel_count),
                dtype=CANONICAL_RAW_SAMPLE_DTYPE,
                maxshape=(None, pod.channel_count),
                chunks=(chunk_rows, pod.channel_count),
                compression=None,
            )
            series = ElectricalSeries(
                name=pod.electrical_series_name,
                description=(
                    "Uncompressed raw signed-int16 Forge samples. Multiply by conversion "
                    "to obtain volts. USB arrival time is not represented as sample time."
                ),
                data=data,
                electrodes=region,
                starting_time=0.0,
                rate=pod.sample_rate_hz,
                conversion=pod.conversion_volts_per_count,
                resolution=pod.conversion_volts_per_count,
                filtering="Acquisition-path filtering is device/profile metadata; not inferred here.",
            )
            nwbfile.add_acquisition(series)

        processing = nwbfile.create_processing_module(
            name="forge_provenance",
            description="Forge Run continuity and journal-to-NWB reconciliation records.",
        )
        processing.add(
            DynamicTable(
                name="forge_block_index",
                description=(
                    "One numeric provenance row per canonical SampleBlock. Columns: "
                    + ", ".join(BLOCK_INDEX_COLUMNS)
                ),
                id=ElementIdentifiers(
                    name="id", data=_empty_vector(H5DataIO, np.dtype("<i8"))
                ),
                columns=[
                    VectorData(
                        name=name,
                        description=f"Canonical SampleBlock {name}",
                        data=_empty_vector(H5DataIO, np.dtype("<u8")),
                    )
                    for name in BLOCK_INDEX_COLUMNS
                ],
                colnames=list(BLOCK_INDEX_COLUMNS),
            )
        )

        for table_plan in schema.event_tables:
            columns = [
                VectorData(
                    name=name,
                    description=description,
                    data=_empty_vector(H5DataIO, _event_dtype(name, description)),
                )
                for name, description in table_plan.columns
            ]
            table = TimeIntervals(
                name=table_plan.name,
                description=table_plan.description,
                id=_empty_vector(H5DataIO, np.dtype("<i8")),
                columns=columns,
                colnames=[name for name, _ in table_plan.columns],
            )
            nwbfile.add_time_intervals(table)

        nwbfile.add_scratch(
            np.asarray([manifest.protocol_contract_hash], dtype="S64"),
            name="forge_protocol_contract_sha256",
            description="LF-normalized SHA-256 of the authoritative Forge host protocol IDL.",
        )
        nwbfile.add_scratch(
            np.asarray([schema.sha256], dtype="S64"),
            name="forge_schema_plan_sha256",
            description="SHA-256 of the predeclared Forge NWB schema plan.",
        )
        nwbfile.add_scratch(
            np.asarray([protocol.EVENT_PAYLOAD_HASH_HEX], dtype="S64"),
            name="forge_event_payload_contract_sha256",
            description=(
                "LF-normalized SHA-256 of the frozen Forge typed-event payload extension."
            ),
        )

        h5file = h5py.File(manifest.inprogress_path, "w-", libver="latest")
        try:
            io = NWBHDF5IO(file=h5file, mode="w")
            try:
                io.write(nwbfile)
            finally:
                io.close()
            h5file = h5py.File(manifest.inprogress_path, "r+", libver="latest")
            series_handles: dict[bytes, Any] = {}
            for pod in manifest.pods:
                dataset = h5file[f"acquisition/{pod.electrical_series_name}/data"]
                if (
                    dataset.dtype != CANONICAL_RAW_SAMPLE_DTYPE
                    or dataset.shape != (0, pod.channel_count)
                    or dataset.maxshape != (None, pod.channel_count)
                    or dataset.chunks is None
                    or dataset.compression is not None
                ):
                    raise MaterializationIdentityError(
                        "created ElectricalSeries dataset violates uncompressed append contract"
                    )
                series_handles[pod.canonical_pod_id] = dataset
            block_root = "processing/forge_provenance/forge_block_index"
            block_columns = {
                name: h5file[f"{block_root}/{name}"] for name in BLOCK_INDEX_COLUMNS
            }
            block_ids = h5file[f"{block_root}/id"]
            if block_ids.maxshape != (None,) or block_ids.chunks is None:
                raise MaterializationIdentityError("block-index ids are not appendable")
            for name, dataset in block_columns.items():
                if (
                    dataset.dtype != np.dtype("<u8")
                    or dataset.maxshape != (None,)
                    or dataset.chunks is None
                    or dataset.compression is not None
                ):
                    raise MaterializationIdentityError(
                        f"block-index column {name} violates append contract"
                    )
            _validate_predeclared_tables(h5file, schema)
            event_handles: dict[str, tuple[Any, dict[str, Any]]] = {}
            event_descriptions: dict[str, dict[str, str]] = {}
            for table in schema.event_tables:
                root = f"intervals/{table.name}"
                event_handles[table.name] = (
                    h5file[f"{root}/id"],
                    {name: h5file[f"{root}/{name}"] for name, _ in table.columns},
                )
                event_descriptions[table.name] = dict(table.columns)
            h5file.swmr_mode = True
        except Exception:
            try:
                h5file.close()
            except Exception:
                pass
            raise

        self._h5 = h5file
        self._manifest = manifest
        self._series = series_handles
        self._sample_counts = {pod.canonical_pod_id: 0 for pod in manifest.pods}
        self._block_columns = block_columns
        self._block_ids = block_ids
        self._event_handles = event_handles
        self._event_descriptions = event_descriptions

    def append(self, block: SampleBlock) -> None:
        if self._h5 is None or self._manifest is None:
            raise RuntimeError("NWB generation is not open")
        dataset = self._series.get(block.canonical_pod_id)
        if dataset is None:
            raise MaterializationIdentityError("SampleBlock Pod is absent from NWB schema")
        current = self._sample_counts[block.canonical_pod_id]
        if dataset.shape[0] != current or dataset.shape[1] != block.channel_count:
            raise MaterializationIdentityError("ElectricalSeries shape diverged from backend state")
        samples = canonical_raw_sample_matrix(block.samples)
        next_count = current + block.sample_count
        dataset.resize((next_count, block.channel_count))
        dataset[current:next_count, :] = samples

        assert self._block_ids is not None
        row = self._block_ids.shape[0]
        if any(dataset.shape[0] != row for dataset in self._block_columns.values()):
            raise MaterializationIdentityError("block-index column lengths diverged")
        values = (
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
        self._block_ids.resize((row + 1,))
        self._block_ids[row] = row
        for name, value in zip(BLOCK_INDEX_COLUMNS, values, strict=True):
            dataset = self._block_columns[name]
            dataset.resize((row + 1,))
            dataset[row] = value
        self._sample_counts[block.canonical_pod_id] = next_count

    def append_event(self, event: MaterializedEvent) -> None:
        if self._h5 is None or self._manifest is None:
            raise RuntimeError("NWB generation is not open")
        handles = self._event_handles.get(event.table_name)
        descriptions = self._event_descriptions.get(event.table_name)
        if handles is None or descriptions is None:
            raise MaterializationIdentityError("event table is absent from NWB schema")
        identifiers, columns = handles
        if set(event.values) != set(columns) or set(descriptions) != set(columns):
            raise MaterializationIdentityError(
                "materialized event columns differ from frozen NWB schema"
            )
        row = identifiers.shape[0]
        if any(dataset.shape[0] != row for dataset in columns.values()):
            raise MaterializationIdentityError("event table column lengths diverged")
        encoded = {
            name: _coerce_event_value(event.values[name], dataset.dtype, descriptions[name])
            for name, dataset in columns.items()
        }
        identifiers.resize((row + 1,))
        identifiers[row] = row
        for name, dataset in columns.items():
            dataset.resize((row + 1,))
            dataset[row] = encoded[name]

    def flush(self) -> None:
        if self._h5 is None:
            raise RuntimeError("NWB generation is not open")
        for dataset in self._series.values():
            dataset.flush()
        assert self._block_ids is not None
        self._block_ids.flush()
        for dataset in self._block_columns.values():
            dataset.flush()
        for identifiers, columns in self._event_handles.values():
            identifiers.flush()
            for dataset in columns.values():
                dataset.flush()
        self._h5.flush()

    def close(self) -> None:
        if self._h5 is None:
            return
        self.flush()
        self._h5.close()
        self._h5 = None
        self._series = {}
        self._block_columns = {}
        self._block_ids = None
        self._event_handles = {}
        self._event_descriptions = {}


def _empty_vector(h5_data_io: Any, dtype: np.dtype[Any]) -> Any:
    chunk_rows = max(1, min(1024, (1024 * 1024) // dtype.itemsize))
    return h5_data_io(
        data=None,
        shape=(0,),
        dtype=dtype,
        maxshape=(None,),
        chunks=(chunk_rows,),
        compression=None,
    )


def _event_dtype(name: str, description: str) -> np.dtype[Any]:
    lowered = f"{name} {description}".casefold()
    if name in {"start_time", "stop_time"}:
        return np.dtype("<f8")
    if "int32" in lowered:
        return np.dtype("<i4")
    if "uint8" in lowered or "bool" in lowered:
        return np.dtype("u1")
    if "uint16" in lowered:
        return np.dtype("<u2")
    if "uint32" in lowered:
        return np.dtype("<u4")
    if "uint64" in lowered:
        return np.dtype("<u8")
    if "hex[64]" in lowered:
        return np.dtype("S64")
    if "hex[32]" in lowered:
        return np.dtype("S32")
    if "utf8[4096]" in lowered:
        return np.dtype("S4096")
    if "utf8[2048]" in lowered:
        return np.dtype("S2048")
    if "utf8[256]" in lowered:
        return np.dtype("S256")
    raise MaterializationIdentityError(
        f"unrecognized frozen event dtype for {name}: {description}"
    )


def _coerce_event_value(value: Any, dtype: np.dtype[Any], description: str) -> Any:
    if dtype.kind == "S":
        if not isinstance(value, str):
            raise MaterializationIdentityError("event text/hex value is not a string")
        encoded = value.encode("utf-8", errors="strict")
        if b"\0" in encoded or len(encoded) > dtype.itemsize:
            raise MaterializationIdentityError("event text exceeds its frozen storage bound")
        if description in {"hex[32]", "hex[64]"}:
            if len(value) != int(description[4:-1]) or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise MaterializationIdentityError("event identity/hash is not lowercase hex")
        return encoded
    if isinstance(value, bool):
        value = int(value)
    if not isinstance(value, (int, float)):
        raise MaterializationIdentityError("event numeric value has the wrong type")
    try:
        return np.asarray(value, dtype=dtype).item()
    except (OverflowError, TypeError, ValueError) as error:
        raise MaterializationIdentityError("event numeric value is out of range") from error


def _validate_predeclared_tables(h5file: Any, schema: NwbSchemaPlan) -> None:
    for table in schema.event_tables:
        root = f"intervals/{table.name}"
        for name, _ in table.columns:
            dataset = h5file[f"{root}/{name}"]
            expected_dtype = _event_dtype(name, dict(table.columns)[name])
            if (
                dataset.dtype != expected_dtype
                or dataset.maxshape != (None,)
                or dataset.chunks is None
                or dataset.compression is not None
            ):
                raise MaterializationIdentityError(
                    f"event table {table.name}/{name} is not predeclared appendable data"
                )
        identifiers = h5file[f"{root}/id"]
        if identifiers.maxshape != (None,) or identifiers.chunks is None:
            raise MaterializationIdentityError(
                f"event table {table.name}/id is not predeclared appendable data"
            )
