"""Canonical worker views and bounded-consumer primitives.

``SampleBlock`` is an analysis adapter over the M0 canonical record and
``SampleBlockV1`` payload; it is not another wire contract.  Stimulation
workers may emit only the protocol binding's ``StimIntentV1`` value.  This SDK
has no local authorization, ``StimCommandV1`` construction, register, or
actuator surface.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Generic, Mapping, Protocol, Sequence, TypeVar, runtime_checkable
from uuid import UUID

import numpy as np
from numpy.typing import NDArray

from ._protocol import protocol
from .journal import JournalChunk, pod_slot_for


Int16Array = NDArray[np.int16]
StimIntentV1 = protocol.StimIntentV1


@dataclass(frozen=True, slots=True)
class SampleBlock:
    """Immutable analysis view of one canonical ``SAMPLE_BLOCK`` record."""

    run_id: UUID
    generation: int
    canonical_pod_id: bytes
    headstage_id: bytes
    pod_slot: int
    journal_sequence: int
    record_sequence: int
    frame_start: int
    frame_end_exclusive: int
    sample_start: int
    sample_end_exclusive: int
    global_time_start_ns: int
    global_time_end_exclusive_ns: int
    channel_layout_id: int
    channel_ids: tuple[int, ...]
    sample_rate_numerator_hz: int
    sample_rate_denominator: int
    record_flags: int
    sample_block_flags: int
    samples: Int16Array = field(repr=False)

    def __post_init__(self) -> None:
        if self.generation < 0:
            raise ValueError("generation must be non-negative")
        if len(self.canonical_pod_id) != 16 or not any(self.canonical_pod_id):
            raise ValueError("canonical_pod_id must be a nonzero 16-byte ID")
        if len(self.headstage_id) != 16 or not any(self.headstage_id):
            raise ValueError("headstage_id must be a nonzero 16-byte ID")
        if self.pod_slot != pod_slot_for(self.canonical_pod_id):
            raise ValueError("pod_slot does not match the canonical Pod ID projection")
        if min(self.journal_sequence, self.record_sequence) < 0:
            raise ValueError("journal and record sequences must be non-negative")
        for name, start, end in (
            ("frame", self.frame_start, self.frame_end_exclusive),
            ("sample", self.sample_start, self.sample_end_exclusive),
            ("global-time", self.global_time_start_ns, self.global_time_end_exclusive_ns),
        ):
            if start < 0 or end <= start:
                raise ValueError(f"{name} range must be positive and end-exclusive")
        if self.channel_layout_id <= 0:
            raise ValueError("channel_layout_id must be positive")
        if self.sample_rate_numerator_hz <= 0 or self.sample_rate_denominator <= 0:
            raise ValueError("sample rate ratio must be positive")
        if not self.channel_ids or len(set(self.channel_ids)) != len(self.channel_ids):
            raise ValueError("channel_ids must be nonempty and unique")
        if any(channel < 0 for channel in self.channel_ids):
            raise ValueError("channel_ids must be non-negative")

        array = np.asarray(self.samples)
        if array.dtype != np.dtype("<i2") and array.dtype != np.dtype("=i2"):
            raise TypeError("canonical SampleBlock samples must be signed int16")
        if array.ndim != 2 or array.shape[0] == 0 or array.shape[1] == 0:
            raise ValueError("samples must be a nonempty [sample, channel] array")
        if array.shape[1] != len(self.channel_ids):
            raise ValueError("channel_ids must match the channel dimension")
        if array.shape[0] != self.sample_end_exclusive - self.sample_start:
            raise ValueError("sample array does not match the canonical exclusive sample range")

        immutable = np.array(array, dtype=np.int16, copy=True, order="C")
        immutable.setflags(write=False)
        object.__setattr__(self, "samples", immutable)

    @classmethod
    def from_journal_chunk(
        cls,
        chunk: JournalChunk,
        *,
        generation: int,
        channel_ids: tuple[int, ...],
    ) -> "SampleBlock":
        envelope = chunk.canonical.envelope
        if envelope.record_kind != protocol.RecordKind.SAMPLE_BLOCK:
            raise ValueError("journal record is not a canonical SampleBlock")
        try:
            payload = protocol.SampleBlockV1.from_bytes(chunk.canonical.payload)
        except protocol.CodecError as error:
            raise ValueError(f"invalid SampleBlockV1 payload: {error.code}") from error
        if (
            payload.channel_count != envelope.channel_count
            or payload.sample_format != envelope.sample_format
            or payload.first_sample_counter != envelope.sample_start
            or payload.samples_per_channel
            != envelope.sample_end_exclusive - envelope.sample_start
            or chunk.metadata.record_sequence != envelope.record_sequence
        ):
            raise ValueError("SampleBlockV1 payload does not match canonical envelope")
        samples = np.asarray(payload.samples, dtype=np.int16).reshape(
            payload.samples_per_channel, payload.channel_count
        )
        return cls(
            run_id=UUID(bytes=envelope.run_id),
            generation=generation,
            canonical_pod_id=envelope.pod_id,
            headstage_id=envelope.headstage_id,
            pod_slot=chunk.metadata.pod_slot,
            journal_sequence=chunk.metadata.journal_sequence,
            record_sequence=envelope.record_sequence,
            frame_start=envelope.frame_start,
            frame_end_exclusive=envelope.frame_end_exclusive,
            sample_start=envelope.sample_start,
            sample_end_exclusive=envelope.sample_end_exclusive,
            global_time_start_ns=envelope.global_time_start_ns,
            global_time_end_exclusive_ns=envelope.global_time_end_exclusive_ns,
            channel_layout_id=envelope.channel_layout_id,
            channel_ids=channel_ids,
            sample_rate_numerator_hz=payload.sample_rate_numerator_hz,
            sample_rate_denominator=payload.sample_rate_denominator,
            record_flags=envelope.flags,
            sample_block_flags=payload.flags,
            samples=samples,
        )

    @property
    def sample_count(self) -> int:
        return self.sample_end_exclusive - self.sample_start

    @property
    def channel_count(self) -> int:
        return len(self.channel_ids)

    @property
    def sample_rate_hz(self) -> float:
        return self.sample_rate_numerator_hz / self.sample_rate_denominator


@dataclass(frozen=True, slots=True)
class AnalysisAnnotation:
    """Schema-neutral reference annotation, never a hardware command."""

    worker_id: str
    algorithm_id: str
    algorithm_version: str
    run_id: UUID
    generation: int
    canonical_pod_id: bytes
    pod_slot: int
    sample_index: int
    channel_id: int | None
    kind: str
    values: Mapping[str, str | int | float | bool | None]
    reference_only: bool = True

    def __post_init__(self) -> None:
        if not self.reference_only:
            raise ValueError("foundation algorithms must remain reference_only")
        if self.pod_slot != pod_slot_for(self.canonical_pod_id):
            raise ValueError("annotation Pod identity/projection mismatch")
        forbidden = {
            "register",
            "register_address",
            "device_command",
            "command_bytes",
            "write_register",
        }
        keys = {key.casefold() for key in self.values}
        if keys & forbidden:
            raise ValueError("analysis annotations cannot contain device-command fields")


@runtime_checkable
class AnalysisWorker(Protocol):
    worker_id: str
    algorithm_id: str
    algorithm_version: str

    def process(self, block: SampleBlock) -> Sequence[AnalysisAnnotation]:
        ...


T = TypeVar("T")


class BoundedConsumer(Generic[T]):
    """Finite non-blocking queue for a disposable downstream branch."""

    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._queue: deque[T] = deque()
        self._lock = Lock()
        self._dropped = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    def __len__(self) -> int:
        with self._lock:
            return len(self._queue)

    def offer(self, item: T) -> bool:
        with self._lock:
            if len(self._queue) >= self._capacity:
                self._dropped += 1
                return False
            self._queue.append(item)
            return True

    def poll(self) -> T | None:
        with self._lock:
            if not self._queue:
                return None
            return self._queue.popleft()


@dataclass(frozen=True, slots=True)
class FrozenStimIntentContext:
    """Arm-frozen identities used to construct protocol ``StimIntentV1``."""

    run_id: bytes
    source_worker_id: bytes
    control_token_id: bytes
    algorithm_hash: bytes
    config_hash: bytes
    template_hash: bytes
    channel_map_hash: bytes

    def __post_init__(self) -> None:
        for name, value, size in (
            ("run_id", self.run_id, 16),
            ("source_worker_id", self.source_worker_id, 16),
            ("control_token_id", self.control_token_id, 16),
            ("algorithm_hash", self.algorithm_hash, 32),
            ("config_hash", self.config_hash, 32),
            ("template_hash", self.template_hash, 32),
            ("channel_map_hash", self.channel_map_hash, 32),
        ):
            if len(value) != size or not any(value):
                raise ValueError(f"{name} must be a nonzero {size}-byte value")

    def propose(
        self,
        block: SampleBlock,
        *,
        source_sample_counter: int,
        source_global_time_ns: int,
        target_channel: int,
        template_id: int,
        deadline_global_time_ns: int,
        intent_nonce: bytes,
    ) -> StimIntentV1:
        if block.run_id.bytes != self.run_id:
            raise ValueError("SampleBlock Run does not match frozen intent context")
        if not block.sample_start <= source_sample_counter < block.sample_end_exclusive:
            raise ValueError("intent source sample is outside its canonical SampleBlock")
        if not (
            block.global_time_start_ns
            <= source_global_time_ns
            < block.global_time_end_exclusive_ns
        ):
            raise ValueError("intent source time is outside its canonical SampleBlock")
        intent = protocol.StimIntentV1(
            run_id=self.run_id,
            source_worker_id=self.source_worker_id,
            control_token_id=self.control_token_id,
            source_record_sequence=block.record_sequence,
            source_sample_counter=source_sample_counter,
            source_global_time_ns=source_global_time_ns,
            algorithm_hash=self.algorithm_hash,
            config_hash=self.config_hash,
            template_hash=self.template_hash,
            channel_map_hash=self.channel_map_hash,
            target_channel=target_channel,
            template_id=template_id,
            intent_flags=0,
            deadline_global_time_ns=deadline_global_time_ns,
            intent_nonce=intent_nonce,
        )
        # Force the normative codec to check every range and reserved field.
        intent.to_bytes()
        return intent
