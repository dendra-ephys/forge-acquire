"""Reference DHL-to-existing-Forge-Host translation boundary."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from .codec import (
    AckPayload,
    AckStatus,
    CtrlFrame,
    CtrlOpcode,
    DescriptorPayload,
    DhlPacket,
    DhlStreamState,
    InventoryPayload,
    ImpedancePayload,
    PacketType,
    ProtocolError,
    decode_ack_payload,
    decode_descriptor_payload,
    decode_inventory_payload,
    decode_impedance_payload,
    decode_neural_payload,
    validate_inventory_against_descriptor,
)


@dataclass(frozen=True, slots=True)
class HostRunContext:
    run_id: bytes
    pod_id: bytes
    channel_layout_id: int
    # SHA-256 of the exact admitted DHL payload bytes.  These are distinct
    # from Descriptor.config_hash and the Inventory authority hashes below.
    expected_descriptor_hash: bytes
    expected_inventory_hash: bytes
    expected_assembly_manifest_hash: bytes
    expected_channel_map_hash: bytes
    expected_inventory_instance_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DescriptorDisposition:
    descriptor: DescriptorPayload


@dataclass(frozen=True, slots=True)
class InventoryDisposition:
    inventory: InventoryPayload
    replayed: bool


@dataclass(frozen=True, slots=True)
class NeuralDisposition:
    canonical_records: tuple[bytes, ...]
    buffered_sample_count: int


@dataclass(frozen=True, slots=True)
class AckDisposition:
    ack: AckPayload
    canonical_records_before_ack: tuple[bytes, ...] = ()


@dataclass(frozen=True, slots=True)
class ImpedanceDisposition:
    result: ImpedancePayload
    scan_complete: bool


BridgeDisposition = (
    DescriptorDisposition | InventoryDisposition | NeuralDisposition | AckDisposition |
    ImpedanceDisposition
)


@dataclass(slots=True)
class _PendingCtrl:
    sequence: int
    opcode: CtrlOpcode
    inventory_replay_seen: bool = False


class DhlToHostBridge:
    """Validate DHL and return one explicit disposition per admitted packet."""

    def __init__(self, context: HostRunContext) -> None:
        if len(context.run_id) != 16 or not any(context.run_id):
            raise ProtocolError("Host run_id must be nonzero 16 bytes")
        if len(context.pod_id) != 16 or not any(context.pod_id):
            raise ProtocolError("Host pod_id must be nonzero 16 bytes")
        if context.channel_layout_id <= 0:
            raise ProtocolError("Host channel_layout_id must be positive")
        if (
            len(context.expected_descriptor_hash) != 32
            or not any(context.expected_descriptor_hash)
            or len(context.expected_inventory_hash) != 32
            or not any(context.expected_inventory_hash)
        ):
            raise ProtocolError(
                "Host exact Descriptor/Inventory payload hashes must be nonzero 32-byte values"
            )
        if (
            len(context.expected_assembly_manifest_hash) != 32
            or not any(context.expected_assembly_manifest_hash)
            or len(context.expected_channel_map_hash) != 32
            or not any(context.expected_channel_map_hash)
        ):
            raise ProtocolError("Host Inventory authority hashes must be nonzero 32-byte values")
        if (
            not context.expected_inventory_instance_ids
            or context.expected_inventory_instance_ids
            != tuple(sorted(set(context.expected_inventory_instance_ids)))
            or any(not 0 <= value <= 0xFFFF for value in context.expected_inventory_instance_ids)
        ):
            raise ProtocolError("Host expected Inventory instance IDs must be sorted and unique")
        self.context = context
        self.stream = DhlStreamState()
        self.descriptor: DescriptorPayload | None = None
        self.inventory: InventoryPayload | None = None
        self._inventory_payload: bytes | None = None
        self._pending_ctrl: _PendingCtrl | None = None
        self._neural_running = False
        self._impedance_scan_sequence: int | None = None
        self._next_impedance_channel = 0
        self._impedance_channel_count: int | None = None
        self._canonical_record_sequence = 0
        self._next_sample_counter: int | None = None
        self._time_anchor_sample_counter: int | None = None
        self._time_anchor_ns: int | None = None
        self._target_samples_per_block: int | None = None
        self._pending_first_sample_counter: int | None = None
        self._pending_samples: list[tuple[int, ...]] = []
        self._poisoned = False

    def reset_lock(self) -> None:
        self.stream.reset_lock()
        self.descriptor = None
        self.inventory = None
        self._inventory_payload = None
        self._pending_ctrl = None
        self._neural_running = False
        self._impedance_scan_sequence = None
        self._next_impedance_channel = 0
        self._impedance_channel_count = None
        self._canonical_record_sequence = 0
        self._next_sample_counter = None
        self._time_anchor_sample_counter = None
        self._time_anchor_ns = None
        self._target_samples_per_block = None
        self._pending_first_sample_counter = None
        self._pending_samples.clear()
        self._poisoned = False

    def expect_ctrl_ack(self, frame: CtrlFrame) -> None:
        """Register the one CTRL frame whose DHL ACK is allowed to arrive."""

        if self._poisoned:
            raise ProtocolError("DHL bridge is poisoned until link relock")
        if self.descriptor is None or self.inventory is None:
            raise ProtocolError("CTRL cannot be pending before Descriptor and Inventory")
        if self._pending_ctrl is not None:
            raise ProtocolError("another CTRL command is already pending")
        if not 0 <= frame.sequence <= 0xFFFFFFFF:
            raise ProtocolError("CTRL sequence does not fit in u32")
        try:
            opcode = CtrlOpcode(frame.opcode)
        except ValueError as exc:
            raise ProtocolError(f"unknown CTRL opcode {frame.opcode}") from exc
        if opcode is CtrlOpcode.QUERY_INVENTORY and len(frame.payload) != 0:
            raise ProtocolError("QUERY_INVENTORY requires a zero-length payload")
        if opcode is CtrlOpcode.ELECTRODE_IMPEDANCE_SCAN and len(frame.payload) != 0:
            raise ProtocolError("ELECTRODE_IMPEDANCE_SCAN requires a zero-length payload")
        if opcode is CtrlOpcode.ELECTRODE_IMPEDANCE_SCAN and self._neural_running:
            raise ProtocolError("impedance scan requires Neural acquisition to be stopped")
        if (
            self._impedance_scan_sequence is not None
            and opcode is CtrlOpcode.NEURAL_START
        ):
            raise ProtocolError("Neural acquisition cannot start during an impedance scan")
        self._pending_ctrl = _PendingCtrl(frame.sequence, opcode)

    def accept(self, packet: DhlPacket) -> BridgeDisposition:
        if self._poisoned:
            raise ProtocolError("DHL bridge is poisoned until link relock")
        try:
            self.stream.admit(packet)
            return self._accept_admitted(packet)
        except ProtocolError:
            # Stream admission advances sequence state before payload and Host
            # mapping validation.  Any later rejection therefore invalidates
            # the whole bridge epoch; callers must explicitly relock rather
            # than attempting to continue from partially consumed state.
            self._poisoned = True
            raise

    def _accept_admitted(self, packet: DhlPacket) -> BridgeDisposition:
        if packet.packet_type is PacketType.DESCRIPTOR:
            if self.descriptor is not None:
                raise ProtocolError("Descriptor repeated without link relock")
            if sha256(packet.payload).digest() != self.context.expected_descriptor_hash:
                raise ProtocolError(
                    "exact Descriptor payload hash does not match the approved Host Run context"
                )
            descriptor = decode_descriptor_payload(packet.payload)
            block_denominator = 1_000 * descriptor.sample_rate_denominator
            target_samples, remainder = divmod(
                descriptor.sample_rate_numerator_hz,
                block_denominator,
            )
            if target_samples == 0 or remainder != 0:
                raise ProtocolError(
                    "Rev A sample rate must produce an integral 1-ms SampleBlock"
                )
            payload_bytes = 32 + 2 * target_samples * descriptor.channel_count
            if payload_bytes > 1_048_576:
                raise ProtocolError("1-ms SampleBlock exceeds the Host payload limit")
            self.descriptor = descriptor
            self._target_samples_per_block = target_samples
            return DescriptorDisposition(descriptor)
        if packet.packet_type is PacketType.INVENTORY:
            if self.descriptor is None:
                raise ProtocolError("Inventory arrived before a valid Descriptor")
            if sha256(packet.payload).digest() != self.context.expected_inventory_hash:
                raise ProtocolError(
                    "exact Inventory payload hash does not match the approved Host Run context"
                )
            inventory = decode_inventory_payload(packet.payload)
            validate_inventory_against_descriptor(inventory, self.descriptor)
            if self.inventory is None:
                if (
                    inventory.assembly_manifest_hash
                    != self.context.expected_assembly_manifest_hash
                    or inventory.channel_map_hash != self.context.expected_channel_map_hash
                ):
                    raise ProtocolError("Inventory hashes do not match the approved Host Run context")
                if tuple(entry.instance_id for entry in inventory.entries) != (
                    self.context.expected_inventory_instance_ids
                ):
                    raise ProtocolError(
                        "Inventory instance IDs do not match the approved Host Run context"
                    )
                self.inventory = inventory
                self._inventory_payload = bytes(packet.payload)
                return InventoryDisposition(inventory, replayed=False)
            pending = self._pending_ctrl
            if pending is None or pending.opcode is not CtrlOpcode.QUERY_INVENTORY:
                raise ProtocolError("unexpected Inventory replay without pending QUERY_INVENTORY")
            if pending.inventory_replay_seen:
                raise ProtocolError("duplicate Inventory replay for one QUERY_INVENTORY")
            if inventory != self.inventory or bytes(packet.payload) != self._inventory_payload:
                raise ProtocolError("Inventory replay differs from the admitted Inventory")
            pending.inventory_replay_seen = True
            return InventoryDisposition(inventory, replayed=True)
        if packet.packet_type is PacketType.ACK:
            ack = decode_ack_payload(packet.payload)
            pending = self._pending_ctrl
            if pending is None:
                raise ProtocolError("ACK arrived without a pending CTRL command")
            if ack.ctrl_sequence != pending.sequence or ack.opcode is not pending.opcode:
                raise ProtocolError("ACK does not match the pending CTRL sequence and opcode")
            if (
                pending.opcode is CtrlOpcode.QUERY_INVENTORY
                and ack.status is AckStatus.OK
                and not pending.inventory_replay_seen
            ):
                raise ProtocolError("QUERY_INVENTORY ACK arrived before its Inventory replay")
            records_before_ack: tuple[bytes, ...] = ()
            if pending.opcode is CtrlOpcode.NEURAL_STOP and ack.status is AckStatus.OK:
                records_before_ack = self._flush_partial_neural()
                self._neural_running = False
            if pending.opcode is CtrlOpcode.NEURAL_START and ack.status is AckStatus.OK:
                self._neural_running = True
            if pending.opcode is CtrlOpcode.ELECTRODE_IMPEDANCE_SCAN:
                if ack.status is AckStatus.OK:
                    if self._impedance_scan_sequence is not None:
                        raise ProtocolError("a second impedance scan was admitted before completion")
                    self._impedance_scan_sequence = pending.sequence
                    self._next_impedance_channel = 0
                    self._impedance_channel_count = None
            self._pending_ctrl = None
            return AckDisposition(ack, records_before_ack)
        if packet.packet_type is PacketType.ELECTRODE_IMPEDANCE:
            if self._impedance_scan_sequence is None:
                raise ProtocolError("impedance result arrived without an admitted scan")
            result = decode_impedance_payload(packet.payload)
            if result.ctrl_sequence != self._impedance_scan_sequence:
                raise ProtocolError("impedance result has the wrong CTRL sequence")
            if self.descriptor is None or result.channel_count != self.descriptor.channel_count:
                raise ProtocolError("impedance channel count differs from Descriptor")
            if self._impedance_channel_count is None:
                self._impedance_channel_count = result.channel_count
            elif result.channel_count != self._impedance_channel_count:
                raise ProtocolError("impedance channel count changed within one scan")
            if result.channel_index != self._next_impedance_channel:
                raise ProtocolError(
                    "impedance channels are missing, duplicated, or out of order"
                )
            self._next_impedance_channel += 1
            complete = self._next_impedance_channel == result.channel_count
            if complete:
                self._impedance_scan_sequence = None
                self._next_impedance_channel = 0
                self._impedance_channel_count = None
            return ImpedanceDisposition(result, complete)
        if packet.packet_type is not PacketType.NEURAL:
            raise ProtocolError(
                f"DHL packet type {packet.packet_type.name} has no frozen Host bridge disposition"
            )
        if self._impedance_scan_sequence is not None:
            raise ProtocolError("Neural data arrived during a pre-recording impedance scan")
        if self.descriptor is None:
            raise ProtocolError("Neural packet arrived before a valid Descriptor")
        if self.inventory is None:
            raise ProtocolError("Neural packet arrived before a valid Inventory")
        if not self._neural_running:
            raise ProtocolError("Neural packet arrived before a successful NEURAL_START ACK")
        first_counter, samples = decode_neural_payload(packet.payload)
        if len(samples[0]) != self.descriptor.channel_count:
            raise ProtocolError("Neural channel count differs from Descriptor")
        if self._next_sample_counter is not None and first_counter != self._next_sample_counter:
            raise ProtocolError(
                f"Neural sample discontinuity: expected {self._next_sample_counter}, got {first_counter}"
            )

        sample_count = len(samples)
        if self._time_anchor_sample_counter is None:
            self._time_anchor_sample_counter = first_counter
            self._time_anchor_ns = packet.timestamp_25mhz * 40
        start_ns = self._sample_time_ns(first_counter)
        source_start_ns = packet.timestamp_25mhz * 40
        if abs(source_start_ns - start_ns) >= 40:
            raise ProtocolError(
                "Neural 25-MHz timestamp disagrees with the Descriptor sample-rate mapping"
            )

        if self._target_samples_per_block is None:
            raise ProtocolError("Neural aggregation has no Descriptor-derived block size")
        if self._pending_first_sample_counter is None:
            self._pending_first_sample_counter = first_counter
        elif first_counter != self._pending_first_sample_counter + len(self._pending_samples):
            raise ProtocolError("Neural aggregation buffer is not sample-contiguous")
        self._pending_samples.extend(tuple(row) for row in samples)
        self._next_sample_counter = first_counter + sample_count

        records: list[bytes] = []
        while len(self._pending_samples) >= self._target_samples_per_block:
            block_rows = self._pending_samples[: self._target_samples_per_block]
            del self._pending_samples[: self._target_samples_per_block]
            block_first = self._pending_first_sample_counter
            if block_first is None:
                raise ProtocolError("Neural aggregation lost its first-sample counter")
            records.append(self._encode_sample_block(block_first, block_rows))
            self._pending_first_sample_counter = block_first + len(block_rows)

        if not self._pending_samples:
            self._pending_first_sample_counter = None
        return NeuralDisposition(tuple(records), len(self._pending_samples))

    def _flush_partial_neural(self) -> tuple[bytes, ...]:
        if not self._pending_samples:
            return ()
        first_counter = self._pending_first_sample_counter
        if first_counter is None:
            raise ProtocolError("Neural partial block has no first-sample counter")
        rows = self._pending_samples
        self._pending_samples = []
        self._pending_first_sample_counter = None
        return (self._encode_sample_block(first_counter, rows),)

    def _encode_sample_block(
        self,
        first_counter: int,
        rows: list[tuple[int, ...]],
    ) -> bytes:
        if self.descriptor is None or not rows:
            raise ProtocolError("cannot encode an empty or unbound Neural SampleBlock")

        # Import lazily so the inner DHL codec stays independent of Host software.
        from forge_protocol_v1 import (  # type: ignore[import-not-found]
            CanonicalRecordEnvelopeV1,
            RecordKind,
            SampleBlockV1,
            encode_record,
        )

        sample_count = len(rows)
        flat_samples = tuple(value for row in rows for value in row)
        block = SampleBlockV1(
            flags=0x3,
            samples_per_channel=sample_count,
            channel_count=self.descriptor.channel_count,
            sample_rate_numerator_hz=self.descriptor.sample_rate_numerator_hz,
            sample_rate_denominator=self.descriptor.sample_rate_denominator,
            first_sample_counter=first_counter,
            samples=flat_samples,
        )
        end_counter = first_counter + sample_count
        envelope = CanonicalRecordEnvelopeV1(
            record_kind=RecordKind.SAMPLE_BLOCK,
            flags=0,
            run_id=self.context.run_id,
            pod_id=self.context.pod_id,
            headstage_id=self.descriptor.device_id,
            record_sequence=self._canonical_record_sequence,
            frame_start=first_counter,
            frame_end_exclusive=end_counter,
            sample_start=first_counter,
            sample_end_exclusive=end_counter,
            global_time_start_ns=self._sample_time_ns(first_counter),
            global_time_end_exclusive_ns=self._sample_time_ns(end_counter),
            channel_layout_id=self.context.channel_layout_id,
            channel_count=self.descriptor.channel_count,
        )
        encoded = encode_record(envelope, block.to_bytes())
        self._canonical_record_sequence += 1
        return encoded

    def _sample_time_ns(self, sample_counter: int) -> int:
        if (
            self.descriptor is None
            or self._time_anchor_sample_counter is None
            or self._time_anchor_ns is None
        ):
            raise ProtocolError("sample-time mapping has no admitted anchor")
        delta = sample_counter - self._time_anchor_sample_counter
        if delta < 0:
            raise ProtocolError("sample counter precedes the admitted time anchor")
        return self._time_anchor_ns + (
            delta
            * 1_000_000_000
            * self.descriptor.sample_rate_denominator
            // self.descriptor.sample_rate_numerator_hz
        )
