from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from forge_dhl_v1 import (
    AckDisposition,
    AckPayload,
    AckStatus,
    CHEM_FLAG_COMPLETE,
    CHEM_FLAG_EPHYS_ARTIFACT_WINDOW_VALID,
    CHEM_FLAG_HARDWARE_TIMESTAMPED,
    BoardProfile,
    ChemMode,
    ChemPayload,
    ComponentCapability,
    ComponentClass,
    ComponentInventoryEntry,
    ComponentModel,
    ComponentStatus,
    CtrlFrame,
    CtrlOpcode,
    DescriptorDisposition,
    DescriptorPayload,
    DhlPacket,
    DhlToHostBridge,
    DhlStreamState,
    ElectrodeConfiguration,
    PacketType,
    ProtocolError,
    HostRunContext,
    InventoryDisposition,
    InventoryPayload,
    IMPEDANCE_FLAGS_ALL,
    ImpedanceDisposition,
    ImpedancePayload,
    NeuralDisposition,
    crc16_ccitt,
    crc32c,
    decode_ack_payload,
    decode_chem_payload,
    decode_ctrl_frame,
    decode_descriptor_payload,
    decode_dhl_packet,
    decode_inventory_payload,
    decode_impedance_payload,
    decode_manchester,
    decode_neural_payload,
    encode_chem_payload,
    encode_ack_payload,
    encode_ctrl_frame,
    encode_descriptor_payload,
    encode_dhl_packet,
    encode_inventory_payload,
    encode_impedance_payload,
    encode_manchester,
    encode_neural_payload,
    validate_inventory_against_descriptor,
)


GOLDEN = Path(__file__).resolve().parents[2] / "golden" / "dhl_v1_vectors.json"
CHANNEL_MAPS = Path(__file__).resolve().parents[2] / "channel_maps_v1.json"
INVENTORY_PROFILES = (
    Path(__file__).resolve().parents[3] / "headstage" / "firmware" / "component_inventory_profiles.json"
)


def host_context(
    *expected_instance_ids: int,
    descriptor_payload: DescriptorPayload | None = None,
    inventory_payload: InventoryPayload | None = None,
) -> HostRunContext:
    if descriptor_payload is None:
        descriptor_payload = decode_descriptor_payload(descriptor().payload)
    if inventory_payload is None:
        inventory_payload = inventory_for_descriptor(descriptor_payload)
    return HostRunContext(
        run_id=bytes.fromhex("44" * 16),
        pod_id=bytes.fromhex("55" * 16),
        channel_layout_id=7,
        expected_descriptor_hash=sha256(
            encode_descriptor_payload(descriptor_payload)
        ).digest(),
        expected_inventory_hash=sha256(
            encode_inventory_payload(inventory_payload)
        ).digest(),
        expected_assembly_manifest_hash=bytes.fromhex("61" * 32),
        expected_channel_map_hash=bytes.fromhex("62" * 32),
        expected_inventory_instance_ids=expected_instance_ids or (0,),
    )


def descriptor() -> DhlPacket:
    return DhlPacket(
        PacketType.DESCRIPTOR,
        0,
        0x11223344,
        0x0102030405060708,
        0,
        25,
        encode_descriptor_payload(
            DescriptorPayload(
                variant=1,
                chip_count=1,
                feature_flags=0,
                channel_count=32,
                sample_rate_numerator_hz=30_000,
                sample_rate_denominator=1,
                device_id=bytes.fromhex("11" * 16),
                config_hash=bytes.fromhex("22" * 32),
                firmware_hash_prefix=bytes.fromhex("33" * 16),
            )
        ),
    )


def bridge_descriptor(payload: DescriptorPayload | None = None) -> DhlPacket:
    if payload is None:
        payload = decode_descriptor_payload(descriptor().payload)
    return DhlPacket(
        PacketType.DESCRIPTOR,
        0,
        9,
        77,
        0,
        0,
        encode_descriptor_payload(payload),
    )


def inventory_for_descriptor(value: DescriptorPayload) -> InventoryPayload:
    profile = {
        (1, 1): BoardProfile.RHD2132_X1,
        (1, 2): BoardProfile.RHD2132_X2,
        (2, 1): BoardProfile.RHD2164_X1,
        (2, 2): BoardProfile.RHD2164_X2,
        (3, 1): BoardProfile.RHS2116_X1,
        (3, 2): BoardProfile.RHS2116_X2,
        (4, 2): BoardProfile.RHD2132_X1_RHS2116_X1,
        (5, 2): BoardProfile.RHD2164_X1_RHS2116_X1,
    }[(value.variant, value.chip_count)]
    models = {
        BoardProfile.RHD2132_X1: (ComponentModel.RHD2132,),
        BoardProfile.RHD2132_X2: (ComponentModel.RHD2132, ComponentModel.RHD2132),
        BoardProfile.RHD2164_X1: (ComponentModel.RHD2164,),
        BoardProfile.RHD2164_X2: (ComponentModel.RHD2164, ComponentModel.RHD2164),
        BoardProfile.RHS2116_X1: (ComponentModel.RHS2116,),
        BoardProfile.RHS2116_X2: (ComponentModel.RHS2116, ComponentModel.RHS2116),
        BoardProfile.RHD2132_X1_RHS2116_X1: (
            ComponentModel.RHD2132, ComponentModel.RHS2116,
        ),
        BoardProfile.RHD2164_X1_RHS2116_X1: (
            ComponentModel.RHD2164, ComponentModel.RHS2116,
        ),
    }[profile]
    channel_count = {
        ComponentModel.RHD2132: 32,
        ComponentModel.RHD2164: 64,
        ComponentModel.RHS2116: 16,
    }
    entries = []
    first_global_channel = 0
    for index, model in enumerate(models):
        count = channel_count[model]
        entries.append(
            ComponentInventoryEntry(
                instance_id=index,
                component_class=ComponentClass.NEURAL_AFE,
                status=ComponentStatus.DETECTED_READY,
                model_id=model,
                first_global_channel=first_global_channel,
                channel_count=count,
                native_channel_base=0,
                driver_abi=1,
                capability_flags=int(
                    ComponentCapability.STREAM_NEURAL
                    | (
                        ComponentCapability.STIMULATION
                        if model is ComponentModel.RHS2116
                        else ComponentCapability.ELECTRODE_IMPEDANCE
                    )
                ),
                component_config_hash_prefix=bytes((0x40 + index,)) * 12,
            )
        )
        first_global_channel += count
    if value.feature_flags & 2:
        entries.append(
            ComponentInventoryEntry(
                100,
                ComponentClass.IMU,
                ComponentStatus.DETECTED_READY,
                ComponentModel.ICM42670P,
                0xFFFF,
                0,
                0,
                1,
                int(ComponentCapability.STREAM_IMU),
                bytes.fromhex("51" * 12),
            )
        )
    if value.feature_flags & 1:
        entries.append(
            ComponentInventoryEntry(
                101,
                ComponentClass.ELECTROCHEM_AFE,
                ComponentStatus.DETECTED_READY,
                ComponentModel.AD5940,
                0xFFFF,
                0,
                0,
                1,
                int(ComponentCapability.AMPEROMETRY | ComponentCapability.FSCV),
                bytes.fromhex("52" * 12),
            )
        )
    return InventoryPayload(
        board_profile_id=profile,
        assembly_manifest_hash=bytes.fromhex("61" * 32),
        channel_map_hash=bytes.fromhex("62" * 32),
        entries=tuple(entries),
    )


def admit_inventory(
    bridge: DhlToHostBridge,
    descriptor_payload: DescriptorPayload,
    *,
    sequence: int,
    boot_id: int = 77,
) -> None:
    disposition = bridge.accept(
        DhlPacket(
            PacketType.INVENTORY,
            0,
            9,
            boot_id,
            sequence,
            0,
            encode_inventory_payload(inventory_for_descriptor(descriptor_payload)),
        )
    )
    assert isinstance(disposition, InventoryDisposition)
    assert not disposition.replayed


def admit_neural_start(
    bridge: DhlToHostBridge,
    *,
    sequence: int,
    ctrl_sequence: int = 0x71000001,
    boot_id: int = 77,
) -> None:
    frame = CtrlFrame(CtrlOpcode.NEURAL_START, 0, ctrl_sequence, b"")
    bridge.expect_ctrl_ack(frame)
    disposition = bridge.accept(
        DhlPacket(
            PacketType.ACK,
            0,
            9,
            boot_id,
            sequence,
            0,
            encode_ack_payload(
                AckPayload(ctrl_sequence, CtrlOpcode.NEURAL_START, AckStatus.OK)
            ),
        )
    )
    assert disposition == AckDisposition(
        AckPayload(ctrl_sequence, CtrlOpcode.NEURAL_START, AckStatus.OK)
    )


def test_standard_crc_check_values() -> None:
    assert crc32c(b"123456789") == 0xE3069283
    assert crc16_ccitt(b"123456789") == 0x29B1


def test_ctrl_opcode_surface_is_high_level_and_stable() -> None:
    assert CtrlOpcode.QUERY_INVENTORY == 0x60
    assert CtrlOpcode.NEURAL_START == 0x71
    assert CtrlOpcode.ELECTRODE_IMPEDANCE_SCAN == 0x73
    assert CtrlOpcode.IMU_START == 0x79
    assert CtrlOpcode.CHEM_CONFIG_FSCV == 0x81


def test_checked_in_channel_maps_are_contiguous_and_complete() -> None:
    contract = json.loads(CHANNEL_MAPS.read_text(encoding="utf-8"))
    expected_totals = {
        "rhd2132x1": 32,
        "rhd2132x2": 64,
        "rhd2164x1": 64,
        "rhd2164x2": 128,
        "rhs2116x1": 16,
        "rhs2116x2": 32,
        "rhd2132x1_rhs2116x1": 48,
        "rhd2164x1_rhs2116x1": 80,
    }
    for name, expected_total in expected_totals.items():
        next_channel = 0
        for instance in contract["profiles"][name]["instances"]:
            assert instance["global_first"] == next_channel
            assert instance["native_first"] == 0
            next_channel += instance["count"]
        assert next_channel == expected_total
    for mapping in contract["physical_connector_maps"].values():
        contacts = mapping["global_channel_to_contact"]
        assert len(contacts) == expected_totals[mapping["profile"]]
        assert len(set(contacts)) == len(contacts)


def test_firmware_inventory_profiles_match_channel_contract() -> None:
    channel_contract = json.loads(CHANNEL_MAPS.read_text(encoding="utf-8"))
    firmware_contract = json.loads(INVENTORY_PROFILES.read_text(encoding="utf-8"))
    for profile in firmware_contract["profiles"]:
        logical = channel_contract["profiles"][profile["name"]]
        assert profile["id"] == logical["board_profile_id"]
        assert [
            (item["instance_id"], item["reference"], item["first_global_channel"], item["channel_count"])
            for item in profile["components"]
        ] == [
            (item["instance_id"], item["reference"], item["global_first"], item["count"])
            for item in logical["instances"]
        ]
    base_instances = {
        profile["id"]: {item["instance_id"] for item in profile["components"]}
        for profile in firmware_contract["profiles"]
    }
    optional_instances = {
        item["instance_id"] for item in firmware_contract["optional_components"]
    }
    for assembly in firmware_contract["assemblies"]:
        expected = set(assembly["expected_instance_ids"])
        assert base_instances[assembly["board_profile_id"]] <= expected
        assert expected <= base_instances[assembly["board_profile_id"]] | optional_instances
        assert assembly["descriptor_feature_flags"] in (0, 1, 2, 3, 4, 5, 6)


def test_dhl_and_ctrl_match_checked_in_goldens() -> None:
    vectors = json.loads(GOLDEN.read_text(encoding="utf-8"))
    dhl_wire = encode_dhl_packet(descriptor())
    ctrl = CtrlFrame(CtrlOpcode.QUERY_INVENTORY, 0, 0x10203040, b"")
    ctrl_wire = encode_ctrl_frame(ctrl)
    assert dhl_wire.hex() == vectors["descriptor_hex"]
    assert ctrl_wire.hex() == vectors["ctrl_hex"]
    assert decode_dhl_packet(dhl_wire) == descriptor()
    assert decode_ctrl_frame(ctrl_wire) == ctrl
    impedance = DhlPacket(
        PacketType.ELECTRODE_IMPEDANCE,
        0,
        0x11223344,
        0x0102030405060708,
        2,
        250,
        encode_impedance_payload(
            ImpedancePayload(
                channel_index=0,
                channel_count=32,
                test_frequency_hz=1_000,
                phase_sample_rate_hz=30_000,
                ctrl_sequence=0x55667788,
                zcheck_scale_code=1,
                dac_amplitude_code=127,
                warmup_cycles=2,
                measurement_cycles=8,
                clip_count=0,
                flags=IMPEDANCE_FLAGS_ALL,
                phase_samples=tuple(1000 + index for index in range(30)),
            )
        ),
    )
    impedance_wire = encode_dhl_packet(impedance)
    assert impedance_wire.hex() == vectors["impedance_hex"]
    assert decode_dhl_packet(impedance_wire) == impedance


def test_impedance_payload_is_frozen_raw_phase_data() -> None:
    value = ImpedancePayload(
        channel_index=7,
        channel_count=32,
        test_frequency_hz=1_000,
        phase_sample_rate_hz=30_000,
        ctrl_sequence=41,
        zcheck_scale_code=1,
        dac_amplitude_code=127,
        warmup_cycles=2,
        measurement_cycles=8,
        clip_count=3,
        flags=IMPEDANCE_FLAGS_ALL,
        phase_samples=tuple(2000 + index for index in range(30)),
    )
    assert decode_impedance_payload(encode_impedance_payload(value)) == value
    with pytest.raises(ProtocolError, match="frozen Rev A baseline"):
        encode_impedance_payload(replace(value, test_frequency_hz=2_000))


def test_neural_payload_is_sample_major_signed_int16() -> None:
    payload = encode_neural_payload([[1, -2, 3], [4, -5, 6]], first_sample_counter=99)
    counter, samples = decode_neural_payload(payload)
    assert counter == 99
    assert samples == [[1, -2, 3], [4, -5, 6]]


def test_fscv_chem_payload_round_trip_and_artifact_window() -> None:
    value = ChemPayload(
        mode=ChemMode.FSCV,
        electrode_configuration=ElectrodeConfiguration.THREE_ELECTRODE,
        flags=(
            CHEM_FLAG_COMPLETE
            | CHEM_FLAG_HARDWARE_TIMESTAMPED
            | CHEM_FLAG_EPHYS_ARTIFACT_WINDOW_VALID
        ),
        acquisition_sequence=19,
        sample_rate_numerator_hz=200_000,
        sample_rate_denominator=1,
        first_sample_counter=1234,
        holding_potential_uv=-400_000,
        switching_potential_uv=1_300_000,
        scan_rate_mv_per_s=400_000,
        repetition_rate_millihz=10_000,
        artifact_start_25mhz=1_000_000,
        artifact_end_25mhz_exclusive=1_287_500,
        config_hash=bytes.fromhex("66" * 32),
        samples=((1,), (-2,), (3,)),
    )
    assert decode_chem_payload(encode_chem_payload(value)) == value


def test_amperometry_has_constant_bias_and_optional_transition_window() -> None:
    value = ChemPayload(
        mode=ChemMode.AMPEROMETRY,
        electrode_configuration=ElectrodeConfiguration.THREE_ELECTRODE,
        flags=CHEM_FLAG_COMPLETE | CHEM_FLAG_HARDWARE_TIMESTAMPED,
        acquisition_sequence=4,
        sample_rate_numerator_hz=1_000,
        sample_rate_denominator=1,
        first_sample_counter=900,
        holding_potential_uv=600_000,
        switching_potential_uv=600_000,
        scan_rate_mv_per_s=0,
        repetition_rate_millihz=0,
        artifact_start_25mhz=0,
        artifact_end_25mhz_exclusive=0,
        config_hash=bytes.fromhex("77" * 32),
        samples=((10,), (11,), (12,)),
    )
    assert decode_chem_payload(encode_chem_payload(value)) == value
    with pytest.raises(ProtocolError, match="amperometry"):
        encode_chem_payload(replace(value, switching_potential_uv=700_000))


def test_fscv_requires_an_explicit_artifact_interval() -> None:
    value = ChemPayload(
        mode=ChemMode.FSCV,
        electrode_configuration=ElectrodeConfiguration.TWO_ELECTRODE,
        flags=CHEM_FLAG_COMPLETE,
        acquisition_sequence=1,
        sample_rate_numerator_hz=100_000,
        sample_rate_denominator=1,
        first_sample_counter=0,
        holding_potential_uv=-400_000,
        switching_potential_uv=1_300_000,
        scan_rate_mv_per_s=400_000,
        repetition_rate_millihz=5_000,
        artifact_start_25mhz=0,
        artifact_end_25mhz_exclusive=0,
        config_hash=bytes.fromhex("88" * 32),
        samples=((0,),),
    )
    with pytest.raises(ProtocolError, match="FSCV"):
        encode_chem_payload(value)


def test_stream_requires_descriptor_then_exact_sequence_and_boot() -> None:
    state = DhlStreamState()
    with pytest.raises(ProtocolError, match="Descriptor"):
        state.admit(DhlPacket(PacketType.STATUS, 0, 1, 7, 0, 0, b""))
    state.admit(DhlPacket(PacketType.DESCRIPTOR, 0, 1, 7, 4, 0, b""))
    with pytest.raises(ProtocolError, match="Inventory"):
        state.admit(DhlPacket(PacketType.STATUS, 0, 1, 7, 5, 1, b""))
    state.admit(DhlPacket(PacketType.INVENTORY, 0, 1, 7, 5, 1, b""))
    state.admit(DhlPacket(PacketType.STATUS, 0, 1, 7, 6, 1, b""))
    with pytest.raises(ProtocolError, match="sequence"):
        state.admit(DhlPacket(PacketType.STATUS, 0, 1, 7, 8, 2, b""))


def test_dhl_header_flags_identity_and_source_are_canonical() -> None:
    canonical = descriptor()
    with pytest.raises(ProtocolError, match="flags"):
        encode_dhl_packet(replace(canonical, flags=1))
    with pytest.raises(ProtocolError, match="source_id"):
        encode_dhl_packet(replace(canonical, source_id=0))
    with pytest.raises(ProtocolError, match="boot_id"):
        encode_dhl_packet(replace(canonical, boot_id=0))

    bad_flags = bytearray(encode_dhl_packet(canonical))
    bad_flags[2] = 1
    bad_flags[-4:] = crc32c(bytes(bad_flags[:-4])).to_bytes(4, "little")
    with pytest.raises(ProtocolError, match="flags"):
        decode_dhl_packet(bytes(bad_flags))

    state = DhlStreamState()
    state.admit(DhlPacket(PacketType.DESCRIPTOR, 0, 1, 7, 0, 0, b""))
    with pytest.raises(ProtocolError, match="source ID"):
        state.admit(DhlPacket(PacketType.INVENTORY, 0, 2, 7, 1, 0, b""))


def test_corruption_and_noncanonical_lengths_fail_closed() -> None:
    wire = bytearray(encode_dhl_packet(descriptor()))
    wire[41] ^= 0x80
    with pytest.raises(ProtocolError, match="CRC32C"):
        decode_dhl_packet(bytes(wire))
    ctrl = bytearray(encode_ctrl_frame(CtrlFrame(1, 0, 0, b"abc")))
    ctrl[-1] ^= 1
    with pytest.raises(ProtocolError, match="CRC16"):
        decode_ctrl_frame(bytes(ctrl))


def test_ack_payload_is_exact_typed_and_canonical() -> None:
    ack = AckPayload(0x12345678, CtrlOpcode.NEURAL_START, AckStatus.OK)
    encoded = encode_ack_payload(ack)
    assert encoded == bytes.fromhex("7856341271000000")
    assert decode_ack_payload(encoded) == ack

    with pytest.raises(ProtocolError, match="length"):
        decode_ack_payload(encoded[:-1])
    with pytest.raises(ProtocolError, match="reserved"):
        decode_ack_payload(bytes.fromhex("7856341271000100"))
    with pytest.raises(ProtocolError, match="unknown"):
        decode_ack_payload(bytes.fromhex("78563412ff000000"))
    with pytest.raises(ProtocolError, match="unknown"):
        decode_ack_payload(bytes.fromhex("7856341271040000"))


def test_manchester_round_trip_and_invalid_pairs() -> None:
    bits = (0, 1, 1, 0, 1, 0)
    assert decode_manchester(encode_manchester(bits)) == bits
    with pytest.raises(ProtocolError, match="invalid Manchester"):
        decode_manchester((0, 0))


def test_neural_packets_aggregate_two_plus_28_rows_into_one_host_record() -> None:
    from forge_protocol_v1 import (
        RecordKind,
        SAMPLE_BLOCK_FLAGS_ALL,
        SampleBlockV1,
        decode_record,
    )

    descriptor_payload = DescriptorPayload(
        variant=1,
        chip_count=1,
        feature_flags=0,
        channel_count=32,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )
    bridge = DhlToHostBridge(host_context())
    descriptor_disposition = bridge.accept(
        DhlPacket(PacketType.DESCRIPTOR, 0, 9, 77, 0, 0, encode_descriptor_payload(descriptor_payload))
    )
    assert descriptor_disposition == DescriptorDisposition(descriptor_payload)
    admit_inventory(bridge, descriptor_payload, sequence=1)
    admit_neural_start(bridge, sequence=2)
    rows = [list(range(32)) for _ in range(30)]
    first = bridge.accept(
        DhlPacket(
            PacketType.NEURAL,
            0,
            9,
            77,
            3,
            2500,
            encode_neural_payload(rows[:2], first_sample_counter=100),
        )
    )
    assert first == NeuralDisposition((), 2)
    second = bridge.accept(
        DhlPacket(
            PacketType.NEURAL,
            0,
            9,
            77,
            4,
            4167,
            encode_neural_payload(rows[2:], first_sample_counter=102),
        )
    )
    assert isinstance(second, NeuralDisposition)
    assert len(second.canonical_records) == 1
    assert second.buffered_sample_count == 0
    decoded = decode_record(second.canonical_records[0])
    assert decoded.envelope.record_kind is RecordKind.SAMPLE_BLOCK
    assert decoded.envelope.global_time_start_ns == 100_000
    assert decoded.envelope.record_sequence == 0
    assert (decoded.envelope.frame_start, decoded.envelope.frame_end_exclusive) == (100, 130)
    assert decoded.envelope.sample_start == 100
    assert decoded.envelope.sample_end_exclusive == 130
    assert decoded.envelope.global_time_end_exclusive_ns == 1_100_000
    block = SampleBlockV1.from_bytes(decoded.payload)
    assert block.samples == tuple(value for row in rows for value in row)
    assert block.samples_per_channel == 30
    assert block.flags == SAMPLE_BLOCK_FLAGS_ALL


def test_descriptor_must_match_an_admitted_skidl_profile() -> None:
    base = DescriptorPayload(
        variant=1,
        chip_count=1,
        feature_flags=0,
        channel_count=32,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )
    assert decode_descriptor_payload(encode_descriptor_payload(base)) == base
    with pytest.raises(ProtocolError, match="active Rev A"):
        encode_descriptor_payload(replace(base, channel_count=31))
    with pytest.raises(ProtocolError, match="active Rev A"):
        encode_descriptor_payload(replace(base, feature_flags=4))

    rhs_x2 = replace(base, variant=3, chip_count=2, feature_flags=4)
    assert decode_descriptor_payload(encode_descriptor_payload(rhs_x2)) == rhs_x2
    rhs_x2_imu = replace(base, variant=3, chip_count=2, feature_flags=6)
    assert decode_descriptor_payload(encode_descriptor_payload(rhs_x2_imu)) == rhs_x2_imu
    with pytest.raises(ProtocolError, match="active Rev A"):
        encode_descriptor_payload(replace(rhs_x2_imu, feature_flags=2))
    with pytest.raises(ProtocolError, match="active Rev A"):
        encode_descriptor_payload(replace(rhs_x2_imu, channel_count=31))
    imu = replace(base, feature_flags=2)
    imu_echem = replace(base, feature_flags=3)
    assert decode_descriptor_payload(encode_descriptor_payload(imu)) == imu
    assert decode_descriptor_payload(encode_descriptor_payload(imu_echem)) == imu_echem


def test_inventory_round_trip_closes_component_and_channel_identity() -> None:
    descriptor_payload = DescriptorPayload(
        variant=1,
        chip_count=1,
        feature_flags=3,
        channel_count=32,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )
    inventory = inventory_for_descriptor(descriptor_payload)
    decoded = decode_inventory_payload(encode_inventory_payload(inventory))
    assert decoded == inventory
    validate_inventory_against_descriptor(decoded, descriptor_payload)
    assert decoded.entries[0].model_id is ComponentModel.RHD2132
    assert (decoded.entries[0].first_global_channel, decoded.entries[0].channel_count) == (0, 32)
    assert decoded.entries[1].model_id is ComponentModel.ICM42670P
    assert decoded.entries[2].model_id is ComponentModel.AD5940


def test_inventory_accepts_explicit_mixed_profile_and_rejects_wrong_model_order() -> None:
    descriptor_payload = DescriptorPayload(
        variant=4,
        chip_count=2,
        feature_flags=4,
        channel_count=48,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )
    inventory = inventory_for_descriptor(descriptor_payload)
    validate_inventory_against_descriptor(inventory, descriptor_payload)
    assert tuple(entry.model_id for entry in inventory.entries) == (
        ComponentModel.RHD2132,
        ComponentModel.RHS2116,
    )
    wrong_order = replace(
        inventory,
        entries=(
            replace(inventory.entries[0], model_id=ComponentModel.RHS2116),
            replace(inventory.entries[1], model_id=ComponentModel.RHD2132),
        ),
    )
    with pytest.raises(ProtocolError, match="model order"):
        validate_inventory_against_descriptor(wrong_order, descriptor_payload)


def test_inventory_rejects_noncontiguous_channel_ranges() -> None:
    descriptor_payload = DescriptorPayload(
        variant=1,
        chip_count=2,
        feature_flags=0,
        channel_count=64,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )
    inventory = inventory_for_descriptor(descriptor_payload)
    shifted_entry = replace(inventory.entries[1], first_global_channel=33)
    shifted = replace(inventory, entries=(inventory.entries[0], shifted_entry))
    with pytest.raises(ProtocolError, match="not contiguous"):
        validate_inventory_against_descriptor(shifted, descriptor_payload)


def test_inventory_detected_optional_features_must_match_descriptor() -> None:
    descriptor_payload = DescriptorPayload(
        variant=1,
        chip_count=1,
        feature_flags=2,
        channel_count=32,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )
    inventory = inventory_for_descriptor(descriptor_payload)
    missing_imu = replace(
        inventory,
        entries=(
            inventory.entries[0],
            replace(inventory.entries[1], status=ComponentStatus.EXPECTED_MISSING),
        ),
    )
    with pytest.raises(ProtocolError, match="detected features"):
        validate_inventory_against_descriptor(missing_imu, descriptor_payload)


def test_bridge_requires_approved_inventory_hashes_and_exact_instance_ids() -> None:
    descriptor_payload = DescriptorPayload(
        variant=1,
        chip_count=1,
        feature_flags=0,
        channel_count=32,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )

    def bridge_for_inventory(expected_inventory: InventoryPayload) -> DhlToHostBridge:
        bridge = DhlToHostBridge(
            host_context(inventory_payload=expected_inventory)
        )
        bridge.accept(
            DhlPacket(
                PacketType.DESCRIPTOR,
                0,
                9,
                77,
                0,
                0,
                encode_descriptor_payload(descriptor_payload),
            )
        )
        return bridge

    inventory = inventory_for_descriptor(descriptor_payload)
    wrong_hash = replace(inventory, assembly_manifest_hash=bytes.fromhex("63" * 32))
    with pytest.raises(ProtocolError, match="approved Host Run context"):
        bridge_for_inventory(wrong_hash).accept(
            DhlPacket(
                PacketType.INVENTORY,
                0,
                9,
                77,
                1,
                0,
                encode_inventory_payload(wrong_hash),
            )
        )

    wrong_instance = replace(
        inventory,
        entries=(replace(inventory.entries[0], instance_id=7),),
    )
    with pytest.raises(ProtocolError, match="instance IDs"):
        bridge_for_inventory(wrong_instance).accept(
            DhlPacket(
                PacketType.INVENTORY,
                0,
                9,
                77,
                1,
                0,
                encode_inventory_payload(wrong_instance),
            )
        )


def test_bridge_binds_exact_startup_payload_hashes() -> None:
    descriptor_payload = decode_descriptor_payload(descriptor().payload)
    inventory_payload = inventory_for_descriptor(descriptor_payload)
    descriptor_bytes = encode_descriptor_payload(descriptor_payload)
    inventory_bytes = encode_inventory_payload(inventory_payload)

    assert sha256(descriptor_bytes).hexdigest() == (
        "9dd32d26249d366d2722a3022f3240094286973f4bad85cedfe3d067b18a8301"
    )
    assert sha256(inventory_bytes).hexdigest() == (
        "bd30a9a3bffab2f15bde701419ffb4aed288aac17541dc3cfc9ed2663ce95108"
    )

    descriptor_mismatch = DhlToHostBridge(
        replace(host_context(), expected_descriptor_hash=bytes.fromhex("63" * 32))
    )
    with pytest.raises(ProtocolError, match="exact Descriptor payload hash"):
        descriptor_mismatch.accept(bridge_descriptor(descriptor_payload))

    inventory_mismatch = DhlToHostBridge(
        replace(host_context(), expected_inventory_hash=bytes.fromhex("64" * 32))
    )
    inventory_mismatch.accept(bridge_descriptor(descriptor_payload))
    with pytest.raises(ProtocolError, match="exact Inventory payload hash"):
        admit_inventory(inventory_mismatch, descriptor_payload, sequence=1)

    with pytest.raises(ProtocolError, match="exact Descriptor/Inventory"):
        DhlToHostBridge(replace(host_context(), expected_descriptor_hash=bytes(32)))


def test_bridge_rejects_data_before_inventory() -> None:
    descriptor_payload = DescriptorPayload(
        variant=1,
        chip_count=1,
        feature_flags=0,
        channel_count=32,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )
    bridge = DhlToHostBridge(host_context(descriptor_payload=descriptor_payload))
    bridge.accept(
        DhlPacket(
            PacketType.DESCRIPTOR,
            0,
            9,
            77,
            0,
            0,
            encode_descriptor_payload(descriptor_payload),
        )
    )
    with pytest.raises(ProtocolError, match="Inventory"):
        bridge.accept(
            DhlPacket(
                PacketType.NEURAL,
                0,
                9,
                77,
                1,
                0,
                encode_neural_payload([[0] * 32], first_sample_counter=0),
            )
        )


def test_bridge_rejects_neural_before_successful_start_ack() -> None:
    descriptor_payload = decode_descriptor_payload(descriptor().payload)
    bridge = DhlToHostBridge(host_context())
    bridge.accept(bridge_descriptor(descriptor_payload))
    admit_inventory(bridge, descriptor_payload, sequence=1)

    with pytest.raises(ProtocolError, match="successful NEURAL_START ACK"):
        bridge.accept(
            DhlPacket(
                PacketType.NEURAL,
                0,
                9,
                77,
                2,
                0,
                encode_neural_payload([[0] * 32], first_sample_counter=0),
            )
        )


def test_bridge_separates_dhl_and_host_sequences_and_uses_one_time_anchor() -> None:
    from forge_protocol_v1 import decode_record

    descriptor_payload = DescriptorPayload(
        variant=1,
        chip_count=1,
        feature_flags=0,
        channel_count=32,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )
    bridge = DhlToHostBridge(host_context())
    assert isinstance(bridge.accept(
        DhlPacket(
            PacketType.DESCRIPTOR,
            0,
            9,
            77,
            10,
            0,
            encode_descriptor_payload(descriptor_payload),
        )
    ), DescriptorDisposition)
    admit_inventory(bridge, descriptor_payload, sequence=11)
    bridge.expect_ctrl_ack(CtrlFrame(CtrlOpcode.GET_STATUS, 0, 500, b""))
    first_ack = bridge.accept(
        DhlPacket(
            PacketType.ACK,
            0,
            9,
            77,
            12,
            1,
            encode_ack_payload(AckPayload(500, CtrlOpcode.GET_STATUS, AckStatus.OK)),
        )
    )
    assert isinstance(first_ack, AckDisposition)
    admit_neural_start(bridge, sequence=13, ctrl_sequence=501)
    rows = [[0] * 32 for _ in range(30)]
    first = bridge.accept(
        DhlPacket(
            PacketType.NEURAL,
            0,
            9,
            77,
            14,
            2_500,
            encode_neural_payload(rows, first_sample_counter=100),
        )
    )
    assert isinstance(first, NeuralDisposition)
    assert len(first.canonical_records) == 1
    assert first.buffered_sample_count == 0
    second = bridge.accept(
        DhlPacket(
            PacketType.NEURAL,
            0,
            9,
            77,
            15,
            27_500,
            encode_neural_payload(rows, first_sample_counter=130),
        )
    )
    assert isinstance(first, NeuralDisposition)
    assert isinstance(second, NeuralDisposition)
    first_record = decode_record(first.canonical_records[0]).envelope
    second_record = decode_record(second.canonical_records[0]).envelope
    assert (first_record.record_sequence, second_record.record_sequence) == (0, 1)
    assert first_record.global_time_end_exclusive_ns == second_record.global_time_start_ns
    assert second_record.global_time_start_ns == 1_100_000


def test_bridge_large_neural_packet_emits_multiple_blocks_and_keeps_remainder() -> None:
    from forge_protocol_v1 import decode_record

    descriptor_payload = replace(
        decode_descriptor_payload(descriptor().payload),
        channel_count=32,
    )
    bridge = DhlToHostBridge(host_context())
    bridge.accept(bridge_descriptor(descriptor_payload))
    admit_inventory(bridge, descriptor_payload, sequence=1)
    admit_neural_start(bridge, sequence=2)
    rows = [[0] * 32 for _ in range(67)]
    disposition = bridge.accept(
        DhlPacket(
            PacketType.NEURAL,
            0,
            9,
            77,
            3,
            2_500,
            encode_neural_payload(rows, first_sample_counter=100),
        )
    )
    assert isinstance(disposition, NeuralDisposition)
    assert len(disposition.canonical_records) == 2
    assert disposition.buffered_sample_count == 7
    envelopes = [decode_record(record).envelope for record in disposition.canonical_records]
    assert [(item.record_sequence, item.sample_start, item.sample_end_exclusive) for item in envelopes] == [
        (0, 100, 130),
        (1, 130, 160),
    ]


def test_bridge_cross_packet_17_plus_20_emits_one_block_and_keeps_seven_pending() -> None:
    from forge_protocol_v1 import decode_record

    descriptor_payload = decode_descriptor_payload(descriptor().payload)
    bridge = DhlToHostBridge(host_context())
    bridge.accept(bridge_descriptor(descriptor_payload))
    admit_inventory(bridge, descriptor_payload, sequence=1)
    admit_neural_start(bridge, sequence=2)
    first = bridge.accept(
        DhlPacket(
            PacketType.NEURAL,
            0,
            9,
            77,
            3,
            2_500,
            encode_neural_payload([[0] * 32 for _ in range(17)], first_sample_counter=100),
        )
    )
    assert first == NeuralDisposition((), 17)
    second = bridge.accept(
        DhlPacket(
            PacketType.NEURAL,
            0,
            9,
            77,
            4,
            16_667,
            encode_neural_payload([[0] * 32 for _ in range(20)], first_sample_counter=117),
        )
    )
    assert isinstance(second, NeuralDisposition)
    assert len(second.canonical_records) == 1
    assert second.buffered_sample_count == 7
    envelope = decode_record(second.canonical_records[0]).envelope
    assert (envelope.record_sequence, envelope.frame_start, envelope.frame_end_exclusive) == (0, 100, 130)
    assert (envelope.sample_start, envelope.sample_end_exclusive) == (100, 130)


def test_bridge_neural_stop_success_flushes_partial_but_other_ack_does_not() -> None:
    from forge_protocol_v1 import (
        SAMPLE_BLOCK_FLAGS_ALL,
        SampleBlockV1,
        decode_record,
    )

    descriptor_payload = decode_descriptor_payload(descriptor().payload)
    bridge = DhlToHostBridge(host_context())
    bridge.accept(bridge_descriptor(descriptor_payload))
    admit_inventory(bridge, descriptor_payload, sequence=1)
    admit_neural_start(bridge, sequence=2)
    bridge.accept(
        DhlPacket(
            PacketType.NEURAL,
            0,
            9,
            77,
            3,
            2_500,
            encode_neural_payload([[0] * 32 for _ in range(17)], first_sample_counter=100),
        )
    )
    bridge.expect_ctrl_ack(CtrlFrame(CtrlOpcode.GET_STATUS, 0, 501, b""))
    status_ack = bridge.accept(
        DhlPacket(
            PacketType.ACK,
            0,
            9,
            77,
            4,
            0,
            encode_ack_payload(AckPayload(501, CtrlOpcode.GET_STATUS, AckStatus.OK)),
        )
    )
    assert status_ack == AckDisposition(AckPayload(501, CtrlOpcode.GET_STATUS, AckStatus.OK))

    bridge.expect_ctrl_ack(CtrlFrame(CtrlOpcode.NEURAL_STOP, 0, 502, b""))
    stop_ack = bridge.accept(
        DhlPacket(
            PacketType.ACK,
            0,
            9,
            77,
            5,
            0,
            encode_ack_payload(AckPayload(502, CtrlOpcode.NEURAL_STOP, AckStatus.OK)),
        )
    )
    assert isinstance(stop_ack, AckDisposition)
    assert len(stop_ack.canonical_records_before_ack) == 1
    record = decode_record(stop_ack.canonical_records_before_ack[0])
    assert (record.envelope.record_sequence, record.envelope.sample_start, record.envelope.sample_end_exclusive) == (
        0,
        100,
        117,
    )
    block = SampleBlockV1.from_bytes(record.payload)
    assert block.samples_per_channel == 17
    assert block.flags == SAMPLE_BLOCK_FLAGS_ALL
    with pytest.raises(ProtocolError, match="successful NEURAL_START ACK"):
        bridge.accept(
            DhlPacket(
                PacketType.NEURAL,
                0,
                9,
                77,
                6,
                16_667,
                encode_neural_payload([[0] * 32], first_sample_counter=117),
            )
        )


def test_bridge_neural_stop_failure_does_not_flush_partial() -> None:
    from forge_protocol_v1 import SampleBlockV1, decode_record

    descriptor_payload = decode_descriptor_payload(descriptor().payload)
    bridge = DhlToHostBridge(host_context())
    bridge.accept(bridge_descriptor(descriptor_payload))
    admit_inventory(bridge, descriptor_payload, sequence=1)
    admit_neural_start(bridge, sequence=2)
    bridge.accept(
        DhlPacket(
            PacketType.NEURAL,
            0,
            9,
            77,
            3,
            2_500,
            encode_neural_payload([[0] * 32 for _ in range(17)], first_sample_counter=100),
        )
    )
    bridge.expect_ctrl_ack(CtrlFrame(CtrlOpcode.NEURAL_STOP, 0, 601, b""))
    failed = bridge.accept(
        DhlPacket(
            PacketType.ACK,
            0,
            9,
            77,
            4,
            0,
            encode_ack_payload(AckPayload(601, CtrlOpcode.NEURAL_STOP, AckStatus.NOT_READY)),
        )
    )
    assert failed == AckDisposition(AckPayload(601, CtrlOpcode.NEURAL_STOP, AckStatus.NOT_READY))
    bridge.expect_ctrl_ack(CtrlFrame(CtrlOpcode.NEURAL_STOP, 0, 602, b""))
    succeeded = bridge.accept(
        DhlPacket(
            PacketType.ACK,
            0,
            9,
            77,
            5,
            0,
            encode_ack_payload(AckPayload(602, CtrlOpcode.NEURAL_STOP, AckStatus.OK)),
        )
    )
    assert isinstance(succeeded, AckDisposition)
    assert len(succeeded.canonical_records_before_ack) == 1
    block = SampleBlockV1.from_bytes(decode_record(succeeded.canonical_records_before_ack[0]).payload)
    assert block.samples_per_channel == 17


def test_bridge_rejects_nonintegral_one_ms_descriptor_rate() -> None:
    payload = replace(decode_descriptor_payload(descriptor().payload), sample_rate_numerator_hz=25_001)
    bridge = DhlToHostBridge(host_context(descriptor_payload=payload))
    with pytest.raises(ProtocolError, match="integral 1-ms"):
        bridge.accept(
            DhlPacket(
                PacketType.DESCRIPTOR,
                0,
                9,
                77,
                0,
                0,
                encode_descriptor_payload(payload),
            )
        )


def test_bridge_query_inventory_requires_exact_replay_then_matching_ack() -> None:
    descriptor_payload = DescriptorPayload(
        variant=1,
        chip_count=1,
        feature_flags=0,
        channel_count=32,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )
    inventory_payload = encode_inventory_payload(inventory_for_descriptor(descriptor_payload))
    bridge = DhlToHostBridge(host_context())
    bridge.accept(
        DhlPacket(
            PacketType.DESCRIPTOR,
            0,
            9,
            77,
            0,
            0,
            encode_descriptor_payload(descriptor_payload),
        )
    )
    admit_inventory(bridge, descriptor_payload, sequence=1)

    query = CtrlFrame(CtrlOpcode.QUERY_INVENTORY, 0, 0x10203040, b"")
    bridge.expect_ctrl_ack(query)
    with pytest.raises(ProtocolError, match="already pending"):
        bridge.expect_ctrl_ack(CtrlFrame(CtrlOpcode.GET_STATUS, 0, 2, b""))
    replay = bridge.accept(
        DhlPacket(PacketType.INVENTORY, 0, 9, 77, 2, 100, inventory_payload)
    )
    assert replay == InventoryDisposition(inventory_for_descriptor(descriptor_payload), True)
    ack = bridge.accept(
        DhlPacket(
            PacketType.ACK,
            0,
            9,
            77,
            3,
            101,
            encode_ack_payload(
                AckPayload(0x10203040, CtrlOpcode.QUERY_INVENTORY, AckStatus.OK)
            ),
        )
    )
    assert ack == AckDisposition(
        AckPayload(0x10203040, CtrlOpcode.QUERY_INVENTORY, AckStatus.OK)
    )


def test_bridge_query_inventory_failure_ack_does_not_require_a_replay() -> None:
    descriptor_payload = DescriptorPayload(
        variant=1,
        chip_count=1,
        feature_flags=0,
        channel_count=32,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )
    bridge = DhlToHostBridge(host_context())
    bridge.accept(
        DhlPacket(
            PacketType.DESCRIPTOR,
            0,
            9,
            77,
            0,
            0,
            encode_descriptor_payload(descriptor_payload),
        )
    )
    admit_inventory(bridge, descriptor_payload, sequence=1)
    bridge.expect_ctrl_ack(CtrlFrame(CtrlOpcode.QUERY_INVENTORY, 0, 41, b""))
    ack = AckPayload(41, CtrlOpcode.QUERY_INVENTORY, AckStatus.NOT_READY)
    assert bridge.accept(
        DhlPacket(
            PacketType.ACK,
            0,
            9,
            77,
            2,
            0,
            encode_ack_payload(ack),
        )
    ) == AckDisposition(ack)
    bridge.expect_ctrl_ack(CtrlFrame(CtrlOpcode.GET_STATUS, 0, 42, b""))


def test_bridge_rejects_unmatched_ack_changed_replay_and_unmapped_packets() -> None:
    descriptor_payload = DescriptorPayload(
        variant=1,
        chip_count=1,
        feature_flags=0,
        channel_count=32,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )

    def primed() -> DhlToHostBridge:
        bridge = DhlToHostBridge(host_context())
        bridge.accept(
            DhlPacket(
                PacketType.DESCRIPTOR,
                0,
                9,
                77,
                0,
                0,
                encode_descriptor_payload(descriptor_payload),
            )
        )
        admit_inventory(bridge, descriptor_payload, sequence=1)
        return bridge

    ack_payload = encode_ack_payload(
        AckPayload(10, CtrlOpcode.QUERY_INVENTORY, AckStatus.OK)
    )
    with pytest.raises(ProtocolError, match="without a pending"):
        primed().accept(DhlPacket(PacketType.ACK, 0, 9, 77, 2, 0, ack_payload))

    before_replay = primed()
    before_replay.expect_ctrl_ack(CtrlFrame(CtrlOpcode.QUERY_INVENTORY, 0, 10, b""))
    with pytest.raises(ProtocolError, match="before its Inventory replay"):
        before_replay.accept(DhlPacket(PacketType.ACK, 0, 9, 77, 2, 0, ack_payload))

    mismatch = primed()
    mismatch.expect_ctrl_ack(CtrlFrame(CtrlOpcode.GET_STATUS, 0, 11, b""))
    with pytest.raises(ProtocolError, match="does not match"):
        mismatch.accept(
            DhlPacket(
                PacketType.ACK,
                0,
                9,
                77,
                2,
                0,
                encode_ack_payload(
                    AckPayload(12, CtrlOpcode.GET_STATUS, AckStatus.OK)
                ),
            )
        )

    changed = primed()
    changed.expect_ctrl_ack(CtrlFrame(CtrlOpcode.QUERY_INVENTORY, 0, 13, b""))
    altered = replace(
        inventory_for_descriptor(descriptor_payload),
        assembly_manifest_hash=bytes.fromhex("63" * 32),
    )
    with pytest.raises(ProtocolError, match="exact Inventory payload hash"):
        changed.accept(
            DhlPacket(
                PacketType.INVENTORY,
                0,
                9,
                77,
                2,
                0,
                encode_inventory_payload(altered),
            )
        )

    with pytest.raises(ProtocolError, match="no frozen Host bridge disposition"):
        primed().accept(DhlPacket(PacketType.STATUS, 0, 9, 77, 2, 0, b""))
    with pytest.raises(ProtocolError, match="zero-length"):
        primed().expect_ctrl_ack(
            CtrlFrame(CtrlOpcode.QUERY_INVENTORY, 0, 14, b"not-empty")
        )


def test_bridge_requires_explicit_relock_after_an_admitted_packet_is_rejected() -> None:
    descriptor_payload = DescriptorPayload(
        variant=1,
        chip_count=1,
        feature_flags=0,
        channel_count=32,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )
    bridge = DhlToHostBridge(host_context())
    descriptor_packet = DhlPacket(
        PacketType.DESCRIPTOR,
        0,
        9,
        77,
        0,
        0,
        encode_descriptor_payload(descriptor_payload),
    )
    bridge.accept(descriptor_packet)
    admit_inventory(bridge, descriptor_payload, sequence=1)

    with pytest.raises(ProtocolError, match="no frozen Host bridge disposition"):
        bridge.accept(DhlPacket(PacketType.STATUS, 0, 9, 77, 2, 0, b""))
    with pytest.raises(ProtocolError, match="poisoned until link relock"):
        bridge.accept(
            DhlPacket(
                PacketType.NEURAL,
                0,
                9,
                77,
                3,
                0,
                encode_neural_payload([[0] * 32], first_sample_counter=0),
            )
        )
    with pytest.raises(ProtocolError, match="poisoned until link relock"):
        bridge.expect_ctrl_ack(CtrlFrame(CtrlOpcode.GET_STATUS, 0, 1, b""))

    bridge.reset_lock()
    assert bridge.accept(descriptor_packet) == DescriptorDisposition(descriptor_payload)
    admit_inventory(bridge, descriptor_payload, sequence=1)
    assert bridge.inventory == inventory_for_descriptor(descriptor_payload)


def test_bridge_rejects_sample_or_25mhz_time_discontinuity() -> None:
    payload = DescriptorPayload(
        variant=3,
        chip_count=1,
        feature_flags=4,
        channel_count=16,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        device_id=bytes.fromhex("11" * 16),
        config_hash=bytes.fromhex("22" * 32),
        firmware_hash_prefix=bytes.fromhex("33" * 16),
    )

    def primed() -> DhlToHostBridge:
        bridge = DhlToHostBridge(host_context(descriptor_payload=payload))
        bridge.accept(DhlPacket(PacketType.DESCRIPTOR, 0, 9, 77, 0, 0, encode_descriptor_payload(payload)))
        admit_inventory(bridge, payload, sequence=1)
        admit_neural_start(bridge, sequence=2)
        bridge.accept(
            DhlPacket(
                PacketType.NEURAL,
                0,
                9,
                77,
                3,
                2_500,
                encode_neural_payload([[0] * 16], first_sample_counter=100),
            )
        )
        return bridge

    with pytest.raises(ProtocolError, match="sample discontinuity"):
        primed().accept(
            DhlPacket(
                PacketType.NEURAL,
                0,
                9,
                77,
                4,
                3_333,
                encode_neural_payload([[0] * 16], first_sample_counter=102),
            )
        )
    with pytest.raises(ProtocolError, match="25-MHz timestamp"):
        primed().accept(
            DhlPacket(
                PacketType.NEURAL,
                0,
                9,
                77,
                4,
                9_999,
                encode_neural_payload([[0] * 16], first_sample_counter=101),
            )
        )


def test_impedance_scan_is_ordered_pre_recording_and_blocks_neural_start() -> None:
    descriptor_payload = decode_descriptor_payload(descriptor().payload)
    bridge = DhlToHostBridge(host_context())
    bridge.accept(bridge_descriptor(descriptor_payload))
    admit_inventory(bridge, descriptor_payload, sequence=1)

    scan = CtrlFrame(CtrlOpcode.ELECTRODE_IMPEDANCE_SCAN, 0, 0x55667788, b"")
    bridge.expect_ctrl_ack(scan)
    ack = bridge.accept(
        DhlPacket(
            PacketType.ACK,
            0,
            9,
            77,
            2,
            10,
            encode_ack_payload(
                AckPayload(scan.sequence, CtrlOpcode.ELECTRODE_IMPEDANCE_SCAN, AckStatus.OK)
            ),
        )
    )
    assert isinstance(ack, AckDisposition)

    with pytest.raises(ProtocolError, match="during an impedance scan"):
        bridge.expect_ctrl_ack(CtrlFrame(CtrlOpcode.NEURAL_START, 0, 100, b""))

    for channel in range(32):
        value = ImpedancePayload(
            channel_index=channel,
            channel_count=32,
            test_frequency_hz=1_000,
            phase_sample_rate_hz=30_000,
            ctrl_sequence=scan.sequence,
            zcheck_scale_code=1,
            dac_amplitude_code=127,
            warmup_cycles=2,
            measurement_cycles=8,
            clip_count=0,
            flags=IMPEDANCE_FLAGS_ALL,
            phase_samples=tuple(1000 + channel + phase for phase in range(30)),
        )
        disposition = bridge.accept(
            DhlPacket(
                PacketType.ELECTRODE_IMPEDANCE,
                0,
                9,
                77,
                3 + channel,
                11 + channel,
                encode_impedance_payload(value),
            )
        )
        assert isinstance(disposition, ImpedanceDisposition)
        assert disposition.result == value
        assert disposition.scan_complete is (channel == 31)

    bridge.expect_ctrl_ack(CtrlFrame(CtrlOpcode.NEURAL_START, 0, 101, b""))


def test_host_rejects_impedance_scan_after_successful_neural_start_ack() -> None:
    descriptor_payload = decode_descriptor_payload(descriptor().payload)
    bridge = DhlToHostBridge(host_context())
    bridge.accept(bridge_descriptor(descriptor_payload))
    admit_inventory(bridge, descriptor_payload, sequence=1)

    neural_start = CtrlFrame(CtrlOpcode.NEURAL_START, 0, 200, b"")
    bridge.expect_ctrl_ack(neural_start)
    bridge.accept(
        DhlPacket(
            PacketType.ACK,
            0,
            9,
            77,
            2,
            10,
            encode_ack_payload(
                AckPayload(neural_start.sequence, CtrlOpcode.NEURAL_START, AckStatus.OK)
            ),
        )
    )
    with pytest.raises(ProtocolError, match="requires Neural acquisition to be stopped"):
        bridge.expect_ctrl_ack(
            CtrlFrame(CtrlOpcode.ELECTRODE_IMPEDANCE_SCAN, 0, 201, b"")
        )
