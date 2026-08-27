from __future__ import annotations

import json

from forge_dhl_v1 import (
    CtrlFrame,
    CtrlOpcode,
    DescriptorPayload,
    DhlPacket,
    IMPEDANCE_FLAGS_ALL,
    ImpedancePayload,
    PacketType,
    encode_ctrl_frame,
    encode_descriptor_payload,
    encode_dhl_packet,
    encode_impedance_payload,
)


def main() -> None:
    descriptor = DhlPacket(
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
    ctrl = CtrlFrame(CtrlOpcode.QUERY_INVENTORY, 0, 0x10203040, b"")
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
    print(
        json.dumps(
            {
                "schema_version": 1,
                "descriptor_hex": encode_dhl_packet(descriptor).hex(),
                "ctrl_hex": encode_ctrl_frame(ctrl).hex(),
                "impedance_hex": encode_dhl_packet(impedance).hex(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
