from __future__ import annotations

import hashlib

from forge_protocol_v1 import *


def ident(seed: int) -> bytes:
    return bytes((seed + i) & 0xFF for i in range(16))


def digest(seed: int) -> bytes:
    return bytes((seed + i * 3) & 0xFF for i in range(32))


RUN_ID = ident(0x01)
POD_ID = ident(0x11)
HEADSTAGE_ID = ident(0x21)
DEVICE_ID = ident(0x31)
PROFILE_ID = ident(0x41)
WORKER_ID = ident(0x51)
TOKEN_ID = ident(0x61)
INTENT_NONCE = ident(0x71)
COMMAND_ID = ident(0x81)
COMMAND_NONCE = ident(0x91)
RECEIPT_NONCE = ident(0xA1)

ALGORITHM_HASH = digest(0x12)
CONFIG_HASH = digest(0x22)
TEMPLATE_HASH = digest(0x32)
CHANNEL_MAP_HASH = digest(0x42)
WORKER_BUILD_HASH = digest(0x52)


def sample_block() -> SampleBlockV1:
    return SampleBlockV1(
        flags=3,
        samples_per_channel=2,
        channel_count=2,
        sample_rate_numerator_hz=30_000,
        sample_rate_denominator=1,
        first_sample_counter=1_000,
        samples=(-32768, -1, 0, 32767),
    )


def record() -> tuple[CanonicalRecordEnvelopeV1, bytes]:
    payload = sample_block().to_bytes()
    return CanonicalRecordEnvelopeV1(
        record_kind=RecordKind.SAMPLE_BLOCK,
        flags=0,
        run_id=RUN_ID,
        pod_id=POD_ID,
        headstage_id=HEADSTAGE_ID,
        record_sequence=7,
        frame_start=100,
        frame_end_exclusive=102,
        sample_start=1_000,
        sample_end_exclusive=1_002,
        global_time_start_ns=1_000_000,
        global_time_end_exclusive_ns=1_066_666,
        channel_layout_id=0x11223344,
        channel_count=2,
    ), payload


def capabilities(stim: bool = True) -> DeviceCapabilitiesV1:
    return DeviceCapabilitiesV1(
        device_id=DEVICE_ID,
        transport=1,
        max_pods=1,
        max_channels_per_pod=256,
        sample_format_mask=1,
        min_sample_rate_hz=1_000,
        max_sample_rate_hz=30_000,
        stim_kind=1 if stim else 0,
        stim_channels=16 if stim else 0,
        max_sample_block_us=1_000,
        capability_flags=REQUIRED_STIM_CAPS if stim else CAP_ACK_REPLAY | CAP_GLOBAL_TIME | CAP_STOP_ACK,
        runtime_safety_flags=REQUIRED_STIM_RUNTIME if stim else RUNTIME_CLOCK_LOCKED | RUNTIME_LINK_HEALTHY,
        hardware_protocol_hash=PROTOCOL_HASH,
    )


def run_command() -> RunCommandV1:
    return RunCommandV1(2, 2, RUN_ID, DEVICE_ID, 1_020_000_000, digest(0x62))


def safety_profile(approval_state: int = 1) -> SafetyProfileV1:
    return SafetyProfileV1(
        PROFILE_ID, approval_state, 5, 2,
        25_000, 10_000, 1_000, 200_000,
        100_000, 500, 50, 100_000,
        10, 10_000, 100_000,
        10_000, 1_000_000,
        -5_000_000, 5_000_000,
        digest(0x72), digest(0x82), digest(0x92), digest(0xA2),
        digest(0xB2), digest(0xC2),
    )


def safety_profile_hash(profile: SafetyProfileV1 | None = None) -> bytes:
    return hashlib.sha256((profile or safety_profile()).to_bytes()).digest()


def token(profile: SafetyProfileV1 | None = None) -> WorkerTokenLeaseV1:
    profile = profile or safety_profile()
    return WorkerTokenLeaseV1(
        RUN_ID, WORKER_ID, TOKEN_ID, 2, 1, 7,
        999_000_000, 2_000_000_000, PROFILE_ID,
        safety_profile_hash(profile), ALGORITHM_HASH, CONFIG_HASH, TEMPLATE_HASH,
        CHANNEL_MAP_HASH, WORKER_BUILD_HASH,
    )


def intent() -> StimIntentV1:
    return StimIntentV1(
        RUN_ID, WORKER_ID, TOKEN_ID, 7, 1_000, 1_000_000_000,
        ALGORITHM_HASH, CONFIG_HASH, TEMPLATE_HASH, CHANNEL_MAP_HASH,
        3, 9, 0, 1_020_000_000, INTENT_NONCE,
    )


def command(profile: SafetyProfileV1 | None = None) -> StimCommandV1:
    profile = profile or safety_profile()
    return StimCommandV1(
        RUN_ID, COMMAND_ID, INTENT_NONCE, DEVICE_ID,
        safety_profile_hash(profile), TEMPLATE_HASH, CHANNEL_MAP_HASH,
        3, 9, 20_000, 200, 50, 200, 10_000, 5,
        1_020_000_000, 1_006_000_000, 7, COMMAND_NONCE,
    )


def receipt() -> StimReceiptV1:
    return StimReceiptV1(
        RUN_ID, COMMAND_ID, INTENT_NONCE, DEVICE_ID, 1, 0, 3, 9,
        1_006_001_000, 1_006_001_450, 1_250_000, 20_050, 0,
        4_000, 7, RECEIPT_NONCE, digest(0xD2),
    )


def bodies() -> list[tuple[str, FixedBody, int, int]]:
    profile = safety_profile()
    return [
        ("device_capabilities_v1", capabilities(), 42, 7),
        ("run_command_v1", run_command(), 43, 7),
        ("safety_profile_v1", profile, 44, 7),
        ("stim_intent_v1", intent(), 45, 7),
        ("stim_command_v1", command(profile), 46, 7),
        ("stim_receipt_v1", receipt(), 47, 7),
        ("worker_token_lease_v1", token(profile), 48, 7),
        ("ack_v1", AckV1(43, 7, 1, 2, digest(0xE2)), 49, 7),
        ("nack_v1", NackV1(45, 7, 12, 0, 0x12345678, digest(0xF2)), 50, 7),
        ("replay_request_v1", ReplayRequestV1(RUN_ID, POD_ID, 10, 20, 1_050_000_000, 1, digest(0x02)), 51, 7),
    ]


def golden_vectors() -> dict[str, bytes]:
    envelope, payload = record()
    result = {
        "sample_block_v1": payload,
        "canonical_record_envelope_v1": encode_record(envelope, payload),
    }
    result.update({name: encode_low_speed(body, request_id, epoch) for name, body, request_id, epoch in bodies()})
    return result
