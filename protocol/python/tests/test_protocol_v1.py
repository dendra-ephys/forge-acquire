from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

from forge_protocol_v1 import *
from fixtures import *


def read_hex(name: str) -> bytes:
    return bytes.fromhex((ROOT / "golden" / f"{name}.hex").read_text(encoding="ascii"))


class ProtocolV1Tests(unittest.TestCase):
    def test_idl_hash_is_protocol_hash(self):
        source = (ROOT / "schema" / "forge_protocol_v1.idl").read_bytes()
        canonical_lf = source.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        self.assertEqual(hashlib.sha256(canonical_lf).hexdigest(), PROTOCOL_HASH_HEX)

    def test_crc32c_standard_vector(self):
        self.assertEqual(crc32c(b"123456789"), 0xE3069283)

    def test_record_and_sample_golden_round_trip(self):
        envelope, payload = record()
        self.assertEqual(payload, read_hex("sample_block_v1"))
        wire = encode_record(envelope, payload)
        self.assertEqual(wire, read_hex("canonical_record_envelope_v1"))
        self.assertEqual(decode_record(wire), DecodedRecord(envelope, payload))

    def test_every_low_speed_message_matches_golden_and_round_trips(self):
        for name, body, request_id, epoch in bodies():
            with self.subTest(name=name):
                wire = encode_low_speed(body, request_id, epoch)
                self.assertEqual(wire, read_hex(name))
                decoded = decode_low_speed(wire)
                self.assertEqual(decoded.body, body)
                self.assertEqual(decoded.request_id, request_id)
                self.assertEqual(decoded.epoch, epoch)

    def test_record_illegal_examples(self):
        wire = bytearray(read_hex("canonical_record_envelope_v1"))
        wire[0] ^= 1
        with self.assertRaisesRegex(CodecError, "bad_magic"):
            decode_record(bytes(wire))

        wire = bytearray(read_hex("canonical_record_envelope_v1"))
        wire[-1] ^= 1
        with self.assertRaisesRegex(CodecError, "payload_crc"):
            decode_record(bytes(wire))

        wire = bytearray(read_hex("canonical_record_envelope_v1"))
        wire[19] |= 0x80
        wire[172:176] = crc32c(bytes(wire[:172])).to_bytes(4, "little")
        with self.assertRaisesRegex(CodecError, "unknown_flags"):
            decode_record(bytes(wire))

    def test_control_illegal_examples(self):
        base = read_hex("device_capabilities_v1")
        wire = bytearray(base)
        wire[40] ^= 1
        wire[76:80] = crc32c(bytes(wire[:76])).to_bytes(4, "little")
        with self.assertRaisesRegex(CodecError, "protocol_hash"):
            decode_low_speed(bytes(wire))

        wire = bytearray(base)
        wire[16:18] = (65535).to_bytes(2, "little")
        wire[76:80] = crc32c(bytes(wire[:76])).to_bytes(4, "little")
        with self.assertRaisesRegex(CodecError, "unknown_kind"):
            decode_low_speed(bytes(wire))

        wire = bytearray(base)
        wire[0:4] = (MAX_LOW_SPEED_MESSAGE_LEN + 1).to_bytes(4, "little")
        wire[76:80] = crc32c(bytes(wire[:76])).to_bytes(4, "little")
        with self.assertRaisesRegex(CodecError, "length_limit"):
            decode_low_speed(bytes(wire))

    def test_valid_stim_gate_and_command(self):
        profile = safety_profile()
        validate_stim_intent(capabilities(), profile, safety_profile_hash(profile), token(profile), intent(), 7, 1_005_000_000)
        validate_stim_command(capabilities(), profile, safety_profile_hash(profile), token(profile), intent(), command(profile), 1_005_000_000)

    def test_stim_gate_fail_closed_matrix(self):
        profile = safety_profile(); profile_hash = safety_profile_hash(profile)
        cases = [
            ("missing_profile", capabilities(), None, profile_hash, token(profile), intent(), 7, 1_005_000_000),
            ("stim_not_capable", capabilities(False), profile, profile_hash, token(profile), intent(), 7, 1_005_000_000),
            ("interlock_or_runtime_health", replace(capabilities(), runtime_safety_flags=REQUIRED_STIM_RUNTIME & ~RUNTIME_INTERLOCK_CLOSED), profile, profile_hash, token(profile), intent(), 7, 1_005_000_000),
            ("interlock_or_runtime_health", replace(capabilities(), runtime_safety_flags=REQUIRED_STIM_RUNTIME & ~RUNTIME_EMERGENCY_STOP_HEALTHY), profile, profile_hash, token(profile), intent(), 7, 1_005_000_000),
            ("missing_safety_feature", replace(capabilities(), capability_flags=REQUIRED_STIM_CAPS & ~CAP_EMERGENCY_STOP_LOOP), profile, profile_hash, token(profile), intent(), 7, 1_005_000_000),
            ("missing_safety_feature", replace(capabilities(), capability_flags=REQUIRED_STIM_CAPS & ~CAP_DEFAULT_OFF_STIM_POWER_GATE), profile, profile_hash, token(profile), intent(), 7, 1_005_000_000),
            ("protocol_hash", replace(capabilities(), hardware_protocol_hash=bytes(32)), profile, profile_hash, token(profile), intent(), 7, 1_005_000_000),
            ("epoch", capabilities(), profile, profile_hash, token(profile), intent(), 8, 1_005_000_000),
            ("deadline", capabilities(), profile, profile_hash, token(profile), intent(), 7, 1_020_000_000),
            ("frozen_hash", capabilities(), profile, profile_hash, token(profile), replace(intent(), template_hash=bytes([0xAA])*32), 7, 1_005_000_000),
        ]
        for expected, caps, candidate_profile, candidate_hash, lease, candidate_intent, epoch, now in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(SafetyError) as caught:
                    validate_stim_intent(caps, candidate_profile, candidate_hash, lease, candidate_intent, epoch, now)
                self.assertEqual(caught.exception.code, expected)

        draft = safety_profile(approval_state=0)
        with self.assertRaises(SafetyError) as caught:
            validate_stim_intent(capabilities(), draft, safety_profile_hash(draft), token(draft), intent(), 7, 1_005_000_000)
        self.assertEqual(caught.exception.code, "profile_not_approved")

    def test_command_hard_limit_is_rejected(self):
        profile=safety_profile(); excessive=replace(command(profile),current_na=profile.max_current_na+1)
        with self.assertRaises(SafetyError) as caught:
            validate_stim_command(capabilities(),profile,safety_profile_hash(profile),token(profile),intent(),excessive,1_005_000_000)
        self.assertEqual(caught.exception.code,"safety_limit")

    def test_profile_body_hash_is_recomputed_by_safety_gate(self):
        profile = safety_profile()
        frozen_hash = safety_profile_hash(profile)
        changed = replace(profile, max_current_na=profile.max_current_na - 1)
        with self.assertRaises(SafetyError) as caught:
            validate_stim_intent(
                capabilities(), changed, frozen_hash, token(profile), intent(), 7,
                1_005_000_000,
            )
        self.assertEqual(caught.exception.code, "profile_hash")

    def test_unbalanced_biphasic_command_is_rejected(self):
        profile = safety_profile()
        unbalanced = replace(command(profile), anodic_phase_us=199)
        with self.assertRaises(SafetyError) as caught:
            validate_stim_command(
                capabilities(), profile, safety_profile_hash(profile),
                token(profile), intent(), unbalanced, 1_005_000_000,
            )
        self.assertEqual(caught.exception.code, "safety_limit")

    def test_reserved_enum_and_flag_values_are_rejected(self):
        with self.assertRaises(CodecError):
            replace(safety_profile(), electrode_material=6).to_bytes()
        with self.assertRaises(CodecError):
            replace(intent(), intent_flags=1).to_bytes()
        with self.assertRaises(CodecError):
            replace(capabilities(), max_sample_block_us=0).to_bytes()
        with self.assertRaises(CodecError):
            replace(capabilities(), max_pods=9).to_bytes()
        with self.assertRaises(CodecError):
            replace(capabilities(), stim_channels=15).to_bytes()
        envelope, payload = record()
        with self.assertRaises(CodecError):
            encode_record(replace(envelope, run_id=bytes(16)), payload)

        reserved_offsets = {
            "safety_profile_v1": 80 + 68,
            "stim_intent_v1": 80 + 212,
            "worker_token_lease_v1": 80 + 54,
            "ack_v1": 80 + 24,
            "nack_v1": 80 + 23,
            "replay_request_v1": 80 + 62,
        }
        for name, offset in reserved_offsets.items():
            with self.subTest(name=name):
                wire = bytearray(read_hex(name))
                wire[offset] = 1
                body = bytes(wire[80:])
                wire[72:76] = crc32c(body).to_bytes(4, "little")
                wire[76:80] = crc32c(bytes(wire[:76])).to_bytes(4, "little")
                with self.assertRaisesRegex(CodecError, "reserved"):
                    decode_low_speed(bytes(wire))

    def test_illegal_vector_manifest_is_fully_exercised(self):
        manifest = json.loads(
            (ROOT / "golden" / "illegal_vectors.json").read_text(encoding="utf-8")
        )
        expected = {case["name"] for case in manifest["cases"]}
        exercised = {
            "record_bad_magic", "record_unknown_flags", "record_bad_payload_crc",
            "control_oversize", "control_protocol_mismatch", "control_unknown_kind",
            "stim_rhd_only", "stim_missing_profile", "stim_unapproved_profile",
            "stim_interlock_open", "stim_wrong_epoch", "stim_expired",
            "stim_hash_mismatch", "stim_limit_exceeded",
        }
        self.assertEqual(exercised, expected)

    def test_parser_truncations_and_mutations_never_escape_typed_errors(self):
        for name, original in golden_vectors().items():
            parser = decode_record if name == "canonical_record_envelope_v1" else (SampleBlockV1.from_bytes if name == "sample_block_v1" else decode_low_speed)
            for length in range(len(original)):
                with self.subTest(name=name, length=length):
                    with self.assertRaises(CodecError): parser(original[:length])
            # CRC-protected frames must reject every single-bit mutation in the
            # first bit of every byte. SampleBlock has no standalone CRC.
            if name != "sample_block_v1":
                for index in range(len(original)):
                    mutated=bytearray(original);mutated[index]^=1
                    try:
                        parser(bytes(mutated))
                    except CodecError:
                        pass
                    except Exception as exc:
                        self.fail(f"untyped exception {name}[{index}]: {exc!r}")
                    else:
                        self.fail(f"CRC-protected mutation accepted: {name}[{index}]")


if __name__ == "__main__":
    unittest.main()
