use std::fs;
use std::path::PathBuf;

use forge_protocol_v1::*;

fn ident(seed: u8) -> Id16 {
    let mut v = [0; 16];
    for (i, x) in v.iter_mut().enumerate() {
        *x = seed.wrapping_add(i as u8)
    }
    v
}
fn digest(seed: u8) -> Hash32 {
    let mut v = [0; 32];
    for (i, x) in v.iter_mut().enumerate() {
        *x = seed.wrapping_add((i * 3) as u8)
    }
    v
}
fn read_hex(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("golden")
        .join(format!("{name}.hex"));
    let text = fs::read_to_string(path).unwrap();
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).unwrap())
        .collect()
}
fn refresh_control_crc(wire: &mut [u8]) {
    let body_crc = crc32c(&wire[80..]);
    wire[72..76].copy_from_slice(&body_crc.to_le_bytes());
    let header_crc = crc32c(&wire[..76]);
    wire[76..80].copy_from_slice(&header_crc.to_le_bytes());
}
fn profile_hash() -> Hash32 {
    [
        0x39, 0x5a, 0xed, 0xb6, 0x84, 0x1c, 0x0c, 0x2b, 0xa9, 0xb4, 0x4b, 0x5b, 0x76, 0x94, 0xa3,
        0x76, 0x03, 0x82, 0xb9, 0x47, 0xf1, 0xbc, 0x2b, 0x06, 0xb3, 0x1e, 0x6d, 0x55, 0x9b, 0xe9,
        0x32, 0xc0,
    ]
}
fn sample() -> SampleBlockV1 {
    SampleBlockV1 {
        flags: 3,
        samples_per_channel: 2,
        channel_count: 2,
        sample_format: 1,
        sample_rate_numerator_hz: 30_000,
        sample_rate_denominator: 1,
        first_sample_counter: 1_000,
        samples: vec![-32768, -1, 0, 32767],
    }
}

#[test]
fn event_payload_extension_matches_cross_language_golden() {
    let values = [
        (
            "marker_payload_v1",
            MarkerPayloadV1 {
                event_id: [1; 16],
                marker_sequence: 7,
                marker_flags: MARKER_FLAG_OPERATOR,
                label: "baseline".into(),
                note: "awake".into(),
            }
            .encode()
            .unwrap(),
        ),
        (
            "fault_payload_v1",
            FaultPayloadV1 {
                event_id: [2; 16],
                fault_code: FaultCode::AnalysisDrop,
                severity: FaultSeverity::ErrorLevel,
                layer: FaultLayer::AnalysisWorker,
                fault_flags: EVENT_FAULT_FLAG_RUN_LATCHED | EVENT_FAULT_FLAG_STIM_DISARMING,
                occurrence_count: 1,
                detail: "consumer ring full".into(),
            }
            .encode()
            .unwrap(),
        ),
        (
            "gap_payload_v1",
            GapPayloadV1 {
                event_id: [3; 16],
                reason: GapReason::CounterDiscontinuity,
                layer: FaultLayer::ReceiverCapture,
                gap_flags: 3,
                missing_record_count: 1,
                missing_frame_count: 1,
                missing_sample_count: 30,
            }
            .encode()
            .unwrap(),
        ),
        (
            "online_analysis_payload_v1",
            OnlineAnalysisPayloadV1 {
                event_id: [4; 16],
                worker_id: [5; 16],
                worker_build_hash: [6; 32],
                algorithm_hash: [7; 32],
                config_hash: [8; 32],
                result_schema_hash: [9; 32],
                source_record_sequence: 11,
                channel_id: 2,
                analysis_flags: ANALYSIS_FLAG_REFERENCE_ONLY,
                result: br#"{"score":1}"#.to_vec(),
            }
            .encode()
            .unwrap(),
        ),
    ];
    for (name, encoded) in values {
        assert_eq!(encoded, read_hex(name));
        assert!(decode_event_payload(&encoded).is_ok());
    }
}
fn envelope() -> CanonicalRecordEnvelopeV1 {
    CanonicalRecordEnvelopeV1 {
        record_kind: RecordKind::SampleBlock,
        flags: 0,
        run_id: ident(1),
        pod_id: ident(0x11),
        headstage_id: ident(0x21),
        record_sequence: 7,
        frame_start: 100,
        frame_end_exclusive: 102,
        sample_start: 1_000,
        sample_end_exclusive: 1_002,
        global_time_start_ns: 1_000_000,
        global_time_end_exclusive_ns: 1_066_666,
        channel_layout_id: 0x1122_3344,
        channel_count: 2,
        sample_format: 1,
    }
}
fn caps(stim: bool) -> DeviceCapabilitiesV1 {
    DeviceCapabilitiesV1 {
        device_id: ident(0x31),
        transport: 1,
        max_pods: 1,
        max_channels_per_pod: 256,
        sample_format_mask: 1,
        min_sample_rate_hz: 1_000,
        max_sample_rate_hz: 30_000,
        stim_kind: u16::from(stim),
        stim_channels: if stim { 16 } else { 0 },
        max_sample_block_us: 1_000,
        capability_flags: if stim {
            REQUIRED_STIM_CAPS
        } else {
            CAP_ACK_REPLAY | CAP_GLOBAL_TIME | CAP_STOP_ACK
        },
        runtime_safety_flags: if stim {
            REQUIRED_STIM_RUNTIME
        } else {
            RUNTIME_CLOCK_LOCKED | RUNTIME_LINK_HEALTHY
        },
        hardware_protocol_hash: PROTOCOL_HASH,
    }
}
fn profile(state: u8) -> SafetyProfileV1 {
    SafetyProfileV1 {
        profile_id: ident(0x41),
        approval_state: state,
        electrode_material: 5,
        recovery_policy: 2,
        wire_diameter_nm: 25_000,
        exposed_area_um2: 10_000,
        impedance_min_ohm: 1_000,
        impedance_max_ohm: 200_000,
        max_current_na: 100_000,
        max_phase_width_us: 500,
        min_interphase_us: 50,
        max_frequency_millihz: 100_000,
        max_train_pulses: 10,
        max_train_duration_ms: 10_000,
        max_duty_cycle_ppm: 100_000,
        max_charge_per_phase_pc: 10_000,
        max_charge_density_pc_per_mm2: 1_000_000,
        compliance_min_uv: -5_000_000,
        compliance_max_uv: 5_000_000,
        experiment_protocol_hash: digest(0x72),
        electrode_geometry_hash: digest(0x82),
        hardware_build_hash: digest(0x92),
        software_build_hash: digest(0xa2),
        approved_limits_hash: digest(0xb2),
        approval_authority_hash: digest(0xc2),
    }
}
fn token() -> WorkerTokenLeaseV1 {
    WorkerTokenLeaseV1 {
        run_id: ident(1),
        worker_id: ident(0x51),
        token_id: ident(0x61),
        role: 2,
        state: 1,
        arm_epoch: 7,
        issued_global_time_ns: 999_000_000,
        expires_global_time_ns: 2_000_000_000,
        safety_profile_id: ident(0x41),
        safety_profile_hash: profile_hash(),
        algorithm_hash: digest(0x12),
        config_hash: digest(0x22),
        template_hash: digest(0x32),
        channel_map_hash: digest(0x42),
        worker_build_hash: digest(0x52),
    }
}
fn intent() -> StimIntentV1 {
    StimIntentV1 {
        run_id: ident(1),
        source_worker_id: ident(0x51),
        control_token_id: ident(0x61),
        source_record_sequence: 7,
        source_sample_counter: 1_000,
        source_global_time_ns: 1_000_000_000,
        algorithm_hash: digest(0x12),
        config_hash: digest(0x22),
        template_hash: digest(0x32),
        channel_map_hash: digest(0x42),
        target_channel: 3,
        template_id: 9,
        intent_flags: 0,
        deadline_global_time_ns: 1_020_000_000,
        intent_nonce: ident(0x71),
    }
}
fn command() -> StimCommandV1 {
    StimCommandV1 {
        run_id: ident(1),
        command_id: ident(0x81),
        intent_nonce: ident(0x71),
        device_id: ident(0x31),
        safety_profile_hash: profile_hash(),
        template_hash: digest(0x32),
        channel_map_hash: digest(0x42),
        target_channel: 3,
        template_id: 9,
        current_na: 20_000,
        cathodic_phase_us: 200,
        interphase_us: 50,
        anodic_phase_us: 200,
        frequency_millihz: 10_000,
        pulse_count: 5,
        deadline_global_time_ns: 1_020_000_000,
        execute_not_before_global_time_ns: 1_006_000_000,
        arm_epoch: 7,
        command_nonce: ident(0x91),
    }
}

#[test]
fn record_and_sample_match_golden() {
    let payload = sample().encode().unwrap();
    assert_eq!(payload, read_hex("sample_block_v1"));
    let wire = encode_record(&envelope(), &payload).unwrap();
    assert_eq!(wire, read_hex("canonical_record_envelope_v1"));
    let decoded = decode_record(&wire).unwrap();
    assert_eq!(decoded.envelope, envelope());
    assert_eq!(decoded.payload, payload);
}

fn assert_golden_message<T: WireBody>(name: &str, body: &T, request_id: u64) {
    let wire = encode_low_speed(0, request_id, 7, body).unwrap();
    assert_eq!(wire, read_hex(name));
    let decoded = decode_low_speed(&wire).unwrap();
    assert_eq!(decoded.kind, T::KIND);
    assert_eq!(decoded.request_id, request_id);
}
macro_rules! golden_msg {
    ($name:literal,$body:expr,$req:expr) => {{
        let body = $body;
        assert_golden_message($name, &body, $req);
    }};
}

#[test]
fn all_low_speed_messages_match_golden() {
    golden_msg!("device_capabilities_v1", caps(true), 42);
    golden_msg!(
        "run_command_v1",
        RunCommandV1 {
            command: 2,
            scope: 2,
            run_id: ident(1),
            target_device_id: ident(0x31),
            deadline_global_time_ns: 1_020_000_000,
            frozen_config_hash: digest(0x62)
        },
        43
    );
    golden_msg!("safety_profile_v1", profile(1), 44);
    golden_msg!("stim_intent_v1", intent(), 45);
    golden_msg!("stim_command_v1", command(), 46);
    golden_msg!(
        "stim_receipt_v1",
        StimReceiptV1 {
            run_id: ident(1),
            command_id: ident(0x81),
            intent_nonce: ident(0x71),
            device_id: ident(0x31),
            result: 1,
            fault_code: 0,
            target_channel: 3,
            template_id: 9,
            actual_start_global_time_ns: 1_006_001_000,
            actual_end_global_time_ns: 1_006_001_450,
            measured_compliance_uv: 1_250_000,
            peak_current_na: 20_050,
            receipt_flags: 0,
            delivered_phase_charge_pc: 4_000,
            arm_epoch: 7,
            receipt_nonce: ident(0xa1),
            hardware_state_hash: digest(0xd2)
        },
        47
    );
    golden_msg!("worker_token_lease_v1", token(), 48);
    golden_msg!(
        "ack_v1",
        AckV1 {
            acknowledged_request_id: 43,
            applied_epoch: 7,
            ack_code: 1,
            state_code: 2,
            receipt_hash: digest(0xe2)
        },
        49
    );
    golden_msg!(
        "nack_v1",
        NackV1 {
            rejected_request_id: 45,
            current_epoch: 7,
            error_code: 12,
            retryable: 0,
            detail_code: 0x1234_5678,
            state_hash: digest(0xf2)
        },
        50
    );
    golden_msg!(
        "replay_request_v1",
        ReplayRequestV1 {
            run_id: ident(1),
            pod_id: ident(0x11),
            first_record_sequence: 10,
            last_record_sequence_exclusive: 20,
            deadline_global_time_ns: 1_050_000_000,
            reason_code: 1,
            request_context_hash: digest(2)
        },
        51
    );
}

#[test]
fn stim_gate_accepts_only_complete_frozen_context() {
    let p = profile(1);
    let h = profile_hash();
    let t = token();
    let i = intent();
    let c = command();
    let capabilities = caps(true);
    validate_stim_intent(&capabilities, Some(&p), &h, Some(&t), &i, 7, 1_005_000_000).unwrap();
    validate_stim_command(&capabilities, &p, &h, &t, &i, &c, 1_005_000_000).unwrap();
    assert_eq!(
        validate_stim_intent(&capabilities, None, &h, Some(&t), &i, 7, 1_005_000_000),
        Err(SafetyError::MissingProfile)
    );
    assert_eq!(
        validate_stim_intent(&caps(false), Some(&p), &h, Some(&t), &i, 7, 1_005_000_000),
        Err(SafetyError::StimNotCapable)
    );
    let mut open = capabilities.clone();
    open.runtime_safety_flags &= !RUNTIME_INTERLOCK_CLOSED;
    assert_eq!(
        validate_stim_intent(&open, Some(&p), &h, Some(&t), &i, 7, 1_005_000_000),
        Err(SafetyError::InterlockOrRuntimeHealth)
    );
    let mut e_stop_open = capabilities.clone();
    e_stop_open.runtime_safety_flags &= !RUNTIME_EMERGENCY_STOP_HEALTHY;
    assert_eq!(
        validate_stim_intent(&e_stop_open, Some(&p), &h, Some(&t), &i, 7, 1_005_000_000),
        Err(SafetyError::InterlockOrRuntimeHealth)
    );
    let mut no_e_stop_capability = capabilities.clone();
    no_e_stop_capability.capability_flags &= !CAP_EMERGENCY_STOP_LOOP;
    assert_eq!(
        validate_stim_intent(
            &no_e_stop_capability,
            Some(&p),
            &h,
            Some(&t),
            &i,
            7,
            1_005_000_000
        ),
        Err(SafetyError::MissingSafetyFeature)
    );
    let mut no_default_off_gate = capabilities.clone();
    no_default_off_gate.capability_flags &= !CAP_DEFAULT_OFF_STIM_POWER_GATE;
    assert_eq!(
        validate_stim_intent(
            &no_default_off_gate,
            Some(&p),
            &h,
            Some(&t),
            &i,
            7,
            1_005_000_000
        ),
        Err(SafetyError::MissingSafetyFeature)
    );
    assert_eq!(
        validate_stim_intent(
            &capabilities,
            Some(&profile(0)),
            &h,
            Some(&t),
            &i,
            7,
            1_005_000_000
        ),
        Err(SafetyError::ProfileNotApproved)
    );
    assert_eq!(
        validate_stim_intent(&capabilities, Some(&p), &h, Some(&t), &i, 8, 1_005_000_000),
        Err(SafetyError::Epoch)
    );
    assert_eq!(
        validate_stim_intent(&capabilities, Some(&p), &h, Some(&t), &i, 7, 1_020_000_000),
        Err(SafetyError::Deadline)
    );
    let mut changed_intent = i.clone();
    changed_intent.template_hash[0] ^= 1;
    assert_eq!(
        validate_stim_intent(
            &capabilities,
            Some(&p),
            &h,
            Some(&t),
            &changed_intent,
            7,
            1_005_000_000
        ),
        Err(SafetyError::FrozenHash)
    );
    let mut excessive = c;
    excessive.current_na = p.max_current_na + 1;
    assert_eq!(
        validate_stim_command(&capabilities, &p, &h, &t, &i, &excessive, 1_005_000_000),
        Err(SafetyError::SafetyLimit)
    );

    let mut changed_profile = p.clone();
    changed_profile.max_current_na -= 1;
    assert_eq!(
        validate_stim_intent(
            &capabilities,
            Some(&changed_profile),
            &h,
            Some(&t),
            &i,
            7,
            1_005_000_000
        ),
        Err(SafetyError::ProfileHash)
    );

    let mut unbalanced = command();
    unbalanced.anodic_phase_us -= 1;
    assert_eq!(
        validate_stim_command(&capabilities, &p, &h, &t, &i, &unbalanced, 1_005_000_000),
        Err(SafetyError::SafetyLimit)
    );
}

#[test]
fn parser_rejects_truncation_and_crc_mutation_without_panic() {
    let record = read_hex("canonical_record_envelope_v1");
    for len in 0..record.len() {
        assert!(decode_record(&record[..len]).is_err())
    }
    for index in 0..record.len() {
        let mut v = record.clone();
        v[index] ^= 1;
        assert!(
            decode_record(&v).is_err(),
            "record mutation {index} accepted"
        );
    }
    for name in [
        "device_capabilities_v1",
        "run_command_v1",
        "safety_profile_v1",
        "stim_intent_v1",
        "stim_command_v1",
        "stim_receipt_v1",
        "worker_token_lease_v1",
        "ack_v1",
        "nack_v1",
        "replay_request_v1",
    ] {
        let wire = read_hex(name);
        for len in 0..wire.len() {
            assert!(decode_low_speed(&wire[..len]).is_err())
        }
        for index in 0..wire.len() {
            let mut v = wire.clone();
            v[index] ^= 1;
            assert!(
                decode_low_speed(&v).is_err(),
                "control mutation {name}[{index}] accepted"
            );
        }
    }
}

#[test]
fn explicit_illegal_wire_mutations_reject() {
    let mut record = read_hex("canonical_record_envelope_v1");
    record[0] ^= 1;
    assert_eq!(decode_record(&record).unwrap_err(), CodecError::BadMagic);
    let mut record = read_hex("canonical_record_envelope_v1");
    *record.last_mut().unwrap() ^= 1;
    assert_eq!(decode_record(&record).unwrap_err(), CodecError::PayloadCrc);
    let mut control = read_hex("device_capabilities_v1");
    control[40] ^= 1;
    let crc = crc32c(&control[..76]);
    control[76..80].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(
        decode_low_speed(&control).unwrap_err(),
        CodecError::ProtocolHash
    );

    let mut record = read_hex("canonical_record_envelope_v1");
    record[19] |= 0x80;
    let crc = crc32c(&record[..172]);
    record[172..176].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(
        decode_record(&record).unwrap_err(),
        CodecError::UnknownFlags
    );

    let mut control = read_hex("device_capabilities_v1");
    control[16..18].copy_from_slice(&u16::MAX.to_le_bytes());
    let crc = crc32c(&control[..76]);
    control[76..80].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(
        decode_low_speed(&control).unwrap_err(),
        CodecError::UnknownKind
    );

    let mut control = read_hex("device_capabilities_v1");
    control[..4].copy_from_slice(&1_048_577_u32.to_le_bytes());
    let crc = crc32c(&control[..76]);
    control[76..80].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(
        decode_low_speed(&control).unwrap_err(),
        CodecError::LengthLimit
    );
}

#[test]
fn idl_lf_hash_matches_frozen_constant() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("schema")
        .join("forge_protocol_v1.idl");
    let source = fs::read(path).unwrap();
    let mut canonical_lf = Vec::with_capacity(source.len());
    let mut index = 0;
    while index < source.len() {
        if source[index] == b'\r' {
            canonical_lf.push(b'\n');
            index += usize::from(source.get(index + 1) == Some(&b'\n')) + 1;
        } else {
            canonical_lf.push(source[index]);
            index += 1;
        }
    }
    assert_eq!(sha256(&canonical_lf), PROTOCOL_HASH);
}

#[test]
fn reserved_enum_and_flag_values_reject() {
    let mut invalid_profile = profile(1);
    invalid_profile.electrode_material = 6;
    assert_eq!(invalid_profile.encode_body(), Err(CodecError::Invariant));
    let mut invalid_intent = intent();
    invalid_intent.intent_flags = 1;
    assert_eq!(invalid_intent.encode_body(), Err(CodecError::Invariant));
    let mut invalid_caps = caps(true);
    invalid_caps.max_sample_block_us = 0;
    assert_eq!(invalid_caps.encode_body(), Err(CodecError::Invariant));
    let mut invalid_caps = caps(true);
    invalid_caps.max_pods = 9;
    assert_eq!(invalid_caps.encode_body(), Err(CodecError::Invariant));
    let mut invalid_caps = caps(true);
    invalid_caps.stim_channels = 15;
    assert_eq!(invalid_caps.encode_body(), Err(CodecError::Invariant));
    let mut invalid_envelope = envelope();
    invalid_envelope.run_id = ZERO_ID;
    assert_eq!(
        encode_record(&invalid_envelope, &sample().encode().unwrap()),
        Err(CodecError::Invariant)
    );

    for (name, body_offset) in [
        ("safety_profile_v1", 68_usize),
        ("stim_intent_v1", 212),
        ("worker_token_lease_v1", 54),
        ("ack_v1", 24),
        ("nack_v1", 23),
        ("replay_request_v1", 62),
    ] {
        let mut wire = read_hex(name);
        wire[80 + body_offset] = 1;
        refresh_control_crc(&mut wire);
        assert_eq!(
            decode_low_speed(&wire),
            Err(CodecError::Reserved),
            "reserved field accepted for {name}"
        );
    }
}

#[test]
fn illegal_vector_manifest_names_are_all_exercised() {
    const EXERCISED: [&str; 14] = [
        "record_bad_magic",
        "record_unknown_flags",
        "record_bad_payload_crc",
        "control_oversize",
        "control_protocol_mismatch",
        "control_unknown_kind",
        "stim_rhd_only",
        "stim_missing_profile",
        "stim_unapproved_profile",
        "stim_interlock_open",
        "stim_wrong_epoch",
        "stim_expired",
        "stim_hash_mismatch",
        "stim_limit_exceeded",
    ];
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("golden")
        .join("illegal_vectors.json");
    let manifest = fs::read_to_string(path).unwrap();
    assert_eq!(manifest.matches("\"name\"").count(), EXERCISED.len());
    for name in EXERCISED {
        assert!(
            manifest.contains(&format!("\"name\": \"{name}\"")),
            "illegal vector manifest drift: {name}"
        );
    }
}
