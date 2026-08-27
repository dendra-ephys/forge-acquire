//! Qualification-only owner-control framing. This is intentionally separate
//! from every frozen Host low-speed IDL and is carried only over a private,
//! authenticated SecurePipe endpoint owned by the GUI-kill harness.

use std::io;

use forge_protocol_v1::crc32c;
use serde::{Deserialize, Serialize};

use crate::run::{RunCommandKind, RunState};

pub(crate) const GUI_KILL_CONTROL_REQUEST_SCHEMA: &str = "forge.gui-kill-control-request.v2";
pub(crate) const GUI_KILL_CONTROL_RESPONSE_SCHEMA: &str = "forge.gui-kill-control-response.v2";
pub(crate) const GUI_KILL_CONTROL_REQUEST_V1_SCHEMA: &str = "forge.gui-kill-control-request.v1";
pub(crate) const GUI_KILL_CONTROL_RESPONSE_V1_SCHEMA: &str = "forge.gui-kill-control-response.v1";
const MAX_FRAME_LEN: usize = 16 * 1024;
const FRAME_PREFIX_LEN: usize = 4;
const FRAME_CRC_LEN: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiKillAttemptModeV1 {
    AfterAck,
    Inflight,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiKillWaitMethodV2 {
    GracefulWait,
    JobObjectTermination,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiKillWaitResultV2 {
    SignaledReaped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiKillContainmentEvidenceV2 {
    pub created_suspended: bool,
    pub kill_on_job_close_configured: bool,
    pub job_assigned_before_resume: bool,
    pub executable_rehashed_before_resume: bool,
}

impl GuiKillContainmentEvidenceV2 {
    pub(crate) fn validate(self) -> io::Result<()> {
        if self.created_suspended
            && self.kill_on_job_close_configured
            && self.job_assigned_before_resume
            && self.executable_rehashed_before_resume
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete containment evidence",
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiKillReapEvidenceV2 {
    pub method: GuiKillWaitMethodV2,
    pub exit_code: u32,
    pub wait_deadline_ms: u32,
    pub wait_elapsed_ms: u32,
    pub wait_result: GuiKillWaitResultV2,
    pub job_active_processes_after_wait: u32,
    pub job_empty_proven: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum GuiKillControlCommandV1 {
    QueryReady,
    Lifecycle {
        request_id: u64,
        command_wire: u8,
    },
    BaselineSnapshot {
        request_id: u64,
    },
    AttemptStarted {
        attempt: u32,
        mode: GuiKillAttemptModeV1,
        gui_pid: u32,
        gui_creation_time_100ns: u64,
        request_id: u64,
        barrier_request_id: Option<u64>,
        post_kill_request_id: u64,
        containment: GuiKillContainmentEvidenceV2,
    },
    StageObserved {
        attempt: u32,
    },
    KillRequested {
        attempt: u32,
    },
    ReapProven {
        attempt: u32,
        evidence: GuiKillReapEvidenceV2,
    },
    CompleteAttempt {
        attempt: u32,
    },
    Exit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiKillControlRequestV1 {
    pub schema: String,
    pub command_sequence: u64,
    pub supervisor_pid: u32,
    pub supervisor_creation_time_100ns: u64,
    pub run_id_hex: String,
    pub command: GuiKillControlCommandV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiKillControlResponseV1 {
    pub schema: String,
    pub command_sequence: u64,
    pub run_id_hex: String,
    pub accepted: bool,
    pub error_code: String,
    pub owner_pid: u32,
    pub owner_creation_time_100ns: u64,
    pub owner_executable_sha256_hex: String,
    pub gui_pipe_name: String,
    pub control_pipe_name: String,
    pub supervisor_pid: u32,
    pub supervisor_creation_time_100ns: u64,
    pub state_wire: u8,
    pub active_epoch: Option<u64>,
    pub committed_record_count: u64,
    pub durable_record_count: u64,
    pub audit_event_sequence: u64,
}

// Source aliases keep qualification-only call sites small while the private
// control protocol is explicitly v2 and feeds receipt/audit v3. There is no
// control-v1 deserialization fallback: the schema gate rejects it before
// typed field parsing.
#[allow(dead_code)]
pub(crate) type GuiKillAttemptModeV3 = GuiKillAttemptModeV1;
#[allow(dead_code)]
pub(crate) type GuiKillControlCommandV3 = GuiKillControlCommandV1;
#[allow(dead_code)]
pub(crate) type GuiKillControlRequestV3 = GuiKillControlRequestV1;
#[allow(dead_code)]
pub(crate) type GuiKillControlResponseV3 = GuiKillControlResponseV1;
#[allow(dead_code)]
pub(crate) type GuiKillControlSequenceV3 = GuiKillControlSequenceV1;

/// Owner-local monotonicity guard. Framing validates that a sequence is
/// nonzero; the owner keeps this guard for the lifetime of one supervisor
/// instance so replayed or reordered control requests fail closed.
#[derive(Clone, Debug, Default)]
pub(crate) struct GuiKillControlSequenceV1 {
    last: Option<u64>,
}

impl GuiKillControlSequenceV1 {
    pub(crate) fn observe(&mut self, request: &GuiKillControlRequestV1) -> io::Result<()> {
        validate_request(request)?;
        let expected = match self.last {
            Some(last) => last.checked_add(1).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "control command sequence overflow",
                )
            })?,
            None => 1,
        };
        if request.command_sequence != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control command sequence is not contiguous",
            ));
        }
        self.last = Some(request.command_sequence);
        Ok(())
    }
}

pub(crate) fn encode_request(request: &GuiKillControlRequestV1) -> io::Result<Vec<u8>> {
    validate_request(request)?;
    encode_frame(request)
}

pub(crate) fn decode_request(bytes: &[u8]) -> io::Result<GuiKillControlRequestV1> {
    reject_legacy_schema(
        bytes,
        "schema",
        GUI_KILL_CONTROL_REQUEST_SCHEMA,
        GUI_KILL_CONTROL_REQUEST_V1_SCHEMA,
    )?;
    let request = decode_frame(bytes)?;
    validate_request(&request)?;
    Ok(request)
}

pub(crate) fn encode_response(response: &GuiKillControlResponseV1) -> io::Result<Vec<u8>> {
    validate_response(response)?;
    encode_frame(response)
}

pub(crate) fn decode_response(bytes: &[u8]) -> io::Result<GuiKillControlResponseV1> {
    reject_legacy_schema(
        bytes,
        "schema",
        GUI_KILL_CONTROL_RESPONSE_SCHEMA,
        GUI_KILL_CONTROL_RESPONSE_V1_SCHEMA,
    )?;
    let response = decode_frame(bytes)?;
    validate_response(&response)?;
    Ok(response)
}

fn encode_frame<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let payload = serde_json::to_vec(value).map_err(invalid_data)?;
    let total_len = FRAME_PREFIX_LEN
        .checked_add(payload.len())
        .and_then(|value| value.checked_add(FRAME_CRC_LEN))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "control frame length overflow")
        })?;
    if total_len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame exceeds private harness bound",
        ));
    }
    let total_len = u32::try_from(total_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "control frame exceeds u32"))?;
    let mut frame = Vec::with_capacity(total_len as usize);
    frame.extend_from_slice(&total_len.to_le_bytes());
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(&crc32c(&payload).to_le_bytes());
    Ok(frame)
}

fn decode_frame<T: for<'a> Deserialize<'a> + Serialize>(bytes: &[u8]) -> io::Result<T> {
    if bytes.len() < FRAME_PREFIX_LEN + FRAME_CRC_LEN || bytes.len() > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame length is outside private harness bounds",
        ));
    }
    let total_len = u32::from_le_bytes(bytes[..FRAME_PREFIX_LEN].try_into().expect("fixed"));
    if total_len as usize != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame declared length does not match bytes",
        ));
    }
    let payload_end = bytes.len() - FRAME_CRC_LEN;
    let payload = &bytes[FRAME_PREFIX_LEN..payload_end];
    let expected_crc = u32::from_le_bytes(bytes[payload_end..].try_into().expect("fixed"));
    if crc32c(payload) != expected_crc {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame CRC32C mismatch",
        ));
    }
    let value: T = serde_json::from_slice(payload).map_err(invalid_data)?;
    if serde_json::to_vec(&value).map_err(invalid_data)? != payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control JSON payload is not in canonical struct encoding",
        ));
    }
    Ok(value)
}

fn reject_legacy_schema(bytes: &[u8], field: &str, expected: &str, legacy: &str) -> io::Result<()> {
    if bytes.len() < FRAME_PREFIX_LEN + FRAME_CRC_LEN || bytes.len() > MAX_FRAME_LEN {
        return Ok(());
    }
    let declared = u32::from_le_bytes(bytes[..FRAME_PREFIX_LEN].try_into().expect("fixed"));
    if declared as usize != bytes.len() {
        return Ok(());
    }
    let payload_end = bytes.len() - FRAME_CRC_LEN;
    let payload = &bytes[FRAME_PREFIX_LEN..payload_end];
    let crc = u32::from_le_bytes(bytes[payload_end..].try_into().expect("fixed"));
    if crc32c(payload) != crc {
        return Ok(());
    }
    let value: serde_json::Value = serde_json::from_slice(payload).map_err(invalid_data)?;
    if value.get(field).and_then(serde_json::Value::as_str) == Some(legacy) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "historical {legacy} control schema is explicitly rejected; expected {expected}"
            ),
        ));
    }
    Ok(())
}

fn validate_request(request: &GuiKillControlRequestV1) -> io::Result<()> {
    if request.schema != GUI_KILL_CONTROL_REQUEST_SCHEMA
        || request.command_sequence == 0
        || request.supervisor_pid == 0
        || request.supervisor_creation_time_100ns == 0
        || !is_canonical_hex_32(&request.run_id_hex)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control request common fields are invalid",
        ));
    }
    match &request.command {
        GuiKillControlCommandV1::QueryReady | GuiKillControlCommandV1::Exit => {}
        GuiKillControlCommandV1::Lifecycle {
            request_id,
            command_wire,
        } => {
            let command = RunCommandKind::from_wire(u16::from(*command_wire)).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "qualification lifecycle command wire is unknown",
                )
            })?;
            if *request_id == 0
                || !matches!(
                    command,
                    RunCommandKind::Prepare
                        | RunCommandKind::Arm
                        | RunCommandKind::Start
                        | RunCommandKind::Stop
                )
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "qualification lifecycle command is not allowed",
                ));
            }
        }
        GuiKillControlCommandV1::BaselineSnapshot { request_id } => {
            if *request_id == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "baseline snapshot request ID is invalid",
                ));
            }
        }
        GuiKillControlCommandV1::AttemptStarted {
            mode,
            gui_pid,
            gui_creation_time_100ns,
            request_id,
            barrier_request_id,
            post_kill_request_id,
            containment,
            ..
        } => {
            if *gui_pid == 0
                || *gui_creation_time_100ns == 0
                || *request_id == 0
                || *post_kill_request_id == 0
                || *post_kill_request_id <= *request_id
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "attempt identity or request order is invalid",
                ));
            }
            containment.validate()?;
            match (mode, barrier_request_id) {
                (GuiKillAttemptModeV1::AfterAck, Some(barrier))
                    if request_id.checked_add(1) == Some(*barrier)
                        && barrier.checked_add(1) == Some(*post_kill_request_id) => {}
                (GuiKillAttemptModeV1::Inflight, None)
                    if request_id.checked_add(2) == Some(*post_kill_request_id) => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "attempt barrier shape does not match mode",
                    ));
                }
            }
        }
        GuiKillControlCommandV1::StageObserved { .. }
        | GuiKillControlCommandV1::KillRequested { .. }
        | GuiKillControlCommandV1::CompleteAttempt { .. } => {}
        GuiKillControlCommandV1::ReapProven { evidence, .. } => {
            if evidence.method != GuiKillWaitMethodV2::JobObjectTermination
                || evidence.wait_result != GuiKillWaitResultV2::SignaledReaped
                || evidence.exit_code == 259
                || evidence.wait_deadline_ms == 0
                || evidence.wait_elapsed_ms > evidence.wait_deadline_ms
                || evidence.job_active_processes_after_wait != 0
                || !evidence.job_empty_proven
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reap evidence is not a primary signaled empty Job proof",
                ));
            }
        }
    }
    Ok(())
}

fn validate_response(response: &GuiKillControlResponseV1) -> io::Result<()> {
    if response.schema != GUI_KILL_CONTROL_RESPONSE_SCHEMA
        || response.command_sequence == 0
        || response.owner_pid == 0
        || response.owner_creation_time_100ns == 0
        || !is_canonical_hex_64(&response.owner_executable_sha256_hex)
        || !is_qualification_pipe_name(&response.gui_pipe_name)
        || !is_qualification_pipe_name(&response.control_pipe_name)
        || response.gui_pipe_name == response.control_pipe_name
        || response.supervisor_pid == 0
        || response.supervisor_creation_time_100ns == 0
        || !is_canonical_hex_32(&response.run_id_hex)
        || response.error_code.is_empty()
        || !response.error_code.is_ascii()
        || response.active_epoch == Some(0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control response common fields are invalid",
        ));
    }
    RunState::from_wire(response.state_wire).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "control response contains an unknown Run state",
        )
    })?;
    if response.accepted && response.error_code != "none" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "accepted control response must use error_code=none",
        ));
    }
    if !response.accepted && response.error_code == "none" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rejected control response requires a non-none error code",
        ));
    }
    Ok(())
}

fn is_qualification_pipe_name(value: &str) -> bool {
    value.starts_with(r"\\.\pipe\forge-acqd-gui-kill-v3-") && value.is_ascii() && value.len() <= 240
}

fn is_canonical_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_hex_32(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_data(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(command: GuiKillControlCommandV1) -> GuiKillControlRequestV1 {
        GuiKillControlRequestV1 {
            schema: GUI_KILL_CONTROL_REQUEST_SCHEMA.to_owned(),
            command_sequence: 7,
            supervisor_pid: 42,
            supervisor_creation_time_100ns: 99,
            run_id_hex: "a".repeat(32),
            command,
        }
    }

    fn response() -> GuiKillControlResponseV1 {
        GuiKillControlResponseV1 {
            schema: GUI_KILL_CONTROL_RESPONSE_SCHEMA.to_owned(),
            command_sequence: 7,
            run_id_hex: "a".repeat(32),
            accepted: true,
            error_code: "none".to_owned(),
            owner_pid: 43,
            owner_creation_time_100ns: 100,
            owner_executable_sha256_hex: "b".repeat(64),
            gui_pipe_name: r"\\.\pipe\forge-acqd-gui-kill-v3-gui-test".to_owned(),
            control_pipe_name: r"\\.\pipe\forge-acqd-gui-kill-v3-control-test".to_owned(),
            supervisor_pid: 42,
            supervisor_creation_time_100ns: 99,
            state_wire: 3,
            active_epoch: Some(1),
            committed_record_count: 11,
            durable_record_count: 10,
            audit_event_sequence: 9,
        }
    }

    fn containment() -> GuiKillContainmentEvidenceV2 {
        GuiKillContainmentEvidenceV2 {
            created_suspended: true,
            kill_on_job_close_configured: true,
            job_assigned_before_resume: true,
            executable_rehashed_before_resume: true,
        }
    }

    fn reap() -> GuiKillReapEvidenceV2 {
        GuiKillReapEvidenceV2 {
            method: GuiKillWaitMethodV2::JobObjectTermination,
            exit_code: 42,
            wait_deadline_ms: 250,
            wait_elapsed_ms: 7,
            wait_result: GuiKillWaitResultV2::SignaledReaped,
            job_active_processes_after_wait: 0,
            job_empty_proven: true,
        }
    }

    #[test]
    fn every_control_variant_round_trips() {
        let variants = vec![
            GuiKillControlCommandV1::QueryReady,
            GuiKillControlCommandV1::Lifecycle {
                request_id: 1,
                command_wire: 1,
            },
            GuiKillControlCommandV1::BaselineSnapshot { request_id: 2 },
            GuiKillControlCommandV1::AttemptStarted {
                attempt: 0,
                mode: GuiKillAttemptModeV1::AfterAck,
                gui_pid: 5,
                gui_creation_time_100ns: 6,
                request_id: 10,
                barrier_request_id: Some(11),
                post_kill_request_id: 12,
                containment: containment(),
            },
            GuiKillControlCommandV1::AttemptStarted {
                attempt: 1,
                mode: GuiKillAttemptModeV1::Inflight,
                gui_pid: 5,
                gui_creation_time_100ns: 6,
                request_id: 13,
                barrier_request_id: None,
                post_kill_request_id: 15,
                containment: containment(),
            },
            GuiKillControlCommandV1::StageObserved { attempt: 0 },
            GuiKillControlCommandV1::KillRequested { attempt: 0 },
            GuiKillControlCommandV1::ReapProven {
                attempt: 0,
                evidence: reap(),
            },
            GuiKillControlCommandV1::CompleteAttempt { attempt: 0 },
            GuiKillControlCommandV1::Exit,
        ];
        for command in variants {
            let request = request(command);
            assert_eq!(
                decode_request(&encode_request(&request).unwrap()).unwrap(),
                request
            );
        }
    }

    #[test]
    fn request_frame_rejects_truncation_crc_length_schema_and_unknown_fields() {
        let encoded = encode_request(&request(GuiKillControlCommandV1::QueryReady)).unwrap();
        for length in 0..encoded.len() {
            assert!(
                decode_request(&encoded[..length]).is_err(),
                "truncation at {length}"
            );
        }
        let mut crc_tamper = encoded.clone();
        let last = crc_tamper.len() - 1;
        crc_tamper[last] ^= 0x01;
        assert!(decode_request(&crc_tamper).is_err());
        let mut length_tamper = encoded.clone();
        length_tamper[0] ^= 0x01;
        assert!(decode_request(&length_tamper).is_err());
        let mut schema = request(GuiKillControlCommandV1::QueryReady);
        schema.schema = "wrong".to_owned();
        assert!(encode_request(&schema).is_err());
        let payload = br#"{"schema":"forge.gui-kill-control-request.v2","command_sequence":1,"supervisor_pid":1,"supervisor_creation_time_100ns":1,"run_id_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":{"kind":"query_ready"},"extra":true}"#;
        let mut unknown = Vec::new();
        unknown.extend_from_slice(
            &u32::try_from(FRAME_PREFIX_LEN + payload.len() + FRAME_CRC_LEN)
                .unwrap()
                .to_le_bytes(),
        );
        unknown.extend_from_slice(payload);
        unknown.extend_from_slice(&crc32c(payload).to_le_bytes());
        assert!(decode_request(&unknown).is_err());
        let bad_mode = br#"{"schema":"forge.gui-kill-control-request.v2","command_sequence":1,"supervisor_pid":1,"supervisor_creation_time_100ns":1,"run_id_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":{"kind":"attempt_started","attempt":0,"mode":"other","gui_pid":1,"gui_creation_time_100ns":1,"request_id":2,"barrier_request_id":null,"post_kill_request_id":3}}"#;
        let mut invalid_mode = Vec::new();
        invalid_mode.extend_from_slice(
            &u32::try_from(FRAME_PREFIX_LEN + bad_mode.len() + FRAME_CRC_LEN)
                .unwrap()
                .to_le_bytes(),
        );
        invalid_mode.extend_from_slice(bad_mode);
        invalid_mode.extend_from_slice(&crc32c(bad_mode).to_le_bytes());
        assert!(decode_request(&invalid_mode).is_err());
        let mut oversize = vec![0_u8; MAX_FRAME_LEN + 1];
        let oversize_len = u32::try_from(oversize.len()).unwrap();
        oversize[..FRAME_PREFIX_LEN].copy_from_slice(&oversize_len.to_le_bytes());
        assert!(decode_request(&oversize).is_err());
    }

    #[test]
    fn request_rejects_zero_identity_and_bad_attempt_shapes() {
        let mut zero = request(GuiKillControlCommandV1::QueryReady);
        zero.command_sequence = 0;
        assert!(encode_request(&zero).is_err());
        zero = request(GuiKillControlCommandV1::QueryReady);
        zero.supervisor_pid = 0;
        assert!(encode_request(&zero).is_err());
        zero = request(GuiKillControlCommandV1::QueryReady);
        zero.run_id_hex = "A".repeat(32);
        assert!(encode_request(&zero).is_err());
        assert!(encode_request(&request(GuiKillControlCommandV1::Lifecycle {
            request_id: 1,
            command_wire: 0,
        }))
        .is_err());
        assert!(encode_request(&request(GuiKillControlCommandV1::Lifecycle {
            request_id: 1,
            command_wire: RunCommandKind::Abort.wire_value() as u8,
        }))
        .is_err());
        let bad_after_ack = request(GuiKillControlCommandV1::AttemptStarted {
            attempt: 0,
            mode: GuiKillAttemptModeV1::AfterAck,
            gui_pid: 1,
            gui_creation_time_100ns: 1,
            request_id: 3,
            barrier_request_id: None,
            post_kill_request_id: 5,
            containment: containment(),
        });
        assert!(encode_request(&bad_after_ack).is_err());
        let bad_inflight = request(GuiKillControlCommandV1::AttemptStarted {
            attempt: 0,
            mode: GuiKillAttemptModeV1::Inflight,
            gui_pid: 1,
            gui_creation_time_100ns: 1,
            request_id: 3,
            barrier_request_id: Some(4),
            post_kill_request_id: 5,
            containment: containment(),
        });
        assert!(encode_request(&bad_inflight).is_err());
    }

    #[test]
    fn containment_and_reap_evidence_mutations_fail_closed() {
        for index in 0..4 {
            let mut evidence = containment();
            match index {
                0 => evidence.created_suspended = false,
                1 => evidence.kill_on_job_close_configured = false,
                2 => evidence.job_assigned_before_resume = false,
                3 => evidence.executable_rehashed_before_resume = false,
                _ => unreachable!(),
            }
            let request = request(GuiKillControlCommandV1::AttemptStarted {
                attempt: 0,
                mode: GuiKillAttemptModeV1::AfterAck,
                gui_pid: 5,
                gui_creation_time_100ns: 6,
                request_id: 10,
                barrier_request_id: Some(11),
                post_kill_request_id: 12,
                containment: evidence,
            });
            assert!(
                encode_request(&request).is_err(),
                "containment fact {index}"
            );
        }

        for index in 0..6 {
            let mut evidence = reap();
            match index {
                0 => evidence.method = GuiKillWaitMethodV2::GracefulWait,
                1 => evidence.exit_code = 259,
                2 => evidence.wait_deadline_ms = 0,
                3 => evidence.wait_elapsed_ms = evidence.wait_deadline_ms + 1,
                4 => evidence.job_active_processes_after_wait = 1,
                5 => evidence.job_empty_proven = false,
                _ => unreachable!(),
            }
            let request = request(GuiKillControlCommandV1::ReapProven {
                attempt: 0,
                evidence,
            });
            assert!(encode_request(&request).is_err(), "reap fact {index}");
        }
    }

    #[test]
    fn response_round_trip_and_tamper_are_strict() {
        let valid_response = response();
        let encoded = encode_response(&valid_response).unwrap();
        assert_eq!(decode_response(&encoded).unwrap(), valid_response);
        let mut tampered = encoded.clone();
        tampered[FRAME_PREFIX_LEN] ^= 1;
        assert!(decode_response(&tampered).is_err());
        let mut rejected = valid_response;
        rejected.accepted = false;
        assert!(encode_response(&rejected).is_err());
        let mut bad_run = response();
        bad_run.run_id_hex = "A".repeat(32);
        assert!(encode_response(&bad_run).is_err());
    }

    #[test]
    fn sequence_guard_rejects_replay_and_reordering() {
        let mut guard = GuiKillControlSequenceV1::default();
        let mut first = request(GuiKillControlCommandV1::QueryReady);
        first.command_sequence = 1;
        guard.observe(&first).unwrap();
        assert!(guard.observe(&first).is_err());
        let mut lower = request(GuiKillControlCommandV1::Exit);
        lower.command_sequence = 0;
        assert!(guard.observe(&lower).is_err());
        let mut next = request(GuiKillControlCommandV1::Exit);
        next.command_sequence = 2;
        assert!(guard.observe(&next).is_ok());
        let mut skipped = request(GuiKillControlCommandV1::Exit);
        skipped.command_sequence = 4;
        assert!(guard.observe(&skipped).is_err());
    }
}
