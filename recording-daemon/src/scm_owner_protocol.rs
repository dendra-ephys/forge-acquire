//! Private, local SCM-supervisor to owner-process framing.
//!
//! This module is deliberately independent of the frozen low-speed IDL and of
//! the GUI qualification harness.  A request stream is strictly ordered and
//! non-idempotent: `command_sequence` starts at one, each `request_id` may be
//! observed once, and no command is accepted after `GracefulShutdown`.

use std::collections::HashSet;
use std::io;
use std::path::Path;

use forge_protocol_v1::crc32c;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

use crate::ipc::AuthenticatedPipeClient;
use crate::run::RunState;
use crate::scm_stop_receipt::StableFileBindingV1;

pub(crate) const SCM_OWNER_REQUEST_SCHEMA: &str = "forge.scm-owner-request.v1";
pub(crate) const SCM_OWNER_RESPONSE_SCHEMA: &str = "forge.scm-owner-response.v1";

const MAX_FRAME_LEN: usize = 16 * 1024;
const LENGTH_LEN: usize = 4;
const MAGIC_LEN: usize = 4;
const VERSION_LEN: usize = 1;
const KIND_LEN: usize = 1;
const RESERVED_LEN: usize = 2;
const HEADER_AFTER_LENGTH_LEN: usize = MAGIC_LEN + VERSION_LEN + KIND_LEN + RESERVED_LEN;
const CRC_LEN: usize = 4;
const MAGIC: [u8; MAGIC_LEN] = *b"FSOP";
const VERSION: u8 = 1;
const REQUEST_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;
const MAX_COMMAND_LEAD_NS: u64 = 30_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScmOwnerCommandV1 {
    QueryReady,
    ActivatePublic,
    GetSnapshot,
    GracefulShutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScmOwnerPhaseV1 {
    Starting,
    Running,
    Stopping,
    ShutdownSealed,
    ShutdownFailedClosed,
    ExitedFailClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScmOwnerErrorCodeV1 {
    None,
    BadRequest,
    DeadlineExpired,
    OwnerUnavailable,
    ShutdownInProgress,
    FailClosed,
    InternalError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScmOwnerRequestV1 {
    pub schema: String,
    pub service_instance_id: [u8; 32],
    pub supervisor_pid: u32,
    pub supervisor_creation_time_100ns: u64,
    pub owner_pid: u32,
    pub owner_creation_time_100ns: u64,
    pub supervisor_executable_sha256: [u8; 32],
    pub owner_executable_sha256: [u8; 32],
    pub command_sequence: u64,
    pub request_id: u64,
    /// Absolute system-wide QPC-derived nanoseconds. Rust `Instant` values are
    /// process-relative and must never be placed on this wire.
    pub deadline_qpc_ns: u64,
    pub command: ScmOwnerCommandV1,
    /// Present only on `graceful_shutdown`.  The supervisor persists this
    /// exact binding before sending the private shutdown request.
    pub stop_intent: Option<StableFileBindingV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScmOwnerResponseV1 {
    pub schema: String,
    pub service_instance_id: [u8; 32],
    pub supervisor_pid: u32,
    pub supervisor_creation_time_100ns: u64,
    pub owner_pid: u32,
    pub owner_creation_time_100ns: u64,
    pub supervisor_executable_sha256: [u8; 32],
    pub owner_executable_sha256: [u8; 32],
    pub command_sequence: u64,
    pub request_id: u64,
    pub accepted: bool,
    pub error_code: ScmOwnerErrorCodeV1,
    pub owner_phase: ScmOwnerPhaseV1,
    pub public_control_pipe_name: String,
    pub public_hardware_pipe_name: String,
    pub public_analysis_pipe_name: Option<String>,
    pub run_state_wire: u8,
    pub active_epoch: Option<u64>,
    pub active_run_id: Option<[u8; 16]>,
    pub committed_record_count: u64,
    pub durable_record_count: u64,
    pub sealed_record_count: u64,
    pub hardware_available: bool,
    pub shutdown_receipt_path: Option<String>,
    pub shutdown_receipt_sha256: Option<[u8; 32]>,
}

/// Stateful owner-side guard for one immutable supervisor/owner instance.
///
/// Request IDs are intentionally *not* idempotent at this private boundary:
/// a retry receives a fresh command sequence and request ID after the caller
/// has established that no prior response was accepted.  This prevents a
/// delayed duplicate shutdown from being mistaken for a current command.
#[derive(Clone, Debug)]
pub(crate) struct SequenceGuard {
    expected: ExpectedOwnerControlPeer,
    next_command_sequence: u64,
    seen_request_ids: HashSet<u64>,
    shutdown_seen: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedOwnerControlPeer {
    pub service_instance_id: [u8; 32],
    pub supervisor_pid: u32,
    pub supervisor_creation_time_100ns: u64,
    pub supervisor_executable_sha256: [u8; 32],
    pub owner_pid: u32,
    pub owner_creation_time_100ns: u64,
    pub owner_executable_sha256: [u8; 32],
}

impl ExpectedOwnerControlPeer {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if !nonzero_bytes(&self.service_instance_id)
            || self.supervisor_pid == 0
            || self.supervisor_creation_time_100ns == 0
            || !nonzero_bytes(&self.supervisor_executable_sha256)
            || self.owner_pid == 0
            || self.owner_creation_time_100ns == 0
            || !nonzero_bytes(&self.owner_executable_sha256)
        {
            return invalid("expected owner-control peer identity is invalid");
        }
        Ok(())
    }
}

impl SequenceGuard {
    pub(crate) fn new(expected: ExpectedOwnerControlPeer) -> io::Result<Self> {
        expected.validate()?;
        Ok(Self {
            expected,
            next_command_sequence: 1,
            seen_request_ids: HashSet::new(),
            shutdown_seen: false,
        })
    }

    pub(crate) fn observe(
        &mut self,
        authenticated_client: &AuthenticatedPipeClient,
        request: &ScmOwnerRequestV1,
        now_qpc_ns: u64,
    ) -> io::Result<()> {
        validate_authenticated_owner_request(
            authenticated_client,
            &self.expected,
            request,
            now_qpc_ns,
        )?;
        if self.shutdown_seen {
            return invalid("owner control command arrived after graceful shutdown");
        }
        if request.command_sequence != self.next_command_sequence {
            return invalid("owner control command sequence is not strictly contiguous");
        }
        if !self.seen_request_ids.insert(request.request_id) {
            return invalid("owner control request ID was replayed");
        }
        self.next_command_sequence =
            self.next_command_sequence.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "command sequence overflow")
            })?;
        if request.command == ScmOwnerCommandV1::GracefulShutdown {
            self.shutdown_seen = true;
        }
        Ok(())
    }
}

pub(crate) fn validate_authenticated_owner_request(
    authenticated_client: &AuthenticatedPipeClient,
    expected: &ExpectedOwnerControlPeer,
    request: &ScmOwnerRequestV1,
    now_qpc_ns: u64,
) -> io::Result<()> {
    expected.validate()?;
    validate_request(request)?;
    if authenticated_client.process_id != expected.supervisor_pid
        || authenticated_client.process_creation_time_100ns
            != expected.supervisor_creation_time_100ns
        || request.service_instance_id != expected.service_instance_id
        || request.supervisor_pid != expected.supervisor_pid
        || request.supervisor_creation_time_100ns != expected.supervisor_creation_time_100ns
        || request.supervisor_executable_sha256 != expected.supervisor_executable_sha256
        || request.owner_pid != expected.owner_pid
        || request.owner_creation_time_100ns != expected.owner_creation_time_100ns
        || request.owner_executable_sha256 != expected.owner_executable_sha256
    {
        return invalid("authenticated owner-control identity does not match frozen peer");
    }
    if now_qpc_ns == 0 || request.deadline_qpc_ns <= now_qpc_ns {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "owner-control command deadline expired",
        ));
    }
    if request.deadline_qpc_ns - now_qpc_ns > MAX_COMMAND_LEAD_NS {
        return invalid("owner-control command deadline exceeds the 30-second bound");
    }
    Ok(())
}

pub(crate) fn encode_request(request: &ScmOwnerRequestV1) -> io::Result<Vec<u8>> {
    validate_request(request)?;
    encode_frame(REQUEST_KIND, request)
}

pub(crate) fn decode_request(bytes: &[u8]) -> io::Result<ScmOwnerRequestV1> {
    let request = decode_frame(REQUEST_KIND, bytes)?;
    validate_request(&request)?;
    Ok(request)
}

pub(crate) fn encode_response(response: &ScmOwnerResponseV1) -> io::Result<Vec<u8>> {
    validate_response(response)?;
    encode_frame(RESPONSE_KIND, response)
}

pub(crate) fn decode_response(bytes: &[u8]) -> io::Result<ScmOwnerResponseV1> {
    let response = decode_frame(RESPONSE_KIND, bytes)?;
    validate_response(&response)?;
    Ok(response)
}

/// Checks that an owner response is a response to this exact request rather
/// than merely a syntactically valid message from some local process.
pub(crate) fn validate_response_for_request(
    request: &ScmOwnerRequestV1,
    response: &ScmOwnerResponseV1,
) -> io::Result<()> {
    validate_request(request)?;
    validate_response(response)?;
    if request.service_instance_id != response.service_instance_id
        || request.supervisor_pid != response.supervisor_pid
        || request.supervisor_creation_time_100ns != response.supervisor_creation_time_100ns
        || request.owner_pid != response.owner_pid
        || request.owner_creation_time_100ns != response.owner_creation_time_100ns
        || request.supervisor_executable_sha256 != response.supervisor_executable_sha256
        || request.owner_executable_sha256 != response.owner_executable_sha256
        || request.command_sequence != response.command_sequence
        || request.request_id != response.request_id
    {
        return invalid("owner response does not echo request identity");
    }
    match request.command {
        ScmOwnerCommandV1::QueryReady
        | ScmOwnerCommandV1::ActivatePublic
        | ScmOwnerCommandV1::GetSnapshot => {
            if matches!(
                response.owner_phase,
                ScmOwnerPhaseV1::ShutdownSealed
                    | ScmOwnerPhaseV1::ShutdownFailedClosed
                    | ScmOwnerPhaseV1::ExitedFailClosed
            ) {
                return invalid("non-shutdown request received a terminal shutdown response");
            }
        }
        ScmOwnerCommandV1::GracefulShutdown => {
            if response.accepted
                && !matches!(
                    response.owner_phase,
                    ScmOwnerPhaseV1::Stopping | ScmOwnerPhaseV1::ShutdownSealed
                )
            {
                return invalid("accepted graceful shutdown response is not stopping or sealed");
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_activation_response(response: &ScmOwnerResponseV1) -> io::Result<()> {
    validate_response(response)?;
    if !response.accepted
        || response.error_code != ScmOwnerErrorCodeV1::None
        || response.owner_phase != ScmOwnerPhaseV1::Running
        || response.shutdown_receipt_path.is_some()
        || response.shutdown_receipt_sha256.is_some()
    {
        return invalid("owner public-activation response is not Running");
    }
    Ok(())
}

pub(crate) fn validate_ready_response(
    response: &ScmOwnerResponseV1,
    expected_control_pipe: &str,
    expected_hardware_pipe: &str,
    expected_analysis_pipe: Option<&str>,
) -> io::Result<()> {
    validate_response(response)?;
    if !response.accepted
        || response.error_code != ScmOwnerErrorCodeV1::None
        || response.owner_phase != ScmOwnerPhaseV1::Running
        || response.public_control_pipe_name != expected_control_pipe
        || response.public_hardware_pipe_name != expected_hardware_pipe
        || response.public_analysis_pipe_name.as_deref() != expected_analysis_pipe
        || response.shutdown_receipt_path.is_some()
        || response.shutdown_receipt_sha256.is_some()
    {
        return invalid("owner ready response does not match frozen runtime endpoints");
    }
    Ok(())
}

/// Returns a system-wide monotonic timestamp suitable for the owner protocol.
/// QPC counter values and frequency are shared across Windows processes; this
/// deliberately does not use a process-relative `Instant` origin.
pub(crate) fn qpc_now_ns() -> io::Result<u64> {
    let mut counter = 0_i64;
    let mut frequency = 0_i64;
    if unsafe { QueryPerformanceFrequency(&mut frequency) } == 0
        || unsafe { QueryPerformanceCounter(&mut counter) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if counter <= 0 || frequency <= 0 {
        return invalid("Windows QPC returned a non-positive value");
    }
    let counter = u64::try_from(counter)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "QPC counter is negative"))?;
    let frequency = u64::try_from(frequency)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "QPC frequency is negative"))?;
    let nanoseconds = u128::from(counter)
        .checked_mul(1_000_000_000)
        .map(|scaled| scaled / u128::from(frequency))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "QPC nanoseconds overflow"))?;
    u64::try_from(nanoseconds)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "QPC nanoseconds exceed u64"))
}

fn encode_frame<T: Serialize>(kind: u8, value: &T) -> io::Result<Vec<u8>> {
    let payload = serde_json::to_vec(value).map_err(invalid_data)?;
    let total_len = LENGTH_LEN
        .checked_add(HEADER_AFTER_LENGTH_LEN)
        .and_then(|value| value.checked_add(payload.len()))
        .and_then(|value| value.checked_add(CRC_LEN))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "owner frame length overflow"))?;
    if total_len > MAX_FRAME_LEN {
        return invalid("owner frame exceeds 16 KiB bound");
    }
    let total_len = u32::try_from(total_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "owner frame exceeds u32"))?;
    let mut bytes = Vec::with_capacity(total_len as usize);
    bytes.extend_from_slice(&total_len.to_le_bytes());
    bytes.extend_from_slice(&MAGIC);
    bytes.push(VERSION);
    bytes.push(kind);
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&crc32c(&bytes[LENGTH_LEN..]).to_le_bytes());
    Ok(bytes)
}

fn decode_frame<T>(expected_kind: u8, bytes: &[u8]) -> io::Result<T>
where
    T: for<'a> Deserialize<'a> + Serialize,
{
    let minimum = LENGTH_LEN + HEADER_AFTER_LENGTH_LEN + CRC_LEN;
    if bytes.len() < minimum || bytes.len() > MAX_FRAME_LEN {
        return invalid("owner frame length is outside allowed bounds");
    }
    let declared =
        u32::from_le_bytes(bytes[..LENGTH_LEN].try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "owner frame missing length")
        })?);
    if usize::try_from(declared).ok() != Some(bytes.len()) {
        return invalid("owner frame declared length does not match bytes");
    }
    if bytes[LENGTH_LEN..LENGTH_LEN + MAGIC_LEN] != MAGIC {
        return invalid("owner frame magic is invalid");
    }
    let version_index = LENGTH_LEN + MAGIC_LEN;
    if bytes[version_index] != VERSION {
        return invalid("owner frame version is unsupported");
    }
    if bytes[version_index + VERSION_LEN] != expected_kind {
        return invalid("owner frame kind does not match endpoint");
    }
    let reserved_start = version_index + VERSION_LEN + KIND_LEN;
    if bytes[reserved_start..reserved_start + RESERVED_LEN] != [0, 0] {
        return invalid("owner frame reserved bits are nonzero");
    }
    let crc_start = bytes.len() - CRC_LEN;
    let expected_crc = u32::from_le_bytes(
        bytes[crc_start..]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "owner frame missing CRC"))?,
    );
    if crc32c(&bytes[LENGTH_LEN..crc_start]) != expected_crc {
        return invalid("owner frame CRC32C mismatch");
    }
    let payload_start = LENGTH_LEN + HEADER_AFTER_LENGTH_LEN;
    let payload = &bytes[payload_start..crc_start];
    let value: T = serde_json::from_slice(payload).map_err(invalid_data)?;
    if serde_json::to_vec(&value).map_err(invalid_data)? != payload {
        return invalid("owner JSON payload is not canonical");
    }
    Ok(value)
}

fn validate_request(request: &ScmOwnerRequestV1) -> io::Result<()> {
    if request.schema != SCM_OWNER_REQUEST_SCHEMA
        || !nonzero_bytes(&request.service_instance_id)
        || request.supervisor_pid == 0
        || request.supervisor_creation_time_100ns == 0
        || request.owner_pid == 0
        || request.owner_creation_time_100ns == 0
        || !nonzero_bytes(&request.supervisor_executable_sha256)
        || !nonzero_bytes(&request.owner_executable_sha256)
        || request.command_sequence == 0
        || request.request_id == 0
        || request.deadline_qpc_ns == 0
    {
        return invalid("owner request common identity fields are invalid");
    }
    match (&request.command, &request.stop_intent) {
        (ScmOwnerCommandV1::GracefulShutdown, Some(binding)) => {
            validate_stop_intent_binding(binding)?
        }
        (ScmOwnerCommandV1::GracefulShutdown, None) => {
            return invalid("graceful shutdown lacks a persisted StopIntent binding")
        }
        (_, None) => {}
        (_, Some(_)) => return invalid("non-shutdown owner command carries StopIntent evidence"),
    }
    Ok(())
}

fn validate_response(response: &ScmOwnerResponseV1) -> io::Result<()> {
    if response.schema != SCM_OWNER_RESPONSE_SCHEMA
        || !nonzero_bytes(&response.service_instance_id)
        || response.supervisor_pid == 0
        || response.supervisor_creation_time_100ns == 0
        || response.owner_pid == 0
        || response.owner_creation_time_100ns == 0
        || !nonzero_bytes(&response.supervisor_executable_sha256)
        || !nonzero_bytes(&response.owner_executable_sha256)
        || response.command_sequence == 0
        || response.request_id == 0
        || !is_local_pipe_name(&response.public_control_pipe_name)
        || !is_local_pipe_name(&response.public_hardware_pipe_name)
        || response
            .public_control_pipe_name
            .eq_ignore_ascii_case(&response.public_hardware_pipe_name)
        || response.active_epoch == Some(0)
        || response.active_run_id == Some([0; 16])
        || response.durable_record_count > response.committed_record_count
        || response.sealed_record_count > response.durable_record_count
    {
        return invalid("owner response common fields are invalid");
    }
    if let Some(analysis) = &response.public_analysis_pipe_name {
        if !is_local_pipe_name(analysis)
            || analysis.eq_ignore_ascii_case(&response.public_control_pipe_name)
            || analysis.eq_ignore_ascii_case(&response.public_hardware_pipe_name)
        {
            return invalid("owner response analysis pipe is invalid or non-unique");
        }
    }
    match (
        &response.shutdown_receipt_path,
        &response.shutdown_receipt_sha256,
    ) {
        (None, None) => {}
        (Some(path), Some(hash)) if is_receipt_path(path) && nonzero_bytes(hash) => {}
        _ => return invalid("owner shutdown receipt path/hash shape is invalid"),
    }
    if response.accepted {
        if response.error_code != ScmOwnerErrorCodeV1::None
            || matches!(
                response.owner_phase,
                ScmOwnerPhaseV1::ShutdownFailedClosed | ScmOwnerPhaseV1::ExitedFailClosed
            )
        {
            return invalid("accepted owner response contradicts error or fail-closed phase");
        }
    } else if response.error_code == ScmOwnerErrorCodeV1::None {
        return invalid("rejected owner response must carry an error code");
    }

    let run_state = RunState::from_wire(response.run_state_wire)?;
    if matches!(
        run_state,
        RunState::Prepared | RunState::Armed | RunState::Recording
    ) && (response.active_epoch.is_none() || response.active_run_id.is_none())
    {
        return invalid("active Run state lacks an epoch or Run identity");
    }
    if response.active_epoch.is_some() != response.active_run_id.is_some() {
        return invalid("owner response Run epoch and identity disagree");
    }
    if response.active_epoch.is_some()
        && (run_state == RunState::JournalSealed || response.sealed_record_count != 0)
    {
        return invalid("active Run cannot claim a sealed journal");
    }
    if run_state == RunState::Recording && response.sealed_record_count != 0 {
        return invalid("Recording cannot claim sealed records");
    }
    match response.owner_phase {
        ScmOwnerPhaseV1::Starting | ScmOwnerPhaseV1::Running | ScmOwnerPhaseV1::Stopping => {
            if response.shutdown_receipt_path.is_some() {
                return invalid("nonterminal owner phase cannot claim a shutdown receipt");
            }
        }
        ScmOwnerPhaseV1::ShutdownSealed => {
            if !response.accepted
                || response.error_code != ScmOwnerErrorCodeV1::None
                || response.active_epoch.is_some()
                || response.shutdown_receipt_path.is_none()
            {
                return invalid("sealed shutdown response lacks terminal receipt semantics");
            }
        }
        ScmOwnerPhaseV1::ShutdownFailedClosed | ScmOwnerPhaseV1::ExitedFailClosed => {
            if response.accepted
                || response.error_code != ScmOwnerErrorCodeV1::FailClosed
                || response.active_epoch.is_some()
            {
                return invalid("fail-closed shutdown response is semantically inconsistent");
            }
        }
    }
    Ok(())
}

fn validate_stop_intent_binding(binding: &StableFileBindingV1) -> io::Result<()> {
    if !Path::new(&binding.path).is_absolute()
        || binding.sha256_hex.len() != 64
        || !binding
            .sha256_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !binding.sha256_hex.bytes().any(|byte| byte != b'0')
        || binding.file_identity.volume_serial_number == 0
        || binding.file_identity.file_index == 0
    {
        return invalid("private graceful shutdown StopIntent binding is malformed");
    }
    Ok(())
}

fn nonzero_bytes(bytes: &[u8; 32]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

fn is_local_pipe_name(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix(r"\\.\pipe\") else {
        return false;
    };
    !suffix.is_empty()
        && !suffix.contains('\\')
        && value.len() <= 240
        && value.is_ascii()
        && !value.bytes().any(|byte| byte == b'\0')
}

fn is_receipt_path(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32_767 && !value.bytes().any(|byte| byte == b'\0')
}

fn invalid<T>(message: &'static str) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn invalid_data(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(command: ScmOwnerCommandV1) -> ScmOwnerRequestV1 {
        ScmOwnerRequestV1 {
            schema: SCM_OWNER_REQUEST_SCHEMA.to_owned(),
            service_instance_id: [1; 32],
            supervisor_pid: 101,
            supervisor_creation_time_100ns: 102,
            owner_pid: 201,
            owner_creation_time_100ns: 202,
            supervisor_executable_sha256: [3; 32],
            owner_executable_sha256: [4; 32],
            command_sequence: 1,
            request_id: 1001,
            deadline_qpc_ns: 1_000_000,
            command,
            stop_intent: (command == ScmOwnerCommandV1::GracefulShutdown).then(|| {
                StableFileBindingV1 {
                    path: r"C:\forge\stop.intent.json".to_owned(),
                    sha256_hex: "11".repeat(32),
                    file_identity: crate::scm_stop_receipt::StableFileIdentityV1 {
                        volume_serial_number: 1,
                        file_index: 2,
                        bytes: 3,
                    },
                }
            }),
        }
    }

    fn expected_peer() -> ExpectedOwnerControlPeer {
        ExpectedOwnerControlPeer {
            service_instance_id: [1; 32],
            supervisor_pid: 101,
            supervisor_creation_time_100ns: 102,
            supervisor_executable_sha256: [3; 32],
            owner_pid: 201,
            owner_creation_time_100ns: 202,
            owner_executable_sha256: [4; 32],
        }
    }

    fn authenticated_supervisor() -> AuthenticatedPipeClient {
        AuthenticatedPipeClient {
            token_user_sid: "S-1-5-18".to_owned(),
            process_id: 101,
            process_creation_time_100ns: 102,
        }
    }

    fn response() -> ScmOwnerResponseV1 {
        ScmOwnerResponseV1 {
            schema: SCM_OWNER_RESPONSE_SCHEMA.to_owned(),
            service_instance_id: [1; 32],
            supervisor_pid: 101,
            supervisor_creation_time_100ns: 102,
            owner_pid: 201,
            owner_creation_time_100ns: 202,
            supervisor_executable_sha256: [3; 32],
            owner_executable_sha256: [4; 32],
            command_sequence: 1,
            request_id: 1001,
            accepted: true,
            error_code: ScmOwnerErrorCodeV1::None,
            owner_phase: ScmOwnerPhaseV1::Running,
            public_control_pipe_name: r"\\.\pipe\forge-acqd-control-test".to_owned(),
            public_hardware_pipe_name: r"\\.\pipe\forge-acqd-hardware-test".to_owned(),
            public_analysis_pipe_name: Some(r"\\.\pipe\forge-acqd-analysis-test".to_owned()),
            run_state_wire: RunState::New.wire_value(),
            active_epoch: None,
            active_run_id: None,
            committed_record_count: 0,
            durable_record_count: 0,
            sealed_record_count: 0,
            hardware_available: false,
            shutdown_receipt_path: None,
            shutdown_receipt_sha256: None,
        }
    }

    fn raw_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let total = LENGTH_LEN + HEADER_AFTER_LENGTH_LEN + payload.len() + CRC_LEN;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::try_from(total).unwrap().to_le_bytes());
        bytes.extend_from_slice(&MAGIC);
        bytes.push(VERSION);
        bytes.push(kind);
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&crc32c(&bytes[LENGTH_LEN..]).to_le_bytes());
        bytes
    }

    #[test]
    fn every_command_round_trips_and_response_echoes_identity() {
        for command in [
            ScmOwnerCommandV1::QueryReady,
            ScmOwnerCommandV1::ActivatePublic,
            ScmOwnerCommandV1::GetSnapshot,
            ScmOwnerCommandV1::GracefulShutdown,
        ] {
            let request = request(command);
            assert_eq!(
                decode_request(&encode_request(&request).unwrap()).unwrap(),
                request
            );
        }
        let request = request(ScmOwnerCommandV1::QueryReady);
        let response = response();
        assert_eq!(
            decode_response(&encode_response(&response).unwrap()).unwrap(),
            response
        );
        validate_response_for_request(&request, &response).unwrap();
    }

    #[test]
    fn request_frame_rejects_every_truncation_and_byte_tamper() {
        let frame = encode_request(&request(ScmOwnerCommandV1::QueryReady)).unwrap();
        for length in 0..frame.len() {
            assert!(
                decode_request(&frame[..length]).is_err(),
                "truncation at {length}"
            );
        }
        for index in 0..frame.len() {
            let mut tampered = frame.clone();
            tampered[index] ^= 1;
            assert!(decode_request(&tampered).is_err(), "tamper at {index}");
        }
    }

    #[test]
    fn decoder_rejects_crc_unknown_and_noncanonical_payloads() {
        let unknown = br#"{"schema":"forge.scm-owner-request.v1","service_instance_id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"supervisor_pid":101,"supervisor_creation_time_100ns":102,"owner_pid":201,"owner_creation_time_100ns":202,"supervisor_executable_sha256":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"owner_executable_sha256":[4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4],"command_sequence":1,"request_id":1001,"deadline_qpc_ns":1000000,"command":"query_ready","extra":true}"#;
        assert!(decode_request(&raw_frame(REQUEST_KIND, unknown)).is_err());
        let canonical = serde_json::to_vec(&request(ScmOwnerCommandV1::QueryReady)).unwrap();
        let spaced = format!(" {}", String::from_utf8(canonical).unwrap());
        assert!(decode_request(&raw_frame(REQUEST_KIND, spaced.as_bytes())).is_err());
        let mut bad_crc = encode_request(&request(ScmOwnerCommandV1::QueryReady)).unwrap();
        let last = bad_crc.len() - 1;
        bad_crc[last] ^= 0x80;
        assert!(decode_request(&bad_crc).is_err());

        let unknown_error = String::from_utf8(serde_json::to_vec(&response()).unwrap())
            .unwrap()
            .replacen("\"none\"", "\"not_known\"", 1);
        assert!(decode_response(&raw_frame(RESPONSE_KIND, unknown_error.as_bytes())).is_err());
    }

    #[test]
    fn semantic_validation_rejects_identity_pipe_and_state_contradictions() {
        let mut bad_request = request(ScmOwnerCommandV1::QueryReady);
        bad_request.owner_executable_sha256 = [0; 32];
        assert!(encode_request(&bad_request).is_err());
        bad_request = request(ScmOwnerCommandV1::QueryReady);
        bad_request.deadline_qpc_ns = 0;
        assert!(encode_request(&bad_request).is_err());

        let mut bad_response = response();
        bad_response.public_hardware_pipe_name = bad_response.public_control_pipe_name.clone();
        assert!(encode_response(&bad_response).is_err());
        bad_response = response();
        bad_response.public_analysis_pipe_name = Some("not-a-pipe".to_owned());
        assert!(encode_response(&bad_response).is_err());
        bad_response = response();
        bad_response.owner_phase = ScmOwnerPhaseV1::ExitedFailClosed;
        assert!(encode_response(&bad_response).is_err());
        bad_response = response();
        bad_response.accepted = false;
        assert!(encode_response(&bad_response).is_err());
        bad_response = response();
        bad_response.run_state_wire = RunState::Recording.wire_value();
        bad_response.active_epoch = Some(1);
        bad_response.sealed_record_count = 1;
        bad_response.durable_record_count = 1;
        bad_response.committed_record_count = 1;
        assert!(encode_response(&bad_response).is_err());
        bad_response = response();
        bad_response.active_epoch = Some(1);
        bad_response.run_state_wire = RunState::JournalSealed.wire_value();
        assert!(encode_response(&bad_response).is_err());

        let request = request(ScmOwnerCommandV1::QueryReady);
        let mut mismatched = response();
        mismatched.owner_pid += 1;
        assert!(validate_response_for_request(&request, &mismatched).is_err());
        validate_ready_response(
            &response(),
            r"\\.\pipe\forge-acqd-control-test",
            r"\\.\pipe\forge-acqd-hardware-test",
            Some(r"\\.\pipe\forge-acqd-analysis-test"),
        )
        .unwrap();
        assert!(validate_ready_response(
            &response(),
            r"\\.\pipe\wrong-control",
            r"\\.\pipe\forge-acqd-hardware-test",
            Some(r"\\.\pipe\forge-acqd-analysis-test"),
        )
        .is_err());
    }

    #[test]
    fn stop_intent_binding_is_required_only_for_graceful_shutdown() {
        let mut graceful = request(ScmOwnerCommandV1::GracefulShutdown);
        graceful.stop_intent = None;
        assert!(encode_request(&graceful).is_err());
        let mut query = request(ScmOwnerCommandV1::GetSnapshot);
        query.stop_intent = request(ScmOwnerCommandV1::GracefulShutdown).stop_intent;
        assert!(encode_request(&query).is_err());
    }

    #[test]
    fn sequence_guard_rejects_replay_reorder_and_all_commands_after_shutdown() {
        let client = authenticated_supervisor();
        let mut guard = SequenceGuard::new(expected_peer()).unwrap();
        let first = request(ScmOwnerCommandV1::QueryReady);
        guard.observe(&client, &first, 100).unwrap();
        assert!(guard.observe(&client, &first, 100).is_err());

        let mut skipped = request(ScmOwnerCommandV1::GetSnapshot);
        skipped.command_sequence = 3;
        skipped.request_id = 1002;
        assert!(guard.observe(&client, &skipped, 100).is_err());

        let mut shutdown = request(ScmOwnerCommandV1::GracefulShutdown);
        shutdown.command_sequence = 2;
        shutdown.request_id = 1002;
        guard.observe(&client, &shutdown, 100).unwrap();

        let mut after = request(ScmOwnerCommandV1::GetSnapshot);
        after.command_sequence = 3;
        after.request_id = 1003;
        assert!(guard.observe(&client, &after, 100).is_err());
    }

    #[test]
    fn authenticated_identity_and_qpc_deadline_are_fail_closed() {
        let request = request(ScmOwnerCommandV1::QueryReady);
        let expected = expected_peer();
        let client = authenticated_supervisor();
        validate_authenticated_owner_request(&client, &expected, &request, 100).unwrap();

        let mut wrong_client = client.clone();
        wrong_client.process_id += 1;
        assert!(
            validate_authenticated_owner_request(&wrong_client, &expected, &request, 100).is_err()
        );
        assert!(validate_authenticated_owner_request(
            &client,
            &expected,
            &request,
            request.deadline_qpc_ns,
        )
        .is_err());
        let mut excessive = request;
        excessive.deadline_qpc_ns = 30_000_000_101;
        assert!(validate_authenticated_owner_request(&client, &expected, &excessive, 100).is_err());

        let first = qpc_now_ns().unwrap();
        let second = qpc_now_ns().unwrap();
        assert!(first > 0);
        assert!(second >= first);
    }
}
