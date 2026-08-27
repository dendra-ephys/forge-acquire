//! Versioned local operator-to-daemon contract for a future real-Pod source.
//!
//! This companion leaves the frozen replay response untouched.  Operator
//! requests carry a relative timeout and the hardware-state hash observed at
//! preflight; only the daemon converts that timeout to an absolute Pod deadline
//! using a fresh DirectPodTimeSnapshotV1.

use std::io;

use forge_protocol_v1::{crc32c, encode_low_speed, Hash32, Id16, RunCommandV1};
use serde::Serialize;

use crate::direct_pod_time::{
    DirectPodTimeTracker, TIME_FLAG_GLOBAL_TIME_VALID, TIME_FLAG_POD_FAULT, TIME_FLAG_POD_READY,
};
use crate::hardware_run::HardwareRunPhase;
use crate::run::RunCommandKind;

pub const HARDWARE_SERVICE_CONTRACT_HASH_HEX: &str =
    "b1dd877cf9b9558352473f8458802a188919fb5a3865884c00a8eb83059e9b54";
pub const HARDWARE_SERVICE_CONTRACT_HASH: Hash32 = [
    0xb1, 0xdd, 0x87, 0x7c, 0xf9, 0xb9, 0x55, 0x83, 0x52, 0x47, 0x3f, 0x84, 0x58, 0x80, 0x2a, 0x18,
    0x89, 0x19, 0xfb, 0x5a, 0x38, 0x65, 0x88, 0x4c, 0x00, 0xa8, 0xeb, 0x83, 0x05, 0x9e, 0x9b, 0x54,
];
pub const HARDWARE_STATUS_REQUEST_LEN: usize = 64;
pub const OPERATOR_RUN_REQUEST_LEN: usize = 176;
pub const HARDWARE_SERVICE_SNAPSHOT_LEN: usize = 256;

pub const AVAIL_ADMISSION_VERIFIED: u32 = 1 << 0;
pub const AVAIL_TRANSPORT_OPEN: u32 = 1 << 1;
pub const AVAIL_TIME_FRESH: u32 = 1 << 2;
pub const AVAIL_HARDWARE_AVAILABLE: u32 = 1 << 3;
const AVAIL_KNOWN: u32 =
    AVAIL_ADMISSION_VERIFIED | AVAIL_TRANSPORT_OPEN | AVAIL_TIME_FRESH | AVAIL_HARDWARE_AVAILABLE;

const STATUS_REQUEST_MAGIC: &[u8; 8] = b"FGRHSQ01";
const RUN_REQUEST_MAGIC: &[u8; 8] = b"FGRHRC01";
const SNAPSHOT_MAGIC: &[u8; 8] = b"FGRHSV01";

/// Single-owner backend contract for the authenticated hardware companion.
/// Implementations must not alias replay or simulator state.
pub trait HardwareServiceBackend {
    fn status(
        &mut self,
        request_id: u64,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1>;

    fn submit(
        &mut self,
        request: OperatorRunRequestV1,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u16)]
pub enum HardwareServiceState {
    Unavailable = 0,
    Ready = 1,
    PrepareRequested = 2,
    Prepared = 3,
    ArmRequested = 4,
    Armed = 5,
    StartRequested = 6,
    StartAcknowledged = 7,
    Recording = 8,
    StopRequested = 9,
    Stopped = 10,
    AbortRequested = 11,
    Aborted = 12,
    Sealed = 13,
    Failed = 14,
}

impl HardwareServiceState {
    fn decode(value: u16) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Unavailable),
            1 => Ok(Self::Ready),
            2 => Ok(Self::PrepareRequested),
            3 => Ok(Self::Prepared),
            4 => Ok(Self::ArmRequested),
            5 => Ok(Self::Armed),
            6 => Ok(Self::StartRequested),
            7 => Ok(Self::StartAcknowledged),
            8 => Ok(Self::Recording),
            9 => Ok(Self::StopRequested),
            10 => Ok(Self::Stopped),
            11 => Ok(Self::AbortRequested),
            12 => Ok(Self::Aborted),
            13 => Ok(Self::Sealed),
            14 => Ok(Self::Failed),
            _ => Err(invalid_data("unknown hardware service state")),
        }
    }
}

impl From<HardwareRunPhase> for HardwareServiceState {
    fn from(value: HardwareRunPhase) -> Self {
        match value {
            HardwareRunPhase::New => Self::Ready,
            HardwareRunPhase::PrepareRequested => Self::PrepareRequested,
            HardwareRunPhase::Prepared => Self::Prepared,
            HardwareRunPhase::ArmRequested => Self::ArmRequested,
            HardwareRunPhase::Armed => Self::Armed,
            HardwareRunPhase::StartRequested => Self::StartRequested,
            HardwareRunPhase::StartAcknowledged => Self::StartAcknowledged,
            HardwareRunPhase::Recording => Self::Recording,
            HardwareRunPhase::StopRequested => Self::StopRequested,
            HardwareRunPhase::Stopped => Self::Stopped,
            HardwareRunPhase::AbortRequested => Self::AbortRequested,
            HardwareRunPhase::Aborted => Self::Aborted,
            HardwareRunPhase::Sealed => Self::Sealed,
            HardwareRunPhase::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u16)]
pub enum HardwareServiceError {
    None = 0,
    Unavailable = 1,
    StaleTime = 2,
    DeviceMismatch = 3,
    StateMismatch = 4,
    InvalidRequest = 5,
    PersistenceFailure = 6,
    TransportFailure = 7,
    ProtocolFailure = 8,
}

impl HardwareServiceError {
    fn decode(value: u16) -> io::Result<Self> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Unavailable),
            2 => Ok(Self::StaleTime),
            3 => Ok(Self::DeviceMismatch),
            4 => Ok(Self::StateMismatch),
            5 => Ok(Self::InvalidRequest),
            6 => Ok(Self::PersistenceFailure),
            7 => Ok(Self::TransportFailure),
            8 => Ok(Self::ProtocolFailure),
            _ => Err(invalid_data("unknown hardware service error")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareStatusRequestV1 {
    pub request_id: u64,
}

impl HardwareStatusRequestV1 {
    pub fn encode(self) -> io::Result<[u8; HARDWARE_STATUS_REQUEST_LEN]> {
        if self.request_id == 0 {
            return Err(invalid_input("hardware status request ID must be nonzero"));
        }
        let mut bytes = [0_u8; HARDWARE_STATUS_REQUEST_LEN];
        header(&mut bytes, STATUS_REQUEST_MAGIC);
        bytes[48..56].copy_from_slice(&self.request_id.to_le_bytes());
        finish_crc(&mut bytes);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        validate_frame(bytes, STATUS_REQUEST_MAGIC, HARDWARE_STATUS_REQUEST_LEN)?;
        if le_u32(bytes, 56)? != 0 {
            return Err(invalid_data(
                "hardware status request reserved field is nonzero",
            ));
        }
        let value = Self {
            request_id: le_u64(bytes, 48)?,
        };
        if value.request_id == 0 {
            return Err(invalid_data("hardware status request ID is zero"));
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorRunRequestV1 {
    pub request_id: u64,
    pub epoch: u64,
    pub command: RunCommandKind,
    pub relative_deadline_ms: u32,
    pub run_id: Id16,
    pub target_device_id: Id16,
    pub frozen_config_hash: Hash32,
    pub expected_hardware_state_hash: Hash32,
}

impl OperatorRunRequestV1 {
    pub fn encode(self) -> io::Result<[u8; OPERATOR_RUN_REQUEST_LEN]> {
        validate_operator_request(&self)?;
        let mut bytes = [0_u8; OPERATOR_RUN_REQUEST_LEN];
        header(&mut bytes, RUN_REQUEST_MAGIC);
        bytes[48..56].copy_from_slice(&self.request_id.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[64..66].copy_from_slice(&self.command.wire_value().to_le_bytes());
        bytes[66..68].copy_from_slice(&1_u16.to_le_bytes());
        bytes[68..72].copy_from_slice(&self.relative_deadline_ms.to_le_bytes());
        bytes[72..88].copy_from_slice(&self.run_id);
        bytes[88..104].copy_from_slice(&self.target_device_id);
        bytes[104..136].copy_from_slice(&self.frozen_config_hash);
        bytes[136..168].copy_from_slice(&self.expected_hardware_state_hash);
        finish_crc(&mut bytes);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        validate_frame(bytes, RUN_REQUEST_MAGIC, OPERATOR_RUN_REQUEST_LEN)?;
        if le_u16(bytes, 66)? != 1 || le_u32(bytes, 168)? != 0 {
            return Err(invalid_data(
                "operator Run request scope/reserved field is invalid",
            ));
        }
        let value = Self {
            request_id: le_u64(bytes, 48)?,
            epoch: le_u64(bytes, 56)?,
            command: RunCommandKind::from_wire(le_u16(bytes, 64)?)?,
            relative_deadline_ms: le_u32(bytes, 68)?,
            run_id: array(bytes, 72)?,
            target_device_id: array(bytes, 88)?,
            frozen_config_hash: array(bytes, 104)?,
            expected_hardware_state_hash: array(bytes, 136)?,
        };
        validate_operator_request(&value)
            .map_err(|_| invalid_data("operator Run request invariants are invalid"))?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct HardwareServiceSnapshotV1 {
    pub request_id: u64,
    pub service_state: HardwareServiceState,
    pub error_code: HardwareServiceError,
    pub availability_flags: u32,
    pub device_id: Id16,
    pub transport_epoch: u64,
    pub status_sequence: u64,
    pub hardware_time_ns: u64,
    pub sample_counter: u64,
    pub frame_counter: u64,
    pub runtime_flags: u32,
    pub hardware_state_hash: Hash32,
    pub active_run_id: Id16,
    pub active_epoch: u64,
    pub pending_request_id: u64,
    pub first_journal_sequence: Option<u64>,
    pub evidence_hash: Hash32,
    pub detail_code: u32,
}

impl HardwareServiceSnapshotV1 {
    pub fn unavailable(
        request_id: u64,
        error_code: HardwareServiceError,
        evidence_hash: Hash32,
    ) -> Self {
        Self {
            request_id,
            service_state: HardwareServiceState::Unavailable,
            error_code,
            availability_flags: 0,
            device_id: [0; 16],
            transport_epoch: 0,
            status_sequence: 0,
            hardware_time_ns: 0,
            sample_counter: 0,
            frame_counter: 0,
            runtime_flags: 0,
            hardware_state_hash: [0; 32],
            active_run_id: [0; 16],
            active_epoch: 0,
            pending_request_id: 0,
            first_journal_sequence: None,
            evidence_hash,
            detail_code: 0,
        }
    }

    pub fn encode(self) -> io::Result<[u8; HARDWARE_SERVICE_SNAPSHOT_LEN]> {
        validate_snapshot(&self)?;
        let mut bytes = [0_u8; HARDWARE_SERVICE_SNAPSHOT_LEN];
        header(&mut bytes, SNAPSHOT_MAGIC);
        bytes[48..56].copy_from_slice(&self.request_id.to_le_bytes());
        bytes[56..58].copy_from_slice(&(self.service_state as u16).to_le_bytes());
        bytes[58..60].copy_from_slice(&(self.error_code as u16).to_le_bytes());
        bytes[60..64].copy_from_slice(&self.availability_flags.to_le_bytes());
        bytes[64..80].copy_from_slice(&self.device_id);
        bytes[80..88].copy_from_slice(&self.transport_epoch.to_le_bytes());
        bytes[88..96].copy_from_slice(&self.status_sequence.to_le_bytes());
        bytes[96..104].copy_from_slice(&self.hardware_time_ns.to_le_bytes());
        bytes[104..112].copy_from_slice(&self.sample_counter.to_le_bytes());
        bytes[112..120].copy_from_slice(&self.frame_counter.to_le_bytes());
        bytes[120..124].copy_from_slice(&self.runtime_flags.to_le_bytes());
        bytes[128..160].copy_from_slice(&self.hardware_state_hash);
        bytes[160..176].copy_from_slice(&self.active_run_id);
        bytes[176..184].copy_from_slice(&self.active_epoch.to_le_bytes());
        bytes[184..192].copy_from_slice(&self.pending_request_id.to_le_bytes());
        bytes[192..200].copy_from_slice(
            &self
                .first_journal_sequence
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        bytes[200..232].copy_from_slice(&self.evidence_hash);
        bytes[232..236].copy_from_slice(&self.detail_code.to_le_bytes());
        finish_crc(&mut bytes);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        validate_frame(bytes, SNAPSHOT_MAGIC, HARDWARE_SERVICE_SNAPSHOT_LEN)?;
        if le_u32(bytes, 124)? != 0 || bytes[236..252].iter().any(|byte| *byte != 0) {
            return Err(invalid_data(
                "hardware service snapshot reserved field is nonzero",
            ));
        }
        let first = le_u64(bytes, 192)?;
        let value = Self {
            request_id: le_u64(bytes, 48)?,
            service_state: HardwareServiceState::decode(le_u16(bytes, 56)?)?,
            error_code: HardwareServiceError::decode(le_u16(bytes, 58)?)?,
            availability_flags: le_u32(bytes, 60)?,
            device_id: array(bytes, 64)?,
            transport_epoch: le_u64(bytes, 80)?,
            status_sequence: le_u64(bytes, 88)?,
            hardware_time_ns: le_u64(bytes, 96)?,
            sample_counter: le_u64(bytes, 104)?,
            frame_counter: le_u64(bytes, 112)?,
            runtime_flags: le_u32(bytes, 120)?,
            hardware_state_hash: array(bytes, 128)?,
            active_run_id: array(bytes, 160)?,
            active_epoch: le_u64(bytes, 176)?,
            pending_request_id: le_u64(bytes, 184)?,
            first_journal_sequence: (first != u64::MAX).then_some(first),
            evidence_hash: array(bytes, 200)?,
            detail_code: le_u32(bytes, 232)?,
        };
        validate_snapshot(&value)
            .map_err(|_| invalid_data("hardware service snapshot invariants are invalid"))?;
        Ok(value)
    }
}

/// Converts a local relative-time operator request into the exact M0 hardware
/// command using the latest fresh Pod snapshot.  The returned bytes, not the
/// local request, are what the direct-Pod control tracker sends to hardware.
pub fn translate_operator_run_request(
    request: &OperatorRunRequestV1,
    time: &mut DirectPodTimeTracker,
    host_monotonic_ns: u64,
) -> io::Result<Vec<u8>> {
    validate_operator_request(request)?;
    let hardware_now = time.require_fresh_ready_time(host_monotonic_ns)?;
    let latest = time
        .snapshot()
        .latest
        .ok_or_else(|| invalid_data("fresh hardware time disappeared"))?;
    if latest.device_id != request.target_device_id || latest.transport_epoch != request.epoch {
        return Err(invalid_input(
            "operator Run target or epoch does not match the fresh Pod snapshot",
        ));
    }
    if latest.hardware_state_hash != request.expected_hardware_state_hash {
        return Err(invalid_input(
            "operator preflight hardware-state hash is stale",
        ));
    }
    let required_flags = TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY;
    if latest.runtime_flags & required_flags != required_flags
        || latest.runtime_flags & TIME_FLAG_POD_FAULT != 0
    {
        return Err(invalid_input("Pod is not ready for a Run command"));
    }
    let timeout_ns = u64::from(request.relative_deadline_ms)
        .checked_mul(1_000_000)
        .ok_or_else(|| invalid_input("operator deadline multiplication overflow"))?;
    let deadline_global_time_ns = hardware_now
        .checked_add(timeout_ns)
        .ok_or_else(|| invalid_input("hardware deadline overflow"))?;
    encode_low_speed(
        0,
        request.request_id,
        request.epoch,
        &RunCommandV1 {
            command: request.command.wire_value(),
            scope: 1,
            run_id: request.run_id,
            target_device_id: request.target_device_id,
            deadline_global_time_ns,
            frozen_config_hash: request.frozen_config_hash,
        },
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("translated M0 hardware command is invalid: {error}"),
        )
    })
}

#[cfg(windows)]
pub fn query_hardware_service(
    pipe_name: &str,
    request_id: u64,
    wait_timeout_ms: u32,
    io_timeout_ms: u32,
) -> io::Result<HardwareServiceSnapshotV1> {
    let request = HardwareStatusRequestV1 { request_id }.encode()?;
    let bytes =
        crate::ipc::call_secure_pipe_bounded(pipe_name, &request, wait_timeout_ms, io_timeout_ms)?;
    let snapshot = HardwareServiceSnapshotV1::decode(&bytes)?;
    if snapshot.request_id != request_id {
        return Err(invalid_data(
            "hardware service status response request ID does not match",
        ));
    }
    Ok(snapshot)
}

#[cfg(windows)]
pub fn call_hardware_run_command(
    pipe_name: &str,
    request: OperatorRunRequestV1,
    wait_timeout_ms: u32,
    io_timeout_ms: u32,
) -> io::Result<HardwareServiceSnapshotV1> {
    let request_id = request.request_id;
    let request = request.encode()?;
    let bytes =
        crate::ipc::call_secure_pipe_bounded(pipe_name, &request, wait_timeout_ms, io_timeout_ms)?;
    let snapshot = HardwareServiceSnapshotV1::decode(&bytes)?;
    if snapshot.request_id != request_id {
        return Err(invalid_data(
            "hardware service command response request ID does not match",
        ));
    }
    Ok(snapshot)
}

fn validate_operator_request(value: &OperatorRunRequestV1) -> io::Result<()> {
    if value.request_id == 0
        || value.epoch == 0
        || !matches!(
            value.command,
            RunCommandKind::Prepare
                | RunCommandKind::Arm
                | RunCommandKind::Start
                | RunCommandKind::Stop
                | RunCommandKind::Abort
        )
        || !(100..=5_000).contains(&value.relative_deadline_ms)
        || !nonzero(&value.run_id)
        || !nonzero(&value.target_device_id)
        || !nonzero(&value.frozen_config_hash)
        || !nonzero(&value.expected_hardware_state_hash)
    {
        Err(invalid_input("operator Run request values are invalid"))
    } else {
        Ok(())
    }
}

fn validate_snapshot(value: &HardwareServiceSnapshotV1) -> io::Result<()> {
    if value.request_id == 0
        || value.availability_flags & !AVAIL_KNOWN != 0
        || !nonzero(&value.evidence_hash)
    {
        return Err(invalid_input(
            "hardware service snapshot base fields are invalid",
        ));
    }
    let available = value.availability_flags & AVAIL_HARDWARE_AVAILABLE != 0;
    let required = AVAIL_ADMISSION_VERIFIED | AVAIL_TRANSPORT_OPEN | AVAIL_TIME_FRESH;
    if available {
        if value.availability_flags & required != required
            || value.error_code != HardwareServiceError::None
            || value.service_state == HardwareServiceState::Unavailable
            || !nonzero(&value.device_id)
            || value.transport_epoch == 0
            || value.hardware_time_ns == 0
            || !nonzero(&value.hardware_state_hash)
        {
            return Err(invalid_input("available hardware snapshot is incomplete"));
        }
    } else if value.service_state != HardwareServiceState::Unavailable
        || value.error_code == HardwareServiceError::None
        || value.availability_flags != 0
        || nonzero(&value.device_id)
        || value.transport_epoch != 0
        || value.status_sequence != 0
        || value.hardware_time_ns != 0
        || value.sample_counter != 0
        || value.frame_counter != 0
        || value.runtime_flags != 0
        || nonzero(&value.hardware_state_hash)
        || nonzero(&value.active_run_id)
        || value.active_epoch != 0
        || value.pending_request_id != 0
        || value.first_journal_sequence.is_some()
    {
        return Err(invalid_input(
            "unavailable hardware snapshot leaks active fields",
        ));
    }
    Ok(())
}

fn header<const N: usize>(bytes: &mut [u8; N], magic: &[u8; 8]) {
    bytes[0..4].copy_from_slice(&(N as u32).to_le_bytes());
    bytes[4..12].copy_from_slice(magic);
    bytes[12..14].copy_from_slice(&1_u16.to_le_bytes());
    bytes[14..16].copy_from_slice(&(N as u16).to_le_bytes());
    bytes[16..48].copy_from_slice(&HARDWARE_SERVICE_CONTRACT_HASH);
}

fn finish_crc<const N: usize>(bytes: &mut [u8; N]) {
    let checksum = crc32c(&bytes[..N - 4]);
    bytes[N - 4..].copy_from_slice(&checksum.to_le_bytes());
}

fn validate_frame(bytes: &[u8], magic: &[u8; 8], length: usize) -> io::Result<()> {
    if bytes.len() != length
        || le_u32(bytes, 0)? as usize != length
        || bytes.get(4..12) != Some(magic)
        || le_u16(bytes, 12)? != 1
        || le_u16(bytes, 14)? as usize != length
        || array::<32>(bytes, 16)? != HARDWARE_SERVICE_CONTRACT_HASH
        || crc32c(&bytes[..length - 4]) != le_u32(bytes, length - 4)?
    {
        Err(invalid_data("hardware service frame is invalid"))
    } else {
        Ok(())
    }
}

fn nonzero<const N: usize>(value: &[u8; N]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn le_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(array(bytes, offset)?))
}

fn le_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(array(bytes, offset)?))
}

fn le_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(array(bytes, offset)?))
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(|| invalid_data("hardware service frame is truncated"))?
        .try_into()
        .map_err(|_| invalid_data("hardware service field length is invalid"))
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_protocol_v1::{decode_low_speed, sha256, WireBody, PROTOCOL_HASH};

    use crate::direct_pod_time::{
        DirectPodTimeSnapshotV1, TIME_FLAG_GLOBAL_TIME_VALID, TIME_FLAG_POD_READY,
    };

    fn operator_request() -> OperatorRunRequestV1 {
        OperatorRunRequestV1 {
            request_id: 7,
            epoch: 9,
            command: RunCommandKind::Prepare,
            relative_deadline_ms: 500,
            run_id: [1; 16],
            target_device_id: [2; 16],
            frozen_config_hash: PROTOCOL_HASH,
            expected_hardware_state_hash: sha256(b"hardware-state"),
        }
    }

    fn time_tracker() -> DirectPodTimeTracker {
        let mut tracker = DirectPodTimeTracker::new([2; 16], 9, 100).unwrap();
        tracker
            .observe(
                &DirectPodTimeSnapshotV1 {
                    device_id: [2; 16],
                    transport_epoch: 9,
                    status_sequence: 3,
                    global_time_ns: 1_000_000_000,
                    sample_counter: 30,
                    frame_counter: 3,
                    runtime_flags: TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY,
                    hardware_state_hash: sha256(b"hardware-state"),
                }
                .encode()
                .unwrap(),
                1_000,
            )
            .unwrap();
        tracker
    }

    fn available_snapshot() -> HardwareServiceSnapshotV1 {
        HardwareServiceSnapshotV1 {
            request_id: 3,
            service_state: HardwareServiceState::Ready,
            error_code: HardwareServiceError::None,
            availability_flags: AVAIL_ADMISSION_VERIFIED
                | AVAIL_TRANSPORT_OPEN
                | AVAIL_TIME_FRESH
                | AVAIL_HARDWARE_AVAILABLE,
            device_id: [2; 16],
            transport_epoch: 9,
            status_sequence: 3,
            hardware_time_ns: 1_000_000_000,
            sample_counter: 30,
            frame_counter: 3,
            runtime_flags: TIME_FLAG_GLOBAL_TIME_VALID | TIME_FLAG_POD_READY,
            hardware_state_hash: sha256(b"hardware-state"),
            active_run_id: [0; 16],
            active_epoch: 0,
            pending_request_id: 0,
            first_journal_sequence: None,
            evidence_hash: sha256(b"snapshot-evidence"),
            detail_code: 0,
        }
    }

    #[test]
    fn contract_hash_matches_lf_normalized_schema() {
        let normalized = include_str!("../schema/forge_hardware_service_v1.idl")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(
            sha256(normalized.as_bytes()),
            HARDWARE_SERVICE_CONTRACT_HASH
        );
    }

    #[test]
    fn all_three_frames_round_trip_and_every_byte_mutation_fails() {
        let status = HardwareStatusRequestV1 { request_id: 4 }.encode().unwrap();
        let run = operator_request().encode().unwrap();
        let snapshot = available_snapshot().encode().unwrap();
        assert_eq!(
            HardwareStatusRequestV1::decode(&status).unwrap(),
            HardwareStatusRequestV1 { request_id: 4 }
        );
        for index in 0..status.len() {
            let mut changed = status.to_vec();
            changed[index] ^= 1;
            assert!(
                HardwareStatusRequestV1::decode(&changed).is_err(),
                "status byte {index}"
            );
        }
        assert_eq!(
            OperatorRunRequestV1::decode(&run).unwrap(),
            operator_request()
        );
        for index in 0..run.len() {
            let mut changed = run.to_vec();
            changed[index] ^= 1;
            assert!(
                OperatorRunRequestV1::decode(&changed).is_err(),
                "run byte {index}"
            );
        }
        assert_eq!(
            HardwareServiceSnapshotV1::decode(&snapshot).unwrap(),
            available_snapshot()
        );
        for index in 0..snapshot.len() {
            let mut changed = snapshot.to_vec();
            changed[index] ^= 1;
            assert!(
                HardwareServiceSnapshotV1::decode(&changed).is_err(),
                "snapshot byte {index}"
            );
        }
    }

    #[test]
    fn unavailable_snapshot_is_explicit_and_cannot_leak_active_state() {
        let value = HardwareServiceSnapshotV1::unavailable(
            5,
            HardwareServiceError::Unavailable,
            sha256(b"no-driver"),
        );
        let bytes = value.encode().unwrap();
        assert_eq!(HardwareServiceSnapshotV1::decode(&bytes).unwrap(), value);
        let mut invalid = value;
        invalid.device_id = [2; 16];
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn translation_uses_exact_pod_time_and_preflight_hash() {
        let request = operator_request();
        let wire = translate_operator_run_request(&request, &mut time_tracker(), 1_050).unwrap();
        let decoded = decode_low_speed(&wire).unwrap();
        let body = RunCommandV1::decode_body(&decoded.body).unwrap();
        assert_eq!(decoded.request_id, request.request_id);
        assert_eq!(decoded.epoch, request.epoch);
        assert_eq!(body.deadline_global_time_ns, 1_500_000_000);

        let mut stale_hash = request;
        stale_hash.expected_hardware_state_hash = sha256(b"old-state");
        assert!(translate_operator_run_request(&stale_hash, &mut time_tracker(), 1_050).is_err());
        assert!(translate_operator_run_request(&request, &mut time_tracker(), 1_101).is_err());
    }
}
