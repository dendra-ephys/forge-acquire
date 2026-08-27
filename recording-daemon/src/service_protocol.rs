use std::io;
use std::path::Path;

use forge_protocol_v1::{
    crc32c, decode_low_speed, sha256, MessageKind, RunCommandV1, WireBody, PROTOCOL_HASH,
};
use serde::Serialize;

use crate::run::{RunCommand, RunCommandKind, RunReceipt, RunState};
use crate::run_ledger::{DurableRunService, DurableRunStatus};
use crate::service_replay::{ProtectedReplaySession, ReplayOwnerShutdownSignal};
#[cfg(windows)]
use crate::{
    analysis_worker_service::AnalysisWorkerRegistrationService, ipc::AuthenticatedPipeClient,
};

pub const DAEMON_RESPONSE_LEN: usize = 400;
pub const SERVICE_CONTRACT_HASH_HEX: &str =
    "1dccd163d6179b69adde2dbb738d1cfc3c0e471820338f36f9ffe2fb2bbf62ed";
pub const SERVICE_CONTRACT_HASH: [u8; 32] = [
    0x1d, 0xcc, 0xd1, 0x63, 0xd6, 0x17, 0x9b, 0x69, 0xad, 0xde, 0x2d, 0xbb, 0x73, 0x8d, 0x1c, 0xfc,
    0x3c, 0x0e, 0x47, 0x18, 0x20, 0x33, 0x8f, 0x36, 0xf9, 0xff, 0xe2, 0xfb, 0x2b, 0xbf, 0x62, 0xed,
];

const RESPONSE_MAGIC: &[u8; 8] = b"FGSVR001";
const RESPONSE_VERSION: u16 = 1;
const REASON_CAPACITY: usize = 84;

const FLAG_ACCEPTED: u32 = 1 << 0;
const FLAG_RETRYABLE: u32 = 1 << 1;
const FLAG_POISONED: u32 = 1 << 2;
const FLAG_AUTO_FAILED: u32 = 1 << 3;
const FLAG_HARDWARE_AVAILABLE: u32 = 1 << 4;
const FLAG_AUTHENTICATED_PIPE: u32 = 1 << 5;
const FLAG_SCM_OWNED: u32 = 1 << 6;
const FLAG_PROTECTED_REPLAY_AVAILABLE: u32 = 1 << 7;
const KNOWN_FLAGS: u32 = FLAG_ACCEPTED
    | FLAG_RETRYABLE
    | FLAG_POISONED
    | FLAG_AUTO_FAILED
    | FLAG_HARDWARE_AVAILABLE
    | FLAG_AUTHENTICATED_PIPE
    | FLAG_SCM_OWNED
    | FLAG_PROTECTED_REPLAY_AVAILABLE;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u32)]
pub enum ServiceErrorV1 {
    None = 0,
    MalformedRequest = 1,
    UnsupportedMessage = 2,
    HardwareUnavailable = 3,
    RunCommandRejected = 4,
    PersistenceFailure = 5,
    InternalFailure = 6,
}

impl TryFrom<u32> for ServiceErrorV1 {
    type Error = io::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::MalformedRequest),
            2 => Ok(Self::UnsupportedMessage),
            3 => Ok(Self::HardwareUnavailable),
            4 => Ok(Self::RunCommandRejected),
            5 => Ok(Self::PersistenceFailure),
            6 => Ok(Self::InternalFailure),
            _ => Err(invalid_response("unknown service error code")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaemonResponseV1 {
    pub state: RunState,
    pub accepted: bool,
    pub retryable: bool,
    pub poisoned: bool,
    pub auto_failed_on_restart: bool,
    pub hardware_transport_available: bool,
    pub authenticated_pipe: bool,
    pub scm_owned: bool,
    pub protected_replay_available: bool,
    pub request_id: u64,
    pub epoch: u64,
    pub ledger_events: u64,
    pub active_run_id: [u8; 16],
    pub latest_published_run_id: [u8; 16],
    pub receipt_hash: [u8; 32],
    pub committed_record_count: Option<u64>,
    pub durable_record_count: Option<u64>,
    pub expected_last_journal_sequence: Option<u64>,
    pub queue_used_slots: Option<u64>,
    pub queue_capacity_slots: Option<u64>,
    pub generated_record_count: Option<u64>,
    pub active_epoch: Option<u64>,
    pub highest_epoch: u64,
    pub active_target_device_id: [u8; 16],
    pub active_frozen_config_hash: [u8; 32],
    pub latest_sealed_run_id: [u8; 16],
    pub error: ServiceErrorV1,
    pub reason: String,
}

#[cfg(windows)]
pub fn query_daemon_snapshot(
    pipe_name: &str,
    request_id: u64,
    epoch: u64,
    wait_timeout_ms: u32,
    io_timeout_ms: u32,
) -> io::Result<DaemonResponseV1> {
    use forge_protocol_v1::encode_low_speed;

    if request_id == 0 || epoch == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "daemon snapshot request_id and epoch must be nonzero",
        ));
    }
    let request = encode_low_speed(
        0,
        request_id,
        epoch,
        &RunCommandV1 {
            command: RunCommandKind::GetSnapshot.wire_value(),
            scope: 1,
            run_id: [0x51; 16],
            target_device_id: [0x52; 16],
            deadline_global_time_ns: u64::MAX,
            frozen_config_hash: SERVICE_CONTRACT_HASH,
        },
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot encode daemon snapshot request: {error}"),
        )
    })?;
    let bytes =
        crate::ipc::call_secure_pipe_bounded(pipe_name, &request, wait_timeout_ms, io_timeout_ms)?;
    let response = DaemonResponseV1::decode(&bytes)?;
    if response.request_id != request_id
        || response.epoch != epoch
        || !response.accepted
        || response.error != ServiceErrorV1::None
        || response.receipt_hash != sha256(&request)
        || !response.authenticated_pipe
        || !response.scm_owned
    {
        return Err(invalid_response(
            "daemon snapshot response does not match the authenticated request",
        ));
    }
    Ok(response)
}

#[cfg(windows)]
pub fn call_daemon_run_command(
    pipe_name: &str,
    request_id: u64,
    epoch: u64,
    body: &RunCommandV1,
    wait_timeout_ms: u32,
    io_timeout_ms: u32,
) -> io::Result<DaemonResponseV1> {
    use forge_protocol_v1::encode_low_speed;

    let request = encode_low_speed(0, request_id, epoch, body).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot encode daemon Run command: {error}"),
        )
    })?;
    let bytes =
        crate::ipc::call_secure_pipe_bounded(pipe_name, &request, wait_timeout_ms, io_timeout_ms)?;
    let response = DaemonResponseV1::decode(&bytes)?;
    if response.request_id != request_id
        || response.epoch != epoch
        || !response.authenticated_pipe
        || !response.scm_owned
    {
        return Err(invalid_response(
            "daemon Run response does not match the authenticated request",
        ));
    }
    Ok(response)
}

/// Query the explicitly non-SCM software/synthetic replay endpoint. This is
/// deliberately separate from `query_daemon_snapshot`: accepting
/// `scm_owned=false` here must never weaken the production client contract.
#[cfg(windows)]
pub fn query_software_replay_snapshot(
    pipe_name: &str,
    request_id: u64,
    epoch: u64,
    wait_timeout_ms: u32,
    io_timeout_ms: u32,
) -> io::Result<DaemonResponseV1> {
    use forge_protocol_v1::encode_low_speed;

    if request_id == 0 || epoch == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "software replay snapshot request_id and epoch must be nonzero",
        ));
    }
    let request = encode_low_speed(
        0,
        request_id,
        epoch,
        &RunCommandV1 {
            command: RunCommandKind::GetSnapshot.wire_value(),
            scope: 1,
            run_id: [0x51; 16],
            target_device_id: [0x52; 16],
            deadline_global_time_ns: u64::MAX,
            frozen_config_hash: SERVICE_CONTRACT_HASH,
        },
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot encode software replay snapshot request: {error}"),
        )
    })?;
    let bytes =
        crate::ipc::call_secure_pipe_bounded(pipe_name, &request, wait_timeout_ms, io_timeout_ms)?;
    let response = DaemonResponseV1::decode(&bytes)?;
    if response.request_id != request_id
        || response.epoch != epoch
        || !response.accepted
        || response.error != ServiceErrorV1::None
        || response.receipt_hash != sha256(&request)
        || !response.authenticated_pipe
        || response.scm_owned
        || !response.protected_replay_available
        || response.hardware_transport_available
    {
        return Err(invalid_response(
            "software replay snapshot response does not match the authenticated non-SCM request",
        ));
    }
    Ok(response)
}

#[cfg(windows)]
pub fn call_software_replay_run_command(
    pipe_name: &str,
    request_id: u64,
    epoch: u64,
    body: &RunCommandV1,
    wait_timeout_ms: u32,
    io_timeout_ms: u32,
) -> io::Result<DaemonResponseV1> {
    use forge_protocol_v1::encode_low_speed;

    let request = encode_low_speed(0, request_id, epoch, body).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot encode software replay Run command: {error}"),
        )
    })?;
    let bytes =
        crate::ipc::call_secure_pipe_bounded(pipe_name, &request, wait_timeout_ms, io_timeout_ms)?;
    let response = DaemonResponseV1::decode(&bytes)?;
    if response.request_id != request_id
        || response.epoch != epoch
        || !response.authenticated_pipe
        || response.scm_owned
        || !response.protected_replay_available
        || response.hardware_transport_available
    {
        return Err(invalid_response(
            "software replay Run response does not match the authenticated non-SCM request",
        ));
    }
    Ok(response)
}

impl DaemonResponseV1 {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let reason = self.reason.as_bytes();
        if reason.is_empty() || reason.len() > REASON_CAPACITY {
            return Err(invalid_response("service reason is empty or too long"));
        }
        if self.accepted != (self.error == ServiceErrorV1::None) {
            return Err(invalid_response(
                "accepted response and service error contradict",
            ));
        }
        if self.hardware_transport_available {
            return Err(invalid_response(
                "hardware transport cannot be advertised by this service build",
            ));
        }
        validate_active_context(
            self.active_epoch,
            self.highest_epoch,
            &self.active_run_id,
            &self.active_target_device_id,
            &self.active_frozen_config_hash,
        )?;
        let mut flags = 0_u32;
        flags |= u32::from(self.accepted) * FLAG_ACCEPTED;
        flags |= u32::from(self.retryable) * FLAG_RETRYABLE;
        flags |= u32::from(self.poisoned) * FLAG_POISONED;
        flags |= u32::from(self.auto_failed_on_restart) * FLAG_AUTO_FAILED;
        flags |= u32::from(self.hardware_transport_available) * FLAG_HARDWARE_AVAILABLE;
        flags |= u32::from(self.authenticated_pipe) * FLAG_AUTHENTICATED_PIPE;
        flags |= u32::from(self.scm_owned) * FLAG_SCM_OWNED;
        flags |= u32::from(self.protected_replay_available) * FLAG_PROTECTED_REPLAY_AVAILABLE;

        let mut bytes = vec![0_u8; DAEMON_RESPONSE_LEN];
        bytes[0..4].copy_from_slice(&(DAEMON_RESPONSE_LEN as u32).to_le_bytes());
        bytes[4..12].copy_from_slice(RESPONSE_MAGIC);
        bytes[12..14].copy_from_slice(&RESPONSE_VERSION.to_le_bytes());
        bytes[14..16].copy_from_slice(&(DAEMON_RESPONSE_LEN as u16).to_le_bytes());
        bytes[16..18].copy_from_slice(&(self.state.wire_value() as u16).to_le_bytes());
        bytes[20..24].copy_from_slice(&flags.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.request_id.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.ledger_events.to_le_bytes());
        bytes[48..64].copy_from_slice(&self.active_run_id);
        bytes[64..80].copy_from_slice(&self.latest_published_run_id);
        bytes[80..112].copy_from_slice(&self.receipt_hash);
        bytes[112..144].copy_from_slice(&PROTOCOL_HASH);
        bytes[144..176].copy_from_slice(&SERVICE_CONTRACT_HASH);
        bytes[176..180].copy_from_slice(&(self.error as u32).to_le_bytes());
        bytes[180..182].copy_from_slice(&(reason.len() as u16).to_le_bytes());
        put_optional_u64(&mut bytes, 184, self.committed_record_count);
        put_optional_u64(&mut bytes, 192, self.durable_record_count);
        put_optional_u64(&mut bytes, 200, self.expected_last_journal_sequence);
        put_optional_u64(&mut bytes, 208, self.queue_used_slots);
        put_optional_u64(&mut bytes, 216, self.queue_capacity_slots);
        put_optional_u64(&mut bytes, 224, self.generated_record_count);
        put_optional_u64(&mut bytes, 232, self.active_epoch);
        bytes[240..248].copy_from_slice(&self.highest_epoch.to_le_bytes());
        bytes[248..264].copy_from_slice(&self.active_target_device_id);
        bytes[264..296].copy_from_slice(&self.active_frozen_config_hash);
        bytes[296..312].copy_from_slice(&self.latest_sealed_run_id);
        bytes[312..312 + reason.len()].copy_from_slice(reason);
        let crc = crc32c(&bytes[..396]);
        bytes[396..400].copy_from_slice(&crc.to_le_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != DAEMON_RESPONSE_LEN
            || le_u32(bytes, 0)? as usize != DAEMON_RESPONSE_LEN
            || bytes.get(4..12) != Some(RESPONSE_MAGIC)
            || le_u16(bytes, 12)? != RESPONSE_VERSION
            || le_u16(bytes, 14)? as usize != DAEMON_RESPONSE_LEN
            || le_u16(bytes, 18)? != 0
            || le_u16(bytes, 182)? != 0
            || bytes.get(112..144) != Some(&PROTOCOL_HASH)
            || bytes.get(144..176) != Some(&SERVICE_CONTRACT_HASH)
            || le_u32(bytes, 396)? != crc32c(&bytes[..396])
        {
            return Err(invalid_response("service response framing is invalid"));
        }
        let state_raw = le_u16(bytes, 16)?;
        let state = u8::try_from(state_raw)
            .ok()
            .and_then(|value| RunState::from_wire(value).ok())
            .ok_or_else(|| invalid_response("unknown Run state"))?;
        let flags = le_u32(bytes, 20)?;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(invalid_response("unknown service response flags"));
        }
        let error = ServiceErrorV1::try_from(le_u32(bytes, 176)?)?;
        let accepted = flags & FLAG_ACCEPTED != 0;
        if accepted != (error == ServiceErrorV1::None) {
            return Err(invalid_response(
                "accepted response and service error contradict",
            ));
        }
        let reason_len = le_u16(bytes, 180)? as usize;
        if !(1..=REASON_CAPACITY).contains(&reason_len)
            || bytes[312 + reason_len..396].iter().any(|value| *value != 0)
        {
            return Err(invalid_response("service reason padding is invalid"));
        }
        let reason = std::str::from_utf8(&bytes[312..312 + reason_len])
            .map_err(|_| invalid_response("service reason is not UTF-8"))?
            .to_owned();
        let active_run_id = array(bytes, 48)?;
        let active_epoch = optional_u64(bytes, 232)?;
        let highest_epoch = le_u64(bytes, 240)?;
        let active_target_device_id = array(bytes, 248)?;
        let active_frozen_config_hash = array(bytes, 264)?;
        validate_active_context(
            active_epoch,
            highest_epoch,
            &active_run_id,
            &active_target_device_id,
            &active_frozen_config_hash,
        )?;
        Ok(Self {
            state,
            accepted,
            retryable: flags & FLAG_RETRYABLE != 0,
            poisoned: flags & FLAG_POISONED != 0,
            auto_failed_on_restart: flags & FLAG_AUTO_FAILED != 0,
            hardware_transport_available: flags & FLAG_HARDWARE_AVAILABLE != 0,
            authenticated_pipe: flags & FLAG_AUTHENTICATED_PIPE != 0,
            scm_owned: flags & FLAG_SCM_OWNED != 0,
            protected_replay_available: flags & FLAG_PROTECTED_REPLAY_AVAILABLE != 0,
            request_id: le_u64(bytes, 24)?,
            epoch: le_u64(bytes, 32)?,
            ledger_events: le_u64(bytes, 40)?,
            active_run_id,
            latest_published_run_id: array(bytes, 64)?,
            receipt_hash: array(bytes, 80)?,
            committed_record_count: optional_u64(bytes, 184)?,
            durable_record_count: optional_u64(bytes, 192)?,
            expected_last_journal_sequence: optional_u64(bytes, 200)?,
            queue_used_slots: optional_u64(bytes, 208)?,
            queue_capacity_slots: optional_u64(bytes, 216)?,
            generated_record_count: optional_u64(bytes, 224)?,
            active_epoch,
            highest_epoch,
            active_target_device_id,
            active_frozen_config_hash,
            latest_sealed_run_id: array(bytes, 296)?,
            error,
            reason,
        })
    }
}

pub struct ServiceDispatcher {
    run_service: DurableRunService,
    replay_session: Option<ProtectedReplaySession>,
    #[cfg(windows)]
    analysis_worker_registration: Option<AnalysisWorkerRegistrationService>,
    authenticated_pipe: bool,
    scm_owned: bool,
}

/// Minimal, non-serializable state copied into the private SCM owner channel.
/// Reading it performs no refresh, journal write, worker join, or hardware
/// request, so the owner can publish the most recently completed control-plane
/// state without turning its private watchdog path into another blocking path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerDispatcherSnapshot {
    pub state: RunState,
    pub active_epoch: Option<u64>,
    pub committed_record_count: u64,
    pub durable_record_count: u64,
    pub sealed_record_count: u64,
    pub hardware_transport_available: bool,
}

struct ResponseOutcome<'a> {
    accepted: bool,
    retryable: bool,
    error: ServiceErrorV1,
    reason: &'a str,
    receipt_hash: [u8; 32],
}

impl ServiceDispatcher {
    pub(crate) fn owner_shutdown_signal(&self) -> Option<ReplayOwnerShutdownSignal> {
        self.replay_session
            .as_ref()
            .map(ProtectedReplaySession::owner_shutdown_signal)
    }

    pub(crate) fn owner_snapshot(&self) -> OwnerDispatcherSnapshot {
        let status = self.run_service.status();
        let progress = self
            .replay_session
            .as_ref()
            .map(ProtectedReplaySession::progress)
            .unwrap_or_default();
        let committed_record_count = progress.committed_record_count.unwrap_or(0);
        let durable_record_count = progress.durable_record_count.unwrap_or(0);
        let sealed_record_count = if status.state == RunState::JournalSealed {
            durable_record_count
        } else {
            0
        };
        OwnerDispatcherSnapshot {
            state: status.state,
            active_epoch: status.active_epoch,
            committed_record_count,
            durable_record_count,
            sealed_record_count,
            hardware_transport_available: status.hardware_transport_available,
        }
    }

    pub fn open(
        ledger_path: impl AsRef<Path>,
        authenticated_pipe: bool,
        scm_owned: bool,
    ) -> io::Result<Self> {
        if scm_owned && !authenticated_pipe {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SCM-owned dispatcher requires an authenticated pipe",
            ));
        }
        Ok(Self {
            run_service: DurableRunService::open(ledger_path)?,
            replay_session: None,
            #[cfg(windows)]
            analysis_worker_registration: None,
            authenticated_pipe,
            scm_owned,
        })
    }

    pub fn open_protected_replay(
        ledger_path: impl AsRef<Path>,
        data_root: impl AsRef<Path>,
        authenticated_pipe: bool,
        scm_owned: bool,
    ) -> io::Result<Self> {
        if scm_owned && !authenticated_pipe {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SCM-owned dispatcher requires an authenticated pipe",
            ));
        }
        Ok(Self {
            run_service: DurableRunService::open(ledger_path)?,
            replay_session: Some(ProtectedReplaySession::new(data_root)?),
            #[cfg(windows)]
            analysis_worker_registration: None,
            authenticated_pipe,
            scm_owned,
        })
    }

    /// Opens a Run-bound, non-SCM software/synthetic replay dispatcher. The
    /// caller must expose it only through the current-user-only operator pipe.
    pub fn open_operator_software_replay(
        ledger_path: impl AsRef<Path>,
        run_directory: impl AsRef<Path>,
        run_id: [u8; 16],
        target_device_id: [u8; 16],
        frozen_config_hash: [u8; 32],
        pod_ids: Vec<[u8; 16]>,
    ) -> io::Result<Self> {
        Ok(Self {
            run_service: DurableRunService::open(ledger_path)?,
            replay_session: Some(ProtectedReplaySession::new_operator_software(
                run_directory,
                run_id,
                target_device_id,
                frozen_config_hash,
                pod_ids,
            )?),
            #[cfg(windows)]
            analysis_worker_registration: None,
            authenticated_pipe: true,
            scm_owned: false,
        })
    }

    #[cfg(windows)]
    pub fn open_protected_replay_with_analysis_worker(
        ledger_path: impl AsRef<Path>,
        data_root: impl AsRef<Path>,
        authenticated_pipe: bool,
        scm_owned: bool,
        service_sid: &str,
        worker_sid: &str,
    ) -> io::Result<Self> {
        let mut value =
            Self::open_protected_replay(ledger_path, data_root, authenticated_pipe, scm_owned)?;
        value.analysis_worker_registration = Some(AnalysisWorkerRegistrationService::new_service(
            service_sid,
            worker_sid,
        )?);
        Ok(value)
    }

    #[cfg(windows)]
    pub fn handle_analysis_worker(
        &mut self,
        client: &AuthenticatedPipeClient,
        request: &[u8],
    ) -> io::Result<Vec<u8>> {
        let (Some(registration), Some(session)) = (
            self.analysis_worker_registration.as_mut(),
            self.replay_session.as_mut(),
        ) else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "analysis-worker registration is unavailable",
            ));
        };
        registration.handle(session, client, request)
    }

    pub fn handle(&mut self, request: &[u8]) -> io::Result<Vec<u8>> {
        let decoded = match decode_low_speed(request) {
            Ok(value) => value,
            Err(error) => {
                return self.response(
                    0,
                    0,
                    ResponseOutcome {
                        accepted: false,
                        retryable: false,
                        error: ServiceErrorV1::MalformedRequest,
                        reason: &format!("malformed request: {error}"),
                        receipt_hash: sha256(request),
                    },
                )
            }
        };
        if decoded.kind != MessageKind::RunCommand {
            return self.response(
                decoded.request_id,
                decoded.epoch,
                ResponseOutcome {
                    accepted: false,
                    retryable: false,
                    error: ServiceErrorV1::UnsupportedMessage,
                    reason: "only RunCommandV1 is accepted",
                    receipt_hash: sha256(request),
                },
            );
        }
        let body = RunCommandV1::decode_body(&decoded.body).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decoded RunCommandV1 body is invalid: {error}"),
            )
        })?;
        let command = RunCommand {
            request_id: decoded.request_id,
            epoch: decoded.epoch,
            body,
        };
        let kind = RunCommandKind::from_wire(command.body.command)?;
        if kind == RunCommandKind::GetSnapshot {
            if let Some(session) = self.replay_session.as_mut() {
                if let Err(error) = session.refresh(&mut self.run_service) {
                    return self.response(
                        command.request_id,
                        command.epoch,
                        ResponseOutcome {
                            accepted: false,
                            retryable: false,
                            error: ServiceErrorV1::PersistenceFailure,
                            reason: "replay worker failed between snapshots",
                            receipt_hash: sha256(format!("{error:?}").as_bytes()),
                        },
                    );
                }
            }
            return self.response(
                command.request_id,
                command.epoch,
                ResponseOutcome {
                    accepted: true,
                    retryable: false,
                    error: ServiceErrorV1::None,
                    reason: "snapshot",
                    receipt_hash: sha256(request),
                },
            );
        }

        let receipt = if let Some(session) = self.replay_session.as_mut() {
            session.handle_command(&mut self.run_service, command)
        } else if kind == RunCommandKind::AcknowledgeFailure {
            self.run_service.handle(command, 1)
        } else {
            self.run_service
                .reject_by_policy(command, "hardware acquisition transport unavailable")
        };
        match receipt {
            Ok(receipt) => self.response_from_receipt(request, &receipt),
            Err(error) => self.response(
                decoded.request_id,
                decoded.epoch,
                ResponseOutcome {
                    accepted: false,
                    retryable: false,
                    error: ServiceErrorV1::PersistenceFailure,
                    reason: "Run receipt persistence failed",
                    receipt_hash: sha256(format!("{error:?}").as_bytes()),
                },
            ),
        }
    }

    pub fn status(&self) -> DurableRunStatus {
        self.run_service.status()
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        if let Some(session) = self.replay_session.as_mut() {
            session.shutdown(&mut self.run_service)?;
        }
        Ok(())
    }

    fn response_from_receipt(&self, request: &[u8], receipt: &RunReceipt) -> io::Result<Vec<u8>> {
        let error = if receipt.accepted {
            ServiceErrorV1::None
        } else if receipt.reason == "hardware acquisition transport unavailable" {
            ServiceErrorV1::HardwareUnavailable
        } else {
            ServiceErrorV1::RunCommandRejected
        };
        self.response(
            receipt.request_id,
            receipt.epoch,
            ResponseOutcome {
                accepted: receipt.accepted,
                retryable: false,
                error,
                reason: &receipt.reason,
                receipt_hash: run_receipt_hash(request, receipt),
            },
        )
    }

    fn response(
        &self,
        request_id: u64,
        epoch: u64,
        outcome: ResponseOutcome<'_>,
    ) -> io::Result<Vec<u8>> {
        let status = self.run_service.status();
        let progress = self
            .replay_session
            .as_ref()
            .map(ProtectedReplaySession::progress)
            .unwrap_or_default();
        DaemonResponseV1 {
            state: status.state,
            accepted: outcome.accepted,
            retryable: outcome.retryable,
            poisoned: status.poisoned,
            auto_failed_on_restart: status.auto_failed_on_restart,
            hardware_transport_available: status.hardware_transport_available,
            authenticated_pipe: self.authenticated_pipe,
            scm_owned: self.scm_owned,
            protected_replay_available: self.replay_session.is_some(),
            request_id,
            epoch,
            ledger_events: status.ledger_events,
            active_run_id: decode_optional_id(status.active_run_id_hex.as_deref())?,
            latest_published_run_id: decode_optional_id(
                status.latest_published_run_id_hex.as_deref(),
            )?,
            receipt_hash: outcome.receipt_hash,
            committed_record_count: progress.committed_record_count,
            durable_record_count: progress.durable_record_count,
            expected_last_journal_sequence: progress.expected_last_journal_sequence,
            queue_used_slots: progress.queue_used_slots,
            queue_capacity_slots: progress.queue_capacity_slots,
            generated_record_count: progress.generated_record_count,
            active_epoch: status.active_epoch,
            highest_epoch: status.highest_epoch,
            active_target_device_id: decode_optional_id(
                status.active_target_device_id_hex.as_deref(),
            )?,
            active_frozen_config_hash: decode_optional_hash(
                status.active_frozen_config_hash_hex.as_deref(),
            )?,
            latest_sealed_run_id: decode_optional_id(status.latest_sealed_run_id_hex.as_deref())?,
            error: outcome.error,
            reason: truncate_reason(outcome.reason),
        }
        .encode()
    }
}

fn run_receipt_hash(request: &[u8], receipt: &RunReceipt) -> [u8; 32] {
    let mut evidence = Vec::with_capacity(request.len() + 32 + receipt.reason.len());
    evidence.extend_from_slice(request);
    evidence.extend_from_slice(&receipt.request_id.to_le_bytes());
    evidence.extend_from_slice(&receipt.epoch.to_le_bytes());
    evidence.extend_from_slice(&receipt.command.wire_value().to_le_bytes());
    evidence.push(u8::from(receipt.accepted));
    evidence.push(receipt.prior_state.wire_value());
    evidence.push(receipt.current_state.wire_value());
    evidence.extend_from_slice(&(receipt.reason.len() as u32).to_le_bytes());
    evidence.extend_from_slice(receipt.reason.as_bytes());
    sha256(&evidence)
}

fn truncate_reason(reason: &str) -> String {
    if reason.len() <= REASON_CAPACITY {
        return reason.to_owned();
    }
    let mut end = REASON_CAPACITY;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_owned()
}

fn decode_optional_id(value: Option<&str>) -> io::Result<[u8; 16]> {
    let Some(value) = value else {
        return Ok([0_u8; 16]);
    };
    if value.len() != 32 {
        return Err(invalid_response("persisted Run ID has invalid hex length"));
    }
    let mut output = [0_u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid_response("persisted Run ID is not hex"))?;
    }
    Ok(output)
}

fn decode_optional_hash(value: Option<&str>) -> io::Result<[u8; 32]> {
    let Some(value) = value else {
        return Ok([0_u8; 32]);
    };
    if value.len() != 64 {
        return Err(invalid_response("persisted hash has invalid hex length"));
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid_response("persisted hash is not hex"))?;
    }
    Ok(output)
}

fn validate_active_context(
    active_epoch: Option<u64>,
    highest_epoch: u64,
    run_id: &[u8; 16],
    target_device_id: &[u8; 16],
    frozen_config_hash: &[u8; 32],
) -> io::Result<()> {
    let identifiers_present = run_id.iter().any(|value| *value != 0)
        && target_device_id.iter().any(|value| *value != 0)
        && frozen_config_hash.iter().any(|value| *value != 0);
    let identifiers_absent = run_id.iter().all(|value| *value == 0)
        && target_device_id.iter().all(|value| *value == 0)
        && frozen_config_hash.iter().all(|value| *value == 0);
    match active_epoch {
        Some(epoch) if epoch != 0 && epoch <= highest_epoch && identifiers_present => Ok(()),
        None if identifiers_absent => Ok(()),
        _ => Err(invalid_response(
            "active Run epoch and frozen context identifiers contradict",
        )),
    }
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

fn put_optional_u64(bytes: &mut [u8], offset: usize, value: Option<u64>) {
    bytes[offset..offset + 8].copy_from_slice(&value.unwrap_or(u64::MAX).to_le_bytes());
}

fn optional_u64(bytes: &[u8], offset: usize) -> io::Result<Option<u64>> {
    let value = le_u64(bytes, offset)?;
    Ok((value != u64::MAX).then_some(value))
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(|| invalid_response("service response is truncated"))?
        .try_into()
        .map_err(|_| invalid_response("service response field has the wrong size"))
}

fn invalid_response(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use forge_protocol_v1::{encode_low_speed, DeviceCapabilitiesV1};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempLedger(std::path::PathBuf);
    impl TempLedger {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "forge-service-dispatch-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }
    }
    impl Drop for TempLedger {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn command(request_id: u64, kind: RunCommandKind) -> Vec<u8> {
        encode_low_speed(
            0,
            request_id,
            1,
            &RunCommandV1 {
                command: kind.wire_value(),
                scope: 1,
                run_id: [0x11; 16],
                target_device_id: [0x22; 16],
                deadline_global_time_ns: u64::MAX,
                frozen_config_hash: [0x33; 32],
            },
        )
        .unwrap()
    }

    #[test]
    fn frozen_contract_hash_and_response_round_trip() {
        let normalized =
            include_str!("../schema/forge_service_response_v1.idl").replace("\r\n", "\n");
        assert_eq!(sha256(normalized.as_bytes()), SERVICE_CONTRACT_HASH);
        let response = DaemonResponseV1 {
            state: RunState::New,
            accepted: true,
            retryable: false,
            poisoned: false,
            auto_failed_on_restart: false,
            hardware_transport_available: false,
            authenticated_pipe: true,
            scm_owned: false,
            protected_replay_available: false,
            request_id: 9,
            epoch: 2,
            ledger_events: 3,
            active_run_id: [0; 16],
            latest_published_run_id: [0x44; 16],
            receipt_hash: [0x55; 32],
            committed_record_count: Some(8),
            durable_record_count: Some(7),
            expected_last_journal_sequence: None,
            queue_used_slots: Some(1),
            queue_capacity_slots: Some(4),
            generated_record_count: Some(9),
            active_epoch: None,
            highest_epoch: 8,
            active_target_device_id: [0; 16],
            active_frozen_config_hash: [0; 32],
            latest_sealed_run_id: [0x66; 16],
            error: ServiceErrorV1::None,
            reason: "snapshot".to_owned(),
        };
        let bytes = response.encode().unwrap();
        assert_eq!(bytes.len(), DAEMON_RESPONSE_LEN);
        assert_eq!(DaemonResponseV1::decode(&bytes).unwrap(), response);
        for index in 0..bytes.len() {
            let mut corrupt = bytes.clone();
            corrupt[index] ^= 1;
            assert!(DaemonResponseV1::decode(&corrupt).is_err());
        }
    }

    #[test]
    fn crc_valid_active_context_contradictions_are_rejected() {
        let response = DaemonResponseV1 {
            state: RunState::Failed,
            accepted: true,
            retryable: false,
            poisoned: false,
            auto_failed_on_restart: true,
            hardware_transport_available: false,
            authenticated_pipe: true,
            scm_owned: true,
            protected_replay_available: true,
            request_id: 9,
            epoch: 41,
            ledger_events: 7,
            active_run_id: [0x11; 16],
            latest_published_run_id: [0; 16],
            receipt_hash: [0x55; 32],
            committed_record_count: Some(3),
            durable_record_count: Some(3),
            expected_last_journal_sequence: Some(2),
            queue_used_slots: Some(0),
            queue_capacity_slots: Some(4),
            generated_record_count: Some(3),
            active_epoch: Some(41),
            highest_epoch: 41,
            active_target_device_id: [0x22; 16],
            active_frozen_config_hash: [0x33; 32],
            latest_sealed_run_id: [0; 16],
            error: ServiceErrorV1::None,
            reason: "failed snapshot".to_owned(),
        };
        let mut bytes = response.encode().unwrap();
        bytes[248..264].fill(0);
        let crc = crc32c(&bytes[..396]);
        bytes[396..400].copy_from_slice(&crc.to_le_bytes());
        assert!(DaemonResponseV1::decode(&bytes).is_err());

        let mut impossible_epoch = response;
        impossible_epoch.highest_epoch = 40;
        assert!(impossible_epoch.encode().is_err());
    }

    #[test]
    fn owner_snapshot_is_nonmutating_and_conservative() {
        let temp = TempLedger::new();
        let dispatcher = ServiceDispatcher::open(&temp.0, true, true).unwrap();
        let snapshot = dispatcher.owner_snapshot();
        assert_eq!(snapshot.state, RunState::New);
        assert_eq!(snapshot.active_epoch, None);
        assert_eq!(snapshot.committed_record_count, 0);
        assert_eq!(snapshot.durable_record_count, 0);
        assert_eq!(snapshot.sealed_record_count, 0);
        assert!(!snapshot.hardware_transport_available);
        assert_eq!(dispatcher.run_service.status().ledger_events, 0);
    }

    #[test]
    fn snapshot_is_read_only_and_mutation_is_durably_rejected() {
        let temp = TempLedger::new();
        let mut dispatcher = ServiceDispatcher::open(&temp.0, true, false).unwrap();
        let snapshot = DaemonResponseV1::decode(
            &dispatcher
                .handle(&command(1, RunCommandKind::GetSnapshot))
                .unwrap(),
        )
        .unwrap();
        assert!(snapshot.accepted);
        assert_eq!(snapshot.state, RunState::New);
        assert_eq!(snapshot.ledger_events, 0);

        let prepare_request = command(2, RunCommandKind::Prepare);
        let rejected =
            DaemonResponseV1::decode(&dispatcher.handle(&prepare_request).unwrap()).unwrap();
        assert!(!rejected.accepted);
        assert_eq!(rejected.error, ServiceErrorV1::HardwareUnavailable);
        assert_eq!(rejected.state, RunState::New);
        assert_eq!(rejected.ledger_events, 1);
        let exact_retry =
            DaemonResponseV1::decode(&dispatcher.handle(&prepare_request).unwrap()).unwrap();
        assert_eq!(exact_retry.receipt_hash, rejected.receipt_hash);
        assert_eq!(exact_retry.ledger_events, 1);

        drop(dispatcher);
        let mut reopened = ServiceDispatcher::open(&temp.0, true, false).unwrap();
        let after_restart =
            DaemonResponseV1::decode(&reopened.handle(&prepare_request).unwrap()).unwrap();
        assert_eq!(after_restart.receipt_hash, rejected.receipt_hash);
        assert_eq!(after_restart.ledger_events, 1);
    }

    #[test]
    fn malformed_and_non_run_messages_fail_closed_without_ledger_writes() {
        let temp = TempLedger::new();
        let mut dispatcher = ServiceDispatcher::open(&temp.0, true, false).unwrap();
        let malformed = DaemonResponseV1::decode(&dispatcher.handle(b"bad").unwrap()).unwrap();
        assert_eq!(malformed.error, ServiceErrorV1::MalformedRequest);
        assert_eq!(malformed.ledger_events, 0);

        let capabilities = DeviceCapabilitiesV1 {
            device_id: [1; 16],
            transport: 1,
            max_pods: 1,
            max_channels_per_pod: 256,
            sample_format_mask: 1,
            min_sample_rate_hz: 30_000,
            max_sample_rate_hz: 30_000,
            stim_kind: 0,
            stim_channels: 0,
            max_sample_block_us: 1_000,
            capability_flags: 1,
            runtime_safety_flags: 0,
            hardware_protocol_hash: PROTOCOL_HASH,
        };
        let other = encode_low_speed(0, 3, 1, &capabilities).unwrap();
        let response = DaemonResponseV1::decode(&dispatcher.handle(&other).unwrap()).unwrap();
        assert_eq!(response.error, ServiceErrorV1::UnsupportedMessage);
        assert_eq!(response.ledger_events, 0);
    }

    #[cfg(windows)]
    #[test]
    fn snapshot_client_requires_the_authenticated_scm_response() {
        use std::thread;

        use crate::ipc::{current_process_user_sid, SecurePipeOptions, SecurePipeServer};

        let temp = TempLedger::new();
        let sid = current_process_user_sid().unwrap();
        let pipe_name = format!(
            r"\\.\pipe\forge-service-query-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        );
        let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
            pipe_name: pipe_name.clone(),
            service_sid: sid.clone(),
            allowed_client_sid: sid,
        })
        .unwrap();
        let mut dispatcher = ServiceDispatcher::open(&temp.0, true, true).unwrap();
        let join =
            thread::spawn(move || server.transact_once(|request| dispatcher.handle(request)));
        let response = query_daemon_snapshot(&pipe_name, 41, 7, 5_000, 5_000).unwrap();
        assert!(response.accepted);
        assert!(response.authenticated_pipe);
        assert!(response.scm_owned);
        assert!(!response.hardware_transport_available);
        assert_eq!(response.request_id, 41);
        assert_eq!(response.epoch, 7);
        assert!(join.join().unwrap().unwrap());
    }

    #[test]
    fn protected_replay_dispatcher_reports_real_watermarks_and_seal() {
        let temp = TempLedger::new();
        fs::create_dir_all(&temp.0).unwrap();
        let mut dispatcher =
            ServiceDispatcher::open_protected_replay(temp.0.join("ledger"), &temp.0, true, true)
                .unwrap();
        for (request_id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
        ] {
            let response =
                DaemonResponseV1::decode(&dispatcher.handle(&command(request_id, kind)).unwrap())
                    .unwrap();
            assert!(response.accepted);
            assert!(response.protected_replay_available);
            assert!(!response.hardware_transport_available);
        }
        std::thread::sleep(std::time::Duration::from_millis(15));
        let snapshot = DaemonResponseV1::decode(
            &dispatcher
                .handle(&command(4, RunCommandKind::GetSnapshot))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(snapshot.state, RunState::Recording);
        assert!(snapshot.generated_record_count.unwrap_or_default() > 0);
        assert_eq!(snapshot.queue_capacity_slots, Some(4));
        assert_eq!(snapshot.active_epoch, Some(1));
        assert_eq!(snapshot.highest_epoch, 1);
        assert_eq!(snapshot.active_run_id, [0x11; 16]);
        assert_eq!(snapshot.active_target_device_id, [0x22; 16]);
        assert_eq!(snapshot.active_frozen_config_hash, [0x33; 32]);

        let stopped = DaemonResponseV1::decode(
            &dispatcher
                .handle(&command(5, RunCommandKind::Stop))
                .unwrap(),
        )
        .unwrap();
        assert!(stopped.accepted);
        assert_eq!(stopped.state, RunState::JournalSealed);
        assert_eq!(stopped.committed_record_count, stopped.durable_record_count);
        assert!(stopped.expected_last_journal_sequence.is_some());
        assert_eq!(stopped.active_epoch, None);
        assert_eq!(stopped.latest_sealed_run_id, [0x11; 16]);
    }
}
