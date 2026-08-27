//! Fail-closed host-side control transaction tracking for one direct FT601 Pod.
//!
//! Ordinary replies prove transport-level request/reply identity only. A Stop
//! acknowledgement is accepted only through the companion
//! `DirectPodStopBoundaryV1` hash, recomputed from final source records already
//! appended to the journal. The SCM Run lifecycle remains unavailable until
//! the Receiver Pod implements that exact ordering and the adapter is integrated
//! and qualified against real hardware.

use std::io;

use forge_protocol_v1::{
    decode_low_speed, sha256, AckV1, DeviceCapabilitiesV1, Hash32, Id16, MessageKind, NackV1,
    ReplayRequestV1, RunCommandV1, WireBody, CAP_ACK_REPLAY, CAP_GLOBAL_TIME, CAP_STOP_ACK,
    PROTOCOL_HASH,
};

#[cfg(windows)]
use crate::d3xx::D3xxDevice;
use crate::d3xx_admission::VerifiedFt601Admission;
use crate::dhl_identity_admission::AdmittedDhlIdentityV1;
use crate::direct_pod_replay::DirectPodReplayBoundaryTracker;
use crate::direct_pod_stop::DirectPodStopBoundaryTracker;

const TRANSPORT_DIRECT_D3XX: u8 = 1;
const RUN_SCOPE_RECORDING: u16 = 1;
const RUN_COMMAND_PREPARE: u16 = 1;
const RUN_COMMAND_ABORT: u16 = 5;
const REQUIRED_ACQUISITION_CAPABILITIES: u32 = CAP_ACK_REPLAY | CAP_GLOBAL_TIME | CAP_STOP_ACK;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectPodSendDecision {
    Send,
    AlreadyPending,
    AlreadyCompleted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectPodReply {
    Ack(AckV1),
    Nack(NackV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchedDirectPodReply {
    pub request_id: u64,
    pub epoch: u64,
    pub request_kind: MessageKind,
    pub run_command: Option<u16>,
    pub reply: DirectPodReply,
    pub request_sha256: Hash32,
    pub reply_sha256: Hash32,
    pub duplicate: bool,
    /// True only for a Stop Ack whose receipt hash matches the exact boundary
    /// recomputed from records already appended to the journal.
    pub source_stop_boundary_verified: bool,
    /// True only after the requested Replay range was appended, made durable,
    /// and bound by the matching hardware ACK receipt.
    pub replay_boundary_verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodControlSnapshot {
    pub transport_epoch: u64,
    pub capability_admitted: bool,
    pub pending_request_id: Option<u64>,
    pub highest_request_id: Option<u64>,
    pub sent_request_count: u64,
    pub matched_reply_count: u64,
    pub duplicate_reply_count: u64,
    pub poisoned: bool,
}

#[derive(Clone, Debug)]
struct AdmittedCapabilities {
    body: DeviceCapabilitiesV1,
    message_sha256: Hash32,
}

#[derive(Clone, Debug)]
struct PendingRequest {
    request_id: u64,
    kind: MessageKind,
    run_command: Option<u16>,
    deadline_global_time_ns: u64,
    message_sha256: Hash32,
}

#[derive(Clone, Debug)]
struct CompletedRequest {
    request_id: u64,
    kind: MessageKind,
    run_command: Option<u16>,
    request_sha256: Hash32,
    reply_sha256: Hash32,
    reply: DirectPodReply,
    source_stop_boundary_verified: bool,
    replay_boundary_verified: bool,
}

pub struct DirectPodControlTracker {
    transport_epoch: u64,
    capabilities: Option<AdmittedCapabilities>,
    pending: Option<PendingRequest>,
    completed: Option<CompletedRequest>,
    highest_request_id: Option<u64>,
    sent_request_count: u64,
    matched_reply_count: u64,
    duplicate_reply_count: u64,
    poisoned: bool,
}

impl DirectPodControlTracker {
    pub fn new(transport_epoch: u64) -> io::Result<Self> {
        if transport_epoch == 0 {
            return Err(invalid_input("direct-Pod control epoch must be nonzero"));
        }
        Ok(Self {
            transport_epoch,
            capabilities: None,
            pending: None,
            completed: None,
            highest_request_id: None,
            sent_request_count: 0,
            matched_reply_count: 0,
            duplicate_reply_count: 0,
            poisoned: false,
        })
    }

    /// Admits exactly one hardware capability statement for this transport
    /// epoch and binds it to the protected FT601 admission receipt.
    pub fn admit_capabilities(
        &mut self,
        message: &[u8],
        admission: &VerifiedFt601Admission,
    ) -> io::Result<DeviceCapabilitiesV1> {
        self.admit_capabilities_values(
            message,
            admission.device_id(),
            admission.hardware_protocol_hash(),
        )
    }

    /// Registers a message immediately before the owning transport writes it.
    /// A `Send` decision creates the sole in-flight transaction. If the write
    /// then fails, the owner must call `poison_after_transport_failure`.
    pub fn admit_outbound(
        &mut self,
        message: &[u8],
        now_global_time_ns: u64,
    ) -> io::Result<DirectPodSendDecision> {
        self.admit_outbound_inner(message, now_global_time_ns, None)
    }

    pub fn admit_replay_outbound(
        &mut self,
        message: &[u8],
        now_global_time_ns: u64,
        boundary: &DirectPodReplayBoundaryTracker,
    ) -> io::Result<DirectPodSendDecision> {
        self.admit_outbound_inner(message, now_global_time_ns, Some(boundary))
    }

    fn admit_outbound_inner(
        &mut self,
        message: &[u8],
        now_global_time_ns: u64,
        replay_boundary: Option<&DirectPodReplayBoundaryTracker>,
    ) -> io::Result<DirectPodSendDecision> {
        self.require_healthy()?;
        if self.capabilities.is_none() {
            return Err(permission_denied(
                "direct-Pod capabilities must be admitted before control",
            ));
        }
        if now_global_time_ns == 0 {
            return Err(invalid_input("current hardware global time is required"));
        }

        let decoded = decode_low_speed(message)
            .map_err(|_| invalid_data("outbound direct-Pod control is not exact protocol v1"))?;
        if decoded.epoch != self.transport_epoch {
            return Err(invalid_data("outbound direct-Pod control epoch mismatch"));
        }
        let (run_command, deadline_global_time_ns) = match decoded.kind {
            MessageKind::RunCommand => {
                let command = RunCommandV1::decode_body(&decoded.body)
                    .map_err(|_| invalid_data("outbound RunCommandV1 is invalid"))?;
                if command.scope != RUN_SCOPE_RECORDING
                    || !(RUN_COMMAND_PREPARE..=RUN_COMMAND_ABORT).contains(&command.command)
                    || command.target_device_id
                        != self.capabilities.as_ref().unwrap().body.device_id
                {
                    return Err(permission_denied(
                        "direct-Pod control admits only acquisition Prepare through Abort for the admitted device",
                    ));
                }
                (Some(command.command), command.deadline_global_time_ns)
            }
            MessageKind::ReplayRequest => {
                let request = ReplayRequestV1::decode_body(&decoded.body)
                    .map_err(|_| invalid_data("outbound ReplayRequestV1 is invalid"))?;
                let Some(boundary) = replay_boundary else {
                    return Err(permission_denied(
                        "ReplayRequestV1 requires an active journal-bound Replay tracker",
                    ));
                };
                boundary.verify_request_message(message)?;
                (None, request.deadline_global_time_ns)
            }
            _ => {
                return Err(permission_denied(
                    "message kind is not admitted by direct-Pod control tracking",
                ))
            }
        };
        if deadline_global_time_ns <= now_global_time_ns {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "direct-Pod control deadline has expired before send",
            ));
        }

        let message_sha256 = sha256(message);
        if let Some(pending) = &self.pending {
            if pending.request_id == decoded.request_id
                && pending.message_sha256 == message_sha256
                && pending.kind == decoded.kind
            {
                return Ok(DirectPodSendDecision::AlreadyPending);
            }
            return Err(
                self.poison("a second or contradictory request arrived while one is pending")
            );
        }
        if let Some(completed) = self.completed.clone() {
            if completed.request_id == decoded.request_id
                && completed.request_sha256 == message_sha256
                && completed.kind == decoded.kind
            {
                return Ok(DirectPodSendDecision::AlreadyCompleted);
            }
        }
        if self
            .highest_request_id
            .is_some_and(|highest| decoded.request_id <= highest)
        {
            return Err(self.poison("direct-Pod request IDs must increase within an epoch"));
        }

        self.pending = Some(PendingRequest {
            request_id: decoded.request_id,
            kind: decoded.kind,
            run_command,
            deadline_global_time_ns,
            message_sha256,
        });
        self.highest_request_id = Some(decoded.request_id);
        self.sent_request_count = self
            .sent_request_count
            .checked_add(1)
            .ok_or_else(|| self.poison("direct-Pod sent-request counter overflow"))?;
        Ok(DirectPodSendDecision::Send)
    }

    /// The only public D3XX control-write path. The request is registered
    /// before the syscall, exact duplicate pending/completed requests are not
    /// written again, and any transport failure poisons the epoch.
    #[cfg(windows)]
    pub fn write_control(
        &mut self,
        device: &mut D3xxDevice,
        message: &[u8],
        now_global_time_ns: u64,
    ) -> io::Result<DirectPodSendDecision> {
        let decision = self.admit_outbound(message, now_global_time_ns)?;
        if decision == DirectPodSendDecision::Send {
            if let Err(error) = device.write_control(message) {
                self.poison_after_transport_failure();
                return Err(error);
            }
        }
        Ok(decision)
    }

    pub fn handle_reply(
        &mut self,
        message: &[u8],
        now_global_time_ns: u64,
    ) -> io::Result<MatchedDirectPodReply> {
        self.handle_reply_inner(message, now_global_time_ns, None, None)
    }

    pub fn handle_reply_with_stop_boundary(
        &mut self,
        message: &[u8],
        now_global_time_ns: u64,
        boundary: &DirectPodStopBoundaryTracker,
    ) -> io::Result<MatchedDirectPodReply> {
        self.handle_reply_inner(message, now_global_time_ns, Some(boundary), None)
    }

    pub fn handle_reply_with_replay_boundary(
        &mut self,
        message: &[u8],
        now_global_time_ns: u64,
        boundary: &mut DirectPodReplayBoundaryTracker,
    ) -> io::Result<MatchedDirectPodReply> {
        self.handle_reply_inner(message, now_global_time_ns, None, Some(boundary))
    }

    fn handle_reply_inner(
        &mut self,
        message: &[u8],
        now_global_time_ns: u64,
        stop_boundary: Option<&DirectPodStopBoundaryTracker>,
        mut replay_boundary: Option<&mut DirectPodReplayBoundaryTracker>,
    ) -> io::Result<MatchedDirectPodReply> {
        self.require_healthy()?;
        if now_global_time_ns == 0 {
            return Err(invalid_input("current hardware global time is required"));
        }
        let decoded = decode_low_speed(message)
            .map_err(|_| self.poison("inbound direct-Pod reply is not exact protocol v1"))?;
        let reply_sha256 = sha256(message);

        if let Some(completed) = self.completed.clone() {
            if decoded.request_id == completed.request_id {
                if decoded.epoch == self.transport_epoch && reply_sha256 == completed.reply_sha256 {
                    self.duplicate_reply_count = self
                        .duplicate_reply_count
                        .checked_add(1)
                        .ok_or_else(|| self.poison("direct-Pod duplicate counter overflow"))?;
                    return Ok(MatchedDirectPodReply {
                        request_id: completed.request_id,
                        epoch: self.transport_epoch,
                        request_kind: completed.kind,
                        run_command: completed.run_command,
                        reply: completed.reply.clone(),
                        request_sha256: completed.request_sha256,
                        reply_sha256: completed.reply_sha256,
                        duplicate: true,
                        source_stop_boundary_verified: completed.source_stop_boundary_verified,
                        replay_boundary_verified: completed.replay_boundary_verified,
                    });
                }
                return Err(
                    self.poison("completed direct-Pod request received a contradictory reply")
                );
            }
        }

        let pending = match self.pending.clone() {
            Some(pending) => pending,
            None => return Err(self.poison("unsolicited direct-Pod reply")),
        };
        if now_global_time_ns > pending.deadline_global_time_ns {
            return Err(self.poison("direct-Pod reply arrived after its deadline"));
        }
        if decoded.request_id != pending.request_id || decoded.epoch != self.transport_epoch {
            return Err(self.poison("direct-Pod reply request ID or epoch mismatch"));
        }
        let mut source_stop_boundary_verified = false;
        let mut replay_boundary_verified = false;
        let reply = match decoded.kind {
            MessageKind::Ack => {
                let ack = AckV1::decode_body(&decoded.body)
                    .map_err(|_| self.poison("direct-Pod AckV1 is invalid"))?;
                if ack.acknowledged_request_id != pending.request_id
                    || ack.applied_epoch != self.transport_epoch
                {
                    return Err(self.poison("direct-Pod AckV1 identity mismatch"));
                }
                if pending.run_command == Some(4) {
                    let Some(boundary) = stop_boundary else {
                        return Err(
                            self.poison("Stop AckV1 requires a journaled source-boundary receipt")
                        );
                    };
                    if boundary
                        .verify_stop_ack(self.transport_epoch, pending.request_id, &ack)
                        .is_err()
                    {
                        return Err(
                            self.poison("Stop AckV1 contradicts the journaled source boundary")
                        );
                    }
                    source_stop_boundary_verified = true;
                }
                if pending.kind == MessageKind::ReplayRequest {
                    let Some(boundary) = replay_boundary.as_mut() else {
                        return Err(
                            self.poison("Replay AckV1 requires a complete durable Replay boundary")
                        );
                    };
                    if boundary.verify_ack(&ack).is_err() || boundary.mark_verified().is_err() {
                        return Err(
                            self.poison("Replay AckV1 contradicts the durable Replay boundary")
                        );
                    }
                    replay_boundary_verified = true;
                }
                DirectPodReply::Ack(ack)
            }
            MessageKind::Nack => {
                let nack = NackV1::decode_body(&decoded.body)
                    .map_err(|_| self.poison("direct-Pod NackV1 is invalid"))?;
                if nack.rejected_request_id != pending.request_id
                    || nack.current_epoch != self.transport_epoch
                {
                    return Err(self.poison("direct-Pod NackV1 identity mismatch"));
                }
                if pending.kind == MessageKind::ReplayRequest {
                    let Some(boundary) = replay_boundary.as_mut() else {
                        return Err(
                            self.poison("Replay NackV1 requires the active Replay boundary")
                        );
                    };
                    if boundary.reject_before_data().is_err() {
                        return Err(self.poison("Replay NackV1 arrived after replay data began"));
                    }
                }
                DirectPodReply::Nack(nack)
            }
            _ => return Err(self.poison("direct-Pod reply kind is neither AckV1 nor NackV1")),
        };

        let completed = CompletedRequest {
            request_id: pending.request_id,
            kind: pending.kind,
            run_command: pending.run_command,
            request_sha256: pending.message_sha256,
            reply_sha256,
            reply: reply.clone(),
            source_stop_boundary_verified,
            replay_boundary_verified,
        };
        self.pending = None;
        self.completed = Some(completed.clone());
        self.matched_reply_count = self
            .matched_reply_count
            .checked_add(1)
            .ok_or_else(|| self.poison("direct-Pod matched-reply counter overflow"))?;
        Ok(MatchedDirectPodReply {
            request_id: completed.request_id,
            epoch: self.transport_epoch,
            request_kind: completed.kind,
            run_command: completed.run_command,
            reply,
            request_sha256: completed.request_sha256,
            reply_sha256: completed.reply_sha256,
            duplicate: false,
            source_stop_boundary_verified,
            replay_boundary_verified,
        })
    }

    pub fn check_timeout(&mut self, now_global_time_ns: u64) -> io::Result<()> {
        self.require_healthy()?;
        if now_global_time_ns == 0 {
            return Err(invalid_input("current hardware global time is required"));
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| now_global_time_ns > pending.deadline_global_time_ns)
        {
            return Err(self.poison("direct-Pod control reply deadline expired"));
        }
        Ok(())
    }

    pub fn finish(&mut self) -> io::Result<()> {
        self.require_healthy()?;
        if self.pending.is_some() {
            return Err(self.poison("transport closed with an unresolved direct-Pod request"));
        }
        Ok(())
    }

    pub fn poison_after_transport_failure(&mut self) {
        self.poisoned = true;
    }

    pub fn reset(&mut self, transport_epoch: u64) -> io::Result<()> {
        if transport_epoch == 0 || transport_epoch == self.transport_epoch {
            return Err(invalid_input(
                "direct-Pod control recovery requires a fresh nonzero epoch",
            ));
        }
        *self = Self::new(transport_epoch)?;
        Ok(())
    }

    pub fn snapshot(&self) -> DirectPodControlSnapshot {
        DirectPodControlSnapshot {
            transport_epoch: self.transport_epoch,
            capability_admitted: self.capabilities.is_some(),
            pending_request_id: self.pending.as_ref().map(|pending| pending.request_id),
            highest_request_id: self.highest_request_id,
            sent_request_count: self.sent_request_count,
            matched_reply_count: self.matched_reply_count,
            duplicate_reply_count: self.duplicate_reply_count,
            poisoned: self.poisoned,
        }
    }

    /// Cross-checks an already admitted Headstage identity against the first
    /// DeviceCapabilities statement.  This is deliberately owned by the
    /// control epoch: a successful DHL capsule admission must not be promoted
    /// or retained until the Pod has proven it can carry that identity.
    pub(crate) fn validate_admitted_identity_against_capabilities(
        &mut self,
        admitted: &AdmittedDhlIdentityV1,
    ) -> io::Result<()> {
        self.require_healthy()?;
        let Some(capabilities) = self.capabilities.as_ref().map(|value| value.body.clone()) else {
            return Err(self.poison("admitted DHL identity requires DeviceCapabilitiesV1 first"));
        };

        if capabilities.max_channels_per_pod < admitted.identity.acquisition_channel_count {
            return Err(self.poison(
                "DeviceCapabilitiesV1 max channel count is below the admitted DHL identity",
            ));
        }

        // The current wire contract has exactly one legal sample format: LE
        // signed i16, represented by bit 0. Keep the explicit check here even
        // though the wire decoder already rejects other Descriptor formats.
        if admitted.descriptor.sample_format != 1 || capabilities.sample_format_mask & 1 == 0 {
            return Err(self.poison(
                "DeviceCapabilitiesV1 sample format mask does not cover the admitted DHL identity",
            ));
        }

        let numerator = u64::from(admitted.approved_sample_rate_numerator_hz);
        let denominator = u64::from(admitted.approved_sample_rate_denominator);
        if denominator == 0 {
            return Err(self.poison("admitted DHL identity has a zero sample-rate denominator"));
        }
        let minimum = u64::from(capabilities.min_sample_rate_hz)
            .checked_mul(denominator)
            .ok_or_else(|| self.poison("minimum sample-rate bound overflowed"))?;
        let maximum = u64::from(capabilities.max_sample_rate_hz)
            .checked_mul(denominator)
            .ok_or_else(|| self.poison("maximum sample-rate bound overflowed"))?;
        if numerator < minimum || numerator > maximum {
            return Err(self.poison(
                "admitted DHL identity rational sample rate is outside DeviceCapabilitiesV1 bounds",
            ));
        }
        Ok(())
    }

    fn admit_capabilities_values(
        &mut self,
        message: &[u8],
        expected_device_id: Id16,
        expected_hardware_protocol_hash: Hash32,
    ) -> io::Result<DeviceCapabilitiesV1> {
        self.require_healthy()?;
        if self.pending.is_some() || self.highest_request_id.is_some() {
            return Err(self.poison("capabilities arrived after direct-Pod control began"));
        }
        let decoded = decode_low_speed(message)
            .map_err(|_| self.poison("direct-Pod capabilities are not exact protocol v1"))?;
        if decoded.kind != MessageKind::DeviceCapabilities || decoded.epoch != self.transport_epoch
        {
            return Err(self.poison("direct-Pod capability message kind or epoch mismatch"));
        }
        let body = DeviceCapabilitiesV1::decode_body(&decoded.body)
            .map_err(|_| self.poison("DeviceCapabilitiesV1 body is invalid"))?;
        if body.device_id != expected_device_id
            || body.transport != TRANSPORT_DIRECT_D3XX
            || body.max_pods != 1
            || body.hardware_protocol_hash != expected_hardware_protocol_hash
            || body.hardware_protocol_hash != PROTOCOL_HASH
            || body.capability_flags & REQUIRED_ACQUISITION_CAPABILITIES
                != REQUIRED_ACQUISITION_CAPABILITIES
        {
            return Err(self.poison("direct-Pod capabilities contradict admission policy"));
        }
        let message_sha256 = sha256(message);
        if let Some(existing) = &self.capabilities {
            if existing.message_sha256 == message_sha256 && existing.body == body {
                return Ok(body);
            }
            return Err(self.poison("direct-Pod capabilities changed within an epoch"));
        }
        self.capabilities = Some(AdmittedCapabilities {
            body: body.clone(),
            message_sha256,
        });
        Ok(body)
    }

    fn require_healthy(&self) -> io::Result<()> {
        if self.poisoned {
            Err(invalid_data("direct-Pod control epoch is poisoned"))
        } else {
            Ok(())
        }
    }

    fn poison(&mut self, message: &'static str) -> io::Error {
        self.poisoned = true;
        invalid_data(message)
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn permission_denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_pod_replay::DirectPodReplayBoundaryTracker;
    use crate::journal::AppendReceipt;
    use crate::source::{DeterministicReplayConfig, DeterministicReplaySource};
    use forge_protocol_v1::{crc32c, decode_record, encode_low_speed, AckV1, NackV1, RunCommandV1};

    const EPOCH: u64 = 7;
    const DEVICE_ID: Id16 = [2; 16];

    fn capability_message(epoch: u64, device_id: Id16, flags: u32) -> Vec<u8> {
        encode_low_speed(
            0,
            900,
            epoch,
            &DeviceCapabilitiesV1 {
                device_id,
                transport: TRANSPORT_DIRECT_D3XX,
                max_pods: 1,
                max_channels_per_pod: 256,
                sample_format_mask: 1,
                min_sample_rate_hz: 30_000,
                max_sample_rate_hz: 30_000,
                stim_kind: 0,
                stim_channels: 0,
                max_sample_block_us: 1_000,
                capability_flags: flags,
                runtime_safety_flags: 0,
                hardware_protocol_hash: PROTOCOL_HASH,
            },
        )
        .unwrap()
    }

    fn command_message(request_id: u64, epoch: u64, command: u16, deadline: u64) -> Vec<u8> {
        encode_low_speed(
            0,
            request_id,
            epoch,
            &RunCommandV1 {
                command,
                scope: RUN_SCOPE_RECORDING,
                run_id: [1; 16],
                target_device_id: DEVICE_ID,
                deadline_global_time_ns: deadline,
                frozen_config_hash: [3; 32],
            },
        )
        .unwrap()
    }

    fn ack_message(request_id: u64, epoch: u64) -> Vec<u8> {
        ack_message_with_hash(request_id, epoch, [8; 32])
    }

    fn ack_message_with_hash(request_id: u64, epoch: u64, receipt_hash: Hash32) -> Vec<u8> {
        encode_low_speed(
            0,
            request_id,
            epoch,
            &AckV1 {
                acknowledged_request_id: request_id,
                applied_epoch: epoch,
                ack_code: 1,
                state_code: 4,
                receipt_hash,
            },
        )
        .unwrap()
    }

    fn admitted_tracker() -> DirectPodControlTracker {
        let mut tracker = DirectPodControlTracker::new(EPOCH).unwrap();
        tracker
            .admit_capabilities_values(
                &capability_message(EPOCH, DEVICE_ID, REQUIRED_ACQUISITION_CAPABILITIES),
                DEVICE_ID,
                PROTOCOL_HASH,
            )
            .unwrap();
        tracker
    }

    fn journaled_boundary() -> DirectPodStopBoundaryTracker {
        let mut source = DeterministicReplaySource::new(DeterministicReplayConfig {
            run_id: [1; 16],
            pod_id: [3; 16],
            headstage_id: [4; 16],
            channel_layout_id: 1,
            channel_count: 4,
            samples_per_channel: 3,
            sample_rate_hz: 30_000,
            total_records: 1,
            seed: 1,
        })
        .unwrap();
        let record = source.next_encoded_record().unwrap().unwrap();
        let decoded = decode_record(&record).unwrap();
        let mut boundary =
            DirectPodStopBoundaryTracker::new([1; 16], DEVICE_ID, [3; 16], [4; 16]).unwrap();
        boundary
            .observe_journaled_record(
                &record,
                AppendReceipt {
                    journal_sequence: 0,
                    record_sequence: decoded.envelope.record_sequence,
                    pod_id: decoded.envelope.pod_id,
                    encoded_record_len: record.len() as u32,
                    encoded_record_crc32c: crc32c(&record),
                    durable: false,
                },
            )
            .unwrap();
        boundary
    }

    #[test]
    fn capabilities_bind_device_transport_protocol_and_required_flags() {
        let mut tracker = DirectPodControlTracker::new(EPOCH).unwrap();
        let message = capability_message(EPOCH, DEVICE_ID, REQUIRED_ACQUISITION_CAPABILITIES);
        let admitted = tracker
            .admit_capabilities_values(&message, DEVICE_ID, PROTOCOL_HASH)
            .unwrap();
        assert_eq!(admitted.device_id, DEVICE_ID);
        assert!(tracker
            .admit_capabilities_values(&message, DEVICE_ID, PROTOCOL_HASH)
            .is_ok());

        for (device_id, flags, hash) in [
            ([9; 16], REQUIRED_ACQUISITION_CAPABILITIES, PROTOCOL_HASH),
            (DEVICE_ID, CAP_GLOBAL_TIME | CAP_STOP_ACK, PROTOCOL_HASH),
            (DEVICE_ID, REQUIRED_ACQUISITION_CAPABILITIES, [9; 32]),
        ] {
            let mut candidate = DirectPodControlTracker::new(EPOCH).unwrap();
            assert!(candidate
                .admit_capabilities_values(
                    &capability_message(EPOCH, device_id, flags),
                    DEVICE_ID,
                    hash,
                )
                .is_err());
            assert!(candidate.snapshot().poisoned);
        }
    }

    #[test]
    fn capabilities_decoder_rejects_unsupported_sample_format_mask() {
        let mut body = DeviceCapabilitiesV1 {
            device_id: DEVICE_ID,
            transport: TRANSPORT_DIRECT_D3XX,
            max_pods: 1,
            max_channels_per_pod: 256,
            sample_format_mask: 1,
            min_sample_rate_hz: 30_000,
            max_sample_rate_hz: 30_000,
            stim_kind: 0,
            stim_channels: 0,
            max_sample_block_us: 1_000,
            capability_flags: REQUIRED_ACQUISITION_CAPABILITIES,
            runtime_safety_flags: 0,
            hardware_protocol_hash: PROTOCOL_HASH,
        }
        .encode_body()
        .unwrap();
        body[24..28].copy_from_slice(&2_u32.to_le_bytes());
        assert!(DeviceCapabilitiesV1::decode_body(&body).is_err());
    }

    #[test]
    fn one_pending_request_matches_ack_and_exact_duplicates_only() {
        let mut tracker = admitted_tracker();
        let start = command_message(1, EPOCH, 3, 1_000);
        assert_eq!(
            tracker.admit_outbound(&start, 100).unwrap(),
            DirectPodSendDecision::Send
        );
        assert_eq!(
            tracker.admit_outbound(&start, 100).unwrap(),
            DirectPodSendDecision::AlreadyPending
        );
        let reply = ack_message(1, EPOCH);
        let matched = tracker.handle_reply(&reply, 200).unwrap();
        assert_eq!(matched.run_command, Some(3));
        assert!(!matched.duplicate);
        assert!(!matched.source_stop_boundary_verified);
        assert!(matches!(matched.reply, DirectPodReply::Ack(_)));
        let duplicate = tracker.handle_reply(&reply, 201).unwrap();
        assert!(duplicate.duplicate);
        assert_eq!(
            tracker.admit_outbound(&start, 202).unwrap(),
            DirectPodSendDecision::AlreadyCompleted
        );
        assert_eq!(tracker.snapshot().duplicate_reply_count, 1);
    }

    #[test]
    fn stop_ack_requires_and_verifies_the_journaled_source_boundary() {
        let boundary = journaled_boundary();
        let mut tracker = admitted_tracker();
        let stop = command_message(5, EPOCH, 4, 1_000);
        tracker.admit_outbound(&stop, 100).unwrap();
        let receipt_hash = boundary.receipt_hash(EPOCH, 5).unwrap();
        let reply = ack_message_with_hash(5, EPOCH, receipt_hash);
        let matched = tracker
            .handle_reply_with_stop_boundary(&reply, 200, &boundary)
            .unwrap();
        assert!(matched.source_stop_boundary_verified);
        assert!(!matched.duplicate);
        assert!(tracker.handle_reply(&reply, 201).unwrap().duplicate);

        let mut missing = admitted_tracker();
        missing.admit_outbound(&stop, 100).unwrap();
        assert!(missing.handle_reply(&reply, 200).is_err());
        assert!(missing.snapshot().poisoned);

        let mut wrong = admitted_tracker();
        wrong.admit_outbound(&stop, 100).unwrap();
        let bad = ack_message_with_hash(5, EPOCH, [9; 32]);
        assert!(wrong
            .handle_reply_with_stop_boundary(&bad, 200, &boundary)
            .is_err());
        assert!(wrong.snapshot().poisoned);
    }

    #[test]
    fn generic_control_api_cannot_bypass_the_journal_bound_replay_gate() {
        let context_hash = DirectPodReplayBoundaryTracker::request_context_hash(
            [1; 16], DEVICE_ID, [3; 16], [4; 16], EPOCH, 5, 0, 1, None, 1_000, 1, [5; 32], [6; 32],
        )
        .unwrap();
        let request_body = ReplayRequestV1 {
            run_id: [1; 16],
            pod_id: [3; 16],
            first_record_sequence: 0,
            last_record_sequence_exclusive: 1,
            deadline_global_time_ns: 1_000,
            reason_code: 1,
            request_context_hash: context_hash,
        };
        let message = encode_low_speed(0, 5, EPOCH, &request_body).unwrap();
        let mut tracker = admitted_tracker();
        let error = tracker.admit_outbound(&message, 100).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!tracker.snapshot().poisoned);
        assert!(tracker.snapshot().pending_request_id.is_none());

        let boundary = DirectPodReplayBoundaryTracker::new(
            [1; 16],
            DEVICE_ID,
            [3; 16],
            [4; 16],
            EPOCH,
            5,
            request_body,
            None,
            [5; 32],
            [6; 32],
        )
        .unwrap();
        assert_eq!(
            tracker
                .admit_replay_outbound(&message, 100, &boundary)
                .unwrap(),
            DirectPodSendDecision::Send
        );
        assert!(tracker.handle_reply(&ack_message(5, EPOCH), 200).is_err());
        assert!(tracker.snapshot().poisoned);
    }

    #[test]
    fn request_ids_are_monotonic_and_contradictions_poison_epoch() {
        let mut tracker = admitted_tracker();
        let first = command_message(10, EPOCH, 1, 1_000);
        tracker.admit_outbound(&first, 100).unwrap();
        tracker.handle_reply(&ack_message(10, EPOCH), 200).unwrap();
        let reused = command_message(10, EPOCH, 2, 1_000);
        assert!(tracker.admit_outbound(&reused, 300).is_err());
        assert!(tracker.snapshot().poisoned);

        tracker.reset(EPOCH + 1).unwrap();
        assert!(!tracker.snapshot().capability_admitted);
        assert!(!tracker.snapshot().poisoned);
    }

    #[test]
    fn timeout_wrong_reply_and_unresolved_finish_fail_closed() {
        let mut tracker = admitted_tracker();
        tracker
            .admit_outbound(&command_message(1, EPOCH, 3, 500), 100)
            .unwrap();
        assert!(tracker.check_timeout(501).is_err());
        assert!(tracker.snapshot().poisoned);

        let mut tracker = admitted_tracker();
        tracker
            .admit_outbound(&command_message(2, EPOCH, 3, 500), 100)
            .unwrap();
        assert!(tracker.handle_reply(&ack_message(3, EPOCH), 200).is_err());
        assert!(tracker.snapshot().poisoned);

        let mut tracker = admitted_tracker();
        tracker
            .admit_outbound(&command_message(3, EPOCH, 3, 500), 100)
            .unwrap();
        assert!(tracker.finish().is_err());
        assert!(tracker.snapshot().poisoned);
    }

    #[test]
    fn nack_is_matched_but_never_relabelled_as_success() {
        let mut tracker = admitted_tracker();
        tracker
            .admit_outbound(&command_message(4, EPOCH, 2, 1_000), 100)
            .unwrap();
        let nack = encode_low_speed(
            0,
            4,
            EPOCH,
            &NackV1 {
                rejected_request_id: 4,
                current_epoch: EPOCH,
                error_code: 12,
                retryable: 0,
                detail_code: 99,
                state_hash: [7; 32],
            },
        )
        .unwrap();
        let matched = tracker.handle_reply(&nack, 200).unwrap();
        assert!(matches!(matched.reply, DirectPodReply::Nack(_)));
        assert!(!matched.source_stop_boundary_verified);
    }

    #[test]
    fn host_only_commands_and_wrong_device_are_never_admitted() {
        let mut tracker = admitted_tracker();
        for command in [6, 7] {
            assert!(tracker
                .admit_outbound(&command_message(1, EPOCH, command, 1_000), 100)
                .is_err());
            assert!(!tracker.snapshot().poisoned);
        }
        let mut wrong = RunCommandV1 {
            command: 1,
            scope: RUN_SCOPE_RECORDING,
            run_id: [1; 16],
            target_device_id: [9; 16],
            deadline_global_time_ns: 1_000,
            frozen_config_hash: [3; 32],
        };
        let encoded = encode_low_speed(0, 1, EPOCH, &wrong).unwrap();
        assert!(tracker.admit_outbound(&encoded, 100).is_err());
        wrong.scope = 2;
        let encoded = encode_low_speed(0, 2, EPOCH, &wrong).unwrap();
        assert!(tracker.admit_outbound(&encoded, 100).is_err());
    }
}
