//! Durable two-phase lifecycle for a real hardware Run.
//!
//! This is deliberately separate from the replay lifecycle.  A command is
//! first persisted as requested, then completed only from a matched hardware
//! reply.  Start has a third gate: the Run does not become Recording until the
//! first canonical record has been appended to the journal.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use forge_protocol_v1::{
    crc32c, decode_low_speed, sha256, Hash32, Id16, MessageKind, ReplayRequestV1, RunCommandV1,
    WireBody,
};
use serde::Serialize;

use crate::direct_pod_replay_offer::{DirectPodReplayOfferV1, DIRECT_POD_REPLAY_OFFER_LEN};
use crate::run::RunCommandKind;

const FRAME_MAGIC: &[u8; 8] = b"FGRHWR01";
const FOOTER_MAGIC: &[u8; 8] = b"FGRHWF01";
const FRAME_VERSION: u16 = 1;
const FRAME_HEADER_LEN: usize = 32;
const FRAME_FOOTER_LEN: usize = 16;
const RUN_COMMAND_WIRE_LEN: usize = 160;
const REPLAY_REQUEST_WIRE_LEN: usize = 176;
const MAX_EVENT_PAYLOAD_LEN: usize = 320;
const MAX_LEDGER_EVENTS: usize = 2_048;

pub const HARDWARE_FAULT_DAEMON_RESTART: u32 = 1;
pub const HARDWARE_FAULT_TRANSPORT: u32 = 2;
pub const HARDWARE_FAULT_PERSISTENCE: u32 = 3;
pub const HARDWARE_FAULT_OWNER_SHUTDOWN: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareRunPhase {
    New,
    PrepareRequested,
    Prepared,
    ArmRequested,
    Armed,
    StartRequested,
    StartAcknowledged,
    Recording,
    StopRequested,
    Stopped,
    AbortRequested,
    Aborted,
    Sealed,
    Failed,
}

impl HardwareRunPhase {
    fn is_restart_sensitive(self) -> bool {
        !matches!(
            self,
            Self::New | Self::Sealed | Self::Aborted | Self::Failed
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HardwareRunReceipt {
    pub request_id: u64,
    pub epoch: u64,
    pub command: RunCommandKind,
    pub phase: HardwareRunPhase,
    /// None means the request is durable but no hardware reply is durable yet.
    pub hardware_accepted: Option<bool>,
    pub evidence_hash: Option<Hash32>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HardwareReplayReceipt {
    pub request_id: u64,
    pub epoch: u64,
    pub phase: HardwareRunPhase,
    /// None means intent is durable but no matched Pod reply is durable yet.
    pub hardware_accepted: Option<bool>,
    pub replay_boundary_verified: bool,
    pub evidence_hash: Option<Hash32>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HardwareRunStatus {
    pub phase: HardwareRunPhase,
    pub active_epoch: Option<u64>,
    pub highest_epoch: u64,
    pub active_run_id_hex: Option<String>,
    pub active_target_device_id_hex: Option<String>,
    pub active_frozen_config_hash_hex: Option<String>,
    pub pending_request_id: Option<u64>,
    pub pending_replay_request_id: Option<u64>,
    pub replay_request_count: u64,
    pub verified_replay_count: u64,
    pub replay_offer_count: u64,
    pub first_journal_sequence: Option<u64>,
    pub ledger_events: u64,
    pub auto_failed_on_restart: bool,
    pub poisoned: bool,
    pub hardware_transport_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HardwareCommand {
    wire: Vec<u8>,
    wire_hash: Hash32,
    request_id: u64,
    epoch: u64,
    body: RunCommandV1,
    kind: RunCommandKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HardwareReplayRequest {
    wire: Vec<u8>,
    wire_hash: Hash32,
    request_id: u64,
    epoch: u64,
    body: ReplayRequestV1,
}

impl HardwareReplayRequest {
    fn decode(wire: &[u8]) -> io::Result<Self> {
        if wire.len() != REPLAY_REQUEST_WIRE_LEN {
            return Err(invalid_input(
                "hardware Replay request must be one exact protocol-v1 message",
            ));
        }
        let decoded = decode_low_speed(wire)
            .map_err(|_| invalid_input("hardware Replay request wire is invalid"))?;
        if decoded.kind != MessageKind::ReplayRequest
            || decoded.flags != 0
            || decoded.request_id == 0
            || decoded.epoch == 0
        {
            return Err(invalid_input(
                "hardware Replay ledger accepts only an unflagged ReplayRequestV1",
            ));
        }
        let body = ReplayRequestV1::decode_body(&decoded.body)
            .map_err(|_| invalid_input("hardware ReplayRequestV1 body is invalid"))?;
        Ok(Self {
            wire: wire.to_vec(),
            wire_hash: sha256(wire),
            request_id: decoded.request_id,
            epoch: decoded.epoch,
            body,
        })
    }

    fn key(&self) -> (u64, u64) {
        (self.epoch, self.request_id)
    }
}

impl HardwareCommand {
    fn decode(wire: &[u8]) -> io::Result<Self> {
        if wire.len() != RUN_COMMAND_WIRE_LEN {
            return Err(invalid_input(
                "hardware Run command must be one exact protocol-v1 message",
            ));
        }
        let decoded = decode_low_speed(wire)
            .map_err(|_| invalid_input("hardware Run command wire is invalid"))?;
        if decoded.kind != MessageKind::RunCommand || decoded.flags != 0 {
            return Err(invalid_input(
                "hardware lifecycle accepts only unflagged RunCommandV1 messages",
            ));
        }
        let body = RunCommandV1::decode_body(&decoded.body)
            .map_err(|_| invalid_input("hardware RunCommandV1 body is invalid"))?;
        if body.scope != 1 {
            return Err(invalid_input(
                "hardware acquisition lifecycle rejects stimulation scope",
            ));
        }
        let kind = RunCommandKind::from_wire(body.command)?;
        if !matches!(
            kind,
            RunCommandKind::Prepare
                | RunCommandKind::Arm
                | RunCommandKind::Start
                | RunCommandKind::Stop
                | RunCommandKind::Abort
        ) || decoded.request_id == 0
            || decoded.epoch == 0
        {
            return Err(invalid_input(
                "hardware lifecycle accepts only nonzero Prepare through Abort commands",
            ));
        }
        Ok(Self {
            wire: wire.to_vec(),
            wire_hash: sha256(wire),
            request_id: decoded.request_id,
            epoch: decoded.epoch,
            body,
            kind,
        })
    }

    fn key(&self) -> (u64, u64) {
        (self.epoch, self.request_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareRunContext {
    pub epoch: u64,
    pub run_id: Id16,
    pub target_device_id: Id16,
    pub frozen_config_hash: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HardwareRunEvent {
    Requested {
        command: HardwareCommand,
        requested_global_time_ns: u64,
    },
    Replied {
        epoch: u64,
        request_id: u64,
        accepted: bool,
        source_stop_boundary_verified: bool,
        evidence_hash: Hash32,
    },
    FirstRecord {
        epoch: u64,
        run_id: Id16,
        journal_sequence: u64,
        record_evidence_hash: Hash32,
    },
    Failed {
        epoch: u64,
        run_id: Id16,
        fault_code: u32,
        evidence_hash: Hash32,
    },
    Sealed {
        epoch: u64,
        run_id: Id16,
        seal_evidence_hash: Hash32,
    },
    ReplayRequested {
        request: HardwareReplayRequest,
        requested_global_time_ns: u64,
    },
    ReplayReplied {
        epoch: u64,
        request_id: u64,
        accepted: bool,
        replay_boundary_verified: bool,
        evidence_hash: Hash32,
    },
    ReplayOffered {
        offer: DirectPodReplayOfferV1,
        offer_hash: Hash32,
    },
}

impl HardwareRunEvent {
    const fn kind(&self) -> u16 {
        match self {
            Self::Requested { .. } => 1,
            Self::Replied { .. } => 2,
            Self::FirstRecord { .. } => 3,
            Self::Failed { .. } => 4,
            Self::Sealed { .. } => 5,
            Self::ReplayRequested { .. } => 6,
            Self::ReplayReplied { .. } => 7,
            Self::ReplayOffered { .. } => 8,
        }
    }
}

pub struct HardwareRunCoordinator {
    ledger: HardwareRunLedger,
    phase: HardwareRunPhase,
    context: Option<HardwareRunContext>,
    highest_epoch: u64,
    pending: Option<HardwareCommand>,
    pending_replay: Option<HardwareReplayRequest>,
    pending_replay_offer: Option<DirectPodReplayOfferV1>,
    commands: HashMap<(u64, u64), (HardwareCommand, HardwareRunReceipt)>,
    replays: HashMap<(u64, u64), (HardwareReplayRequest, HardwareReplayReceipt)>,
    verified_replay_count: u64,
    replay_offer_count: u64,
    first_journal_sequence: Option<u64>,
    auto_failed_on_restart: bool,
    poisoned: bool,
}

impl HardwareRunCoordinator {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let (mut ledger, events) = HardwareRunLedger::open(path)?;
        let mut value = Self {
            ledger: HardwareRunLedger::placeholder(),
            phase: HardwareRunPhase::New,
            context: None,
            highest_epoch: 0,
            pending: None,
            pending_replay: None,
            pending_replay_offer: None,
            commands: HashMap::new(),
            replays: HashMap::new(),
            verified_replay_count: 0,
            replay_offer_count: 0,
            first_journal_sequence: None,
            auto_failed_on_restart: false,
            poisoned: false,
        };
        for event in &events {
            value.apply_event(event, true)?;
        }
        if value.phase.is_restart_sensitive() {
            let context = value.context.ok_or_else(|| {
                invalid_data("restart-sensitive hardware Run has no active identity")
            })?;
            let event = HardwareRunEvent::Failed {
                epoch: context.epoch,
                run_id: context.run_id,
                fault_code: HARDWARE_FAULT_DAEMON_RESTART,
                evidence_hash: sha256(b"forge-hardware-run-restart-fail-closed-v1"),
            };
            ledger.append(&event)?;
            value.apply_event(&event, false)?;
            value.auto_failed_on_restart = true;
        }
        value.ledger = ledger;
        Ok(value)
    }

    /// Durably records intent before the caller writes the command to hardware.
    pub fn request(
        &mut self,
        wire: &[u8],
        now_global_time_ns: u64,
    ) -> io::Result<HardwareRunReceipt> {
        self.ensure_usable()?;
        let command = HardwareCommand::decode(wire)?;
        if let Some((prior, receipt)) = self.commands.get(&command.key()) {
            return if prior.wire == command.wire {
                Ok(receipt.clone())
            } else {
                Err(invalid_input(
                    "hardware Run request ID was reused with different bytes",
                ))
            };
        }
        if self.pending.is_some()
            || self.pending_replay.is_some()
            || self.pending_replay_offer.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "one hardware control transaction is already pending",
            ));
        }
        if now_global_time_ns == 0 || now_global_time_ns >= command.body.deadline_global_time_ns {
            return Err(invalid_input(
                "hardware Run command is expired or lacks hardware-global time",
            ));
        }
        self.validate_request(&command)?;
        let event = HardwareRunEvent::Requested {
            command,
            requested_global_time_ns: now_global_time_ns,
        };
        self.persist_then_apply(event)?;
        Ok(self
            .commands
            .get(&self.pending.as_ref().unwrap().key())
            .unwrap()
            .1
            .clone())
    }

    /// Records the already matched and semantically checked hardware reply.
    /// Stop acceptance additionally requires the source-boundary proof produced
    /// by DirectPodStopBoundaryTracker.
    pub fn complete_reply(
        &mut self,
        epoch: u64,
        request_id: u64,
        accepted: bool,
        evidence_hash: Hash32,
        source_stop_boundary_verified: bool,
    ) -> io::Result<HardwareRunReceipt> {
        self.ensure_usable()?;
        if !evidence_hash.iter().any(|byte| *byte != 0) {
            return Err(invalid_input(
                "hardware reply evidence hash must be nonzero",
            ));
        }
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| invalid_input("there is no pending hardware Run command"))?;
        if pending.key() != (epoch, request_id) {
            return Err(invalid_input(
                "hardware reply does not match the pending Run command",
            ));
        }
        if accepted && pending.kind == RunCommandKind::Stop && !source_stop_boundary_verified {
            return Err(invalid_input(
                "Stop acceptance lacks the journaled source-boundary proof",
            ));
        }
        if pending.kind != RunCommandKind::Stop && source_stop_boundary_verified {
            return Err(invalid_input(
                "source Stop-boundary proof was attached to a non-Stop command",
            ));
        }
        let key = pending.key();
        self.persist_then_apply(HardwareRunEvent::Replied {
            epoch,
            request_id,
            accepted,
            source_stop_boundary_verified,
            evidence_hash,
        })?;
        Ok(self.commands.get(&key).unwrap().1.clone())
    }

    /// Durably records a journal-bound Replay intent before hardware OUT. The
    /// request is legal only while the confirmed Run is Recording and no Run
    /// command or other Replay is pending.
    pub fn request_replay(
        &mut self,
        wire: &[u8],
        now_global_time_ns: u64,
    ) -> io::Result<HardwareReplayReceipt> {
        self.ensure_usable()?;
        let request = HardwareReplayRequest::decode(wire)?;
        if let Some((prior, receipt)) = self.replays.get(&request.key()) {
            return if prior.wire == request.wire {
                Ok(receipt.clone())
            } else {
                Err(invalid_input(
                    "hardware Replay request ID was reused with different bytes",
                ))
            };
        }
        if self.pending.is_some() || self.pending_replay.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "one hardware control transaction is already pending",
            ));
        }
        if now_global_time_ns == 0 || now_global_time_ns >= request.body.deadline_global_time_ns {
            return Err(invalid_input(
                "hardware Replay request is expired or lacks hardware-global time",
            ));
        }
        let context = self
            .context
            .ok_or_else(|| invalid_input("hardware Replay has no active Run"))?;
        if self.phase != HardwareRunPhase::Recording
            || request.epoch != context.epoch
            || request.body.run_id != context.run_id
        {
            return Err(invalid_input(
                "hardware Replay identity does not match the confirmed Recording Run",
            ));
        }
        if let Some(offer) = self.pending_replay_offer {
            if request.body.run_id != offer.run_id
                || request.body.pod_id != offer.pod_id
                || request.epoch != offer.transport_epoch
                || request.body.first_record_sequence != offer.first_missing_record_sequence
                || request.body.last_record_sequence_exclusive
                    != offer.last_missing_record_sequence_exclusive
                || request.body.deadline_global_time_ns != offer.deadline_global_time_ns
                || request.body.reason_code != offer.reason_code
            {
                return Err(invalid_input(
                    "hardware Replay request does not match the durable source offer",
                ));
            }
        }
        self.persist_then_apply(HardwareRunEvent::ReplayRequested {
            request,
            requested_global_time_ns: now_global_time_ns,
        })?;
        Ok(self
            .replays
            .get(&self.pending_replay.as_ref().unwrap().key())
            .unwrap()
            .1
            .clone())
    }

    /// Persists source-authored Replay availability before the corresponding
    /// request intent and hardware OUT. Exact duplicate evidence is not
    /// accepted as a new offer; callers retry the already durable request.
    pub fn record_replay_offer(&mut self, encoded_offer: &[u8]) -> io::Result<()> {
        self.ensure_usable()?;
        if encoded_offer.len() != DIRECT_POD_REPLAY_OFFER_LEN {
            return Err(invalid_input("hardware Replay offer has the wrong length"));
        }
        let offer = DirectPodReplayOfferV1::decode(encoded_offer)?;
        let context = self
            .context
            .ok_or_else(|| invalid_input("hardware Replay offer has no active Run"))?;
        if self.phase != HardwareRunPhase::Recording
            || self.pending.is_some()
            || self.pending_replay.is_some()
            || self.pending_replay_offer.is_some()
            || offer.run_id != context.run_id
            || offer.device_id != context.target_device_id
            || offer.transport_epoch != context.epoch
        {
            return Err(invalid_input(
                "hardware Replay offer contradicts the active Recording lifecycle",
            ));
        }
        self.persist_then_apply(HardwareRunEvent::ReplayOffered {
            offer,
            offer_hash: sha256(encoded_offer),
        })
    }

    /// Persists a matched Replay reply. Acceptance requires the durable Replay
    /// boundary proof; rejection is fail-closed for the active Run.
    pub fn complete_replay_reply(
        &mut self,
        epoch: u64,
        request_id: u64,
        accepted: bool,
        evidence_hash: Hash32,
        replay_boundary_verified: bool,
    ) -> io::Result<HardwareReplayReceipt> {
        self.ensure_usable()?;
        if evidence_hash == [0; 32] {
            return Err(invalid_input(
                "hardware Replay reply evidence hash must be nonzero",
            ));
        }
        let pending = self
            .pending_replay
            .as_ref()
            .ok_or_else(|| invalid_input("there is no pending hardware Replay request"))?;
        if pending.key() != (epoch, request_id)
            || (accepted && !replay_boundary_verified)
            || (!accepted && replay_boundary_verified)
        {
            return Err(invalid_input(
                "hardware Replay reply contradicts its request or durable boundary proof",
            ));
        }
        let key = pending.key();
        self.persist_then_apply(HardwareRunEvent::ReplayReplied {
            epoch,
            request_id,
            accepted,
            replay_boundary_verified,
            evidence_hash,
        })?;
        Ok(self.replays.get(&key).unwrap().1.clone())
    }

    /// Third Start gate: call only after this exact canonical record has been
    /// appended successfully. USB arrival time is never an input.
    pub fn observe_first_journaled_record(
        &mut self,
        epoch: u64,
        run_id: Id16,
        journal_sequence: u64,
        record_evidence_hash: Hash32,
    ) -> io::Result<HardwareRunReceipt> {
        self.ensure_usable()?;
        if !record_evidence_hash.iter().any(|byte| *byte != 0) {
            return Err(invalid_input("first-record evidence hash must be nonzero"));
        }
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| invalid_input("Start is not awaiting its first journaled record"))?;
        if self.phase != HardwareRunPhase::StartAcknowledged
            || pending.kind != RunCommandKind::Start
            || pending.epoch != epoch
            || pending.body.run_id != run_id
        {
            return Err(invalid_input(
                "first record does not match the acknowledged Start",
            ));
        }
        let key = pending.key();
        self.persist_then_apply(HardwareRunEvent::FirstRecord {
            epoch,
            run_id,
            journal_sequence,
            record_evidence_hash,
        })?;
        Ok(self.commands.get(&key).unwrap().1.clone())
    }

    pub fn fail_closed(&mut self, fault_code: u32, evidence_hash: Hash32) -> io::Result<()> {
        self.ensure_usable()?;
        if fault_code == 0 || !evidence_hash.iter().any(|byte| *byte != 0) {
            return Err(invalid_input("hardware failure evidence is invalid"));
        }
        let context = self
            .context
            .ok_or_else(|| invalid_input("there is no hardware Run to fail closed"))?;
        if !self.phase.is_restart_sensitive() {
            return Err(invalid_input("hardware Run is not active"));
        }
        self.persist_then_apply(HardwareRunEvent::Failed {
            epoch: context.epoch,
            run_id: context.run_id,
            fault_code,
            evidence_hash,
        })
    }

    pub fn mark_sealed(&mut self, seal_evidence_hash: Hash32) -> io::Result<()> {
        self.ensure_usable()?;
        if self.phase != HardwareRunPhase::Stopped
            || !seal_evidence_hash.iter().any(|byte| *byte != 0)
        {
            return Err(invalid_input(
                "hardware Run can seal only after verified Stop with nonzero evidence",
            ));
        }
        let context = self.context.unwrap();
        self.persist_then_apply(HardwareRunEvent::Sealed {
            epoch: context.epoch,
            run_id: context.run_id,
            seal_evidence_hash,
        })
    }

    pub fn phase(&self) -> HardwareRunPhase {
        self.phase
    }

    pub fn pending_command(&self) -> Option<(u64, u64, RunCommandKind)> {
        self.pending
            .as_ref()
            .map(|command| (command.epoch, command.request_id, command.kind))
    }

    pub fn pending_replay(&self) -> Option<(u64, u64)> {
        self.pending_replay
            .as_ref()
            .map(|request| (request.epoch, request.request_id))
    }

    pub fn active_context(&self) -> Option<HardwareRunContext> {
        self.context
    }

    pub fn status(&self) -> HardwareRunStatus {
        HardwareRunStatus {
            phase: self.phase,
            active_epoch: self.context.map(|value| value.epoch),
            highest_epoch: self.highest_epoch,
            active_run_id_hex: self.context.map(|value| hex(value.run_id)),
            active_target_device_id_hex: self.context.map(|value| hex(value.target_device_id)),
            active_frozen_config_hash_hex: self.context.map(|value| hex(value.frozen_config_hash)),
            pending_request_id: self.pending.as_ref().map(|value| value.request_id),
            pending_replay_request_id: self.pending_replay.as_ref().map(|value| value.request_id),
            replay_request_count: self.replays.len() as u64,
            verified_replay_count: self.verified_replay_count,
            replay_offer_count: self.replay_offer_count,
            first_journal_sequence: self.first_journal_sequence,
            ledger_events: self.ledger.next_sequence,
            auto_failed_on_restart: self.auto_failed_on_restart,
            poisoned: self.poisoned,
            hardware_transport_available: false,
        }
    }

    fn validate_request(&self, command: &HardwareCommand) -> io::Result<()> {
        if command.kind == RunCommandKind::Prepare {
            if !matches!(self.phase, HardwareRunPhase::New | HardwareRunPhase::Sealed)
                || command.epoch <= self.highest_epoch
            {
                return Err(invalid_input(
                    "hardware Prepare requires New/Sealed and a fresh epoch",
                ));
            }
            return Ok(());
        }
        let context = self
            .context
            .ok_or_else(|| invalid_input("hardware Run has no active identity"))?;
        if context.epoch != command.epoch
            || context.run_id != command.body.run_id
            || context.target_device_id != command.body.target_device_id
            || context.frozen_config_hash != command.body.frozen_config_hash
        {
            return Err(invalid_input(
                "hardware command identity does not match the active Run",
            ));
        }
        let legal = matches!(
            (self.phase, command.kind),
            (HardwareRunPhase::Prepared, RunCommandKind::Arm)
                | (HardwareRunPhase::Armed, RunCommandKind::Start)
                | (HardwareRunPhase::Recording, RunCommandKind::Stop)
                | (
                    HardwareRunPhase::Prepared
                        | HardwareRunPhase::Armed
                        | HardwareRunPhase::Recording,
                    RunCommandKind::Abort
                )
        );
        if legal {
            Ok(())
        } else {
            Err(invalid_input(
                "hardware Run command is invalid in the current confirmed phase",
            ))
        }
    }

    fn persist_then_apply(&mut self, event: HardwareRunEvent) -> io::Result<()> {
        if let Err(error) = self.ledger.append(&event) {
            self.poisoned = true;
            self.phase = HardwareRunPhase::Failed;
            return Err(io::Error::new(
                error.kind(),
                format!("failed to durably append hardware Run event: {error}"),
            ));
        }
        if let Err(error) = self.apply_event(&event, false) {
            self.poisoned = true;
            self.phase = HardwareRunPhase::Failed;
            return Err(io::Error::new(
                error.kind(),
                format!("durable hardware Run event could not be applied: {error}"),
            ));
        }
        Ok(())
    }

    fn apply_event(&mut self, event: &HardwareRunEvent, restoring: bool) -> io::Result<()> {
        match event {
            HardwareRunEvent::Requested {
                command,
                requested_global_time_ns,
            } => {
                if *requested_global_time_ns == 0
                    || *requested_global_time_ns >= command.body.deadline_global_time_ns
                {
                    return Err(invalid_data("persisted hardware request timing is invalid"));
                }
                if self.commands.contains_key(&command.key())
                    || self.replays.contains_key(&command.key())
                    || self.pending.is_some()
                {
                    return Err(invalid_data(
                        "persisted hardware request key is duplicate or overlaps another request",
                    ));
                }
                if self.pending_replay.is_some() {
                    return Err(invalid_data(
                        "persisted hardware Run request overlaps a Replay request",
                    ));
                }
                self.validate_request(command).map_err(|_| {
                    invalid_data("persisted hardware request breaks the lifecycle chain")
                })?;
                if command.kind == RunCommandKind::Prepare {
                    self.context = Some(HardwareRunContext {
                        epoch: command.epoch,
                        run_id: command.body.run_id,
                        target_device_id: command.body.target_device_id,
                        frozen_config_hash: command.body.frozen_config_hash,
                    });
                    self.highest_epoch = command.epoch;
                    self.first_journal_sequence = None;
                }
                self.phase = requested_phase(command.kind);
                let receipt = HardwareRunReceipt {
                    request_id: command.request_id,
                    epoch: command.epoch,
                    command: command.kind,
                    phase: self.phase,
                    hardware_accepted: None,
                    evidence_hash: None,
                    reason: "request durably recorded; hardware reply pending".to_owned(),
                };
                self.pending = Some(command.clone());
                self.commands
                    .insert(command.key(), (command.clone(), receipt));
            }
            HardwareRunEvent::Replied {
                epoch,
                request_id,
                accepted,
                source_stop_boundary_verified,
                evidence_hash,
            } => {
                if !evidence_hash.iter().any(|byte| *byte != 0) {
                    return Err(invalid_data("persisted hardware reply evidence is zero"));
                }
                let pending = self
                    .pending
                    .clone()
                    .ok_or_else(|| invalid_data("persisted hardware reply has no request"))?;
                if pending.key() != (*epoch, *request_id)
                    || (*accepted
                        && pending.kind == RunCommandKind::Stop
                        && !*source_stop_boundary_verified)
                    || (pending.kind != RunCommandKind::Stop && *source_stop_boundary_verified)
                {
                    return Err(invalid_data(
                        "persisted hardware reply contradicts its request or Stop proof",
                    ));
                }
                let next = if !accepted {
                    HardwareRunPhase::Failed
                } else {
                    acknowledged_phase(pending.kind)
                };
                let receipt = self.commands.get_mut(&pending.key()).unwrap();
                receipt.1.phase = next;
                receipt.1.hardware_accepted = Some(*accepted);
                receipt.1.evidence_hash = Some(*evidence_hash);
                receipt.1.reason = if !accepted {
                    "hardware rejected command; Run failed closed".to_owned()
                } else if pending.kind == RunCommandKind::Start {
                    "Start ACK durable; first journaled record pending".to_owned()
                } else {
                    "matched hardware ACK durably recorded".to_owned()
                };
                self.phase = next;
                if !accepted || pending.kind != RunCommandKind::Start {
                    self.pending = None;
                }
            }
            HardwareRunEvent::FirstRecord {
                epoch,
                run_id,
                journal_sequence,
                record_evidence_hash,
            } => {
                let pending = self
                    .pending
                    .clone()
                    .ok_or_else(|| invalid_data("persisted first record has no pending Start"))?;
                if self.phase != HardwareRunPhase::StartAcknowledged
                    || pending.kind != RunCommandKind::Start
                    || pending.epoch != *epoch
                    || pending.body.run_id != *run_id
                    || !record_evidence_hash.iter().any(|byte| *byte != 0)
                {
                    return Err(invalid_data(
                        "persisted first record contradicts the acknowledged Start",
                    ));
                }
                self.phase = HardwareRunPhase::Recording;
                self.first_journal_sequence = Some(*journal_sequence);
                let receipt = self.commands.get_mut(&pending.key()).unwrap();
                receipt.1.phase = self.phase;
                receipt.1.evidence_hash = Some(*record_evidence_hash);
                receipt.1.reason = "first valid canonical record is journaled".to_owned();
                self.pending = None;
            }
            HardwareRunEvent::Failed {
                epoch,
                run_id,
                fault_code,
                evidence_hash,
            } => {
                let context = self
                    .context
                    .ok_or_else(|| invalid_data("persisted hardware failure has no Run"))?;
                if context.epoch != *epoch
                    || context.run_id != *run_id
                    || *fault_code == 0
                    || !evidence_hash.iter().any(|byte| *byte != 0)
                    || !self.phase.is_restart_sensitive()
                {
                    return Err(invalid_data(
                        "persisted hardware failure contradicts the active Run",
                    ));
                }
                if let Some(pending) = self.pending.take() {
                    let receipt = self.commands.get_mut(&pending.key()).unwrap();
                    receipt.1.phase = HardwareRunPhase::Failed;
                    receipt.1.hardware_accepted = Some(false);
                    receipt.1.evidence_hash = Some(*evidence_hash);
                    receipt.1.reason = format!("hardware Run failed closed (fault {fault_code})");
                }
                if let Some(pending) = self.pending_replay.take() {
                    let receipt = self.replays.get_mut(&pending.key()).unwrap();
                    receipt.1.phase = HardwareRunPhase::Failed;
                    receipt.1.hardware_accepted = Some(false);
                    receipt.1.evidence_hash = Some(*evidence_hash);
                    receipt.1.reason = format!(
                        "hardware Run failed closed with Replay unresolved (fault {fault_code})"
                    );
                }
                self.pending_replay_offer = None;
                self.phase = HardwareRunPhase::Failed;
            }
            HardwareRunEvent::Sealed {
                epoch,
                run_id,
                seal_evidence_hash,
            } => {
                let context = self
                    .context
                    .ok_or_else(|| invalid_data("persisted hardware seal has no Run"))?;
                if self.phase != HardwareRunPhase::Stopped
                    || context.epoch != *epoch
                    || context.run_id != *run_id
                    || !seal_evidence_hash.iter().any(|byte| *byte != 0)
                {
                    return Err(invalid_data(
                        "persisted hardware seal contradicts the stopped Run",
                    ));
                }
                self.phase = HardwareRunPhase::Sealed;
            }
            HardwareRunEvent::ReplayRequested {
                request,
                requested_global_time_ns,
            } => {
                if *requested_global_time_ns == 0
                    || *requested_global_time_ns >= request.body.deadline_global_time_ns
                    || self.phase != HardwareRunPhase::Recording
                    || self.pending.is_some()
                    || self.pending_replay.is_some()
                    || self.replays.contains_key(&request.key())
                    || self.commands.contains_key(&request.key())
                {
                    return Err(invalid_data(
                        "persisted hardware Replay request breaks the lifecycle chain",
                    ));
                }
                let context = self.context.ok_or_else(|| {
                    invalid_data("persisted hardware Replay has no active Run identity")
                })?;
                if request.epoch != context.epoch || request.body.run_id != context.run_id {
                    return Err(invalid_data(
                        "persisted hardware Replay identity contradicts the active Run",
                    ));
                }
                if let Some(offer) = self.pending_replay_offer {
                    if request.body.pod_id != offer.pod_id
                        || request.epoch != offer.transport_epoch
                        || request.body.first_record_sequence != offer.first_missing_record_sequence
                        || request.body.last_record_sequence_exclusive
                            != offer.last_missing_record_sequence_exclusive
                        || request.body.deadline_global_time_ns != offer.deadline_global_time_ns
                        || request.body.reason_code != offer.reason_code
                    {
                        return Err(invalid_data(
                            "persisted Replay request does not match its source offer",
                        ));
                    }
                }
                let receipt = HardwareReplayReceipt {
                    request_id: request.request_id,
                    epoch: request.epoch,
                    phase: self.phase,
                    hardware_accepted: None,
                    replay_boundary_verified: false,
                    evidence_hash: None,
                    reason: "Replay request durably recorded; hardware data/reply pending"
                        .to_owned(),
                };
                self.pending_replay = Some(request.clone());
                self.pending_replay_offer = None;
                self.replays
                    .insert(request.key(), (request.clone(), receipt));
            }
            HardwareRunEvent::ReplayReplied {
                epoch,
                request_id,
                accepted,
                replay_boundary_verified,
                evidence_hash,
            } => {
                let pending = self.pending_replay.clone().ok_or_else(|| {
                    invalid_data("persisted hardware Replay reply has no request")
                })?;
                if pending.key() != (*epoch, *request_id)
                    || *evidence_hash == [0; 32]
                    || (*accepted && !*replay_boundary_verified)
                    || (!*accepted && *replay_boundary_verified)
                {
                    return Err(invalid_data(
                        "persisted hardware Replay reply contradicts its request or proof",
                    ));
                }
                let receipt = self.replays.get_mut(&pending.key()).unwrap();
                receipt.1.hardware_accepted = Some(*accepted);
                receipt.1.replay_boundary_verified = *replay_boundary_verified;
                receipt.1.evidence_hash = Some(*evidence_hash);
                receipt.1.reason = if *accepted {
                    "matched Replay ACK and durable journal boundary recorded".to_owned()
                } else {
                    "hardware rejected Replay; Run failed closed".to_owned()
                };
                self.pending_replay = None;
                if *accepted {
                    self.verified_replay_count = self
                        .verified_replay_count
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("verified Replay count overflow"))?;
                } else {
                    self.phase = HardwareRunPhase::Failed;
                    receipt.1.phase = HardwareRunPhase::Failed;
                }
            }
            HardwareRunEvent::ReplayOffered { offer, offer_hash } => {
                let context = self
                    .context
                    .ok_or_else(|| invalid_data("persisted Replay offer has no active Run"))?;
                let encoded = offer.encode()?;
                if self.phase != HardwareRunPhase::Recording
                    || self.pending.is_some()
                    || self.pending_replay.is_some()
                    || self.pending_replay_offer.is_some()
                    || offer.run_id != context.run_id
                    || offer.device_id != context.target_device_id
                    || offer.transport_epoch != context.epoch
                    || sha256(&encoded) != *offer_hash
                {
                    return Err(invalid_data(
                        "persisted Replay offer contradicts the active Recording lifecycle",
                    ));
                }
                self.replay_offer_count = self
                    .replay_offer_count
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("Replay offer count overflow"))?;
                self.pending_replay_offer = Some(*offer);
            }
        }
        if restoring && self.commands.len() + self.replays.len() > MAX_LEDGER_EVENTS {
            return Err(invalid_data("hardware receipt set exceeds its bound"));
        }
        Ok(())
    }

    fn ensure_usable(&self) -> io::Result<()> {
        if self.poisoned {
            Err(io::Error::other(
                "hardware Run coordinator is poisoned after persistence failure",
            ))
        } else {
            Ok(())
        }
    }
}

fn requested_phase(kind: RunCommandKind) -> HardwareRunPhase {
    match kind {
        RunCommandKind::Prepare => HardwareRunPhase::PrepareRequested,
        RunCommandKind::Arm => HardwareRunPhase::ArmRequested,
        RunCommandKind::Start => HardwareRunPhase::StartRequested,
        RunCommandKind::Stop => HardwareRunPhase::StopRequested,
        RunCommandKind::Abort => HardwareRunPhase::AbortRequested,
        _ => unreachable!("hardware lifecycle filtered non-mutating commands"),
    }
}

fn acknowledged_phase(kind: RunCommandKind) -> HardwareRunPhase {
    match kind {
        RunCommandKind::Prepare => HardwareRunPhase::Prepared,
        RunCommandKind::Arm => HardwareRunPhase::Armed,
        RunCommandKind::Start => HardwareRunPhase::StartAcknowledged,
        RunCommandKind::Stop => HardwareRunPhase::Stopped,
        RunCommandKind::Abort => HardwareRunPhase::Aborted,
        _ => unreachable!("hardware lifecycle filtered non-mutating commands"),
    }
}

struct HardwareRunLedger {
    root: PathBuf,
    next_sequence: u64,
}

impl HardwareRunLedger {
    fn placeholder() -> Self {
        Self {
            root: PathBuf::new(),
            next_sequence: 0,
        }
    }

    fn open(path: impl AsRef<Path>) -> io::Result<(Self, Vec<HardwareRunEvent>)> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        if !root.is_dir() {
            return Err(invalid_input("hardware Run ledger path is not a directory"));
        }
        let mut paths = Vec::new();
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".pending-hardware-event-") {
                return Err(invalid_data(
                    "incomplete hardware Run event requires forensic recovery",
                ));
            }
            if name.starts_with("hardware-event-") {
                paths.push((parse_event_filename(&name)?, entry.path()));
            }
        }
        paths.sort_by_key(|value| value.0);
        if paths.len() > MAX_LEDGER_EVENTS {
            return Err(invalid_data("hardware Run ledger exceeds its event bound"));
        }
        let mut events = Vec::with_capacity(paths.len());
        for (expected, (sequence, path)) in paths.into_iter().enumerate() {
            if sequence != expected as u64 {
                return Err(invalid_data(
                    "hardware Run ledger event sequence is not contiguous",
                ));
            }
            events.push(read_event(&path, sequence)?);
        }
        Ok((
            Self {
                root,
                next_sequence: events.len() as u64,
            },
            events,
        ))
    }

    fn append(&mut self, event: &HardwareRunEvent) -> io::Result<()> {
        if self.next_sequence as usize >= MAX_LEDGER_EVENTS {
            return Err(io::Error::other(
                "hardware Run ledger event capacity is exhausted",
            ));
        }
        let sequence = self.next_sequence;
        let final_path = self.root.join(event_filename(sequence));
        let pending_path = self.root.join(format!(
            ".pending-hardware-event-{sequence:020}-{}.bin",
            std::process::id()
        ));
        let bytes = encode_event(sequence, event)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        if final_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "hardware Run event target already exists",
            ));
        }
        fs::rename(&pending_path, &final_path)?;
        self.next_sequence += 1;
        Ok(())
    }
}

fn encode_event(sequence: u64, event: &HardwareRunEvent) -> io::Result<Vec<u8>> {
    let payload = encode_payload(event)?;
    if payload.len() > MAX_EVENT_PAYLOAD_LEN {
        return Err(invalid_input(
            "hardware Run event payload exceeds its bound",
        ));
    }
    let total_len = FRAME_HEADER_LEN + payload.len() + FRAME_FOOTER_LEN;
    let mut frame = vec![0_u8; FRAME_HEADER_LEN];
    frame[0..8].copy_from_slice(FRAME_MAGIC);
    frame[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
    frame[10..12].copy_from_slice(&(FRAME_HEADER_LEN as u16).to_le_bytes());
    frame[12..14].copy_from_slice(&event.kind().to_le_bytes());
    frame[16..20].copy_from_slice(&(total_len as u32).to_le_bytes());
    frame[20..28].copy_from_slice(&sequence.to_le_bytes());
    frame[28..32].copy_from_slice(&crc32c(&payload).to_le_bytes());
    frame.extend_from_slice(&payload);
    let frame_crc = crc32c(&frame);
    frame.extend_from_slice(FOOTER_MAGIC);
    frame.extend_from_slice(&frame_crc.to_le_bytes());
    frame.extend_from_slice(&0_u32.to_le_bytes());
    Ok(frame)
}

fn encode_payload(event: &HardwareRunEvent) -> io::Result<Vec<u8>> {
    let mut payload = Vec::new();
    match event {
        HardwareRunEvent::Requested {
            command,
            requested_global_time_ns,
        } => {
            if command.wire.len() != RUN_COMMAND_WIRE_LEN
                || sha256(&command.wire) != command.wire_hash
                || *requested_global_time_ns == 0
            {
                return Err(invalid_input("hardware request event is invalid"));
            }
            payload.extend_from_slice(&requested_global_time_ns.to_le_bytes());
            payload.extend_from_slice(&command.wire);
        }
        HardwareRunEvent::Replied {
            epoch,
            request_id,
            accepted,
            source_stop_boundary_verified,
            evidence_hash,
        } => {
            if *epoch == 0 || *request_id == 0 || !evidence_hash.iter().any(|byte| *byte != 0) {
                return Err(invalid_input("hardware reply event is invalid"));
            }
            payload.extend_from_slice(&epoch.to_le_bytes());
            payload.extend_from_slice(&request_id.to_le_bytes());
            payload.push(u8::from(*accepted));
            payload.push(u8::from(*source_stop_boundary_verified));
            payload.extend_from_slice(&[0_u8; 6]);
            payload.extend_from_slice(evidence_hash);
        }
        HardwareRunEvent::FirstRecord {
            epoch,
            run_id,
            journal_sequence,
            record_evidence_hash,
        } => {
            validate_identity(*epoch, run_id, record_evidence_hash)?;
            payload.extend_from_slice(&epoch.to_le_bytes());
            payload.extend_from_slice(run_id);
            payload.extend_from_slice(&journal_sequence.to_le_bytes());
            payload.extend_from_slice(record_evidence_hash);
        }
        HardwareRunEvent::Failed {
            epoch,
            run_id,
            fault_code,
            evidence_hash,
        } => {
            validate_identity(*epoch, run_id, evidence_hash)?;
            if *fault_code == 0 {
                return Err(invalid_input("hardware failure code must be nonzero"));
            }
            payload.extend_from_slice(&epoch.to_le_bytes());
            payload.extend_from_slice(run_id);
            payload.extend_from_slice(&fault_code.to_le_bytes());
            payload.extend_from_slice(&0_u32.to_le_bytes());
            payload.extend_from_slice(evidence_hash);
        }
        HardwareRunEvent::Sealed {
            epoch,
            run_id,
            seal_evidence_hash,
        } => {
            validate_identity(*epoch, run_id, seal_evidence_hash)?;
            payload.extend_from_slice(&epoch.to_le_bytes());
            payload.extend_from_slice(run_id);
            payload.extend_from_slice(seal_evidence_hash);
        }
        HardwareRunEvent::ReplayRequested {
            request,
            requested_global_time_ns,
        } => {
            if request.wire.len() != REPLAY_REQUEST_WIRE_LEN
                || sha256(&request.wire) != request.wire_hash
                || *requested_global_time_ns == 0
            {
                return Err(invalid_input("hardware Replay request event is invalid"));
            }
            payload.extend_from_slice(&requested_global_time_ns.to_le_bytes());
            payload.extend_from_slice(&request.wire);
        }
        HardwareRunEvent::ReplayReplied {
            epoch,
            request_id,
            accepted,
            replay_boundary_verified,
            evidence_hash,
        } => {
            if *epoch == 0
                || *request_id == 0
                || *evidence_hash == [0; 32]
                || (*accepted && !*replay_boundary_verified)
                || (!*accepted && *replay_boundary_verified)
            {
                return Err(invalid_input("hardware Replay reply event is invalid"));
            }
            payload.extend_from_slice(&epoch.to_le_bytes());
            payload.extend_from_slice(&request_id.to_le_bytes());
            payload.push(u8::from(*accepted));
            payload.push(u8::from(*replay_boundary_verified));
            payload.extend_from_slice(&[0; 6]);
            payload.extend_from_slice(evidence_hash);
        }
        HardwareRunEvent::ReplayOffered { offer, offer_hash } => {
            let encoded = offer.encode()?;
            if sha256(&encoded) != *offer_hash {
                return Err(invalid_input("hardware Replay offer event hash is invalid"));
            }
            payload.extend_from_slice(&encoded);
            payload.extend_from_slice(offer_hash);
        }
    }
    Ok(payload)
}

fn read_event(path: &Path, expected_sequence: u64) -> io::Result<HardwareRunEvent> {
    let mut file = File::open(path)?;
    let length = usize::try_from(file.metadata()?.len())
        .map_err(|_| invalid_data("hardware Run event file is too large"))?;
    if !(FRAME_HEADER_LEN + FRAME_FOOTER_LEN
        ..=FRAME_HEADER_LEN + MAX_EVENT_PAYLOAD_LEN + FRAME_FOOTER_LEN)
        .contains(&length)
    {
        return Err(invalid_data("hardware Run event length is invalid"));
    }
    let mut frame = vec![0_u8; length];
    file.read_exact(&mut frame)?;
    if &frame[0..8] != FRAME_MAGIC
        || le_u16(&frame, 8)? != FRAME_VERSION
        || le_u16(&frame, 10)? as usize != FRAME_HEADER_LEN
        || le_u16(&frame, 14)? != 0
        || le_u32(&frame, 16)? as usize != frame.len()
        || le_u64(&frame, 20)? != expected_sequence
    {
        return Err(invalid_data("hardware Run event header is invalid"));
    }
    let payload_end = frame.len() - FRAME_FOOTER_LEN;
    let payload = &frame[FRAME_HEADER_LEN..payload_end];
    if crc32c(payload) != le_u32(&frame, 28)?
        || &frame[payload_end..payload_end + 8] != FOOTER_MAGIC
        || le_u32(&frame, payload_end + 12)? != 0
        || crc32c(&frame[..payload_end]) != le_u32(&frame, payload_end + 8)?
    {
        return Err(invalid_data("hardware Run event CRC/footer is invalid"));
    }
    decode_payload(le_u16(&frame, 12)?, payload)
}

fn decode_payload(kind: u16, payload: &[u8]) -> io::Result<HardwareRunEvent> {
    match kind {
        1 => {
            if payload.len() != 8 + RUN_COMMAND_WIRE_LEN {
                return Err(invalid_data("hardware request payload length is invalid"));
            }
            let requested_global_time_ns = le_u64(payload, 0)?;
            let command = HardwareCommand::decode(&payload[8..])?;
            Ok(HardwareRunEvent::Requested {
                command,
                requested_global_time_ns,
            })
        }
        2 => {
            if payload.len() != 56 || payload[18..24].iter().any(|byte| *byte != 0) {
                return Err(invalid_data("hardware reply payload is invalid"));
            }
            let accepted = decode_bool(payload[16])?;
            let source_stop_boundary_verified = decode_bool(payload[17])?;
            Ok(HardwareRunEvent::Replied {
                epoch: le_u64(payload, 0)?,
                request_id: le_u64(payload, 8)?,
                accepted,
                source_stop_boundary_verified,
                evidence_hash: array(payload, 24)?,
            })
        }
        3 => {
            if payload.len() != 64 {
                return Err(invalid_data("hardware first-record payload is invalid"));
            }
            Ok(HardwareRunEvent::FirstRecord {
                epoch: le_u64(payload, 0)?,
                run_id: array(payload, 8)?,
                journal_sequence: le_u64(payload, 24)?,
                record_evidence_hash: array(payload, 32)?,
            })
        }
        4 => {
            if payload.len() != 64 || le_u32(payload, 28)? != 0 {
                return Err(invalid_data("hardware failure payload is invalid"));
            }
            Ok(HardwareRunEvent::Failed {
                epoch: le_u64(payload, 0)?,
                run_id: array(payload, 8)?,
                fault_code: le_u32(payload, 24)?,
                evidence_hash: array(payload, 32)?,
            })
        }
        5 => {
            if payload.len() != 56 {
                return Err(invalid_data("hardware seal payload is invalid"));
            }
            Ok(HardwareRunEvent::Sealed {
                epoch: le_u64(payload, 0)?,
                run_id: array(payload, 8)?,
                seal_evidence_hash: array(payload, 24)?,
            })
        }
        6 => {
            if payload.len() != 8 + REPLAY_REQUEST_WIRE_LEN {
                return Err(invalid_data(
                    "hardware Replay request payload length is invalid",
                ));
            }
            Ok(HardwareRunEvent::ReplayRequested {
                requested_global_time_ns: le_u64(payload, 0)?,
                request: HardwareReplayRequest::decode(&payload[8..])?,
            })
        }
        7 => {
            if payload.len() != 56 || payload[18..24].iter().any(|byte| *byte != 0) {
                return Err(invalid_data("hardware Replay reply payload is invalid"));
            }
            Ok(HardwareRunEvent::ReplayReplied {
                epoch: le_u64(payload, 0)?,
                request_id: le_u64(payload, 8)?,
                accepted: decode_bool(payload[16])?,
                replay_boundary_verified: decode_bool(payload[17])?,
                evidence_hash: array(payload, 24)?,
            })
        }
        8 => {
            if payload.len() != DIRECT_POD_REPLAY_OFFER_LEN + 32 {
                return Err(invalid_data("hardware Replay offer payload is invalid"));
            }
            let offer = DirectPodReplayOfferV1::decode(&payload[..DIRECT_POD_REPLAY_OFFER_LEN])?;
            let offer_hash = array(payload, DIRECT_POD_REPLAY_OFFER_LEN)?;
            if sha256(&payload[..DIRECT_POD_REPLAY_OFFER_LEN]) != offer_hash {
                return Err(invalid_data("hardware Replay offer hash is invalid"));
            }
            Ok(HardwareRunEvent::ReplayOffered { offer, offer_hash })
        }
        _ => Err(invalid_data("unknown hardware Run event kind")),
    }
}

fn validate_identity(epoch: u64, run_id: &Id16, hash: &Hash32) -> io::Result<()> {
    if epoch == 0 || !run_id.iter().any(|byte| *byte != 0) || !hash.iter().any(|byte| *byte != 0) {
        Err(invalid_input("hardware Run event identity is invalid"))
    } else {
        Ok(())
    }
}

fn event_filename(sequence: u64) -> String {
    format!("hardware-event-{sequence:020}.bin")
}

fn parse_event_filename(name: &str) -> io::Result<u64> {
    let value = name
        .strip_prefix("hardware-event-")
        .and_then(|value| value.strip_suffix(".bin"))
        .ok_or_else(|| invalid_data("hardware Run event filename is invalid"))?;
    if value.len() != 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_data("hardware Run event filename is invalid"));
    }
    value
        .parse()
        .map_err(|_| invalid_data("hardware Run event sequence is invalid"))
}

fn decode_bool(value: u8) -> io::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid_data("persisted boolean is invalid")),
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

fn array<const N: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(|| invalid_data("hardware Run event field is truncated"))?
        .try_into()
        .map_err(|_| invalid_data("hardware Run event field length is invalid"))
}

fn hex<const N: usize>(bytes: [u8; N]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
    use forge_protocol_v1::{encode_low_speed, PROTOCOL_HASH};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempLedger(PathBuf);

    impl TempLedger {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            Self(std::env::temp_dir().join(format!(
                "forge-hardware-run-{label}-{}-{nonce}",
                std::process::id()
            )))
        }
    }

    impl Drop for TempLedger {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn command(request_id: u64, epoch: u64, kind: RunCommandKind) -> Vec<u8> {
        encode_low_speed(
            0,
            request_id,
            epoch,
            &RunCommandV1 {
                command: kind.wire_value(),
                scope: 1,
                run_id: [0x11; 16],
                target_device_id: [0x22; 16],
                deadline_global_time_ns: 100_000,
                frozen_config_hash: PROTOCOL_HASH,
            },
        )
        .unwrap()
    }

    fn complete(
        coordinator: &mut HardwareRunCoordinator,
        request_id: u64,
        epoch: u64,
        kind: RunCommandKind,
    ) -> HardwareRunReceipt {
        let requested = coordinator
            .request(&command(request_id, epoch, kind), 10)
            .unwrap();
        assert_eq!(requested.hardware_accepted, None);
        coordinator
            .complete_reply(
                epoch,
                request_id,
                true,
                sha256(&[kind.wire_value() as u8]),
                kind == RunCommandKind::Stop,
            )
            .unwrap()
    }

    fn recording(coordinator: &mut HardwareRunCoordinator, epoch: u64) {
        complete(coordinator, 1, epoch, RunCommandKind::Prepare);
        complete(coordinator, 2, epoch, RunCommandKind::Arm);
        complete(coordinator, 3, epoch, RunCommandKind::Start);
        coordinator
            .observe_first_journaled_record(epoch, [0x11; 16], 0, sha256(b"record-0"))
            .unwrap();
    }

    fn replay(request_id: u64, epoch: u64) -> Vec<u8> {
        encode_low_speed(
            0,
            request_id,
            epoch,
            &ReplayRequestV1 {
                run_id: [0x11; 16],
                pod_id: [0x33; 16],
                first_record_sequence: 1,
                last_record_sequence_exclusive: 3,
                deadline_global_time_ns: 100_000,
                reason_code: 1,
                request_context_hash: [0x44; 32],
            },
        )
        .unwrap()
    }

    fn replay_offer(epoch: u64) -> Vec<u8> {
        DirectPodReplayOfferV1 {
            flags: crate::direct_pod_replay_offer::REPLAY_OFFER_REQUIRED_FLAGS,
            device_id: [0x22; 16],
            run_id: [0x11; 16],
            pod_id: [0x33; 16],
            headstage_id: [0x44; 16],
            transport_epoch: epoch,
            offer_sequence: 1,
            first_missing_record_sequence: 1,
            last_missing_record_sequence_exclusive: 3,
            oldest_replayable_record_sequence: 1,
            newest_replayable_record_sequence_exclusive: 3,
            source_next_live_record_sequence: 3,
            last_produced_record_sequence_exclusive: 3,
            prior_record_sequence: Some(0),
            offer_global_time_ns: 1_000,
            deadline_global_time_ns: 100_000,
            reason_code: 1,
            hardware_state_hash: [0x55; 32],
        }
        .encode()
        .unwrap()
        .to_vec()
    }

    #[test]
    fn source_offer_is_durable_blocks_interleaving_and_fails_closed_on_restart() {
        let temp = TempLedger::new("replay-offer-crash");
        {
            let mut value = HardwareRunCoordinator::open(&temp.0).unwrap();
            recording(&mut value, 31);
            value.record_replay_offer(&replay_offer(31)).unwrap();
            assert_eq!(value.status().replay_offer_count, 1);
            assert_eq!(value.status().ledger_events, 8);
            assert!(value
                .request(&command(4, 31, RunCommandKind::Stop), 10)
                .is_err());

            let mut mismatched = replay(4, 31);
            let decoded = decode_low_speed(&mismatched).unwrap();
            let mut body = ReplayRequestV1::decode_body(&decoded.body).unwrap();
            body.last_record_sequence_exclusive = 4;
            mismatched =
                forge_protocol_v1::encode_low_speed(0, decoded.request_id, decoded.epoch, &body)
                    .unwrap();
            assert!(value.request_replay(&mismatched, 10).is_err());
            assert_eq!(value.status().ledger_events, 8);
        }

        let reopened = HardwareRunCoordinator::open(&temp.0).unwrap();
        assert_eq!(reopened.phase(), HardwareRunPhase::Failed);
        assert!(reopened.status().auto_failed_on_restart);
        assert_eq!(reopened.status().replay_offer_count, 1);
        assert_eq!(reopened.status().pending_replay_request_id, None);
        assert_eq!(reopened.status().ledger_events, 9);
    }

    #[test]
    fn replay_request_and_verified_reply_are_durable_and_idempotent() {
        let temp = TempLedger::new("replay-durable");
        let wire = replay(4, 19);
        let expected_evidence = sha256(b"durable-replay-completion");
        {
            let mut value = HardwareRunCoordinator::open(&temp.0).unwrap();
            recording(&mut value, 19);
            let requested = value.request_replay(&wire, 10).unwrap();
            assert_eq!(requested.hardware_accepted, None);
            assert_eq!(value.status().pending_replay_request_id, Some(4));
            assert!(value
                .complete_replay_reply(19, 4, true, expected_evidence, false)
                .is_err());
            let receipt = value
                .complete_replay_reply(19, 4, true, expected_evidence, true)
                .unwrap();
            assert_eq!(receipt.phase, HardwareRunPhase::Recording);
            assert_eq!(receipt.hardware_accepted, Some(true));
            assert!(receipt.replay_boundary_verified);
            assert_eq!(value.status().verified_replay_count, 1);
            let retry = value.request_replay(&wire, 10).unwrap();
            assert_eq!(retry, receipt);
            assert_eq!(value.status().ledger_events, 9);
        }
        let mut reopened = HardwareRunCoordinator::open(&temp.0).unwrap();
        assert_eq!(reopened.phase(), HardwareRunPhase::Failed);
        assert_eq!(reopened.status().verified_replay_count, 1);
        let retry = reopened.request_replay(&wire, 10).unwrap();
        assert_eq!(retry.hardware_accepted, Some(true));
        assert!(retry.replay_boundary_verified);
    }

    #[test]
    fn unresolved_or_rejected_replay_fails_run_closed_across_restart() {
        let pending = TempLedger::new("replay-pending-crash");
        let wire = replay(4, 21);
        {
            let mut value = HardwareRunCoordinator::open(&pending.0).unwrap();
            recording(&mut value, 21);
            value.request_replay(&wire, 10).unwrap();
        }
        let reopened = HardwareRunCoordinator::open(&pending.0).unwrap();
        assert_eq!(reopened.phase(), HardwareRunPhase::Failed);
        assert!(reopened.status().auto_failed_on_restart);
        assert!(reopened.status().pending_replay_request_id.is_none());

        let rejected = TempLedger::new("replay-nack");
        let mut value = HardwareRunCoordinator::open(&rejected.0).unwrap();
        recording(&mut value, 23);
        value.request_replay(&replay(4, 23), 10).unwrap();
        let receipt = value
            .complete_replay_reply(23, 4, false, sha256(b"replay-nack"), false)
            .unwrap();
        assert_eq!(receipt.phase, HardwareRunPhase::Failed);
        assert_eq!(value.phase(), HardwareRunPhase::Failed);
    }

    #[test]
    fn replay_is_recording_only_and_cannot_overlap_or_reuse_run_command_key() {
        let temp = TempLedger::new("replay-order");
        let mut value = HardwareRunCoordinator::open(&temp.0).unwrap();
        complete(&mut value, 1, 25, RunCommandKind::Prepare);
        assert!(value.request_replay(&replay(2, 25), 10).is_err());
        complete(&mut value, 2, 25, RunCommandKind::Arm);
        complete(&mut value, 3, 25, RunCommandKind::Start);
        value
            .observe_first_journaled_record(25, [0x11; 16], 0, sha256(b"first"))
            .unwrap();
        value.request_replay(&replay(4, 25), 10).unwrap();
        assert!(value
            .request(&command(5, 25, RunCommandKind::Stop), 10)
            .is_err());

        let temp = TempLedger::new("replay-key-collision");
        let mut value = HardwareRunCoordinator::open(&temp.0).unwrap();
        recording(&mut value, 27);
        assert!(value.request_replay(&replay(3, 27), 10).is_err());
    }

    #[test]
    fn start_requires_ack_and_first_journaled_record() {
        let temp = TempLedger::new("start-gates");
        let mut value = HardwareRunCoordinator::open(&temp.0).unwrap();
        assert_eq!(
            complete(&mut value, 1, 7, RunCommandKind::Prepare).phase,
            HardwareRunPhase::Prepared
        );
        assert_eq!(
            complete(&mut value, 2, 7, RunCommandKind::Arm).phase,
            HardwareRunPhase::Armed
        );
        let requested = value
            .request(&command(3, 7, RunCommandKind::Start), 10)
            .unwrap();
        assert_eq!(requested.phase, HardwareRunPhase::StartRequested);
        let acked = value
            .complete_reply(7, 3, true, sha256(b"start-ack"), false)
            .unwrap();
        assert_eq!(acked.phase, HardwareRunPhase::StartAcknowledged);
        assert_ne!(value.phase(), HardwareRunPhase::Recording);
        let recording = value
            .observe_first_journaled_record(7, [0x11; 16], 0, sha256(b"record-0"))
            .unwrap();
        assert_eq!(recording.phase, HardwareRunPhase::Recording);
        assert_eq!(value.status().first_journal_sequence, Some(0));
    }

    #[test]
    fn stop_requires_source_boundary_then_seal() {
        let temp = TempLedger::new("stop-boundary");
        let mut value = HardwareRunCoordinator::open(&temp.0).unwrap();
        complete(&mut value, 1, 9, RunCommandKind::Prepare);
        complete(&mut value, 2, 9, RunCommandKind::Arm);
        complete(&mut value, 3, 9, RunCommandKind::Start);
        value
            .observe_first_journaled_record(9, [0x11; 16], 12, sha256(b"first"))
            .unwrap();
        value
            .request(&command(4, 9, RunCommandKind::Stop), 10)
            .unwrap();
        assert!(value
            .complete_reply(9, 4, true, sha256(b"stop-ack"), false)
            .is_err());
        assert_eq!(value.phase(), HardwareRunPhase::StopRequested);
        let stopped = value
            .complete_reply(9, 4, true, sha256(b"stop-ack"), true)
            .unwrap();
        assert_eq!(stopped.phase, HardwareRunPhase::Stopped);
        value.mark_sealed(sha256(b"journal-seal")).unwrap();
        assert_eq!(value.phase(), HardwareRunPhase::Sealed);
    }

    #[test]
    fn exact_retry_survives_restart_without_resending() {
        let temp = TempLedger::new("idempotent");
        let wire = command(1, 11, RunCommandKind::Prepare);
        {
            let mut value = HardwareRunCoordinator::open(&temp.0).unwrap();
            value.request(&wire, 10).unwrap();
            value
                .complete_reply(11, 1, true, sha256(b"prepare-ack"), false)
                .unwrap();
            assert_eq!(value.phase(), HardwareRunPhase::Prepared);
        }
        let mut reopened = HardwareRunCoordinator::open(&temp.0).unwrap();
        assert_eq!(reopened.phase(), HardwareRunPhase::Failed);
        assert!(reopened.status().auto_failed_on_restart);
        let receipt = reopened.request(&wire, 10).unwrap();
        assert_eq!(receipt.phase, HardwareRunPhase::Prepared);
        assert_eq!(receipt.hardware_accepted, Some(true));
        assert_eq!(reopened.status().ledger_events, 3);
    }

    #[test]
    fn crash_between_start_ack_and_first_record_fails_closed() {
        let temp = TempLedger::new("start-crash");
        let start = command(3, 13, RunCommandKind::Start);
        {
            let mut value = HardwareRunCoordinator::open(&temp.0).unwrap();
            complete(&mut value, 1, 13, RunCommandKind::Prepare);
            complete(&mut value, 2, 13, RunCommandKind::Arm);
            value.request(&start, 10).unwrap();
            value
                .complete_reply(13, 3, true, sha256(b"start-ack"), false)
                .unwrap();
            assert_eq!(value.phase(), HardwareRunPhase::StartAcknowledged);
        }
        let mut reopened = HardwareRunCoordinator::open(&temp.0).unwrap();
        assert_eq!(reopened.phase(), HardwareRunPhase::Failed);
        let receipt = reopened.request(&start, 10).unwrap();
        assert_eq!(receipt.phase, HardwareRunPhase::Failed);
        assert_eq!(receipt.hardware_accepted, Some(false));
    }

    #[test]
    fn nack_and_corruption_are_fail_closed() {
        let temp = TempLedger::new("nack-corrupt");
        {
            let mut value = HardwareRunCoordinator::open(&temp.0).unwrap();
            value
                .request(&command(1, 17, RunCommandKind::Prepare), 10)
                .unwrap();
            let receipt = value
                .complete_reply(17, 1, false, sha256(b"nack"), false)
                .unwrap();
            assert_eq!(receipt.phase, HardwareRunPhase::Failed);
        }
        let event = temp.0.join(event_filename(0));
        let mut bytes = fs::read(&event).unwrap();
        bytes[FRAME_HEADER_LEN + 9] ^= 0x80;
        fs::write(&event, bytes).unwrap();
        assert_eq!(
            HardwareRunCoordinator::open(&temp.0).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
