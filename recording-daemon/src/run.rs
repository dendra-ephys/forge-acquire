use std::collections::HashMap;
use std::io;

use forge_protocol_v1::{Hash32, Id16, RunCommandV1, WireBody};
use serde::Serialize;

const MAX_CACHED_RECEIPTS: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunCommandKind {
    Prepare,
    Arm,
    Start,
    Stop,
    Abort,
    GetSnapshot,
    AcknowledgeFailure,
}

impl RunCommandKind {
    pub(crate) fn from_wire(value: u16) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Prepare),
            2 => Ok(Self::Arm),
            3 => Ok(Self::Start),
            4 => Ok(Self::Stop),
            5 => Ok(Self::Abort),
            6 => Ok(Self::GetSnapshot),
            7 => Ok(Self::AcknowledgeFailure),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown M0 RunCommandV1 command",
            )),
        }
    }

    pub const fn wire_value(self) -> u16 {
        match self {
            Self::Prepare => 1,
            Self::Arm => 2,
            Self::Start => 3,
            Self::Stop => 4,
            Self::Abort => 5,
            Self::GetSnapshot => 6,
            Self::AcknowledgeFailure => 7,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    New,
    Prepared,
    Armed,
    Recording,
    Stopped,
    JournalSealed,
    Finalized,
    Aborted,
    Failed,
}

impl RunState {
    pub(crate) const fn wire_value(self) -> u8 {
        match self {
            Self::New => 0,
            Self::Prepared => 1,
            Self::Armed => 2,
            Self::Recording => 3,
            Self::Stopped => 4,
            Self::Finalized => 5,
            Self::Aborted => 6,
            Self::Failed => 7,
            Self::JournalSealed => 8,
        }
    }

    pub(crate) fn from_wire(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::New),
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Armed),
            3 => Ok(Self::Recording),
            4 => Ok(Self::Stopped),
            5 => Ok(Self::Finalized),
            6 => Ok(Self::Aborted),
            7 => Ok(Self::Failed),
            8 => Ok(Self::JournalSealed),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown persisted Run state",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCommand {
    /// Authenticated low-speed envelope request identifier.
    pub request_id: u64,
    /// Authenticated low-speed envelope epoch.
    pub epoch: u64,
    /// The normative M0 body. RunService does not define a parallel wire type.
    pub body: RunCommandV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunReceipt {
    pub request_id: u64,
    pub epoch: u64,
    pub command: RunCommandKind,
    pub accepted: bool,
    pub prior_state: RunState,
    pub current_state: RunState,
    pub reason: String,
}

/// In-memory lifecycle state machine. Persistence of Run receipts and service
/// authentication remains an explicit production boundary; this type does not
/// pretend to provide either one.
pub struct RunService {
    state: RunState,
    active_epoch: Option<u64>,
    highest_epoch: u64,
    receipts: HashMap<(u64, u64), (RunCommand, RunReceipt)>,
    active_run_id: Option<Id16>,
    active_target_device_id: Option<Id16>,
    active_frozen_config_hash: Option<Hash32>,
}

impl Default for RunService {
    fn default() -> Self {
        Self {
            state: RunState::New,
            active_epoch: None,
            highest_epoch: 0,
            receipts: HashMap::new(),
            active_run_id: None,
            active_target_device_id: None,
            active_frozen_config_hash: None,
        }
    }
}

impl RunService {
    pub fn handle(
        &mut self,
        command: RunCommand,
        now_global_time_ns: u64,
    ) -> io::Result<RunReceipt> {
        if command.request_id == 0 || command.epoch == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Run command request_id and epoch must be nonzero",
            ));
        }
        let receipt_key = (command.epoch, command.request_id);
        if let Some((prior_command, receipt)) = self.receipts.get(&receipt_key) {
            if prior_command == &command {
                return Ok(receipt.clone());
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request_id was reused with a different Run command in the same epoch",
            ));
        }
        if self.receipts.len() >= MAX_CACHED_RECEIPTS {
            return Err(io::Error::other(
                "bounded idempotence receipt cache is full",
            ));
        }
        command.body.encode_body().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid M0 RunCommandV1 body: {error}"),
            )
        })?;
        if command.body.scope != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recording RunService rejects stimulation-scope commands",
            ));
        }
        let kind = RunCommandKind::from_wire(command.body.command)?;
        let prior_state = self.state;
        let (accepted, reason) = self.apply(&command, kind, now_global_time_ns);
        let receipt = RunReceipt {
            request_id: command.request_id,
            epoch: command.epoch,
            command: kind,
            accepted,
            prior_state,
            current_state: self.state,
            reason: reason.to_owned(),
        };
        self.receipts
            .insert(receipt_key, (command, receipt.clone()));
        Ok(receipt)
    }

    /// Records a policy-layer rejection without applying the command. This is
    /// used when the authenticated service boundary is healthy but a required
    /// capability (for example a real acquisition source) is unavailable.
    /// The rejection participates in the same bounded idempotence cache.
    pub(crate) fn cache_policy_rejection(
        &mut self,
        command: RunCommand,
        reason: &str,
    ) -> io::Result<RunReceipt> {
        if command.request_id == 0 || command.epoch == 0 || reason.is_empty() || reason.len() > 256
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "policy rejection requires a valid key and bounded reason",
            ));
        }
        command.body.encode_body().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid M0 RunCommandV1 body: {error}"),
            )
        })?;
        let kind = RunCommandKind::from_wire(command.body.command)?;
        let key = (command.epoch, command.request_id);
        if let Some((prior, receipt)) = self.receipts.get(&key) {
            return if prior == &command {
                Ok(receipt.clone())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "request_id was reused with different bytes in the same epoch",
                ))
            };
        }
        if self.receipts.len() >= MAX_CACHED_RECEIPTS {
            return Err(io::Error::other(
                "bounded idempotence receipt cache is full",
            ));
        }
        let receipt = RunReceipt {
            request_id: command.request_id,
            epoch: command.epoch,
            command: kind,
            accepted: false,
            prior_state: self.state,
            current_state: self.state,
            reason: reason.to_owned(),
        };
        self.receipts.insert(key, (command, receipt.clone()));
        Ok(receipt)
    }

    fn apply(
        &mut self,
        command: &RunCommand,
        kind: RunCommandKind,
        now_global_time_ns: u64,
    ) -> (bool, &'static str) {
        if now_global_time_ns >= command.body.deadline_global_time_ns {
            return (false, "Run command expired before evaluation");
        }
        if kind == RunCommandKind::Prepare {
            if !matches!(
                self.state,
                RunState::New | RunState::JournalSealed | RunState::Finalized
            ) || command.epoch <= self.highest_epoch
            {
                return (
                    false,
                    "Prepare requires New/JournalSealed/Finalized state and a fresh epoch",
                );
            }
            self.active_epoch = Some(command.epoch);
            self.highest_epoch = command.epoch;
            self.active_run_id = Some(command.body.run_id);
            self.active_target_device_id = Some(command.body.target_device_id);
            self.active_frozen_config_hash = Some(command.body.frozen_config_hash);
            self.state = RunState::Prepared;
            return (true, "prepared");
        }
        if self.active_epoch != Some(command.epoch)
            || self.active_run_id != Some(command.body.run_id)
            || self.active_target_device_id != Some(command.body.target_device_id)
            || self.active_frozen_config_hash != Some(command.body.frozen_config_hash)
        {
            return (
                false,
                "command epoch/Run/device/frozen-config does not match the active Run",
            );
        }
        if kind == RunCommandKind::GetSnapshot {
            if self.active_epoch == Some(command.epoch) {
                return (true, "snapshot");
            }
            return (false, "snapshot epoch does not match the active Run");
        }
        let next = match (self.state, kind) {
            (RunState::Prepared, RunCommandKind::Arm) => Some((RunState::Armed, "armed")),
            (RunState::Armed, RunCommandKind::Start) => Some((RunState::Recording, "recording")),
            (RunState::Recording, RunCommandKind::Stop) => Some((RunState::Stopped, "stopped")),
            (RunState::Prepared | RunState::Armed | RunState::Recording, RunCommandKind::Abort) => {
                Some((RunState::Aborted, "aborted"))
            }
            (RunState::Failed, RunCommandKind::AcknowledgeFailure) => {
                self.active_epoch = None;
                self.active_run_id = None;
                self.active_target_device_id = None;
                self.active_frozen_config_hash = None;
                Some((
                    RunState::New,
                    "failure acknowledged; a fresh epoch is required",
                ))
            }
            _ => None,
        };
        if let Some((state, reason)) = next {
            self.state = state;
            (true, reason)
        } else {
            (false, "Run command is invalid in the current state")
        }
    }

    pub fn fail_closed(&mut self) {
        if matches!(
            self.state,
            RunState::Prepared | RunState::Armed | RunState::Recording | RunState::Stopped
        ) {
            self.state = RunState::Failed;
        }
    }

    /// Called only after the owning journal has durably sealed and its receipt
    /// has been retained. This does not mean that NWB validation/publication
    /// has completed; Stop alone is deliberately insufficient.
    pub fn mark_journal_sealed(&mut self) -> io::Result<()> {
        if self.state != RunState::Stopped {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Run journal can seal only after an accepted Stop",
            ));
        }
        self.state = RunState::JournalSealed;
        self.active_epoch = None;
        self.active_run_id = None;
        self.active_target_device_id = None;
        self.active_frozen_config_hash = None;
        Ok(())
    }

    pub fn state(&self) -> RunState {
        self.state
    }

    pub fn active_epoch(&self) -> Option<u64> {
        self.active_epoch
    }

    pub fn highest_epoch(&self) -> u64 {
        self.highest_epoch
    }

    pub fn active_run_id(&self) -> Option<Id16> {
        self.active_run_id
    }

    pub fn active_target_device_id(&self) -> Option<Id16> {
        self.active_target_device_id
    }

    pub fn active_frozen_config_hash(&self) -> Option<Hash32> {
        self.active_frozen_config_hash
    }

    pub(crate) fn restore_command_receipt(
        &mut self,
        command: RunCommand,
        receipt: RunReceipt,
    ) -> io::Result<()> {
        command.body.encode_body().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("persisted Run command is invalid: {error}"),
            )
        })?;
        let kind = RunCommandKind::from_wire(command.body.command)?;
        if command.body.scope != 1
            || command.request_id != receipt.request_id
            || command.epoch != receipt.epoch
            || kind != receipt.command
            || receipt.prior_state != self.state
            || (receipt.reason.is_empty() || receipt.reason.len() > 256)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persisted Run command/receipt identity or state chain is invalid",
            ));
        }
        let key = (command.epoch, command.request_id);
        if self.receipts.contains_key(&key) || self.receipts.len() >= MAX_CACHED_RECEIPTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persisted Run receipt key is duplicate or the bounded ledger is full",
            ));
        }

        if receipt.accepted {
            if kind != RunCommandKind::Prepare
                && (self.active_epoch != Some(command.epoch)
                    || self.active_run_id != Some(command.body.run_id)
                    || self.active_target_device_id != Some(command.body.target_device_id)
                    || self.active_frozen_config_hash != Some(command.body.frozen_config_hash))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "persisted accepted command does not match the active Run context",
                ));
            }
            let expected_state = match (self.state, kind) {
                (
                    RunState::New | RunState::JournalSealed | RunState::Finalized,
                    RunCommandKind::Prepare,
                ) if command.epoch > self.highest_epoch => {
                    self.active_epoch = Some(command.epoch);
                    self.highest_epoch = command.epoch;
                    self.active_run_id = Some(command.body.run_id);
                    self.active_target_device_id = Some(command.body.target_device_id);
                    self.active_frozen_config_hash = Some(command.body.frozen_config_hash);
                    RunState::Prepared
                }
                (RunState::Prepared, RunCommandKind::Arm) => RunState::Armed,
                (RunState::Armed, RunCommandKind::Start) => RunState::Recording,
                (RunState::Recording, RunCommandKind::Stop) => RunState::Stopped,
                (
                    RunState::Prepared | RunState::Armed | RunState::Recording,
                    RunCommandKind::Abort,
                ) => RunState::Aborted,
                (state, RunCommandKind::GetSnapshot)
                    if self.active_epoch == Some(command.epoch) =>
                {
                    state
                }
                (RunState::Failed, RunCommandKind::AcknowledgeFailure) => {
                    self.clear_active_context();
                    RunState::New
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "persisted accepted Run transition is invalid",
                    ))
                }
            };
            if receipt.current_state != expected_state {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "persisted accepted Run transition has the wrong resulting state",
                ));
            }
        } else if receipt.current_state != receipt.prior_state {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persisted rejected Run command changed state",
            ));
        }

        self.state = receipt.current_state;
        self.receipts.insert(key, (command, receipt));
        Ok(())
    }

    pub(crate) fn restore_policy_rejection(
        &mut self,
        command: RunCommand,
        receipt: RunReceipt,
    ) -> io::Result<()> {
        command.body.encode_body().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("persisted policy-rejected command is invalid: {error}"),
            )
        })?;
        let kind = RunCommandKind::from_wire(command.body.command)?;
        if receipt.accepted
            || receipt.request_id != command.request_id
            || receipt.epoch != command.epoch
            || receipt.command != kind
            || receipt.prior_state != self.state
            || receipt.current_state != self.state
            || receipt.reason.is_empty()
            || receipt.reason.len() > 256
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persisted policy rejection contradicts Run state",
            ));
        }
        let key = (command.epoch, command.request_id);
        if self.receipts.insert(key, (command, receipt)).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persisted policy rejection reuses an idempotence key",
            ));
        }
        Ok(())
    }

    pub(crate) fn restore_journal_sealed(&mut self, epoch: u64, run_id: Id16) -> io::Result<()> {
        if self.state != RunState::Stopped
            || self.active_epoch != Some(epoch)
            || self.active_run_id != Some(run_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persisted journal-sealed event does not match a stopped active Run",
            ));
        }
        self.state = RunState::JournalSealed;
        self.clear_active_context();
        Ok(())
    }

    pub(crate) fn restore_fail_closed(&mut self, epoch: u64, run_id: Id16) -> io::Result<()> {
        if !matches!(
            self.state,
            RunState::Prepared | RunState::Armed | RunState::Recording | RunState::Stopped
        ) || self.active_epoch != Some(epoch)
            || self.active_run_id != Some(run_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persisted fail-closed event does not match an active Run",
            ));
        }
        self.state = RunState::Failed;
        Ok(())
    }

    fn clear_active_context(&mut self) {
        self.active_epoch = None;
        self.active_run_id = None;
        self.active_target_device_id = None;
        self.active_frozen_config_hash = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(id: u64, kind: RunCommandKind) -> RunCommand {
        RunCommand {
            request_id: id,
            epoch: 1,
            body: RunCommandV1 {
                command: kind.wire_value(),
                scope: 1,
                run_id: [0x11; 16],
                target_device_id: [0x22; 16],
                deadline_global_time_ns: 1_000,
                frozen_config_hash: [0x33; 32],
            },
        }
    }

    #[test]
    fn ordered_lifecycle_and_exact_idempotence() {
        let mut service = RunService::default();
        for (id, kind, state) in [
            (1, RunCommandKind::Prepare, RunState::Prepared),
            (2, RunCommandKind::Arm, RunState::Armed),
            (3, RunCommandKind::Start, RunState::Recording),
            (4, RunCommandKind::Stop, RunState::Stopped),
        ] {
            let receipt = service.handle(command(id, kind), 1).unwrap();
            assert!(receipt.accepted);
            assert_eq!(receipt.current_state, state);
            assert_eq!(service.handle(command(id, kind), 1).unwrap(), receipt);
        }
    }

    #[test]
    fn invalid_order_and_epoch_are_nacked_without_state_change() {
        let mut service = RunService::default();
        let start = service
            .handle(command(1, RunCommandKind::Start), 1)
            .unwrap();
        assert!(!start.accepted);
        assert_eq!(service.state(), RunState::New);
        service
            .handle(command(2, RunCommandKind::Prepare), 1)
            .unwrap();
        let mut wrong_epoch = command(3, RunCommandKind::Arm);
        wrong_epoch.epoch = 2;
        let wrong_epoch = service.handle(wrong_epoch, 1).unwrap();
        assert!(!wrong_epoch.accepted);
        assert_eq!(service.state(), RunState::Prepared);
    }

    #[test]
    fn reused_request_id_with_different_command_is_protocol_error() {
        let mut service = RunService::default();
        service
            .handle(command(1, RunCommandKind::Prepare), 1)
            .unwrap();
        assert!(service.handle(command(1, RunCommandKind::Arm), 1).is_err());
    }

    #[test]
    fn request_id_can_be_reused_in_a_new_epoch() {
        let mut service = RunService::default();
        for (id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
            (4, RunCommandKind::Stop),
        ] {
            assert!(service.handle(command(id, kind), 1).unwrap().accepted);
        }
        service.mark_journal_sealed().unwrap();

        let mut next = command(1, RunCommandKind::Prepare);
        next.epoch = 2;
        next.body.run_id = [0x44; 16];
        assert!(service.handle(next, 1).unwrap().accepted);
    }

    #[test]
    fn failure_acknowledgement_requires_a_new_epoch() {
        let mut service = RunService::default();
        service
            .handle(command(1, RunCommandKind::Prepare), 1)
            .unwrap();
        service.handle(command(2, RunCommandKind::Arm), 1).unwrap();
        service.fail_closed();
        assert_eq!(service.state(), RunState::Failed);
        assert!(
            service
                .handle(command(3, RunCommandKind::AcknowledgeFailure), 1)
                .unwrap()
                .accepted
        );
        assert!(
            !service
                .handle(command(4, RunCommandKind::Prepare), 1)
                .unwrap()
                .accepted
        );
        assert!(
            service
                .handle(
                    {
                        let mut fresh = command(5, RunCommandKind::Prepare);
                        fresh.epoch = 2;
                        fresh.body.run_id = [0x44; 16];
                        fresh
                    },
                    1
                )
                .unwrap()
                .accepted
        );
    }

    #[test]
    fn frozen_context_mismatch_and_expired_command_are_nacked() {
        let mut service = RunService::default();
        service
            .handle(command(1, RunCommandKind::Prepare), 1)
            .unwrap();
        let mut mismatch = command(2, RunCommandKind::Arm);
        mismatch.body.frozen_config_hash = [0x55; 32];
        assert!(!service.handle(mismatch, 1).unwrap().accepted);

        let expired = command(3, RunCommandKind::Arm);
        assert!(!service.handle(expired, 1_000).unwrap().accepted);
        assert_eq!(service.state(), RunState::Prepared);
    }

    #[test]
    fn stop_does_not_allow_next_run_until_durable_seal_is_marked() {
        let mut service = RunService::default();
        for (id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
            (4, RunCommandKind::Stop),
        ] {
            assert!(service.handle(command(id, kind), 1).unwrap().accepted);
        }
        let mut next = command(5, RunCommandKind::Prepare);
        next.epoch = 2;
        next.body.run_id = [0x44; 16];
        assert!(!service.handle(next.clone(), 1).unwrap().accepted);
        service.mark_journal_sealed().unwrap();
        next.request_id = 6;
        assert!(service.handle(next, 1).unwrap().accepted);
    }
}
