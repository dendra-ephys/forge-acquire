//! Durable, no-overwrite Run command and terminal-event ledger.
//!
//! Each accepted or rejected command receipt is written as one CRC32C-framed
//! file, flushed, and atomically renamed inside a dedicated ledger directory
//! before it may be returned to an IPC caller. A process restart while a Run
//! was Prepared, Armed, or Recording appends an auditable fail-closed event;
//! it never silently reconstructs an active Run.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use forge_protocol_v1::{
    crc32c, decode_low_speed, encode_low_speed, sha256, Hash32, Id16, MessageKind, RunCommandV1,
    WireBody,
};
use serde::Serialize;

use crate::run::{RunCommand, RunCommandKind, RunReceipt, RunService, RunState};

const FRAME_MAGIC: &[u8; 8] = b"FGRLED01";
const FOOTER_MAGIC: &[u8; 8] = b"FGRLEDF1";
const FRAME_VERSION: u16 = 1;
const FRAME_HEADER_LEN: usize = 32;
const FRAME_FOOTER_LEN: usize = 16;
const COMMAND_WIRE_LEN: usize = 160;
const MAX_REASON_LEN: usize = 256;
const MAX_EVENT_PAYLOAD_LEN: usize = 1024;
const MAX_LEDGER_EVENTS: usize = 1024;

pub const FAULT_DAEMON_RESTART: u32 = 1;
pub const FAULT_INTERNAL_PERSISTENCE: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
enum RunLedgerEvent {
    Command {
        command: RunCommand,
        receipt: RunReceipt,
    },
    JournalSealed {
        epoch: u64,
        run_id: Id16,
        seal_evidence_hash: Hash32,
    },
    NwbPublished {
        epoch: u64,
        run_id: Id16,
        publication_evidence_hash: Hash32,
    },
    FailClosed {
        epoch: u64,
        run_id: Id16,
        fault_code: u32,
        evidence_hash: Hash32,
    },
    PolicyRejected {
        command: RunCommand,
        receipt: RunReceipt,
    },
}

impl RunLedgerEvent {
    const fn kind(&self) -> u16 {
        match self {
            Self::Command { .. } => 1,
            Self::JournalSealed { .. } => 2,
            Self::FailClosed { .. } => 3,
            Self::NwbPublished { .. } => 4,
            Self::PolicyRejected { .. } => 5,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DurableRunStatus {
    pub state: RunState,
    pub active_epoch: Option<u64>,
    pub highest_epoch: u64,
    pub active_run_id_hex: Option<String>,
    pub active_target_device_id_hex: Option<String>,
    pub active_frozen_config_hash_hex: Option<String>,
    pub ledger_events: u64,
    pub auto_failed_on_restart: bool,
    pub poisoned: bool,
    pub hardware_transport_available: bool,
    pub latest_sealed_run_id_hex: Option<String>,
    pub latest_published_run_id_hex: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadOnlyNwbPublicationProof {
    pub epoch: u64,
    pub run_id: Id16,
    pub journal_seal_evidence_hash: Hash32,
    pub publication_evidence_hash: Hash32,
}

/// Verifies one specific finalized Run without creating the ledger directory,
/// appending restart evidence, or consulting whichever Run happens to be
/// latest. Event restoration is performed in memory only.
pub(crate) fn verify_nwb_publication_proof_read_only(
    path: impl AsRef<Path>,
    run_id: Id16,
    publication_evidence_hash: Hash32,
) -> io::Result<ReadOnlyNwbPublicationProof> {
    if !run_id.iter().any(|byte| *byte != 0)
        || !publication_evidence_hash.iter().any(|byte| *byte != 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "read-only publication proof identity must be nonzero",
        ));
    }
    let (ledger, events) = RunLedger::open_read_only(path)?;
    let mut restored = RunService::default();
    for event in &events {
        restore_event(&mut restored, event)?;
    }
    let (epoch, journal_seal_evidence_hash) =
        ledger.sealed_runs.get(&run_id).copied().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Run ledger has no journal seal for the requested Run",
            )
        })?;
    let (published_epoch, recorded_publication_hash) =
        ledger.published_runs.get(&run_id).copied().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Run ledger has no NWB publication for the requested Run",
            )
        })?;
    if published_epoch != epoch || recorded_publication_hash != publication_evidence_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Run ledger NWB publication proof differs for the requested Run",
        ));
    }
    Ok(ReadOnlyNwbPublicationProof {
        epoch,
        run_id,
        journal_seal_evidence_hash,
        publication_evidence_hash: recorded_publication_hash,
    })
}

pub struct DurableRunService {
    service: RunService,
    ledger: RunLedger,
    poisoned: bool,
    auto_failed_on_restart: bool,
}

impl DurableRunService {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let (mut ledger, events) = RunLedger::open(path)?;
        let mut service = RunService::default();
        for event in &events {
            restore_event(&mut service, event)?;
        }

        let mut auto_failed_on_restart = false;
        if matches!(
            service.state(),
            RunState::Prepared | RunState::Armed | RunState::Recording | RunState::Stopped
        ) {
            let epoch = service.active_epoch().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "active restored Run has no epoch",
                )
            })?;
            let run_id = service.active_run_id().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "active restored Run has no Run ID",
                )
            })?;
            let event = RunLedgerEvent::FailClosed {
                epoch,
                run_id,
                fault_code: FAULT_DAEMON_RESTART,
                evidence_hash: sha256(b"forge-acqd-active-run-restart-fail-closed-v1"),
            };
            ledger.append(event.clone())?;
            restore_event(&mut service, &event)?;
            auto_failed_on_restart = true;
        }

        Ok(Self {
            service,
            ledger,
            poisoned: false,
            auto_failed_on_restart,
        })
    }

    pub fn handle(
        &mut self,
        command: RunCommand,
        now_global_time_ns: u64,
    ) -> io::Result<RunReceipt> {
        if self.poisoned {
            return Err(io::Error::other(
                "durable Run service is poisoned after a persistence failure",
            ));
        }
        let key = (command.epoch, command.request_id);
        if let Some((prior_command, receipt)) = self.ledger.receipts.get(&key) {
            if prior_command == &command {
                return Ok(receipt.clone());
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request_id was reused with different bytes in the same epoch",
            ));
        }

        let receipt = self.service.handle(command.clone(), now_global_time_ns)?;
        let event = RunLedgerEvent::Command {
            command,
            receipt: receipt.clone(),
        };
        if let Err(error) = self.ledger.append(event) {
            self.service.fail_closed();
            self.poisoned = true;
            return Err(io::Error::new(
                error.kind(),
                format!("failed to durably persist Run receipt: {error}"),
            ));
        }
        Ok(receipt)
    }

    /// Durably records a capability/policy rejection while leaving the Run
    /// state unchanged. Exact retries return the original receipt after a
    /// process restart; conflicting reuse of the idempotence key is rejected.
    pub fn reject_by_policy(
        &mut self,
        command: RunCommand,
        reason: &str,
    ) -> io::Result<RunReceipt> {
        self.ensure_usable()?;
        let key = (command.epoch, command.request_id);
        if let Some((prior_command, receipt)) = self.ledger.receipts.get(&key) {
            return if prior_command == &command {
                Ok(receipt.clone())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "request_id was reused with different bytes in the same epoch",
                ))
            };
        }
        let receipt = self
            .service
            .cache_policy_rejection(command.clone(), reason)?;
        if let Err(error) = self.ledger.append(RunLedgerEvent::PolicyRejected {
            command,
            receipt: receipt.clone(),
        }) {
            self.service.fail_closed();
            self.poisoned = true;
            return Err(io::Error::new(
                error.kind(),
                format!("failed to durably persist policy rejection: {error}"),
            ));
        }
        Ok(receipt)
    }

    /// The caller must supply a nonzero hash that binds the durable journal
    /// seal and retained Run receipt. The event is durable before in-memory
    /// state is released for a new epoch.
    pub fn mark_journal_sealed(&mut self, seal_evidence_hash: Hash32) -> io::Result<()> {
        self.ensure_usable()?;
        if !seal_evidence_hash.iter().any(|byte| *byte != 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seal evidence hash must be nonzero",
            ));
        }
        let epoch = self.service.active_epoch().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no active stopped Run epoch")
        })?;
        let run_id = self.service.active_run_id().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no active stopped Run ID")
        })?;
        if self.service.state() != RunState::Stopped {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Run journal can seal only after an accepted Stop",
            ));
        }
        let event = RunLedgerEvent::JournalSealed {
            epoch,
            run_id,
            seal_evidence_hash,
        };
        self.ledger.append(event)?;
        self.service.mark_journal_sealed()
    }

    pub fn fail_closed(&mut self, fault_code: u32, evidence_hash: Hash32) -> io::Result<()> {
        self.ensure_usable()?;
        if fault_code == 0 || !evidence_hash.iter().any(|byte| *byte != 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fault code and evidence hash must be nonzero",
            ));
        }
        let epoch = self.service.active_epoch().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no active Run to fail closed")
        })?;
        let run_id = self.service.active_run_id().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no active Run to fail closed")
        })?;
        if !matches!(
            self.service.state(),
            RunState::Prepared | RunState::Armed | RunState::Recording | RunState::Stopped
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only an active or stopped-unsealed Run can enter the durable failed state",
            ));
        }
        self.service.fail_closed();
        let event = RunLedgerEvent::FailClosed {
            epoch,
            run_id,
            fault_code,
            evidence_hash,
        };
        if let Err(error) = self.ledger.append(event) {
            self.poisoned = true;
            return Err(io::Error::new(
                error.kind(),
                format!("Run failed closed but its audit event did not persist: {error}"),
            ));
        }
        Ok(())
    }

    /// Durably binds an owner-produced NWB publication receipt to a previously
    /// sealed Run. Publication may finish after a newer Run has started, so
    /// this is keyed by immutable Run ID rather than the active Run context.
    pub fn mark_nwb_published(
        &mut self,
        run_id: Id16,
        publication_evidence_hash: Hash32,
    ) -> io::Result<()> {
        self.ensure_usable()?;
        if !run_id.iter().any(|byte| *byte != 0)
            || !publication_evidence_hash.iter().any(|byte| *byte != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "published Run ID and evidence hash must be nonzero",
            ));
        }
        let (epoch, _) = self
            .ledger
            .sealed_runs
            .get(&run_id)
            .copied()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NWB publication does not match a sealed Run",
                )
            })?;
        if let Some((prior_epoch, prior_hash)) = self.ledger.published_runs.get(&run_id) {
            return if *prior_epoch == epoch && *prior_hash == publication_evidence_hash {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Run already has a different NWB publication receipt",
                ))
            };
        }
        self.ledger.append(RunLedgerEvent::NwbPublished {
            epoch,
            run_id,
            publication_evidence_hash,
        })
    }

    /// Rechecks the immutable publication-receipt hash recorded for a sealed
    /// Run.  This is deliberately read-only: later retention gates must not
    /// infer publication from a current state string alone.
    pub fn verify_nwb_publication_binding(
        &self,
        run_id: Id16,
        publication_evidence_hash: Hash32,
    ) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other("Run ledger is poisoned"));
        }
        let Some((_, recorded)) = self.ledger.published_runs.get(&run_id) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Run ledger has no NWB publication for this Run",
            ));
        };
        if *recorded != publication_evidence_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Run ledger NWB publication receipt hash differs",
            ));
        }
        Ok(())
    }

    pub fn status(&self) -> DurableRunStatus {
        let state = if self.service.state() == RunState::JournalSealed
            && self
                .ledger
                .latest_sealed_run
                .is_some_and(|(_, run_id)| self.ledger.published_runs.contains_key(&run_id))
        {
            RunState::Finalized
        } else {
            self.service.state()
        };
        DurableRunStatus {
            state,
            active_epoch: self.service.active_epoch(),
            highest_epoch: self.service.highest_epoch(),
            active_run_id_hex: self.service.active_run_id().map(hex),
            active_target_device_id_hex: self.service.active_target_device_id().map(hex),
            active_frozen_config_hash_hex: self.service.active_frozen_config_hash().map(hex),
            ledger_events: self.ledger.next_sequence,
            auto_failed_on_restart: self.auto_failed_on_restart,
            poisoned: self.poisoned,
            hardware_transport_available: false,
            latest_sealed_run_id_hex: self.ledger.latest_sealed_run.map(|(_, run_id)| hex(run_id)),
            latest_published_run_id_hex: self
                .ledger
                .latest_published_run
                .map(|(_, run_id)| hex(run_id)),
        }
    }

    fn ensure_usable(&self) -> io::Result<()> {
        if self.poisoned {
            Err(io::Error::other(
                "durable Run service is poisoned after a persistence failure",
            ))
        } else {
            Ok(())
        }
    }
}

struct RunLedger {
    root: PathBuf,
    next_sequence: u64,
    receipts: HashMap<(u64, u64), (RunCommand, RunReceipt)>,
    sealed_runs: HashMap<Id16, (u64, Hash32)>,
    published_runs: HashMap<Id16, (u64, Hash32)>,
    latest_sealed_run: Option<(u64, Id16)>,
    latest_published_run: Option<(u64, Id16)>,
}

fn collect_event_paths_bounded(
    entries: impl IntoIterator<Item = io::Result<(String, PathBuf)>>,
    max_events: usize,
) -> io::Result<Vec<(u64, PathBuf)>> {
    if max_events > MAX_LEDGER_EVENTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Run ledger path collection bound exceeds the product limit",
        ));
    }
    let mut paths = Vec::with_capacity(max_events);
    for entry in entries {
        let (name, path) = entry?;
        if name.starts_with(".pending-event-") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete pending Run ledger event requires explicit forensic recovery",
            ));
        }
        if name.starts_with("event-") {
            let sequence = parse_event_filename(&name)?;
            if paths.len() >= max_events {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Run ledger exceeds its bounded event count",
                ));
            }
            paths.push((sequence, path));
        }
    }
    paths.sort_by_key(|(sequence, _)| *sequence);
    Ok(paths)
}

impl RunLedger {
    fn open(path: impl AsRef<Path>) -> io::Result<(Self, Vec<RunLedgerEvent>)> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Run ledger path is not a directory",
            ));
        }
        Self::load_existing(root)
    }

    fn open_read_only(path: impl AsRef<Path>) -> io::Result<(Self, Vec<RunLedgerEvent>)> {
        let root = path.as_ref().to_path_buf();
        let metadata = fs::metadata(&root)?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Run ledger path is not an existing directory",
            ));
        }
        Self::load_existing(root)
    }

    fn load_existing(root: PathBuf) -> io::Result<(Self, Vec<RunLedgerEvent>)> {
        let entries = fs::read_dir(&root)?.map(|entry| {
            let entry = entry?;
            Ok((
                entry.file_name().to_string_lossy().into_owned(),
                entry.path(),
            ))
        });
        let paths = collect_event_paths_bounded(entries, MAX_LEDGER_EVENTS)?;

        let mut events = Vec::with_capacity(paths.len());
        let mut receipts = HashMap::new();
        let mut sealed_runs = HashMap::new();
        let mut published_runs = HashMap::new();
        let mut latest_sealed_run = None;
        let mut latest_published_run = None;
        for (expected, (sequence, path)) in paths.into_iter().enumerate() {
            if sequence != expected as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Run ledger event sequence is not contiguous",
                ));
            }
            let event = read_event_file(&path, sequence)?;
            if let RunLedgerEvent::Command { command, receipt }
            | RunLedgerEvent::PolicyRejected { command, receipt } = &event
            {
                let key = (command.epoch, command.request_id);
                if receipts
                    .insert(key, (command.clone(), receipt.clone()))
                    .is_some()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Run ledger contains a duplicate idempotence key",
                    ));
                }
            }
            match &event {
                RunLedgerEvent::JournalSealed {
                    epoch,
                    run_id,
                    seal_evidence_hash,
                } => {
                    if sealed_runs
                        .insert(*run_id, (*epoch, *seal_evidence_hash))
                        .is_some()
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Run ledger contains duplicate journal-seal evidence",
                        ));
                    }
                    latest_sealed_run = Some((*epoch, *run_id));
                }
                RunLedgerEvent::NwbPublished {
                    epoch,
                    run_id,
                    publication_evidence_hash,
                } => {
                    if sealed_runs.get(run_id).map(|(value, _)| value) != Some(epoch)
                        || published_runs
                            .insert(*run_id, (*epoch, *publication_evidence_hash))
                            .is_some()
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "NWB publication does not follow exactly one matching journal seal",
                        ));
                    }
                    latest_published_run = Some((*epoch, *run_id));
                }
                _ => {}
            }
            events.push(event);
        }

        Ok((
            Self {
                root,
                next_sequence: events.len() as u64,
                receipts,
                sealed_runs,
                published_runs,
                latest_sealed_run,
                latest_published_run,
            },
            events,
        ))
    }

    fn append(&mut self, event: RunLedgerEvent) -> io::Result<()> {
        if self.next_sequence as usize >= MAX_LEDGER_EVENTS {
            return Err(io::Error::other(
                "bounded Run ledger event capacity is exhausted",
            ));
        }
        if let RunLedgerEvent::Command { command, .. }
        | RunLedgerEvent::PolicyRejected { command, .. } = &event
        {
            let key = (command.epoch, command.request_id);
            if self.receipts.contains_key(&key) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Run ledger idempotence key already exists",
                ));
            }
        }
        match &event {
            RunLedgerEvent::JournalSealed { run_id, .. }
                if self.sealed_runs.contains_key(run_id) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Run journal seal is already recorded",
                ));
            }
            RunLedgerEvent::NwbPublished { epoch, run_id, .. }
                if self.sealed_runs.get(run_id).map(|(value, _)| value) != Some(epoch)
                    || self.published_runs.contains_key(run_id) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NWB publication lacks one unpublished matching journal seal",
                ));
            }
            _ => {}
        }

        let sequence = self.next_sequence;
        let final_path = self.root.join(event_filename(sequence));
        let pending_path = self.root.join(format!(
            ".pending-event-{sequence:020}-{}.bin",
            std::process::id()
        ));
        let bytes = encode_event(sequence, &event)?;
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
                "Run ledger event target already exists",
            ));
        }
        fs::rename(&pending_path, &final_path)?;

        if let RunLedgerEvent::Command { command, receipt }
        | RunLedgerEvent::PolicyRejected { command, receipt } = &event
        {
            self.receipts.insert(
                (command.epoch, command.request_id),
                (command.clone(), receipt.clone()),
            );
        }
        match &event {
            RunLedgerEvent::JournalSealed {
                epoch,
                run_id,
                seal_evidence_hash,
            } => {
                self.sealed_runs
                    .insert(*run_id, (*epoch, *seal_evidence_hash));
                self.latest_sealed_run = Some((*epoch, *run_id));
            }
            RunLedgerEvent::NwbPublished {
                epoch,
                run_id,
                publication_evidence_hash,
            } => {
                self.published_runs
                    .insert(*run_id, (*epoch, *publication_evidence_hash));
                self.latest_published_run = Some((*epoch, *run_id));
            }
            _ => {}
        }
        self.next_sequence += 1;
        Ok(())
    }
}

fn restore_event(service: &mut RunService, event: &RunLedgerEvent) -> io::Result<()> {
    match event {
        RunLedgerEvent::Command { command, receipt } => {
            service.restore_command_receipt(command.clone(), receipt.clone())
        }
        RunLedgerEvent::PolicyRejected { command, receipt } => {
            service.restore_policy_rejection(command.clone(), receipt.clone())
        }
        RunLedgerEvent::JournalSealed { epoch, run_id, .. } => {
            service.restore_journal_sealed(*epoch, *run_id)
        }
        RunLedgerEvent::NwbPublished { .. } => Ok(()),
        RunLedgerEvent::FailClosed {
            epoch,
            run_id,
            fault_code,
            ..
        } => {
            if *fault_code == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "persisted fail-closed event has a zero fault code",
                ));
            }
            service.restore_fail_closed(*epoch, *run_id)
        }
    }
}

fn encode_event(sequence: u64, event: &RunLedgerEvent) -> io::Result<Vec<u8>> {
    let payload = encode_event_payload(event)?;
    if payload.len() > MAX_EVENT_PAYLOAD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Run ledger event payload exceeds its bound",
        ));
    }
    let total_len = FRAME_HEADER_LEN
        .checked_add(payload.len())
        .and_then(|value| value.checked_add(FRAME_FOOTER_LEN))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "event length overflow"))?;
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

fn encode_event_payload(event: &RunLedgerEvent) -> io::Result<Vec<u8>> {
    match event {
        RunLedgerEvent::Command { command, receipt }
        | RunLedgerEvent::PolicyRejected { command, receipt } => {
            if command.request_id != receipt.request_id
                || command.epoch != receipt.epoch
                || command.body.command != receipt.command.wire_value()
                || receipt.reason.is_empty()
                || receipt.reason.len() > MAX_REASON_LEN
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Run command receipt cannot be encoded",
                ));
            }
            let command_wire =
                encode_low_speed(0, command.request_id, command.epoch, &command.body).map_err(
                    |error| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("Run command wire encoding failed: {error}"),
                        )
                    },
                )?;
            if command_wire.len() != COMMAND_WIRE_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Run command wire length changed without a ledger version bump",
                ));
            }
            let mut payload = Vec::with_capacity(12 + command_wire.len() + receipt.reason.len());
            payload.extend_from_slice(&(command_wire.len() as u32).to_le_bytes());
            payload.push(u8::from(receipt.accepted));
            payload.push(receipt.prior_state.wire_value());
            payload.push(receipt.current_state.wire_value());
            payload.push(receipt.command.wire_value() as u8);
            payload.extend_from_slice(&(receipt.reason.len() as u16).to_le_bytes());
            payload.extend_from_slice(&0_u16.to_le_bytes());
            payload.extend_from_slice(&command_wire);
            payload.extend_from_slice(receipt.reason.as_bytes());
            Ok(payload)
        }
        RunLedgerEvent::JournalSealed {
            epoch,
            run_id,
            seal_evidence_hash,
        } => {
            validate_terminal_identity(*epoch, run_id, seal_evidence_hash)?;
            let mut payload = Vec::with_capacity(56);
            payload.extend_from_slice(&epoch.to_le_bytes());
            payload.extend_from_slice(run_id);
            payload.extend_from_slice(seal_evidence_hash);
            Ok(payload)
        }
        RunLedgerEvent::NwbPublished {
            epoch,
            run_id,
            publication_evidence_hash,
        } => {
            validate_terminal_identity(*epoch, run_id, publication_evidence_hash)?;
            let mut payload = Vec::with_capacity(56);
            payload.extend_from_slice(&epoch.to_le_bytes());
            payload.extend_from_slice(run_id);
            payload.extend_from_slice(publication_evidence_hash);
            Ok(payload)
        }
        RunLedgerEvent::FailClosed {
            epoch,
            run_id,
            fault_code,
            evidence_hash,
        } => {
            validate_terminal_identity(*epoch, run_id, evidence_hash)?;
            if *fault_code == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "fail-closed fault code must be nonzero",
                ));
            }
            let mut payload = Vec::with_capacity(64);
            payload.extend_from_slice(&epoch.to_le_bytes());
            payload.extend_from_slice(run_id);
            payload.extend_from_slice(&fault_code.to_le_bytes());
            payload.extend_from_slice(&0_u32.to_le_bytes());
            payload.extend_from_slice(evidence_hash);
            Ok(payload)
        }
    }
}

fn read_event_file(path: &Path, expected_sequence: u64) -> io::Result<RunLedgerEvent> {
    let mut file = File::open(path)?;
    let length = usize::try_from(file.metadata()?.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Run ledger event file is too large",
        )
    })?;
    if !(FRAME_HEADER_LEN + FRAME_FOOTER_LEN
        ..=FRAME_HEADER_LEN + MAX_EVENT_PAYLOAD_LEN + FRAME_FOOTER_LEN)
        .contains(&length)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Run ledger event file length is invalid",
        ));
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
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Run ledger event header is invalid",
        ));
    }
    let payload_end = frame.len() - FRAME_FOOTER_LEN;
    let payload = &frame[FRAME_HEADER_LEN..payload_end];
    if crc32c(payload) != le_u32(&frame, 28)?
        || &frame[payload_end..payload_end + 8] != FOOTER_MAGIC
        || le_u32(&frame, payload_end + 12)? != 0
        || crc32c(&frame[..payload_end]) != le_u32(&frame, payload_end + 8)?
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Run ledger event CRC/footer is invalid",
        ));
    }
    decode_event_payload(le_u16(&frame, 12)?, payload)
}

fn decode_event_payload(kind: u16, payload: &[u8]) -> io::Result<RunLedgerEvent> {
    match kind {
        1 | 5 => {
            if payload.len() < 12 {
                return Err(invalid_payload());
            }
            let command_len = le_u32(payload, 0)? as usize;
            let accepted = match payload[4] {
                0 => false,
                1 => true,
                _ => return Err(invalid_payload()),
            };
            let prior_state = RunState::from_wire(payload[5])?;
            let current_state = RunState::from_wire(payload[6])?;
            let command = RunCommandKind::from_wire(payload[7] as u16)?;
            let reason_len = le_u16(payload, 8)? as usize;
            if le_u16(payload, 10)? != 0
                || command_len != COMMAND_WIRE_LEN
                || reason_len == 0
                || reason_len > MAX_REASON_LEN
                || payload.len() != 12 + command_len + reason_len
            {
                return Err(invalid_payload());
            }
            let decoded = decode_low_speed(&payload[12..12 + command_len]).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("persisted Run command wire is invalid: {error}"),
                )
            })?;
            if decoded.kind != MessageKind::RunCommand || decoded.flags != 0 {
                return Err(invalid_payload());
            }
            let body = RunCommandV1::decode_body(&decoded.body).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("persisted Run command body is invalid: {error}"),
                )
            })?;
            let reason = std::str::from_utf8(&payload[12 + command_len..])
                .map_err(|_| invalid_payload())?
                .to_owned();
            let command_value = RunCommand {
                request_id: decoded.request_id,
                epoch: decoded.epoch,
                body,
            };
            if command_value.body.command != command.wire_value() {
                return Err(invalid_payload());
            }
            let receipt = RunReceipt {
                request_id: command_value.request_id,
                epoch: command_value.epoch,
                command,
                accepted,
                prior_state,
                current_state,
                reason,
            };
            if kind == 1 {
                Ok(RunLedgerEvent::Command {
                    command: command_value,
                    receipt,
                })
            } else {
                if receipt.accepted || receipt.prior_state != receipt.current_state {
                    return Err(invalid_payload());
                }
                Ok(RunLedgerEvent::PolicyRejected {
                    command: command_value,
                    receipt,
                })
            }
        }
        2 => {
            if payload.len() != 56 {
                return Err(invalid_payload());
            }
            let epoch = le_u64(payload, 0)?;
            let run_id = array::<16>(payload, 8)?;
            let seal_evidence_hash = array::<32>(payload, 24)?;
            validate_terminal_identity(epoch, &run_id, &seal_evidence_hash)?;
            Ok(RunLedgerEvent::JournalSealed {
                epoch,
                run_id,
                seal_evidence_hash,
            })
        }
        3 => {
            if payload.len() != 64 || le_u32(payload, 28)? != 0 {
                return Err(invalid_payload());
            }
            let epoch = le_u64(payload, 0)?;
            let run_id = array::<16>(payload, 8)?;
            let fault_code = le_u32(payload, 24)?;
            let evidence_hash = array::<32>(payload, 32)?;
            validate_terminal_identity(epoch, &run_id, &evidence_hash)?;
            if fault_code == 0 {
                return Err(invalid_payload());
            }
            Ok(RunLedgerEvent::FailClosed {
                epoch,
                run_id,
                fault_code,
                evidence_hash,
            })
        }
        4 => {
            if payload.len() != 56 {
                return Err(invalid_payload());
            }
            let epoch = le_u64(payload, 0)?;
            let run_id = array::<16>(payload, 8)?;
            let publication_evidence_hash = array::<32>(payload, 24)?;
            validate_terminal_identity(epoch, &run_id, &publication_evidence_hash)?;
            Ok(RunLedgerEvent::NwbPublished {
                epoch,
                run_id,
                publication_evidence_hash,
            })
        }
        _ => Err(invalid_payload()),
    }
}

fn validate_terminal_identity(epoch: u64, run_id: &Id16, evidence_hash: &Hash32) -> io::Result<()> {
    if epoch == 0
        || !run_id.iter().any(|byte| *byte != 0)
        || !evidence_hash.iter().any(|byte| *byte != 0)
    {
        Err(invalid_payload())
    } else {
        Ok(())
    }
}

fn parse_event_filename(name: &str) -> io::Result<u64> {
    let digits = name
        .strip_prefix("event-")
        .and_then(|value| value.strip_suffix(".bin"))
        .ok_or_else(invalid_payload)?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Run ledger event filename is invalid",
        ));
    }
    digits.parse().map_err(|_| invalid_payload())
}

fn event_filename(sequence: u64) -> String {
    format!("event-{sequence:020}.bin")
}

fn invalid_payload() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Run ledger event payload is invalid",
    )
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
        .ok_or_else(invalid_payload)?
        .try_into()
        .map_err(|_| invalid_payload())
}

fn hex<const N: usize>(bytes: [u8; N]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempLedger {
        path: PathBuf,
    }

    impl TempLedger {
        fn new() -> Self {
            let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("forge-run-ledger-{}-{suffix}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempLedger {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn command(request_id: u64, epoch: u64, kind: RunCommandKind) -> RunCommand {
        RunCommand {
            request_id,
            epoch,
            body: RunCommandV1 {
                command: kind.wire_value(),
                scope: 1,
                run_id: if epoch == 1 { [0x11; 16] } else { [0x44; 16] },
                target_device_id: [0x22; 16],
                deadline_global_time_ns: 1_000,
                frozen_config_hash: [0x33; 32],
            },
        }
    }

    #[test]
    fn exact_command_receipt_survives_restart_without_duplicate_append() {
        let temp = TempLedger::new();
        let prepare = command(1, 1, RunCommandKind::Prepare);
        let original = {
            let mut service = DurableRunService::open(&temp.path).unwrap();
            service.handle(prepare.clone(), 1).unwrap()
        };
        let mut reopened = DurableRunService::open(&temp.path).unwrap();
        assert!(reopened.status().auto_failed_on_restart);
        let count_before = reopened.status().ledger_events;
        assert_eq!(reopened.handle(prepare.clone(), 1).unwrap(), original);
        assert_eq!(reopened.status().ledger_events, count_before);

        let mut conflict = prepare;
        conflict.body.command = RunCommandKind::Arm.wire_value();
        assert!(reopened.handle(conflict, 1).is_err());
    }

    #[test]
    fn policy_rejection_is_durable_idempotent_and_does_not_advance_state() {
        let temp = TempLedger::new();
        let prepare = command(1, 1, RunCommandKind::Prepare);
        let original = {
            let mut service = DurableRunService::open(&temp.path).unwrap();
            let receipt = service
                .reject_by_policy(prepare.clone(), "acquisition transport unavailable")
                .unwrap();
            assert!(!receipt.accepted);
            assert_eq!(receipt.prior_state, RunState::New);
            assert_eq!(receipt.current_state, RunState::New);
            assert_eq!(service.status().ledger_events, 1);
            receipt
        };
        let mut reopened = DurableRunService::open(&temp.path).unwrap();
        assert_eq!(reopened.status().state, RunState::New);
        assert_eq!(
            reopened
                .reject_by_policy(prepare.clone(), "reason is ignored on exact retry")
                .unwrap(),
            original
        );
        assert_eq!(reopened.status().ledger_events, 1);
        let mut conflict = prepare;
        conflict.body.target_device_id = [0x99; 16];
        assert!(reopened
            .reject_by_policy(conflict, "acquisition transport unavailable")
            .is_err());
    }

    #[test]
    fn active_run_restart_is_durably_failed_and_can_be_acknowledged() {
        let temp = TempLedger::new();
        {
            let mut service = DurableRunService::open(&temp.path).unwrap();
            service
                .handle(command(1, 1, RunCommandKind::Prepare), 1)
                .unwrap();
            service
                .handle(command(2, 1, RunCommandKind::Arm), 1)
                .unwrap();
        }
        let mut reopened = DurableRunService::open(&temp.path).unwrap();
        assert_eq!(reopened.status().state, RunState::Failed);
        assert!(reopened.status().auto_failed_on_restart);
        assert!(
            reopened
                .handle(command(3, 1, RunCommandKind::AcknowledgeFailure), 1)
                .unwrap()
                .accepted
        );
        assert_eq!(reopened.status().state, RunState::New);
    }

    #[test]
    fn durable_journal_seal_allows_new_epoch_and_request_id_reuse_after_restart() {
        let temp = TempLedger::new();
        {
            let mut service = DurableRunService::open(&temp.path).unwrap();
            for (id, kind) in [
                (1, RunCommandKind::Prepare),
                (2, RunCommandKind::Arm),
                (3, RunCommandKind::Start),
                (4, RunCommandKind::Stop),
            ] {
                assert!(service.handle(command(id, 1, kind), 1).unwrap().accepted);
            }
            service.mark_journal_sealed([0x55; 32]).unwrap();
        }
        let mut reopened = DurableRunService::open(&temp.path).unwrap();
        assert_eq!(reopened.status().state, RunState::JournalSealed);
        assert!(!reopened.status().auto_failed_on_restart);
        assert!(
            reopened
                .handle(command(1, 2, RunCommandKind::Prepare), 1)
                .unwrap()
                .accepted
        );
    }

    #[test]
    fn publication_receipt_finalizes_matching_run_and_survives_restart() {
        let temp = TempLedger::new();
        {
            let mut service = DurableRunService::open(&temp.path).unwrap();
            for (id, kind) in [
                (1, RunCommandKind::Prepare),
                (2, RunCommandKind::Arm),
                (3, RunCommandKind::Start),
                (4, RunCommandKind::Stop),
            ] {
                assert!(service.handle(command(id, 1, kind), 1).unwrap().accepted);
            }
            service.mark_journal_sealed([0x55; 32]).unwrap();
            assert_eq!(service.status().state, RunState::JournalSealed);
            service.mark_nwb_published([0x11; 16], [0x66; 32]).unwrap();
            assert_eq!(service.status().state, RunState::Finalized);
            assert_eq!(
                service.status().latest_published_run_id_hex.as_deref(),
                Some("11111111111111111111111111111111")
            );
            service.mark_nwb_published([0x11; 16], [0x66; 32]).unwrap();
            service
                .verify_nwb_publication_binding([0x11; 16], [0x66; 32])
                .unwrap();
            assert!(service
                .verify_nwb_publication_binding([0x11; 16], [0x77; 32])
                .is_err());
            assert!(service.mark_nwb_published([0x11; 16], [0x77; 32]).is_err());
        }
        let mut reopened = DurableRunService::open(&temp.path).unwrap();
        assert_eq!(reopened.status().state, RunState::Finalized);
        assert!(!reopened.status().auto_failed_on_restart);
        assert!(
            reopened
                .handle(command(1, 2, RunCommandKind::Prepare), 1)
                .unwrap()
                .accepted
        );
        assert_eq!(reopened.status().state, RunState::Prepared);
    }

    #[test]
    fn read_only_publication_proof_targets_old_run_without_writing_restart_event() {
        let temp = TempLedger::new();
        let mut service = DurableRunService::open(&temp.path).unwrap();
        for (id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
            (4, RunCommandKind::Stop),
        ] {
            assert!(service.handle(command(id, 1, kind), 1).unwrap().accepted);
        }
        service.mark_journal_sealed([0x55; 32]).unwrap();
        service.mark_nwb_published([0x11; 16], [0x66; 32]).unwrap();
        assert!(
            service
                .handle(command(1, 2, RunCommandKind::Prepare), 1)
                .unwrap()
                .accepted
        );
        drop(service);

        let mut before: Vec<_> = fs::read_dir(&temp.path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        before.sort();
        let proof =
            verify_nwb_publication_proof_read_only(&temp.path, [0x11; 16], [0x66; 32]).unwrap();
        assert_eq!(proof.epoch, 1);
        assert_eq!(proof.run_id, [0x11; 16]);
        assert_eq!(proof.journal_seal_evidence_hash, [0x55; 32]);
        assert_eq!(proof.publication_evidence_hash, [0x66; 32]);
        assert!(
            verify_nwb_publication_proof_read_only(&temp.path, [0x11; 16], [0x77; 32]).is_err()
        );
        let mut after: Vec<_> = fs::read_dir(&temp.path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        after.sort();
        assert_eq!(after, before);
    }

    #[test]
    fn read_only_publication_proof_never_creates_a_missing_ledger_directory() {
        let path = std::env::temp_dir().join(format!(
            "forge-run-ledger-read-only-missing-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        assert!(verify_nwb_publication_proof_read_only(&path, [0x11; 16], [0x66; 32]).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn event_path_collection_accepts_exact_bound_and_rejects_before_extra_push() {
        let exact = (0..u64::try_from(MAX_LEDGER_EVENTS).unwrap()).map(|sequence| {
            Ok::<_, io::Error>((
                event_filename(sequence),
                PathBuf::from(format!("exact-{sequence}")),
            ))
        });
        let paths = collect_event_paths_bounded(exact, MAX_LEDGER_EVENTS).unwrap();
        assert_eq!(paths.len(), MAX_LEDGER_EVENTS);

        let small_limit = 3;
        let overflow = (0_u64..=u64::try_from(small_limit).unwrap())
            .map(|sequence| {
                Ok::<_, io::Error>((
                    event_filename(sequence),
                    PathBuf::from(format!("overflow-{sequence}")),
                ))
            })
            .chain(std::iter::once_with(|| -> io::Result<(String, PathBuf)> {
                panic!("collector polled after the first over-limit event")
            }));
        let error = collect_event_paths_bounded(overflow, small_limit).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn explicit_fault_event_survives_restart() {
        let temp = TempLedger::new();
        {
            let mut service = DurableRunService::open(&temp.path).unwrap();
            service
                .handle(command(1, 1, RunCommandKind::Prepare), 1)
                .unwrap();
            service.fail_closed(77, [0x66; 32]).unwrap();
        }
        let reopened = DurableRunService::open(&temp.path).unwrap();
        assert_eq!(reopened.status().state, RunState::Failed);
        assert!(!reopened.status().auto_failed_on_restart);
    }

    #[test]
    fn stopped_unsealed_run_can_fail_closed_and_survives_restart() {
        let temp = TempLedger::new();
        {
            let mut service = DurableRunService::open(&temp.path).unwrap();
            for (id, kind) in [
                (1, RunCommandKind::Prepare),
                (2, RunCommandKind::Arm),
                (3, RunCommandKind::Start),
                (4, RunCommandKind::Stop),
            ] {
                assert!(service.handle(command(id, 1, kind), 1).unwrap().accepted);
            }
            assert_eq!(service.status().state, RunState::Stopped);
            service.fail_closed(78, [0x67; 32]).unwrap();
            assert_eq!(service.status().state, RunState::Failed);
        }
        let reopened = DurableRunService::open(&temp.path).unwrap();
        assert_eq!(reopened.status().state, RunState::Failed);
        assert!(!reopened.status().auto_failed_on_restart);
    }

    #[test]
    fn corrupted_event_and_pending_event_both_fail_closed() {
        let temp = TempLedger::new();
        {
            let mut service = DurableRunService::open(&temp.path).unwrap();
            service
                .handle(command(1, 1, RunCommandKind::Prepare), 1)
                .unwrap();
        }
        let path = temp.path.join(event_filename(0));
        let mut bytes = fs::read(&path).unwrap();
        bytes[FRAME_HEADER_LEN + 5] ^= 0x80;
        fs::write(&path, bytes).unwrap();
        assert!(DurableRunService::open(&temp.path).is_err());

        let pending = TempLedger::new();
        fs::write(
            pending
                .path
                .join(".pending-event-00000000000000000000-1.bin"),
            b"x",
        )
        .unwrap();
        assert!(DurableRunService::open(&pending.path).is_err());
    }

    #[test]
    fn zero_terminal_evidence_is_rejected_without_state_release() {
        let temp = TempLedger::new();
        let mut service = DurableRunService::open(&temp.path).unwrap();
        for (id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
            (4, RunCommandKind::Stop),
        ] {
            service.handle(command(id, 1, kind), 1).unwrap();
        }
        assert!(service.mark_journal_sealed([0; 32]).is_err());
        assert_eq!(service.status().state, RunState::Stopped);
    }
}
