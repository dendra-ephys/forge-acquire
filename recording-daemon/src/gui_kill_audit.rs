//! Owner-exclusive, qualification-only GUI-loss audit.  This JSONL format is
//! local integrity evidence, not a signature, attestation, SCM, or product
//! logging protocol.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::gui_kill_control::GuiKillContainmentEvidenceV2;
use forge_protocol_v1::{crc32c, sha256};
use serde::{Deserialize, Serialize};

pub(crate) const GUI_KILL_AUDIT_EVENT_SCHEMA: &str = "forge.gui-kill-audit-event.v3";
pub(crate) const GUI_KILL_AUDIT_EVENT_V2_SCHEMA: &str = "forge.gui-kill-audit-event.v2";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuiKillAuditIdentityV2 {
    pub run_id_hex: String,
    pub supervisor_pid: u32,
    pub supervisor_creation_time_100ns: u64,
    pub owner_pid: u32,
    pub owner_creation_time_100ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiKillAuditKindV2 {
    AuditStarted,
    OwnerReady,
    LifecyclePrepare,
    LifecycleArm,
    LifecycleStart,
    BaselineSnapshot,
    GuiSpawned,
    StageConfirmed,
    KillRequested,
    ReapProven,
    PostKillSnapshot,
    SupervisorStop,
    OwnerSealed,
    OwnerExitArmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiKillAuditAttemptModeV2 {
    AfterAck,
    Inflight,
}

/// The supervisor reports this typed value from its retained Job/process
/// handles. The owner independently checks the primary process exit code, but
/// does not hold a duplicate Job handle and therefore does not independently
/// observe Job emptiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiKillAuditKillMethodV2 {
    JobObjectTermination,
    /// Kept parseable solely so the verifier can explicitly reject a record
    /// that claims a less-contained termination path.
    DirectTerminateProcess,
}

/// The only positive wait result.  Timeout/failed/still-active are errors in
/// the owner and therefore never become a `reap_proven` audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiKillAuditWaitResultV2 {
    SignaledReaped,
    TimedOut,
    Failed,
    StillActive,
}

/// Caller-supplied event context.  Identity and sequence are owner-owned and
/// are populated by `GuiKillAuditWriterV2`, never trusted from this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuiKillAuditEventDataV2 {
    pub kind: GuiKillAuditKindV2,
    pub attempt: Option<u32>,
    pub mode: Option<GuiKillAuditAttemptModeV2>,
    pub gui_pid: Option<u32>,
    pub gui_creation_time_100ns: Option<u64>,
    pub request_id: Option<u64>,
    pub barrier_request_id: Option<u64>,
    pub post_kill_request_id: Option<u64>,
    pub state_wire: Option<u8>,
    pub active_epoch: Option<u64>,
    pub committed_record_count: Option<u64>,
    pub durable_record_count: Option<u64>,
    pub exit_code: Option<u32>,
    pub kill_method: Option<GuiKillAuditKillMethodV2>,
    pub wait_deadline_ms: Option<u32>,
    pub wait_elapsed_ms: Option<u32>,
    pub wait_result: Option<GuiKillAuditWaitResultV2>,
    pub containment: Option<GuiKillContainmentEvidenceV2>,
    pub job_active_processes_after_wait: Option<u32>,
    pub job_empty_proven: Option<bool>,
}

impl GuiKillAuditEventDataV2 {
    pub(crate) fn static_event(kind: GuiKillAuditKindV2) -> Self {
        Self {
            kind,
            attempt: None,
            mode: None,
            gui_pid: None,
            gui_creation_time_100ns: None,
            request_id: None,
            barrier_request_id: None,
            post_kill_request_id: None,
            state_wire: None,
            active_epoch: None,
            committed_record_count: None,
            durable_record_count: None,
            exit_code: None,
            kill_method: None,
            wait_deadline_ms: None,
            wait_elapsed_ms: None,
            wait_result: None,
            containment: None,
            job_active_processes_after_wait: None,
            job_empty_proven: None,
        }
    }
}

/// Fixed-order bytes covered by CRC32C and the SHA-256 chain. Do not add serde
/// defaults: absence must remain visible and subject to kind-specific checks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuiKillAuditCoreV2 {
    schema: String,
    event_sequence: u64,
    run_id_hex: String,
    supervisor_pid: u32,
    supervisor_creation_time_100ns: u64,
    owner_pid: u32,
    owner_creation_time_100ns: u64,
    kind: GuiKillAuditKindV2,
    attempt: Option<u32>,
    mode: Option<GuiKillAuditAttemptModeV2>,
    gui_pid: Option<u32>,
    gui_creation_time_100ns: Option<u64>,
    request_id: Option<u64>,
    barrier_request_id: Option<u64>,
    post_kill_request_id: Option<u64>,
    state_wire: Option<u8>,
    active_epoch: Option<u64>,
    committed_record_count: Option<u64>,
    durable_record_count: Option<u64>,
    exit_code: Option<u32>,
    kill_method: Option<GuiKillAuditKillMethodV2>,
    wait_deadline_ms: Option<u32>,
    wait_elapsed_ms: Option<u32>,
    wait_result: Option<GuiKillAuditWaitResultV2>,
    containment: Option<GuiKillContainmentEvidenceV2>,
    job_active_processes_after_wait: Option<u32>,
    job_empty_proven: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuiKillAuditLineV2 {
    #[serde(flatten)]
    core: GuiKillAuditCoreV2,
    previous_event_hash_hex: String,
    crc32c: u32,
    event_hash_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuiKillAuditEvidenceV2 {
    pub path: String,
    pub sha256_hex: String,
    pub bytes: u64,
    pub event_count: u64,
    pub first_event_hash_hex: String,
    pub last_event_hash_hex: String,
    pub durable_event_sequence: u64,
}

#[allow(dead_code)]
pub(crate) type GuiKillAuditIdentityV3 = GuiKillAuditIdentityV2;
#[allow(dead_code)]
pub(crate) type GuiKillAuditKindV3 = GuiKillAuditKindV2;
#[allow(dead_code)]
pub(crate) type GuiKillAuditEventDataV3 = GuiKillAuditEventDataV2;
#[allow(dead_code)]
pub(crate) type GuiKillAuditEvidenceV3 = GuiKillAuditEvidenceV2;

pub(crate) struct GuiKillAuditWriterV2 {
    path: PathBuf,
    file: File,
    identity: GuiKillAuditIdentityV2,
    next_sequence: u64,
    previous_hash: [u8; 32],
    first_hash_hex: Option<String>,
    finished: bool,
    poisoned: bool,
}

impl GuiKillAuditWriterV2 {
    pub(crate) fn create(path: &Path, identity: GuiKillAuditIdentityV2) -> io::Result<Self> {
        validate_identity(&identity)?;
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity,
            next_sequence: 0,
            previous_hash: [0; 32],
            first_hash_hex: None,
            finished: false,
            poisoned: false,
        })
    }

    pub(crate) fn append(&mut self, data: GuiKillAuditEventDataV2) -> io::Result<u64> {
        if self.finished || self.poisoned || data.kind == GuiKillAuditKindV2::OwnerExitArmed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit writer is closed/poisoned or owner_exit_armed was supplied directly",
            ));
        }
        let sequence = self.next_sequence;
        let core = core_from_data(&self.identity, sequence, data);
        if let Err(error) = validate_core_local(&core) {
            self.poisoned = true;
            return Err(error);
        }
        if let Err(error) = self.append_core(core) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(sequence)
    }

    /// Formal evidence exists only after this method appends and syncs the
    /// terminal owner-exit event. A dropped/incomplete writer has no valid tail.
    pub(crate) fn finish(mut self) -> io::Result<GuiKillAuditEvidenceV2> {
        if self.finished || self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit writer cannot finish after closure or poison",
            ));
        }
        let sequence = self.next_sequence;
        let terminal = core_from_data(
            &self.identity,
            sequence,
            GuiKillAuditEventDataV2::static_event(GuiKillAuditKindV2::OwnerExitArmed),
        );
        if let Err(error) = self.append_core(terminal) {
            self.poisoned = true;
            return Err(error);
        }
        self.file.flush()?;
        self.file.sync_all()?;
        self.finished = true;
        let bytes = fs::metadata(&self.path)?.len();
        let event_count = self.next_sequence;
        Ok(GuiKillAuditEvidenceV2 {
            path: self.path.to_string_lossy().into_owned(),
            sha256_hex: hex(&sha256(&fs::read(&self.path)?)),
            bytes,
            event_count,
            first_event_hash_hex: self.first_hash_hex.unwrap_or_default(),
            last_event_hash_hex: hex(&self.previous_hash),
            durable_event_sequence: event_count
                .checked_sub(1)
                .ok_or_else(|| io::Error::other("audit has no terminal event"))?,
        })
    }

    fn append_core(&mut self, core: GuiKillAuditCoreV2) -> io::Result<()> {
        let core_bytes = canonical_core_bytes(&core)?;
        let crc = crc32c(&core_bytes);
        let event_hash = hash_event(&self.previous_hash, &core_bytes, crc);
        let line = GuiKillAuditLineV2 {
            core,
            previous_event_hash_hex: hex(&self.previous_hash),
            crc32c: crc,
            event_hash_hex: hex(&event_hash),
        };
        let bytes = serde_json::to_vec(&line).map_err(invalid_data)?;
        self.file.write_all(&bytes)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.file.sync_data()?;
        if self.first_hash_hex.is_none() {
            self.first_hash_hex = Some(line.event_hash_hex.clone());
        }
        self.previous_hash = event_hash;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("audit event sequence overflow"))?;
        Ok(())
    }
}

pub(crate) fn verify_gui_kill_audit_v3(
    path: &Path,
    identity: &GuiKillAuditIdentityV2,
    expected_attempts: u32,
    expected_recording_wire: u8,
) -> io::Result<GuiKillAuditEvidenceV2> {
    validate_identity(identity)?;
    let bytes = fs::read(path)?;
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "audit must be nonempty and newline terminated",
        ));
    }
    let mut lines = Vec::new();
    for raw in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if raw.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audit contains empty line",
            ));
        }
        let raw_value: serde_json::Value = serde_json::from_slice(raw).map_err(invalid_data)?;
        match raw_value.get("schema").and_then(serde_json::Value::as_str) {
            Some(GUI_KILL_AUDIT_EVENT_V2_SCHEMA) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "historical audit v2 is incomplete and explicitly rejected",
                ))
            }
            Some(GUI_KILL_AUDIT_EVENT_SCHEMA) => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown audit schema",
                ))
            }
        }
        let line = serde_json::from_value::<GuiKillAuditLineV2>(raw_value).map_err(invalid_data)?;
        if serde_json::to_vec(&line).map_err(invalid_data)? != raw {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audit line is not in canonical struct encoding",
            ));
        }
        lines.push(line);
    }
    let expected_count = u64::from(expected_attempts)
        .checked_mul(5)
        .and_then(|count| count.checked_add(9))
        .ok_or_else(|| io::Error::other("audit expected count overflow"))?;
    if lines.len() as u64 != expected_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "audit does not have the required prefix/attempt/tail count",
        ));
    }
    let mut previous_hash = [0_u8; 32];
    let mut baseline_epoch = None;
    let mut previous_committed = None;
    let mut previous_durable = None;
    let mut attempt_contexts = std::collections::BTreeSet::new();
    let mut used_request_ids = std::collections::BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        let core = &line.core;
        if core.event_sequence != index as u64
            || !core_matches_identity(core, identity)
            || line.previous_event_hash_hex != hex(&previous_hash)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audit sequence, identity, or previous hash drifted",
            ));
        }
        validate_core_local(core)?;
        let core_bytes = canonical_core_bytes(core)?;
        if line.crc32c != crc32c(&core_bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audit CRC32C mismatch",
            ));
        }
        let event_hash = hash_event(&previous_hash, &core_bytes, line.crc32c);
        if line.event_hash_hex != hex(&event_hash) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audit hash-chain mismatch",
            ));
        }
        verify_event_position(
            core,
            index,
            expected_attempts,
            expected_recording_wire,
            &mut baseline_epoch,
            &mut previous_committed,
            &mut previous_durable,
            &mut attempt_contexts,
            &mut used_request_ids,
        )?;
        previous_hash = event_hash;
    }
    Ok(GuiKillAuditEvidenceV2 {
        path: path.to_string_lossy().into_owned(),
        sha256_hex: hex(&sha256(&bytes)),
        bytes: bytes.len() as u64,
        event_count: expected_count,
        first_event_hash_hex: lines
            .first()
            .map(|line| line.event_hash_hex.clone())
            .unwrap_or_default(),
        last_event_hash_hex: hex(&previous_hash),
        durable_event_sequence: expected_count - 1,
    })
}

#[cfg(test)]
fn verify_gui_kill_audit_v2(
    path: &Path,
    identity: &GuiKillAuditIdentityV2,
    attempts: u32,
    expected_recording_wire: u8,
) -> io::Result<GuiKillAuditEvidenceV2> {
    verify_gui_kill_audit_v3(path, identity, attempts, expected_recording_wire)
}

#[allow(clippy::too_many_arguments)] // explicit verifier state keeps every replay invariant visible
fn verify_event_position(
    core: &GuiKillAuditCoreV2,
    index: usize,
    attempts: u32,
    expected_recording_wire: u8,
    baseline_epoch: &mut Option<u64>,
    previous_committed: &mut Option<u64>,
    previous_durable: &mut Option<u64>,
    attempt_contexts: &mut std::collections::BTreeSet<(u32, u64, Option<u64>, u64)>,
    used_request_ids: &mut std::collections::BTreeSet<u64>,
) -> io::Result<()> {
    let prefix = [
        GuiKillAuditKindV2::AuditStarted,
        GuiKillAuditKindV2::OwnerReady,
        GuiKillAuditKindV2::LifecyclePrepare,
        GuiKillAuditKindV2::LifecycleArm,
        GuiKillAuditKindV2::LifecycleStart,
        GuiKillAuditKindV2::BaselineSnapshot,
    ];
    if index < prefix.len() {
        if core.kind != prefix[index] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audit prefix reordered",
            ));
        }
        if matches!(
            core.kind,
            GuiKillAuditKindV2::LifecyclePrepare
                | GuiKillAuditKindV2::LifecycleArm
                | GuiKillAuditKindV2::LifecycleStart
                | GuiKillAuditKindV2::BaselineSnapshot
        ) && !used_request_ids.insert(core.request_id.unwrap_or(0))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audit lifecycle/baseline request ID reused",
            ));
        }
        if core.kind == GuiKillAuditKindV2::BaselineSnapshot {
            verify_snapshot(
                core,
                None,
                expected_recording_wire,
                baseline_epoch,
                previous_committed,
                previous_durable,
            )?;
        }
        return Ok(());
    }
    let attempt_offset = index - prefix.len();
    let attempt_events = attempts as usize * 5;
    if attempt_offset < attempt_events {
        let attempt = (attempt_offset / 5) as u32;
        let phase = attempt_offset % 5;
        let expected = [
            GuiKillAuditKindV2::GuiSpawned,
            GuiKillAuditKindV2::StageConfirmed,
            GuiKillAuditKindV2::KillRequested,
            GuiKillAuditKindV2::ReapProven,
            GuiKillAuditKindV2::PostKillSnapshot,
        ][phase];
        if core.kind != expected || core.attempt != Some(attempt) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audit attempt order drifted",
            ));
        }
        let (request, barrier, post) = attempt_context(core)?;
        let context = (attempt, request, barrier, post);
        if phase == 0 {
            if !attempt_contexts.insert(context)
                || !used_request_ids.insert(request)
                || barrier.is_some_and(|value| !used_request_ids.insert(value))
                || !used_request_ids.insert(post)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "audit attempt request IDs reused",
                ));
            }
        } else if !attempt_contexts.contains(&context) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audit attempt context changed after spawn",
            ));
        }
        if phase == 4 {
            verify_snapshot(
                core,
                Some((request, barrier, post)),
                expected_recording_wire,
                baseline_epoch,
                previous_committed,
                previous_durable,
            )?;
        }
        return Ok(());
    }
    let tail = [
        GuiKillAuditKindV2::SupervisorStop,
        GuiKillAuditKindV2::OwnerSealed,
        GuiKillAuditKindV2::OwnerExitArmed,
    ];
    let tail_index = attempt_offset - attempt_events;
    if tail_index >= tail.len() || core.kind != tail[tail_index] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "audit tail reordered",
        ));
    }
    if core.kind == GuiKillAuditKindV2::SupervisorStop {
        let request_id = core.request_id.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "supervisor Stop lacks request ID",
            )
        })?;
        if !used_request_ids.insert(request_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "supervisor Stop request ID was reused",
            ));
        }
    }
    Ok(())
}

fn verify_snapshot(
    core: &GuiKillAuditCoreV2,
    _attempt: Option<(u64, Option<u64>, u64)>,
    expected_recording_wire: u8,
    baseline_epoch: &mut Option<u64>,
    previous_committed: &mut Option<u64>,
    previous_durable: &mut Option<u64>,
) -> io::Result<()> {
    let epoch = core
        .active_epoch
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "snapshot lacks epoch"))?;
    let committed = core.committed_record_count.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot lacks committed watermark",
        )
    })?;
    let durable = core.durable_record_count.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot lacks durable watermark",
        )
    })?;
    if epoch == 0
        || core.state_wire != Some(expected_recording_wire)
        || baseline_epoch.is_some_and(|value| value != epoch)
        || previous_committed.is_some_and(|value| committed < value)
        || previous_durable.is_some_and(|value| durable < value)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot state/epoch/watermark is invalid",
        ));
    }
    *baseline_epoch = Some(epoch);
    *previous_committed = Some(committed);
    *previous_durable = Some(durable);
    Ok(())
}

fn attempt_context(core: &GuiKillAuditCoreV2) -> io::Result<(u64, Option<u64>, u64)> {
    let request = core
        .request_id
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "attempt lacks request ID"))?;
    let post = core.post_kill_request_id.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "attempt lacks post-kill request ID",
        )
    })?;
    let mode = core
        .mode
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "attempt lacks mode"))?;
    let barrier = core.barrier_request_id;
    if core.gui_pid.is_none_or(|value| value == 0)
        || core.gui_creation_time_100ns.is_none_or(|value| value == 0)
        || request == 0
        || post <= request
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "attempt common context is invalid",
        ));
    }
    match (mode, barrier) {
        (GuiKillAuditAttemptModeV2::AfterAck, Some(value))
            if request.checked_add(1) == Some(value) && value.checked_add(1) == Some(post) => {}
        (GuiKillAuditAttemptModeV2::Inflight, None) if request.checked_add(2) == Some(post) => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "attempt mode/barrier shape is invalid",
            ))
        }
    }
    Ok((request, barrier, post))
}

fn validate_core_local(core: &GuiKillAuditCoreV2) -> io::Result<()> {
    if core.schema != GUI_KILL_AUDIT_EVENT_SCHEMA || !is_hex_32(&core.run_id_hex) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "audit core schema/run identity invalid",
        ));
    }
    let static_kind = matches!(
        core.kind,
        GuiKillAuditKindV2::AuditStarted
            | GuiKillAuditKindV2::OwnerReady
            | GuiKillAuditKindV2::OwnerSealed
            | GuiKillAuditKindV2::OwnerExitArmed
    );
    if static_kind && has_context(core) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "static audit event carries context",
        ));
    }
    if matches!(
        core.kind,
        GuiKillAuditKindV2::LifecyclePrepare
            | GuiKillAuditKindV2::LifecycleArm
            | GuiKillAuditKindV2::LifecycleStart
    ) && (core.request_id.is_none_or(|value| value == 0) || has_context_except_request(core))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "lifecycle audit context invalid",
        ));
    }
    if core.kind == GuiKillAuditKindV2::SupervisorStop
        && (core.request_id.is_none_or(|value| value == 0) || has_context_except_request(core))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "supervisor Stop audit context invalid",
        ));
    }
    if core.kind == GuiKillAuditKindV2::BaselineSnapshot
        && (core.request_id.is_none_or(|value| value == 0)
            || core.state_wire.is_none()
            || core.active_epoch.is_none()
            || core.committed_record_count.is_none()
            || core.durable_record_count.is_none()
            || core.attempt.is_some()
            || core.mode.is_some()
            || core.gui_pid.is_some()
            || core.gui_creation_time_100ns.is_some()
            || core.barrier_request_id.is_some()
            || core.post_kill_request_id.is_some()
            || core.exit_code.is_some()
            || core.kill_method.is_some()
            || core.wait_deadline_ms.is_some()
            || core.wait_elapsed_ms.is_some()
            || core.wait_result.is_some()
            || core.containment.is_some()
            || core.job_active_processes_after_wait.is_some()
            || core.job_empty_proven.is_some())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "baseline snapshot context invalid",
        ));
    }
    if matches!(
        core.kind,
        GuiKillAuditKindV2::GuiSpawned
            | GuiKillAuditKindV2::StageConfirmed
            | GuiKillAuditKindV2::KillRequested
            | GuiKillAuditKindV2::ReapProven
            | GuiKillAuditKindV2::PostKillSnapshot
    ) {
        attempt_context(core)?;
        let is_snapshot = core.kind == GuiKillAuditKindV2::PostKillSnapshot;
        let has_any_snapshot = core.state_wire.is_some()
            || core.active_epoch.is_some()
            || core.committed_record_count.is_some()
            || core.durable_record_count.is_some();
        let has_complete_snapshot = core.state_wire.is_some()
            && core.active_epoch.is_some()
            && core.committed_record_count.is_some()
            && core.durable_record_count.is_some();
        if (is_snapshot && !has_complete_snapshot) || (!is_snapshot && has_any_snapshot) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "attempt snapshot context invalid",
            ));
        }
        let is_reap = core.kind == GuiKillAuditKindV2::ReapProven;
        let is_spawn = core.kind == GuiKillAuditKindV2::GuiSpawned;
        let valid_spawn_containment = core
            .containment
            .is_some_and(|value| value.validate().is_ok());
        if (is_spawn && !valid_spawn_containment) || (!is_spawn && core.containment.is_some()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "supervisor containment facts are absent, invalid, or attached to the wrong event",
            ));
        }
        if (is_reap && !has_complete_reap_evidence(core))
            || (!is_reap && has_any_reap_evidence(core))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reap evidence is absent, malformed, or attached to the wrong event",
            ));
        }
    }
    Ok(())
}

fn has_context(core: &GuiKillAuditCoreV2) -> bool {
    core.attempt.is_some()
        || core.mode.is_some()
        || core.gui_pid.is_some()
        || core.gui_creation_time_100ns.is_some()
        || core.request_id.is_some()
        || core.barrier_request_id.is_some()
        || core.post_kill_request_id.is_some()
        || core.state_wire.is_some()
        || core.active_epoch.is_some()
        || core.committed_record_count.is_some()
        || core.durable_record_count.is_some()
        || core.exit_code.is_some()
        || core.kill_method.is_some()
        || core.wait_deadline_ms.is_some()
        || core.wait_elapsed_ms.is_some()
        || core.wait_result.is_some()
        || core.containment.is_some()
        || core.job_active_processes_after_wait.is_some()
        || core.job_empty_proven.is_some()
}

fn has_context_except_request(core: &GuiKillAuditCoreV2) -> bool {
    core.attempt.is_some()
        || core.mode.is_some()
        || core.gui_pid.is_some()
        || core.gui_creation_time_100ns.is_some()
        || core.barrier_request_id.is_some()
        || core.post_kill_request_id.is_some()
        || core.state_wire.is_some()
        || core.active_epoch.is_some()
        || core.committed_record_count.is_some()
        || core.durable_record_count.is_some()
        || core.exit_code.is_some()
        || core.kill_method.is_some()
        || core.wait_deadline_ms.is_some()
        || core.wait_elapsed_ms.is_some()
        || core.wait_result.is_some()
        || core.containment.is_some()
        || core.job_active_processes_after_wait.is_some()
        || core.job_empty_proven.is_some()
}

fn has_complete_reap_evidence(core: &GuiKillAuditCoreV2) -> bool {
    let Some(exit_code) = core.exit_code else {
        return false;
    };
    let Some(kill_method) = core.kill_method else {
        return false;
    };
    let Some(deadline_ms) = core.wait_deadline_ms else {
        return false;
    };
    let Some(elapsed_ms) = core.wait_elapsed_ms else {
        return false;
    };
    let Some(wait_result) = core.wait_result else {
        return false;
    };
    let Some(active) = core.job_active_processes_after_wait else {
        return false;
    };
    let Some(job_empty) = core.job_empty_proven else {
        return false;
    };
    exit_code != 259
        && deadline_ms != 0
        && elapsed_ms <= deadline_ms
        && kill_method == GuiKillAuditKillMethodV2::JobObjectTermination
        && wait_result == GuiKillAuditWaitResultV2::SignaledReaped
        && active == 0
        && job_empty
}

fn has_any_reap_evidence(core: &GuiKillAuditCoreV2) -> bool {
    core.exit_code.is_some()
        || core.kill_method.is_some()
        || core.wait_deadline_ms.is_some()
        || core.wait_elapsed_ms.is_some()
        || core.wait_result.is_some()
        || core.job_active_processes_after_wait.is_some()
        || core.job_empty_proven.is_some()
}

fn core_from_data(
    identity: &GuiKillAuditIdentityV2,
    event_sequence: u64,
    data: GuiKillAuditEventDataV2,
) -> GuiKillAuditCoreV2 {
    GuiKillAuditCoreV2 {
        schema: GUI_KILL_AUDIT_EVENT_SCHEMA.to_owned(),
        event_sequence,
        run_id_hex: identity.run_id_hex.clone(),
        supervisor_pid: identity.supervisor_pid,
        supervisor_creation_time_100ns: identity.supervisor_creation_time_100ns,
        owner_pid: identity.owner_pid,
        owner_creation_time_100ns: identity.owner_creation_time_100ns,
        kind: data.kind,
        attempt: data.attempt,
        mode: data.mode,
        gui_pid: data.gui_pid,
        gui_creation_time_100ns: data.gui_creation_time_100ns,
        request_id: data.request_id,
        barrier_request_id: data.barrier_request_id,
        post_kill_request_id: data.post_kill_request_id,
        state_wire: data.state_wire,
        active_epoch: data.active_epoch,
        committed_record_count: data.committed_record_count,
        durable_record_count: data.durable_record_count,
        exit_code: data.exit_code,
        kill_method: data.kill_method,
        wait_deadline_ms: data.wait_deadline_ms,
        wait_elapsed_ms: data.wait_elapsed_ms,
        wait_result: data.wait_result,
        containment: data.containment,
        job_active_processes_after_wait: data.job_active_processes_after_wait,
        job_empty_proven: data.job_empty_proven,
    }
}

fn core_matches_identity(core: &GuiKillAuditCoreV2, identity: &GuiKillAuditIdentityV2) -> bool {
    core.run_id_hex == identity.run_id_hex
        && core.supervisor_pid == identity.supervisor_pid
        && core.supervisor_creation_time_100ns == identity.supervisor_creation_time_100ns
        && core.owner_pid == identity.owner_pid
        && core.owner_creation_time_100ns == identity.owner_creation_time_100ns
}
fn validate_identity(identity: &GuiKillAuditIdentityV2) -> io::Result<()> {
    if !is_hex_32(&identity.run_id_hex)
        || identity.supervisor_pid == 0
        || identity.supervisor_creation_time_100ns == 0
        || identity.owner_pid == 0
        || identity.owner_creation_time_100ns == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "audit identity invalid",
        ));
    }
    Ok(())
}
fn canonical_core_bytes(core: &GuiKillAuditCoreV2) -> io::Result<Vec<u8>> {
    serde_json::to_vec(core).map_err(invalid_data)
}
fn hash_event(previous: &[u8; 32], core: &[u8], crc: u32) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(32 + core.len() + 4);
    bytes.extend_from_slice(previous);
    bytes.extend_from_slice(core);
    bytes.extend_from_slice(&crc.to_le_bytes());
    sha256(&bytes)
}
fn is_hex_32(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
fn invalid_data(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    fn path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "forge-gui-audit-{label}-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn identity() -> GuiKillAuditIdentityV2 {
        GuiKillAuditIdentityV2 {
            run_id_hex: "a".repeat(32),
            supervisor_pid: 10,
            supervisor_creation_time_100ns: 11,
            owner_pid: 12,
            owner_creation_time_100ns: 13,
        }
    }
    fn attempt(
        kind: GuiKillAuditKindV2,
        index: u32,
        mode: GuiKillAuditAttemptModeV2,
        state: bool,
        committed: u64,
    ) -> GuiKillAuditEventDataV2 {
        let request = 100 + u64::from(index) * 3;
        let reap = kind == GuiKillAuditKindV2::ReapProven;
        GuiKillAuditEventDataV2 {
            kind,
            attempt: Some(index),
            mode: Some(mode),
            gui_pid: Some(20 + index),
            gui_creation_time_100ns: Some(30 + u64::from(index)),
            request_id: Some(request),
            barrier_request_id: (mode == GuiKillAuditAttemptModeV2::AfterAck)
                .then_some(request + 1),
            post_kill_request_id: Some(request + 2),
            state_wire: state.then_some(3),
            active_epoch: state.then_some(1),
            committed_record_count: state.then_some(committed),
            durable_record_count: state.then_some(committed),
            exit_code: reap.then_some(42),
            kill_method: reap.then_some(GuiKillAuditKillMethodV2::JobObjectTermination),
            wait_deadline_ms: reap.then_some(250),
            wait_elapsed_ms: reap.then_some(7),
            wait_result: reap.then_some(GuiKillAuditWaitResultV2::SignaledReaped),
            containment: (kind == GuiKillAuditKindV2::GuiSpawned).then_some(
                GuiKillContainmentEvidenceV2 {
                    created_suspended: true,
                    kill_on_job_close_configured: true,
                    job_assigned_before_resume: true,
                    executable_rehashed_before_resume: true,
                },
            ),
            job_active_processes_after_wait: reap.then_some(0),
            job_empty_proven: reap.then_some(true),
        }
    }
    fn write_valid(path: &Path) -> GuiKillAuditEvidenceV2 {
        let mut writer = GuiKillAuditWriterV2::create(path, identity()).unwrap();
        for kind in [
            GuiKillAuditKindV2::AuditStarted,
            GuiKillAuditKindV2::OwnerReady,
        ] {
            writer
                .append(GuiKillAuditEventDataV2::static_event(kind))
                .unwrap();
        }
        for (kind, request) in [
            (GuiKillAuditKindV2::LifecyclePrepare, 1),
            (GuiKillAuditKindV2::LifecycleArm, 2),
            (GuiKillAuditKindV2::LifecycleStart, 3),
        ] {
            let mut data = GuiKillAuditEventDataV2::static_event(kind);
            data.request_id = Some(request);
            writer.append(data).unwrap();
        }
        let mut baseline =
            GuiKillAuditEventDataV2::static_event(GuiKillAuditKindV2::BaselineSnapshot);
        baseline.request_id = Some(4);
        baseline.state_wire = Some(3);
        baseline.active_epoch = Some(1);
        baseline.committed_record_count = Some(5);
        baseline.durable_record_count = Some(5);
        writer.append(baseline).unwrap();
        for (index, mode) in [
            (0, GuiKillAuditAttemptModeV2::AfterAck),
            (1, GuiKillAuditAttemptModeV2::Inflight),
        ] {
            for kind in [
                GuiKillAuditKindV2::GuiSpawned,
                GuiKillAuditKindV2::StageConfirmed,
                GuiKillAuditKindV2::KillRequested,
                GuiKillAuditKindV2::ReapProven,
            ] {
                writer.append(attempt(kind, index, mode, false, 0)).unwrap();
            }
            writer
                .append(attempt(
                    GuiKillAuditKindV2::PostKillSnapshot,
                    index,
                    mode,
                    true,
                    6 + u64::from(index),
                ))
                .unwrap();
        }
        let mut stop = GuiKillAuditEventDataV2::static_event(GuiKillAuditKindV2::SupervisorStop);
        stop.request_id = Some(1_000);
        writer.append(stop).unwrap();
        writer
            .append(GuiKillAuditEventDataV2::static_event(
                GuiKillAuditKindV2::OwnerSealed,
            ))
            .unwrap();
        writer.finish().unwrap()
    }

    /// Rewrite every integrity field after a semantic mutation.  These cases
    /// prove the verifier is enforcing the owner evidence itself, not merely
    /// detecting an unchanged CRC/hash-chain mismatch.
    fn rechain(path: &Path, mutate: impl FnOnce(&mut Vec<GuiKillAuditLineV2>)) {
        let mut lines = fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<GuiKillAuditLineV2>(line).unwrap())
            .collect::<Vec<_>>();
        mutate(&mut lines);
        let mut previous = [0_u8; 32];
        for line in &mut lines {
            line.previous_event_hash_hex = hex(&previous);
            let core = canonical_core_bytes(&line.core).unwrap();
            line.crc32c = crc32c(&core);
            previous = hash_event(&previous, &core, line.crc32c);
            line.event_hash_hex = hex(&previous);
        }
        let output = lines
            .iter()
            .map(|line| serde_json::to_string(line).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(path, format!("{output}\n")).unwrap();
    }
    #[test]
    fn two_attempts_after_ack_and_inflight_verify() {
        let p = path("valid");
        let evidence = write_valid(&p);
        assert_eq!(
            verify_gui_kill_audit_v2(&p, &identity(), 2, 3).unwrap(),
            evidence
        );
        let _ = fs::remove_file(p);
    }
    #[test]
    fn truncation_and_integrity_tamper_reject() {
        for cut in [1_usize, 20] {
            let p = path("cut");
            write_valid(&p);
            let mut bytes = fs::read(&p).unwrap();
            bytes.truncate(bytes.len().saturating_sub(cut));
            fs::write(&p, bytes).unwrap();
            assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
            let _ = fs::remove_file(p);
        }
        let p = path("hash");
        write_valid(&p);
        let mut bytes = fs::read(&p).unwrap();
        bytes[10] ^= 1;
        fs::write(&p, bytes).unwrap();
        assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
        let _ = fs::remove_file(p);
        let p = path("middle-cut");
        write_valid(&p);
        let mut bytes = fs::read(&p).unwrap();
        let first_line = bytes.iter().position(|byte| *byte == b'\n').unwrap();
        bytes.drain(first_line + 4..first_line + 7);
        fs::write(&p, bytes).unwrap();
        assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
        let _ = fs::remove_file(p);
    }
    #[test]
    fn identity_attempt_and_line_order_tamper_reject() {
        let p = path("mutate");
        write_valid(&p);
        let text = fs::read_to_string(&p).unwrap();
        let changed = text.replacen("\"supervisor_pid\":10", "\"supervisor_pid\":99", 1);
        fs::write(&p, changed).unwrap();
        assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
        let _ = fs::remove_file(p);
        for (label, from, to) in [
            ("run", "\"run_id_hex\":\"aaaa", "\"run_id_hex\":\"bbbb"),
            ("attempt", "\"attempt\":0", "\"attempt\":9"),
            ("request", "\"request_id\":100", "\"request_id\":999"),
        ] {
            let p = path(label);
            write_valid(&p);
            let text = fs::read_to_string(&p).unwrap();
            fs::write(&p, text.replacen(from, to, 1)).unwrap();
            assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
            let _ = fs::remove_file(p);
        }
        let p = path("reorder");
        write_valid(&p);
        let mut lines: Vec<_> = fs::read_to_string(&p)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        lines.swap(6, 7);
        fs::write(&p, format!("{}\n", lines.join("\n"))).unwrap();
        assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
        let _ = fs::remove_file(p);
    }
    #[test]
    fn deletion_duplication_and_unfinished_tail_reject() {
        let p = path("delete");
        write_valid(&p);
        let mut lines: Vec<_> = fs::read_to_string(&p)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        lines.remove(7);
        fs::write(&p, format!("{}\n", lines.join("\n"))).unwrap();
        assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
        let _ = fs::remove_file(p);
        let p = path("duplicate");
        write_valid(&p);
        let mut lines: Vec<_> = fs::read_to_string(&p)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        lines.insert(7, lines[7].clone());
        fs::write(&p, format!("{}\n", lines.join("\n"))).unwrap();
        assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
        let _ = fs::remove_file(p);
        let p = path("unfinished");
        let mut writer = GuiKillAuditWriterV2::create(&p, identity()).unwrap();
        writer
            .append(GuiKillAuditEventDataV2::static_event(
                GuiKillAuditKindV2::AuditStarted,
            ))
            .unwrap();
        drop(writer);
        assert!(verify_gui_kill_audit_v2(&p, &identity(), 0, 3).is_err());
        let _ = fs::remove_file(p);
    }

    #[test]
    fn reap_evidence_semantic_tamper_rejects_after_rechain() {
        // Prefix consumes 6 events, so the first attempt's ReapProven event
        // has index 9: spawned, staged, kill-requested, reap-proven.
        for (label, mutate) in [
            (
                "missing-exit",
                Box::new(|lines: &mut Vec<GuiKillAuditLineV2>| {
                    lines[9].core.exit_code = None;
                }) as Box<dyn FnOnce(&mut Vec<GuiKillAuditLineV2>)>,
            ),
            (
                "still-active",
                Box::new(|lines: &mut Vec<GuiKillAuditLineV2>| {
                    lines[9].core.exit_code = Some(259);
                }) as Box<dyn FnOnce(&mut Vec<GuiKillAuditLineV2>)>,
            ),
            (
                "elapsed-over-deadline",
                Box::new(|lines: &mut Vec<GuiKillAuditLineV2>| {
                    lines[9].core.wait_elapsed_ms = Some(251);
                }) as Box<dyn FnOnce(&mut Vec<GuiKillAuditLineV2>)>,
            ),
            (
                "wrong-kill-method",
                Box::new(|lines: &mut Vec<GuiKillAuditLineV2>| {
                    lines[9].core.kill_method =
                        Some(GuiKillAuditKillMethodV2::DirectTerminateProcess);
                }) as Box<dyn FnOnce(&mut Vec<GuiKillAuditLineV2>)>,
            ),
            (
                "wrong-wait-result",
                Box::new(|lines: &mut Vec<GuiKillAuditLineV2>| {
                    lines[9].core.wait_result = Some(GuiKillAuditWaitResultV2::StillActive);
                }) as Box<dyn FnOnce(&mut Vec<GuiKillAuditLineV2>)>,
            ),
            (
                "job-active",
                Box::new(|lines: &mut Vec<GuiKillAuditLineV2>| {
                    lines[9].core.job_active_processes_after_wait = Some(1);
                }) as Box<dyn FnOnce(&mut Vec<GuiKillAuditLineV2>)>,
            ),
            (
                "job-not-empty",
                Box::new(|lines: &mut Vec<GuiKillAuditLineV2>| {
                    lines[9].core.job_empty_proven = Some(false);
                }) as Box<dyn FnOnce(&mut Vec<GuiKillAuditLineV2>)>,
            ),
            (
                "spawn-containment-missing",
                Box::new(|lines: &mut Vec<GuiKillAuditLineV2>| {
                    lines[6].core.containment = Some(GuiKillContainmentEvidenceV2 {
                        created_suspended: false,
                        kill_on_job_close_configured: true,
                        job_assigned_before_resume: true,
                        executable_rehashed_before_resume: true,
                    });
                }) as Box<dyn FnOnce(&mut Vec<GuiKillAuditLineV2>)>,
            ),
        ] {
            let p = path(label);
            write_valid(&p);
            rechain(&p, mutate);
            assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
            let _ = fs::remove_file(p);
        }

        for index in 0..4 {
            let p = path(&format!("spawn-containment-fact-{index}"));
            write_valid(&p);
            rechain(&p, |lines| {
                let evidence = lines[6]
                    .core
                    .containment
                    .as_mut()
                    .expect("valid spawn containment");
                match index {
                    0 => evidence.created_suspended = false,
                    1 => evidence.kill_on_job_close_configured = false,
                    2 => evidence.job_assigned_before_resume = false,
                    3 => evidence.executable_rehashed_before_resume = false,
                    _ => unreachable!(),
                }
            });
            assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
            let _ = fs::remove_file(p);
        }

        let p = path("containment-on-stage");
        write_valid(&p);
        rechain(&p, |lines| {
            lines[7].core.containment = lines[6].core.containment;
        });
        assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
        let _ = fs::remove_file(p);

        let p = path("job-fields-on-baseline");
        write_valid(&p);
        rechain(&p, |lines| {
            lines[5].core.job_active_processes_after_wait = Some(0);
            lines[5].core.job_empty_proven = Some(true);
        });
        assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
        let _ = fs::remove_file(p);

        let p = path("evidence-on-nonreap");
        write_valid(&p);
        rechain(&p, |lines| {
            lines[8].core.exit_code = Some(42);
            lines[8].core.kill_method = Some(GuiKillAuditKillMethodV2::JobObjectTermination);
            lines[8].core.wait_deadline_ms = Some(250);
            lines[8].core.wait_elapsed_ms = Some(7);
            lines[8].core.wait_result = Some(GuiKillAuditWaitResultV2::SignaledReaped);
        });
        assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
        let _ = fs::remove_file(p);

        let p = path("partial-evidence-on-nonreap");
        write_valid(&p);
        rechain(&p, |lines| {
            lines[8].core.exit_code = Some(42);
        });
        assert!(verify_gui_kill_audit_v2(&p, &identity(), 2, 3).is_err());
        let _ = fs::remove_file(p);
    }
}
