//! Fixed-size, owner-written audit for one NWB generation attempt.
//!
//! This is deliberately independent of the worker validation receipt.  The
//! worker cannot create or append this file, and an incomplete file is never
//! promoted to evidence.  The format is binary so there is no JSON ordering or
//! missing-field ambiguity.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use forge_protocol_v1::{crc32c, sha256, Hash32, Id16};
use sha2::{Digest, Sha256};

pub(crate) const AUDIT_SCHEMA: &[u8; 8] = b"FGRNGA01";
pub(crate) const RECEIPT_SCHEMA: &[u8; 8] = b"FGRNGR01";
pub(crate) const AUDIT_VERSION: u16 = 1;
pub(crate) const AUDIT_RECORD_LEN: usize = 512;
pub(crate) const AUDIT_RECEIPT_LEN: usize = 256;
pub(crate) const MAX_AUDIT_EVENTS: u64 = 32;
const DOMAIN: &[u8] = b"forge.nwb-generation-audit.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum NwbGenerationAuditEventKindV1 {
    AuditStarted = 1,
    GenerationReserved = 2,
    LaunchContained = 3,
    WorkerExitObserved = 4,
    ValidationAccepted = 5,
    AttemptFailed = 6,
    AuditSealed = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum NwbGenerationAuditEvidenceSourceV1 {
    SupervisorObserved = 1,
    OwnerIndependent = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum NwbGenerationAuditExitMethodV1 {
    None = 0,
    JobObjectTermination = 1,
    Graceful = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum NwbGenerationAuditWaitResultV1 {
    None = 0,
    SignaledReaped = 1,
    TimedOut = 2,
    Failed = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum NwbGenerationAuditReasonV1 {
    None = 0,
    WorkerLaunchFailed = 1,
    IdentityMismatch = 2,
    NonzeroExit = 3,
    DeadlineExceeded = 4,
    ValidationRejected = 5,
    ContainmentUnqualified = 6,
    ArtifactChanged = 7,
    RecoveryPoisoned = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NwbGenerationProcessIdentityV1 {
    pub pid: u32,
    pub creation_time_100ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NwbGenerationLaunchContainmentV1 {
    pub suspended_created: bool,
    pub job_assigned: bool,
    pub kill_on_job_close: bool,
    pub executable_reverified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NwbGenerationAuditEventDataV1 {
    pub kind: NwbGenerationAuditEventKindV1,
    pub source: NwbGenerationAuditEvidenceSourceV1,
    pub supervisor: NwbGenerationProcessIdentityV1,
    pub worker: NwbGenerationProcessIdentityV1,
    pub containment: NwbGenerationLaunchContainmentV1,
    pub exit_method: NwbGenerationAuditExitMethodV1,
    pub wait_result: NwbGenerationAuditWaitResultV1,
    pub exit_code: u32,
    pub deadline_ns: u64,
    pub elapsed_ms: u32,
    pub job_active_processes: u32,
    pub job_empty: bool,
    pub independent_handle_wait: bool,
    pub durable_journal_sequence: u64,
    pub durable_journal_valid_len: u64,
    pub journal_sha256: Hash32,
    pub manifest_sha256: Hash32,
    pub executable_sha256: Hash32,
    pub old_artifact_sha256: Hash32,
    pub old_artifact_size: u64,
    pub reason: NwbGenerationAuditReasonV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NwbGenerationAuditContextV1 {
    pub run_id: Id16,
    pub run_epoch: u64,
    pub generation: u32,
    pub attempt: u32,
    pub supervisor: NwbGenerationProcessIdentityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NwbGenerationAuditEvidenceV1 {
    pub bytes: u64,
    pub sha256: Hash32,
    pub event_count: u64,
    pub last_event_hash: Hash32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NwbGenerationAuditReceiptV1 {
    pub run_id: Id16,
    pub run_epoch: u64,
    pub generation: u32,
    pub attempt: u32,
    pub audit_bytes: u64,
    pub event_count: u64,
    pub audit_sha256: Hash32,
    pub last_event_hash: Hash32,
    pub publication_authorized: bool,
}

pub(crate) struct NwbGenerationAuditWriterV1 {
    path: PathBuf,
    file: File,
    context: NwbGenerationAuditContextV1,
    next_sequence: u64,
    previous_hash: Hash32,
    worker: Option<NwbGenerationProcessIdentityV1>,
    phase: AuditPhaseV1,
    sealed: bool,
    poisoned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditPhaseV1 {
    Empty,
    Started,
    Reserved,
    Contained,
    Exited,
    Accepted,
    Failed,
    Sealed,
}

impl NwbGenerationAuditWriterV1 {
    pub(crate) fn create_new(
        path: &Path,
        context: NwbGenerationAuditContextV1,
    ) -> io::Result<Self> {
        validate_context(&context)?;
        if !path.is_absolute() || path.parent().is_none_or(|p| !p.is_dir()) {
            return Err(invalid(
                "audit path must be absolute with an existing parent",
            ));
        }
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            context,
            next_sequence: 0,
            previous_hash: [0; 32],
            worker: None,
            phase: AuditPhaseV1::Empty,
            sealed: false,
            poisoned: false,
        })
    }

    pub(crate) fn append(&mut self, data: NwbGenerationAuditEventDataV1) -> io::Result<u64> {
        if self.sealed || self.poisoned || self.next_sequence >= MAX_AUDIT_EVENTS {
            return Err(invalid("audit is sealed, poisoned, or full"));
        }
        let result = (|| {
            validate_data(&self.context, self.worker, self.phase, &data)?;
            let next_phase = transition(self.phase, data.kind)?;
            let bytes = encode_event(&self.context, self.next_sequence, self.previous_hash, data)?;
            validate_decoded(data.kind, data.source, &bytes, self.worker)?;
            self.file.write_all(&bytes)?;
            self.file.flush()?;
            self.file.sync_data()?;
            let event_hash = event_hash(
                &self.previous_hash,
                &bytes[..AUDIT_RECORD_LEN - 4],
                le_u32(&bytes, AUDIT_RECORD_LEN - 4)?,
            );
            self.previous_hash = event_hash;
            let seq = self.next_sequence;
            self.next_sequence += 1;
            self.sealed = data.kind == NwbGenerationAuditEventKindV1::AuditSealed;
            self.phase = next_phase;
            if data.kind == NwbGenerationAuditEventKindV1::LaunchContained {
                self.worker = Some(data.worker);
            }
            Ok(seq)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(crate) fn finish(self, receipt_path: &Path) -> io::Result<NwbGenerationAuditEvidenceV1> {
        if self.poisoned || !self.sealed || self.next_sequence == 0 {
            return Err(invalid("audit requires durable AuditSealed tail"));
        }
        self.file.sync_all()?;
        drop(self.file);
        let evidence = verify_nwb_generation_audit(&self.path, &self.context)?;
        if !receipt_path.is_absolute() || receipt_path.parent() != self.path.parent() {
            return Err(invalid(
                "receipt must be absolute and share audit directory",
            ));
        }
        let receipt = NwbGenerationAuditReceiptV1 {
            run_id: self.context.run_id,
            run_epoch: self.context.run_epoch,
            generation: self.context.generation,
            attempt: self.context.attempt,
            audit_bytes: evidence.bytes,
            event_count: evidence.event_count,
            audit_sha256: evidence.sha256,
            last_event_hash: evidence.last_event_hash,
            publication_authorized: false,
        };
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(receipt_path)?;
        let raw = encode_receipt(&receipt)?;
        f.write_all(&raw)?;
        f.flush()?;
        f.sync_all()?;
        drop(f);
        verify_nwb_generation_audit_receipt(&self.path, receipt_path, &self.context)
    }
}

pub(crate) fn verify_nwb_generation_audit(
    path: &Path,
    context: &NwbGenerationAuditContextV1,
) -> io::Result<NwbGenerationAuditEvidenceV1> {
    validate_context(context)?;
    if !path.is_absolute() {
        return Err(invalid("audit path is not absolute"));
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty()
        || bytes.len() % AUDIT_RECORD_LEN != 0
        || bytes.len() / AUDIT_RECORD_LEN > MAX_AUDIT_EVENTS as usize
    {
        return Err(invalid("audit physical length or event limit invalid"));
    }
    let mut previous = [0; 32];
    let mut sealed = false;
    let mut phase = AuditPhaseV1::Empty;
    let mut worker = None;
    for (index, raw) in bytes.chunks_exact(AUDIT_RECORD_LEN).enumerate() {
        let (event, hash) = decode_event(raw, context, worker, phase, index as u64, previous)?;
        if sealed {
            return Err(invalid("data follows AuditSealed"));
        }
        phase = transition(phase, event.kind)?;
        if event.kind == NwbGenerationAuditEventKindV1::LaunchContained {
            worker = Some(event.worker);
        }
        if event.kind == NwbGenerationAuditEventKindV1::AuditSealed {
            sealed = true;
        }
        previous = hash;
    }
    if !sealed {
        return Err(invalid("audit has no sealed tail"));
    }
    Ok(NwbGenerationAuditEvidenceV1 {
        bytes: bytes.len() as u64,
        sha256: sha256(&bytes),
        event_count: (bytes.len() / AUDIT_RECORD_LEN) as u64,
        last_event_hash: previous,
    })
}

pub(crate) fn verify_nwb_generation_audit_receipt(
    path: &Path,
    receipt_path: &Path,
    context: &NwbGenerationAuditContextV1,
) -> io::Result<NwbGenerationAuditEvidenceV1> {
    let evidence = verify_nwb_generation_audit(path, context)?;
    let receipt = decode_receipt(&fs::read(receipt_path)?)?;
    if receipt.run_id != context.run_id
        || receipt.run_epoch != context.run_epoch
        || receipt.generation != context.generation
        || receipt.attempt != context.attempt
        || receipt.publication_authorized
        || receipt.audit_bytes != evidence.bytes
        || receipt.event_count != evidence.event_count
        || receipt.audit_sha256 != evidence.sha256
        || receipt.last_event_hash != evidence.last_event_hash
    {
        return Err(invalid("audit receipt binding mismatch"));
    }
    Ok(evidence)
}

fn encode_event(
    context: &NwbGenerationAuditContextV1,
    sequence: u64,
    previous: Hash32,
    data: NwbGenerationAuditEventDataV1,
) -> io::Result<[u8; AUDIT_RECORD_LEN]> {
    let mut b = [0u8; AUDIT_RECORD_LEN];
    b[0..8].copy_from_slice(AUDIT_SCHEMA);
    put_u16(&mut b, 8, AUDIT_VERSION);
    put_u16(&mut b, 10, AUDIT_RECORD_LEN as u16);
    put_u64(&mut b, 12, sequence);
    b[20] = data.kind as u8;
    b[21] = data.source as u8;
    b[24..40].copy_from_slice(&context.run_id);
    put_u64(&mut b, 40, context.run_epoch);
    put_u32(&mut b, 48, context.generation);
    put_u32(&mut b, 52, context.attempt);
    put_process(&mut b, 56, data.supervisor);
    put_process(&mut b, 68, data.worker);
    b[80] = data.containment.suspended_created as u8;
    b[81] = data.containment.job_assigned as u8;
    b[82] = data.containment.kill_on_job_close as u8;
    b[83] = data.containment.executable_reverified as u8;
    b[84] = data.exit_method as u8;
    b[85] = data.wait_result as u8;
    b[86] = data.job_empty as u8;
    b[87] = data.independent_handle_wait as u8;
    put_u32(&mut b, 88, data.exit_code);
    put_u64(&mut b, 92, data.deadline_ns);
    put_u32(&mut b, 100, data.elapsed_ms);
    put_u32(&mut b, 104, data.job_active_processes);
    put_u64(&mut b, 108, data.durable_journal_sequence);
    put_u64(&mut b, 116, data.durable_journal_valid_len);
    put_hash(&mut b, 124, data.journal_sha256);
    put_hash(&mut b, 156, data.manifest_sha256);
    put_hash(&mut b, 188, data.executable_sha256);
    put_hash(&mut b, 220, data.old_artifact_sha256);
    put_u64(&mut b, 252, data.old_artifact_size);
    b[260] = data.reason as u8;
    b[261] = 0;
    b[264..296].copy_from_slice(&previous);
    let crc = crc32c(&b[..AUDIT_RECORD_LEN - 4]);
    put_u32(&mut b, AUDIT_RECORD_LEN - 4, crc);
    Ok(b)
}

fn decode_event(
    raw: &[u8],
    c: &NwbGenerationAuditContextV1,
    expected_worker: Option<NwbGenerationProcessIdentityV1>,
    phase: AuditPhaseV1,
    seq: u64,
    previous: Hash32,
) -> io::Result<(DecodedEvent, Hash32)> {
    if &raw[0..8] != AUDIT_SCHEMA
        || le_u16(raw, 8)? != AUDIT_VERSION
        || le_u16(raw, 10)? as usize != AUDIT_RECORD_LEN
        || le_u64(raw, 12)? != seq
        || raw[22..24].iter().any(|x| *x != 0)
        || raw[262..264].iter().any(|x| *x != 0)
        || raw[264..296] != previous
        || raw[296..AUDIT_RECORD_LEN - 4].iter().any(|x| *x != 0)
    {
        return Err(invalid("audit header/reserved bytes invalid"));
    }
    if crc32c(&raw[..AUDIT_RECORD_LEN - 4]) != le_u32(raw, AUDIT_RECORD_LEN - 4)? {
        return Err(invalid("audit CRC32C mismatch"));
    }
    if raw[24..40] != c.run_id
        || le_u64(raw, 40)? != c.run_epoch
        || le_u32(raw, 48)? != c.generation
        || le_u32(raw, 52)? != c.attempt
        || read_process(raw, 56)? != c.supervisor
        || expected_worker.is_some_and(|w| read_process(raw, 68).ok() != Some(w))
    {
        return Err(invalid("audit identity mismatch"));
    }
    let kind = kind(raw[20])?;
    let source = source(raw[21])?;
    let worker = read_process(raw, 68)?;
    let zero_worker = NwbGenerationProcessIdentityV1 {
        pid: 0,
        creation_time_100ns: 0,
    };
    if expected_worker.is_none()
        && kind != NwbGenerationAuditEventKindV1::LaunchContained
        && worker != zero_worker
    {
        return Err(invalid("pre-launch event has worker identity"));
    }
    let mut canonical = [0u8; AUDIT_RECORD_LEN];
    canonical.copy_from_slice(raw);
    let hash = event_hash(
        &previous,
        &canonical[..AUDIT_RECORD_LEN - 4],
        le_u32(raw, AUDIT_RECORD_LEN - 4)?,
    );
    let _ = phase;
    validate_decoded(kind, source, raw, expected_worker)?;
    if matches!(
        kind,
        NwbGenerationAuditEventKindV1::LaunchContained
            | NwbGenerationAuditEventKindV1::WorkerExitObserved
            | NwbGenerationAuditEventKindV1::ValidationAccepted
    ) && (worker.pid == 0 || worker.creation_time_100ns == 0)
    {
        return Err(invalid("post-launch event has zero worker identity"));
    }
    Ok((DecodedEvent { kind, worker }, hash))
}

#[derive(Clone, Copy)]
struct DecodedEvent {
    kind: NwbGenerationAuditEventKindV1,
    worker: NwbGenerationProcessIdentityV1,
}

fn validate_data(
    c: &NwbGenerationAuditContextV1,
    bound_worker: Option<NwbGenerationProcessIdentityV1>,
    phase: AuditPhaseV1,
    d: &NwbGenerationAuditEventDataV1,
) -> io::Result<()> {
    let zero = NwbGenerationProcessIdentityV1 {
        pid: 0,
        creation_time_100ns: 0,
    };
    let next_phase = transition(phase, d.kind)?;
    let launching_now = d.kind == NwbGenerationAuditEventKindV1::LaunchContained;
    if d.supervisor != c.supervisor
        || (bound_worker.is_none() && !launching_now && d.worker != zero)
        || (bound_worker.is_none()
            && launching_now
            && (d.worker.pid == 0 || d.worker.creation_time_100ns == 0))
        || bound_worker.is_some_and(|worker| worker != d.worker)
        || d.supervisor.pid == 0
        || d.supervisor.creation_time_100ns == 0
        || (d.source == NwbGenerationAuditEvidenceSourceV1::OwnerIndependent
            && !d.independent_handle_wait)
    {
        return Err(invalid(
            "event identity or evidence-source invariant failed",
        ));
    }
    if d.reason == NwbGenerationAuditReasonV1::None
        && d.kind == NwbGenerationAuditEventKindV1::AttemptFailed
    {
        return Err(invalid("failed attempt requires a reason"));
    }
    if next_phase == AuditPhaseV1::Failed
        && bound_worker.is_some()
        && !terminal_snapshot_is_proven(d)
    {
        return Err(invalid(
            "post-launch failure cannot seal without terminal Job/handle evidence",
        ));
    }
    let bytes = encode_event(c, 0, [0; 32], *d)?;
    validate_decoded(d.kind, d.source, &bytes, bound_worker)?;
    Ok(())
}
fn validate_decoded(
    k: NwbGenerationAuditEventKindV1,
    s: NwbGenerationAuditEvidenceSourceV1,
    raw: &[u8],
    expected_worker: Option<NwbGenerationProcessIdentityV1>,
) -> io::Result<()> {
    let exit = exit_method(raw[84])?;
    let wait = wait_result(raw[85])?;
    if k == NwbGenerationAuditEventKindV1::AuditSealed
        && s != NwbGenerationAuditEvidenceSourceV1::SupervisorObserved
    {
        return Err(invalid("seal must be supervisor observed"));
    }
    if k == NwbGenerationAuditEventKindV1::ValidationAccepted
        && raw[260] != NwbGenerationAuditReasonV1::None as u8
    {
        return Err(invalid("accepted validation carries failure reason"));
    }
    if raw[80..84].iter().any(|x| *x > 1) || raw[86] > 1 || raw[87] > 1 {
        return Err(invalid("containment boolean invalid"));
    }
    let containment = raw[80..84].iter().all(|x| *x == 1);
    let reason = raw[260];
    if reason > NwbGenerationAuditReasonV1::RecoveryPoisoned as u8 {
        return Err(invalid("unknown audit reason"));
    }
    let static_exit_fields = exit == NwbGenerationAuditExitMethodV1::None
        && wait == NwbGenerationAuditWaitResultV1::None
        && le_u32(raw, 88)? == 0
        && le_u64(raw, 92)? == 0
        && le_u32(raw, 100)? == 0
        && le_u32(raw, 104)? == 0
        && raw[86] == 0
        && raw[87] == 0;
    let containment_empty = raw[80..84].iter().all(|value| *value == 0);
    let terminal_snapshot = matches!(
        exit,
        NwbGenerationAuditExitMethodV1::Graceful
            | NwbGenerationAuditExitMethodV1::JobObjectTermination
    ) && wait == NwbGenerationAuditWaitResultV1::SignaledReaped
        && le_u64(raw, 92)? != 0
        && raw[86] == 1
        && le_u32(raw, 104)? == 0
        && raw[87] == 1;
    match k {
        NwbGenerationAuditEventKindV1::AuditStarted
        | NwbGenerationAuditEventKindV1::GenerationReserved
            if !static_exit_fields || !containment_empty =>
        {
            return Err(invalid("pre-launch event carries process evidence"))
        }
        NwbGenerationAuditEventKindV1::LaunchContained
            if !containment
                || !static_exit_fields
                || !raw[156..188].iter().any(|value| *value != 0)
                || !raw[188..220].iter().any(|value| *value != 0) =>
        {
            return Err(invalid("LaunchContained lacks all containment facts"))
        }
        NwbGenerationAuditEventKindV1::WorkerExitObserved if !terminal_snapshot => {
            return Err(invalid("WorkerExitObserved lacks wait/deadline evidence"))
        }
        NwbGenerationAuditEventKindV1::ValidationAccepted
            if s != NwbGenerationAuditEvidenceSourceV1::OwnerIndependent =>
        {
            return Err(invalid("ValidationAccepted must be owner independent"))
        }
        NwbGenerationAuditEventKindV1::ValidationAccepted
            if !terminal_snapshot
                || le_u32(raw, 88)? != 0
                || !raw[124..156].iter().any(|value| *value != 0)
                || !raw[156..188].iter().any(|value| *value != 0)
                || !raw[188..220].iter().any(|value| *value != 0) =>
        {
            return Err(invalid("ValidationAccepted lacks reaped snapshot"))
        }
        NwbGenerationAuditEventKindV1::AttemptFailed
            if reason == 0
                || (expected_worker.is_none() && (!static_exit_fields || !containment_empty))
                || (expected_worker.is_some() && (!terminal_snapshot || !containment)) =>
        {
            return Err(invalid("AttemptFailed lacks a reason"))
        }
        NwbGenerationAuditEventKindV1::AuditStarted
        | NwbGenerationAuditEventKindV1::GenerationReserved
        | NwbGenerationAuditEventKindV1::AuditSealed
            if reason != 0 || !static_exit_fields || !containment_empty =>
        {
            return Err(invalid("static event carries process or failure evidence"))
        }
        _ => {}
    }
    Ok(())
}

fn terminal_snapshot_is_proven(data: &NwbGenerationAuditEventDataV1) -> bool {
    matches!(
        data.exit_method,
        NwbGenerationAuditExitMethodV1::Graceful
            | NwbGenerationAuditExitMethodV1::JobObjectTermination
    ) && data.wait_result == NwbGenerationAuditWaitResultV1::SignaledReaped
        && data.deadline_ns != 0
        && data.job_active_processes == 0
        && data.job_empty
        && data.independent_handle_wait
        && data.containment.suspended_created
        && data.containment.job_assigned
        && data.containment.kill_on_job_close
        && data.containment.executable_reverified
}
fn transition(
    phase: AuditPhaseV1,
    kind: NwbGenerationAuditEventKindV1,
) -> io::Result<AuditPhaseV1> {
    use NwbGenerationAuditEventKindV1 as K;
    let next = match (phase, kind) {
        (AuditPhaseV1::Empty, K::AuditStarted) => AuditPhaseV1::Started,
        (AuditPhaseV1::Started, K::GenerationReserved) => AuditPhaseV1::Reserved,
        (AuditPhaseV1::Reserved, K::LaunchContained) => AuditPhaseV1::Contained,
        (AuditPhaseV1::Contained, K::WorkerExitObserved) => AuditPhaseV1::Exited,
        (AuditPhaseV1::Exited, K::ValidationAccepted) => AuditPhaseV1::Accepted,
        (AuditPhaseV1::Accepted, K::AuditSealed) => AuditPhaseV1::Sealed,
        (
            AuditPhaseV1::Started
            | AuditPhaseV1::Reserved
            | AuditPhaseV1::Contained
            | AuditPhaseV1::Exited
            | AuditPhaseV1::Accepted,
            K::AttemptFailed,
        ) => AuditPhaseV1::Failed,
        (AuditPhaseV1::Failed, K::AuditSealed) => AuditPhaseV1::Sealed,
        _ => return Err(invalid("audit state-machine transition invalid")),
    };
    Ok(next)
}
fn validate_context(c: &NwbGenerationAuditContextV1) -> io::Result<()> {
    if c.run_id == [0; 16]
        || c.run_epoch == 0
        || c.generation == 0
        || c.attempt == 0
        || c.supervisor.pid == 0
        || c.supervisor.creation_time_100ns == 0
    {
        return Err(invalid("audit context invalid"));
    }
    Ok(())
}

fn encode_receipt(r: &NwbGenerationAuditReceiptV1) -> io::Result<[u8; AUDIT_RECEIPT_LEN]> {
    let mut b = [0u8; AUDIT_RECEIPT_LEN];
    b[..8].copy_from_slice(RECEIPT_SCHEMA);
    put_u16(&mut b, 8, AUDIT_VERSION);
    put_u16(&mut b, 10, AUDIT_RECEIPT_LEN as u16);
    b[12..28].copy_from_slice(&r.run_id);
    put_u64(&mut b, 28, r.run_epoch);
    put_u32(&mut b, 36, r.generation);
    put_u32(&mut b, 40, r.attempt);
    put_u64(&mut b, 44, r.audit_bytes);
    put_u64(&mut b, 52, r.event_count);
    put_hash(&mut b, 60, r.audit_sha256);
    put_hash(&mut b, 92, r.last_event_hash);
    b[124] = r.publication_authorized as u8;
    let crc = crc32c(&b[..AUDIT_RECEIPT_LEN - 4]);
    put_u32(&mut b, AUDIT_RECEIPT_LEN - 4, crc);
    Ok(b)
}
fn decode_receipt(raw: &[u8]) -> io::Result<NwbGenerationAuditReceiptV1> {
    if raw.len() != AUDIT_RECEIPT_LEN
        || &raw[..8] != RECEIPT_SCHEMA
        || le_u16(raw, 8)? != AUDIT_VERSION
        || le_u16(raw, 10)? as usize != AUDIT_RECEIPT_LEN
        || raw[125..AUDIT_RECEIPT_LEN - 4].iter().any(|x| *x != 0)
        || crc32c(&raw[..AUDIT_RECEIPT_LEN - 4]) != le_u32(raw, AUDIT_RECEIPT_LEN - 4)?
        || raw[124] > 1
    {
        return Err(invalid("audit receipt invalid"));
    }
    Ok(NwbGenerationAuditReceiptV1 {
        run_id: raw[12..28].try_into().unwrap(),
        run_epoch: le_u64(raw, 28)?,
        generation: le_u32(raw, 36)?,
        attempt: le_u32(raw, 40)?,
        audit_bytes: le_u64(raw, 44)?,
        event_count: le_u64(raw, 52)?,
        audit_sha256: raw[60..92].try_into().unwrap(),
        last_event_hash: raw[92..124].try_into().unwrap(),
        publication_authorized: raw[124] != 0,
    })
}
fn event_hash(previous: &Hash32, bytes: &[u8], crc: u32) -> Hash32 {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(previous);
    h.update(bytes);
    h.update(crc.to_le_bytes());
    h.finalize().into()
}
fn kind(v: u8) -> io::Result<NwbGenerationAuditEventKindV1> {
    match v {
        1 => Ok(NwbGenerationAuditEventKindV1::AuditStarted),
        2 => Ok(NwbGenerationAuditEventKindV1::GenerationReserved),
        3 => Ok(NwbGenerationAuditEventKindV1::LaunchContained),
        4 => Ok(NwbGenerationAuditEventKindV1::WorkerExitObserved),
        5 => Ok(NwbGenerationAuditEventKindV1::ValidationAccepted),
        6 => Ok(NwbGenerationAuditEventKindV1::AttemptFailed),
        7 => Ok(NwbGenerationAuditEventKindV1::AuditSealed),
        _ => Err(invalid("unknown audit event kind")),
    }
}
fn exit_method(v: u8) -> io::Result<NwbGenerationAuditExitMethodV1> {
    match v {
        0 => Ok(NwbGenerationAuditExitMethodV1::None),
        1 => Ok(NwbGenerationAuditExitMethodV1::JobObjectTermination),
        2 => Ok(NwbGenerationAuditExitMethodV1::Graceful),
        _ => Err(invalid("unknown exit method")),
    }
}
fn wait_result(v: u8) -> io::Result<NwbGenerationAuditWaitResultV1> {
    match v {
        0 => Ok(NwbGenerationAuditWaitResultV1::None),
        1 => Ok(NwbGenerationAuditWaitResultV1::SignaledReaped),
        2 => Ok(NwbGenerationAuditWaitResultV1::TimedOut),
        3 => Ok(NwbGenerationAuditWaitResultV1::Failed),
        _ => Err(invalid("unknown wait result")),
    }
}
fn source(v: u8) -> io::Result<NwbGenerationAuditEvidenceSourceV1> {
    match v {
        1 => Ok(NwbGenerationAuditEvidenceSourceV1::SupervisorObserved),
        2 => Ok(NwbGenerationAuditEvidenceSourceV1::OwnerIndependent),
        _ => Err(invalid("unknown evidence source")),
    }
}
fn put_process(b: &mut [u8], o: usize, p: NwbGenerationProcessIdentityV1) {
    put_u32(b, o, p.pid);
    put_u64(b, o + 4, p.creation_time_100ns)
}
fn read_process(b: &[u8], o: usize) -> io::Result<NwbGenerationProcessIdentityV1> {
    Ok(NwbGenerationProcessIdentityV1 {
        pid: le_u32(b, o)?,
        creation_time_100ns: le_u64(b, o + 4)?,
    })
}
fn put_hash(b: &mut [u8], o: usize, h: Hash32) {
    b[o..o + 32].copy_from_slice(&h)
}
fn put_u16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes())
}
fn put_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes())
}
fn put_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes())
}
fn le_u16(b: &[u8], o: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(o..o + 2)
            .ok_or_else(|| invalid("short input"))?
            .try_into()
            .unwrap(),
    ))
}
fn le_u32(b: &[u8], o: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(o..o + 4)
            .ok_or_else(|| invalid("short input"))?
            .try_into()
            .unwrap(),
    ))
}
fn le_u64(b: &[u8], o: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(o..o + 8)
            .ok_or_else(|| invalid("short input"))?
            .try_into()
            .unwrap(),
    ))
}
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn paths(tag: &str) -> (PathBuf, PathBuf) {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("forge-nwb-audit-{tag}-{n}"));
        fs::create_dir_all(&root).unwrap();
        (root.join("attempt.audit"), root.join("attempt.receipt"))
    }
    fn context() -> NwbGenerationAuditContextV1 {
        NwbGenerationAuditContextV1 {
            run_id: [7; 16],
            run_epoch: 9,
            generation: 1,
            attempt: 1,
            supervisor: NwbGenerationProcessIdentityV1 {
                pid: 10,
                creation_time_100ns: 11,
            },
        }
    }
    fn data(
        c: &NwbGenerationAuditContextV1,
        kind: NwbGenerationAuditEventKindV1,
        source: NwbGenerationAuditEvidenceSourceV1,
    ) -> NwbGenerationAuditEventDataV1 {
        let launched = matches!(
            kind,
            NwbGenerationAuditEventKindV1::LaunchContained
                | NwbGenerationAuditEventKindV1::WorkerExitObserved
                | NwbGenerationAuditEventKindV1::ValidationAccepted
                | NwbGenerationAuditEventKindV1::AuditSealed
        );
        let terminal = matches!(
            kind,
            NwbGenerationAuditEventKindV1::WorkerExitObserved
                | NwbGenerationAuditEventKindV1::ValidationAccepted
        );
        let contained = matches!(
            kind,
            NwbGenerationAuditEventKindV1::LaunchContained
                | NwbGenerationAuditEventKindV1::WorkerExitObserved
                | NwbGenerationAuditEventKindV1::ValidationAccepted
        );
        NwbGenerationAuditEventDataV1 {
            kind,
            source,
            supervisor: c.supervisor,
            worker: if launched {
                NwbGenerationProcessIdentityV1 {
                    pid: 20,
                    creation_time_100ns: 21,
                }
            } else {
                NwbGenerationProcessIdentityV1 {
                    pid: 0,
                    creation_time_100ns: 0,
                }
            },
            containment: NwbGenerationLaunchContainmentV1 {
                suspended_created: contained,
                job_assigned: contained,
                kill_on_job_close: contained,
                executable_reverified: contained,
            },
            exit_method: if terminal {
                NwbGenerationAuditExitMethodV1::JobObjectTermination
            } else {
                NwbGenerationAuditExitMethodV1::None
            },
            wait_result: if terminal {
                NwbGenerationAuditWaitResultV1::SignaledReaped
            } else {
                NwbGenerationAuditWaitResultV1::None
            },
            exit_code: 0,
            deadline_ns: if terminal { 100 } else { 0 },
            elapsed_ms: if terminal { 1 } else { 0 },
            job_active_processes: 0,
            job_empty: terminal,
            independent_handle_wait: terminal,
            durable_journal_sequence: 0,
            durable_journal_valid_len: 64,
            journal_sha256: [1; 32],
            manifest_sha256: [2; 32],
            executable_sha256: [3; 32],
            old_artifact_sha256: [4; 32],
            old_artifact_size: 5,
            reason: NwbGenerationAuditReasonV1::None,
        }
    }

    fn append_success(
        writer: &mut NwbGenerationAuditWriterV1,
        context: &NwbGenerationAuditContextV1,
    ) {
        for (kind, source) in [
            (
                NwbGenerationAuditEventKindV1::AuditStarted,
                NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
            ),
            (
                NwbGenerationAuditEventKindV1::GenerationReserved,
                NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
            ),
            (
                NwbGenerationAuditEventKindV1::LaunchContained,
                NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
            ),
            (
                NwbGenerationAuditEventKindV1::WorkerExitObserved,
                NwbGenerationAuditEvidenceSourceV1::OwnerIndependent,
            ),
            (
                NwbGenerationAuditEventKindV1::ValidationAccepted,
                NwbGenerationAuditEvidenceSourceV1::OwnerIndependent,
            ),
            (
                NwbGenerationAuditEventKindV1::AuditSealed,
                NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
            ),
        ] {
            writer.append(data(context, kind, source)).unwrap();
        }
    }

    fn rewrite_record_crc(bytes: &mut [u8], record_index: usize) {
        let start = record_index * AUDIT_RECORD_LEN;
        let end = start + AUDIT_RECORD_LEN;
        let crc = crc32c(&bytes[start..end - 4]);
        bytes[end - 4..end].copy_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn roundtrip_and_create_new_receipt() {
        let (audit, receipt) = paths("roundtrip");
        let c = context();
        let mut w = NwbGenerationAuditWriterV1::create_new(&audit, c).unwrap();
        append_success(&mut w, &c);
        let e = w.finish(&receipt).unwrap();
        assert_eq!(e.event_count, 6);
        assert!(verify_nwb_generation_audit_receipt(&audit, &receipt, &c).is_ok());
        assert!(NwbGenerationAuditWriterV1::create_new(&audit, c).is_err());
        let _ = fs::remove_dir_all(audit.parent().unwrap());
    }
    #[test]
    fn tamper_truncate_and_unsealed_fail_closed() {
        let (audit, receipt) = paths("tamper");
        let c = context();
        let mut w = NwbGenerationAuditWriterV1::create_new(&audit, c).unwrap();
        w.append(data(
            &c,
            NwbGenerationAuditEventKindV1::AuditStarted,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        ))
        .unwrap();
        drop(w);
        assert!(verify_nwb_generation_audit(&audit, &c).is_err());
        let mut bytes = fs::read(&audit).unwrap();
        bytes[100] ^= 1;
        fs::write(&audit, bytes).unwrap();
        assert!(verify_nwb_generation_audit(&audit, &c).is_err());
        assert!(verify_nwb_generation_audit_receipt(&audit, &receipt, &c).is_err());
        let _ = fs::remove_dir_all(audit.parent().unwrap());
    }

    #[test]
    fn launch_before_reservation_is_rejected_without_growth() {
        let (audit, _) = paths("order");
        let c = context();
        let mut w = NwbGenerationAuditWriterV1::create_new(&audit, c).unwrap();
        w.append(data(
            &c,
            NwbGenerationAuditEventKindV1::LaunchContained,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        ))
        .unwrap_err();
        assert_eq!(fs::metadata(&audit).unwrap().len(), 0);
        let _ = fs::remove_dir_all(audit.parent().unwrap());
    }

    #[test]
    fn reservation_first_and_duplicate_start_are_rejected_without_growth() {
        for (tag, first, second) in [
            (
                "reservation-first",
                NwbGenerationAuditEventKindV1::GenerationReserved,
                None,
            ),
            (
                "duplicate-start",
                NwbGenerationAuditEventKindV1::AuditStarted,
                Some(NwbGenerationAuditEventKindV1::AuditStarted),
            ),
        ] {
            let (audit, _) = paths(tag);
            let c = context();
            let mut writer = NwbGenerationAuditWriterV1::create_new(&audit, c).unwrap();
            let first_result = writer.append(data(
                &c,
                first,
                NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
            ));
            if let Some(second) = second {
                first_result.unwrap();
                let before = fs::metadata(&audit).unwrap().len();
                assert!(writer
                    .append(data(
                        &c,
                        second,
                        NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
                    ))
                    .is_err());
                assert_eq!(fs::metadata(&audit).unwrap().len(), before);
            } else {
                assert!(first_result.is_err());
                assert_eq!(fs::metadata(&audit).unwrap().len(), 0);
            }
            let _ = fs::remove_dir_all(audit.parent().unwrap());
        }
    }
    #[test]
    fn launch_after_failure_is_rejected_without_growth() {
        let (audit, _) = paths("failed");
        let c = context();
        let mut w = NwbGenerationAuditWriterV1::create_new(&audit, c).unwrap();
        w.append(data(
            &c,
            NwbGenerationAuditEventKindV1::AuditStarted,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        ))
        .unwrap();
        let mut f = data(
            &c,
            NwbGenerationAuditEventKindV1::AttemptFailed,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        );
        f.reason = NwbGenerationAuditReasonV1::WorkerLaunchFailed;
        w.append(f).unwrap();
        let before = fs::metadata(&audit).unwrap().len();
        w.append(data(
            &c,
            NwbGenerationAuditEventKindV1::LaunchContained,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        ))
        .unwrap_err();
        assert_eq!(fs::metadata(&audit).unwrap().len(), before);
        let _ = fs::remove_dir_all(audit.parent().unwrap());
    }
    #[test]
    fn worker_identity_drift_is_rejected() {
        let (audit, _) = paths("drift");
        let c = context();
        let mut w = NwbGenerationAuditWriterV1::create_new(&audit, c).unwrap();
        w.append(data(
            &c,
            NwbGenerationAuditEventKindV1::AuditStarted,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        ))
        .unwrap();
        w.append(data(
            &c,
            NwbGenerationAuditEventKindV1::GenerationReserved,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        ))
        .unwrap();
        w.append(data(
            &c,
            NwbGenerationAuditEventKindV1::LaunchContained,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        ))
        .unwrap();
        let mut d = data(
            &c,
            NwbGenerationAuditEventKindV1::WorkerExitObserved,
            NwbGenerationAuditEvidenceSourceV1::OwnerIndependent,
        );
        d.worker.pid += 1;
        w.append(d).unwrap_err();
        let _ = fs::remove_dir_all(audit.parent().unwrap());
    }
    #[test]
    fn validation_requires_owner_independent_source() {
        let (audit, _) = paths("source");
        let c = context();
        let mut w = NwbGenerationAuditWriterV1::create_new(&audit, c).unwrap();
        for k in [
            NwbGenerationAuditEventKindV1::AuditStarted,
            NwbGenerationAuditEventKindV1::GenerationReserved,
            NwbGenerationAuditEventKindV1::LaunchContained,
            NwbGenerationAuditEventKindV1::WorkerExitObserved,
        ] {
            w.append(data(
                &c,
                k,
                if k as u8 >= 4 {
                    NwbGenerationAuditEvidenceSourceV1::OwnerIndependent
                } else {
                    NwbGenerationAuditEvidenceSourceV1::SupervisorObserved
                },
            ))
            .unwrap();
        }
        w.append(data(
            &c,
            NwbGenerationAuditEventKindV1::ValidationAccepted,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        ))
        .unwrap_err();
        let _ = fs::remove_dir_all(audit.parent().unwrap());
    }
    #[test]
    fn zero_epoch_or_attempt_context_is_rejected() {
        let (audit, _) = paths("zero");
        let mut c = context();
        c.run_epoch = 0;
        assert!(NwbGenerationAuditWriterV1::create_new(&audit, c).is_err());
        c = context();
        c.attempt = 0;
        assert!(NwbGenerationAuditWriterV1::create_new(&audit, c).is_err());
        let _ = fs::remove_dir_all(audit.parent().unwrap());
    }

    #[test]
    fn prelaunch_and_postlaunch_failures_seal_with_correct_worker_binding() {
        let c = context();

        let (pre_audit, pre_receipt) = paths("prelaunch-sealed");
        let mut pre = NwbGenerationAuditWriterV1::create_new(&pre_audit, c).unwrap();
        pre.append(data(
            &c,
            NwbGenerationAuditEventKindV1::AuditStarted,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        ))
        .unwrap();
        let mut failed = data(
            &c,
            NwbGenerationAuditEventKindV1::AttemptFailed,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        );
        failed.reason = NwbGenerationAuditReasonV1::WorkerLaunchFailed;
        pre.append(failed).unwrap();
        let mut seal = data(
            &c,
            NwbGenerationAuditEventKindV1::AuditSealed,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        );
        seal.worker = NwbGenerationProcessIdentityV1 {
            pid: 0,
            creation_time_100ns: 0,
        };
        pre.append(seal).unwrap();
        assert_eq!(pre.finish(&pre_receipt).unwrap().event_count, 3);

        let (post_audit, post_receipt) = paths("postlaunch-sealed");
        let mut post = NwbGenerationAuditWriterV1::create_new(&post_audit, c).unwrap();
        for kind in [
            NwbGenerationAuditEventKindV1::AuditStarted,
            NwbGenerationAuditEventKindV1::GenerationReserved,
            NwbGenerationAuditEventKindV1::LaunchContained,
        ] {
            post.append(data(
                &c,
                kind,
                NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
            ))
            .unwrap();
        }
        let mut failed = data(
            &c,
            NwbGenerationAuditEventKindV1::AttemptFailed,
            NwbGenerationAuditEvidenceSourceV1::OwnerIndependent,
        );
        failed.worker = NwbGenerationProcessIdentityV1 {
            pid: 20,
            creation_time_100ns: 21,
        };
        failed.containment = NwbGenerationLaunchContainmentV1 {
            suspended_created: true,
            job_assigned: true,
            kill_on_job_close: true,
            executable_reverified: true,
        };
        failed.exit_method = NwbGenerationAuditExitMethodV1::JobObjectTermination;
        failed.wait_result = NwbGenerationAuditWaitResultV1::SignaledReaped;
        failed.deadline_ns = 100;
        failed.elapsed_ms = 1;
        failed.job_empty = true;
        failed.independent_handle_wait = true;
        failed.reason = NwbGenerationAuditReasonV1::DeadlineExceeded;
        post.append(failed).unwrap();
        post.append(data(
            &c,
            NwbGenerationAuditEventKindV1::AuditSealed,
            NwbGenerationAuditEvidenceSourceV1::SupervisorObserved,
        ))
        .unwrap();
        assert_eq!(post.finish(&post_receipt).unwrap().event_count, 5);

        let _ = fs::remove_dir_all(pre_audit.parent().unwrap());
        let _ = fs::remove_dir_all(post_audit.parent().unwrap());
    }

    #[test]
    fn embedded_chain_and_enum_tampering_fail_even_with_recomputed_crc() {
        for (tag, record, offset, value) in [
            ("previous-hash", 1_usize, 264_usize, 0x5a_u8),
            ("exit-enum", 3_usize, 84_usize, 0xff_u8),
            ("wait-enum", 3_usize, 85_usize, 0xff_u8),
        ] {
            let (audit, receipt) = paths(tag);
            let c = context();
            let mut writer = NwbGenerationAuditWriterV1::create_new(&audit, c).unwrap();
            append_success(&mut writer, &c);
            writer.finish(&receipt).unwrap();
            let mut bytes = fs::read(&audit).unwrap();
            bytes[record * AUDIT_RECORD_LEN + offset] = value;
            rewrite_record_crc(&mut bytes, record);
            fs::write(&audit, bytes).unwrap();
            assert!(verify_nwb_generation_audit(&audit, &c).is_err());
            let _ = fs::remove_dir_all(audit.parent().unwrap());
        }
    }
    #[test]
    fn duplicate_receipt_is_create_new_failure() {
        let (audit, receipt) = paths("receipt");
        let c = context();
        let mut w = NwbGenerationAuditWriterV1::create_new(&audit, c).unwrap();
        append_success(&mut w, &c);
        w.finish(&receipt).unwrap();
        let mut w2 =
            NwbGenerationAuditWriterV1::create_new(&audit.with_file_name("second.audit"), c)
                .unwrap();
        append_success(&mut w2, &c);
        assert!(w2.finish(&receipt).is_err());

        let mut receipt_bytes = fs::read(&receipt).unwrap();
        receipt_bytes[60] ^= 1;
        let crc = crc32c(&receipt_bytes[..AUDIT_RECEIPT_LEN - 4]);
        receipt_bytes[AUDIT_RECEIPT_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        fs::write(&receipt, receipt_bytes).unwrap();
        assert!(verify_nwb_generation_audit_receipt(&audit, &receipt, &c).is_err());
        let _ = fs::remove_dir_all(audit.parent().unwrap());
    }
}
