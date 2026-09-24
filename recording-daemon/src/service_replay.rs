use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;

#[cfg(windows)]
use forge_protocol_v1::{
    decode_record, RECORD_FLAG_CLOCK_UNLOCKED, RECORD_FLAG_DISCONTINUITY_BEFORE,
    RECORD_FLAG_SOURCE_CRC_ERROR, RECORD_FLAG_SOURCE_OVERFLOW,
};
use forge_protocol_v1::{sha256, RECORD_HEADER_LEN};

#[cfg(windows)]
use crate::analysis_mapping::MappedAnalysisRing;
#[cfg(windows)]
use crate::analysis_ring::{AnalysisBranchIdentityV1, AnalysisFaultV1, AnalysisRingError};
use crate::buffer_pool::{BoundedBufferPool, PooledBuffer};
use crate::journal::{seal_evidence_hash, JournalIdentity, JournalScan, JournalWriter};
use crate::run::{RunCommand, RunCommandKind, RunReceipt, RunState};
use crate::run_ledger::{DurableRunService, FAULT_INTERNAL_PERSISTENCE};
#[cfg(windows)]
use crate::safety_arbiter::AnalysisBranchFaultRoute;
use crate::source::{DeterministicReplayConfig, DeterministicReplaySource};

const ACTION_RUNNING: u8 = 0;
const ACTION_STOP_AND_SEAL: u8 = 1;
const ACTION_ABORT: u8 = 2;
const QUEUE_CAPACITY: usize = 4;
const DEFAULT_PAYLOAD_BYTES: usize = 92;
const SAMPLE_BLOCK_PAYLOAD_HEADER_BYTES: usize = 32;
const DEFAULT_DURABILITY_BATCH: u64 = 128;
const STOP_DEADLINE: Duration = Duration::from_secs(10);
const PAUSE_DRAIN_DEADLINE: Duration = Duration::from_secs(2);
const BACKPRESSURE_POLL_INTERVAL: Duration = Duration::from_micros(50);
const OPERATOR_CHANNEL_COUNT: u16 = 32;
const OPERATOR_SAMPLES_PER_CHANNEL: u32 = 30;
const OPERATOR_SAMPLE_RATE_HZ: u32 = 30_000;
const MAX_OPERATOR_PODS: usize = 8;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReplayProgressSnapshot {
    pub committed_record_count: Option<u64>,
    pub durable_record_count: Option<u64>,
    pub expected_last_journal_sequence: Option<u64>,
    pub queue_used_slots: Option<u64>,
    pub queue_capacity_slots: Option<u64>,
    pub generated_record_count: Option<u64>,
    pub analysis_published_record_count: Option<u64>,
    pub analysis_dropped_record_count: Option<u64>,
    pub analysis_faulted: Option<bool>,
    /// At least one analysis fault event failed to enter its bounded in-memory
    /// evidence queue. This says nothing about durable persistence.
    pub fault_evidence_lost: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplayPauseOutcome {
    pub accepted: bool,
    pub paused: bool,
    pub discarded_record_count: u64,
    pub reason: String,
}

pub struct ProtectedReplaySession {
    data_root: PathBuf,
    explicit_journal_path: Option<PathBuf>,
    expected_context: Option<ReplayExpectedContext>,
    stream: ReplayStreamConfig,
    prepared: Option<PreparedReplay>,
    worker: Option<ReplayWorker>,
    progress: Arc<ReplayProgress>,
    owner_shutdown: Arc<AtomicBool>,
    #[cfg(windows)]
    analysis_branches: Vec<LiveAnalysisBranch>,
}

#[derive(Clone, Copy)]
struct ReplayExpectedContext {
    run_id: [u8; 16],
    target_device_id: [u8; 16],
    frozen_config_hash: [u8; 32],
}

#[derive(Clone)]
struct ReplayStreamConfig {
    pod_ids: Vec<[u8; 16]>,
    channel_count: u16,
    samples_per_channel: u32,
    sample_rate_hz: u32,
    queue_capacity: usize,
    #[cfg(test)]
    durability_batch: u64,
    #[cfg(test)]
    durability_barrier_delay: Duration,
}

impl ReplayStreamConfig {
    fn encoded_capacity(&self) -> io::Result<usize> {
        let sample_bytes = usize::from(self.channel_count)
            .checked_mul(self.samples_per_channel as usize)
            .and_then(|value| value.checked_mul(2))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "replay payload overflow")
            })?;
        RECORD_HEADER_LEN
            .checked_add(SAMPLE_BLOCK_PAYLOAD_HEADER_BYTES)
            .and_then(|value| value.checked_add(sample_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "replay record overflow"))
    }
}

#[cfg(windows)]
struct LiveAnalysisBranch {
    mapping: MappedAnalysisRing,
    fault_route: Arc<AnalysisBranchFaultRoute>,
    next_journal_sequence: Option<u64>,
}

#[cfg(windows)]
impl LiveAnalysisBranch {
    fn new(
        mapping: MappedAnalysisRing,
        fault_route: Arc<AnalysisBranchFaultRoute>,
    ) -> io::Result<Self> {
        let identity = fault_route.identity();
        if identity.run_id() != mapping.run_id()
            || identity.consumer_id() != mapping.consumer_id()
            || identity.producer_epoch() != mapping.producer_epoch()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "analysis fault route identity does not match mapping",
            ));
        }
        if !fault_route.bind_mapping_once() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "analysis fault route is already bound to a mapping",
            ));
        }
        Ok(Self {
            mapping,
            fault_route,
            next_journal_sequence: None,
        })
    }

    fn publish(
        &mut self,
        encoded_record: &[u8],
        journal_sequence: u64,
        observed_monotonic_ns: u64,
    ) -> Result<u64, AnalysisRingError> {
        if let Some(expected) = self.next_journal_sequence {
            if expected != journal_sequence {
                self.fault_route.dispatch(
                    AnalysisFaultV1::DataGap,
                    observed_monotonic_ns,
                    Some(expected),
                    Some(journal_sequence),
                );
            }
        }
        self.next_journal_sequence = journal_sequence.checked_add(1);

        if let Ok(decoded) = decode_record(encoded_record) {
            let flags = decoded.envelope.flags;
            let fault = if flags & RECORD_FLAG_SOURCE_CRC_ERROR != 0 {
                Some(AnalysisFaultV1::CrcFault)
            } else if flags & (RECORD_FLAG_DISCONTINUITY_BEFORE | RECORD_FLAG_SOURCE_OVERFLOW) != 0
            {
                Some(AnalysisFaultV1::DataGap)
            } else if flags & RECORD_FLAG_CLOCK_UNLOCKED != 0 {
                Some(AnalysisFaultV1::DeadlineMiss)
            } else {
                None
            };
            if let Some(fault) = fault {
                self.fault_route.dispatch(
                    fault,
                    observed_monotonic_ns,
                    Some(journal_sequence),
                    Some(journal_sequence),
                );
            }
        }

        let result =
            self.mapping
                .try_publish(encoded_record, journal_sequence, observed_monotonic_ns);
        if let Err(error) = result {
            let fault = match error {
                AnalysisRingError::Full => AnalysisFaultV1::RingFull,
                AnalysisRingError::Contradiction
                | AnalysisRingError::InvalidCanonicalRecord
                | AnalysisRingError::NonSampleRecord
                | AnalysisRingError::RecordTooLarge
                | AnalysisRingError::InvalidConfiguration => AnalysisFaultV1::CrcFault,
            };
            self.fault_route.dispatch(
                fault,
                observed_monotonic_ns,
                Some(journal_sequence),
                Some(journal_sequence),
            );
        }
        result
    }
}

#[cfg(windows)]
impl Drop for LiveAnalysisBranch {
    fn drop(&mut self) {
        // The registration cache can retain the route after the mapping is
        // gone.  Revoke synchronously before the mapping handle disappears;
        // this is deliberately sink-free and idempotent.
        self.fault_route.fail_closed_controller_loss();
    }
}

#[derive(Clone)]
pub(crate) struct ReplayOwnerShutdownSignal {
    requested: Arc<AtomicBool>,
}

impl ReplayOwnerShutdownSignal {
    pub(crate) fn request_abort(&self) {
        self.requested.store(true, Ordering::Release);
    }
}

struct PreparedReplay {
    run_id: [u8; 16],
    writer: JournalWriter,
    stream: ReplayStreamConfig,
}

struct ReplayWorker {
    action: Arc<AtomicU8>,
    paused: Arc<AtomicBool>,
    pause_acknowledged: Arc<AtomicBool>,
    completion: mpsc::Receiver<WorkerCompletion>,
    join: Option<JoinHandle<()>>,
}

enum WorkerCompletion {
    Sealed(JournalScan),
    Aborted,
    Failed(String),
}

#[derive(Default)]
struct ReplayProgress {
    generated: AtomicU64,
    committed: AtomicU64,
    durable: AtomicU64,
    queue_used: AtomicU64,
    queue_capacity: AtomicU64,
    expected_last_plus_one: AtomicU64,
    analysis_published: AtomicU64,
    analysis_dropped: AtomicU64,
    analysis_faulted: AtomicU64,
    fault_evidence_lost: AtomicU64,
    discarded_while_paused: AtomicU64,
}

impl ProtectedReplaySession {
    pub fn new(data_root: impl AsRef<Path>) -> io::Result<Self> {
        let data_root = data_root.as_ref();
        if !data_root.is_absolute() || !data_root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "protected replay data root must be an existing absolute directory",
            ));
        }
        Ok(Self {
            data_root: data_root.to_path_buf(),
            explicit_journal_path: None,
            expected_context: None,
            stream: ReplayStreamConfig {
                pod_ids: vec![[0x50; 16]],
                channel_count: 1,
                samples_per_channel: ((DEFAULT_PAYLOAD_BYTES - SAMPLE_BLOCK_PAYLOAD_HEADER_BYTES)
                    / 2) as u32,
                sample_rate_hz: 30_000,
                queue_capacity: QUEUE_CAPACITY,
                #[cfg(test)]
                durability_batch: DEFAULT_DURABILITY_BATCH,
                #[cfg(test)]
                durability_barrier_delay: Duration::ZERO,
            },
            prepared: None,
            worker: None,
            progress: Arc::new(ReplayProgress::default()),
            owner_shutdown: Arc::new(AtomicBool::new(false)),
            #[cfg(windows)]
            analysis_branches: Vec::new(),
        })
    }

    /// Creates the run-bound, software/synthetic replay used by the
    /// non-SCM operator daemon. The directory must already have been reserved
    /// by that daemon; Prepare still owns creation of the fixed `run.forgewal`
    /// file through `JournalWriter::create` (create-new/no-overwrite).
    pub fn new_operator_software(
        run_directory: impl AsRef<Path>,
        run_id: [u8; 16],
        target_device_id: [u8; 16],
        frozen_config_hash: [u8; 32],
        pod_ids: Vec<[u8; 16]>,
    ) -> io::Result<Self> {
        let run_directory = run_directory.as_ref();
        if !run_directory.is_absolute() || !run_directory.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "operator replay Run directory must be an existing absolute directory",
            ));
        }
        if run_id == [0; 16]
            || target_device_id == [0; 16]
            || frozen_config_hash == [0; 32]
            || pod_ids.is_empty()
            || pod_ids.len() > MAX_OPERATOR_PODS
            || pod_ids.iter().any(|pod_id| *pod_id == [0; 16])
            || pod_ids
                .iter()
                .enumerate()
                .any(|(index, pod_id)| pod_ids[..index].contains(pod_id))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "operator replay requires one to eight unique nonzero Pod identities and a nonzero Run context",
            ));
        }
        let queue_capacity = QUEUE_CAPACITY
            .checked_mul(pod_ids.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "replay queue overflow"))?;
        let stream = ReplayStreamConfig {
            pod_ids,
            channel_count: OPERATOR_CHANNEL_COUNT,
            samples_per_channel: OPERATOR_SAMPLES_PER_CHANNEL,
            sample_rate_hz: OPERATOR_SAMPLE_RATE_HZ,
            queue_capacity,
            #[cfg(test)]
            durability_batch: DEFAULT_DURABILITY_BATCH,
            #[cfg(test)]
            durability_barrier_delay: Duration::ZERO,
        };
        let _ = stream.encoded_capacity()?;
        Ok(Self {
            data_root: run_directory.to_path_buf(),
            explicit_journal_path: Some(run_directory.join("run.forgewal")),
            expected_context: Some(ReplayExpectedContext {
                run_id,
                target_device_id,
                frozen_config_hash,
            }),
            stream,
            prepared: None,
            worker: None,
            progress: Arc::new(ReplayProgress::default()),
            owner_shutdown: Arc::new(AtomicBool::new(false)),
            #[cfg(windows)]
            analysis_branches: Vec::new(),
        })
    }

    pub(crate) fn owner_shutdown_signal(&self) -> ReplayOwnerShutdownSignal {
        ReplayOwnerShutdownSignal {
            requested: Arc::clone(&self.owner_shutdown),
        }
    }

    #[cfg(windows)]
    /// Attaches one already-authenticated, Run-bound analysis branch. The
    /// caller remains responsible for SID-authenticated worker registration;
    /// the SCM host does not call this until that handoff contract exists.
    pub fn attach_analysis_mapping(&mut self, mapping: MappedAnalysisRing) -> io::Result<()> {
        let identity = AnalysisBranchIdentityV1::new(
            mapping.run_id(),
            mapping.consumer_id(),
            mapping.producer_epoch(),
        )?;
        let fault_route = AnalysisBranchFaultRoute::observer(identity);
        self.attach_analysis_mapping_with_fault_route(mapping, fault_route)
    }

    #[cfg(windows)]
    pub(crate) fn attach_analysis_mapping_with_fault_route(
        &mut self,
        mapping: MappedAnalysisRing,
        fault_route: Arc<AnalysisBranchFaultRoute>,
    ) -> io::Result<()> {
        if self.prepared.is_some() || self.worker.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "analysis mappings can only be attached before Prepare",
            ));
        }
        if self.analysis_branches.iter().any(|existing| {
            existing.mapping.consumer_id() == mapping.consumer_id()
                || (existing.mapping.run_id(), existing.mapping.producer_epoch())
                    != (mapping.run_id(), mapping.producer_epoch())
        }) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "analysis mapping identity is duplicate or conflicts with this branch set",
            ));
        }
        self.analysis_branches
            .push(LiveAnalysisBranch::new(mapping, fault_route)?);
        Ok(())
    }

    pub fn refresh(&mut self, lifecycle: &mut DurableRunService) -> io::Result<()> {
        let Some(worker) = self.worker.as_mut() else {
            return Ok(());
        };
        match worker.completion.try_recv() {
            Ok(completion) => {
                worker.join()?;
                self.worker = None;
                match completion {
                    WorkerCompletion::Failed(message) => fail_active(lifecycle, &message),
                    WorkerCompletion::Sealed(_) | WorkerCompletion::Aborted => Err(
                        io::Error::other("replay worker completed without an owner command"),
                    ),
                }
            }
            Err(mpsc::TryRecvError::Empty) => Ok(()),
            Err(mpsc::TryRecvError::Disconnected) => {
                worker.join()?;
                self.worker = None;
                fail_active(lifecycle, "replay worker completion channel disconnected")
            }
        }
    }

    pub fn handle_command(
        &mut self,
        lifecycle: &mut DurableRunService,
        command: RunCommand,
    ) -> io::Result<RunReceipt> {
        if self.owner_shutdown.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SCM owner shutdown has begun; replay commands are disabled",
            ));
        }
        self.refresh(lifecycle)?;
        let kind = RunCommandKind::from_wire(command.body.command)?;
        match kind {
            RunCommandKind::Prepare => self.prepare(lifecycle, command),
            RunCommandKind::Arm => lifecycle.handle(command, 1),
            RunCommandKind::Start => self.start(lifecycle, command),
            RunCommandKind::Stop => self.stop(lifecycle, command),
            RunCommandKind::Abort => self.abort(lifecycle, command),
            RunCommandKind::AcknowledgeFailure => {
                if self.worker.is_some() {
                    lifecycle
                        .reject_by_policy(command, "replay worker termination is not yet proven")
                } else {
                    lifecycle.handle(command, 1)
                }
            }
            RunCommandKind::GetSnapshot => lifecycle.handle(command, 1),
        }
    }

    pub fn progress(&self) -> ReplayProgressSnapshot {
        let generated = self.progress.generated.load(Ordering::Acquire);
        let committed = self.progress.committed.load(Ordering::Acquire);
        let durable = self.progress.durable.load(Ordering::Acquire);
        let expected_plus_one = self.progress.expected_last_plus_one.load(Ordering::Acquire);
        let active = self.prepared.is_some() || self.worker.is_some() || generated != 0;
        if !active {
            return ReplayProgressSnapshot::default();
        }
        ReplayProgressSnapshot {
            committed_record_count: Some(committed),
            durable_record_count: Some(durable),
            expected_last_journal_sequence: (expected_plus_one != 0).then(|| expected_plus_one - 1),
            queue_used_slots: Some(self.progress.queue_used.load(Ordering::Acquire)),
            queue_capacity_slots: Some(self.progress.queue_capacity.load(Ordering::Acquire)),
            generated_record_count: Some(generated),
            analysis_published_record_count: Some(
                self.progress.analysis_published.load(Ordering::Acquire),
            ),
            analysis_dropped_record_count: Some(
                self.progress.analysis_dropped.load(Ordering::Acquire),
            ),
            analysis_faulted: Some(self.progress.analysis_faulted.load(Ordering::Acquire) != 0),
            fault_evidence_lost: Some(
                self.progress.fault_evidence_lost.load(Ordering::Acquire) != 0,
            ),
        }
    }

    /// Pauses only storage publication. The source worker continues advancing
    /// every live interval, so a real transport can keep being drained without
    /// applying backpressure to the device. Resume writes the next available
    /// interval with an explicit discontinuity marker.
    pub(crate) fn set_operator_paused(
        &mut self,
        lifecycle: &DurableRunService,
        epoch: u64,
        run_id: [u8; 16],
        paused: bool,
    ) -> ReplayPauseOutcome {
        let status = lifecycle.status();
        if status.state != RunState::Recording
            || status.active_epoch != Some(epoch)
            || status.active_run_id_hex.as_deref() != Some(hex(&run_id).as_str())
        {
            return ReplayPauseOutcome {
                accepted: false,
                paused: self.worker.as_ref().is_some_and(ReplayWorker::is_paused),
                discarded_record_count: self
                    .progress
                    .discarded_while_paused
                    .load(Ordering::Acquire),
                reason: "pause control does not match the active recording Run".to_owned(),
            };
        }
        let Some(worker) = self.worker.as_mut() else {
            return ReplayPauseOutcome {
                accepted: false,
                paused: false,
                discarded_record_count: self
                    .progress
                    .discarded_while_paused
                    .load(Ordering::Acquire),
                reason: "recording worker is unavailable".to_owned(),
            };
        };
        match worker.set_paused(paused, &self.progress) {
            Ok(()) => ReplayPauseOutcome {
                accepted: true,
                paused,
                discarded_record_count: self
                    .progress
                    .discarded_while_paused
                    .load(Ordering::Acquire),
                reason: if paused {
                    "recording storage paused; source intervals continue to be consumed"
                } else {
                    "recording storage resumed after an intentional discontinuity"
                }
                .to_owned(),
            },
            Err(error) => ReplayPauseOutcome {
                accepted: false,
                paused: worker.is_paused(),
                discarded_record_count: self
                    .progress
                    .discarded_while_paused
                    .load(Ordering::Acquire),
                reason: error.to_string(),
            },
        }
    }

    pub fn shutdown(&mut self, lifecycle: &mut DurableRunService) -> io::Result<()> {
        let mut worker_error = None;
        if let Some(mut worker) = self.worker.take() {
            match worker.finish(ACTION_ABORT, STOP_DEADLINE) {
                Ok(WorkerCompletion::Aborted) => {}
                Ok(WorkerCompletion::Failed(message)) => worker_error = Some(message),
                Ok(WorkerCompletion::Sealed(_)) => {
                    worker_error = Some("replay worker sealed during SCM shutdown".to_owned())
                }
                Err(error) => worker_error = Some(error.to_string()),
            }
        }
        self.prepared = None;
        #[cfg(windows)]
        {
            self.analysis_branches.clear();
        }
        fail_active(
            lifecycle,
            worker_error
                .as_deref()
                .unwrap_or("SCM service shutdown interrupted an unsealed replay Run"),
        )?;
        if let Some(error) = worker_error {
            return Err(io::Error::other(error));
        }
        Ok(())
    }

    fn prepare(
        &mut self,
        lifecycle: &mut DurableRunService,
        command: RunCommand,
    ) -> io::Result<RunReceipt> {
        if self.expected_context.is_some_and(|expected| {
            command.body.run_id != expected.run_id
                || command.body.target_device_id != expected.target_device_id
                || command.body.frozen_config_hash != expected.frozen_config_hash
        }) {
            return lifecycle
                .reject_by_policy(command, "software replay reservation context mismatch");
        }
        #[cfg(windows)]
        if self
            .analysis_branches
            .iter()
            .any(|branch| branch.mapping.run_id() != command.body.run_id)
        {
            return lifecycle.reject_by_policy(command, "analysis mapping Run identity mismatch");
        }
        let receipt = lifecycle.handle(command.clone(), 1)?;
        if !receipt.accepted || self.prepared.is_some() {
            return Ok(receipt);
        }
        self.reset_progress(self.stream.queue_capacity as u64);
        let run_id = command.body.run_id;
        let journal_path = self.explicit_journal_path.clone().unwrap_or_else(|| {
            self.data_root
                .join(format!("run-{}.forgewal", hex(&run_id)))
        });
        match JournalWriter::create(&journal_path, JournalIdentity::for_run(run_id)?) {
            Ok(writer) => {
                self.prepared = Some(PreparedReplay {
                    run_id,
                    writer,
                    stream: self.stream.clone(),
                });
                Ok(receipt)
            }
            Err(error) => {
                fail_active(
                    lifecycle,
                    &format!("replay journal prepare failed: {error}"),
                )?;
                Err(error)
            }
        }
    }

    fn start(
        &mut self,
        lifecycle: &mut DurableRunService,
        command: RunCommand,
    ) -> io::Result<RunReceipt> {
        let receipt = lifecycle.handle(command, 1)?;
        if !receipt.accepted || self.worker.is_some() {
            return Ok(receipt);
        }
        let prepared = self.prepared.take().ok_or_else(|| {
            io::Error::other("accepted replay Start has no prepared journal resource")
        })?;
        match ReplayWorker::spawn(
            prepared,
            Arc::clone(&self.owner_shutdown),
            Arc::clone(&self.progress),
            #[cfg(windows)]
            std::mem::take(&mut self.analysis_branches),
        ) {
            Ok(worker) => {
                self.worker = Some(worker);
                Ok(receipt)
            }
            Err(error) => {
                fail_active(lifecycle, &format!("replay worker start failed: {error}"))?;
                Err(error)
            }
        }
    }

    fn stop(
        &mut self,
        lifecycle: &mut DurableRunService,
        command: RunCommand,
    ) -> io::Result<RunReceipt> {
        let receipt = lifecycle.handle(command, 1)?;
        if !receipt.accepted {
            return Ok(receipt);
        }
        let Some(mut worker) = self.worker.take() else {
            return Ok(receipt);
        };
        match worker.finish(ACTION_STOP_AND_SEAL, STOP_DEADLINE) {
            Ok(WorkerCompletion::Sealed(scan)) => {
                let seal = scan
                    .seal
                    .as_ref()
                    .ok_or_else(|| io::Error::other("sealed replay has no seal receipt"))?;
                self.progress
                    .durable
                    .store(scan.durable.durable_record_count, Ordering::Release);
                lifecycle.mark_journal_sealed(seal_evidence_hash(scan.identity.run_id, seal))?;
                Ok(receipt)
            }
            Ok(WorkerCompletion::Failed(message)) => {
                fail_active(lifecycle, &message)?;
                Err(io::Error::other(message))
            }
            Ok(WorkerCompletion::Aborted) => Err(io::Error::other(
                "replay worker aborted during Stop-and-seal",
            )),
            Err(error) => {
                self.worker = Some(worker);
                fail_active(lifecycle, &format!("replay Stop failed: {error}"))?;
                Err(error)
            }
        }
    }

    fn abort(
        &mut self,
        lifecycle: &mut DurableRunService,
        command: RunCommand,
    ) -> io::Result<RunReceipt> {
        let receipt = lifecycle.handle(command, 1)?;
        if !receipt.accepted {
            return Ok(receipt);
        }
        self.prepared = None;
        #[cfg(windows)]
        {
            self.analysis_branches.clear();
        }
        if let Some(mut worker) = self.worker.take() {
            match worker.finish(ACTION_ABORT, STOP_DEADLINE)? {
                WorkerCompletion::Aborted => {}
                WorkerCompletion::Failed(message) => return Err(io::Error::other(message)),
                WorkerCompletion::Sealed(_) => {
                    return Err(io::Error::other("replay worker sealed during Abort"))
                }
            }
        }
        Ok(receipt)
    }

    fn reset_progress(&self, queue_capacity: u64) {
        self.progress.generated.store(0, Ordering::Release);
        self.progress.committed.store(0, Ordering::Release);
        self.progress.durable.store(0, Ordering::Release);
        self.progress.queue_used.store(0, Ordering::Release);
        self.progress
            .queue_capacity
            .store(queue_capacity, Ordering::Release);
        self.progress
            .expected_last_plus_one
            .store(0, Ordering::Release);
        self.progress.analysis_published.store(0, Ordering::Release);
        self.progress.analysis_dropped.store(0, Ordering::Release);
        self.progress.analysis_faulted.store(0, Ordering::Release);
        self.progress
            .fault_evidence_lost
            .store(0, Ordering::Release);
        self.progress
            .discarded_while_paused
            .store(0, Ordering::Release);
    }
}

impl ReplayWorker {
    fn spawn(
        prepared: PreparedReplay,
        owner_shutdown: Arc<AtomicBool>,
        progress: Arc<ReplayProgress>,
        #[cfg(windows)] analysis_branches: Vec<LiveAnalysisBranch>,
    ) -> io::Result<Self> {
        if owner_shutdown.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "replay owner shutdown was requested before worker start",
            ));
        }
        let action = Arc::new(AtomicU8::new(ACTION_RUNNING));
        let paused = Arc::new(AtomicBool::new(false));
        let pause_acknowledged = Arc::new(AtomicBool::new(false));
        let worker_action = Arc::clone(&action);
        let worker_paused = Arc::clone(&paused);
        let worker_pause_acknowledged = Arc::clone(&pause_acknowledged);
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        let join = thread::Builder::new()
            .name("forge-protected-replay".to_owned())
            .spawn(move || {
                let result = run_worker(
                    prepared,
                    worker_action,
                    worker_paused,
                    worker_pause_acknowledged,
                    owner_shutdown,
                    progress,
                    #[cfg(windows)]
                    analysis_branches,
                )
                .unwrap_or_else(|error| WorkerCompletion::Failed(error.to_string()));
                let _ = completion_tx.send(result);
            })?;
        Ok(Self {
            action,
            paused,
            pause_acknowledged,
            completion: completion_rx,
            join: Some(join),
        })
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    fn set_paused(&mut self, paused: bool, progress: &ReplayProgress) -> io::Result<()> {
        if !paused {
            self.pause_acknowledged.store(false, Ordering::Release);
            self.paused.store(false, Ordering::Release);
            return Ok(());
        }
        self.pause_acknowledged.store(false, Ordering::Release);
        self.paused.store(true, Ordering::Release);
        let deadline = std::time::Instant::now() + PAUSE_DRAIN_DEADLINE;
        while !self.pause_acknowledged.load(Ordering::Acquire)
            || progress.queue_used.load(Ordering::Acquire) != 0
        {
            if self.action.load(Ordering::Acquire) != ACTION_RUNNING {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "recording stopped while pause was draining queued records",
                ));
            }
            if std::time::Instant::now() >= deadline {
                self.paused.store(false, Ordering::Release);
                self.pause_acknowledged.store(false, Ordering::Release);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "recording pause could not drain the write queue before its deadline",
                ));
            }
            thread::park_timeout(BACKPRESSURE_POLL_INTERVAL);
        }
        Ok(())
    }

    fn finish(&mut self, action: u8, timeout: Duration) -> io::Result<WorkerCompletion> {
        self.action.store(action, Ordering::Release);
        let completion = self.completion.recv_timeout(timeout).map_err(|error| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("replay worker did not finish before deadline: {error}"),
            )
        })?;
        self.join()?;
        Ok(completion)
    }

    fn join(&mut self) -> io::Result<()> {
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| io::Error::other("replay worker panicked"))?;
        }
        Ok(())
    }
}

fn run_worker(
    prepared: PreparedReplay,
    action: Arc<AtomicU8>,
    paused: Arc<AtomicBool>,
    pause_acknowledged: Arc<AtomicBool>,
    owner_shutdown: Arc<AtomicBool>,
    progress: Arc<ReplayProgress>,
    #[cfg(windows)] mut analysis_branches: Vec<LiveAnalysisBranch>,
) -> io::Result<WorkerCompletion> {
    let stream = prepared.stream.clone();
    #[cfg(test)]
    let durability_batch = stream.durability_batch;
    #[cfg(not(test))]
    let durability_batch = DEFAULT_DURABILITY_BATCH;
    let mut sources = stream
        .pod_ids
        .iter()
        .enumerate()
        .map(|(index, pod_id)| {
            let headstage_hash = sha256(pod_id);
            let mut headstage_id = [0_u8; 16];
            headstage_id.copy_from_slice(&headstage_hash[..16]);
            let mut seed_bytes = [0_u8; 8];
            seed_bytes.copy_from_slice(&pod_id[..8]);
            DeterministicReplaySource::new(DeterministicReplayConfig {
                run_id: prepared.run_id,
                pod_id: *pod_id,
                headstage_id,
                channel_layout_id: u32::try_from(index + 1).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Pod layout index overflow")
                })?,
                channel_count: stream.channel_count,
                samples_per_channel: stream.samples_per_channel,
                sample_rate_hz: stream.sample_rate_hz,
                total_records: u64::MAX,
                seed: u64::from_le_bytes(seed_bytes) ^ 0x464f_5247_4552_504c,
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let pool = BoundedBufferPool::new(stream.queue_capacity + 1, stream.encoded_capacity()?)?;
    let (record_tx, record_rx) = mpsc::sync_channel::<PooledBuffer>(stream.queue_capacity);
    let producer_action = Arc::clone(&action);
    let producer_owner_shutdown = Arc::clone(&owner_shutdown);
    let producer_progress = Arc::clone(&progress);
    let consumer_failed = Arc::new(AtomicBool::new(false));
    let producer_consumer_failed = Arc::clone(&consumer_failed);
    let producer_error = Arc::new(Mutex::new(None::<String>));
    let producer_error_thread = Arc::clone(&producer_error);
    let producer = thread::Builder::new()
        .name("forge-protected-replay-source".to_owned())
        .spawn(move || {
            if let Err(error) = run_replay_producer(
                &mut sources,
                &pool,
                &record_tx,
                &producer_action,
                &paused,
                &pause_acknowledged,
                &producer_owner_shutdown,
                &producer_consumer_failed,
                &producer_progress,
            ) {
                if let Ok(mut slot) = producer_error_thread.lock() {
                    *slot = Some(error.to_string());
                }
            }
        })?;

    let mut writer = prepared.writer;
    #[cfg(windows)]
    let analysis_clock_origin = Instant::now();
    let writer_result = (|| -> io::Result<()> {
        while let Ok(record) = record_rx.recv() {
            writer.append_record(record.as_slice())?;
            let committed = progress.committed.fetch_add(1, Ordering::AcqRel) + 1;
            #[cfg(windows)]
            analysis_branches.retain_mut(|branch| {
                let observed_monotonic_ns =
                    u64::try_from(analysis_clock_origin.elapsed().as_nanos())
                        .unwrap_or(u64::MAX)
                        .saturating_add(1);
                let publish =
                    branch.publish(record.as_slice(), committed - 1, observed_monotonic_ns);
                if branch.fault_route.is_degraded() {
                    progress.analysis_faulted.store(1, Ordering::Release);
                }
                if branch.fault_route.fault_evidence_snapshot().evidence_lost() {
                    progress.fault_evidence_lost.store(1, Ordering::Release);
                }
                match publish {
                    Ok(_) => {
                        progress.analysis_published.fetch_add(1, Ordering::AcqRel);
                        true
                    }
                    Err(AnalysisRingError::Full) => {
                        progress.analysis_dropped.fetch_add(1, Ordering::AcqRel);
                        progress.analysis_faulted.store(1, Ordering::Release);
                        true
                    }
                    Err(_) => {
                        progress.analysis_dropped.fetch_add(1, Ordering::AcqRel);
                        progress.analysis_faulted.store(1, Ordering::Release);
                        false
                    }
                }
            });
            progress
                .expected_last_plus_one
                .store(committed, Ordering::Release);
            // Keep the logical queue slot occupied until the record is actually
            // committed. Pause waits for this watermark after the producer has
            // acknowledged the request, so its success reply is also the exact
            // storage-write boundary.
            release_replay_queue_slot(&progress)?;
            if committed.is_multiple_of(durability_batch) {
                #[cfg(test)]
                thread::sleep(stream.durability_barrier_delay);
                let checkpoint = writer.durability_barrier()?;
                progress
                    .durable
                    .store(checkpoint.durable_record_count, Ordering::Release);
            }
        }
        Ok(())
    })();
    if writer_result.is_err() {
        consumer_failed.store(true, Ordering::Release);
        action.store(ACTION_ABORT, Ordering::Release);
    }
    drop(record_rx);
    producer
        .join()
        .map_err(|_| io::Error::other("replay source panicked"))?;
    writer_result?;
    if let Some(error) = producer_error
        .lock()
        .map_err(|_| io::Error::other("replay source error mutex poisoned"))?
        .take()
    {
        return Err(io::Error::other(error));
    }
    let action = if owner_shutdown.load(Ordering::Acquire) {
        ACTION_ABORT
    } else {
        action.load(Ordering::Acquire)
    };
    let committed = progress.committed.load(Ordering::Acquire);
    match action {
        ACTION_STOP_AND_SEAL => {
            let scan = writer.seal(committed.checked_sub(1))?;
            Ok(WorkerCompletion::Sealed(scan))
        }
        ACTION_ABORT => {
            let checkpoint = writer.durability_barrier()?;
            progress
                .durable
                .store(checkpoint.durable_record_count, Ordering::Release);
            Ok(WorkerCompletion::Aborted)
        }
        _ => Err(io::Error::other(
            "replay source stopped without Stop or Abort action",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_replay_producer(
    sources: &mut [DeterministicReplaySource],
    pool: &BoundedBufferPool,
    record_tx: &mpsc::SyncSender<PooledBuffer>,
    action: &AtomicU8,
    paused: &AtomicBool,
    pause_acknowledged: &AtomicBool,
    owner_shutdown: &AtomicBool,
    consumer_failed: &AtomicBool,
    progress: &ReplayProgress,
) -> io::Result<()> {
    while action.load(Ordering::Acquire) == ACTION_RUNNING
        && !owner_shutdown.load(Ordering::Acquire)
    {
        if paused.load(Ordering::Acquire) {
            pause_acknowledged.store(true, Ordering::Release);
            for source in sources.iter_mut() {
                source.skip_next_record()?;
                progress
                    .discarded_while_paused
                    .fetch_add(1, Ordering::AcqRel);
            }
            thread::sleep(Duration::from_millis(1));
            continue;
        }
        // One complete round emits exactly one 1 ms SampleBlock for every
        // selected Pod. Stop and Abort are observed only between rounds. A
        // transiently full journal queue therefore applies bounded
        // backpressure; it never drops a block or truncates a multi-Pod round.
        for source in sources.iter_mut() {
            reserve_replay_queue_slot(progress, consumer_failed)?;

            let build = (|| {
                let encoded = source.next_encoded_record()?.ok_or_else(|| {
                    io::Error::other("deterministic replay source ended unexpectedly")
                })?;
                let mut buffer = pool.try_acquire()?.ok_or_else(|| {
                    io::Error::other(
                        "replay buffer-pool accounting contradiction after queue reservation",
                    )
                })?;
                buffer.try_extend_from_slice(&encoded)?;
                Ok::<_, io::Error>(buffer)
            })();
            let buffer = match build {
                Ok(buffer) => buffer,
                Err(error) => {
                    release_replay_queue_slot(progress)?;
                    return Err(error);
                }
            };

            match record_tx.try_send(buffer) {
                Ok(()) => {
                    progress.generated.fetch_add(1, Ordering::AcqRel);
                }
                Err(mpsc::TrySendError::Full(_)) => {
                    release_replay_queue_slot(progress)?;
                    return Err(io::Error::other(
                        "replay queue accounting contradiction after slot reservation",
                    ));
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    release_replay_queue_slot(progress)?;
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "replay journal consumer disconnected",
                    ));
                }
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

fn reserve_replay_queue_slot(
    progress: &ReplayProgress,
    consumer_failed: &AtomicBool,
) -> io::Result<()> {
    let capacity = progress.queue_capacity.load(Ordering::Acquire);
    if capacity == 0 {
        return Err(io::Error::other("replay queue capacity is unavailable"));
    }
    loop {
        if consumer_failed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "replay journal consumer failed during backpressure",
            ));
        }
        let used = progress.queue_used.load(Ordering::Acquire);
        if used < capacity
            && progress
                .queue_used
                .compare_exchange_weak(used, used + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return Ok(());
        }
        thread::park_timeout(BACKPRESSURE_POLL_INTERVAL);
    }
}

fn release_replay_queue_slot(progress: &ReplayProgress) -> io::Result<()> {
    progress
        .queue_used
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_sub(1)
        })
        .map(|_| ())
        .map_err(|_| io::Error::other("replay queue watermark underflow"))
}

fn fail_active(lifecycle: &mut DurableRunService, message: &str) -> io::Result<()> {
    if matches!(
        lifecycle.status().state,
        RunState::Prepared | RunState::Armed | RunState::Recording | RunState::Stopped
    ) {
        lifecycle.fail_closed(FAULT_INTERNAL_PERSISTENCE, sha256(message.as_bytes()))?;
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_protocol_v1::{RunCommandV1, SampleBlockV1};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(windows)]
    use crate::analysis_mapping::{AnalysisMappingConfig, MappedAnalysisRing};
    #[cfg(windows)]
    use crate::ipc::current_process_user_sid;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "forge-service-replay-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn command(id: u64, kind: RunCommandKind) -> RunCommand {
        command_for_run(id, kind, [0x61; 16])
    }

    fn command_for_run(id: u64, kind: RunCommandKind, run_id: [u8; 16]) -> RunCommand {
        RunCommand {
            request_id: id,
            epoch: 1,
            body: RunCommandV1 {
                command: kind.wire_value(),
                scope: 1,
                run_id,
                target_device_id: [0x62; 16],
                deadline_global_time_ns: u64::MAX,
                frozen_config_hash: [0x63; 32],
            },
        }
    }

    #[test]
    fn stop_and_abort_preserve_complete_multi_pod_round_under_backpressure() {
        for requested_action in [ACTION_STOP_AND_SEAL, ACTION_ABORT] {
            let pod_ids = [[0x51; 16], [0x52; 16]];
            let mut sources = pod_ids
                .iter()
                .enumerate()
                .map(|(index, pod_id)| {
                    DeterministicReplaySource::new(DeterministicReplayConfig {
                        run_id: [0x61; 16],
                        pod_id: *pod_id,
                        headstage_id: [0x48 + index as u8; 16],
                        channel_layout_id: (index + 1) as u32,
                        channel_count: 1,
                        samples_per_channel: 30,
                        sample_rate_hz: 30_000,
                        total_records: u64::MAX,
                        seed: 81 + index as u64,
                    })
                })
                .collect::<io::Result<Vec<_>>>()
                .unwrap();
            let pool = BoundedBufferPool::new(2, RECORD_HEADER_LEN + 32 + 60).unwrap();
            let (record_tx, record_rx) = mpsc::sync_channel::<PooledBuffer>(1);
            let action = Arc::new(AtomicU8::new(ACTION_RUNNING));
            let paused = Arc::new(AtomicBool::new(false));
            let pause_acknowledged = Arc::new(AtomicBool::new(false));
            let owner_shutdown = Arc::new(AtomicBool::new(false));
            let consumer_failed = Arc::new(AtomicBool::new(false));
            let progress = Arc::new(ReplayProgress::default());
            progress.queue_capacity.store(1, Ordering::Release);

            let producer_action = Arc::clone(&action);
            let producer_owner_shutdown = Arc::clone(&owner_shutdown);
            let producer_consumer_failed = Arc::clone(&consumer_failed);
            let producer_progress = Arc::clone(&progress);
            let producer_pool = pool.clone();
            let producer = thread::spawn(move || {
                run_replay_producer(
                    &mut sources,
                    &producer_pool,
                    &record_tx,
                    &producer_action,
                    &paused,
                    &pause_acknowledged,
                    &producer_owner_shutdown,
                    &producer_consumer_failed,
                    &producer_progress,
                )
            });

            let wait_deadline = std::time::Instant::now() + Duration::from_secs(1);
            while progress.generated.load(Ordering::Acquire) == 0
                && std::time::Instant::now() < wait_deadline
            {
                thread::yield_now();
            }
            assert_eq!(progress.generated.load(Ordering::Acquire), 1);
            assert_eq!(progress.queue_used.load(Ordering::Acquire), 1);
            assert!(!producer.is_finished());

            // Request termination while Pod 2 is waiting behind the one-slot
            // queue. The producer must finish Pod 2 rather than treating the
            // transient backpressure as loss or sealing a partial round.
            action.store(requested_action, Ordering::Release);
            let mut observed_pods = Vec::new();
            for _ in 0..pod_ids.len() {
                let record = record_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                release_replay_queue_slot(&progress).unwrap();
                observed_pods.push(
                    forge_protocol_v1::decode_record(record.as_slice())
                        .unwrap()
                        .envelope
                        .pod_id,
                );
            }
            assert!(producer.join().unwrap().is_ok());
            assert_eq!(observed_pods, pod_ids);
            assert_eq!(progress.generated.load(Ordering::Acquire), 2);
            assert_eq!(progress.queue_used.load(Ordering::Acquire), 0);
            assert_eq!(pool.snapshot().unwrap().checked_out, 0);
        }
    }

    #[test]
    fn durability_barrier_backpressure_drains_and_seals_without_record_loss() {
        let root = TempRoot::new();
        let mut lifecycle = DurableRunService::open(root.0.join("run.ledger")).unwrap();
        let pod_ids = vec![[0x51; 16], [0x52; 16]];
        let mut replay = ProtectedReplaySession::new_operator_software(
            &root.0,
            [0x61; 16],
            [0x62; 16],
            [0x63; 32],
            pod_ids.clone(),
        )
        .unwrap();
        replay.stream.queue_capacity = 1;
        replay.stream.durability_batch = 1;
        replay.stream.durability_barrier_delay = Duration::from_millis(100);

        for (id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
        ] {
            assert!(
                replay
                    .handle_command(&mut lifecycle, command(id, kind))
                    .unwrap()
                    .accepted
            );
        }

        let wait_deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let progress = replay.progress();
            if progress.committed_record_count == Some(1) && progress.queue_used_slots == Some(1) {
                break;
            }
            assert!(
                std::time::Instant::now() < wait_deadline,
                "writer did not enter the forced durability-barrier backpressure window"
            );
            thread::yield_now();
        }

        assert!(
            replay
                .handle_command(&mut lifecycle, command(4, RunCommandKind::Stop))
                .unwrap()
                .accepted
        );
        assert_eq!(lifecycle.status().state, RunState::JournalSealed);
        let progress = replay.progress();
        assert_eq!(
            progress.generated_record_count,
            progress.committed_record_count
        );
        assert_eq!(
            progress.committed_record_count,
            progress.durable_record_count
        );
        assert_eq!(progress.queue_used_slots, Some(0));

        let records = crate::journal::JournalReader::open_sealed(root.0.join("run.forgewal"))
            .unwrap()
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        assert!(!records.is_empty());
        assert_eq!(records.len() % pod_ids.len(), 0);
        for round in records.chunks_exact(pod_ids.len()) {
            assert_eq!(round[0].canonical.envelope.pod_id, pod_ids[0]);
            assert_eq!(round[1].canonical.envelope.pod_id, pod_ids[1]);
        }
    }

    #[test]
    fn operator_pause_drains_then_discards_live_intervals_until_resume() {
        let root = TempRoot::new();
        let mut lifecycle = DurableRunService::open(root.0.join("run.ledger")).unwrap();
        let mut replay = ProtectedReplaySession::new_operator_software(
            &root.0,
            [0x61; 16],
            [0x62; 16],
            [0x63; 32],
            vec![[0x51; 16]],
        )
        .unwrap();
        for (id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
        ] {
            assert!(
                replay
                    .handle_command(&mut lifecycle, command(id, kind))
                    .unwrap()
                    .accepted
            );
        }
        thread::sleep(Duration::from_millis(10));
        let pause = replay.set_operator_paused(&lifecycle, 1, [0x61; 16], true);
        assert!(pause.accepted);
        assert!(pause.paused);
        let committed_at_pause = replay.progress().committed_record_count.unwrap();
        thread::sleep(Duration::from_millis(10));
        assert_eq!(
            replay.progress().committed_record_count,
            Some(committed_at_pause)
        );

        let resume = replay.set_operator_paused(&lifecycle, 1, [0x61; 16], false);
        assert!(resume.accepted);
        assert!(!resume.paused);
        assert!(resume.discarded_record_count > 0);
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while replay.progress().committed_record_count == Some(committed_at_pause) {
            assert!(std::time::Instant::now() < deadline);
            thread::yield_now();
        }
        assert!(
            replay
                .handle_command(&mut lifecycle, command(4, RunCommandKind::Stop))
                .unwrap()
                .accepted
        );

        let records = crate::journal::JournalReader::open_sealed(root.0.join("run.forgewal"))
            .unwrap()
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        assert!(records.iter().any(|record| {
            record.canonical.envelope.flags & forge_protocol_v1::RECORD_FLAG_DISCONTINUITY_BEFORE
                != 0
        }));
    }

    #[cfg(windows)]
    fn mapping_name(label: &str) -> String {
        format!(
            r"Local\ForgeAnalysisRing-{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[cfg(windows)]
    fn analysis_source(run_id: [u8; 16], total_records: u64) -> DeterministicReplaySource {
        DeterministicReplaySource::new(DeterministicReplayConfig {
            run_id,
            pod_id: [0x50; 16],
            headstage_id: [0x48; 16],
            channel_layout_id: 1,
            channel_count: 1,
            samples_per_channel: ((DEFAULT_PAYLOAD_BYTES - 32) / 2) as u32,
            sample_rate_hz: 30_000,
            total_records,
            seed: 81,
        })
        .unwrap()
    }

    #[cfg(windows)]
    #[test]
    fn journal_commit_fans_out_to_live_mapping_without_becoming_a_gate() {
        let root = TempRoot::new();
        let mut lifecycle = DurableRunService::open(root.0.join("ledger")).unwrap();
        let mut replay = ProtectedReplaySession::new(&root.0).unwrap();
        let name = mapping_name("replay-fanout");
        let sid = current_process_user_sid().unwrap();
        let producer = MappedAnalysisRing::create_test(
            &name,
            &sid,
            AnalysisMappingConfig {
                slot_count: 64,
                payload_capacity: RECORD_HEADER_LEN + DEFAULT_PAYLOAD_BYTES,
                run_id: [0x61; 16],
                consumer_id: [0x71; 16],
                producer_epoch: 1,
            },
        )
        .unwrap();
        let mut consumer = MappedAnalysisRing::open(&name, [0x61; 16], [0x71; 16], 1).unwrap();
        replay.attach_analysis_mapping(producer).unwrap();
        for (id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
        ] {
            assert!(
                replay
                    .handle_command(&mut lifecycle, command(id, kind))
                    .unwrap()
                    .accepted
            );
        }
        thread::sleep(Duration::from_millis(15));
        assert!(
            replay
                .handle_command(&mut lifecycle, command(4, RunCommandKind::Stop))
                .unwrap()
                .accepted
        );
        let progress = replay.progress();
        let mut received = 0_u64;
        while consumer.try_consume(10_000 + received).unwrap().is_some() {
            received += 1;
        }
        assert_eq!(progress.analysis_published_record_count, Some(received));
        assert_eq!(progress.analysis_dropped_record_count, Some(0));
        assert_eq!(progress.analysis_faulted, Some(false));
        assert_eq!(progress.fault_evidence_lost, Some(false));
        assert_eq!(progress.committed_record_count, Some(received));
        assert_eq!(consumer.fault_flags(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn analysis_mapping_identity_mismatch_is_rejected_before_prepare() {
        let root = TempRoot::new();
        let mut lifecycle = DurableRunService::open(root.0.join("ledger")).unwrap();
        let mut replay = ProtectedReplaySession::new(&root.0).unwrap();
        let name = mapping_name("wrong-run");
        let sid = current_process_user_sid().unwrap();
        let producer = MappedAnalysisRing::create_test(
            &name,
            &sid,
            AnalysisMappingConfig {
                slot_count: 2,
                payload_capacity: RECORD_HEADER_LEN + DEFAULT_PAYLOAD_BYTES,
                run_id: [0x72; 16],
                consumer_id: [0x71; 16],
                producer_epoch: 1,
            },
        )
        .unwrap();
        replay.attach_analysis_mapping(producer).unwrap();
        let receipt = replay
            .handle_command(&mut lifecycle, command(1, RunCommandKind::Prepare))
            .unwrap();
        assert!(!receipt.accepted);
        assert_eq!(receipt.reason, "analysis mapping Run identity mismatch");
        assert_eq!(lifecycle.status().state, RunState::New);
    }

    #[cfg(windows)]
    #[test]
    fn full_analysis_branch_latches_drop_but_journal_still_seals() {
        let root = TempRoot::new();
        let mut lifecycle = DurableRunService::open(root.0.join("ledger")).unwrap();
        let mut replay = ProtectedReplaySession::new(&root.0).unwrap();
        let name = mapping_name("drop-isolated");
        let sid = current_process_user_sid().unwrap();
        let producer = MappedAnalysisRing::create_test(
            &name,
            &sid,
            AnalysisMappingConfig {
                slot_count: 2,
                payload_capacity: RECORD_HEADER_LEN + DEFAULT_PAYLOAD_BYTES,
                run_id: [0x61; 16],
                consumer_id: [0x71; 16],
                producer_epoch: 1,
            },
        )
        .unwrap();
        replay.attach_analysis_mapping(producer).unwrap();
        for (id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
        ] {
            assert!(
                replay
                    .handle_command(&mut lifecycle, command(id, kind))
                    .unwrap()
                    .accepted
            );
        }
        thread::sleep(Duration::from_millis(15));
        assert!(
            replay
                .handle_command(&mut lifecycle, command(4, RunCommandKind::Stop))
                .unwrap()
                .accepted
        );
        let progress = replay.progress();
        assert_eq!(lifecycle.status().state, RunState::JournalSealed);
        assert_eq!(progress.analysis_published_record_count, Some(2));
        assert!(progress.analysis_dropped_record_count.unwrap_or_default() > 0);
        assert_eq!(progress.analysis_faulted, Some(true));
        assert_eq!(progress.fault_evidence_lost, Some(false));
        assert!(progress.committed_record_count.unwrap_or_default() > 2);
        assert_eq!(
            progress.committed_record_count,
            progress.durable_record_count
        );
    }

    #[cfg(windows)]
    #[test]
    fn controller_ring_full_disarms_before_drop_and_journal_still_seals() {
        let root = TempRoot::new();
        let mut lifecycle = DurableRunService::open(root.0.join("ledger")).unwrap();
        let mut replay = ProtectedReplaySession::new(&root.0).unwrap();
        let (arbiter, _intent, route) = crate::safety_arbiter::tests::armed_with_route_capacity(1);
        route.prefill_fault_evidence_for_test();
        let identity = route.identity();
        let name = mapping_name("controller-drop-isolated");
        let sid = current_process_user_sid().unwrap();
        let producer = MappedAnalysisRing::create_test(
            &name,
            &sid,
            AnalysisMappingConfig {
                slot_count: 2,
                payload_capacity: RECORD_HEADER_LEN + DEFAULT_PAYLOAD_BYTES,
                run_id: identity.run_id(),
                consumer_id: identity.consumer_id(),
                producer_epoch: identity.producer_epoch(),
            },
        )
        .unwrap();
        replay
            .attach_analysis_mapping_with_fault_route(producer, route)
            .unwrap();
        for (id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
        ] {
            assert!(
                replay
                    .handle_command(&mut lifecycle, command_for_run(id, kind, identity.run_id()),)
                    .unwrap()
                    .accepted
            );
        }
        thread::sleep(Duration::from_millis(15));
        assert!(
            replay
                .handle_command(
                    &mut lifecycle,
                    command_for_run(4, RunCommandKind::Stop, identity.run_id()),
                )
                .unwrap()
                .accepted
        );
        let progress = replay.progress();
        assert_eq!(
            arbiter.state(),
            crate::safety_arbiter::ArbiterState::FaultLatched
        );
        assert_eq!(
            arbiter.last_disarm_reason(),
            Some(crate::safety_arbiter::DisarmReason::Overflow)
        );
        assert_eq!(lifecycle.status().state, RunState::JournalSealed);
        assert_eq!(progress.analysis_published_record_count, Some(2));
        assert!(progress.analysis_dropped_record_count.unwrap_or_default() > 0);
        assert_eq!(progress.fault_evidence_lost, Some(true));
        assert!(progress.committed_record_count.unwrap_or_default() > 2);
        assert_eq!(
            progress.committed_record_count,
            progress.durable_record_count
        );
    }

    #[cfg(windows)]
    #[test]
    fn controller_gap_and_source_crc_flags_use_the_same_fault_route() {
        for crc_case in [false, true] {
            let (arbiter, _intent, route) = crate::safety_arbiter::tests::armed_with_route();
            let identity = route.identity();
            let name = mapping_name(if crc_case {
                "source-crc"
            } else {
                "continuity-gap"
            });
            let sid = current_process_user_sid().unwrap();
            let mapping = MappedAnalysisRing::create_test(
                &name,
                &sid,
                AnalysisMappingConfig {
                    slot_count: 4,
                    payload_capacity: RECORD_HEADER_LEN + DEFAULT_PAYLOAD_BYTES,
                    run_id: identity.run_id(),
                    consumer_id: identity.consumer_id(),
                    producer_epoch: identity.producer_epoch(),
                },
            )
            .unwrap();
            let mut branch = LiveAnalysisBranch::new(mapping, route).unwrap();
            let mut source = analysis_source(identity.run_id(), 2);
            let first = source.next_encoded_record().unwrap().unwrap();
            branch.publish(&first, 0, 1).unwrap();
            if crc_case {
                let decoded =
                    decode_record(&source.next_encoded_record().unwrap().unwrap()).unwrap();
                let mut envelope = decoded.envelope;
                envelope.flags |= RECORD_FLAG_SOURCE_CRC_ERROR;
                let flagged =
                    forge_protocol_v1::encode_record(&envelope, &decoded.payload).unwrap();
                branch.publish(&flagged, 1, 2).unwrap();
                assert_eq!(
                    arbiter.last_disarm_reason(),
                    Some(crate::safety_arbiter::DisarmReason::SourceCrc)
                );
            } else {
                let second = source.next_encoded_record().unwrap().unwrap();
                branch.publish(&second, 2, 2).unwrap();
                assert_eq!(
                    arbiter.last_disarm_reason(),
                    Some(crate::safety_arbiter::DisarmReason::DataGap)
                );
            }
            assert_eq!(
                arbiter.state(),
                crate::safety_arbiter::ArbiterState::FaultLatched
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn controller_route_cannot_be_reused_for_a_second_mapping() {
        let (_arbiter, _intent, route) = crate::safety_arbiter::tests::armed_with_route();
        let identity = route.identity();
        let sid = current_process_user_sid().unwrap();
        let config = AnalysisMappingConfig {
            slot_count: 2,
            payload_capacity: RECORD_HEADER_LEN + DEFAULT_PAYLOAD_BYTES,
            run_id: identity.run_id(),
            consumer_id: identity.consumer_id(),
            producer_epoch: identity.producer_epoch(),
        };
        let first =
            MappedAnalysisRing::create_test(&mapping_name("single-route-a"), &sid, config).unwrap();
        let second =
            MappedAnalysisRing::create_test(&mapping_name("single-route-b"), &sid, config).unwrap();
        let _bound = LiveAnalysisBranch::new(first, Arc::clone(&route)).unwrap();
        assert_eq!(
            LiveAnalysisBranch::new(second, route).err().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[cfg(windows)]
    #[test]
    fn dropping_observer_mapping_does_not_revoke_live_controller() {
        let (mut arbiter, intent, controller_route) =
            crate::safety_arbiter::tests::armed_with_route();
        let controller_identity = controller_route.identity();
        let sid = current_process_user_sid().unwrap();
        let controller_mapping = MappedAnalysisRing::create_test(
            &mapping_name("observer-drop-controller"),
            &sid,
            AnalysisMappingConfig {
                slot_count: 4,
                payload_capacity: 1024,
                run_id: controller_identity.run_id(),
                consumer_id: controller_identity.consumer_id(),
                producer_epoch: controller_identity.producer_epoch(),
            },
        )
        .unwrap();
        let controller = LiveAnalysisBranch::new(controller_mapping, controller_route).unwrap();

        let observer_identity = AnalysisBranchIdentityV1::new(
            controller_identity.run_id(),
            [0x91; 16],
            controller_identity.producer_epoch(),
        )
        .unwrap();
        let observer_mapping = MappedAnalysisRing::create_test(
            &mapping_name("observer-drop-observer"),
            &sid,
            AnalysisMappingConfig {
                slot_count: 4,
                payload_capacity: 1024,
                run_id: observer_identity.run_id(),
                consumer_id: observer_identity.consumer_id(),
                producer_epoch: observer_identity.producer_epoch(),
            },
        )
        .unwrap();
        let observer = LiveAnalysisBranch::new(
            observer_mapping,
            AnalysisBranchFaultRoute::observer(observer_identity),
        )
        .unwrap();
        drop(observer);
        assert_eq!(arbiter.state(), crate::safety_arbiter::ArbiterState::Armed);
        assert!(arbiter.submit_intent(&intent, 10_000).is_ok());
        drop(controller);
    }

    #[test]
    fn service_replay_runs_in_background_then_durably_seals() {
        let root = TempRoot::new();
        let mut lifecycle = DurableRunService::open(root.0.join("ledger")).unwrap();
        let mut replay = ProtectedReplaySession::new(&root.0).unwrap();
        for (id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
        ] {
            assert!(
                replay
                    .handle_command(&mut lifecycle, command(id, kind))
                    .unwrap()
                    .accepted
            );
        }
        thread::sleep(Duration::from_millis(15));
        let progress = replay.progress();
        assert!(progress.generated_record_count.unwrap_or_default() > 0);
        assert!(
            replay
                .handle_command(&mut lifecycle, command(4, RunCommandKind::Stop))
                .unwrap()
                .accepted
        );
        assert_eq!(lifecycle.status().state, RunState::JournalSealed);
        assert_eq!(
            replay.progress().committed_record_count,
            replay.progress().durable_record_count
        );
        let journal = root.0.join(format!("run-{}.forgewal", hex(&[0x61; 16])));
        assert!(
            crate::journal::JournalReader::open_sealed(journal)
                .unwrap()
                .count()
                > 0
        );
    }

    #[test]
    fn operator_replay_round_robins_eight_32_channel_pods_into_fixed_journal() {
        let root = TempRoot::new();
        let ledger = root.0.join("run.ledger");
        let mut lifecycle = DurableRunService::open(&ledger).unwrap();
        let pod_ids = (0_u8..8)
            .map(|index| [0x50 + index; 16])
            .collect::<Vec<_>>();
        let mut replay = ProtectedReplaySession::new_operator_software(
            &root.0,
            [0x61; 16],
            [0x62; 16],
            [0x63; 32],
            pod_ids.clone(),
        )
        .unwrap();
        for (id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
        ] {
            assert!(
                replay
                    .handle_command(&mut lifecycle, command(id, kind))
                    .unwrap()
                    .accepted
            );
        }
        thread::sleep(Duration::from_millis(15));
        assert!(
            replay
                .handle_command(&mut lifecycle, command(4, RunCommandKind::Stop))
                .unwrap()
                .accepted
        );
        assert_eq!(lifecycle.status().state, RunState::JournalSealed);
        assert_eq!(
            replay.progress().committed_record_count,
            replay.progress().durable_record_count
        );
        let records = crate::journal::JournalReader::open_sealed(root.0.join("run.forgewal"))
            .unwrap()
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        assert!(!records.is_empty());
        assert_eq!(records.len() % pod_ids.len(), 0);
        let mut per_pod = HashMap::<[u8; 16], usize>::new();
        for record in records {
            let block = SampleBlockV1::decode(&record.canonical.payload).unwrap();
            assert_eq!(block.channel_count, 32);
            assert_eq!(block.samples_per_channel, 30);
            assert_eq!(block.sample_rate_numerator_hz, 30_000);
            assert_eq!(block.sample_rate_denominator, 1);
            *per_pod.entry(record.canonical.envelope.pod_id).or_default() += 1;
        }
        assert_eq!(per_pod.len(), 8);
        let records_per_pod = per_pod[&pod_ids[0]];
        assert!(records_per_pod > 0);
        assert!(pod_ids
            .iter()
            .all(|pod_id| per_pod[pod_id] == records_per_pod));
    }

    #[test]
    fn operator_replay_rejects_prepare_outside_reserved_context() {
        let root = TempRoot::new();
        let mut lifecycle = DurableRunService::open(root.0.join("run.ledger")).unwrap();
        let mut replay = ProtectedReplaySession::new_operator_software(
            &root.0,
            [0x61; 16],
            [0x62; 16],
            [0x63; 32],
            vec![[0x50; 16]],
        )
        .unwrap();
        let mut wrong = command(1, RunCommandKind::Prepare);
        wrong.body.frozen_config_hash = [0x64; 32];
        let receipt = replay.handle_command(&mut lifecycle, wrong).unwrap();
        assert!(!receipt.accepted);
        assert_eq!(lifecycle.status().state, RunState::New);
        assert!(!root.0.join("run.forgewal").exists());
    }

    #[test]
    fn scm_shutdown_aborts_worker_and_durably_latches_failure() {
        let root = TempRoot::new();
        let ledger = root.0.join("ledger");
        let mut lifecycle = DurableRunService::open(&ledger).unwrap();
        let mut replay = ProtectedReplaySession::new(&root.0).unwrap();
        for (id, kind) in [
            (1, RunCommandKind::Prepare),
            (2, RunCommandKind::Arm),
            (3, RunCommandKind::Start),
        ] {
            assert!(
                replay
                    .handle_command(&mut lifecycle, command(id, kind))
                    .unwrap()
                    .accepted
            );
        }
        thread::sleep(Duration::from_millis(5));
        replay.shutdown(&mut lifecycle).unwrap();
        assert_eq!(lifecycle.status().state, RunState::Failed);
        drop(lifecycle);
        assert_eq!(
            DurableRunService::open(ledger).unwrap().status().state,
            RunState::Failed
        );
    }
}
