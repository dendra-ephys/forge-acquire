//! Owner-only, non-blocking supervision of an optional NWB materializer.
//!
//! This is deliberately not a process deployment layer.  A production
//! launcher is unavailable until a separately qualified Windows worker/ACL
//! implementation exists; acquisition never waits for this state machine.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::PathBuf;

use forge_protocol_v1::Id16;

use crate::nwb_receipt::{
    verify_nwb_validation_bundle, NwbGenerationValidationReceiptV1, NwbValidationBundlePaths,
    VerifiedNwbGeneration,
};

pub(crate) const MAX_SUPERVISOR_EVENTS: usize = 32;
pub(crate) const MAX_RAPID_CRASHES: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NwbEvidenceSourceV1 {
    UnqualifiedWindowsRuntime,
    WindowsService,
    #[cfg(test)]
    SyntheticTest,
}

/// Capability held only by the service owner's background/control task.
/// Its presence makes it a type error to schedule launch, exit observation,
/// or receipt validation from the acquisition/journal callback path.
pub(crate) struct BackgroundNwbSupervisorToken {
    _private: (),
}

impl BackgroundNwbSupervisorToken {
    pub(crate) fn for_owner_background_task() -> Self {
        Self { _private: () }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NwbSupervisorPathsV1 {
    pub journal: PathBuf,
    pub journal_seal: PathBuf,
    pub checkpoint_a: PathBuf,
    pub checkpoint_b: PathBuf,
    pub generation_root: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NwbGenerationLaunchV1 {
    pub run_id: Id16,
    pub generation: u32,
    pub rebuild_from_journal_sequence: u64,
    pub paths: NwbValidationBundlePaths,
}

pub(crate) trait NwbWorkerHandle: Send {
    fn identity(&self) -> &str;
    fn try_wait(&mut self) -> io::Result<Option<i32>>;
    fn request_stop(&mut self) -> io::Result<()>;
}

pub(crate) trait NwbWorkerLauncher: Send {
    fn launch(&mut self, request: &NwbGenerationLaunchV1) -> io::Result<Box<dyn NwbWorkerHandle>>;
}

/// The only production default until worker process containment is qualified.
pub(crate) struct UnavailableNwbWorkerLauncher;

impl NwbWorkerLauncher for UnavailableNwbWorkerLauncher {
    fn launch(&mut self, _: &NwbGenerationLaunchV1) -> io::Result<Box<dyn NwbWorkerHandle>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NWB worker process launcher is not production-qualified",
        ))
    }
}

pub(crate) trait NwbValidationVerifier: Send {
    fn verify(&mut self, paths: &NwbValidationBundlePaths) -> io::Result<VerifiedNwbGeneration>;
}

pub(crate) struct IndependentNwbValidationVerifier;

impl NwbValidationVerifier for IndependentNwbValidationVerifier {
    fn verify(&mut self, paths: &NwbValidationBundlePaths) -> io::Result<VerifiedNwbGeneration> {
        verify_nwb_validation_bundle(paths)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NwbGenerationStateV1 {
    Idle,
    Running,
    AwaitingOwnerValidation,
    ValidatedUnpublished,
    UnqualifiedGenerationRoot,
    Degraded,
    StopRequestedUnreaped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NwbSupervisorEventV1 {
    Started { generation: u32 },
    WorkerFailed { generation: u32 },
    ValidatedUnpublished { generation: u32 },
    QueueOverflow,
    ShutdownRequested,
}

struct ActiveWorker {
    launch: NwbGenerationLaunchV1,
    identity: String,
    started_ns: u64,
    handle: Box<dyn NwbWorkerHandle>,
}

struct CompletedWorker {
    launch: NwbGenerationLaunchV1,
}

/// No method in this type writes a Run ledger, seals a journal, or publishes
/// an NWB artifact.  It only retains optional worker evidence for the owner.
pub(crate) struct NwbGenerationSupervisorV1<L, V> {
    run_id: Id16,
    paths: NwbSupervisorPathsV1,
    evidence_source: NwbEvidenceSourceV1,
    generation_root_qualified: bool,
    launcher: L,
    verifier: V,
    next_generation: u32,
    state: NwbGenerationStateV1,
    active: Option<ActiveWorker>,
    completed: Option<CompletedWorker>,
    events: VecDeque<NwbSupervisorEventV1>,
    nwb_degraded: bool,
    rapid_crashes: u32,
    latest_validated: Option<NwbGenerationValidationReceiptV1>,
}

impl<L: NwbWorkerLauncher, V: NwbValidationVerifier> NwbGenerationSupervisorV1<L, V> {
    /// Constructs the supervisor in an explicitly unqualified runtime.  It is
    /// owner-internal and cannot start a production generation until a stable
    /// handle/ACL/reparse proof qualifies the generation root.
    pub(crate) fn new_unqualified_owner(
        run_id: Id16,
        paths: NwbSupervisorPathsV1,
        launcher: L,
        verifier: V,
    ) -> io::Result<Self> {
        Self::new_with_owner_source(
            run_id,
            paths,
            NwbEvidenceSourceV1::UnqualifiedWindowsRuntime,
            false,
            launcher,
            verifier,
        )
    }

    /// Reserved for the Windows service owner.  Being the service is not
    /// proof that the root is safe, so this remains fail-closed today.
    pub(crate) fn new_windows_service_owner(
        run_id: Id16,
        paths: NwbSupervisorPathsV1,
        launcher: L,
        verifier: V,
    ) -> io::Result<Self> {
        Self::new_with_owner_source(
            run_id,
            paths,
            NwbEvidenceSourceV1::WindowsService,
            false,
            launcher,
            verifier,
        )
    }

    #[cfg(test)]
    fn new_synthetic(
        run_id: Id16,
        paths: NwbSupervisorPathsV1,
        launcher: L,
        verifier: V,
    ) -> io::Result<Self> {
        Self::new_with_owner_source(
            run_id,
            paths,
            NwbEvidenceSourceV1::SyntheticTest,
            true,
            launcher,
            verifier,
        )
    }

    fn new_with_owner_source(
        run_id: Id16,
        paths: NwbSupervisorPathsV1,
        evidence_source: NwbEvidenceSourceV1,
        generation_root_qualified: bool,
        launcher: L,
        verifier: V,
    ) -> io::Result<Self> {
        if !run_id.iter().any(|byte| *byte != 0)
            || !paths.journal.is_absolute()
            || !paths.journal_seal.is_absolute()
            || !paths.checkpoint_a.is_absolute()
            || !paths.checkpoint_b.is_absolute()
            || !paths.generation_root.is_absolute()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NWB supervisor paths/run are not owner-trusted absolute inputs",
            ));
        }
        let next_generation = generation_cursor(&paths.generation_root)?;
        Ok(Self {
            run_id,
            paths,
            evidence_source,
            generation_root_qualified,
            launcher,
            verifier,
            next_generation,
            state: NwbGenerationStateV1::Idle,
            active: None,
            completed: None,
            events: VecDeque::new(),
            nwb_degraded: false,
            rapid_crashes: 0,
            latest_validated: None,
        })
    }

    pub(crate) fn state(&self) -> NwbGenerationStateV1 {
        self.state
    }
    pub(crate) fn nwb_degraded(&self) -> bool {
        self.nwb_degraded
    }
    pub(crate) fn evidence_source(&self) -> NwbEvidenceSourceV1 {
        self.evidence_source
    }
    pub(crate) fn latest_validated(&self) -> Option<&NwbGenerationValidationReceiptV1> {
        self.latest_validated.as_ref()
    }
    pub(crate) fn active_started_ns(&self) -> Option<u64> {
        self.active.as_ref().map(|active| active.started_ns)
    }
    pub(crate) fn drain_events(&mut self) -> impl Iterator<Item = NwbSupervisorEventV1> + '_ {
        self.events.drain(..)
    }

    pub(crate) fn start_next(
        &mut self,
        _background: &BackgroundNwbSupervisorToken,
        now_ns: u64,
    ) -> io::Result<u32> {
        if self.active.is_some()
            || self.completed.is_some()
            || !matches!(
                self.state,
                NwbGenerationStateV1::Idle | NwbGenerationStateV1::Degraded
            )
            || now_ns == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "NWB generation cannot start in the current owner state",
            ));
        }
        if !self.generation_root_qualified {
            self.nwb_degraded = true;
            self.state = NwbGenerationStateV1::UnqualifiedGenerationRoot;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "UnqualifiedGenerationRoot: {:?} has no stable-handle ACL/reparse proof",
                    self.evidence_source
                ),
            ));
        }
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("NWB generation counter overflow"))?;
        let directory = self
            .paths
            .generation_root
            .join(format!("generation-{generation:08}"));
        fs::create_dir_all(&self.paths.generation_root)?;
        fs::create_dir(&directory)?;
        // The worker, not the supervisor, owns create-new of the payload.
        // A generation-specific name prevents any cross-generation resume.
        let nwb_inprogress = directory.join(format!("run.g{generation:04}.nwb.inprogress"));
        let session_manifest = directory.join(format!("session.g{generation:04}.json"));
        let launch = NwbGenerationLaunchV1 {
            run_id: self.run_id,
            generation,
            rebuild_from_journal_sequence: 0,
            paths: NwbValidationBundlePaths::for_generation(
                directory.join("validation.receipt"),
                self.paths.journal.clone(),
                nwb_inprogress,
                session_manifest,
                directory.join("validation-report.json"),
            ),
        };
        let handle = match self.launcher.launch(&launch) {
            Ok(handle) if !handle.identity().is_empty() => handle,
            Ok(mut handle) => {
                // A returned but unauthenticated process is still evidence we
                // must retain until terminal observation; never drop it.
                let _ = handle.request_stop();
                self.active = Some(ActiveWorker {
                    launch,
                    identity: String::new(),
                    started_ns: now_ns,
                    handle,
                });
                self.state = NwbGenerationStateV1::StopRequestedUnreaped;
                self.nwb_degraded = true;
                return Err(io::Error::other(
                    "NWB worker launched without a stable identity",
                ));
            }
            Err(_) => {
                self.worker_failed(generation);
                return Err(io::Error::other(
                    "NWB worker did not launch with a stable identity",
                ));
            }
        };
        let identity = handle.identity().to_owned();
        self.active = Some(ActiveWorker {
            launch,
            identity,
            started_ns: now_ns,
            handle,
        });
        self.state = NwbGenerationStateV1::Running;
        self.push(NwbSupervisorEventV1::Started { generation });
        Ok(generation)
    }

    /// Non-blockingly observes only an already-started optional worker. This
    /// API is for the owner control thread; it never validates, sleeps, joins,
    /// seals, or feeds back into the acquisition/journal path.
    pub(crate) fn poll_exit(
        &mut self,
        _background: &BackgroundNwbSupervisorToken,
    ) -> io::Result<()> {
        let stop_was_requested = self.state == NwbGenerationStateV1::StopRequestedUnreaped;
        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };
        let exit = match active.handle.try_wait() {
            Ok(Some(exit)) => exit,
            Ok(None) => return Ok(()),
            Err(_) => {
                let generation = active.launch.generation;
                self.active = None;
                self.worker_failed(generation);
                return Ok(());
            }
        };
        let active = self.active.take().expect("active worker checked above");
        if stop_was_requested || exit != 0 || active.identity != active.handle.identity() {
            self.worker_failed(active.launch.generation);
            return Ok(());
        }
        self.completed = Some(CompletedWorker {
            launch: active.launch,
        });
        self.state = NwbGenerationStateV1::AwaitingOwnerValidation;
        Ok(())
    }

    /// Performs the potentially expensive receipt validation only after
    /// `poll_exit` observed a clean worker exit.  The owner must schedule this
    /// on its worker/control path, never on the acquisition/journal thread.
    pub(crate) fn verify_completed_generation(
        &mut self,
        _background: &BackgroundNwbSupervisorToken,
    ) -> io::Result<()> {
        let Some(completed) = self.completed.take() else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no NWB generation is awaiting owner validation",
            ));
        };
        // The worker owns create-new of this artifact. A clean exit without it
        // is not a valid generation, even if a verifier fixture says otherwise.
        if !completed.launch.paths.nwb_inprogress.is_file() {
            self.worker_failed(completed.launch.generation);
            return Ok(());
        }
        let verified = self.verifier.verify(&completed.launch.paths);
        match verified {
            Ok(verified)
                if verified.receipt.run_id == self.run_id
                    && verified.receipt.generation == completed.launch.generation
                    && !verified.publication_authorized =>
            {
                self.latest_validated = Some(verified.receipt);
                self.state = NwbGenerationStateV1::ValidatedUnpublished;
                self.push(NwbSupervisorEventV1::ValidatedUnpublished {
                    generation: completed.launch.generation,
                });
            }
            _ => self.worker_failed(completed.launch.generation),
        }
        Ok(())
    }

    pub(crate) fn shutdown_worker_only(&mut self) {
        if let Some(active) = self.active.as_mut() {
            let _ = active.handle.request_stop();
        }
        // No production Job/reap contract exists. Retain the handle and block
        // a new generation until poll_exit observes terminal state.
        self.nwb_degraded = true;
        self.state = NwbGenerationStateV1::StopRequestedUnreaped;
        self.push(NwbSupervisorEventV1::ShutdownRequested);
    }

    fn worker_failed(&mut self, generation: u32) {
        self.rapid_crashes = self.rapid_crashes.saturating_add(1);
        self.nwb_degraded |= self.rapid_crashes >= MAX_RAPID_CRASHES;
        self.state = NwbGenerationStateV1::Degraded;
        self.push(NwbSupervisorEventV1::WorkerFailed { generation });
    }

    fn push(&mut self, event: NwbSupervisorEventV1) {
        if self.events.len() == MAX_SUPERVISOR_EVENTS {
            self.events.pop_front();
            self.nwb_degraded = true;
            self.events.push_back(NwbSupervisorEventV1::QueueOverflow);
            if self.events.len() == MAX_SUPERVISOR_EVENTS {
                self.events.pop_front();
            }
        }
        self.events.push_back(event);
    }
}

/// Reconstructs a strictly monotonic generation cursor without ever resuming
/// prior generation artifacts.  An owner must investigate any unexpected
/// object rather than allowing an alias to silently influence the cursor.
fn generation_cursor(generation_root: &std::path::Path) -> io::Result<u32> {
    if !generation_root.exists() {
        return Ok(1);
    }
    let mut maximum = 0_u32;
    for entry in fs::read_dir(generation_root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let digits = name
            .strip_prefix("generation-")
            .filter(|digits| digits.len() == 8 && digits.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "generation root contains a non-canonical entry",
                )
            })?;
        let generation = digits.parse::<u32>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "generation directory number is not a u32",
            )
        })?;
        if generation == 0 || !entry.file_type()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "generation root contains an invalid generation object",
            ));
        }
        maximum = maximum.max(generation);
    }
    maximum
        .checked_add(1)
        .ok_or_else(|| io::Error::other("NWB generation counter overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct FakeHandle {
        identity: String,
        exits: VecDeque<io::Result<Option<i32>>>,
        stopped: Arc<Mutex<bool>>,
    }
    impl NwbWorkerHandle for FakeHandle {
        fn identity(&self) -> &str {
            &self.identity
        }
        fn try_wait(&mut self) -> io::Result<Option<i32>> {
            self.exits.pop_front().unwrap_or(Ok(None))
        }
        fn request_stop(&mut self) -> io::Result<()> {
            *self.stopped.lock().unwrap() = true;
            Ok(())
        }
    }
    struct FakeLauncher {
        exits: VecDeque<io::Result<Option<i32>>>,
        stopped: Arc<Mutex<bool>>,
    }
    impl NwbWorkerLauncher for FakeLauncher {
        fn launch(
            &mut self,
            request: &NwbGenerationLaunchV1,
        ) -> io::Result<Box<dyn NwbWorkerHandle>> {
            std::fs::write(
                &request.paths.nwb_inprogress,
                b"worker-owned create-new fixture",
            )?;
            Ok(Box::new(FakeHandle {
                identity: "fake-worker".to_owned(),
                exits: std::mem::take(&mut self.exits),
                stopped: self.stopped.clone(),
            }))
        }
    }
    struct FakeVerifier {
        receipt: Option<NwbGenerationValidationReceiptV1>,
        publication_authorized: bool,
    }
    impl NwbValidationVerifier for FakeVerifier {
        fn verify(&mut self, _: &NwbValidationBundlePaths) -> io::Result<VerifiedNwbGeneration> {
            let receipt = self
                .receipt
                .take()
                .ok_or_else(|| io::Error::other("invalid receipt"))?;
            Ok(VerifiedNwbGeneration {
                receipt,
                final_path: PathBuf::from(r"F:\final.nwb"),
                publication_authorized: self.publication_authorized,
            })
        }
    }
    fn paths(tag: &str) -> (PathBuf, NwbSupervisorPathsV1) {
        let root =
            std::env::temp_dir().join(format!("forge-nwb-supervisor-{tag}-{}", std::process::id()));
        let absolute = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(root.file_name().unwrap());
        (
            root.clone(),
            NwbSupervisorPathsV1 {
                journal: absolute.join("run.wal"),
                journal_seal: absolute.join("run.wal.seal"),
                checkpoint_a: absolute.join("a"),
                checkpoint_b: absolute.join("b"),
                generation_root: absolute.join("generations"),
            },
        )
    }
    fn supervisor(
        tag: &str,
        exits: Vec<io::Result<Option<i32>>>,
    ) -> (
        PathBuf,
        NwbGenerationSupervisorV1<FakeLauncher, FakeVerifier>,
    ) {
        let (root, paths) = paths(tag);
        let stopped = Arc::new(Mutex::new(false));
        (
            root,
            NwbGenerationSupervisorV1::new_synthetic(
                [7; 16],
                paths,
                FakeLauncher {
                    exits: exits.into(),
                    stopped,
                },
                FakeVerifier {
                    receipt: None,
                    publication_authorized: false,
                },
            )
            .unwrap(),
        )
    }
    fn receipt(generation: u32) -> NwbGenerationValidationReceiptV1 {
        NwbGenerationValidationReceiptV1 {
            validation_flags: 0xff,
            run_id: [7; 16],
            generation,
            pod_count: 1,
            expected_last_journal_sequence: 0,
            checked_blocks: 1,
            total_samples: 1,
            validated_at_unix_ns: 1,
            journal_bytes: 1,
            nwb_bytes: 1,
            schema_error_count: 0,
            inspector_critical_count: 0,
            reconciliation_error_count: 0,
            host_protocol_hash: [1; 32],
            receipt_contract_hash: [1; 32],
            journal_sha256: [1; 32],
            journal_seal_sha256: [1; 32],
            durable_checkpoint_set_sha256: [1; 32],
            nwb_sha256: [1; 32],
            schema_plan_sha256: [1; 32],
            dependency_lock_sha256: [1; 32],
            materializer_build_sha256: [1; 32],
            validation_report_sha256: [1; 32],
            samples_manifest_sha256: [1; 32],
            session_manifest_sha256: [1; 32],
            run_ledger_seal_evidence_sha256: [1; 32],
            validation_sequence: 1,
        }
    }
    #[test]
    fn start_crash_rebuilds_new_generation_and_retains_old_artifact() {
        let (root, mut s) = supervisor("crash", vec![Ok(Some(1))]);
        let background = BackgroundNwbSupervisorToken::for_owner_background_task();
        assert_eq!(s.start_next(&background, 1).unwrap(), 1);
        s.poll_exit(&background).unwrap();
        assert_eq!(s.state(), NwbGenerationStateV1::Degraded);
        assert!(root.join("generations/generation-00000001").is_dir());
        assert_eq!(s.start_next(&background, 2).unwrap(), 2);
        assert!(root.join("generations/generation-00000002").is_dir());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn queue_overflow_degrades_without_worker_or_journal_stop() {
        let (root, mut s) = supervisor("queue", vec![]);
        for i in 1..=(MAX_SUPERVISOR_EVENTS as u64 + 2) {
            s.push(NwbSupervisorEventV1::Started {
                generation: i as u32,
            });
        }
        assert!(s.nwb_degraded());
        assert!(s
            .drain_events()
            .any(|event| event == NwbSupervisorEventV1::QueueOverflow));
        if root.exists() {
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn unavailable_production_launcher_fails_closed() {
        let (root, p) = paths("unavailable");
        let mut s = NwbGenerationSupervisorV1::new_unqualified_owner(
            [1; 16],
            p,
            UnavailableNwbWorkerLauncher,
            FakeVerifier {
                receipt: None,
                publication_authorized: false,
            },
        )
        .unwrap();
        let background = BackgroundNwbSupervisorToken::for_owner_background_task();
        assert!(s.start_next(&background, 1).is_err());
        assert_eq!(s.state(), NwbGenerationStateV1::UnqualifiedGenerationRoot);
        assert_eq!(
            s.evidence_source(),
            NwbEvidenceSourceV1::UnqualifiedWindowsRuntime
        );
        if root.exists() {
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn clean_worker_result_is_validated_but_never_published() {
        let (root, paths) = paths("validated");
        let stopped = Arc::new(Mutex::new(false));
        let mut s = NwbGenerationSupervisorV1::new_synthetic(
            [7; 16],
            paths,
            FakeLauncher {
                exits: vec![Ok(Some(0))].into(),
                stopped,
            },
            FakeVerifier {
                receipt: Some(receipt(1)),
                publication_authorized: false,
            },
        )
        .unwrap();
        let background = BackgroundNwbSupervisorToken::for_owner_background_task();
        assert_eq!(s.start_next(&background, 1).unwrap(), 1);
        assert_eq!(s.active_started_ns(), Some(1));
        s.poll_exit(&background).unwrap();
        assert_eq!(s.state(), NwbGenerationStateV1::AwaitingOwnerValidation);
        assert!(s.start_next(&background, 2).is_err());
        s.verify_completed_generation(&background).unwrap();
        assert_eq!(s.state(), NwbGenerationStateV1::ValidatedUnpublished);
        assert!(s.active.is_none());
        assert!(s.completed.is_none());
        assert!(s.start_next(&background, 3).is_err());
        assert_eq!(s.latest_validated().unwrap().generation, 1);
        assert!(root.join("generations/generation-00000001").is_dir());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_run_receipt_and_rapid_crashes_fail_closed_without_journal_action() {
        let (root, paths) = paths("wrong-run");
        let stopped = Arc::new(Mutex::new(false));
        let mut bad = receipt(1);
        bad.run_id = [8; 16];
        let mut s = NwbGenerationSupervisorV1::new_synthetic(
            [7; 16],
            paths,
            FakeLauncher {
                exits: vec![Ok(Some(0))].into(),
                stopped: stopped.clone(),
            },
            FakeVerifier {
                receipt: Some(bad),
                publication_authorized: false,
            },
        )
        .unwrap();
        let background = BackgroundNwbSupervisorToken::for_owner_background_task();
        s.start_next(&background, 1).unwrap();
        s.poll_exit(&background).unwrap();
        s.verify_completed_generation(&background).unwrap();
        assert_eq!(s.state(), NwbGenerationStateV1::Degraded);
        s.worker_failed(2);
        s.worker_failed(3);
        assert!(s.nwb_degraded());
        s.shutdown_worker_only();
        assert!(!*stopped.lock().unwrap());
        assert!(root.join("generations/generation-00000001").is_dir());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restart_scans_only_canonical_generations_and_never_reuses_one() {
        let (root, supervisor_paths) = paths("restart-cursor");
        let generations = supervisor_paths.generation_root.clone();
        std::fs::create_dir_all(generations.join("generation-00000003")).unwrap();
        let stopped = Arc::new(Mutex::new(false));
        let mut s = NwbGenerationSupervisorV1::new_synthetic(
            [7; 16],
            supervisor_paths,
            FakeLauncher {
                exits: vec![Ok(None)].into(),
                stopped,
            },
            FakeVerifier {
                receipt: None,
                publication_authorized: false,
            },
        )
        .unwrap();
        let background = BackgroundNwbSupervisorToken::for_owner_background_task();
        assert_eq!(s.start_next(&background, 1).unwrap(), 4);
        std::fs::remove_dir_all(root).unwrap();

        let (bad_root, bad_paths) = paths("restart-malformed");
        std::fs::create_dir_all(&bad_paths.generation_root).unwrap();
        std::fs::write(bad_paths.generation_root.join("generation-four"), b"bad").unwrap();
        assert!(NwbGenerationSupervisorV1::new_synthetic(
            [7; 16],
            bad_paths,
            FakeLauncher {
                exits: VecDeque::new(),
                stopped: Arc::new(Mutex::new(false)),
            },
            FakeVerifier {
                receipt: None,
                publication_authorized: false,
            },
        )
        .is_err());
        std::fs::remove_dir_all(bad_root).unwrap();
    }

    #[test]
    fn shutdown_retains_handle_until_terminal_observation() {
        let (root, mut s) = supervisor("shutdown-unreaped", vec![Ok(Some(0))]);
        let background = BackgroundNwbSupervisorToken::for_owner_background_task();
        s.start_next(&background, 1).unwrap();
        s.shutdown_worker_only();
        assert_eq!(s.state(), NwbGenerationStateV1::StopRequestedUnreaped);
        assert!(s.start_next(&background, 2).is_err());
        s.poll_exit(&background).unwrap();
        assert_eq!(s.state(), NwbGenerationStateV1::Degraded);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publication_authority_in_worker_receipt_is_rejected() {
        let (root, paths) = paths("publication-authority");
        let mut s = NwbGenerationSupervisorV1::new_synthetic(
            [7; 16],
            paths,
            FakeLauncher {
                exits: vec![Ok(Some(0))].into(),
                stopped: Arc::new(Mutex::new(false)),
            },
            FakeVerifier {
                receipt: Some(receipt(1)),
                publication_authorized: true,
            },
        )
        .unwrap();
        let background = BackgroundNwbSupervisorToken::for_owner_background_task();
        s.start_next(&background, 1).unwrap();
        s.poll_exit(&background).unwrap();
        s.verify_completed_generation(&background).unwrap();
        assert_eq!(s.state(), NwbGenerationStateV1::Degraded);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn windows_service_identity_does_not_qualify_generation_root() {
        let (root, paths) = paths("windows-service-root");
        let mut s = NwbGenerationSupervisorV1::new_windows_service_owner(
            [1; 16],
            paths,
            UnavailableNwbWorkerLauncher,
            FakeVerifier {
                receipt: None,
                publication_authorized: false,
            },
        )
        .unwrap();
        let background = BackgroundNwbSupervisorToken::for_owner_background_task();
        assert!(s.start_next(&background, 1).is_err());
        assert_eq!(s.evidence_source(), NwbEvidenceSourceV1::WindowsService);
        let _independent = IndependentNwbValidationVerifier;
        if root.exists() {
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
