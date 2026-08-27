//! Authenticated local dispatch boundary for the future real-hardware owner.
//!
//! This module is intentionally separate from `ServiceDispatcher`, whose
//! current production-shaped path owns protected replay. A hardware request
//! can never fall through to replay or simulator semantics.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use forge_protocol_v1::{sha256, Hash32};

use crate::direct_pod_control::MatchedDirectPodReply;
use crate::direct_pod_ingest::{
    DirectPodByteTransport, DirectPodRunPlan, DirectPodRuntimePoll, DurableDirectPodRuntime,
    PreRunDirectPodConnection,
};
use crate::hardware_service_protocol::{
    HardwareServiceBackend, HardwareServiceError, HardwareServiceSnapshotV1,
    HardwareStatusRequestV1, OperatorRunRequestV1, AVAIL_ADMISSION_VERIFIED,
    AVAIL_HARDWARE_AVAILABLE, AVAIL_TIME_FRESH, AVAIL_TRANSPORT_OPEN, HARDWARE_STATUS_REQUEST_LEN,
    OPERATOR_RUN_REQUEST_LEN,
};

/// Dispatches one exact hardware companion frame to one single-owner backend.
/// Production-shaped construction requires both the SCM ownership and the
/// authenticated named-pipe boundary to have already been established.
pub struct HardwareServiceDispatcher<B: HardwareServiceBackend> {
    backend: B,
}

impl<B: HardwareServiceBackend> HardwareServiceDispatcher<B> {
    pub fn new(backend: B, authenticated_pipe: bool, scm_owned: bool) -> io::Result<Self> {
        if !authenticated_pipe || !scm_owned {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "hardware service requires an authenticated SCM-owned pipe",
            ));
        }
        Ok(Self { backend })
    }

    pub fn handle(&mut self, request: &[u8], host_monotonic_ns: u64) -> io::Result<Vec<u8>> {
        if host_monotonic_ns == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hardware service requires a nonzero host monotonic timestamp",
            ));
        }
        let snapshot = match request.len() {
            HARDWARE_STATUS_REQUEST_LEN => {
                let decoded = HardwareStatusRequestV1::decode(request)?;
                let snapshot = self.backend.status(decoded.request_id, host_monotonic_ns)?;
                require_matching_request(decoded.request_id, snapshot)?
            }
            OPERATOR_RUN_REQUEST_LEN => {
                let decoded = OperatorRunRequestV1::decode(request)?;
                let snapshot = self.backend.submit(decoded, host_monotonic_ns)?;
                require_matching_request(decoded.request_id, snapshot)?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hardware service accepts only exact status or operator Run frames",
                ))
            }
        };
        Ok(snapshot.encode()?.to_vec())
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }
}

fn require_matching_request(
    request_id: u64,
    snapshot: HardwareServiceSnapshotV1,
) -> io::Result<HardwareServiceSnapshotV1> {
    if snapshot.request_id != request_id {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hardware backend returned a snapshot for a different request",
        ))
    } else {
        Ok(snapshot)
    }
}

/// Honest backend used until a qualified D3XX owner is explicitly bound.
/// It never translates, sends, or re-labels a Run request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnavailableHardwareBackend {
    evidence_hash: Hash32,
    detail_code: u32,
}

impl UnavailableHardwareBackend {
    pub fn new(reason: &[u8], detail_code: u32) -> io::Result<Self> {
        if reason.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unavailable hardware evidence reason must be nonempty",
            ));
        }
        Ok(Self {
            evidence_hash: sha256(reason),
            detail_code,
        })
    }

    pub fn from_verified_evidence(evidence_hash: Hash32, detail_code: u32) -> io::Result<Self> {
        if evidence_hash == [0; 32] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unavailable hardware evidence hash must be nonzero",
            ));
        }
        Ok(Self {
            evidence_hash,
            detail_code,
        })
    }

    fn snapshot(self, request_id: u64) -> HardwareServiceSnapshotV1 {
        let mut snapshot = HardwareServiceSnapshotV1::unavailable(
            request_id,
            HardwareServiceError::Unavailable,
            self.evidence_hash,
        );
        snapshot.detail_code = self.detail_code;
        snapshot
    }
}

impl HardwareServiceBackend for UnavailableHardwareBackend {
    fn status(
        &mut self,
        request_id: u64,
        _host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        Ok(self.snapshot(request_id))
    }

    fn submit(
        &mut self,
        request: OperatorRunRequestV1,
        _host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        Ok(self.snapshot(request.request_id))
    }
}

impl OwnedHardwareServiceBackend for UnavailableHardwareBackend {
    fn poll_owner_once(&mut self, _host_monotonic_ns: u64) -> io::Result<()> {
        Ok(())
    }
}

/// Hardware service adapter for one already admitted, primed, journal-bound
/// direct-Pod Run.
///
/// This is deliberately narrower than a production connection factory: it
/// cannot discover a Pod, create a journal, or survive owner-process restart.
/// Its value is that the authenticated service protocol and the real transport
/// scheduler now share one ordering domain for intent persistence, hardware
/// OUT, Pod replies, canonical records, and hardware time.
pub struct JournalBoundDirectPodBackend<T: DirectPodByteTransport> {
    runtime: DurableDirectPodRuntime<T>,
    admission_receipt_sha256: Hash32,
}

impl<T: DirectPodByteTransport> JournalBoundDirectPodBackend<T> {
    pub fn new(runtime: DurableDirectPodRuntime<T>) -> io::Result<Self> {
        let snapshot = runtime.snapshot();
        if snapshot.poisoned
            || !snapshot.runtime.primed
            || !snapshot.runtime.ingest.control.capability_admitted
            || snapshot.runtime.ingest.hardware_time.latest.is_none()
            || snapshot.runtime.ingest.cabline_source.latest.is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal-bound hardware backend requires a healthy, primed, admitted runtime with Pod time and CABLINE source status",
            ));
        }
        let admission_receipt_sha256 = runtime.admission_receipt_sha256();
        if admission_receipt_sha256.iter().all(|byte| *byte == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal-bound hardware backend admission evidence is zero",
            ));
        }
        Ok(Self {
            runtime,
            admission_receipt_sha256,
        })
    }

    /// Advances exactly one completion in the same owner that persists Run
    /// events. The durable lifecycle consumes the reply before this method
    /// returns it to observers.
    pub fn poll_once(
        &mut self,
        host_monotonic_ns: u64,
    ) -> io::Result<(DirectPodRuntimePoll, Option<MatchedDirectPodReply>)> {
        self.poll_once_from_owner(host_monotonic_ns, Instant::now())
    }

    fn poll_once_from_owner(
        &mut self,
        host_monotonic_ns: u64,
        wall_started: Instant,
    ) -> io::Result<(DirectPodRuntimePoll, Option<MatchedDirectPodReply>)> {
        let polled = self
            .runtime
            .poll_once_from_snapshot_started(host_monotonic_ns, wall_started)?;
        let reply = self.runtime.take_reply();
        Ok((polled, reply))
    }

    fn submit_from_owner(
        &mut self,
        request: OperatorRunRequestV1,
        host_monotonic_ns: u64,
        wall_started: Instant,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        let request_id = request.request_id;
        self.runtime.send_operator_run_request_from_owner(
            &request,
            host_monotonic_ns,
            wall_started,
        )?;
        self.available_snapshot(request_id, host_monotonic_ns)
    }

    pub fn durability_barrier(&mut self) -> io::Result<crate::journal::DurableCheckpoint> {
        self.runtime.durability_barrier()
    }

    pub fn runtime(&self) -> &DurableDirectPodRuntime<T> {
        &self.runtime
    }

    fn shutdown_owner_now(&mut self) -> io::Result<()> {
        self.runtime.shutdown_owner()
    }

    fn available_snapshot(
        &mut self,
        request_id: u64,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        self.runtime
            .require_fresh_hardware_time(host_monotonic_ns)?;
        let snapshot = self.runtime.snapshot();
        if snapshot.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal-bound direct-Pod runtime is poisoned",
            ));
        }
        let time = snapshot
            .runtime
            .ingest
            .hardware_time
            .latest
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Pod time is missing"))?;
        let cabline = snapshot
            .runtime
            .ingest
            .cabline_source
            .latest
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CABLINE source status is missing",
                )
            })?;
        let context = self.runtime.active_context();
        if let Some(context) = context {
            if context.target_device_id != time.device_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "active Run target differs from the admitted Pod",
                ));
            }
        }

        let service_state = snapshot.lifecycle.phase.into();
        let active_run_id = context.map(|value| value.run_id).unwrap_or([0; 16]);
        let active_epoch = context.map(|value| value.epoch).unwrap_or(0);
        let pending_request_id = snapshot.lifecycle.pending_request_id.unwrap_or(0);
        let first_journal_sequence = snapshot.lifecycle.first_journal_sequence;
        let evidence_hash = service_snapshot_evidence(
            self.admission_receipt_sha256,
            &time.encode()?,
            &cabline.encode()?,
            service_state as u16,
            active_run_id,
            active_epoch,
            pending_request_id,
            first_journal_sequence,
            snapshot.runtime.ingest.committed_record_count,
            snapshot.runtime.ingest.durable_record_count,
        );

        Ok(HardwareServiceSnapshotV1 {
            request_id,
            service_state,
            error_code: HardwareServiceError::None,
            availability_flags: AVAIL_ADMISSION_VERIFIED
                | AVAIL_TRANSPORT_OPEN
                | AVAIL_TIME_FRESH
                | AVAIL_HARDWARE_AVAILABLE,
            device_id: time.device_id,
            transport_epoch: time.transport_epoch,
            status_sequence: time.status_sequence,
            hardware_time_ns: time.global_time_ns,
            sample_counter: time.sample_counter,
            frame_counter: time.frame_counter,
            runtime_flags: time.runtime_flags,
            hardware_state_hash: time.hardware_state_hash,
            active_run_id,
            active_epoch,
            pending_request_id,
            first_journal_sequence,
            evidence_hash,
            detail_code: 0,
        })
    }
}

impl<T: DirectPodByteTransport> HardwareServiceBackend for JournalBoundDirectPodBackend<T> {
    fn status(
        &mut self,
        request_id: u64,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        self.available_snapshot(request_id, host_monotonic_ns)
    }

    fn submit(
        &mut self,
        request: OperatorRunRequestV1,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        self.submit_from_owner(request, host_monotonic_ns, Instant::now())
    }
}

/// Protected policy boundary for turning an authenticated Prepare request into
/// fixed storage and Pod/headstage/config identities. Implementations must not
/// pass through operator-supplied paths or invent an unapproved device map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectPodPreflightAuthority {
    pod_id: [u8; 16],
    headstage_id: [u8; 16],
    approved_cabline_binding_sha256: Hash32,
}

impl DirectPodPreflightAuthority {
    pub(crate) fn new(
        pod_id: [u8; 16],
        headstage_id: [u8; 16],
        approved_cabline_binding_sha256: Hash32,
    ) -> io::Result<Self> {
        if pod_id == [0; 16]
            || headstage_id == [0; 16]
            || approved_cabline_binding_sha256 == [0; 32]
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "direct-Pod preflight authority requires nonzero protected identities",
            ));
        }
        Ok(Self {
            pod_id,
            headstage_id,
            approved_cabline_binding_sha256,
        })
    }
}

pub(crate) trait DirectPodRunPlanProvider: Send + 'static {
    fn preflight_authority(&self) -> io::Result<DirectPodPreflightAuthority>;

    fn plan_for_prepare(&mut self, request: &OperatorRunRequestV1) -> io::Result<DirectPodRunPlan>;
}

enum PromotableDirectPodState<T: DirectPodByteTransport> {
    PreRun(Box<PreRunDirectPodConnection<T>>),
    Run(Box<JournalBoundDirectPodBackend<T>>),
}

/// One backend whose exclusive transport ownership spans pre-Run monitoring
/// and the journal-bound Run. The state transition moves the same transport;
/// there is never a second D3XX handle owner or a cancel/re-prime window.
pub(crate) struct PromotableDirectPodBackend<T, P>
where
    T: DirectPodByteTransport,
    P: DirectPodRunPlanProvider,
{
    state: Option<PromotableDirectPodState<T>>,
    plan_provider: P,
    preflight_authority: DirectPodPreflightAuthority,
    admission_receipt_sha256: Hash32,
}

impl<T, P> PromotableDirectPodBackend<T, P>
where
    T: DirectPodByteTransport,
    P: DirectPodRunPlanProvider,
{
    pub(crate) fn new(
        mut connection: PreRunDirectPodConnection<T>,
        plan_provider: P,
    ) -> io::Result<Self> {
        let validation = (|| {
            let snapshot = connection.snapshot();
            if snapshot.promoted || snapshot.poisoned || !snapshot.primed {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "promotable direct-Pod backend requires a healthy primed pre-Run owner",
                ));
            }
            let admission_receipt_sha256 = connection.admission_receipt_sha256()?;
            if admission_receipt_sha256.iter().all(|byte| *byte == 0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "promotable direct-Pod backend admission evidence is zero",
                ));
            }
            let preflight_authority = plan_provider.preflight_authority()?;
            Ok((admission_receipt_sha256, preflight_authority))
        })();
        match validation {
            Ok((admission_receipt_sha256, preflight_authority)) => Ok(Self {
                state: Some(PromotableDirectPodState::PreRun(Box::new(connection))),
                plan_provider,
                preflight_authority,
                admission_receipt_sha256,
            }),
            Err(error) => {
                let _ = connection.shutdown_owner();
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn is_run_bound(&self) -> bool {
        matches!(self.state, Some(PromotableDirectPodState::Run(_)))
    }

    pub(crate) fn transport_epoch(&self) -> io::Result<u64> {
        match self
            .state
            .as_ref()
            .ok_or_else(|| io::Error::other("direct-Pod backend lost exclusive state"))?
        {
            PromotableDirectPodState::PreRun(connection) => {
                Ok(connection.snapshot().stream.transport_epoch)
            }
            PromotableDirectPodState::Run(backend) => Ok(backend
                .runtime()
                .snapshot()
                .runtime
                .ingest
                .stream
                .transport_epoch),
        }
    }

    pub(crate) fn shutdown_owner_now(&mut self) -> io::Result<()> {
        match self
            .state
            .as_mut()
            .ok_or_else(|| io::Error::other("direct-Pod backend lost exclusive state"))?
        {
            PromotableDirectPodState::PreRun(connection) => connection.shutdown_owner(),
            PromotableDirectPodState::Run(backend) => backend.shutdown_owner_now(),
        }
    }

    fn pre_run_available_snapshot(
        admission_receipt_sha256: Hash32,
        preflight_authority: DirectPodPreflightAuthority,
        connection: &mut PreRunDirectPodConnection<T>,
        request_id: u64,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        connection.require_fresh_hardware_time_for(
            host_monotonic_ns,
            preflight_authority.pod_id,
            preflight_authority.headstage_id,
            preflight_authority.approved_cabline_binding_sha256,
        )?;
        let snapshot = connection.snapshot();
        let time = snapshot
            .hardware_time
            .latest
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Pod time is missing"))?;
        let cabline = snapshot.cabline_source.latest.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "CABLINE source status is missing",
            )
        })?;
        let service_state = crate::hardware_service_protocol::HardwareServiceState::Ready;
        let evidence_hash = service_snapshot_evidence(
            admission_receipt_sha256,
            &time.encode()?,
            &cabline.encode()?,
            service_state as u16,
            [0; 16],
            0,
            0,
            None,
            0,
            0,
        );
        Ok(HardwareServiceSnapshotV1 {
            request_id,
            service_state,
            error_code: HardwareServiceError::None,
            availability_flags: AVAIL_ADMISSION_VERIFIED
                | AVAIL_TRANSPORT_OPEN
                | AVAIL_TIME_FRESH
                | AVAIL_HARDWARE_AVAILABLE,
            device_id: time.device_id,
            transport_epoch: time.transport_epoch,
            status_sequence: time.status_sequence,
            hardware_time_ns: time.global_time_ns,
            sample_counter: time.sample_counter,
            frame_counter: time.frame_counter,
            runtime_flags: time.runtime_flags,
            hardware_state_hash: time.hardware_state_hash,
            active_run_id: [0; 16],
            active_epoch: 0,
            pending_request_id: 0,
            first_journal_sequence: None,
            evidence_hash,
            detail_code: 0,
        })
    }
}

impl<T, P> HardwareServiceBackend for PromotableDirectPodBackend<T, P>
where
    T: DirectPodByteTransport,
    P: DirectPodRunPlanProvider,
{
    fn status(
        &mut self,
        request_id: u64,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        match self
            .state
            .as_mut()
            .ok_or_else(|| io::Error::other("direct-Pod backend lost exclusive state"))?
        {
            PromotableDirectPodState::PreRun(connection) => Self::pre_run_available_snapshot(
                self.admission_receipt_sha256,
                self.preflight_authority,
                connection,
                request_id,
                host_monotonic_ns,
            ),
            PromotableDirectPodState::Run(backend) => backend.status(request_id, host_monotonic_ns),
        }
    }

    fn submit(
        &mut self,
        request: OperatorRunRequestV1,
        host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        let wall_started = Instant::now();
        if matches!(self.state, Some(PromotableDirectPodState::Run(_))) {
            let Some(PromotableDirectPodState::Run(backend)) = self.state.as_mut() else {
                unreachable!();
            };
            return backend.submit_from_owner(request, host_monotonic_ns, wall_started);
        }
        if request.command != crate::run::RunCommandKind::Prepare {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pre-Run direct-Pod backend accepts only Prepare",
            ));
        }
        let plan = self.plan_provider.plan_for_prepare(&request)?;
        let promotion = match self
            .state
            .as_mut()
            .ok_or_else(|| io::Error::other("direct-Pod backend lost exclusive state"))?
        {
            PromotableDirectPodState::PreRun(connection) => connection
                .prepare_and_promote_from_owner(&request, &plan, host_monotonic_ns, wall_started)?,
            PromotableDirectPodState::Run(_) => unreachable!(),
        };
        let backend = JournalBoundDirectPodBackend::new(promotion.into_runtime())?;
        self.state = Some(PromotableDirectPodState::Run(Box::new(backend)));
        let Some(PromotableDirectPodState::Run(backend)) = self.state.as_mut() else {
            unreachable!();
        };
        backend.status(request.request_id, host_monotonic_ns)
    }
}

/// Nonblocking work performed by the hardware owner independently of any GUI
/// or named-pipe request. Implementations must return promptly; a transport
/// stall is a fault, not permission to block this thread indefinitely.
pub trait OwnedHardwareServiceBackend: HardwareServiceBackend + Send + 'static {
    fn poll_owner_once(&mut self, host_monotonic_ns: u64) -> io::Result<()>;

    /// Called exactly once before the exclusive owner thread exits, including
    /// after a polling error. Implementations with a live transport must cancel
    /// it and durably fail any unfinished Run; the default is for no-I/O
    /// unavailable backends only.
    fn shutdown_owner(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<T> OwnedHardwareServiceBackend for JournalBoundDirectPodBackend<T>
where
    T: DirectPodByteTransport + Send + 'static,
{
    fn poll_owner_once(&mut self, host_monotonic_ns: u64) -> io::Result<()> {
        let wall_started = Instant::now();
        self.poll_once_from_owner(host_monotonic_ns, wall_started)?;
        self.runtime
            .require_fresh_hardware_time(host_monotonic_ns)
            .map(|_| ())
    }

    fn shutdown_owner(&mut self) -> io::Result<()> {
        self.shutdown_owner_now()
    }
}

impl<T, P> OwnedHardwareServiceBackend for PromotableDirectPodBackend<T, P>
where
    T: DirectPodByteTransport + Send + 'static,
    P: DirectPodRunPlanProvider,
{
    fn poll_owner_once(&mut self, host_monotonic_ns: u64) -> io::Result<()> {
        let wall_started = Instant::now();
        let authority = self.preflight_authority;
        match self
            .state
            .as_mut()
            .ok_or_else(|| io::Error::other("direct-Pod backend lost exclusive state"))?
        {
            PromotableDirectPodState::PreRun(connection) => {
                connection.poll_once(host_monotonic_ns)?;
                connection
                    .require_fresh_hardware_time_for(
                        host_monotonic_ns,
                        authority.pod_id,
                        authority.headstage_id,
                        authority.approved_cabline_binding_sha256,
                    )
                    .map(|_| ())
            }
            PromotableDirectPodState::Run(backend) => {
                backend.poll_once_from_owner(host_monotonic_ns, wall_started)?;
                backend
                    .runtime
                    .require_fresh_hardware_time(host_monotonic_ns)
                    .map(|_| ())
            }
        }
    }

    fn shutdown_owner(&mut self) -> io::Result<()> {
        self.shutdown_owner_now()
    }
}

/// One host-monotonic origin shared by the hardware owner and its pipe
/// listener. This prevents independent `Instant` origins from being compared.
#[derive(Clone, Debug)]
pub struct HostMonotonicClock {
    origin: Arc<Instant>,
}

impl HostMonotonicClock {
    pub fn new() -> Self {
        Self {
            origin: Arc::new(Instant::now()),
        }
    }

    pub fn now_ns(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_nanos())
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1)
    }
}

impl Default for HostMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

enum HardwareOwnerRequest {
    Status {
        request_id: u64,
        response: mpsc::SyncSender<io::Result<HardwareServiceSnapshotV1>>,
    },
    Submit {
        request: OperatorRunRequestV1,
        response: mpsc::SyncSender<io::Result<HardwareServiceSnapshotV1>>,
    },
}

/// Bounded request proxy. Dropping every client proxy does not stop the owner
/// and is never translated into a Run Stop or Abort.
#[derive(Clone)]
pub struct HardwareServiceProxy {
    requests: mpsc::SyncSender<HardwareOwnerRequest>,
    response_timeout: Duration,
}

impl HardwareServiceProxy {
    fn call(
        &self,
        request: HardwareOwnerRequest,
        response: mpsc::Receiver<io::Result<HardwareServiceSnapshotV1>>,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        self.requests
            .try_send(request)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "hardware owner request queue is full",
                ),
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "hardware owner is unavailable")
                }
            })?;
        response
            .recv_timeout(self.response_timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => io::Error::new(
                    io::ErrorKind::TimedOut,
                    "hardware owner response deadline expired",
                ),
                mpsc::RecvTimeoutError::Disconnected => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "hardware owner exited")
                }
            })?
    }
}

impl HardwareServiceBackend for HardwareServiceProxy {
    fn status(
        &mut self,
        request_id: u64,
        _host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        self.call(
            HardwareOwnerRequest::Status {
                request_id,
                response: response_tx,
            },
            response_rx,
        )
    }

    fn submit(
        &mut self,
        request: OperatorRunRequestV1,
        _host_monotonic_ns: u64,
    ) -> io::Result<HardwareServiceSnapshotV1> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        self.call(
            HardwareOwnerRequest::Submit {
                request,
                response: response_tx,
            },
            response_rx,
        )
    }
}

/// Dedicated hardware owner. It polls even when no client is connected and
/// owns the only mutable backend instance. Shutdown ends the owner thread but
/// does not synthesize a hardware Stop; an active Run must fail closed during
/// durable restart recovery.
pub struct HardwareServiceOwner {
    proxy: HardwareServiceProxy,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<io::Result<()>>>,
}

#[derive(Clone)]
pub(crate) struct HardwareOwnerShutdownSignal {
    stop: Arc<AtomicBool>,
}

impl HardwareOwnerShutdownSignal {
    pub(crate) fn request(&self) {
        self.stop.store(true, Ordering::Release);
    }
}

impl HardwareServiceOwner {
    pub fn spawn<B: OwnedHardwareServiceBackend>(
        mut backend: B,
        clock: HostMonotonicClock,
        queue_capacity: usize,
        poll_interval: Duration,
        response_timeout: Duration,
    ) -> io::Result<Self> {
        if queue_capacity == 0
            || poll_interval.is_zero()
            || response_timeout.is_zero()
            || poll_interval >= response_timeout
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hardware owner bounds are invalid",
            ));
        }
        let (requests_tx, requests_rx) = mpsc::sync_channel(queue_capacity);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let join = thread::Builder::new()
            .name("forge-hardware-owner".to_owned())
            .spawn(move || {
                let work_result = loop {
                    if worker_stop.load(Ordering::Acquire) {
                        break Ok(());
                    }
                    // Hardware progress has priority over control-plane traffic;
                    // a busy or hostile client cannot starve IN completions.
                    if let Err(error) = backend.poll_owner_once(clock.now_ns()) {
                        break Err(error);
                    }
                    match requests_rx.recv_timeout(poll_interval) {
                        Ok(HardwareOwnerRequest::Status {
                            request_id,
                            response,
                        }) => {
                            // Linearization point for a queued request: a
                            // concurrently latched owner stop wins even when
                            // recv_timeout woke for the request first.
                            let result = if worker_stop.load(Ordering::Acquire) {
                                Err(io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "hardware owner stopped before status dispatch",
                                ))
                            } else {
                                backend.status(request_id, clock.now_ns())
                            };
                            let _ = response.send(result);
                        }
                        Ok(HardwareOwnerRequest::Submit { request, response }) => {
                            let result = if worker_stop.load(Ordering::Acquire) {
                                Err(io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "hardware owner stopped before command dispatch",
                                ))
                            } else {
                                backend.submit(request, clock.now_ns())
                            };
                            let _ = response.send(result);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            // The owner lifetime, not client presence, controls exit.
                            thread::yield_now();
                        }
                    }
                };
                let shutdown_result = backend.shutdown_owner();
                match (work_result, shutdown_result) {
                    (Err(error), _) => Err(error),
                    (Ok(()), result) => result,
                }
            })?;
        Ok(Self {
            proxy: HardwareServiceProxy {
                requests: requests_tx,
                response_timeout,
            },
            stop,
            join: Some(join),
        })
    }

    pub fn proxy(&self) -> HardwareServiceProxy {
        self.proxy.clone()
    }

    pub(crate) fn shutdown_signal(&self) -> HardwareOwnerShutdownSignal {
        HardwareOwnerShutdownSignal {
            stop: Arc::clone(&self.stop),
        }
    }

    pub fn shutdown(mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        self.join_owner()
    }

    fn join_owner(&mut self) -> io::Result<()> {
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        join.join()
            .map_err(|_| io::Error::other("hardware owner thread panicked"))?
    }
}

impl Drop for HardwareServiceOwner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.join_owner();
    }
}

#[allow(clippy::too_many_arguments)]
fn service_snapshot_evidence(
    admission_receipt_sha256: Hash32,
    time_snapshot: &[u8],
    cabline_status: &[u8],
    service_state: u16,
    active_run_id: [u8; 16],
    active_epoch: u64,
    pending_request_id: u64,
    first_journal_sequence: Option<u64>,
    committed_record_count: u64,
    durable_record_count: u64,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(32 + time_snapshot.len() + cabline_status.len() + 66);
    bytes.extend_from_slice(b"FORGE-HARDWARE-SERVICE-EVIDENCE-V2");
    bytes.extend_from_slice(&admission_receipt_sha256);
    bytes.extend_from_slice(time_snapshot);
    bytes.extend_from_slice(cabline_status);
    bytes.extend_from_slice(&service_state.to_le_bytes());
    bytes.extend_from_slice(&active_run_id);
    bytes.extend_from_slice(&active_epoch.to_le_bytes());
    bytes.extend_from_slice(&pending_request_id.to_le_bytes());
    bytes.extend_from_slice(&first_journal_sequence.unwrap_or(u64::MAX).to_le_bytes());
    bytes.extend_from_slice(&committed_record_count.to_le_bytes());
    bytes.extend_from_slice(&durable_record_count.to_le_bytes());
    sha256(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_protocol_v1::{sha256, PROTOCOL_HASH};

    #[cfg(windows)]
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::hardware_service_protocol::{HardwareServiceState, AVAIL_HARDWARE_AVAILABLE};
    use crate::run::RunCommandKind;

    #[cfg(windows)]
    static NEXT_PIPE: AtomicU64 = AtomicU64::new(1);

    struct PollingBackend {
        polls: mpsc::Sender<()>,
        unavailable: UnavailableHardwareBackend,
    }

    impl HardwareServiceBackend for PollingBackend {
        fn status(
            &mut self,
            request_id: u64,
            host_monotonic_ns: u64,
        ) -> io::Result<HardwareServiceSnapshotV1> {
            self.unavailable.status(request_id, host_monotonic_ns)
        }

        fn submit(
            &mut self,
            request: OperatorRunRequestV1,
            host_monotonic_ns: u64,
        ) -> io::Result<HardwareServiceSnapshotV1> {
            self.unavailable.submit(request, host_monotonic_ns)
        }
    }

    impl OwnedHardwareServiceBackend for PollingBackend {
        fn poll_owner_once(&mut self, _host_monotonic_ns: u64) -> io::Result<()> {
            self.polls
                .send(())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "test observer exited"))
        }
    }

    struct ShutdownBackend {
        shutdowns: mpsc::Sender<()>,
        unavailable: UnavailableHardwareBackend,
    }

    impl HardwareServiceBackend for ShutdownBackend {
        fn status(
            &mut self,
            request_id: u64,
            host_monotonic_ns: u64,
        ) -> io::Result<HardwareServiceSnapshotV1> {
            self.unavailable.status(request_id, host_monotonic_ns)
        }

        fn submit(
            &mut self,
            request: OperatorRunRequestV1,
            host_monotonic_ns: u64,
        ) -> io::Result<HardwareServiceSnapshotV1> {
            self.unavailable.submit(request, host_monotonic_ns)
        }
    }

    impl OwnedHardwareServiceBackend for ShutdownBackend {
        fn poll_owner_once(&mut self, _host_monotonic_ns: u64) -> io::Result<()> {
            Ok(())
        }

        fn shutdown_owner(&mut self) -> io::Result<()> {
            self.shutdowns
                .send(())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "shutdown observer exited"))
        }
    }

    fn operator_request() -> OperatorRunRequestV1 {
        OperatorRunRequestV1 {
            request_id: 7,
            epoch: 3,
            command: RunCommandKind::Prepare,
            relative_deadline_ms: 500,
            run_id: [1; 16],
            target_device_id: [2; 16],
            frozen_config_hash: PROTOCOL_HASH,
            expected_hardware_state_hash: sha256(b"preflight-state"),
        }
    }

    #[test]
    fn construction_requires_both_scm_and_authenticated_pipe() {
        let backend = UnavailableHardwareBackend::new(b"not-bound", 11).unwrap();
        assert!(HardwareServiceDispatcher::new(backend, false, true).is_err());
        assert!(HardwareServiceDispatcher::new(backend, true, false).is_err());
        assert!(HardwareServiceDispatcher::new(backend, true, true).is_ok());
        assert!(UnavailableHardwareBackend::from_verified_evidence([0; 32], 1).is_err());
        assert!(UnavailableHardwareBackend::from_verified_evidence([1; 32], 2).is_ok());
    }

    #[test]
    fn unbound_status_and_commands_are_explicitly_unavailable() {
        let backend = UnavailableHardwareBackend::new(b"D3XX owner is not bound", 23).unwrap();
        let evidence_hash = backend.evidence_hash;
        let mut dispatcher = HardwareServiceDispatcher::new(backend, true, true).unwrap();

        let status = HardwareStatusRequestV1 { request_id: 5 }.encode().unwrap();
        let status =
            HardwareServiceSnapshotV1::decode(&dispatcher.handle(&status, 1).unwrap()).unwrap();
        assert_eq!(status.request_id, 5);
        assert_eq!(status.service_state, HardwareServiceState::Unavailable);
        assert_eq!(status.error_code, HardwareServiceError::Unavailable);
        assert_eq!(status.availability_flags & AVAIL_HARDWARE_AVAILABLE, 0);
        assert_eq!(status.evidence_hash, evidence_hash);
        assert_eq!(status.detail_code, 23);

        let command = operator_request().encode().unwrap();
        let command =
            HardwareServiceSnapshotV1::decode(&dispatcher.handle(&command, 2).unwrap()).unwrap();
        assert_eq!(command.request_id, 7);
        assert_eq!(command.service_state, HardwareServiceState::Unavailable);
        assert_eq!(command.error_code, HardwareServiceError::Unavailable);
        assert_eq!(command.availability_flags, 0);
    }

    #[test]
    fn owner_keeps_polling_after_every_client_proxy_is_dropped() {
        let (poll_tx, poll_rx) = mpsc::channel();
        let owner = HardwareServiceOwner::spawn(
            PollingBackend {
                polls: poll_tx,
                unavailable: UnavailableHardwareBackend::new(b"test-only-unavailable", 9).unwrap(),
            },
            HostMonotonicClock::new(),
            2,
            Duration::from_millis(1),
            Duration::from_millis(100),
        )
        .unwrap();
        let proxy = owner.proxy();
        poll_rx.recv_timeout(Duration::from_millis(100)).unwrap();
        drop(proxy);
        poll_rx.recv_timeout(Duration::from_millis(100)).unwrap();

        let mut dispatcher = HardwareServiceDispatcher::new(owner.proxy(), true, true).unwrap();
        let status = HardwareStatusRequestV1 { request_id: 77 }.encode().unwrap();
        let response = dispatcher.handle(&status, 1).unwrap();
        assert_eq!(
            HardwareServiceSnapshotV1::decode(&response)
                .unwrap()
                .request_id,
            77
        );
        drop(dispatcher);
        poll_rx.recv_timeout(Duration::from_millis(100)).unwrap();
        owner.shutdown().unwrap();
    }

    #[test]
    fn explicit_owner_shutdown_always_calls_backend_shutdown_hook() {
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let owner = HardwareServiceOwner::spawn(
            ShutdownBackend {
                shutdowns: shutdown_tx,
                unavailable: UnavailableHardwareBackend::new(b"shutdown-hook-test", 12).unwrap(),
            },
            HostMonotonicClock::new(),
            1,
            Duration::from_millis(1),
            Duration::from_millis(100),
        )
        .unwrap();
        owner.shutdown().unwrap();
        shutdown_rx
            .recv_timeout(Duration::from_millis(100))
            .unwrap();
    }

    #[test]
    fn owner_poll_cannot_be_starved_by_continuous_status_requests() {
        let (poll_tx, poll_rx) = mpsc::channel();
        let owner = HardwareServiceOwner::spawn(
            PollingBackend {
                polls: poll_tx,
                unavailable: UnavailableHardwareBackend::new(b"request-flood-test", 10).unwrap(),
            },
            HostMonotonicClock::new(),
            2,
            Duration::from_millis(1),
            Duration::from_millis(100),
        )
        .unwrap();
        let mut proxy = owner.proxy();
        for request_id in 1..=8 {
            assert_eq!(
                proxy.status(request_id, request_id).unwrap().request_id,
                request_id
            );
        }
        for _ in 0..8 {
            poll_rx.recv_timeout(Duration::from_millis(100)).unwrap();
        }
        owner.shutdown().unwrap();
    }

    #[test]
    fn malformed_or_wrong_sized_input_never_reaches_a_fallback() {
        let backend = UnavailableHardwareBackend::new(b"not-bound", 0).unwrap();
        let mut dispatcher = HardwareServiceDispatcher::new(backend, true, true).unwrap();
        assert!(dispatcher.handle(b"replay", 1).is_err());

        let mut status = HardwareStatusRequestV1 { request_id: 9 }.encode().unwrap();
        status[0] ^= 1;
        assert!(dispatcher.handle(&status, 1).is_err());
        assert!(dispatcher
            .handle(&[0; OPERATOR_RUN_REQUEST_LEN], 1)
            .is_err());
        assert!(dispatcher
            .handle(&operator_request().encode().unwrap(), 0)
            .is_err());
    }

    #[cfg(windows)]
    #[test]
    fn bounded_sid_protected_pipe_round_trips_status_and_command() {
        use crate::hardware_service_protocol::{call_hardware_run_command, query_hardware_service};
        use crate::ipc::{current_process_user_sid, SecurePipeOptions, SecurePipeServer};

        let sid = current_process_user_sid().unwrap();
        let pipe_name = format!(
            r"\\.\pipe\forge-hardware-service-test-{}-{}",
            std::process::id(),
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        );
        let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
            pipe_name: pipe_name.clone(),
            service_sid: sid.clone(),
            allowed_client_sid: sid,
        })
        .unwrap();
        let stop = server.stop_handle();
        let mut dispatcher = HardwareServiceDispatcher::new(
            UnavailableHardwareBackend::new(b"test hardware is not bound", 41).unwrap(),
            true,
            true,
        )
        .unwrap();
        let join = std::thread::spawn(move || {
            server.run_until_stopped(|request| dispatcher.handle(request, 1))
        });

        let status = query_hardware_service(&pipe_name, 17, 5_000, 5_000).unwrap();
        assert_eq!(status.request_id, 17);
        assert_eq!(status.error_code, HardwareServiceError::Unavailable);
        assert_eq!(status.detail_code, 41);
        let command =
            call_hardware_run_command(&pipe_name, operator_request(), 5_000, 5_000).unwrap();
        assert_eq!(command.request_id, 7);
        assert_eq!(command.error_code, HardwareServiceError::Unavailable);

        stop.request_stop().unwrap();
        assert_eq!(join.join().unwrap().unwrap(), 2);
    }
}
