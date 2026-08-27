use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;

use forge_protocol_v1::{sha256, Hash32, Id16};

use crate::analysis_mapping::{AnalysisMappingConfig, MappedAnalysisRing};
use crate::analysis_ring::{AnalysisBranchIdentityV1, AnalysisConsumerRoleV1, AnalysisFaultV1};
use crate::analysis_worker_protocol::{
    AnalysisWorkerErrorV1, AnalysisWorkerRegisterRequestV1, AnalysisWorkerRegisterResponseV1,
};
use crate::ipc::{canonical_sid_string, AuthenticatedPipeClient};
use crate::safety_arbiter::{AnalysisBranchFaultRoute, AnalysisFaultDispatchV1};
use crate::service_replay::ProtectedReplaySession;

const MAX_REGISTRATIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RequestKey {
    producer_epoch: u64,
    request_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ConsumerKey {
    producer_epoch: u64,
    run_id: Id16,
    consumer_id: Id16,
}

struct CachedRegistration {
    request_hash: Hash32,
    process_id: u32,
    process_creation_time_100ns: u64,
    role: AnalysisConsumerRoleV1,
    fault_route: Arc<AnalysisBranchFaultRoute>,
    response: Vec<u8>,
}

/// A minted controller lease is unsafe until exactly one live mapping owns it.
/// Every registration exit before that commit revokes the lease without
/// attempting event persistence; callers may retain their `Arc` indefinitely.
struct RequestedControllerRouteGuard {
    route: Option<Arc<AnalysisBranchFaultRoute>>,
    committed: bool,
}

impl RequestedControllerRouteGuard {
    fn new(route: Option<&Arc<AnalysisBranchFaultRoute>>) -> Self {
        Self {
            route: route.cloned(),
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for RequestedControllerRouteGuard {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(route) = &self.route {
                route.fail_closed_controller_loss();
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisWorkerHealthObservationV1 {
    pub producer_epoch: u64,
    pub request_id: u64,
    pub process_id: u32,
    pub process_creation_time_100ns: u64,
    pub observed_producer_epoch: u64,
    pub handle_alive: bool,
    pub consumer_heartbeat_monotonic_ns: u64,
    pub observed_monotonic_ns: u64,
    pub heartbeat_timeout_ns: u64,
    pub deadline_missed: bool,
}

enum MappingCreator {
    Production {
        service_sid: String,
        worker_sid: String,
    },
    #[cfg(test)]
    Test { worker_sid: String },
}

pub struct AnalysisWorkerRegistrationService {
    worker_sid: String,
    creator: MappingCreator,
    requests: HashMap<RequestKey, CachedRegistration>,
    consumers: HashSet<ConsumerKey>,
}

impl AnalysisWorkerRegistrationService {
    pub fn new_service(service_sid: &str, worker_sid: &str) -> io::Result<Self> {
        let service_sid = canonical_sid_string(service_sid)?;
        let worker_sid = canonical_sid_string(worker_sid)?;
        if !service_sid.starts_with("S-1-5-80-") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "analysis registration requires an NT SERVICE SID",
            ));
        }
        Ok(Self {
            worker_sid: worker_sid.clone(),
            creator: MappingCreator::Production {
                service_sid,
                worker_sid,
            },
            requests: HashMap::new(),
            consumers: HashSet::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn new_test(worker_sid: &str) -> io::Result<Self> {
        let worker_sid = canonical_sid_string(worker_sid)?;
        Ok(Self {
            worker_sid: worker_sid.clone(),
            creator: MappingCreator::Test { worker_sid },
            requests: HashMap::new(),
            consumers: HashSet::new(),
        })
    }

    pub fn handle(
        &mut self,
        session: &mut ProtectedReplaySession,
        client: &AuthenticatedPipeClient,
        encoded_request: &[u8],
    ) -> io::Result<Vec<u8>> {
        self.handle_with_fault_route(session, client, encoded_request, None)
    }

    fn handle_with_fault_route(
        &mut self,
        session: &mut ProtectedReplaySession,
        client: &AuthenticatedPipeClient,
        encoded_request: &[u8],
        requested_fault_route: Option<Arc<AnalysisBranchFaultRoute>>,
    ) -> io::Result<Vec<u8>> {
        let mut controller_guard =
            RequestedControllerRouteGuard::new(requested_fault_route.as_ref());
        if canonical_sid_string(&client.token_user_sid)? != self.worker_sid
            || client.process_id == 0
            || client.process_creation_time_100ns == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "analysis registration client identity is not authenticated",
            ));
        }
        let request = AnalysisWorkerRegisterRequestV1::decode(encoded_request)?;
        let request_hash = sha256(encoded_request);
        let key = RequestKey {
            producer_epoch: request.producer_epoch,
            request_id: request.request_id,
        };
        let identity = AnalysisBranchIdentityV1::new(
            request.run_id,
            request.consumer_id,
            request.producer_epoch,
        )?;
        let requested_role = requested_fault_route
            .as_ref()
            .map_or(AnalysisConsumerRoleV1::Observer, |route| route.role());
        if let Some(cached) = self.requests.get(&key) {
            let controller_replay_matches = requested_fault_route.as_ref().is_some_and(|route| {
                Arc::ptr_eq(route, &cached.fault_route)
                    && route.identity() == identity
                    && route.controller_mapping_is_live()
            });
            if cached.request_hash == request_hash
                && cached.process_id == client.process_id
                && cached.process_creation_time_100ns == client.process_creation_time_100ns
                && cached.role == requested_role
                && cached.fault_route.identity() == identity
                && (cached.role == AnalysisConsumerRoleV1::Observer || controller_replay_matches)
            {
                controller_guard.commit();
                return Ok(cached.response.clone());
            }
            return AnalysisWorkerRegisterResponseV1::rejected(
                &request,
                AnalysisWorkerErrorV1::Conflict,
            )?
            .encode();
        }
        if self.requests.len() >= MAX_REGISTRATIONS {
            return AnalysisWorkerRegisterResponseV1::rejected(
                &request,
                AnalysisWorkerErrorV1::Unavailable,
            )?
            .encode();
        }
        let consumer_key = ConsumerKey {
            producer_epoch: request.producer_epoch,
            run_id: request.run_id,
            consumer_id: request.consumer_id,
        };
        if self.consumers.contains(&consumer_key) {
            return AnalysisWorkerRegisterResponseV1::rejected(
                &request,
                AnalysisWorkerErrorV1::Conflict,
            )?
            .encode();
        }
        let mapping_name = mapping_name(&request);
        let config = AnalysisMappingConfig {
            slot_count: request.slot_count as usize,
            payload_capacity: request.payload_capacity as usize,
            run_id: request.run_id,
            consumer_id: request.consumer_id,
            producer_epoch: request.producer_epoch,
        };
        let fault_route = if let Some(route) = requested_fault_route {
            if route.identity() != identity {
                return AnalysisWorkerRegisterResponseV1::rejected(
                    &request,
                    AnalysisWorkerErrorV1::Conflict,
                )?
                .encode();
            }
            route
        } else {
            // The published registration wire contract is observer-only.
            AnalysisBranchFaultRoute::observer(identity)
        };
        // Construct every fallible response byte before the mapping becomes
        // live, so an encoding error cannot leave an accepted half-transaction.
        let response =
            AnalysisWorkerRegisterResponseV1::accepted(&request, mapping_name.clone())?.encode()?;
        let mapping = match &self.creator {
            MappingCreator::Production {
                service_sid,
                worker_sid,
            } => MappedAnalysisRing::create_service(&mapping_name, service_sid, worker_sid, config),
            #[cfg(test)]
            MappingCreator::Test { worker_sid } => {
                MappedAnalysisRing::create_test(&mapping_name, worker_sid, config)
            }
        };
        let mapping = match mapping {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return AnalysisWorkerRegisterResponseV1::rejected(
                    &request,
                    AnalysisWorkerErrorV1::Conflict,
                )?
                .encode()
            }
            Err(error) => return Err(error),
        };
        if let Err(error) =
            session.attach_analysis_mapping_with_fault_route(mapping, Arc::clone(&fault_route))
        {
            return AnalysisWorkerRegisterResponseV1::rejected(
                &request,
                if error.kind() == io::ErrorKind::AlreadyExists {
                    AnalysisWorkerErrorV1::Conflict
                } else {
                    AnalysisWorkerErrorV1::Unavailable
                },
            )?
            .encode();
        }
        controller_guard.commit();
        self.consumers.insert(consumer_key);
        self.requests.insert(
            key,
            CachedRegistration {
                request_hash,
                process_id: client.process_id,
                process_creation_time_100ns: client.process_creation_time_100ns,
                role: fault_route.role(),
                fault_route,
                response: response.clone(),
            },
        );
        Ok(response)
    }

    /// Routes authenticated process/epoch/heartbeat observations through the
    /// same branch fault transition used by the producer.  The monitor that
    /// supplies these observations remains an integration boundary.
    pub fn observe_worker_health(
        &self,
        observation: AnalysisWorkerHealthObservationV1,
    ) -> io::Result<Option<AnalysisFaultDispatchV1>> {
        let key = RequestKey {
            producer_epoch: observation.producer_epoch,
            request_id: observation.request_id,
        };
        let registration = self.requests.get(&key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "analysis worker registration is unknown",
            )
        })?;
        let fault = if !observation.handle_alive
            || observation.process_id != registration.process_id
            || observation.process_creation_time_100ns != registration.process_creation_time_100ns
            || observation.observed_producer_epoch != observation.producer_epoch
        {
            Some(AnalysisFaultV1::ConsumerLost)
        } else if observation.consumer_heartbeat_monotonic_ns == 0
            || observation.observed_monotonic_ns == 0
            || observation.observed_monotonic_ns < observation.consumer_heartbeat_monotonic_ns
            || observation.heartbeat_timeout_ns == 0
            || observation
                .observed_monotonic_ns
                .saturating_sub(observation.consumer_heartbeat_monotonic_ns)
                >= observation.heartbeat_timeout_ns
        {
            Some(AnalysisFaultV1::HeartbeatTimeout)
        } else if observation.deadline_missed {
            Some(AnalysisFaultV1::DeadlineMiss)
        } else {
            None
        };
        Ok(fault.map(|fault| {
            registration
                .fault_route
                .dispatch(fault, observation.observed_monotonic_ns, None, None)
        }))
    }

    pub fn registered_role(
        &self,
        producer_epoch: u64,
        request_id: u64,
    ) -> Option<AnalysisConsumerRoleV1> {
        self.requests
            .get(&RequestKey {
                producer_epoch,
                request_id,
            })
            .map(|registration| registration.role)
    }
}

fn mapping_name(request: &AnalysisWorkerRegisterRequestV1) -> String {
    format!(
        r"Local\ForgeAnalysisRing-{}-{}-{:016x}-{:016x}",
        hex(&request.run_id),
        hex(&request.consumer_id),
        request.producer_epoch,
        request.request_id
    )
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
    use crate::analysis_worker_protocol::AnalysisWorkerRegisterResponseV1;
    use crate::ipc::{
        call_secure_pipe, current_process_user_sid, SecurePipeOptions, SecurePipeServer,
    };
    use forge_protocol_v1::RECORD_HEADER_LEN;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "forge-analysis-registration-{}-{}",
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

    fn request(request_id: u64, consumer: u8) -> AnalysisWorkerRegisterRequestV1 {
        AnalysisWorkerRegisterRequestV1 {
            request_id,
            producer_epoch: NEXT_TEMP.fetch_add(1, Ordering::Relaxed) + 100,
            run_id: [0x61; 16],
            consumer_id: [consumer; 16],
            worker_build_hash: [0x73; 32],
            slot_count: 4,
            payload_capacity: (RECORD_HEADER_LEN + 256) as u32,
        }
    }

    fn pipe_name() -> String {
        format!(
            r"\\.\pipe\forge-analysis-register-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn controller_request(
        route: &AnalysisBranchFaultRoute,
        request_id: u64,
    ) -> AnalysisWorkerRegisterRequestV1 {
        let identity = route.identity();
        AnalysisWorkerRegisterRequestV1 {
            request_id,
            producer_epoch: identity.producer_epoch(),
            run_id: identity.run_id(),
            consumer_id: identity.consumer_id(),
            worker_build_hash: [0x73; 32],
            slot_count: 4,
            payload_capacity: (RECORD_HEADER_LEN + 256) as u32,
        }
    }

    fn test_client(sid: String) -> AuthenticatedPipeClient {
        AuthenticatedPipeClient {
            token_user_sid: sid,
            process_id: 41,
            process_creation_time_100ns: 42,
        }
    }

    #[test]
    fn authenticated_named_pipe_hands_mapping_to_the_verified_process() {
        let root = TempRoot::new();
        let sid = current_process_user_sid().unwrap();
        let pipe_name = pipe_name();
        let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
            pipe_name: pipe_name.clone(),
            service_sid: sid.clone(),
            allowed_client_sid: sid.clone(),
        })
        .unwrap();
        let registration = AnalysisWorkerRegistrationService::new_test(&sid).unwrap();
        let session = ProtectedReplaySession::new(&root.0).unwrap();
        let encoded = request(9, 8).encode().unwrap();
        let server_join = std::thread::spawn(move || {
            let mut registration = registration;
            let mut session = session;
            let result = server.transact_once_authenticated(|client, request| {
                registration.handle(&mut session, client, request)
            });
            (result, registration, session)
        });
        let response = call_secure_pipe(&pipe_name, &encoded, 5_000).unwrap();
        let (server_result, _registration, _session) = server_join.join().unwrap();
        assert!(server_result.unwrap());
        let response = AnalysisWorkerRegisterResponseV1::decode(&response).unwrap();
        assert!(response.accepted);
        let opened = MappedAnalysisRing::open(
            &response.mapping_name,
            response.run_id,
            response.consumer_id,
            response.producer_epoch,
        )
        .unwrap();
        assert_eq!(opened.consumer_id(), [8; 16]);
    }

    #[test]
    fn authenticated_process_registration_is_exactly_idempotent() {
        let root = TempRoot::new();
        let sid = current_process_user_sid().unwrap();
        let mut service = AnalysisWorkerRegistrationService::new_test(&sid).unwrap();
        let mut session = ProtectedReplaySession::new(&root.0).unwrap();
        let client = AuthenticatedPipeClient {
            token_user_sid: sid,
            process_id: 41,
            process_creation_time_100ns: 42,
        };
        let request = request(1, 2).encode().unwrap();
        let first = service.handle(&mut session, &client, &request).unwrap();
        let second = service.handle(&mut session, &client, &request).unwrap();
        assert_eq!(first, second);
        let response = AnalysisWorkerRegisterResponseV1::decode(&first).unwrap();
        assert!(response.accepted);
        let opened = MappedAnalysisRing::open(
            &response.mapping_name,
            response.run_id,
            response.consumer_id,
            response.producer_epoch,
        )
        .unwrap();
        assert_eq!(opened.consumer_id(), [2; 16]);
    }

    #[test]
    fn failed_controller_mapping_attach_revokes_even_when_the_route_arc_survives() {
        let root = TempRoot::new();
        let sid = current_process_user_sid().unwrap();
        let mut service = AnalysisWorkerRegistrationService::new_test(&sid).unwrap();
        let mut session = ProtectedReplaySession::new(&root.0).unwrap();
        let client = test_client(sid.clone());
        let (mut arbiter, intent, route) = crate::safety_arbiter::tests::armed_with_route();
        let request = controller_request(&route, 501);
        let identity = route.identity();

        // A pre-existing observer branch is invisible to the registration
        // cache but makes the controller's live attach fail deterministically.
        let occupied = MappedAnalysisRing::create_test(
            &format!(r"Local\ForgeAnalysisRing-occupied-{}", request.request_id),
            &sid,
            AnalysisMappingConfig {
                slot_count: request.slot_count as usize,
                payload_capacity: request.payload_capacity as usize,
                run_id: identity.run_id(),
                consumer_id: identity.consumer_id(),
                producer_epoch: identity.producer_epoch(),
            },
        )
        .unwrap();
        session.attach_analysis_mapping(occupied).unwrap();

        let response = AnalysisWorkerRegisterResponseV1::decode(
            &service
                .handle_with_fault_route(
                    &mut session,
                    &client,
                    &request.encode().unwrap(),
                    Some(Arc::clone(&route)),
                )
                .unwrap(),
        )
        .unwrap();
        assert!(!response.accepted);
        assert_eq!(response.error, AnalysisWorkerErrorV1::Conflict);
        assert_eq!(
            arbiter.state(),
            crate::safety_arbiter::ArbiterState::FaultLatched
        );
        assert_eq!(
            arbiter.last_disarm_reason(),
            Some(crate::safety_arbiter::DisarmReason::WorkerLost)
        );
        assert_eq!(route.fault_evidence_snapshot().enqueued_count, 0);
        assert!(arbiter.submit_intent(&intent, 10_000).is_err());
    }

    #[test]
    fn failed_controller_mapping_creation_revokes_even_when_the_route_arc_survives() {
        let root = TempRoot::new();
        let sid = current_process_user_sid().unwrap();
        let mut service = AnalysisWorkerRegistrationService::new_test(&sid).unwrap();
        let mut session = ProtectedReplaySession::new(&root.0).unwrap();
        let client = test_client(sid.clone());
        let (mut arbiter, intent, route) = crate::safety_arbiter::tests::armed_with_route();
        let request = controller_request(&route, 503);

        let _occupied = MappedAnalysisRing::create_test(
            &mapping_name(&request),
            &sid,
            AnalysisMappingConfig {
                slot_count: request.slot_count as usize,
                payload_capacity: request.payload_capacity as usize,
                run_id: request.run_id,
                consumer_id: request.consumer_id,
                producer_epoch: request.producer_epoch,
            },
        )
        .unwrap();
        let response = AnalysisWorkerRegisterResponseV1::decode(
            &service
                .handle_with_fault_route(
                    &mut session,
                    &client,
                    &request.encode().unwrap(),
                    Some(Arc::clone(&route)),
                )
                .unwrap(),
        )
        .unwrap();
        assert!(!response.accepted);
        assert_eq!(response.error, AnalysisWorkerErrorV1::Conflict);
        assert_eq!(
            arbiter.state(),
            crate::safety_arbiter::ArbiterState::FaultLatched
        );
        assert_eq!(
            arbiter.last_disarm_reason(),
            Some(crate::safety_arbiter::DisarmReason::WorkerLost)
        );
        assert_eq!(route.fault_evidence_snapshot().enqueued_count, 0);
        assert!(arbiter.submit_intent(&intent, 10_000).is_err());
    }

    #[test]
    fn controller_cache_never_outlives_its_live_mapping_or_replays_to_observer_api() {
        let root = TempRoot::new();
        let sid = current_process_user_sid().unwrap();
        let mut service = AnalysisWorkerRegistrationService::new_test(&sid).unwrap();
        let client = test_client(sid);
        let (mut arbiter, intent, route) = crate::safety_arbiter::tests::armed_with_route();
        let request = controller_request(&route, 502);
        let encoded = request.encode().unwrap();
        let accepted = {
            let mut session = ProtectedReplaySession::new(&root.0).unwrap();
            let first = service
                .handle_with_fault_route(&mut session, &client, &encoded, Some(Arc::clone(&route)))
                .unwrap();
            let replay = service
                .handle_with_fault_route(&mut session, &client, &encoded, Some(Arc::clone(&route)))
                .unwrap();
            assert_eq!(first, replay);
            let public_observer = AnalysisWorkerRegisterResponseV1::decode(
                &service.handle(&mut session, &client, &encoded).unwrap(),
            )
            .unwrap();
            assert!(!public_observer.accepted);
            assert_eq!(public_observer.error, AnalysisWorkerErrorV1::Conflict);
            assert!(arbiter.submit_intent(&intent, 10_000).is_ok());
            AnalysisWorkerRegisterResponseV1::decode(&first)
                .unwrap()
                .accepted
        };
        assert!(accepted);
        // `service.requests` still holds an Arc, but dropping the session's
        // LiveAnalysisBranch has synchronously consumed the controller lease.
        assert_eq!(
            arbiter.state(),
            crate::safety_arbiter::ArbiterState::FaultLatched
        );
        assert!(arbiter.submit_intent(&intent, 10_000).is_err());
        let replay_after_drop = AnalysisWorkerRegisterResponseV1::decode(
            &service
                .handle_with_fault_route(
                    &mut ProtectedReplaySession::new(&root.0).unwrap(),
                    &client,
                    &encoded,
                    Some(route),
                )
                .unwrap(),
        )
        .unwrap();
        assert!(!replay_after_drop.accepted);
        assert_eq!(replay_after_drop.error, AnalysisWorkerErrorV1::Conflict);
    }

    #[test]
    fn restart_or_request_key_reuse_cannot_resume_the_mapping() {
        let root = TempRoot::new();
        let sid = current_process_user_sid().unwrap();
        let mut service = AnalysisWorkerRegistrationService::new_test(&sid).unwrap();
        let mut session = ProtectedReplaySession::new(&root.0).unwrap();
        let client = AuthenticatedPipeClient {
            token_user_sid: sid,
            process_id: 41,
            process_creation_time_100ns: 42,
        };
        let value = request(1, 2);
        let encoded = value.encode().unwrap();
        assert!(
            AnalysisWorkerRegisterResponseV1::decode(
                &service.handle(&mut session, &client, &encoded).unwrap()
            )
            .unwrap()
            .accepted
        );
        let restarted = AuthenticatedPipeClient {
            process_id: 43,
            process_creation_time_100ns: 44,
            ..client.clone()
        };
        let response = AnalysisWorkerRegisterResponseV1::decode(
            &service.handle(&mut session, &restarted, &encoded).unwrap(),
        )
        .unwrap();
        assert!(!response.accepted);
        assert_eq!(response.error, AnalysisWorkerErrorV1::Conflict);

        let mut changed = value;
        changed.worker_build_hash = [0x74; 32];
        let response = AnalysisWorkerRegisterResponseV1::decode(
            &service
                .handle(&mut session, &client, &changed.encode().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(!response.accepted);
        assert_eq!(response.error, AnalysisWorkerErrorV1::Conflict);
    }

    #[test]
    fn observer_health_fault_degrades_without_controller_authority() {
        let root = TempRoot::new();
        let sid = current_process_user_sid().unwrap();
        let mut service = AnalysisWorkerRegistrationService::new_test(&sid).unwrap();
        let mut session = ProtectedReplaySession::new(&root.0).unwrap();
        let client = AuthenticatedPipeClient {
            token_user_sid: sid,
            process_id: 41,
            process_creation_time_100ns: 42,
        };
        let request = request(51, 52);
        assert!(
            AnalysisWorkerRegisterResponseV1::decode(
                &service
                    .handle(&mut session, &client, &request.encode().unwrap())
                    .unwrap()
            )
            .unwrap()
            .accepted
        );
        assert_eq!(
            service.registered_role(request.producer_epoch, request.request_id),
            Some(AnalysisConsumerRoleV1::Observer)
        );
        let dispatch = service
            .observe_worker_health(AnalysisWorkerHealthObservationV1 {
                producer_epoch: request.producer_epoch,
                request_id: request.request_id,
                process_id: client.process_id,
                process_creation_time_100ns: client.process_creation_time_100ns,
                observed_producer_epoch: request.producer_epoch,
                handle_alive: true,
                consumer_heartbeat_monotonic_ns: 10,
                observed_monotonic_ns: 30,
                heartbeat_timeout_ns: 20,
                deadline_missed: false,
            })
            .unwrap()
            .unwrap();
        assert!(dispatch.first_fault);
        assert!(!dispatch.controller_disarmed);
    }

    #[test]
    fn controller_process_epoch_heartbeat_and_deadline_faults_share_fail_closed_route() {
        enum Case {
            ProcessLost,
            WrongProcess,
            WrongEpoch,
            HeartbeatTimeout,
            DeadlineMiss,
        }
        for (index, case) in [
            Case::ProcessLost,
            Case::WrongProcess,
            Case::WrongEpoch,
            Case::HeartbeatTimeout,
            Case::DeadlineMiss,
        ]
        .into_iter()
        .enumerate()
        {
            let root = TempRoot::new();
            let sid = current_process_user_sid().unwrap();
            let mut service = AnalysisWorkerRegistrationService::new_test(&sid).unwrap();
            let mut session = ProtectedReplaySession::new(&root.0).unwrap();
            let client = AuthenticatedPipeClient {
                token_user_sid: sid,
                process_id: 41,
                process_creation_time_100ns: 42,
            };
            let (arbiter, _intent, route) = crate::safety_arbiter::tests::armed_with_route();
            let identity = route.identity();
            let request = AnalysisWorkerRegisterRequestV1 {
                request_id: 100 + index as u64,
                producer_epoch: identity.producer_epoch(),
                run_id: identity.run_id(),
                consumer_id: identity.consumer_id(),
                worker_build_hash: [0x73; 32],
                slot_count: 4,
                payload_capacity: (RECORD_HEADER_LEN + 256) as u32,
            };
            assert!(
                AnalysisWorkerRegisterResponseV1::decode(
                    &service
                        .handle_with_fault_route(
                            &mut session,
                            &client,
                            &request.encode().unwrap(),
                            Some(route),
                        )
                        .unwrap()
                )
                .unwrap()
                .accepted
            );
            assert_eq!(
                service.registered_role(request.producer_epoch, request.request_id),
                Some(AnalysisConsumerRoleV1::Controller)
            );
            let mut observation = AnalysisWorkerHealthObservationV1 {
                producer_epoch: request.producer_epoch,
                request_id: request.request_id,
                process_id: client.process_id,
                process_creation_time_100ns: client.process_creation_time_100ns,
                observed_producer_epoch: request.producer_epoch,
                handle_alive: true,
                consumer_heartbeat_monotonic_ns: 90,
                observed_monotonic_ns: 100,
                heartbeat_timeout_ns: 20,
                deadline_missed: false,
            };
            let expected_reason = match case {
                Case::ProcessLost => {
                    observation.handle_alive = false;
                    crate::safety_arbiter::DisarmReason::WorkerLost
                }
                Case::WrongProcess => {
                    observation.process_id += 1;
                    crate::safety_arbiter::DisarmReason::WorkerLost
                }
                Case::WrongEpoch => {
                    observation.observed_producer_epoch += 1;
                    crate::safety_arbiter::DisarmReason::WorkerLost
                }
                Case::HeartbeatTimeout => {
                    observation.observed_monotonic_ns = 110;
                    crate::safety_arbiter::DisarmReason::WorkerLost
                }
                Case::DeadlineMiss => {
                    observation.deadline_missed = true;
                    crate::safety_arbiter::DisarmReason::DeadlineMiss
                }
            };
            let dispatch = service.observe_worker_health(observation).unwrap().unwrap();
            assert!(dispatch.controller_disarmed);
            assert_eq!(
                arbiter.state(),
                crate::safety_arbiter::ArbiterState::FaultLatched
            );
            assert_eq!(arbiter.last_disarm_reason(), Some(expected_reason));
        }
    }
}
