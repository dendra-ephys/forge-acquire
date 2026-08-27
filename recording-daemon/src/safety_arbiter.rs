//! Fail-closed host SafetyArbiter foundation.
//!
//! This module can be exercised with replay and a dummy load. It deliberately
//! has no hardware transport. Returning a [`StimCommandV1`] is authorization
//! for an independently interlocked device to evaluate the command; it is not
//! evidence that a pulse was delivered.

use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use forge_protocol_v1::{
    sha256, validate_stim_command, validate_stim_intent, DeviceCapabilitiesV1, Hash32, Id16,
    SafetyProfileV1, StimCommandV1, StimIntentV1, StimReceiptV1, WireBody, WorkerTokenLeaseV1,
    PROTOCOL_HASH, REQUIRED_STIM_CAPS, REQUIRED_STIM_RUNTIME, RUNTIME_CLOCK_LOCKED,
    RUNTIME_COMPLIANCE_READY, RUNTIME_EMERGENCY_STOP_HEALTHY, RUNTIME_LINK_HEALTHY,
    RUNTIME_PHYSICAL_ENABLE_ASSERTED, RUNTIME_STIM_POWER_ENABLED, RUNTIME_WATCHDOG_HEALTHY,
};

use crate::analysis_fault_evidence::{
    AnalysisFaultEvidenceDrainError, AnalysisFaultEvidenceQueue, AnalysisFaultEvidenceSnapshotV1,
};
use crate::analysis_ring::{
    AnalysisBranchIdentityV1, AnalysisConsumerRoleV1, AnalysisFaultEventV1, AnalysisFaultV1,
};

const MAX_TEMPLATE_COUNT: usize = 64;
const MAX_NONCE_LEDGER: usize = 65_536;
const TEMPLATE_CATALOG_DOMAIN: &[u8] = b"FORGE-STIM-TEMPLATE-CATALOG-V1\0";
const COMMAND_ID_DOMAIN: &[u8] = b"FORGE-STIM-COMMAND-ID-V1\0";
const COMMAND_NONCE_DOMAIN: &[u8] = b"FORGE-STIM-COMMAND-NONCE-V1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedStimTemplateV1 {
    pub template_id: u16,
    pub current_na: u32,
    pub cathodic_phase_us: u32,
    pub interphase_us: u32,
    pub anodic_phase_us: u32,
    pub frequency_millihz: u32,
    pub pulse_count: u32,
}

impl FixedStimTemplateV1 {
    fn append_canonical(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.template_id.to_le_bytes());
        for value in [
            self.current_na,
            self.cathodic_phase_us,
            self.interphase_us,
            self.anodic_phase_us,
            self.frequency_millihz,
            self.pulse_count,
        ] {
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// Canonical hash of a sorted, duplicate-free fixed-template catalog.
///
/// The hash is deliberately computed again inside the Rust data plane. A UI
/// supplied `template_hash` is never accepted as proof of the template bytes.
pub fn template_catalog_hash(templates: &[FixedStimTemplateV1]) -> Result<Hash32, ArbiterError> {
    if templates.is_empty() || templates.len() > MAX_TEMPLATE_COUNT {
        return Err(ArbiterError::TemplateCatalog);
    }
    let mut sorted = templates.to_vec();
    sorted.sort_unstable_by_key(|template| template.template_id);
    if sorted
        .windows(2)
        .any(|pair| pair[0].template_id == pair[1].template_id)
        || sorted.iter().any(|template| template.template_id == 0)
    {
        return Err(ArbiterError::TemplateCatalog);
    }
    let mut canonical = Vec::with_capacity(TEMPLATE_CATALOG_DOMAIN.len() + 4 + sorted.len() * 26);
    canonical.extend_from_slice(TEMPLATE_CATALOG_DOMAIN);
    canonical.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for template in sorted {
        template.append_canonical(&mut canonical);
    }
    Ok(sha256(&canonical))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArbiterState {
    Disarmed,
    Armed,
    AwaitingReceipt,
    FaultLatched,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisarmReason {
    Operator,
    DataGap,
    SourceCrc,
    Overflow,
    ClockLoss,
    LinkLoss,
    WorkerLost,
    Watchdog,
    EmergencyStop,
    PhysicalEnable,
    StimPower,
    Compliance,
    DeadlineMiss,
    ReceiptMismatch,
    ReceiptRejected,
    DuplicateIntent,
    NonceLedgerFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArbiterError {
    NotDisarmed,
    NotArmed,
    FaultLatched,
    TemplateCatalog,
    TemplateHash,
    TemplateMissing,
    Profile,
    Capability,
    Token,
    ProtocolSafety,
    DuplicateIntent,
    PendingReceipt,
    ReceiptMissing,
    ReceiptMismatch,
    ReceiptRejected,
    Deadline,
    NonceLedgerFull,
    AnalysisController,
    StaleArmEpoch,
}

impl fmt::Display for ArbiterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ArbiterError {}

#[derive(Clone, Debug)]
struct ArmedContext {
    capabilities: DeviceCapabilitiesV1,
    profile: SafetyProfileV1,
    profile_hash: Hash32,
    token: WorkerTokenLeaseV1,
    templates: Vec<FixedStimTemplateV1>,
}

#[derive(Clone, Debug)]
struct PendingCommand {
    command: StimCommandV1,
}

#[derive(Debug)]
struct AnalysisRuntimeInterlock {
    fault_code: AtomicU8,
    current_arm_epoch: AtomicU64,
    last_revoked_arm_epoch: AtomicU64,
    active_controller_lease: AtomicU64,
    next_controller_lease: AtomicU64,
}

impl Default for AnalysisRuntimeInterlock {
    fn default() -> Self {
        Self {
            fault_code: AtomicU8::new(0),
            current_arm_epoch: AtomicU64::new(0),
            last_revoked_arm_epoch: AtomicU64::new(0),
            active_controller_lease: AtomicU64::new(0),
            next_controller_lease: AtomicU64::new(1),
        }
    }
}

impl AnalysisRuntimeInterlock {
    fn begin_arm(&self, arm_epoch: u64) -> Result<(), ArbiterError> {
        if arm_epoch == 0
            || self.fault().is_some()
            || self.current_arm_epoch.load(Ordering::Acquire) != 0
            || self.active_controller_lease.load(Ordering::Acquire) != 0
        {
            return Err(ArbiterError::AnalysisController);
        }
        if arm_epoch <= self.last_revoked_arm_epoch.load(Ordering::Acquire) {
            return Err(ArbiterError::StaleArmEpoch);
        }
        self.current_arm_epoch.store(arm_epoch, Ordering::Release);
        Ok(())
    }

    fn mint_controller_lease(&self, arm_epoch: u64) -> Result<u64, ArbiterError> {
        if self.fault().is_some()
            || arm_epoch == 0
            || self.current_arm_epoch.load(Ordering::Acquire) != arm_epoch
        {
            return Err(ArbiterError::AnalysisController);
        }
        let lease = self.next_controller_lease.fetch_add(1, Ordering::AcqRel);
        if lease == 0 || lease == u64::MAX {
            return Err(ArbiterError::AnalysisController);
        }
        self.active_controller_lease
            .compare_exchange(0, lease, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ArbiterError::AnalysisController)?;
        Ok(lease)
    }

    fn controller_valid(&self, arm_epoch: u64) -> bool {
        arm_epoch != 0
            && self.fault().is_none()
            && self.current_arm_epoch.load(Ordering::Acquire) == arm_epoch
            && self.active_controller_lease.load(Ordering::Acquire) != 0
    }

    fn controller_lease_valid(&self, arm_epoch: u64, lease: u64) -> bool {
        arm_epoch != 0
            && lease != 0
            && self.fault().is_none()
            && self.current_arm_epoch.load(Ordering::Acquire) == arm_epoch
            && self.active_controller_lease.load(Ordering::Acquire) == lease
    }

    fn fault_controller(&self, arm_epoch: u64, lease: u64, fault: AnalysisFaultV1) -> bool {
        if arm_epoch == 0
            || lease == 0
            || self.current_arm_epoch.load(Ordering::Acquire) != arm_epoch
            || self.active_controller_lease.load(Ordering::Acquire) != lease
        {
            return false;
        }
        let _ = self.fault_code.compare_exchange(
            0,
            analysis_fault_code(fault),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.active_controller_lease.store(0, Ordering::Release);
        self.current_arm_epoch.store(0, Ordering::Release);
        self.last_revoked_arm_epoch
            .fetch_max(arm_epoch, Ordering::AcqRel);
        true
    }

    fn revoke_arm(&self) {
        let arm_epoch = self.current_arm_epoch.swap(0, Ordering::AcqRel);
        self.active_controller_lease.store(0, Ordering::Release);
        if arm_epoch != 0 {
            self.last_revoked_arm_epoch
                .fetch_max(arm_epoch, Ordering::AcqRel);
        }
    }

    fn fault(&self) -> Option<AnalysisFaultV1> {
        analysis_fault_from_code(self.fault_code.load(Ordering::Acquire))
    }

    fn acknowledge_fault(&self) {
        self.fault_code.store(0, Ordering::Release);
    }
}

pub struct AnalysisBranchFaultRoute {
    identity: AnalysisBranchIdentityV1,
    role: AnalysisConsumerRoleV1,
    controller: Option<ControllerFaultLease>,
    attached: AtomicBool,
    degraded: AtomicBool,
    evidence_queue: Arc<AnalysisFaultEvidenceQueue>,
}

struct ControllerFaultLease {
    interlock: Arc<AnalysisRuntimeInterlock>,
    arm_epoch: u64,
    lease: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisFaultDispatchV1 {
    pub first_fault: bool,
    pub controller_disarmed: bool,
    /// True only when the event entered the bounded in-memory queue. It is not
    /// evidence that a worker drained or durably persisted the event.
    pub event_enqueued: bool,
}

impl AnalysisBranchFaultRoute {
    pub(crate) fn observer(identity: AnalysisBranchIdentityV1) -> Arc<Self> {
        Self::observer_with_evidence_queue(
            identity,
            Arc::new(AnalysisFaultEvidenceQueue::default()),
        )
    }

    fn observer_with_evidence_queue(
        identity: AnalysisBranchIdentityV1,
        evidence_queue: Arc<AnalysisFaultEvidenceQueue>,
    ) -> Arc<Self> {
        Arc::new(Self {
            identity,
            role: AnalysisConsumerRoleV1::Observer,
            controller: None,
            attached: AtomicBool::new(false),
            degraded: AtomicBool::new(false),
            evidence_queue,
        })
    }

    pub fn identity(&self) -> AnalysisBranchIdentityV1 {
        self.identity
    }

    pub fn role(&self) -> AnalysisConsumerRoleV1 {
        self.role
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    pub fn fault_evidence_snapshot(&self) -> AnalysisFaultEvidenceSnapshotV1 {
        self.evidence_queue.snapshot()
    }

    pub fn try_drain_fault_evidence(
        &self,
        max_events: usize,
    ) -> Result<Vec<AnalysisFaultEventV1>, AnalysisFaultEvidenceDrainError> {
        self.evidence_queue.try_drain(max_events)
    }

    #[cfg(test)]
    pub(crate) fn prefill_fault_evidence_for_test(&self) {
        for sequence in 0..self.evidence_queue.capacity() {
            assert!(self.evidence_queue.try_enqueue(AnalysisFaultEventV1 {
                branch: self.identity,
                role: self.role,
                fault: AnalysisFaultV1::RingFull,
                observed_monotonic_ns: sequence as u64 + 1,
                expected_journal_sequence: Some(sequence as u64),
                observed_journal_sequence: Some(sequence as u64),
            }));
        }
    }

    #[cfg(test)]
    pub(crate) fn disconnect_fault_evidence_receiver_for_test(&self) {
        self.evidence_queue.disconnect_receiver_for_test();
    }

    #[cfg(test)]
    pub(crate) fn fault_evidence_queue_for_test(&self) -> Arc<AnalysisFaultEvidenceQueue> {
        Arc::clone(&self.evidence_queue)
    }

    pub(crate) fn bind_mapping_once(&self) -> bool {
        self.attached
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Revoke a controller route whose requested registration or live mapping
    /// disappeared.  This path is intentionally atomic-only: callers use it
    /// from guards and `Drop`, where evidence I/O would be unsafe.
    pub(crate) fn fail_closed_controller_loss(&self) -> bool {
        self.degraded.store(true, Ordering::Release);
        self.controller.as_ref().is_some_and(|controller| {
            controller.interlock.fault_controller(
                controller.arm_epoch,
                controller.lease,
                AnalysisFaultV1::ConsumerLost,
            )
        })
    }

    pub(crate) fn controller_mapping_is_live(&self) -> bool {
        self.attached.load(Ordering::Acquire)
            && self.controller.as_ref().is_some_and(|controller| {
                controller
                    .interlock
                    .controller_lease_valid(controller.arm_epoch, controller.lease)
            })
    }

    /// Synchronously performs the atomic safety transition, marks the first
    /// route fault, then uses only the concrete queue's bounded `try_send`.
    pub fn dispatch(
        &self,
        fault: AnalysisFaultV1,
        observed_monotonic_ns: u64,
        expected_journal_sequence: Option<u64>,
        observed_journal_sequence: Option<u64>,
    ) -> AnalysisFaultDispatchV1 {
        // Controller authority is revoked before any other route mutation or
        // evidence operation. Observer routes have no controller lease.
        let controller_disarmed = self.controller.as_ref().is_some_and(|controller| {
            controller
                .interlock
                .fault_controller(controller.arm_epoch, controller.lease, fault)
        });
        let first_fault = !self.degraded.swap(true, Ordering::AcqRel);
        let event_enqueued = if first_fault {
            self.evidence_queue.try_enqueue(AnalysisFaultEventV1 {
                branch: self.identity,
                role: self.role,
                fault,
                observed_monotonic_ns,
                expected_journal_sequence,
                observed_journal_sequence,
            })
        } else {
            false
        };
        AnalysisFaultDispatchV1 {
            first_fault,
            controller_disarmed,
            event_enqueued,
        }
    }
}

impl Drop for AnalysisBranchFaultRoute {
    fn drop(&mut self) {
        // A controller route that never reaches registration still owns the
        // active lease.  Final release must fail closed without attempting
        // evidence I/O; repeated explicit faults or live-branch cleanup are
        // intentionally harmless through the lease match in the interlock.
        self.fail_closed_controller_loss();
    }
}

fn analysis_fault_code(fault: AnalysisFaultV1) -> u8 {
    match fault {
        AnalysisFaultV1::RingFull => 1,
        AnalysisFaultV1::ConsumerLost => 2,
        AnalysisFaultV1::HeartbeatTimeout => 3,
        AnalysisFaultV1::DataGap => 4,
        AnalysisFaultV1::CrcFault => 5,
        AnalysisFaultV1::DeadlineMiss => 6,
    }
}

fn analysis_fault_from_code(code: u8) -> Option<AnalysisFaultV1> {
    match code {
        1 => Some(AnalysisFaultV1::RingFull),
        2 => Some(AnalysisFaultV1::ConsumerLost),
        3 => Some(AnalysisFaultV1::HeartbeatTimeout),
        4 => Some(AnalysisFaultV1::DataGap),
        5 => Some(AnalysisFaultV1::CrcFault),
        6 => Some(AnalysisFaultV1::DeadlineMiss),
        _ => None,
    }
}

fn analysis_fault_disarm_reason(fault: AnalysisFaultV1) -> DisarmReason {
    match fault {
        AnalysisFaultV1::RingFull => DisarmReason::Overflow,
        AnalysisFaultV1::ConsumerLost | AnalysisFaultV1::HeartbeatTimeout => {
            DisarmReason::WorkerLost
        }
        AnalysisFaultV1::DataGap => DisarmReason::DataGap,
        AnalysisFaultV1::CrcFault => DisarmReason::SourceCrc,
        AnalysisFaultV1::DeadlineMiss => DisarmReason::DeadlineMiss,
    }
}

/// Single-controller, single-command SafetyArbiter.
///
/// The processed intent and receipt nonce ledgers survive disarm/re-arm within
/// the same Run. They are bounded; exhaustion latches a fault instead of
/// evicting old entries and risking duplicate physical execution.
pub struct SafetyArbiter {
    state: ArbiterState,
    context: Option<ArmedContext>,
    pending: Option<PendingCommand>,
    analysis_interlock: Arc<AnalysisRuntimeInterlock>,
    ledger_run_id: Option<Id16>,
    processed_intents: HashSet<Id16>,
    processed_receipts: HashSet<Id16>,
    last_disarm_reason: Option<DisarmReason>,
}

impl Default for SafetyArbiter {
    fn default() -> Self {
        Self {
            state: ArbiterState::Disarmed,
            context: None,
            pending: None,
            analysis_interlock: Arc::new(AnalysisRuntimeInterlock::default()),
            ledger_run_id: None,
            processed_intents: HashSet::new(),
            processed_receipts: HashSet::new(),
            last_disarm_reason: None,
        }
    }
}

impl SafetyArbiter {
    pub fn state(&self) -> ArbiterState {
        if self.analysis_interlock.fault().is_some() {
            ArbiterState::FaultLatched
        } else {
            self.state
        }
    }

    pub fn last_disarm_reason(&self) -> Option<DisarmReason> {
        self.analysis_interlock
            .fault()
            .map(analysis_fault_disarm_reason)
            .or(self.last_disarm_reason)
    }

    pub fn pending_command(&self) -> Option<&StimCommandV1> {
        if self.analysis_interlock.fault().is_some() {
            None
        } else {
            self.pending.as_ref().and_then(|pending| {
                self.analysis_interlock
                    .controller_valid(pending.command.arm_epoch)
                    .then_some(&pending.command)
            })
        }
    }

    /// Mint the sole controller fault route for the current frozen arm epoch.
    /// Observer routes are constructed separately and never receive control
    /// authority.  The route has no public constructor.
    pub fn analysis_controller_fault_route(
        &mut self,
        identity: AnalysisBranchIdentityV1,
    ) -> Result<Arc<AnalysisBranchFaultRoute>, ArbiterError> {
        self.analysis_controller_fault_route_with_evidence_queue(
            identity,
            Arc::new(AnalysisFaultEvidenceQueue::default()),
        )
    }

    fn analysis_controller_fault_route_with_evidence_queue(
        &mut self,
        identity: AnalysisBranchIdentityV1,
        evidence_queue: Arc<AnalysisFaultEvidenceQueue>,
    ) -> Result<Arc<AnalysisBranchFaultRoute>, ArbiterError> {
        self.synchronize_analysis_fault();
        if self.state != ArbiterState::Armed {
            return Err(ArbiterError::NotArmed);
        }
        let context = self.context.as_ref().ok_or(ArbiterError::NotArmed)?;
        if identity.run_id() != context.token.run_id
            || identity.consumer_id() != context.token.worker_id
        {
            return Err(ArbiterError::AnalysisController);
        }
        let arm_epoch = context.token.arm_epoch;
        let lease = self.analysis_interlock.mint_controller_lease(arm_epoch)?;
        Ok(Arc::new(AnalysisBranchFaultRoute {
            identity,
            role: AnalysisConsumerRoleV1::Controller,
            controller: Some(ControllerFaultLease {
                interlock: Arc::clone(&self.analysis_interlock),
                arm_epoch,
                lease,
            }),
            attached: AtomicBool::new(false),
            degraded: AtomicBool::new(false),
            evidence_queue,
        }))
    }

    pub fn arm(
        &mut self,
        capabilities: DeviceCapabilitiesV1,
        profile: SafetyProfileV1,
        token: WorkerTokenLeaseV1,
        templates: Vec<FixedStimTemplateV1>,
        now_global_time_ns: u64,
    ) -> Result<(), ArbiterError> {
        self.synchronize_analysis_fault();
        if self.state == ArbiterState::FaultLatched {
            return Err(ArbiterError::FaultLatched);
        }
        if self.state != ArbiterState::Disarmed {
            return Err(ArbiterError::NotDisarmed);
        }
        let profile_body = profile.encode_body().map_err(|_| ArbiterError::Profile)?;
        let profile_hash = sha256(&profile_body);
        profile
            .validate_approved()
            .map_err(|_| ArbiterError::Profile)?;
        validate_capability_and_token(
            &capabilities,
            &profile,
            &profile_hash,
            &token,
            now_global_time_ns,
        )?;
        let catalog_hash = template_catalog_hash(&templates)?;
        if catalog_hash != token.template_hash {
            return Err(ArbiterError::TemplateHash);
        }
        for template in &templates {
            validate_template(template, &profile)?;
        }
        self.analysis_interlock.begin_arm(token.arm_epoch)?;

        if self.ledger_run_id != Some(token.run_id) {
            self.processed_intents.clear();
            self.processed_receipts.clear();
            self.ledger_run_id = Some(token.run_id);
        }
        self.context = Some(ArmedContext {
            capabilities,
            profile,
            profile_hash,
            token,
            templates,
        });
        self.pending = None;
        self.last_disarm_reason = None;
        self.state = ArbiterState::Armed;
        Ok(())
    }

    pub fn submit_intent(
        &mut self,
        intent: &StimIntentV1,
        now_global_time_ns: u64,
    ) -> Result<StimCommandV1, ArbiterError> {
        self.synchronize_analysis_fault();
        match self.state {
            ArbiterState::FaultLatched => return Err(ArbiterError::FaultLatched),
            ArbiterState::AwaitingReceipt => return Err(ArbiterError::PendingReceipt),
            ArbiterState::Armed => {}
            ArbiterState::Disarmed => return Err(ArbiterError::NotArmed),
        }
        if self.processed_intents.contains(&intent.intent_nonce) {
            self.latch(DisarmReason::DuplicateIntent);
            return Err(ArbiterError::DuplicateIntent);
        }
        if self.processed_intents.len() >= MAX_NONCE_LEDGER {
            self.latch(DisarmReason::NonceLedgerFull);
            return Err(ArbiterError::NonceLedgerFull);
        }

        let arm_epoch = self
            .context
            .as_ref()
            .ok_or(ArbiterError::NotArmed)?
            .token
            .arm_epoch;
        if !self.analysis_interlock.controller_valid(arm_epoch) {
            self.latch(DisarmReason::WorkerLost);
            return Err(ArbiterError::AnalysisController);
        }
        let context = self.context.as_ref().ok_or(ArbiterError::NotArmed)?;
        validate_stim_intent(
            &context.capabilities,
            Some(&context.profile),
            &context.profile_hash,
            Some(&context.token),
            intent,
            context.token.arm_epoch,
            now_global_time_ns,
        )
        .map_err(|_| ArbiterError::ProtocolSafety)?;
        let template = context
            .templates
            .iter()
            .find(|template| template.template_id == intent.template_id)
            .ok_or(ArbiterError::TemplateMissing)?;
        if now_global_time_ns == 0 || now_global_time_ns >= intent.deadline_global_time_ns {
            self.latch(DisarmReason::DeadlineMiss);
            return Err(ArbiterError::Deadline);
        }

        let command_id = derive_id(
            COMMAND_ID_DOMAIN,
            &intent.run_id,
            &context.token.token_id,
            &intent.intent_nonce,
            context.token.arm_epoch,
        );
        let command_nonce = derive_id(
            COMMAND_NONCE_DOMAIN,
            &intent.run_id,
            &context.token.token_id,
            &intent.intent_nonce,
            context.token.arm_epoch,
        );
        let command = StimCommandV1 {
            run_id: intent.run_id,
            command_id,
            intent_nonce: intent.intent_nonce,
            device_id: context.capabilities.device_id,
            safety_profile_hash: context.profile_hash,
            template_hash: intent.template_hash,
            channel_map_hash: intent.channel_map_hash,
            target_channel: intent.target_channel,
            template_id: intent.template_id,
            current_na: template.current_na,
            cathodic_phase_us: template.cathodic_phase_us,
            interphase_us: template.interphase_us,
            anodic_phase_us: template.anodic_phase_us,
            frequency_millihz: template.frequency_millihz,
            pulse_count: template.pulse_count,
            deadline_global_time_ns: intent.deadline_global_time_ns,
            execute_not_before_global_time_ns: now_global_time_ns,
            arm_epoch: context.token.arm_epoch,
            command_nonce,
        };
        validate_stim_command(
            &context.capabilities,
            &context.profile,
            &context.profile_hash,
            &context.token,
            intent,
            &command,
            now_global_time_ns,
        )
        .map_err(|_| ArbiterError::ProtocolSafety)?;

        // Commit the nonce before the command can cross a transport boundary.
        // If transport submission subsequently becomes ambiguous, the caller
        // must fault-latch and never regenerate this command.
        self.processed_intents.insert(intent.intent_nonce);
        self.pending = Some(PendingCommand {
            command: command.clone(),
        });
        self.state = ArbiterState::AwaitingReceipt;
        if !self.analysis_interlock.controller_valid(command.arm_epoch) {
            self.synchronize_analysis_fault();
            if self.state != ArbiterState::FaultLatched {
                self.latch(DisarmReason::WorkerLost);
            }
            return Err(ArbiterError::FaultLatched);
        }
        Ok(command)
    }

    pub fn accept_receipt(&mut self, receipt: &StimReceiptV1) -> Result<(), ArbiterError> {
        self.synchronize_analysis_fault();
        if self.state == ArbiterState::FaultLatched {
            return Err(ArbiterError::FaultLatched);
        }
        if self.processed_receipts.contains(&receipt.receipt_nonce) {
            self.latch(DisarmReason::ReceiptMismatch);
            return Err(ArbiterError::ReceiptMismatch);
        }
        if self.state != ArbiterState::AwaitingReceipt {
            if self.state == ArbiterState::Armed {
                self.latch(DisarmReason::ReceiptMismatch);
                return Err(ArbiterError::ReceiptMismatch);
            }
            return Err(ArbiterError::ReceiptMissing);
        }
        if self.processed_receipts.len() >= MAX_NONCE_LEDGER {
            self.latch(DisarmReason::NonceLedgerFull);
            return Err(ArbiterError::NonceLedgerFull);
        }
        receipt
            .encode_body()
            .map_err(|_| ArbiterError::ReceiptMismatch)?;
        let context = self.context.as_ref().ok_or(ArbiterError::NotArmed)?;
        let pending = self.pending.as_ref().ok_or(ArbiterError::ReceiptMissing)?;
        let command = &pending.command;
        if !self.analysis_interlock.controller_valid(command.arm_epoch) {
            self.latch(DisarmReason::WorkerLost);
            return Err(ArbiterError::AnalysisController);
        }
        let matching = receipt.run_id == command.run_id
            && receipt.command_id == command.command_id
            && receipt.intent_nonce == command.intent_nonce
            && receipt.device_id == command.device_id
            && receipt.target_channel == command.target_channel
            && receipt.template_id == command.template_id
            && receipt.arm_epoch == command.arm_epoch;
        if !matching {
            self.latch(DisarmReason::ReceiptMismatch);
            return Err(ArbiterError::ReceiptMismatch);
        }
        if receipt.result != 1 {
            self.processed_receipts.insert(receipt.receipt_nonce);
            self.latch(DisarmReason::ReceiptRejected);
            return Err(ArbiterError::ReceiptRejected);
        }
        if receipt.actual_start_global_time_ns < command.execute_not_before_global_time_ns
            || receipt.actual_start_global_time_ns >= command.deadline_global_time_ns
            || receipt.actual_end_global_time_ns < receipt.actual_start_global_time_ns
            || receipt.measured_compliance_uv < context.profile.compliance_min_uv
            || receipt.measured_compliance_uv > context.profile.compliance_max_uv
            || receipt.peak_current_na > context.profile.max_current_na
            || receipt.delivered_phase_charge_pc > context.profile.max_charge_per_phase_pc
        {
            self.latch(DisarmReason::ReceiptMismatch);
            return Err(ArbiterError::ReceiptMismatch);
        }
        self.processed_receipts.insert(receipt.receipt_nonce);
        self.pending = None;
        self.state = ArbiterState::Armed;
        Ok(())
    }

    /// Check token and receipt deadlines using the hardware global-time domain.
    pub fn tick(&mut self, now_global_time_ns: u64) {
        self.synchronize_analysis_fault();
        if self.state == ArbiterState::FaultLatched {
            return;
        }
        let expired_token = self
            .context
            .as_ref()
            .is_some_and(|context| now_global_time_ns >= context.token.expires_global_time_ns);
        let expired_receipt = self
            .pending
            .as_ref()
            .is_some_and(|pending| now_global_time_ns >= pending.command.deadline_global_time_ns);
        if expired_token || expired_receipt {
            self.latch(DisarmReason::DeadlineMiss);
        }
    }

    /// Revalidate the independently read hardware safety snapshot. Callers
    /// must invoke this for every authenticated capability/health update; any
    /// missing bit latches a fault even while a receipt is outstanding.
    pub fn observe_runtime(&mut self, latest: &DeviceCapabilitiesV1) {
        self.synchronize_analysis_fault();
        if !matches!(
            self.state,
            ArbiterState::Armed | ArbiterState::AwaitingReceipt
        ) {
            return;
        }
        let Some(context) = self.context.as_ref() else {
            self.latch(DisarmReason::LinkLoss);
            return;
        };
        if latest.encode_body().is_err()
            || latest.device_id != context.capabilities.device_id
            || latest.hardware_protocol_hash != PROTOCOL_HASH
            || latest.stim_kind != context.capabilities.stim_kind
            || latest.stim_channels != context.capabilities.stim_channels
            || latest.capability_flags & REQUIRED_STIM_CAPS != REQUIRED_STIM_CAPS
        {
            self.latch(DisarmReason::LinkLoss);
            return;
        }
        let flags = latest.runtime_safety_flags;
        let reason = if flags & RUNTIME_PHYSICAL_ENABLE_ASSERTED == 0 {
            Some(DisarmReason::PhysicalEnable)
        } else if flags & RUNTIME_EMERGENCY_STOP_HEALTHY == 0 {
            Some(DisarmReason::EmergencyStop)
        } else if flags & RUNTIME_STIM_POWER_ENABLED == 0 {
            Some(DisarmReason::StimPower)
        } else if flags & RUNTIME_WATCHDOG_HEALTHY == 0 {
            Some(DisarmReason::Watchdog)
        } else if flags & RUNTIME_COMPLIANCE_READY == 0 {
            Some(DisarmReason::Compliance)
        } else if flags & RUNTIME_CLOCK_LOCKED == 0 {
            Some(DisarmReason::ClockLoss)
        } else if flags & RUNTIME_LINK_HEALTHY == 0 {
            Some(DisarmReason::LinkLoss)
        } else {
            None
        };
        if let Some(reason) = reason {
            self.latch(reason);
        } else if let Some(context) = self.context.as_mut() {
            context.capabilities.runtime_safety_flags = flags;
        }
    }

    pub fn disarm(&mut self, reason: DisarmReason) {
        self.analysis_interlock.revoke_arm();
        self.context = None;
        self.pending = None;
        self.last_disarm_reason = Some(reason);
        self.state = ArbiterState::Disarmed;
    }

    pub fn latch(&mut self, reason: DisarmReason) {
        self.analysis_interlock.revoke_arm();
        self.context = None;
        self.pending = None;
        self.last_disarm_reason = Some(reason);
        self.state = ArbiterState::FaultLatched;
    }

    /// Acknowledgement only clears the latch. A fresh `arm` with a still-valid
    /// token and independently re-read hardware state is always required.
    pub fn acknowledge_fault(&mut self) {
        self.synchronize_analysis_fault();
        if self.state == ArbiterState::FaultLatched {
            self.analysis_interlock.acknowledge_fault();
            self.state = ArbiterState::Disarmed;
        }
    }

    fn synchronize_analysis_fault(&mut self) {
        let Some(fault) = self.analysis_interlock.fault() else {
            return;
        };
        self.context = None;
        self.pending = None;
        self.last_disarm_reason = Some(analysis_fault_disarm_reason(fault));
        self.state = ArbiterState::FaultLatched;
    }
}

fn validate_capability_and_token(
    capabilities: &DeviceCapabilitiesV1,
    profile: &SafetyProfileV1,
    profile_hash: &Hash32,
    token: &WorkerTokenLeaseV1,
    now_global_time_ns: u64,
) -> Result<(), ArbiterError> {
    capabilities
        .encode_body()
        .map_err(|_| ArbiterError::Capability)?;
    token.encode_body().map_err(|_| ArbiterError::Token)?;
    if capabilities.hardware_protocol_hash != PROTOCOL_HASH
        || capabilities.stim_kind != 1
        || capabilities.stim_channels != 16
        || capabilities.capability_flags & REQUIRED_STIM_CAPS != REQUIRED_STIM_CAPS
        || capabilities.runtime_safety_flags & REQUIRED_STIM_RUNTIME != REQUIRED_STIM_RUNTIME
    {
        return Err(ArbiterError::Capability);
    }
    if token.role != 2
        || token.state != 1
        || token.arm_epoch == 0
        || now_global_time_ns < token.issued_global_time_ns
        || now_global_time_ns >= token.expires_global_time_ns
        || token.safety_profile_id != profile.profile_id
        || token.safety_profile_hash != *profile_hash
    {
        return Err(ArbiterError::Token);
    }
    Ok(())
}

fn validate_template(
    template: &FixedStimTemplateV1,
    profile: &SafetyProfileV1,
) -> Result<(), ArbiterError> {
    if template.template_id == 0
        || template.current_na == 0
        || template.current_na > profile.max_current_na
        || template.cathodic_phase_us == 0
        || template.cathodic_phase_us > profile.max_phase_width_us
        || template.anodic_phase_us != template.cathodic_phase_us
        || template.interphase_us < profile.min_interphase_us
        || template.frequency_millihz == 0
        || template.frequency_millihz > profile.max_frequency_millihz
        || template.pulse_count == 0
        || template.pulse_count > profile.max_train_pulses
    {
        return Err(ArbiterError::TemplateCatalog);
    }
    let charge_pc = div_ceil(
        template.current_na as u128 * template.cathodic_phase_us as u128,
        1_000,
    );
    let density = div_ceil(charge_pc * 1_000_000, profile.exposed_area_um2 as u128);
    let pulse_width_us = template.cathodic_phase_us as u128
        + template.interphase_us as u128
        + template.anodic_phase_us as u128;
    let duty_ppm = div_ceil(pulse_width_us * template.frequency_millihz as u128, 1_000);
    let waveform_ms = div_ceil(pulse_width_us, 1_000);
    let period_ms = div_ceil(1_000_000, template.frequency_millihz as u128);
    let train_ms = (template.pulse_count.saturating_sub(1) as u128)
        .saturating_mul(period_ms)
        .saturating_add(waveform_ms);
    if charge_pc > profile.max_charge_per_phase_pc as u128
        || density > profile.max_charge_density_pc_per_mm2 as u128
        || duty_ppm > profile.max_duty_cycle_ppm as u128
        || train_ms > profile.max_train_duration_ms as u128
    {
        return Err(ArbiterError::TemplateCatalog);
    }
    Ok(())
}

fn derive_id(domain: &[u8], run: &Id16, token: &Id16, intent: &Id16, epoch: u64) -> Id16 {
    let mut bytes = Vec::with_capacity(domain.len() + 56);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(run);
    bytes.extend_from_slice(token);
    bytes.extend_from_slice(intent);
    bytes.extend_from_slice(&epoch.to_le_bytes());
    let digest = sha256(&bytes);
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

fn div_ceil(numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        return u128::MAX;
    }
    numerator / denominator + u128::from(!numerator.is_multiple_of(denominator))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use forge_protocol_v1::{
        CAP_ACK_REPLAY, CAP_DEFAULT_OFF_STIM_POWER_GATE, CAP_EMERGENCY_STOP_LOOP, CAP_GLOBAL_TIME,
        CAP_HARDWARE_WATCHDOG, CAP_NONCE_DEDUP, CAP_NO_OVERLAP_STIM, CAP_PHYSICAL_ENABLE_INTERLOCK,
        CAP_STIM_RECEIPTS, CAP_STOP_ACK, RUNTIME_CLOCK_LOCKED, RUNTIME_COMPLIANCE_READY,
        RUNTIME_EMERGENCY_STOP_HEALTHY, RUNTIME_LINK_HEALTHY, RUNTIME_PHYSICAL_ENABLE_ASSERTED,
        RUNTIME_STIM_POWER_ENABLED, RUNTIME_WATCHDOG_HEALTHY,
    };

    const NOW: u64 = 10_000;

    fn hash(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn id(byte: u8) -> Id16 {
        [byte; 16]
    }

    fn profile() -> SafetyProfileV1 {
        SafetyProfileV1 {
            profile_id: id(10),
            approval_state: 1,
            electrode_material: 5,
            recovery_policy: 2,
            wire_diameter_nm: 25_000,
            exposed_area_um2: 1_000_000,
            impedance_min_ohm: 1_000,
            impedance_max_ohm: 1_000_000,
            max_current_na: 100_000,
            max_phase_width_us: 500,
            min_interphase_us: 50,
            max_frequency_millihz: 100_000,
            max_train_pulses: 10,
            max_train_duration_ms: 10_000,
            max_duty_cycle_ppm: 100_000,
            max_charge_per_phase_pc: 50_000,
            max_charge_density_pc_per_mm2: 100_000,
            compliance_min_uv: -5_000_000,
            compliance_max_uv: 5_000_000,
            experiment_protocol_hash: hash(11),
            electrode_geometry_hash: hash(12),
            hardware_build_hash: hash(13),
            software_build_hash: hash(14),
            approved_limits_hash: hash(15),
            approval_authority_hash: hash(16),
        }
    }

    fn template() -> FixedStimTemplateV1 {
        FixedStimTemplateV1 {
            template_id: 1,
            current_na: 50_000,
            cathodic_phase_us: 200,
            interphase_us: 100,
            anodic_phase_us: 200,
            frequency_millihz: 10_000,
            pulse_count: 2,
        }
    }

    fn fixture() -> (
        DeviceCapabilitiesV1,
        SafetyProfileV1,
        WorkerTokenLeaseV1,
        StimIntentV1,
    ) {
        let profile = profile();
        let profile_hash = sha256(&profile.encode_body().unwrap());
        let template_hash = template_catalog_hash(&[template()]).unwrap();
        let capabilities = DeviceCapabilitiesV1 {
            device_id: id(2),
            transport: 1,
            max_pods: 1,
            max_channels_per_pod: 48,
            sample_format_mask: 1,
            min_sample_rate_hz: 30_000,
            max_sample_rate_hz: 30_000,
            stim_kind: 1,
            stim_channels: 16,
            max_sample_block_us: 1_000,
            capability_flags: CAP_ACK_REPLAY
                | CAP_GLOBAL_TIME
                | CAP_STOP_ACK
                | CAP_STIM_RECEIPTS
                | CAP_PHYSICAL_ENABLE_INTERLOCK
                | CAP_HARDWARE_WATCHDOG
                | CAP_NONCE_DEDUP
                | CAP_NO_OVERLAP_STIM
                | CAP_EMERGENCY_STOP_LOOP
                | CAP_DEFAULT_OFF_STIM_POWER_GATE,
            runtime_safety_flags: RUNTIME_PHYSICAL_ENABLE_ASSERTED
                | RUNTIME_STIM_POWER_ENABLED
                | RUNTIME_WATCHDOG_HEALTHY
                | RUNTIME_COMPLIANCE_READY
                | RUNTIME_CLOCK_LOCKED
                | RUNTIME_LINK_HEALTHY
                | RUNTIME_EMERGENCY_STOP_HEALTHY,
            hardware_protocol_hash: PROTOCOL_HASH,
        };
        let token = WorkerTokenLeaseV1 {
            run_id: id(3),
            worker_id: id(4),
            token_id: id(5),
            role: 2,
            state: 1,
            arm_epoch: 7,
            issued_global_time_ns: 1,
            expires_global_time_ns: 1_000_000,
            safety_profile_id: profile.profile_id,
            safety_profile_hash: profile_hash,
            algorithm_hash: hash(20),
            config_hash: hash(21),
            template_hash,
            channel_map_hash: hash(23),
            worker_build_hash: hash(24),
        };
        let intent = StimIntentV1 {
            run_id: token.run_id,
            source_worker_id: token.worker_id,
            control_token_id: token.token_id,
            source_record_sequence: 100,
            source_sample_counter: 1_000,
            source_global_time_ns: NOW - 1,
            algorithm_hash: token.algorithm_hash,
            config_hash: token.config_hash,
            template_hash: token.template_hash,
            channel_map_hash: token.channel_map_hash,
            target_channel: 3,
            template_id: 1,
            intent_flags: 0,
            deadline_global_time_ns: NOW + 1_000,
            intent_nonce: id(30),
        };
        (capabilities, profile, token, intent)
    }

    pub(crate) fn armed_with_route() -> (SafetyArbiter, StimIntentV1, Arc<AnalysisBranchFaultRoute>)
    {
        let (arbiter, intent, route) = armed_with_route_capacity(
            crate::analysis_fault_evidence::ANALYSIS_FAULT_EVIDENCE_QUEUE_CAPACITY,
        );
        (arbiter, intent, route)
    }

    pub(crate) fn armed_with_route_capacity(
        capacity: usize,
    ) -> (SafetyArbiter, StimIntentV1, Arc<AnalysisBranchFaultRoute>) {
        let (capabilities, profile, token, intent) = fixture();
        let identity = AnalysisBranchIdentityV1::new(token.run_id, token.worker_id, 1).unwrap();
        let mut arbiter = SafetyArbiter::default();
        arbiter
            .arm(capabilities, profile, token, vec![template()], NOW)
            .unwrap();
        let route = arbiter
            .analysis_controller_fault_route_with_evidence_queue(
                identity,
                Arc::new(AnalysisFaultEvidenceQueue::with_capacity(capacity).unwrap()),
            )
            .unwrap();
        (arbiter, intent, route)
    }

    fn armed() -> (SafetyArbiter, StimIntentV1, Arc<AnalysisBranchFaultRoute>) {
        armed_with_route()
    }

    fn executed_receipt(command: &StimCommandV1) -> StimReceiptV1 {
        StimReceiptV1 {
            run_id: command.run_id,
            command_id: command.command_id,
            intent_nonce: command.intent_nonce,
            device_id: command.device_id,
            result: 1,
            fault_code: 0,
            target_channel: command.target_channel,
            template_id: command.template_id,
            actual_start_global_time_ns: command.execute_not_before_global_time_ns + 10,
            actual_end_global_time_ns: command.execute_not_before_global_time_ns + 410,
            measured_compliance_uv: 100_000,
            peak_current_na: command.current_na,
            receipt_flags: 0,
            delivered_phase_charge_pc: 10_000,
            arm_epoch: command.arm_epoch,
            receipt_nonce: id(40),
            hardware_state_hash: hash(41),
        }
    }

    #[test]
    fn template_hash_is_order_stable_and_rejects_duplicates() {
        let mut second = template();
        second.template_id = 2;
        assert_eq!(
            template_catalog_hash(&[template(), second]).unwrap(),
            template_catalog_hash(&[second, template()]).unwrap()
        );
        assert_eq!(
            template_catalog_hash(&[template(), template()]),
            Err(ArbiterError::TemplateCatalog)
        );
    }

    #[test]
    fn command_is_generated_once_then_requires_matching_receipt() {
        let (mut arbiter, intent, _route) = armed();
        let command = arbiter.submit_intent(&intent, NOW).unwrap();
        assert_eq!(arbiter.state(), ArbiterState::AwaitingReceipt);
        assert_eq!(command.target_channel, 3);
        assert_eq!(command.current_na, template().current_na);
        assert_eq!(
            arbiter.submit_intent(&intent, NOW),
            Err(ArbiterError::PendingReceipt)
        );
        arbiter.accept_receipt(&executed_receipt(&command)).unwrap();
        assert_eq!(arbiter.state(), ArbiterState::Armed);
        assert_eq!(
            arbiter.submit_intent(&intent, NOW),
            Err(ArbiterError::DuplicateIntent)
        );
        assert_eq!(arbiter.state(), ArbiterState::FaultLatched);
    }

    #[test]
    fn replayed_receipt_fault_latches_after_success() {
        let (mut arbiter, intent, _route) = armed();
        let command = arbiter.submit_intent(&intent, NOW).unwrap();
        let receipt = executed_receipt(&command);
        arbiter.accept_receipt(&receipt).unwrap();
        assert_eq!(
            arbiter.accept_receipt(&receipt),
            Err(ArbiterError::ReceiptMismatch)
        );
        assert_eq!(arbiter.state(), ArbiterState::FaultLatched);
    }

    #[test]
    fn unsafe_runtime_state_refuses_arm() {
        let (mut capabilities, profile, token, _) = fixture();
        capabilities.runtime_safety_flags &= !RUNTIME_EMERGENCY_STOP_HEALTHY;
        let mut arbiter = SafetyArbiter::default();
        assert_eq!(
            arbiter.arm(capabilities, profile, token, vec![template()], NOW),
            Err(ArbiterError::Capability)
        );
        assert_eq!(arbiter.state(), ArbiterState::Disarmed);
    }

    #[test]
    fn runtime_health_loss_fault_latches_after_arm() {
        let (mut capabilities, profile, token, _) = fixture();
        let mut arbiter = SafetyArbiter::default();
        arbiter
            .arm(capabilities.clone(), profile, token, vec![template()], NOW)
            .unwrap();
        capabilities.runtime_safety_flags &= !RUNTIME_EMERGENCY_STOP_HEALTHY;
        arbiter.observe_runtime(&capabilities);
        assert_eq!(arbiter.state(), ArbiterState::FaultLatched);
        assert_eq!(
            arbiter.last_disarm_reason(),
            Some(DisarmReason::EmergencyStop)
        );
    }

    #[test]
    fn expired_intent_never_produces_a_command() {
        let (mut arbiter, mut intent, _route) = armed();
        intent.deadline_global_time_ns = NOW;
        assert!(arbiter.submit_intent(&intent, NOW).is_err());
        assert!(arbiter.pending_command().is_none());
    }

    #[test]
    fn deadline_without_receipt_fault_latches() {
        let (mut arbiter, intent, _route) = armed();
        let command = arbiter.submit_intent(&intent, NOW).unwrap();
        arbiter.tick(command.deadline_global_time_ns);
        assert_eq!(arbiter.state(), ArbiterState::FaultLatched);
        assert_eq!(
            arbiter.last_disarm_reason(),
            Some(DisarmReason::DeadlineMiss)
        );
    }

    #[test]
    fn mismatched_receipt_fault_latches() {
        let (mut arbiter, intent, _route) = armed();
        let command = arbiter.submit_intent(&intent, NOW).unwrap();
        let mut receipt = executed_receipt(&command);
        receipt.command_id = id(99);
        assert_eq!(
            arbiter.accept_receipt(&receipt),
            Err(ArbiterError::ReceiptMismatch)
        );
        assert_eq!(arbiter.state(), ArbiterState::FaultLatched);
    }

    #[test]
    fn data_fault_disarms_and_requires_fresh_arm() {
        let (mut arbiter, _, _route) = armed();
        arbiter.disarm(DisarmReason::DataGap);
        assert_eq!(arbiter.state(), ArbiterState::Disarmed);
        assert_eq!(arbiter.last_disarm_reason(), Some(DisarmReason::DataGap));
    }

    #[test]
    fn controller_fault_revokes_token_before_return_and_is_idempotent() {
        let (mut arbiter, intent, route) = armed_with_route();
        let first = route.dispatch(AnalysisFaultV1::RingFull, 11, Some(4), Some(4));
        assert!(first.first_fault);
        assert!(first.controller_disarmed);
        assert!(first.event_enqueued);
        assert_eq!(route.try_drain_fault_evidence(4).unwrap().len(), 1);
        assert_eq!(arbiter.state(), ArbiterState::FaultLatched);
        assert_eq!(arbiter.last_disarm_reason(), Some(DisarmReason::Overflow));
        assert!(arbiter.pending_command().is_none());
        assert_eq!(
            arbiter.submit_intent(&intent, NOW),
            Err(ArbiterError::FaultLatched)
        );

        let duplicate = route.dispatch(AnalysisFaultV1::RingFull, 12, Some(4), Some(4));
        assert!(!duplicate.first_fault);
        assert!(!duplicate.controller_disarmed);
        assert!(!duplicate.event_enqueued);
        assert_eq!(arbiter.state(), ArbiterState::FaultLatched);
    }

    #[test]
    fn unregistered_controller_route_final_drop_revokes_the_active_lease() {
        let (mut arbiter, intent, route) = armed_with_route();
        let evidence = route.fault_evidence_queue_for_test();
        drop(route);
        assert_eq!(arbiter.state(), ArbiterState::FaultLatched);
        assert_eq!(arbiter.last_disarm_reason(), Some(DisarmReason::WorkerLost));
        assert_eq!(
            arbiter.submit_intent(&intent, NOW),
            Err(ArbiterError::FaultLatched)
        );
        assert_eq!(evidence.snapshot().enqueued_count, 0);
    }

    #[test]
    fn observer_final_drop_does_not_revoke_a_legal_controller() {
        let (mut arbiter, intent, controller) = armed_with_route();
        let observer = AnalysisBranchFaultRoute::observer(
            AnalysisBranchIdentityV1::new(intent.run_id, id(90), 2).unwrap(),
        );
        drop(observer);
        assert_eq!(arbiter.state(), ArbiterState::Armed);
        assert!(arbiter.submit_intent(&intent, NOW).is_ok());
        drop(controller);
    }

    #[test]
    fn controller_final_drop_after_explicit_fault_preserves_the_first_reason() {
        let (arbiter, _intent, route) = armed_with_route();
        route.dispatch(AnalysisFaultV1::DataGap, 30, Some(8), Some(9));
        assert_eq!(arbiter.last_disarm_reason(), Some(DisarmReason::DataGap));
        drop(route);
        assert_eq!(arbiter.state(), ArbiterState::FaultLatched);
        assert_eq!(arbiter.last_disarm_reason(), Some(DisarmReason::DataGap));
    }

    #[test]
    fn observer_fault_degrades_only_its_branch() {
        let (mut arbiter, intent, _controller) = armed_with_route();
        let identity = AnalysisBranchIdentityV1::new(intent.run_id, id(90), 2).unwrap();
        let observer = AnalysisBranchFaultRoute::observer(identity);
        let dispatch = observer.dispatch(AnalysisFaultV1::RingFull, 20, None, None);
        assert!(dispatch.first_fault);
        assert!(!dispatch.controller_disarmed);
        assert!(observer.is_degraded());
        assert_eq!(arbiter.state(), ArbiterState::Armed);
        assert!(arbiter.submit_intent(&intent, NOW).is_ok());
    }

    #[test]
    fn observer_evidence_disconnect_does_not_revoke_a_legal_controller() {
        let (mut arbiter, intent, _controller) = armed_with_route();
        let identity = AnalysisBranchIdentityV1::new(intent.run_id, id(91), 2).unwrap();
        let observer = AnalysisBranchFaultRoute::observer(identity);
        observer.disconnect_fault_evidence_receiver_for_test();
        let dispatch = observer.dispatch(AnalysisFaultV1::CrcFault, 20, None, None);
        assert!(dispatch.first_fault);
        assert!(!dispatch.controller_disarmed);
        assert!(!dispatch.event_enqueued);
        assert!(observer.fault_evidence_snapshot().evidence_lost());
        assert_eq!(arbiter.state(), ArbiterState::Armed);
        assert!(arbiter.submit_intent(&intent, NOW).is_ok());
    }

    #[test]
    fn full_evidence_queue_cannot_prevent_controller_disarm() {
        let (mut arbiter, intent, route) = armed_with_route_capacity(1);
        route.prefill_fault_evidence_for_test();
        let dispatch = route.dispatch(AnalysisFaultV1::ConsumerLost, 21, None, None);
        assert!(dispatch.controller_disarmed);
        assert!(!dispatch.event_enqueued);
        let evidence = route.fault_evidence_snapshot();
        assert_eq!(evidence.lost_count, 1);
        assert!(evidence.overflowed);
        assert_eq!(arbiter.state(), ArbiterState::FaultLatched);
        assert_eq!(
            arbiter.submit_intent(&intent, NOW),
            Err(ArbiterError::FaultLatched)
        );
    }

    #[test]
    fn disconnected_evidence_queue_cannot_prevent_controller_disarm() {
        let (mut arbiter, intent, route) = armed_with_route_capacity(1);
        route.disconnect_fault_evidence_receiver_for_test();
        let dispatch = route.dispatch(AnalysisFaultV1::ConsumerLost, 21, None, None);
        assert!(dispatch.controller_disarmed);
        assert!(!dispatch.event_enqueued);
        let evidence = route.fault_evidence_snapshot();
        assert_eq!(evidence.lost_count, 1);
        assert!(evidence.receiver_unavailable);
        assert_eq!(arbiter.state(), ArbiterState::FaultLatched);
        assert_eq!(
            arbiter.submit_intent(&intent, NOW),
            Err(ArbiterError::FaultLatched)
        );
    }

    #[test]
    fn all_six_controller_fault_classes_latch_and_enqueue_once() {
        for (fault, expected_reason) in [
            (AnalysisFaultV1::RingFull, DisarmReason::Overflow),
            (AnalysisFaultV1::ConsumerLost, DisarmReason::WorkerLost),
            (AnalysisFaultV1::HeartbeatTimeout, DisarmReason::WorkerLost),
            (AnalysisFaultV1::DataGap, DisarmReason::DataGap),
            (AnalysisFaultV1::CrcFault, DisarmReason::SourceCrc),
            (AnalysisFaultV1::DeadlineMiss, DisarmReason::DeadlineMiss),
        ] {
            let (mut arbiter, intent, route) = armed_with_route();
            let dispatch = route.dispatch(fault, 25, Some(9), Some(10));
            assert!(dispatch.controller_disarmed, "{fault:?}");
            assert!(dispatch.event_enqueued, "{fault:?}");
            assert_eq!(arbiter.state(), ArbiterState::FaultLatched, "{fault:?}");
            assert_eq!(
                arbiter.last_disarm_reason(),
                Some(expected_reason),
                "{fault:?}"
            );
            assert_eq!(
                arbiter.submit_intent(&intent, NOW),
                Err(ArbiterError::FaultLatched),
                "{fault:?}"
            );
            let events = route.try_drain_fault_evidence(2).unwrap();
            assert_eq!(events.len(), 1, "{fault:?}");
            assert_eq!(events[0].fault, fault, "{fault:?}");
        }
    }

    #[test]
    fn controller_route_is_unique_and_cannot_cross_arbiter() {
        let (mut first, _intent, first_route) = armed_with_route();
        let identity = first_route.identity();
        assert!(matches!(
            first.analysis_controller_fault_route_with_evidence_queue(
                identity,
                Arc::new(AnalysisFaultEvidenceQueue::default())
            ),
            Err(ArbiterError::AnalysisController)
        ));

        let (second, _, _second_route) = armed_with_route();
        first_route.dispatch(AnalysisFaultV1::HeartbeatTimeout, 22, None, None);
        assert_eq!(first.state(), ArbiterState::FaultLatched);
        assert_eq!(second.state(), ArbiterState::Armed);
    }

    #[test]
    fn explicit_rearm_requires_new_epoch_and_rejects_old_intent_and_route() {
        let (mut arbiter, old_intent, old_route) = armed_with_route();
        old_route.dispatch(AnalysisFaultV1::DataGap, 30, Some(8), Some(9));
        arbiter.acknowledge_fault();
        assert_eq!(arbiter.state(), ArbiterState::Disarmed);

        let (capabilities, profile, mut token, mut new_intent) = fixture();
        assert_eq!(
            arbiter.arm(
                capabilities.clone(),
                profile.clone(),
                token.clone(),
                vec![template()],
                NOW
            ),
            Err(ArbiterError::StaleArmEpoch)
        );
        token.arm_epoch += 1;
        token.token_id = id(6);
        new_intent.control_token_id = token.token_id;
        new_intent.intent_nonce = id(31);
        arbiter
            .arm(capabilities, profile, token.clone(), vec![template()], NOW)
            .unwrap();
        let new_route = arbiter
            .analysis_controller_fault_route_with_evidence_queue(
                AnalysisBranchIdentityV1::new(token.run_id, token.worker_id, 2).unwrap(),
                Arc::new(AnalysisFaultEvidenceQueue::default()),
            )
            .unwrap();
        assert_eq!(
            arbiter.submit_intent(&old_intent, NOW),
            Err(ArbiterError::ProtocolSafety)
        );
        old_route.dispatch(AnalysisFaultV1::ConsumerLost, 31, None, None);
        assert_eq!(arbiter.state(), ArbiterState::Armed);
        assert!(arbiter.submit_intent(&new_intent, NOW).is_ok());
        assert_eq!(new_route.role(), AnalysisConsumerRoleV1::Controller);
    }

    #[test]
    fn controller_fault_consumes_pending_nonce_across_rearm() {
        let (mut arbiter, old_intent, old_route) = armed_with_route();
        assert!(arbiter.submit_intent(&old_intent, NOW).is_ok());
        old_route.dispatch(AnalysisFaultV1::DeadlineMiss, 40, None, None);
        assert!(arbiter.pending_command().is_none());
        arbiter.acknowledge_fault();

        let (capabilities, profile, mut token, mut replayed) = fixture();
        token.arm_epoch += 1;
        token.token_id = id(7);
        replayed.control_token_id = token.token_id;
        arbiter
            .arm(capabilities, profile, token.clone(), vec![template()], NOW)
            .unwrap();
        let _new_route = arbiter
            .analysis_controller_fault_route_with_evidence_queue(
                AnalysisBranchIdentityV1::new(token.run_id, token.worker_id, 2).unwrap(),
                Arc::new(AnalysisFaultEvidenceQueue::default()),
            )
            .unwrap();
        assert_eq!(
            arbiter.submit_intent(&replayed, NOW),
            Err(ArbiterError::DuplicateIntent)
        );
        assert_eq!(arbiter.state(), ArbiterState::FaultLatched);
    }
}
