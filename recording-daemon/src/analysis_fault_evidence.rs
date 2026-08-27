//! Bounded, process-local analysis-fault evidence handoff.
//!
//! A successful enqueue is not durable or persisted evidence.  The acquisition
//! writer only calls `SyncSender::try_send`; receiver locking and allocation are
//! confined to the explicit drain side.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Mutex, TryLockError};

use crate::analysis_ring::AnalysisFaultEventV1;

pub const ANALYSIS_FAULT_EVIDENCE_QUEUE_CAPACITY: usize = 16;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AnalysisFaultEvidenceSnapshotV1 {
    /// Total events successfully handed to the in-memory queue, saturating.
    pub enqueued_count: u64,
    /// Total events known not to have been handed off, saturating.
    pub lost_count: u64,
    pub overflowed: bool,
    pub receiver_unavailable: bool,
    pub receiver_poisoned: bool,
}

impl AnalysisFaultEvidenceSnapshotV1 {
    pub fn evidence_lost(self) -> bool {
        self.lost_count != 0 || self.receiver_unavailable || self.receiver_poisoned
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisFaultEvidenceDrainError {
    InvalidLimit,
    Busy,
    ReceiverUnavailable,
    ReceiverPoisoned,
}

/// Fixed-capacity queue shared by one analysis fault route and its evidence
/// consumer.  It intentionally owns no background thread and performs no I/O.
pub struct AnalysisFaultEvidenceQueue {
    sender: SyncSender<AnalysisFaultEventV1>,
    receiver: Mutex<Option<Receiver<AnalysisFaultEventV1>>>,
    capacity: usize,
    enqueued_count: AtomicU64,
    lost_count: AtomicU64,
    overflowed: AtomicBool,
    receiver_unavailable: AtomicBool,
    receiver_poisoned: AtomicBool,
}

impl Default for AnalysisFaultEvidenceQueue {
    fn default() -> Self {
        Self::with_capacity(ANALYSIS_FAULT_EVIDENCE_QUEUE_CAPACITY)
            .expect("nonzero fixed analysis fault evidence capacity")
    }
}

impl AnalysisFaultEvidenceQueue {
    pub(crate) fn with_capacity(capacity: usize) -> Option<Self> {
        if capacity == 0 {
            return None;
        }
        let (sender, receiver) = mpsc::sync_channel(capacity);
        Some(Self {
            sender,
            receiver: Mutex::new(Some(receiver)),
            capacity,
            enqueued_count: AtomicU64::new(0),
            lost_count: AtomicU64::new(0),
            overflowed: AtomicBool::new(false),
            receiver_unavailable: AtomicBool::new(false),
            receiver_poisoned: AtomicBool::new(false),
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Writer-side operation. This performs only bounded `try_send` plus atomic
    /// bookkeeping and never touches the receiver mutex.
    pub(crate) fn try_enqueue(&self, event: AnalysisFaultEventV1) -> bool {
        match self.sender.try_send(event) {
            Ok(()) => {
                saturating_increment(&self.enqueued_count);
                true
            }
            Err(TrySendError::Full(_)) => {
                self.overflowed.store(true, Ordering::Release);
                saturating_increment(&self.lost_count);
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                self.receiver_unavailable.store(true, Ordering::Release);
                saturating_increment(&self.lost_count);
                false
            }
        }
    }

    /// Receiver-side operation. It never waits for the mutex or for an event.
    /// The returned events are only in-memory handoff evidence.
    pub fn try_drain(
        &self,
        max_events: usize,
    ) -> Result<Vec<AnalysisFaultEventV1>, AnalysisFaultEvidenceDrainError> {
        if max_events == 0 {
            return Err(AnalysisFaultEvidenceDrainError::InvalidLimit);
        }
        let mut guard = match self.receiver.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(AnalysisFaultEvidenceDrainError::Busy),
            Err(TryLockError::Poisoned(_)) => {
                self.mark_receiver_poisoned();
                return Err(AnalysisFaultEvidenceDrainError::ReceiverPoisoned);
            }
        };
        let receiver = guard.as_mut().ok_or_else(|| {
            self.mark_receiver_unavailable();
            AnalysisFaultEvidenceDrainError::ReceiverUnavailable
        })?;
        let limit = max_events.min(self.capacity);
        let mut events = Vec::with_capacity(limit);
        while events.len() < limit {
            match receiver.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.mark_receiver_unavailable();
                    break;
                }
            }
        }
        Ok(events)
    }

    pub fn snapshot(&self) -> AnalysisFaultEvidenceSnapshotV1 {
        AnalysisFaultEvidenceSnapshotV1 {
            enqueued_count: self.enqueued_count.load(Ordering::Acquire),
            lost_count: self.lost_count.load(Ordering::Acquire),
            overflowed: self.overflowed.load(Ordering::Acquire),
            receiver_unavailable: self.receiver_unavailable.load(Ordering::Acquire),
            receiver_poisoned: self.receiver_poisoned.load(Ordering::Acquire),
        }
    }

    fn mark_receiver_unavailable(&self) {
        if !self.receiver_unavailable.swap(true, Ordering::AcqRel) {
            saturating_increment(&self.lost_count);
        }
    }

    fn mark_receiver_poisoned(&self) {
        if !self.receiver_poisoned.swap(true, Ordering::AcqRel) {
            saturating_increment(&self.lost_count);
        }
        self.receiver_unavailable.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn disconnect_receiver_for_test(&self) {
        match self.receiver.lock() {
            Ok(mut guard) => {
                guard.take();
            }
            Err(_) => self.mark_receiver_poisoned(),
        }
    }
}

fn saturating_increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        Some(value.saturating_add(1))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis_ring::{AnalysisBranchIdentityV1, AnalysisConsumerRoleV1, AnalysisFaultV1};
    use std::sync::Arc;

    fn event(sequence: u64) -> AnalysisFaultEventV1 {
        AnalysisFaultEventV1 {
            branch: AnalysisBranchIdentityV1::new([1; 16], [2; 16], 3).unwrap(),
            role: AnalysisConsumerRoleV1::Controller,
            fault: AnalysisFaultV1::RingFull,
            observed_monotonic_ns: sequence.saturating_add(1),
            expected_journal_sequence: Some(sequence),
            observed_journal_sequence: Some(sequence),
        }
    }

    #[test]
    fn normal_enqueue_and_try_drain_are_bounded_and_nonblocking() {
        let queue = AnalysisFaultEvidenceQueue::with_capacity(2).unwrap();
        assert!(queue.try_enqueue(event(4)));
        assert_eq!(queue.try_drain(8).unwrap(), vec![event(4)]);
        assert_eq!(
            queue.snapshot(),
            AnalysisFaultEvidenceSnapshotV1 {
                enqueued_count: 1,
                ..AnalysisFaultEvidenceSnapshotV1::default()
            }
        );
    }

    #[test]
    fn full_and_disconnected_receiver_mark_lost_without_blocking() {
        let queue = AnalysisFaultEvidenceQueue::with_capacity(1).unwrap();
        assert!(queue.try_enqueue(event(1)));
        assert!(!queue.try_enqueue(event(2)));
        let full = queue.snapshot();
        assert_eq!(full.enqueued_count, 1);
        assert_eq!(full.lost_count, 1);
        assert!(full.overflowed);

        let disconnected = AnalysisFaultEvidenceQueue::with_capacity(1).unwrap();
        disconnected.disconnect_receiver_for_test();
        assert!(!disconnected.try_enqueue(event(3)));
        let snapshot = disconnected.snapshot();
        assert_eq!(snapshot.lost_count, 1);
        assert!(snapshot.receiver_unavailable);
    }

    #[test]
    fn poisoned_receiver_is_visible_and_never_panics_the_drain_caller() {
        let queue = Arc::new(AnalysisFaultEvidenceQueue::with_capacity(1).unwrap());
        let poisoner = Arc::clone(&queue);
        assert!(std::thread::spawn(move || {
            let _guard = poisoner.receiver.lock().unwrap();
            panic!("poison analysis fault receiver for test");
        })
        .join()
        .is_err());
        assert_eq!(
            queue.try_drain(1),
            Err(AnalysisFaultEvidenceDrainError::ReceiverPoisoned)
        );
        let snapshot = queue.snapshot();
        assert_eq!(snapshot.lost_count, 1);
        assert!(snapshot.receiver_poisoned);
        assert!(snapshot.receiver_unavailable);
    }

    #[test]
    fn counters_saturate_instead_of_wrapping_or_panicking() {
        let queue = AnalysisFaultEvidenceQueue::with_capacity(1).unwrap();
        queue.enqueued_count.store(u64::MAX, Ordering::Release);
        assert!(queue.try_enqueue(event(1)));
        assert_eq!(queue.snapshot().enqueued_count, u64::MAX);
        queue.lost_count.store(u64::MAX, Ordering::Release);
        assert!(!queue.try_enqueue(event(2)));
        assert_eq!(queue.snapshot().lost_count, u64::MAX);
    }
}
