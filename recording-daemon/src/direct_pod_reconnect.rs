//! Durable evidence and bounded owner state for direct-Pod fresh-epoch reconnect.
//!
//! Reconnect is a new transport admission, never continuation of an old Run.
//! The old owner must already be cancelled and any unfinished Run durably
//! failed before a reconnect attempt is recorded or opened.

#![cfg(windows)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use forge_protocol_v1::{crc32c, sha256, Hash32, Id16, PROTOCOL_HASH};

pub const DIRECT_POD_RECONNECT_EVENT_LEN: usize = 272;
pub const DIRECT_POD_RECONNECT_CONTRACT_HASH_HEX: &str =
    "c9ac28947e22333f3f4e4ed937bfd6e77376e43855cb7e7f306ccddc0b2e3767";
pub const DIRECT_POD_RECONNECT_CONTRACT_HASH: Hash32 = [
    0xc9, 0xac, 0x28, 0x94, 0x7e, 0x22, 0x33, 0x3f, 0x3f, 0x4e, 0x4e, 0xd9, 0x37, 0xbf, 0xd6, 0xe7,
    0x73, 0x76, 0xe4, 0x38, 0x55, 0xcb, 0x7e, 0x7f, 0x30, 0x6c, 0xcd, 0xdc, 0x0b, 0x2e, 0x37, 0x67,
];

const MAGIC: &[u8; 8] = b"FGRRCN01";
const VERSION: u16 = 1;
const MAX_RECONNECT_EVENTS: u64 = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum DirectPodReconnectEventKind {
    TransportFault = 1,
    AttemptStarted = 2,
    AttemptFailed = 3,
    FreshEpochAdmitted = 4,
    AttemptsExhausted = 5,
    ServiceCancelled = 6,
}

impl TryFrom<u16> for DirectPodReconnectEventKind {
    type Error = io::Error;

    fn try_from(value: u16) -> io::Result<Self> {
        match value {
            1 => Ok(Self::TransportFault),
            2 => Ok(Self::AttemptStarted),
            3 => Ok(Self::AttemptFailed),
            4 => Ok(Self::FreshEpochAdmitted),
            5 => Ok(Self::AttemptsExhausted),
            6 => Ok(Self::ServiceCancelled),
            _ => Err(invalid_data("unknown direct-Pod reconnect event kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodReconnectEventV1 {
    pub event_kind: DirectPodReconnectEventKind,
    pub device_id: Id16,
    pub reconnect_sequence: u64,
    pub previous_transport_epoch: u64,
    pub candidate_transport_epoch: u64,
    pub host_monotonic_ns: u64,
    pub attempt_number: u32,
    pub max_attempts: u32,
    pub fault_kind: u16,
    pub result_code: u16,
    pub prior_event_hash: Hash32,
    pub deployment_evidence_hash: Hash32,
    pub detail_hash: Hash32,
    pub service_instance_id: Id16,
}

impl DirectPodReconnectEventV1 {
    pub fn encode(self) -> io::Result<[u8; DIRECT_POD_RECONNECT_EVENT_LEN]> {
        validate_event(&self)?;
        let mut bytes = [0_u8; DIRECT_POD_RECONNECT_EVENT_LEN];
        bytes[0..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(DIRECT_POD_RECONNECT_EVENT_LEN as u16).to_le_bytes());
        bytes[12..14].copy_from_slice(&(self.event_kind as u16).to_le_bytes());
        bytes[16..48].copy_from_slice(&DIRECT_POD_RECONNECT_CONTRACT_HASH);
        bytes[48..64].copy_from_slice(&self.device_id);
        bytes[64..72].copy_from_slice(&self.reconnect_sequence.to_le_bytes());
        bytes[72..80].copy_from_slice(&self.previous_transport_epoch.to_le_bytes());
        bytes[80..88].copy_from_slice(&self.candidate_transport_epoch.to_le_bytes());
        bytes[88..96].copy_from_slice(&self.host_monotonic_ns.to_le_bytes());
        bytes[96..100].copy_from_slice(&self.attempt_number.to_le_bytes());
        bytes[100..104].copy_from_slice(&self.max_attempts.to_le_bytes());
        bytes[104..106].copy_from_slice(&self.fault_kind.to_le_bytes());
        bytes[106..108].copy_from_slice(&self.result_code.to_le_bytes());
        bytes[112..144].copy_from_slice(&self.prior_event_hash);
        bytes[144..176].copy_from_slice(&self.deployment_evidence_hash);
        bytes[176..208].copy_from_slice(&self.detail_hash);
        bytes[208..240].copy_from_slice(&PROTOCOL_HASH);
        bytes[240..256].copy_from_slice(&self.service_instance_id);
        let checksum = crc32c(&bytes[..268]);
        bytes[268..272].copy_from_slice(&checksum.to_le_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != DIRECT_POD_RECONNECT_EVENT_LEN
            || bytes.get(0..8) != Some(MAGIC)
            || le_u16(bytes, 8)? != VERSION
            || le_u16(bytes, 10)? as usize != DIRECT_POD_RECONNECT_EVENT_LEN
            || le_u16(bytes, 14)? != 0
            || array::<32>(bytes, 16)? != DIRECT_POD_RECONNECT_CONTRACT_HASH
            || le_u32(bytes, 108)? != 0
            || array::<32>(bytes, 208)? != PROTOCOL_HASH
            || array::<16>(bytes, 240)? == [0; 16]
            || bytes[256..268].iter().any(|byte| *byte != 0)
            || crc32c(&bytes[..268]) != le_u32(bytes, 268)?
        {
            return Err(invalid_data(
                "direct-Pod reconnect event framing is invalid",
            ));
        }
        let value = Self {
            event_kind: DirectPodReconnectEventKind::try_from(le_u16(bytes, 12)?)?,
            device_id: array(bytes, 48)?,
            reconnect_sequence: le_u64(bytes, 64)?,
            previous_transport_epoch: le_u64(bytes, 72)?,
            candidate_transport_epoch: le_u64(bytes, 80)?,
            host_monotonic_ns: le_u64(bytes, 88)?,
            attempt_number: le_u32(bytes, 96)?,
            max_attempts: le_u32(bytes, 100)?,
            fault_kind: le_u16(bytes, 104)?,
            result_code: le_u16(bytes, 106)?,
            prior_event_hash: array(bytes, 112)?,
            deployment_evidence_hash: array(bytes, 144)?,
            detail_hash: array(bytes, 176)?,
            service_instance_id: array(bytes, 240)?,
        };
        validate_event(&value)
            .map_err(|_| invalid_data("direct-Pod reconnect event semantics are invalid"))?;
        Ok(value)
    }

    pub fn evidence_hash(self) -> io::Result<Hash32> {
        Ok(sha256(&self.encode()?))
    }
}

fn validate_event(value: &DirectPodReconnectEventV1) -> io::Result<()> {
    if value.device_id == [0; 16]
        || value.reconnect_sequence == 0
        || value.host_monotonic_ns == 0
        || value.max_attempts == 0
        || value.max_attempts > 64
        || value.deployment_evidence_hash == [0; 32]
        || value.detail_hash == [0; 32]
        || value.service_instance_id == [0; 16]
        || (value.reconnect_sequence == 1) != (value.prior_event_hash == [0; 32])
    {
        return Err(invalid_input(
            "direct-Pod reconnect common event fields are invalid",
        ));
    }
    let valid = match value.event_kind {
        DirectPodReconnectEventKind::TransportFault => {
            value.attempt_number == 0
                && value.candidate_transport_epoch == 0
                && value.fault_kind != 0
                && value.result_code == 0
        }
        DirectPodReconnectEventKind::AttemptStarted => {
            (1..=value.max_attempts).contains(&value.attempt_number)
                && value.candidate_transport_epoch == 0
                && value.fault_kind == 0
                && value.result_code == 0
        }
        DirectPodReconnectEventKind::AttemptFailed => {
            (1..=value.max_attempts).contains(&value.attempt_number)
                && value.candidate_transport_epoch == 0
                && value.fault_kind != 0
                && value.result_code != 0
        }
        DirectPodReconnectEventKind::FreshEpochAdmitted => {
            (1..=value.max_attempts).contains(&value.attempt_number)
                && value.candidate_transport_epoch > value.previous_transport_epoch
                && value.fault_kind == 0
                && value.result_code == 0
        }
        DirectPodReconnectEventKind::AttemptsExhausted => {
            value.attempt_number == value.max_attempts
                && value.candidate_transport_epoch == 0
                && value.fault_kind != 0
                && value.result_code != 0
        }
        DirectPodReconnectEventKind::ServiceCancelled => {
            value.attempt_number <= value.max_attempts
                && value.candidate_transport_epoch == 0
                && value.fault_kind == 0
                && value.result_code == 0
        }
    };
    if !valid {
        return Err(invalid_input(
            "direct-Pod reconnect event-kind fields are invalid",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub struct DirectPodReconnectLedger {
    path: PathBuf,
    device_id: Id16,
    deployment_evidence_hash: Hash32,
    next_sequence: u64,
    prior_event_hash: Hash32,
    last_event: Option<DirectPodReconnectEventV1>,
    last_service_instance_id: Option<Id16>,
    last_host_monotonic_ns: u64,
    highest_admitted_epoch: u64,
    cycle_previous_epoch: u64,
    completed_attempts: u32,
    pending_attempt: Option<u32>,
    attempts_exhausted: bool,
    recorded_max_attempts: Option<u32>,
    poisoned: bool,
}

impl DirectPodReconnectLedger {
    pub fn open(
        path: impl AsRef<Path>,
        device_id: Id16,
        deployment_evidence_hash: Hash32,
    ) -> io::Result<Self> {
        if device_id == [0; 16] || deployment_evidence_hash == [0; 32] {
            return Err(invalid_input("reconnect ledger identity/evidence is zero"));
        }
        let path = path.as_ref().to_path_buf();
        fs::create_dir(&path).or_else(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists && path.is_dir() {
                Ok(())
            } else {
                Err(error)
            }
        })?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid_data("reconnect ledger filename is not UTF-8"))?;
            let sequence = parse_event_filename(&name)?;
            if !entry.file_type()?.is_file() {
                return Err(invalid_data("reconnect ledger contains a non-file entry"));
            }
            entries.push((sequence, entry.path()));
        }
        entries.sort_by_key(|entry| entry.0);
        if entries.len() as u64 > MAX_RECONNECT_EVENTS {
            return Err(invalid_data("reconnect ledger exceeds its event bound"));
        }
        let mut prior_event_hash = [0; 32];
        let mut last_event = None;
        let mut last_service_instance_id = None;
        let mut last_host_monotonic_ns = 0;
        let mut highest_admitted_epoch = 0;
        let mut cycle_previous_epoch = 0;
        let mut completed_attempts = 0;
        let mut pending_attempt = None;
        let mut attempts_exhausted = false;
        let mut recorded_max_attempts = None;
        for (expected, (sequence, event_path)) in entries.iter().enumerate() {
            let expected = u64::try_from(expected)
                .map_err(|_| invalid_data("reconnect ledger sequence exceeds u64"))?
                + 1;
            if *sequence != expected {
                return Err(invalid_data(
                    "reconnect ledger event sequence is not contiguous",
                ));
            }
            let mut bytes = Vec::new();
            File::open(event_path)?.read_to_end(&mut bytes)?;
            let event = DirectPodReconnectEventV1::decode(&bytes)?;
            if event.reconnect_sequence != expected
                || event.device_id != device_id
                || event.deployment_evidence_hash != deployment_evidence_hash
                || event.prior_event_hash != prior_event_hash
                || (last_service_instance_id == Some(event.service_instance_id)
                    && event.host_monotonic_ns < last_host_monotonic_ns)
            {
                return Err(invalid_data(
                    "reconnect ledger chain or identity is invalid",
                ));
            }
            if recorded_max_attempts.is_some_and(|value| value != event.max_attempts) {
                return Err(invalid_data(
                    "reconnect ledger changed its bounded attempt policy",
                ));
            }
            recorded_max_attempts = Some(event.max_attempts);
            apply_recovered_event(
                &event,
                &mut highest_admitted_epoch,
                &mut cycle_previous_epoch,
                &mut completed_attempts,
                &mut pending_attempt,
                &mut attempts_exhausted,
            )?;
            prior_event_hash = sha256(&bytes);
            last_service_instance_id = Some(event.service_instance_id);
            last_host_monotonic_ns = event.host_monotonic_ns;
            last_event = Some(event);
        }
        let next_sequence = u64::try_from(entries.len())
            .map_err(|_| invalid_data("reconnect ledger length exceeds u64"))?
            + 1;
        Ok(Self {
            path,
            device_id,
            deployment_evidence_hash,
            next_sequence,
            prior_event_hash,
            last_event,
            last_service_instance_id,
            last_host_monotonic_ns,
            highest_admitted_epoch,
            cycle_previous_epoch,
            completed_attempts,
            pending_attempt,
            attempts_exhausted,
            recorded_max_attempts,
            poisoned: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        event_kind: DirectPodReconnectEventKind,
        previous_transport_epoch: u64,
        candidate_transport_epoch: u64,
        host_monotonic_ns: u64,
        attempt_number: u32,
        max_attempts: u32,
        fault_kind: u16,
        result_code: u16,
        detail_hash: Hash32,
        service_instance_id: Id16,
    ) -> io::Result<DirectPodReconnectEventV1> {
        if self.poisoned || self.next_sequence > MAX_RECONNECT_EVENTS {
            return Err(io::Error::other("reconnect ledger is poisoned or full"));
        }
        if self.last_service_instance_id == Some(service_instance_id)
            && host_monotonic_ns < self.last_host_monotonic_ns
        {
            return Err(invalid_input(
                "reconnect host monotonic time regressed within one service instance",
            ));
        }
        if self
            .recorded_max_attempts
            .is_some_and(|value| value != max_attempts)
        {
            return Err(invalid_input(
                "reconnect attempt policy differs from durable evidence",
            ));
        }
        let event = DirectPodReconnectEventV1 {
            event_kind,
            device_id: self.device_id,
            reconnect_sequence: self.next_sequence,
            previous_transport_epoch,
            candidate_transport_epoch,
            host_monotonic_ns,
            attempt_number,
            max_attempts,
            fault_kind,
            result_code,
            prior_event_hash: self.prior_event_hash,
            deployment_evidence_hash: self.deployment_evidence_hash,
            detail_hash,
            service_instance_id,
        };
        let bytes = event.encode()?;
        let mut highest_admitted_epoch = self.highest_admitted_epoch;
        let mut cycle_previous_epoch = self.cycle_previous_epoch;
        let mut completed_attempts = self.completed_attempts;
        let mut pending_attempt = self.pending_attempt;
        let mut attempts_exhausted = self.attempts_exhausted;
        apply_recovered_event(
            &event,
            &mut highest_admitted_epoch,
            &mut cycle_previous_epoch,
            &mut completed_attempts,
            &mut pending_attempt,
            &mut attempts_exhausted,
        )?;
        let path = self.path.join(event_filename(self.next_sequence));
        let result = (|| {
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            file.write_all(&bytes)?;
            file.sync_all()
        })();
        if let Err(error) = result {
            self.poisoned = true;
            return Err(error);
        }
        self.prior_event_hash = sha256(&bytes);
        self.last_event = Some(event);
        self.last_service_instance_id = Some(service_instance_id);
        self.last_host_monotonic_ns = host_monotonic_ns;
        self.highest_admitted_epoch = highest_admitted_epoch;
        self.cycle_previous_epoch = cycle_previous_epoch;
        self.completed_attempts = completed_attempts;
        self.pending_attempt = pending_attempt;
        self.attempts_exhausted = attempts_exhausted;
        self.recorded_max_attempts = Some(max_attempts);
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| invalid_data("reconnect sequence overflow"))?;
        Ok(event)
    }

    pub fn event_count(&self) -> u64 {
        self.next_sequence - 1
    }

    pub fn last_event(&self) -> Option<DirectPodReconnectEventV1> {
        self.last_event
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn highest_admitted_epoch(&self) -> u64 {
        self.highest_admitted_epoch
    }

    pub fn cycle_previous_epoch(&self) -> u64 {
        self.cycle_previous_epoch
    }

    pub fn completed_attempts(&self) -> u32 {
        self.completed_attempts
    }

    pub fn pending_attempt(&self) -> Option<u32> {
        self.pending_attempt
    }

    pub fn attempts_exhausted(&self) -> bool {
        self.attempts_exhausted
    }

    pub fn recorded_max_attempts(&self) -> Option<u32> {
        self.recorded_max_attempts
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_recovered_event(
    event: &DirectPodReconnectEventV1,
    highest_admitted_epoch: &mut u64,
    cycle_previous_epoch: &mut u64,
    completed_attempts: &mut u32,
    pending_attempt: &mut Option<u32>,
    attempts_exhausted: &mut bool,
) -> io::Result<()> {
    let valid = match event.event_kind {
        DirectPodReconnectEventKind::TransportFault => {
            let valid = event.previous_transport_epoch >= *highest_admitted_epoch
                && pending_attempt.is_none();
            if valid {
                *cycle_previous_epoch = event.previous_transport_epoch;
                *completed_attempts = 0;
                *attempts_exhausted = false;
            }
            valid
        }
        DirectPodReconnectEventKind::AttemptStarted => {
            let base = (*cycle_previous_epoch).max(*highest_admitted_epoch);
            let valid = !*attempts_exhausted
                && pending_attempt.is_none()
                && event.previous_transport_epoch >= base
                && event.attempt_number == completed_attempts.saturating_add(1);
            if valid {
                *cycle_previous_epoch = event.previous_transport_epoch;
                *pending_attempt = Some(event.attempt_number);
            }
            valid
        }
        DirectPodReconnectEventKind::AttemptFailed => {
            let valid = *pending_attempt == Some(event.attempt_number)
                && event.previous_transport_epoch == *cycle_previous_epoch;
            if valid {
                *completed_attempts = event.attempt_number;
                *pending_attempt = None;
            }
            valid
        }
        DirectPodReconnectEventKind::FreshEpochAdmitted => {
            let valid = *pending_attempt == Some(event.attempt_number)
                && event.previous_transport_epoch == *cycle_previous_epoch
                && event.candidate_transport_epoch > *highest_admitted_epoch;
            if valid {
                *highest_admitted_epoch = event.candidate_transport_epoch;
                *cycle_previous_epoch = event.candidate_transport_epoch;
                *completed_attempts = 0;
                *pending_attempt = None;
                *attempts_exhausted = false;
            }
            valid
        }
        DirectPodReconnectEventKind::AttemptsExhausted => {
            let valid = pending_attempt.is_none()
                && *completed_attempts == event.max_attempts
                && event.attempt_number == *completed_attempts
                && event.previous_transport_epoch == *cycle_previous_epoch;
            if valid {
                *attempts_exhausted = true;
            }
            valid
        }
        DirectPodReconnectEventKind::ServiceCancelled => {
            let may_initialize_cycle =
                *cycle_previous_epoch == 0 && *completed_attempts == 0 && pending_attempt.is_none();
            let valid = (event.previous_transport_epoch == *cycle_previous_epoch
                || may_initialize_cycle)
                && (*pending_attempt == Some(event.attempt_number)
                    || (pending_attempt.is_none() && event.attempt_number == *completed_attempts));
            if valid {
                *cycle_previous_epoch = event.previous_transport_epoch;
                *completed_attempts = (*completed_attempts).max(event.attempt_number);
                *pending_attempt = None;
                *attempts_exhausted = *completed_attempts >= event.max_attempts;
            }
            valid
        }
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_data(
            "reconnect ledger event transition is contradictory",
        ))
    }
}

fn event_filename(sequence: u64) -> String {
    format!("event-{sequence:016x}.bin")
}

fn parse_event_filename(value: &str) -> io::Result<u64> {
    let hex = value
        .strip_prefix("event-")
        .and_then(|value| value.strip_suffix(".bin"))
        .filter(|value| value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| invalid_data("reconnect ledger contains an unknown filename"))?;
    u64::from_str_radix(hex, 16).map_err(|_| invalid_data("reconnect filename is invalid"))
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| invalid_data("truncated direct-Pod reconnect event"))
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

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempLedger(PathBuf);

    impl TempLedger {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "forge-reconnect-{label}-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for TempLedger {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn event(kind: DirectPodReconnectEventKind) -> DirectPodReconnectEventV1 {
        DirectPodReconnectEventV1 {
            event_kind: kind,
            device_id: [0x11; 16],
            reconnect_sequence: 1,
            previous_transport_epoch: 7,
            candidate_transport_epoch: 0,
            host_monotonic_ns: 100,
            attempt_number: 0,
            max_attempts: 3,
            fault_kind: 4,
            result_code: 0,
            prior_event_hash: [0; 32],
            deployment_evidence_hash: [0x22; 32],
            detail_hash: [0x33; 32],
            service_instance_id: [0x44; 16],
        }
    }

    #[test]
    fn contract_hash_and_every_mutation_are_exact() {
        let schema = include_str!("../schema/forge_direct_pod_reconnect_event_v1.idl")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(
            sha256(schema.as_bytes()),
            DIRECT_POD_RECONNECT_CONTRACT_HASH
        );
        let bytes = event(DirectPodReconnectEventKind::TransportFault)
            .encode()
            .unwrap();
        assert_eq!(
            DirectPodReconnectEventV1::decode(&bytes).unwrap(),
            event(DirectPodReconnectEventKind::TransportFault)
        );
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(
                DirectPodReconnectEventV1::decode(&changed).is_err(),
                "byte {index}"
            );
        }
        for length in 0..bytes.len() {
            assert!(DirectPodReconnectEventV1::decode(&bytes[..length]).is_err());
        }
    }

    #[test]
    fn independent_python_golden_matches_exact_reconnect_event() {
        let text = include_str!("../golden/direct_pod_reconnect_event_v1.hex").trim();
        let bytes = (0..text.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&text[offset..offset + 2], 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(bytes.len(), DIRECT_POD_RECONNECT_EVENT_LEN);
        assert_eq!(
            DirectPodReconnectEventV1::decode(&bytes).unwrap(),
            event(DirectPodReconnectEventKind::TransportFault)
        );
        assert_eq!(
            event(DirectPodReconnectEventKind::TransportFault)
                .encode()
                .unwrap()
                .as_slice(),
            bytes
        );
    }

    #[test]
    fn ledger_is_no_overwrite_hash_chained_and_reopenable() {
        let temp = TempLedger::new("chain");
        let mut ledger = DirectPodReconnectLedger::open(&temp.0, [0x11; 16], [0x22; 32]).unwrap();
        let first = ledger
            .append(
                DirectPodReconnectEventKind::TransportFault,
                7,
                0,
                100,
                0,
                3,
                4,
                0,
                [0x33; 32],
                [0x44; 16],
            )
            .unwrap();
        let started = ledger
            .append(
                DirectPodReconnectEventKind::AttemptStarted,
                7,
                0,
                150,
                1,
                3,
                0,
                0,
                [0x44; 32],
                [0x44; 16],
            )
            .unwrap();
        let second = ledger
            .append(
                DirectPodReconnectEventKind::AttemptFailed,
                7,
                0,
                200,
                1,
                3,
                1,
                2,
                [0x44; 32],
                [0x44; 16],
            )
            .unwrap();
        assert_eq!(started.prior_event_hash, first.evidence_hash().unwrap());
        assert_eq!(second.prior_event_hash, started.evidence_hash().unwrap());
        drop(ledger);
        let reopened = DirectPodReconnectLedger::open(&temp.0, [0x11; 16], [0x22; 32]).unwrap();
        assert_eq!(reopened.event_count(), 3);
        assert_eq!(reopened.last_event(), Some(second));
        assert_eq!(reopened.completed_attempts(), 1);
        assert!(DirectPodReconnectLedger::open(&temp.0, [0x12; 16], [0x22; 32]).is_err());
    }

    #[test]
    fn stale_epoch_and_event_kind_contradictions_fail_closed() {
        let mut fresh = event(DirectPodReconnectEventKind::FreshEpochAdmitted);
        fresh.attempt_number = 1;
        fresh.fault_kind = 0;
        fresh.candidate_transport_epoch = 7;
        assert!(fresh.encode().is_err());
        fresh.candidate_transport_epoch = 8;
        fresh.encode().unwrap();

        let mut exhausted = event(DirectPodReconnectEventKind::AttemptsExhausted);
        exhausted.attempt_number = 2;
        exhausted.result_code = 1;
        assert!(exhausted.encode().is_err());
    }

    #[test]
    fn interrupted_attempt_survives_reopen_and_budget_cannot_reset() {
        let temp = TempLedger::new("interrupted");
        let mut ledger = DirectPodReconnectLedger::open(&temp.0, [0x11; 16], [0x22; 32]).unwrap();
        ledger
            .append(
                DirectPodReconnectEventKind::AttemptStarted,
                40,
                0,
                10,
                1,
                2,
                0,
                0,
                [0x55; 32],
                [0x44; 16],
            )
            .unwrap();
        drop(ledger);

        let mut reopened = DirectPodReconnectLedger::open(&temp.0, [0x11; 16], [0x22; 32]).unwrap();
        assert_eq!(reopened.pending_attempt(), Some(1));
        reopened
            .append(
                DirectPodReconnectEventKind::AttemptFailed,
                40,
                0,
                1,
                1,
                2,
                1,
                2,
                [0x66; 32],
                [0x45; 16],
            )
            .unwrap();
        reopened
            .append(
                DirectPodReconnectEventKind::AttemptStarted,
                40,
                0,
                2,
                2,
                2,
                0,
                0,
                [0x77; 32],
                [0x45; 16],
            )
            .unwrap();
        reopened
            .append(
                DirectPodReconnectEventKind::AttemptFailed,
                40,
                0,
                3,
                2,
                2,
                1,
                1,
                [0x88; 32],
                [0x45; 16],
            )
            .unwrap();
        reopened
            .append(
                DirectPodReconnectEventKind::AttemptsExhausted,
                40,
                0,
                4,
                2,
                2,
                1,
                1,
                [0x99; 32],
                [0x45; 16],
            )
            .unwrap();
        drop(reopened);

        let exhausted = DirectPodReconnectLedger::open(&temp.0, [0x11; 16], [0x22; 32]).unwrap();
        assert!(exhausted.attempts_exhausted());
        assert_eq!(exhausted.completed_attempts(), 2);
        assert_eq!(exhausted.cycle_previous_epoch(), 40);
        assert!(DirectPodReconnectLedger::open(&temp.0, [0x11; 16], [0x23; 32]).is_err());
    }

    #[test]
    fn admitted_epoch_is_a_durable_strict_floor() {
        let temp = TempLedger::new("epoch-floor");
        let mut ledger = DirectPodReconnectLedger::open(&temp.0, [0x11; 16], [0x22; 32]).unwrap();
        ledger
            .append(
                DirectPodReconnectEventKind::AttemptStarted,
                9,
                0,
                10,
                1,
                3,
                0,
                0,
                [0x55; 32],
                [0x44; 16],
            )
            .unwrap();
        ledger
            .append(
                DirectPodReconnectEventKind::FreshEpochAdmitted,
                9,
                10,
                20,
                1,
                3,
                0,
                0,
                [0x66; 32],
                [0x44; 16],
            )
            .unwrap();
        drop(ledger);
        let reopened = DirectPodReconnectLedger::open(&temp.0, [0x11; 16], [0x22; 32]).unwrap();
        assert_eq!(reopened.highest_admitted_epoch(), 10);
        assert_eq!(reopened.completed_attempts(), 0);
    }
}
