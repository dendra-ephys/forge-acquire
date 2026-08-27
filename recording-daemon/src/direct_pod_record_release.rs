//! Frozen direct-Pod record-release companion.  This is deliberately not M0/DHL.

use std::io;

use forge_protocol_v1::{crc32c, sha256, Hash32, Id16, PROTOCOL_HASH};

pub const DIRECT_POD_RECORD_RELEASE_LEN: usize = 312;
pub const DIRECT_POD_RECORD_RELEASE_CONTRACT_HASH_HEX: &str =
    "512d2fb554d4bc9bb2d56f46c3e25bd8d12548c93fa3eec62ae98800af067285";
pub const DIRECT_POD_RECORD_RELEASE_CONTRACT_HASH: Hash32 = [
    0x51, 0x2d, 0x2f, 0xb5, 0x54, 0xd4, 0xbc, 0x9b, 0xb2, 0xd5, 0x6f, 0x46, 0xc3, 0xe2, 0x5b, 0xd8,
    0xd1, 0x25, 0x48, 0xc9, 0x3f, 0xa3, 0xee, 0xc6, 0x2a, 0xe9, 0x88, 0x00, 0xaf, 0x06, 0x72, 0x85,
];
pub const RELEASE_FLAG_HAS_RELEASED: u16 = 1;
pub const RELEASE_FLAG_HAS_RETAINED: u16 = 2;
pub const RELEASE_FLAG_HAS_COMMITTED: u16 = 4;
pub const RELEASE_FLAG_SEQUENCE_TERMINAL: u16 = 8;
const RELEASE_KNOWN_FLAGS: u16 = RELEASE_FLAG_HAS_RELEASED
    | RELEASE_FLAG_HAS_RETAINED
    | RELEASE_FLAG_HAS_COMMITTED
    | RELEASE_FLAG_SEQUENCE_TERMINAL;
const REQUEST_MAGIC: &[u8; 8] = b"FGRREL01";
const REPLY_MAGIC: &[u8; 8] = b"FGRRLR01";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum DirectPodRecordReleaseStatusV1 {
    Applied = 1,
    Duplicate = 2,
    Stale = 3,
    Future = 4,
    WrongEpoch = 5,
    WrongHash = 6,
    Rejected = 7,
    Aborted = 8,
}

impl TryFrom<u16> for DirectPodRecordReleaseStatusV1 {
    type Error = io::Error;
    fn try_from(value: u16) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Applied),
            2 => Ok(Self::Duplicate),
            3 => Ok(Self::Stale),
            4 => Ok(Self::Future),
            5 => Ok(Self::WrongEpoch),
            6 => Ok(Self::WrongHash),
            7 => Ok(Self::Rejected),
            8 => Ok(Self::Aborted),
            _ => Err(invalid_data("unknown direct-Pod record-release status")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodRecordReleaseRequestV1 {
    pub device_id: Id16,
    pub run_id: Id16,
    pub pod_id: Id16,
    pub headstage_id: Id16,
    pub transport_epoch: u64,
    pub request_id: u64,
    pub first_record_sequence: u64,
    pub last_record_sequence_inclusive: u64,
    pub release_record_count: u16,
    pub expected_store_depth: u16,
    pub durable_journal_sequence: u64,
    pub durable_record_count: u64,
    pub durable_checkpoint_generation: u64,
    pub durable_prefix_hash: Hash32,
    pub durable_checkpoint_hash: Hash32,
    pub completion_evidence_hash: Hash32,
}

impl DirectPodRecordReleaseRequestV1 {
    pub fn completion_evidence_hash(&self) -> Hash32 {
        request_completion_hash(self)
    }
    pub fn request_hash(&self) -> io::Result<Hash32> {
        Ok(sha256(&self.encode()?))
    }
    pub fn encode(self) -> io::Result<[u8; DIRECT_POD_RECORD_RELEASE_LEN]> {
        validate_request(&self)?;
        let mut bytes = [0_u8; DIRECT_POD_RECORD_RELEASE_LEN];
        bytes[0..8].copy_from_slice(REQUEST_MAGIC);
        put_u16(&mut bytes, 8, VERSION);
        put_u16(&mut bytes, 10, DIRECT_POD_RECORD_RELEASE_LEN as u16);
        bytes[16..48].copy_from_slice(&DIRECT_POD_RECORD_RELEASE_CONTRACT_HASH);
        bytes[48..80].copy_from_slice(&PROTOCOL_HASH);
        bytes[80..96].copy_from_slice(&self.device_id);
        bytes[96..112].copy_from_slice(&self.run_id);
        bytes[112..128].copy_from_slice(&self.pod_id);
        bytes[128..144].copy_from_slice(&self.headstage_id);
        put_u64(&mut bytes, 144, self.transport_epoch);
        put_u64(&mut bytes, 152, self.request_id);
        put_u64(&mut bytes, 160, self.first_record_sequence);
        put_u64(&mut bytes, 168, self.last_record_sequence_inclusive);
        put_u16(&mut bytes, 176, self.release_record_count);
        put_u16(&mut bytes, 178, self.expected_store_depth);
        put_u64(&mut bytes, 184, self.durable_journal_sequence);
        put_u64(&mut bytes, 192, self.durable_record_count);
        put_u64(&mut bytes, 200, self.durable_checkpoint_generation);
        bytes[208..240].copy_from_slice(&self.durable_prefix_hash);
        bytes[240..272].copy_from_slice(&self.durable_checkpoint_hash);
        bytes[272..304].copy_from_slice(&self.completion_evidence_hash);
        let checksum = crc32c(&bytes[..308]);
        put_u32(&mut bytes, 308, checksum);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != DIRECT_POD_RECORD_RELEASE_LEN
            || bytes.get(..8) != Some(REQUEST_MAGIC)
            || le_u16(bytes, 8)? != VERSION
            || le_u16(bytes, 10)? as usize != DIRECT_POD_RECORD_RELEASE_LEN
            || le_u32(bytes, 12)? != 0
            || array::<32>(bytes, 16)? != DIRECT_POD_RECORD_RELEASE_CONTRACT_HASH
            || array::<32>(bytes, 48)? != PROTOCOL_HASH
            || le_u32(bytes, 180)? != 0
            || le_u32(bytes, 304)? != 0
            || le_u32(bytes, 308)? != crc32c(&bytes[..308])
        {
            return Err(invalid_data(
                "direct-Pod record-release request framing is invalid",
            ));
        }
        let value = Self {
            device_id: array(bytes, 80)?,
            run_id: array(bytes, 96)?,
            pod_id: array(bytes, 112)?,
            headstage_id: array(bytes, 128)?,
            transport_epoch: le_u64(bytes, 144)?,
            request_id: le_u64(bytes, 152)?,
            first_record_sequence: le_u64(bytes, 160)?,
            last_record_sequence_inclusive: le_u64(bytes, 168)?,
            release_record_count: le_u16(bytes, 176)?,
            expected_store_depth: le_u16(bytes, 178)?,
            durable_journal_sequence: le_u64(bytes, 184)?,
            durable_record_count: le_u64(bytes, 192)?,
            durable_checkpoint_generation: le_u64(bytes, 200)?,
            durable_prefix_hash: array(bytes, 208)?,
            durable_checkpoint_hash: array(bytes, 240)?,
            completion_evidence_hash: array(bytes, 272)?,
        };
        validate_request(&value).map_err(|_| {
            invalid_data("direct-Pod record-release request violates semantic invariants")
        })?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPodRecordReleaseReplyV1 {
    pub status: DirectPodRecordReleaseStatusV1,
    pub state_flags: u16,
    pub device_id: Id16,
    pub run_id: Id16,
    pub pod_id: Id16,
    pub headstage_id: Id16,
    pub requested_epoch: u64,
    pub current_epoch: u64,
    pub request_id: u64,
    pub request_hash: Hash32,
    pub released_through_inclusive: u64,
    pub oldest_retained_sequence: u64,
    pub newest_committed_sequence_inclusive: u64,
    pub store_depth: u16,
    pub retained_count: u16,
    pub store_state_hash: Hash32,
    pub receipt_hash: Hash32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedCanonicalRecord<'a> {
    pub sequence: u64,
    pub bytes: &'a [u8],
}

impl DirectPodRecordReleaseReplyV1 {
    pub fn receipt_hash(&self) -> Hash32 {
        reply_receipt_hash(self)
    }
    pub fn encode(self) -> io::Result<[u8; DIRECT_POD_RECORD_RELEASE_LEN]> {
        validate_reply(&self)?;
        let mut bytes = [0_u8; DIRECT_POD_RECORD_RELEASE_LEN];
        bytes[0..8].copy_from_slice(REPLY_MAGIC);
        put_u16(&mut bytes, 8, VERSION);
        put_u16(&mut bytes, 10, DIRECT_POD_RECORD_RELEASE_LEN as u16);
        put_u16(&mut bytes, 12, self.status as u16);
        put_u16(&mut bytes, 14, self.state_flags);
        bytes[16..48].copy_from_slice(&DIRECT_POD_RECORD_RELEASE_CONTRACT_HASH);
        bytes[48..80].copy_from_slice(&PROTOCOL_HASH);
        bytes[80..96].copy_from_slice(&self.device_id);
        bytes[96..112].copy_from_slice(&self.run_id);
        bytes[112..128].copy_from_slice(&self.pod_id);
        bytes[128..144].copy_from_slice(&self.headstage_id);
        put_u64(&mut bytes, 144, self.requested_epoch);
        put_u64(&mut bytes, 152, self.current_epoch);
        put_u64(&mut bytes, 160, self.request_id);
        bytes[168..200].copy_from_slice(&self.request_hash);
        put_u64(&mut bytes, 200, self.released_through_inclusive);
        put_u64(&mut bytes, 208, self.oldest_retained_sequence);
        put_u64(&mut bytes, 216, self.newest_committed_sequence_inclusive);
        put_u16(&mut bytes, 224, self.store_depth);
        put_u16(&mut bytes, 226, self.retained_count);
        bytes[240..272].copy_from_slice(&self.store_state_hash);
        bytes[272..304].copy_from_slice(&self.receipt_hash);
        let checksum = crc32c(&bytes[..308]);
        put_u32(&mut bytes, 308, checksum);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != DIRECT_POD_RECORD_RELEASE_LEN
            || bytes.get(..8) != Some(REPLY_MAGIC)
            || le_u16(bytes, 8)? != VERSION
            || le_u16(bytes, 10)? as usize != DIRECT_POD_RECORD_RELEASE_LEN
            || array::<32>(bytes, 16)? != DIRECT_POD_RECORD_RELEASE_CONTRACT_HASH
            || array::<32>(bytes, 48)? != PROTOCOL_HASH
            || bytes[228..240].iter().any(|byte| *byte != 0)
            || le_u32(bytes, 304)? != 0
            || le_u32(bytes, 308)? != crc32c(&bytes[..308])
        {
            return Err(invalid_data(
                "direct-Pod record-release reply framing is invalid",
            ));
        }
        let value = Self {
            status: le_u16(bytes, 12)?.try_into()?,
            state_flags: le_u16(bytes, 14)?,
            device_id: array(bytes, 80)?,
            run_id: array(bytes, 96)?,
            pod_id: array(bytes, 112)?,
            headstage_id: array(bytes, 128)?,
            requested_epoch: le_u64(bytes, 144)?,
            current_epoch: le_u64(bytes, 152)?,
            request_id: le_u64(bytes, 160)?,
            request_hash: array(bytes, 168)?,
            released_through_inclusive: le_u64(bytes, 200)?,
            oldest_retained_sequence: le_u64(bytes, 208)?,
            newest_committed_sequence_inclusive: le_u64(bytes, 216)?,
            store_depth: le_u16(bytes, 224)?,
            retained_count: le_u16(bytes, 226)?,
            store_state_hash: array(bytes, 240)?,
            receipt_hash: array(bytes, 272)?,
        };
        validate_reply(&value).map_err(|_| {
            invalid_data("direct-Pod record-release reply violates semantic invariants")
        })?;
        Ok(value)
    }
}

pub fn record_prefix_hash(
    first: u64,
    last: u64,
    count: u16,
    records: &[&[u8]],
) -> io::Result<Hash32> {
    validate_range(first, last, count)?;
    if records.len() != count as usize {
        return Err(invalid_input(
            "record-release prefix hash list length is invalid",
        ));
    }
    let mut preimage = b"FORGE-DIRECT-POD-RECORD-RELEASE-PREFIX-V1\0".to_vec();
    preimage.extend_from_slice(&first.to_le_bytes());
    preimage.extend_from_slice(&last.to_le_bytes());
    preimage.extend_from_slice(&count.to_le_bytes());
    for record in records {
        preimage.extend_from_slice(&sha256(record));
    }
    Ok(sha256(&preimage))
}

#[allow(clippy::too_many_arguments)]
pub fn store_state_hash(
    device_id: Id16,
    run_id: Id16,
    pod_id: Id16,
    headstage_id: Id16,
    current_epoch: u64,
    state_flags: u16,
    released_through_inclusive: u64,
    oldest_retained_sequence: u64,
    newest_committed_sequence_inclusive: u64,
    store_depth: u16,
    retained_records: &[RetainedCanonicalRecord<'_>],
) -> io::Result<Hash32> {
    if retained_records.len() > u16::MAX as usize {
        return Err(invalid_input(
            "record-release retained record count is too large",
        ));
    }
    validate_store_state(
        [device_id, run_id, pod_id, headstage_id],
        current_epoch,
        state_flags,
        released_through_inclusive,
        oldest_retained_sequence,
        newest_committed_sequence_inclusive,
        store_depth,
        retained_records.len() as u16,
    )?;
    for (index, record) in retained_records.iter().enumerate() {
        let expected = oldest_retained_sequence
            .checked_add(index as u64)
            .ok_or_else(|| invalid_input("record-release retained sequence overflows"))?;
        if record.sequence != expected {
            return Err(invalid_input(
                "record-release retained records are not contiguous",
            ));
        }
    }
    let mut bytes = b"FORGE-DIRECT-POD-RECORD-STORE-STATE-V1\0".to_vec();
    bytes.extend_from_slice(&DIRECT_POD_RECORD_RELEASE_CONTRACT_HASH);
    bytes.extend_from_slice(&PROTOCOL_HASH);
    for id in [device_id, run_id, pod_id, headstage_id] {
        bytes.extend_from_slice(&id);
    }
    bytes.extend_from_slice(&current_epoch.to_le_bytes());
    bytes.extend_from_slice(&state_flags.to_le_bytes());
    for frontier in [
        released_through_inclusive,
        oldest_retained_sequence,
        newest_committed_sequence_inclusive,
    ] {
        bytes.extend_from_slice(&frontier.to_le_bytes());
    }
    bytes.extend_from_slice(&store_depth.to_le_bytes());
    bytes.extend_from_slice(&(retained_records.len() as u16).to_le_bytes());
    for record in retained_records {
        bytes.extend_from_slice(&record.sequence.to_le_bytes());
        bytes.extend_from_slice(&sha256(record.bytes));
    }
    Ok(sha256(&bytes))
}

fn request_completion_hash(value: &DirectPodRecordReleaseRequestV1) -> Hash32 {
    let mut bytes = b"FORGE-DIRECT-POD-RECORD-RELEASE-EVIDENCE-V1\0".to_vec();
    bytes.extend_from_slice(&DIRECT_POD_RECORD_RELEASE_CONTRACT_HASH);
    bytes.extend_from_slice(&PROTOCOL_HASH);
    bytes.extend_from_slice(&value.device_id);
    bytes.extend_from_slice(&value.run_id);
    bytes.extend_from_slice(&value.pod_id);
    bytes.extend_from_slice(&value.headstage_id);
    for number in [
        value.transport_epoch,
        value.request_id,
        value.first_record_sequence,
        value.last_record_sequence_inclusive,
    ] {
        bytes.extend_from_slice(&number.to_le_bytes());
    }
    bytes.extend_from_slice(&value.release_record_count.to_le_bytes());
    bytes.extend_from_slice(&value.expected_store_depth.to_le_bytes());
    for number in [
        value.durable_journal_sequence,
        value.durable_record_count,
        value.durable_checkpoint_generation,
    ] {
        bytes.extend_from_slice(&number.to_le_bytes());
    }
    bytes.extend_from_slice(&value.durable_prefix_hash);
    bytes.extend_from_slice(&value.durable_checkpoint_hash);
    sha256(&bytes)
}

fn reply_receipt_hash(value: &DirectPodRecordReleaseReplyV1) -> Hash32 {
    let mut bytes = b"FORGE-DIRECT-POD-RECORD-RELEASE-RECEIPT-V1\0".to_vec();
    bytes.extend_from_slice(&DIRECT_POD_RECORD_RELEASE_CONTRACT_HASH);
    bytes.extend_from_slice(&PROTOCOL_HASH);
    bytes.extend_from_slice(&value.device_id);
    bytes.extend_from_slice(&value.run_id);
    bytes.extend_from_slice(&value.pod_id);
    bytes.extend_from_slice(&value.headstage_id);
    bytes.extend_from_slice(&(value.status as u16).to_le_bytes());
    bytes.extend_from_slice(&value.state_flags.to_le_bytes());
    for number in [value.requested_epoch, value.current_epoch, value.request_id] {
        bytes.extend_from_slice(&number.to_le_bytes());
    }
    bytes.extend_from_slice(&value.request_hash);
    for number in [
        value.released_through_inclusive,
        value.oldest_retained_sequence,
        value.newest_committed_sequence_inclusive,
    ] {
        bytes.extend_from_slice(&number.to_le_bytes());
    }
    bytes.extend_from_slice(&value.store_depth.to_le_bytes());
    bytes.extend_from_slice(&value.retained_count.to_le_bytes());
    bytes.extend_from_slice(&value.store_state_hash);
    sha256(&bytes)
}

fn validate_request(value: &DirectPodRecordReleaseRequestV1) -> io::Result<()> {
    if !ids_nonzero([
        value.device_id,
        value.run_id,
        value.pod_id,
        value.headstage_id,
    ]) || value.transport_epoch == 0
        || value.request_id == 0
        || value.release_record_count == 0
        || value.release_record_count > 2
        || value.expected_store_depth == 0
        || value.expected_store_depth > 2
        || value.release_record_count > value.expected_store_depth
        || value.durable_record_count < value.release_record_count as u64
        || value.durable_checkpoint_generation == 0
        || !nonzero(&value.durable_prefix_hash)
        || !nonzero(&value.durable_checkpoint_hash)
        || value.completion_evidence_hash != request_completion_hash(value)
    {
        return Err(invalid_input(
            "direct-Pod record-release request semantics are invalid",
        ));
    }
    validate_range(
        value.first_record_sequence,
        value.last_record_sequence_inclusive,
        value.release_record_count,
    )
}
fn validate_reply(value: &DirectPodRecordReleaseReplyV1) -> io::Result<()> {
    let released = value.state_flags & RELEASE_FLAG_HAS_RELEASED != 0;
    if !ids_nonzero([
        value.device_id,
        value.run_id,
        value.pod_id,
        value.headstage_id,
    ]) || value.requested_epoch == 0
        || value.current_epoch == 0
        || value.request_id == 0
        || !nonzero(&value.request_hash)
        || !nonzero(&value.store_state_hash)
        || value.state_flags & !RELEASE_KNOWN_FLAGS != 0
        || value.store_depth == 0
        || value.store_depth > 2
        || value.retained_count > value.store_depth
        || validate_store_state(
            [
                value.device_id,
                value.run_id,
                value.pod_id,
                value.headstage_id,
            ],
            value.current_epoch,
            value.state_flags,
            value.released_through_inclusive,
            value.oldest_retained_sequence,
            value.newest_committed_sequence_inclusive,
            value.store_depth,
            value.retained_count,
        )
        .is_err()
        || matches!(
            value.status,
            DirectPodRecordReleaseStatusV1::Applied | DirectPodRecordReleaseStatusV1::Duplicate
        ) && !released
        || value.receipt_hash != reply_receipt_hash(value)
    {
        return Err(invalid_input(
            "direct-Pod record-release reply semantics are invalid",
        ));
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn validate_store_state(
    ids: [Id16; 4],
    current_epoch: u64,
    state_flags: u16,
    released_through: u64,
    oldest_retained: u64,
    newest_committed: u64,
    store_depth: u16,
    retained_count: u16,
) -> io::Result<()> {
    let released = state_flags & RELEASE_FLAG_HAS_RELEASED != 0;
    let retained = state_flags & RELEASE_FLAG_HAS_RETAINED != 0;
    let committed = state_flags & RELEASE_FLAG_HAS_COMMITTED != 0;
    let terminal = state_flags & RELEASE_FLAG_SEQUENCE_TERMINAL != 0;
    let expected_newest = oldest_retained.checked_add((retained_count as u64).saturating_sub(1));
    if !ids_nonzero(ids)
        || current_epoch == 0
        || state_flags & !RELEASE_KNOWN_FLAGS != 0
        || store_depth == 0
        || store_depth > 2
        || retained_count > store_depth
        || retained != (retained_count > 0)
        || terminal != (committed && newest_committed == u64::MAX)
        || (!committed
            && (released
                || retained
                || terminal
                || released_through != 0
                || oldest_retained != 0
                || newest_committed != 0
                || retained_count != 0))
        || (retained
            && (!committed
                || expected_newest != Some(newest_committed)
                || (released && released_through.checked_add(1) != Some(oldest_retained))
                || (!released && oldest_retained != 0)))
        || (!retained && oldest_retained != 0)
        || (committed && retained_count == 0 && (!released || released_through != newest_committed))
        || (released && (!committed || released_through > newest_committed))
    {
        Err(invalid_input(
            "direct-Pod record-release store state is invalid",
        ))
    } else {
        Ok(())
    }
}
fn validate_range(first: u64, last: u64, count: u16) -> io::Result<()> {
    if last < first || first.checked_add((count as u64).saturating_sub(1)) != Some(last) {
        Err(invalid_input("direct-Pod record-release range is invalid"))
    } else {
        Ok(())
    }
}
fn ids_nonzero(ids: [Id16; 4]) -> bool {
    ids.iter().all(|id| nonzero(id))
}
fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}
fn array<const N: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .and_then(|part| part.try_into().ok())
        .ok_or_else(|| invalid_data("truncated direct-Pod record-release companion"))
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
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
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
    fn request() -> DirectPodRecordReleaseRequestV1 {
        let mut value = DirectPodRecordReleaseRequestV1 {
            device_id: [1; 16],
            run_id: [2; 16],
            pod_id: [3; 16],
            headstage_id: [4; 16],
            transport_epoch: 7,
            request_id: 9,
            first_record_sequence: 11,
            last_record_sequence_inclusive: 12,
            release_record_count: 2,
            expected_store_depth: 2,
            durable_journal_sequence: 13,
            durable_record_count: 14,
            durable_checkpoint_generation: 15,
            durable_prefix_hash: [5; 32],
            durable_checkpoint_hash: [6; 32],
            completion_evidence_hash: [0; 32],
        };
        value.completion_evidence_hash = value.completion_evidence_hash();
        value
    }
    fn reply() -> DirectPodRecordReleaseReplyV1 {
        let request = request().encode().unwrap();
        let retained = [
            RetainedCanonicalRecord {
                sequence: 13,
                bytes: b"retained-13",
            },
            RetainedCanonicalRecord {
                sequence: 14,
                bytes: b"retained-14",
            },
        ];
        let state_flags =
            RELEASE_FLAG_HAS_RELEASED | RELEASE_FLAG_HAS_RETAINED | RELEASE_FLAG_HAS_COMMITTED;
        let mut value = DirectPodRecordReleaseReplyV1 {
            status: DirectPodRecordReleaseStatusV1::Applied,
            state_flags,
            device_id: [1; 16],
            run_id: [2; 16],
            pod_id: [3; 16],
            headstage_id: [4; 16],
            requested_epoch: 7,
            current_epoch: 7,
            request_id: 9,
            request_hash: sha256(&request),
            released_through_inclusive: 12,
            oldest_retained_sequence: 13,
            newest_committed_sequence_inclusive: 14,
            store_depth: 2,
            retained_count: 2,
            store_state_hash: store_state_hash(
                [1; 16],
                [2; 16],
                [3; 16],
                [4; 16],
                7,
                state_flags,
                12,
                13,
                14,
                2,
                &retained,
            )
            .unwrap(),
            receipt_hash: [0; 32],
        };
        value.receipt_hash = value.receipt_hash();
        value
    }
    fn refresh_crc(bytes: &mut [u8; DIRECT_POD_RECORD_RELEASE_LEN]) {
        let checksum = crc32c(&bytes[..308]);
        put_u32(bytes, 308, checksum);
    }
    #[test]
    fn schema_hash_and_exact_golden_round_trip() {
        let schema = include_str!("../schema/forge_direct_pod_record_release_v1.idl")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(
            sha256(schema.as_bytes()),
            DIRECT_POD_RECORD_RELEASE_CONTRACT_HASH
        );
        for (text, actual) in [
            (
                include_str!("../../protocol/golden/direct_pod_record_release_request_v1.hex")
                    .trim(),
                request().encode().unwrap().to_vec(),
            ),
            (
                include_str!("../../protocol/golden/direct_pod_record_release_reply_v1.hex").trim(),
                reply().encode().unwrap().to_vec(),
            ),
        ] {
            let expected: Vec<u8> = (0..DIRECT_POD_RECORD_RELEASE_LEN)
                .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
                .collect();
            assert_eq!(actual, expected);
        }
    }
    #[test]
    fn request_reply_truncation_and_all_single_bit_mutations_fail() {
        for bytes in [request().encode().unwrap(), reply().encode().unwrap()] {
            for length in 0..bytes.len() {
                assert!(
                    DirectPodRecordReleaseRequestV1::decode(&bytes[..length]).is_err()
                        && DirectPodRecordReleaseReplyV1::decode(&bytes[..length]).is_err()
                );
            }
            for index in 0..bytes.len() {
                let mut changed = bytes;
                changed[index] ^= 1;
                assert!(DirectPodRecordReleaseRequestV1::decode(&changed).is_err());
                assert!(DirectPodRecordReleaseReplyV1::decode(&changed).is_err());
            }
        }
    }
    #[test]
    fn semantic_negatives_and_max_singleton() {
        let mut r = request().encode().unwrap();
        for (offset, width) in [(80, 16), (16, 32), (48, 32), (208, 32), (272, 32)] {
            r[offset..offset + width].fill(0);
            refresh_crc(&mut r);
            assert!(DirectPodRecordReleaseRequestV1::decode(&r).is_err());
            r = request().encode().unwrap();
        }
        let mut bad = request();
        bad.first_record_sequence = u64::MAX;
        bad.last_record_sequence_inclusive = u64::MAX;
        bad.release_record_count = 1;
        bad.expected_store_depth = 1;
        bad.durable_record_count = 1;
        bad.completion_evidence_hash = bad.completion_evidence_hash();
        assert!(bad.encode().is_ok());
        assert!(record_prefix_hash(u64::MAX, u64::MAX, 1, &[b"canonical"]).is_ok());
        let mut q = reply().encode().unwrap();
        q[14] |= 0x80;
        refresh_crc(&mut q);
        assert!(DirectPodRecordReleaseReplyV1::decode(&q).is_err());
    }
    #[test]
    fn request_hash_and_store_state_golden_are_exact() {
        let request = request();
        assert_eq!(
            request.request_hash().unwrap(),
            sha256(&request.encode().unwrap())
        );
        let records = [
            RetainedCanonicalRecord {
                sequence: 13,
                bytes: b"retained-13",
            },
            RetainedCanonicalRecord {
                sequence: 14,
                bytes: b"retained-14",
            },
        ];
        let actual = store_state_hash(
            [1; 16],
            [2; 16],
            [3; 16],
            [4; 16],
            7,
            RELEASE_FLAG_HAS_RELEASED | RELEASE_FLAG_HAS_RETAINED | RELEASE_FLAG_HAS_COMMITTED,
            12,
            13,
            14,
            2,
            &records,
        )
        .unwrap();
        let text =
            include_str!("../../protocol/golden/direct_pod_record_store_state_v1.hex").trim();
        let expected: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        assert_eq!(actual.as_slice(), expected.as_slice());
        assert_ne!(
            actual,
            store_state_hash(
                [1; 16],
                [2; 16],
                [3; 16],
                [4; 16],
                7,
                RELEASE_FLAG_HAS_RELEASED | RELEASE_FLAG_HAS_RETAINED | RELEASE_FLAG_HAS_COMMITTED,
                12,
                13,
                14,
                2,
                &[
                    RetainedCanonicalRecord {
                        sequence: 13,
                        bytes: b"retained-13!"
                    },
                    RetainedCanonicalRecord {
                        sequence: 14,
                        bytes: b"retained-14"
                    }
                ],
            )
            .unwrap()
        );
        assert!(store_state_hash(
            [1; 16],
            [2; 16],
            [3; 16],
            [4; 16],
            7,
            RELEASE_FLAG_HAS_RELEASED | RELEASE_FLAG_HAS_RETAINED | RELEASE_FLAG_HAS_COMMITTED,
            12,
            13,
            14,
            2,
            &[
                RetainedCanonicalRecord {
                    sequence: 13,
                    bytes: b"one"
                },
                RetainedCanonicalRecord {
                    sequence: 15,
                    bytes: b"two"
                }
            ],
        )
        .is_err());
    }
}
