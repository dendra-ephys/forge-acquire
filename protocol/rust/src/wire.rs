use std::fmt;

use crate::types::*;
use crate::{PROTOCOL_HASH, PROTOCOL_VERSION};

const RECORD_MAGIC: &[u8; 8] = b"FGRREC01";
const CONTROL_MAGIC: &[u8; 8] = b"FGRCTL01";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    Length,
    LengthLimit,
    BadMagic,
    Version,
    UnknownKind,
    UnknownFlags,
    Reserved,
    HeaderCrc,
    PayloadCrc,
    BodyCrc,
    ProtocolHash,
    Invariant,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CodecError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRecord {
    pub envelope: CanonicalRecordEnvelopeV1,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLowSpeed {
    pub kind: MessageKind,
    pub flags: u16,
    pub request_id: u64,
    pub epoch: u64,
    pub body: Vec<u8>,
}

const CRC32C_TABLE: [u32; 256] = make_crc32c_table();

const fn make_crc32c_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut index = 0_usize;
    while index < table.len() {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & (0_u32.wrapping_sub(crc & 1)));
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

/// Dependency-free, table-driven reflected Castagnoli CRC-32C.
pub fn crc32c(bytes: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sse4.2") {
        // SAFETY: the runtime feature check above proves that the instruction
        // set used by this function is available on the current processor.
        return unsafe { crc32c_sse42(bytes) };
    }
    crc32c_table(bytes)
}

fn crc32c_table(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        let index = ((crc ^ u32::from(*byte)) & 0xff) as usize;
        crc = (crc >> 8) ^ CRC32C_TABLE[index];
    }
    !crc
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn crc32c_sse42(bytes: &[u8]) -> u32 {
    use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};

    let mut crc = u64::from(!0_u32);
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes(chunk.try_into().expect("exact chunk length"));
        crc = _mm_crc32_u64(crc, word);
    }
    let mut tail_crc = crc as u32;
    for byte in chunks.remainder() {
        tail_crc = _mm_crc32_u8(tail_crc, *byte);
    }
    !tail_crc
}

pub fn encode_record(
    envelope: &CanonicalRecordEnvelopeV1,
    payload: &[u8],
) -> Result<Vec<u8>, CodecError> {
    validate_envelope(envelope, payload)?;
    if payload.len() > MAX_RECORD_PAYLOAD_LEN {
        return Err(CodecError::LengthLimit);
    }

    let mut out = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
    out.extend_from_slice(RECORD_MAGIC);
    put_u16(&mut out, PROTOCOL_VERSION);
    put_u16(&mut out, RECORD_HEADER_LEN as u16);
    put_u16(&mut out, envelope.record_kind as u16);
    put_u16(&mut out, 0);
    put_u32(&mut out, envelope.flags);
    put_u32(&mut out, payload.len() as u32);
    out.extend_from_slice(&envelope.run_id);
    out.extend_from_slice(&envelope.pod_id);
    out.extend_from_slice(&envelope.headstage_id);
    for value in [
        envelope.record_sequence,
        envelope.frame_start,
        envelope.frame_end_exclusive,
        envelope.sample_start,
        envelope.sample_end_exclusive,
        envelope.global_time_start_ns,
        envelope.global_time_end_exclusive_ns,
    ] {
        put_u64(&mut out, value);
    }
    put_u32(&mut out, envelope.channel_layout_id);
    put_u16(&mut out, envelope.channel_count);
    put_u16(&mut out, envelope.sample_format);
    out.extend_from_slice(&PROTOCOL_HASH);
    put_u32(&mut out, crc32c(payload));
    let header_crc = crc32c(&out);
    put_u32(&mut out, header_crc);
    debug_assert_eq!(out.len(), RECORD_HEADER_LEN);
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_record(bytes: &[u8]) -> Result<DecodedRecord, CodecError> {
    if bytes.len() < RECORD_HEADER_LEN {
        return Err(CodecError::Length);
    }
    if bytes.get(0..8) != Some(RECORD_MAGIC) {
        return Err(CodecError::BadMagic);
    }
    if le_u16(bytes, 8)? != PROTOCOL_VERSION {
        return Err(CodecError::Version);
    }
    if le_u16(bytes, 10)? as usize != RECORD_HEADER_LEN {
        return Err(CodecError::Length);
    }
    let kind = RecordKind::try_from(le_u16(bytes, 12)?)?;
    if le_u16(bytes, 14)? != 0 {
        return Err(CodecError::Reserved);
    }
    let flags = le_u32(bytes, 16)?;
    if flags & !RECORD_FLAGS_ALL != 0 {
        return Err(CodecError::UnknownFlags);
    }
    let payload_len = le_u32(bytes, 20)? as usize;
    if payload_len > MAX_RECORD_PAYLOAD_LEN {
        return Err(CodecError::LengthLimit);
    }
    if bytes.len()
        != RECORD_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(CodecError::Length)?
    {
        return Err(CodecError::Length);
    }
    if arr32(bytes, 136)? != PROTOCOL_HASH {
        return Err(CodecError::ProtocolHash);
    }
    if le_u32(bytes, 172)? != crc32c(&bytes[..172]) {
        return Err(CodecError::HeaderCrc);
    }
    let payload = &bytes[RECORD_HEADER_LEN..];
    if le_u32(bytes, 168)? != crc32c(payload) {
        return Err(CodecError::PayloadCrc);
    }

    let envelope = CanonicalRecordEnvelopeV1 {
        record_kind: kind,
        flags,
        run_id: arr16(bytes, 24)?,
        pod_id: arr16(bytes, 40)?,
        headstage_id: arr16(bytes, 56)?,
        record_sequence: le_u64(bytes, 72)?,
        frame_start: le_u64(bytes, 80)?,
        frame_end_exclusive: le_u64(bytes, 88)?,
        sample_start: le_u64(bytes, 96)?,
        sample_end_exclusive: le_u64(bytes, 104)?,
        global_time_start_ns: le_u64(bytes, 112)?,
        global_time_end_exclusive_ns: le_u64(bytes, 120)?,
        channel_layout_id: le_u32(bytes, 128)?,
        channel_count: le_u16(bytes, 132)?,
        sample_format: le_u16(bytes, 134)?,
    };
    validate_envelope(&envelope, payload)?;
    Ok(DecodedRecord {
        envelope,
        payload: payload.to_vec(),
    })
}

fn validate_envelope(e: &CanonicalRecordEnvelopeV1, payload: &[u8]) -> Result<(), CodecError> {
    if e.flags & !RECORD_FLAGS_ALL != 0 {
        return Err(CodecError::UnknownFlags);
    }
    if is_zero_id(&e.run_id)
        || is_zero_id(&e.pod_id)
        || is_zero_id(&e.headstage_id)
        || e.frame_start >= e.frame_end_exclusive
        || e.sample_start >= e.sample_end_exclusive
        || e.global_time_start_ns >= e.global_time_end_exclusive_ns
        || e.channel_layout_id == 0
        || e.channel_count == 0
        || e.sample_format != 1
    {
        return Err(CodecError::Invariant);
    }
    if e.record_kind == RecordKind::SampleBlock {
        let block = SampleBlockV1::decode(payload)?;
        if block.channel_count != e.channel_count
            || block.sample_format != e.sample_format
            || block.first_sample_counter != e.sample_start
            || block.samples_per_channel as u64 != e.sample_end_exclusive - e.sample_start
        {
            return Err(CodecError::Invariant);
        }
    } else if payload.is_empty() {
        return Err(CodecError::Length);
    }
    Ok(())
}

pub fn encode_low_speed<T: WireBody>(
    flags: u16,
    request_id: u64,
    epoch: u64,
    body: &T,
) -> Result<Vec<u8>, CodecError> {
    if flags != 0 {
        return Err(CodecError::UnknownFlags);
    }
    if request_id == 0 || epoch == 0 {
        return Err(CodecError::Invariant);
    }
    let body = body.encode_body()?;
    if body.len() != T::KIND.body_len() {
        return Err(CodecError::Length);
    }
    let total_len = LOW_SPEED_HEADER_LEN
        .checked_add(body.len())
        .ok_or(CodecError::LengthLimit)?;
    if total_len > MAX_LOW_SPEED_MESSAGE_LEN {
        return Err(CodecError::LengthLimit);
    }
    let mut out = Vec::with_capacity(total_len);
    put_u32(&mut out, total_len as u32);
    out.extend_from_slice(CONTROL_MAGIC);
    put_u16(&mut out, PROTOCOL_VERSION);
    put_u16(&mut out, LOW_SPEED_HEADER_LEN as u16);
    put_u16(&mut out, T::KIND as u16);
    put_u16(&mut out, flags);
    put_u32(&mut out, body.len() as u32);
    put_u64(&mut out, request_id);
    put_u64(&mut out, epoch);
    out.extend_from_slice(&PROTOCOL_HASH);
    put_u32(&mut out, crc32c(&body));
    let header_crc = crc32c(&out);
    put_u32(&mut out, header_crc);
    debug_assert_eq!(out.len(), LOW_SPEED_HEADER_LEN);
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode_low_speed(bytes: &[u8]) -> Result<DecodedLowSpeed, CodecError> {
    if bytes.len() < LOW_SPEED_HEADER_LEN {
        return Err(CodecError::Length);
    }
    let total_len = le_u32(bytes, 0)? as usize;
    if total_len > MAX_LOW_SPEED_MESSAGE_LEN {
        return Err(CodecError::LengthLimit);
    }
    if total_len != bytes.len() {
        return Err(CodecError::Length);
    }
    if bytes.get(4..12) != Some(CONTROL_MAGIC) {
        return Err(CodecError::BadMagic);
    }
    if le_u16(bytes, 12)? != PROTOCOL_VERSION {
        return Err(CodecError::Version);
    }
    if le_u16(bytes, 14)? as usize != LOW_SPEED_HEADER_LEN {
        return Err(CodecError::Length);
    }
    let kind = MessageKind::try_from(le_u16(bytes, 16)?)?;
    let flags = le_u16(bytes, 18)?;
    if flags != 0 {
        return Err(CodecError::UnknownFlags);
    }
    let body_len = le_u32(bytes, 20)? as usize;
    if body_len != kind.body_len()
        || total_len
            != LOW_SPEED_HEADER_LEN
                .checked_add(body_len)
                .ok_or(CodecError::Length)?
    {
        return Err(CodecError::Length);
    }
    let request_id = le_u64(bytes, 24)?;
    let epoch = le_u64(bytes, 32)?;
    if request_id == 0 || epoch == 0 {
        return Err(CodecError::Invariant);
    }
    if arr32(bytes, 40)? != PROTOCOL_HASH {
        return Err(CodecError::ProtocolHash);
    }
    if le_u32(bytes, 76)? != crc32c(&bytes[..76]) {
        return Err(CodecError::HeaderCrc);
    }
    let body = &bytes[LOW_SPEED_HEADER_LEN..];
    if le_u32(bytes, 72)? != crc32c(body) {
        return Err(CodecError::BodyCrc);
    }
    check_body(body, kind.body_len())?;
    // Dispatch to the typed decoder here so reserved fields and all invariants
    // are checked even when a caller only wants the generic message.
    match kind {
        MessageKind::DeviceCapabilities => {
            DeviceCapabilitiesV1::decode_body(body)?;
        }
        MessageKind::RunCommand => {
            RunCommandV1::decode_body(body)?;
        }
        MessageKind::SafetyProfile => {
            SafetyProfileV1::decode_body(body)?;
        }
        MessageKind::StimIntent => {
            StimIntentV1::decode_body(body)?;
        }
        MessageKind::StimCommand => {
            StimCommandV1::decode_body(body)?;
        }
        MessageKind::StimReceipt => {
            StimReceiptV1::decode_body(body)?;
        }
        MessageKind::WorkerTokenLease => {
            WorkerTokenLeaseV1::decode_body(body)?;
        }
        MessageKind::Ack => {
            AckV1::decode_body(body)?;
        }
        MessageKind::Nack => {
            NackV1::decode_body(body)?;
        }
        MessageKind::ReplayRequest => {
            ReplayRequestV1::decode_body(body)?;
        }
    }
    Ok(DecodedLowSpeed {
        kind,
        flags,
        request_id,
        epoch,
        body: body.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_crc32c_vector() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn accelerated_crc_matches_portable_table_across_tail_lengths() {
        let bytes: Vec<u8> = (0..4097)
            .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
            .collect();
        for length in 0..=bytes.len() {
            assert_eq!(crc32c(&bytes[..length]), crc32c_table(&bytes[..length]));
        }
    }
}
