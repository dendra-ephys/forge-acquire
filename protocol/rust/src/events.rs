//! Self-hashed event payload extension for canonical protocol-v1 records.
//!
//! This companion contract does not change `PROTOCOL_HASH`. Each payload
//! embeds `EVENT_PAYLOAD_HASH`, so an outer CRC-valid record is still rejected
//! when its event semantics are missing, stale, or contradictory.

use std::fmt;

use crate::{is_zero_hash, is_zero_id, Hash32, Id16};

pub const EVENT_PAYLOAD_MAGIC: &[u8; 8] = b"FGREVT01";
pub const EVENT_PAYLOAD_VERSION: u16 = 1;
pub const EVENT_PAYLOAD_COMMON_HEADER_LEN: usize = 80;
pub const EVENT_PAYLOAD_MAX_BODY_LEN: usize = 65_536;
pub const EVENT_PAYLOAD_HASH_HEX: &str =
    "68ad1bf0c16c57ddcad79cc8e5a950513d8e54a2c874cbe4b56cea054b7dd6d8";
pub const EVENT_PAYLOAD_HASH: Hash32 = [
    0x68, 0xad, 0x1b, 0xf0, 0xc1, 0x6c, 0x57, 0xdd, 0xca, 0xd7, 0x9c, 0xc8, 0xe5, 0xa9, 0x50, 0x51,
    0x3d, 0x8e, 0x54, 0xa2, 0xc8, 0x74, 0xcb, 0xe4, 0xb5, 0x6c, 0xea, 0x05, 0x4b, 0x7d, 0xd6, 0xd8,
];

pub const MARKER_FLAG_OPERATOR: u32 = 1;
pub const MARKER_FLAG_EXTERNAL: u32 = 2;
pub const EVENT_FAULT_FLAG_RUN_LATCHED: u32 = 1;
pub const EVENT_FAULT_FLAG_STIM_DISARMING: u32 = 2;
pub const ANALYSIS_FLAG_REFERENCE_ONLY: u32 = 1;
pub const ANALYSIS_FLAG_CONTROLLER_CANDIDATE: u32 = 2;
pub const ANALYSIS_CHANNEL_NONE: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventPayloadError {
    Length,
    LengthLimit,
    BadMagic,
    Version,
    UnknownKind,
    UnknownEnum,
    UnknownFlags,
    Reserved,
    ContractHash,
    Identity,
    Utf8,
    Invariant,
}

impl fmt::Display for EventPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for EventPayloadError {}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventPayloadKind {
    Marker = 1,
    Fault = 2,
    Gap = 3,
    OnlineAnalysis = 4,
}

impl TryFrom<u16> for EventPayloadKind {
    type Error = EventPayloadError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Marker),
            2 => Ok(Self::Fault),
            3 => Ok(Self::Gap),
            4 => Ok(Self::OnlineAnalysis),
            _ => Err(EventPayloadError::UnknownKind),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultSeverity {
    Info = 1,
    Warning = 2,
    ErrorLevel = 3,
    Fatal = 4,
}

impl TryFrom<u8> for FaultSeverity {
    type Error = EventPayloadError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Info),
            2 => Ok(Self::Warning),
            3 => Ok(Self::ErrorLevel),
            4 => Ok(Self::Fatal),
            _ => Err(EventPayloadError::UnknownEnum),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultLayer {
    ReceiverCapture = 1,
    PodFt600 = 2,
    D3xxHost = 3,
    AggregatorRing = 4,
    NetworkSocket = 5,
    RecordWriter = 6,
    AnalysisWorker = 7,
    Materializer = 8,
    Synchronization = 9,
    Stimulation = 10,
}

impl TryFrom<u8> for FaultLayer {
    type Error = EventPayloadError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ReceiverCapture),
            2 => Ok(Self::PodFt600),
            3 => Ok(Self::D3xxHost),
            4 => Ok(Self::AggregatorRing),
            5 => Ok(Self::NetworkSocket),
            6 => Ok(Self::RecordWriter),
            7 => Ok(Self::AnalysisWorker),
            8 => Ok(Self::Materializer),
            9 => Ok(Self::Synchronization),
            10 => Ok(Self::Stimulation),
            _ => Err(EventPayloadError::UnknownEnum),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultCode {
    SourceCrc = 1,
    CounterGap = 2,
    CaptureOverflow = 3,
    Ft600Backpressure = 4,
    D3xxQueue = 5,
    AggregatorOverflow = 6,
    SocketDrop = 7,
    WriterIo = 8,
    SyncLost = 9,
    AnalysisDrop = 10,
    MaterializerFailure = 11,
    DeadlineMiss = 12,
    ReceiptContradiction = 13,
    ComplianceFault = 14,
    InterlockFault = 15,
    TransportDisconnect = 16,
}

impl TryFrom<u16> for FaultCode {
    type Error = EventPayloadError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SourceCrc),
            2 => Ok(Self::CounterGap),
            3 => Ok(Self::CaptureOverflow),
            4 => Ok(Self::Ft600Backpressure),
            5 => Ok(Self::D3xxQueue),
            6 => Ok(Self::AggregatorOverflow),
            7 => Ok(Self::SocketDrop),
            8 => Ok(Self::WriterIo),
            9 => Ok(Self::SyncLost),
            10 => Ok(Self::AnalysisDrop),
            11 => Ok(Self::MaterializerFailure),
            12 => Ok(Self::DeadlineMiss),
            13 => Ok(Self::ReceiptContradiction),
            14 => Ok(Self::ComplianceFault),
            15 => Ok(Self::InterlockFault),
            16 => Ok(Self::TransportDisconnect),
            _ => Err(EventPayloadError::UnknownEnum),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapReason {
    SourceCrc = 1,
    CounterDiscontinuity = 2,
    CaptureOverflow = 3,
    TransportDisconnect = 4,
    ReplayUnavailable = 5,
    ClockLoss = 6,
}

impl TryFrom<u16> for GapReason {
    type Error = EventPayloadError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SourceCrc),
            2 => Ok(Self::CounterDiscontinuity),
            3 => Ok(Self::CaptureOverflow),
            4 => Ok(Self::TransportDisconnect),
            5 => Ok(Self::ReplayUnavailable),
            6 => Ok(Self::ClockLoss),
            _ => Err(EventPayloadError::UnknownEnum),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerPayloadV1 {
    pub event_id: Id16,
    pub marker_sequence: u64,
    pub marker_flags: u32,
    pub label: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultPayloadV1 {
    pub event_id: Id16,
    pub fault_code: FaultCode,
    pub severity: FaultSeverity,
    pub layer: FaultLayer,
    pub fault_flags: u32,
    pub occurrence_count: u64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapPayloadV1 {
    pub event_id: Id16,
    pub reason: GapReason,
    pub layer: FaultLayer,
    pub gap_flags: u32,
    pub missing_record_count: u64,
    pub missing_frame_count: u64,
    pub missing_sample_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlineAnalysisPayloadV1 {
    pub event_id: Id16,
    pub worker_id: Id16,
    pub worker_build_hash: Hash32,
    pub algorithm_hash: Hash32,
    pub config_hash: Hash32,
    pub result_schema_hash: Hash32,
    pub source_record_sequence: u64,
    pub channel_id: u32,
    pub analysis_flags: u32,
    pub result: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedEventPayload {
    Marker(MarkerPayloadV1),
    Fault(FaultPayloadV1),
    Gap(GapPayloadV1),
    OnlineAnalysis(OnlineAnalysisPayloadV1),
}

impl MarkerPayloadV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EventPayloadError> {
        let label = checked_utf8(&self.label, 1, 256)?;
        let note = checked_utf8(&self.note, 0, 2_048)?;
        if self.marker_flags != MARKER_FLAG_OPERATOR && self.marker_flags != MARKER_FLAG_EXTERNAL {
            return Err(EventPayloadError::UnknownFlags);
        }
        let mut out = event_header(
            EventPayloadKind::Marker,
            104,
            label.len() + note.len(),
            self.event_id,
        )?;
        put_u64(&mut out, self.marker_sequence);
        put_u16(&mut out, label.len() as u16);
        put_u16(&mut out, note.len() as u16);
        put_u32(&mut out, self.marker_flags);
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(label);
        out.extend_from_slice(note);
        Ok(out)
    }
}

impl FaultPayloadV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EventPayloadError> {
        let detail = checked_utf8(&self.detail, 0, 2_048)?;
        if self.fault_flags & !(EVENT_FAULT_FLAG_RUN_LATCHED | EVENT_FAULT_FLAG_STIM_DISARMING) != 0
        {
            return Err(EventPayloadError::UnknownFlags);
        }
        if self.occurrence_count == 0 {
            return Err(EventPayloadError::Invariant);
        }
        let mut out = event_header(EventPayloadKind::Fault, 104, detail.len(), self.event_id)?;
        put_u16(&mut out, self.fault_code as u16);
        out.push(self.severity as u8);
        out.push(self.layer as u8);
        put_u32(&mut out, self.fault_flags);
        put_u64(&mut out, self.occurrence_count);
        put_u16(&mut out, detail.len() as u16);
        out.extend_from_slice(&[0; 6]);
        out.extend_from_slice(detail);
        Ok(out)
    }
}

impl GapPayloadV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EventPayloadError> {
        if self.gap_flags & !(EVENT_FAULT_FLAG_RUN_LATCHED | EVENT_FAULT_FLAG_STIM_DISARMING) != 0 {
            return Err(EventPayloadError::UnknownFlags);
        }
        if self.missing_record_count == 0
            && self.missing_frame_count == 0
            && self.missing_sample_count == 0
        {
            return Err(EventPayloadError::Invariant);
        }
        let mut out = event_header(EventPayloadKind::Gap, 112, 0, self.event_id)?;
        put_u16(&mut out, self.reason as u16);
        out.push(self.layer as u8);
        out.push(0);
        put_u32(&mut out, self.gap_flags);
        put_u64(&mut out, self.missing_record_count);
        put_u64(&mut out, self.missing_frame_count);
        put_u64(&mut out, self.missing_sample_count);
        Ok(out)
    }
}

impl OnlineAnalysisPayloadV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EventPayloadError> {
        if is_zero_id(&self.worker_id)
            || is_zero_hash(&self.worker_build_hash)
            || is_zero_hash(&self.algorithm_hash)
            || is_zero_hash(&self.config_hash)
            || is_zero_hash(&self.result_schema_hash)
        {
            return Err(EventPayloadError::Identity);
        }
        if self.result.is_empty()
            || self.result.len() > 4_096
            || self.result.contains(&0)
            || std::str::from_utf8(&self.result).is_err()
        {
            return Err(EventPayloadError::LengthLimit);
        }
        if self.analysis_flags
            & !(ANALYSIS_FLAG_REFERENCE_ONLY | ANALYSIS_FLAG_CONTROLLER_CANDIDATE)
            != 0
        {
            return Err(EventPayloadError::UnknownFlags);
        }
        let mut out = event_header(
            EventPayloadKind::OnlineAnalysis,
            248,
            self.result.len(),
            self.event_id,
        )?;
        out.extend_from_slice(&self.worker_id);
        out.extend_from_slice(&self.worker_build_hash);
        out.extend_from_slice(&self.algorithm_hash);
        out.extend_from_slice(&self.config_hash);
        out.extend_from_slice(&self.result_schema_hash);
        put_u64(&mut out, self.source_record_sequence);
        put_u32(&mut out, self.channel_id);
        put_u32(&mut out, self.analysis_flags);
        put_u32(&mut out, self.result.len() as u32);
        put_u32(&mut out, 0);
        out.extend_from_slice(&self.result);
        Ok(out)
    }
}

pub fn decode_event_payload(bytes: &[u8]) -> Result<DecodedEventPayload, EventPayloadError> {
    if bytes.len() < EVENT_PAYLOAD_COMMON_HEADER_LEN {
        return Err(EventPayloadError::Length);
    }
    if &bytes[..8] != EVENT_PAYLOAD_MAGIC {
        return Err(EventPayloadError::BadMagic);
    }
    if le_u16(bytes, 8)? != EVENT_PAYLOAD_VERSION {
        return Err(EventPayloadError::Version);
    }
    let kind = EventPayloadKind::try_from(le_u16(bytes, 10)?)?;
    let header_len = le_u16(bytes, 12)? as usize;
    if le_u16(bytes, 14)? != 0 || bytes[72..80].iter().any(|byte| *byte != 0) {
        return Err(EventPayloadError::Reserved);
    }
    let total_len = le_u32(bytes, 16)? as usize;
    let body_len = le_u32(bytes, 20)? as usize;
    if total_len != bytes.len()
        || body_len > EVENT_PAYLOAD_MAX_BODY_LEN
        || header_len.checked_add(body_len) != Some(total_len)
    {
        return Err(EventPayloadError::Length);
    }
    if bytes[24..56] != EVENT_PAYLOAD_HASH {
        return Err(EventPayloadError::ContractHash);
    }
    let event_id: Id16 = bytes[56..72]
        .try_into()
        .map_err(|_| EventPayloadError::Length)?;
    if is_zero_id(&event_id) {
        return Err(EventPayloadError::Identity);
    }

    match kind {
        EventPayloadKind::Marker => decode_marker(bytes, header_len, body_len, event_id),
        EventPayloadKind::Fault => decode_fault(bytes, header_len, body_len, event_id),
        EventPayloadKind::Gap => decode_gap(bytes, header_len, body_len, event_id),
        EventPayloadKind::OnlineAnalysis => decode_analysis(bytes, header_len, body_len, event_id),
    }
}

fn decode_marker(
    bytes: &[u8],
    header_len: usize,
    body_len: usize,
    event_id: Id16,
) -> Result<DecodedEventPayload, EventPayloadError> {
    if header_len != 104 || bytes[96..104].iter().any(|byte| *byte != 0) {
        return Err(EventPayloadError::Reserved);
    }
    let label_len = le_u16(bytes, 88)? as usize;
    let note_len = le_u16(bytes, 90)? as usize;
    let marker_flags = le_u32(bytes, 92)?;
    if !(1..=256).contains(&label_len)
        || note_len > 2_048
        || label_len.checked_add(note_len) != Some(body_len)
        || (marker_flags != MARKER_FLAG_OPERATOR && marker_flags != MARKER_FLAG_EXTERNAL)
    {
        return Err(EventPayloadError::Invariant);
    }
    let label = decode_text(&bytes[104..104 + label_len])?;
    let note = decode_text(&bytes[104 + label_len..])?;
    Ok(DecodedEventPayload::Marker(MarkerPayloadV1 {
        event_id,
        marker_sequence: le_u64(bytes, 80)?,
        marker_flags,
        label,
        note,
    }))
}

fn decode_fault(
    bytes: &[u8],
    header_len: usize,
    body_len: usize,
    event_id: Id16,
) -> Result<DecodedEventPayload, EventPayloadError> {
    if header_len != 104 || bytes[98..104].iter().any(|byte| *byte != 0) {
        return Err(EventPayloadError::Reserved);
    }
    let fault_flags = le_u32(bytes, 84)?;
    let occurrence_count = le_u64(bytes, 88)?;
    let detail_len = le_u16(bytes, 96)? as usize;
    if fault_flags & !(EVENT_FAULT_FLAG_RUN_LATCHED | EVENT_FAULT_FLAG_STIM_DISARMING) != 0 {
        return Err(EventPayloadError::UnknownFlags);
    }
    if occurrence_count == 0 || detail_len != body_len || detail_len > 2_048 {
        return Err(EventPayloadError::Invariant);
    }
    Ok(DecodedEventPayload::Fault(FaultPayloadV1 {
        event_id,
        fault_code: FaultCode::try_from(le_u16(bytes, 80)?)?,
        severity: FaultSeverity::try_from(bytes[82])?,
        layer: FaultLayer::try_from(bytes[83])?,
        fault_flags,
        occurrence_count,
        detail: decode_text(&bytes[104..])?,
    }))
}

fn decode_gap(
    bytes: &[u8],
    header_len: usize,
    body_len: usize,
    event_id: Id16,
) -> Result<DecodedEventPayload, EventPayloadError> {
    if header_len != 112 || body_len != 0 || bytes[83] != 0 {
        return Err(EventPayloadError::Reserved);
    }
    let gap_flags = le_u32(bytes, 84)?;
    let missing_record_count = le_u64(bytes, 88)?;
    let missing_frame_count = le_u64(bytes, 96)?;
    let missing_sample_count = le_u64(bytes, 104)?;
    if gap_flags & !(EVENT_FAULT_FLAG_RUN_LATCHED | EVENT_FAULT_FLAG_STIM_DISARMING) != 0 {
        return Err(EventPayloadError::UnknownFlags);
    }
    if missing_record_count == 0 && missing_frame_count == 0 && missing_sample_count == 0 {
        return Err(EventPayloadError::Invariant);
    }
    Ok(DecodedEventPayload::Gap(GapPayloadV1 {
        event_id,
        reason: GapReason::try_from(le_u16(bytes, 80)?)?,
        layer: FaultLayer::try_from(bytes[82])?,
        gap_flags,
        missing_record_count,
        missing_frame_count,
        missing_sample_count,
    }))
}

fn decode_analysis(
    bytes: &[u8],
    header_len: usize,
    body_len: usize,
    event_id: Id16,
) -> Result<DecodedEventPayload, EventPayloadError> {
    if header_len != 248 || le_u32(bytes, 244)? != 0 {
        return Err(EventPayloadError::Reserved);
    }
    let worker_id = array(bytes, 80)?;
    let worker_build_hash = array(bytes, 96)?;
    let algorithm_hash = array(bytes, 128)?;
    let config_hash = array(bytes, 160)?;
    let result_schema_hash = array(bytes, 192)?;
    if is_zero_id(&worker_id)
        || is_zero_hash(&worker_build_hash)
        || is_zero_hash(&algorithm_hash)
        || is_zero_hash(&config_hash)
        || is_zero_hash(&result_schema_hash)
    {
        return Err(EventPayloadError::Identity);
    }
    let analysis_flags = le_u32(bytes, 236)?;
    if analysis_flags & !(ANALYSIS_FLAG_REFERENCE_ONLY | ANALYSIS_FLAG_CONTROLLER_CANDIDATE) != 0 {
        return Err(EventPayloadError::UnknownFlags);
    }
    if body_len == 0
        || body_len > 4_096
        || le_u32(bytes, 240)? as usize != body_len
        || bytes[248..].contains(&0)
        || std::str::from_utf8(&bytes[248..]).is_err()
    {
        return Err(EventPayloadError::Invariant);
    }
    Ok(DecodedEventPayload::OnlineAnalysis(
        OnlineAnalysisPayloadV1 {
            event_id,
            worker_id,
            worker_build_hash,
            algorithm_hash,
            config_hash,
            result_schema_hash,
            source_record_sequence: le_u64(bytes, 224)?,
            channel_id: le_u32(bytes, 232)?,
            analysis_flags,
            result: bytes[248..].to_vec(),
        },
    ))
}

fn event_header(
    kind: EventPayloadKind,
    header_len: usize,
    body_len: usize,
    event_id: Id16,
) -> Result<Vec<u8>, EventPayloadError> {
    if is_zero_id(&event_id) {
        return Err(EventPayloadError::Identity);
    }
    if body_len > EVENT_PAYLOAD_MAX_BODY_LEN {
        return Err(EventPayloadError::LengthLimit);
    }
    let total_len = header_len
        .checked_add(body_len)
        .ok_or(EventPayloadError::LengthLimit)?;
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(EVENT_PAYLOAD_MAGIC);
    put_u16(&mut out, EVENT_PAYLOAD_VERSION);
    put_u16(&mut out, kind as u16);
    put_u16(&mut out, header_len as u16);
    put_u16(&mut out, 0);
    put_u32(&mut out, total_len as u32);
    put_u32(&mut out, body_len as u32);
    out.extend_from_slice(&EVENT_PAYLOAD_HASH);
    out.extend_from_slice(&event_id);
    out.extend_from_slice(&[0; 8]);
    Ok(out)
}

fn checked_utf8(text: &str, minimum: usize, maximum: usize) -> Result<&[u8], EventPayloadError> {
    let bytes = text.as_bytes();
    if !(minimum..=maximum).contains(&bytes.len()) || bytes.contains(&0) {
        return Err(EventPayloadError::Invariant);
    }
    Ok(bytes)
}

fn decode_text(bytes: &[u8]) -> Result<String, EventPayloadError> {
    if bytes.contains(&0) {
        return Err(EventPayloadError::Utf8);
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| EventPayloadError::Utf8)
}

fn array<const SIZE: usize>(bytes: &[u8], offset: usize) -> Result<[u8; SIZE], EventPayloadError> {
    bytes
        .get(offset..offset + SIZE)
        .ok_or(EventPayloadError::Length)?
        .try_into()
        .map_err(|_| EventPayloadError::Length)
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, EventPayloadError> {
    Ok(u16::from_le_bytes(array(bytes, offset)?))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, EventPayloadError> {
    Ok(u32::from_le_bytes(array(bytes, offset)?))
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64, EventPayloadError> {
    Ok(u64::from_le_bytes(array(bytes, offset)?))
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_hash_matches_lf_normalized_idl() {
        let normalized = include_str!("../../schema/forge_event_payload_v1.idl")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(crate::sha256(normalized.as_bytes()), EVENT_PAYLOAD_HASH);
    }

    #[test]
    fn all_event_payloads_round_trip() {
        let payloads = [
            MarkerPayloadV1 {
                event_id: [1; 16],
                marker_sequence: 7,
                marker_flags: MARKER_FLAG_OPERATOR,
                label: "baseline".into(),
                note: "awake".into(),
            }
            .encode()
            .unwrap(),
            FaultPayloadV1 {
                event_id: [2; 16],
                fault_code: FaultCode::AnalysisDrop,
                severity: FaultSeverity::ErrorLevel,
                layer: FaultLayer::AnalysisWorker,
                fault_flags: EVENT_FAULT_FLAG_RUN_LATCHED | EVENT_FAULT_FLAG_STIM_DISARMING,
                occurrence_count: 1,
                detail: "consumer ring full".into(),
            }
            .encode()
            .unwrap(),
            GapPayloadV1 {
                event_id: [3; 16],
                reason: GapReason::CounterDiscontinuity,
                layer: FaultLayer::ReceiverCapture,
                gap_flags: EVENT_FAULT_FLAG_RUN_LATCHED | EVENT_FAULT_FLAG_STIM_DISARMING,
                missing_record_count: 1,
                missing_frame_count: 1,
                missing_sample_count: 30,
            }
            .encode()
            .unwrap(),
            OnlineAnalysisPayloadV1 {
                event_id: [4; 16],
                worker_id: [5; 16],
                worker_build_hash: [6; 32],
                algorithm_hash: [7; 32],
                config_hash: [8; 32],
                result_schema_hash: [9; 32],
                source_record_sequence: 11,
                channel_id: 2,
                analysis_flags: ANALYSIS_FLAG_REFERENCE_ONLY,
                result: br#"{"score":1}"#.to_vec(),
            }
            .encode()
            .unwrap(),
        ];
        for payload in payloads {
            assert!(decode_event_payload(&payload).is_ok());
            for length in 0..payload.len() {
                assert!(decode_event_payload(&payload[..length]).is_err());
            }
        }
    }

    #[test]
    fn contract_hash_reserved_flags_and_utf8_fail_closed() {
        let mut marker = MarkerPayloadV1 {
            event_id: [1; 16],
            marker_sequence: 0,
            marker_flags: MARKER_FLAG_OPERATOR,
            label: "x".into(),
            note: String::new(),
        }
        .encode()
        .unwrap();
        marker[24] ^= 1;
        assert_eq!(
            decode_event_payload(&marker),
            Err(EventPayloadError::ContractHash)
        );
        marker[24] ^= 1;
        marker[92] = 4;
        assert_eq!(
            decode_event_payload(&marker),
            Err(EventPayloadError::Invariant)
        );
        marker[92] = 1;
        marker[104] = 0xff;
        assert_eq!(decode_event_payload(&marker), Err(EventPayloadError::Utf8));
    }
}
