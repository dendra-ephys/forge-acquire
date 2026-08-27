use std::io;

use forge_protocol_v1::{crc32c, sha256, Hash32, Id16, PROTOCOL_HASH};

use crate::analysis_mapping::{validate_mapping_name, AnalysisMappingConfig};
use crate::analysis_ring::{ANALYSIS_RING_SCHEMA_HASH, ANALYSIS_RING_SLOT_HEADER_BYTES};

pub const ANALYSIS_WORKER_REQUEST_LEN: usize = 256;
pub const ANALYSIS_WORKER_RESPONSE_LEN: usize = 384;
pub const ANALYSIS_WORKER_CONTRACT_HASH_HEX: &str =
    "53b8b86e417dd12ab82d5b9ce5226e9e0e81a3b45e3ad8f9bf3f9c682d2069ca";
pub const ANALYSIS_WORKER_CONTRACT_HASH: Hash32 = [
    0x53, 0xb8, 0xb8, 0x6e, 0x41, 0x7d, 0xd1, 0x2a, 0xb8, 0x2d, 0x5b, 0x9c, 0xe5, 0x22, 0x6e, 0x9e,
    0x0e, 0x81, 0xa3, 0xb4, 0x5e, 0x3a, 0xd8, 0xf9, 0xbf, 0x3f, 0x9c, 0x68, 0x2d, 0x20, 0x69, 0xca,
];

const REQUEST_MAGIC: &[u8; 8] = b"FGANRQ01";
const RESPONSE_MAGIC: &[u8; 8] = b"FGANRS01";
const VERSION: u16 = 1;
const OP_REGISTER_OBSERVER: u16 = 1;
const ROLE_OBSERVER: u16 = 1;
const RESPONSE_ACCEPTED: u16 = 1;
const RESPONSE_REJECTED: u16 = 2;
const FLAG_LIVE_MAPPING: u32 = 1;
const FLAG_OBSERVER_ONLY: u32 = 2;
const KNOWN_FLAGS: u32 = FLAG_LIVE_MAPPING | FLAG_OBSERVER_ONLY;
const MAPPING_NAME_CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AnalysisWorkerErrorV1 {
    None = 0,
    Invalid = 1,
    Unavailable = 2,
    Conflict = 3,
    Internal = 4,
}

impl TryFrom<u16> for AnalysisWorkerErrorV1 {
    type Error = io::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Invalid),
            2 => Ok(Self::Unavailable),
            3 => Ok(Self::Conflict),
            4 => Ok(Self::Internal),
            _ => Err(invalid("unknown analysis-worker error")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisWorkerRegisterRequestV1 {
    pub request_id: u64,
    pub producer_epoch: u64,
    pub run_id: Id16,
    pub consumer_id: Id16,
    pub worker_build_hash: Hash32,
    pub slot_count: u32,
    pub payload_capacity: u32,
}

impl AnalysisWorkerRegisterRequestV1 {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = vec![0_u8; ANALYSIS_WORKER_REQUEST_LEN];
        put_u32(&mut bytes, 0, ANALYSIS_WORKER_REQUEST_LEN as u32);
        bytes[4..12].copy_from_slice(REQUEST_MAGIC);
        put_u16(&mut bytes, 12, VERSION);
        put_u16(&mut bytes, 14, ANALYSIS_WORKER_REQUEST_LEN as u16);
        put_u16(&mut bytes, 16, OP_REGISTER_OBSERVER);
        put_u16(&mut bytes, 18, ROLE_OBSERVER);
        put_u64(&mut bytes, 20, self.request_id);
        put_u64(&mut bytes, 28, self.producer_epoch);
        bytes[36..52].copy_from_slice(&self.run_id);
        bytes[52..68].copy_from_slice(&self.consumer_id);
        bytes[68..100].copy_from_slice(&self.worker_build_hash);
        put_u32(&mut bytes, 100, self.slot_count);
        put_u32(&mut bytes, 104, self.payload_capacity);
        bytes[108..140].copy_from_slice(&PROTOCOL_HASH);
        bytes[140..172].copy_from_slice(&ANALYSIS_RING_SCHEMA_HASH);
        let crc = crc32c(&bytes[..252]);
        put_u32(&mut bytes, 252, crc);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != ANALYSIS_WORKER_REQUEST_LEN
            || le_u32(bytes, 0)? as usize != ANALYSIS_WORKER_REQUEST_LEN
            || bytes.get(4..12) != Some(REQUEST_MAGIC)
            || le_u16(bytes, 12)? != VERSION
            || le_u16(bytes, 14)? as usize != ANALYSIS_WORKER_REQUEST_LEN
            || le_u16(bytes, 16)? != OP_REGISTER_OBSERVER
            || le_u16(bytes, 18)? != ROLE_OBSERVER
            || bytes.get(108..140) != Some(&PROTOCOL_HASH)
            || bytes.get(140..172) != Some(&ANALYSIS_RING_SCHEMA_HASH)
            || bytes[172..252].iter().any(|value| *value != 0)
            || le_u32(bytes, 252)? != crc32c(&bytes[..252])
        {
            return Err(invalid("invalid analysis-worker registration frame"));
        }
        let value = Self {
            request_id: le_u64(bytes, 20)?,
            producer_epoch: le_u64(bytes, 28)?,
            run_id: array(bytes, 36)?,
            consumer_id: array(bytes, 52)?,
            worker_build_hash: array(bytes, 68)?,
            slot_count: le_u32(bytes, 100)?,
            payload_capacity: le_u32(bytes, 104)?,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn exact_hash(&self) -> io::Result<Hash32> {
        Ok(sha256(&self.encode()?))
    }

    fn validate(&self) -> io::Result<()> {
        if self.request_id == 0
            || self.producer_epoch == 0
            || is_zero(&self.run_id)
            || is_zero(&self.consumer_id)
            || is_zero(&self.worker_build_hash)
        {
            return Err(invalid("invalid analysis-worker registration identity"));
        }
        AnalysisMappingConfig {
            slot_count: self.slot_count as usize,
            payload_capacity: self.payload_capacity as usize,
            run_id: self.run_id,
            consumer_id: self.consumer_id,
            producer_epoch: self.producer_epoch,
        }
        .layout()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisWorkerRegisterResponseV1 {
    pub accepted: bool,
    pub error: AnalysisWorkerErrorV1,
    pub request_id: u64,
    pub producer_epoch: u64,
    pub run_id: Id16,
    pub consumer_id: Id16,
    pub mapping_name: String,
    pub slot_count: u32,
    pub payload_capacity: u32,
    pub slot_stride: u64,
    pub total_mapping_bytes: u64,
    pub request_hash: Hash32,
    pub worker_build_hash: Hash32,
}

impl AnalysisWorkerRegisterResponseV1 {
    pub fn accepted(
        request: &AnalysisWorkerRegisterRequestV1,
        mapping_name: String,
    ) -> io::Result<Self> {
        let (slot_stride, total_mapping_bytes) = AnalysisMappingConfig {
            slot_count: request.slot_count as usize,
            payload_capacity: request.payload_capacity as usize,
            run_id: request.run_id,
            consumer_id: request.consumer_id,
            producer_epoch: request.producer_epoch,
        }
        .layout()?;
        let value = Self {
            accepted: true,
            error: AnalysisWorkerErrorV1::None,
            request_id: request.request_id,
            producer_epoch: request.producer_epoch,
            run_id: request.run_id,
            consumer_id: request.consumer_id,
            mapping_name,
            slot_count: request.slot_count,
            payload_capacity: request.payload_capacity,
            slot_stride: slot_stride as u64,
            total_mapping_bytes: total_mapping_bytes as u64,
            request_hash: request.exact_hash()?,
            worker_build_hash: request.worker_build_hash,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn rejected(
        request: &AnalysisWorkerRegisterRequestV1,
        error: AnalysisWorkerErrorV1,
    ) -> io::Result<Self> {
        if error == AnalysisWorkerErrorV1::None {
            return Err(invalid("rejected analysis response requires an error"));
        }
        let value = Self {
            accepted: false,
            error,
            request_id: request.request_id,
            producer_epoch: request.producer_epoch,
            run_id: request.run_id,
            consumer_id: request.consumer_id,
            mapping_name: String::new(),
            slot_count: 0,
            payload_capacity: 0,
            slot_stride: 0,
            total_mapping_bytes: 0,
            request_hash: request.exact_hash()?,
            worker_build_hash: request.worker_build_hash,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = vec![0_u8; ANALYSIS_WORKER_RESPONSE_LEN];
        put_u32(&mut bytes, 0, ANALYSIS_WORKER_RESPONSE_LEN as u32);
        bytes[4..12].copy_from_slice(RESPONSE_MAGIC);
        put_u16(&mut bytes, 12, VERSION);
        put_u16(&mut bytes, 14, ANALYSIS_WORKER_RESPONSE_LEN as u16);
        put_u16(
            &mut bytes,
            16,
            if self.accepted {
                RESPONSE_ACCEPTED
            } else {
                RESPONSE_REJECTED
            },
        );
        put_u16(&mut bytes, 18, self.error as u16);
        put_u64(&mut bytes, 20, self.request_id);
        put_u64(&mut bytes, 28, self.producer_epoch);
        bytes[36..52].copy_from_slice(&self.run_id);
        bytes[52..68].copy_from_slice(&self.consumer_id);
        let name = self.mapping_name.as_bytes();
        put_u16(&mut bytes, 68, name.len() as u16);
        bytes[72..72 + name.len()].copy_from_slice(name);
        put_u32(&mut bytes, 200, self.slot_count);
        put_u32(&mut bytes, 204, self.payload_capacity);
        put_u64(&mut bytes, 208, self.slot_stride);
        put_u64(&mut bytes, 216, self.total_mapping_bytes);
        bytes[224..256].copy_from_slice(&PROTOCOL_HASH);
        bytes[256..288].copy_from_slice(&ANALYSIS_RING_SCHEMA_HASH);
        bytes[288..320].copy_from_slice(&self.request_hash);
        bytes[320..352].copy_from_slice(&self.worker_build_hash);
        put_u32(&mut bytes, 352, if self.accepted { KNOWN_FLAGS } else { 0 });
        let crc = crc32c(&bytes[..380]);
        put_u32(&mut bytes, 380, crc);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != ANALYSIS_WORKER_RESPONSE_LEN
            || le_u32(bytes, 0)? as usize != ANALYSIS_WORKER_RESPONSE_LEN
            || bytes.get(4..12) != Some(RESPONSE_MAGIC)
            || le_u16(bytes, 12)? != VERSION
            || le_u16(bytes, 14)? as usize != ANALYSIS_WORKER_RESPONSE_LEN
            || le_u16(bytes, 70)? != 0
            || bytes.get(224..256) != Some(&PROTOCOL_HASH)
            || bytes.get(256..288) != Some(&ANALYSIS_RING_SCHEMA_HASH)
            || bytes[356..380].iter().any(|value| *value != 0)
            || le_u32(bytes, 380)? != crc32c(&bytes[..380])
        {
            return Err(invalid("invalid analysis-worker response frame"));
        }
        let name_len = le_u16(bytes, 68)? as usize;
        if name_len > MAPPING_NAME_CAPACITY
            || bytes[72 + name_len..200].iter().any(|value| *value != 0)
        {
            return Err(invalid("invalid analysis-worker mapping name padding"));
        }
        let mapping_name = std::str::from_utf8(&bytes[72..72 + name_len])
            .map_err(|_| invalid("analysis-worker mapping name is not ASCII"))?
            .to_owned();
        let result = le_u16(bytes, 16)?;
        let value = Self {
            accepted: result == RESPONSE_ACCEPTED,
            error: AnalysisWorkerErrorV1::try_from(le_u16(bytes, 18)?)?,
            request_id: le_u64(bytes, 20)?,
            producer_epoch: le_u64(bytes, 28)?,
            run_id: array(bytes, 36)?,
            consumer_id: array(bytes, 52)?,
            mapping_name,
            slot_count: le_u32(bytes, 200)?,
            payload_capacity: le_u32(bytes, 204)?,
            slot_stride: le_u64(bytes, 208)?,
            total_mapping_bytes: le_u64(bytes, 216)?,
            request_hash: array(bytes, 288)?,
            worker_build_hash: array(bytes, 320)?,
        };
        if !matches!(result, RESPONSE_ACCEPTED | RESPONSE_REJECTED)
            || le_u32(bytes, 352)? != if value.accepted { KNOWN_FLAGS } else { 0 }
        {
            return Err(invalid("analysis-worker result or flags are invalid"));
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> io::Result<()> {
        if self.request_id == 0
            || self.producer_epoch == 0
            || is_zero(&self.run_id)
            || is_zero(&self.consumer_id)
            || is_zero(&self.request_hash)
            || is_zero(&self.worker_build_hash)
            || self.accepted != (self.error == AnalysisWorkerErrorV1::None)
        {
            return Err(invalid("invalid analysis-worker response identity"));
        }
        if self.accepted {
            validate_mapping_name(&self.mapping_name)?;
            if !self.mapping_name.is_ascii()
                || self.mapping_name.len() > MAPPING_NAME_CAPACITY
                || self.slot_stride
                    < (ANALYSIS_RING_SLOT_HEADER_BYTES + self.payload_capacity as usize) as u64
                || !self.slot_stride.is_multiple_of(64)
            {
                return Err(invalid("invalid accepted analysis mapping geometry"));
            }
            let expected = AnalysisMappingConfig {
                slot_count: self.slot_count as usize,
                payload_capacity: self.payload_capacity as usize,
                run_id: self.run_id,
                consumer_id: self.consumer_id,
                producer_epoch: self.producer_epoch,
            }
            .layout()?;
            if (self.slot_stride, self.total_mapping_bytes)
                != (expected.0 as u64, expected.1 as u64)
            {
                return Err(invalid("analysis mapping geometry does not match request"));
            }
        } else if !self.mapping_name.is_empty()
            || self.slot_count != 0
            || self.payload_capacity != 0
            || self.slot_stride != 0
            || self.total_mapping_bytes != 0
        {
            return Err(invalid("rejected analysis response advertises a mapping"));
        }
        Ok(())
    }
}

fn is_zero<const N: usize>(value: &[u8; N]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
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

fn le_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| invalid("truncated u16"))
}

fn le_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| invalid("truncated u32"))
}

fn le_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| invalid("truncated u64"))
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| invalid("truncated fixed field"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn request() -> AnalysisWorkerRegisterRequestV1 {
        AnalysisWorkerRegisterRequestV1 {
            request_id: 11,
            producer_epoch: 7,
            run_id: [1; 16],
            consumer_id: [2; 16],
            worker_build_hash: [3; 32],
            slot_count: 4,
            payload_capacity: (forge_protocol_v1::RECORD_HEADER_LEN + 256) as u32,
        }
    }

    #[test]
    fn frozen_contract_hash_matches_lf_normalized_idl() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../workers/schema/forge_analysis_worker_ipc_v1.idl");
        let normalized = fs::read_to_string(path)
            .unwrap()
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(sha256(normalized.as_bytes()), ANALYSIS_WORKER_CONTRACT_HASH);
    }

    #[test]
    fn request_and_accepted_response_round_trip_exactly() {
        let request = request();
        let encoded = request.encode().unwrap();
        assert_eq!(
            AnalysisWorkerRegisterRequestV1::decode(&encoded).unwrap(),
            request
        );
        let response = AnalysisWorkerRegisterResponseV1::accepted(
            &request,
            r"Local\ForgeAnalysisRing-test".to_owned(),
        )
        .unwrap();
        let encoded_response = response.encode().unwrap();
        assert_eq!(
            AnalysisWorkerRegisterResponseV1::decode(&encoded_response).unwrap(),
            response
        );
    }

    #[test]
    fn truncation_mutation_and_crc_valid_reserved_data_fail_closed() {
        let encoded = request().encode().unwrap();
        for length in 0..encoded.len() {
            assert!(AnalysisWorkerRegisterRequestV1::decode(&encoded[..length]).is_err());
        }
        for offset in [0, 4, 20, 68, 108, 140, 252] {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 1;
            assert!(AnalysisWorkerRegisterRequestV1::decode(&mutated).is_err());
        }
        let mut reserved = encoded;
        reserved[180] = 1;
        let crc = crc32c(&reserved[..252]);
        put_u32(&mut reserved, 252, crc);
        assert!(AnalysisWorkerRegisterRequestV1::decode(&reserved).is_err());
    }
}
