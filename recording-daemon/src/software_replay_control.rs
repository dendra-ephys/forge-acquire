//! Host-local pause/resume control for the operator software recorder.
//!
//! This is deliberately separate from the hardware `RunCommandV1` contract.
//! A pause keeps the source/transport draining and suppresses journal writes;
//! it does not ask a Pod to stop acquisition.

use std::io;

use serde::{Deserialize, Serialize};

const REQUEST_MAGIC: &[u8; 8] = b"FGSRCTL1";
const RESPONSE_MAGIC: &[u8; 8] = b"FGSRRSP1";
pub const SOFTWARE_REPLAY_CONTROL_SCHEMA: &str = "forge.software-replay-control.v1";
pub const SOFTWARE_REPLAY_CONTROL_RESPONSE_SCHEMA: &str =
    "forge.software-replay-control-response.v1";
const MAX_CONTROL_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareReplayControlCommandV1 {
    Pause,
    Resume,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareReplayControlRequestV1 {
    pub schema: String,
    pub command: SoftwareReplayControlCommandV1,
    pub request_id: u64,
    pub epoch: u64,
    pub run_id: [u8; 16],
}

impl SoftwareReplayControlRequestV1 {
    pub fn new(
        command: SoftwareReplayControlCommandV1,
        request_id: u64,
        epoch: u64,
        run_id: [u8; 16],
    ) -> io::Result<Self> {
        let value = Self {
            schema: SOFTWARE_REPLAY_CONTROL_SCHEMA.to_owned(),
            command,
            request_id,
            epoch,
            run_id,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        encode_prefixed(REQUEST_MAGIC, self)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let value: Self = decode_prefixed(REQUEST_MAGIC, bytes)?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> io::Result<()> {
        if self.schema != SOFTWARE_REPLAY_CONTROL_SCHEMA
            || self.request_id == 0
            || self.epoch == 0
            || self.run_id == [0; 16]
        {
            return Err(invalid("software replay control request is invalid"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareReplayControlResponseV1 {
    pub schema: String,
    pub accepted: bool,
    pub paused: bool,
    pub request_id: u64,
    pub epoch: u64,
    pub discarded_record_count: u64,
    pub reason: String,
}

impl SoftwareReplayControlResponseV1 {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        encode_prefixed(RESPONSE_MAGIC, self)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let value: Self = decode_prefixed(RESPONSE_MAGIC, bytes)?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> io::Result<()> {
        if self.schema != SOFTWARE_REPLAY_CONTROL_RESPONSE_SCHEMA
            || self.request_id == 0
            || self.epoch == 0
            || self.reason.is_empty()
            || self.reason.len() > 256
        {
            return Err(invalid("software replay control response is invalid"));
        }
        Ok(())
    }
}

pub fn is_software_replay_control_request(bytes: &[u8]) -> bool {
    bytes.get(4..12) == Some(REQUEST_MAGIC)
}

#[cfg(windows)]
pub fn call_software_replay_control(
    pipe_name: &str,
    request: &SoftwareReplayControlRequestV1,
    wait_timeout_ms: u32,
    io_timeout_ms: u32,
) -> io::Result<SoftwareReplayControlResponseV1> {
    let request_bytes = request.encode()?;
    let response_bytes = crate::ipc::call_secure_pipe_bounded(
        pipe_name,
        &request_bytes,
        wait_timeout_ms,
        io_timeout_ms,
    )?;
    let response = SoftwareReplayControlResponseV1::decode(&response_bytes)?;
    if response.request_id != request.request_id || response.epoch != request.epoch {
        return Err(invalid(
            "software replay control response does not match its request",
        ));
    }
    Ok(response)
}

fn encode_prefixed<T: Serialize>(magic: &[u8; 8], value: &T) -> io::Result<Vec<u8>> {
    let json = serde_json::to_vec(value).map_err(json_error)?;
    let length = 4_usize
        .checked_add(magic.len())
        .and_then(|value| value.checked_add(json.len()))
        .ok_or_else(|| invalid("software replay control length overflow"))?;
    if length > MAX_CONTROL_BYTES {
        return Err(invalid("software replay control message is too large"));
    }
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&(length as u32).to_le_bytes());
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&json);
    Ok(bytes)
}

fn decode_prefixed<T: for<'de> Deserialize<'de>>(magic: &[u8; 8], bytes: &[u8]) -> io::Result<T> {
    if bytes.len() < 12
        || bytes.len() > MAX_CONTROL_BYTES
        || u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| invalid("software replay control length prefix is truncated"))?,
        ) as usize
            != bytes.len()
        || bytes.get(4..12) != Some(magic)
    {
        return Err(invalid("software replay control framing is invalid"));
    }
    serde_json::from_slice(&bytes[12..]).map_err(json_error)
}

fn json_error(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_response_round_trip_and_reject_wrong_magic() {
        let request = SoftwareReplayControlRequestV1::new(
            SoftwareReplayControlCommandV1::Pause,
            7,
            9,
            [0x31; 16],
        )
        .unwrap();
        let encoded = request.encode().unwrap();
        assert_eq!(
            SoftwareReplayControlRequestV1::decode(&encoded).unwrap(),
            request
        );
        let mut wrong = encoded;
        wrong[0] ^= 1;
        assert!(SoftwareReplayControlRequestV1::decode(&wrong).is_err());

        let response = SoftwareReplayControlResponseV1 {
            schema: SOFTWARE_REPLAY_CONTROL_RESPONSE_SCHEMA.to_owned(),
            accepted: true,
            paused: true,
            request_id: 7,
            epoch: 9,
            discarded_record_count: 12,
            reason: "paused".to_owned(),
        };
        assert_eq!(
            SoftwareReplayControlResponseV1::decode(&response.encode().unwrap()).unwrap(),
            response
        );
    }
}
