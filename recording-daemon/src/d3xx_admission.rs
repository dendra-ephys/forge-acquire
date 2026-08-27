//! Exact, fail-closed admission receipt for one FT601 Receiver Pod.
//!
//! The receipt is not a device attestation or a digital signature. Trust comes
//! from two independent values supplied by protected service configuration: the
//! exact receipt-file SHA-256 and the Forge internal approval-authority hash.
//! This is not an FTDI licence, external authorization or online activation.
//! Callers cannot construct `VerifiedFt601Admission` directly.

use std::io;
use std::path::Path;

use forge_protocol_v1::{crc32c, Hash32, Id16, PROTOCOL_HASH};
use sha2::{Digest, Sha256};

pub const FT601_ADMISSION_RECEIPT_LEN: usize = 320;
pub const FT601_ADMISSION_CONTRACT_HASH_HEX: &str =
    "8a6c6fb4905466be086781f1f2aef2901b6d092524b6b3609b7a02974cbdb992";
pub const FT601_ADMISSION_CONTRACT_HASH: Hash32 = [
    0x8a, 0x6c, 0x6f, 0xb4, 0x90, 0x54, 0x66, 0xbe, 0x08, 0x67, 0x81, 0xf1, 0xf2, 0xae, 0xf2, 0x90,
    0x1b, 0x6d, 0x09, 0x25, 0x24, 0xb6, 0xb3, 0x60, 0x9b, 0x7a, 0x02, 0x97, 0x4c, 0xbd, 0xb9, 0x92,
];

pub const FT601_PROFILE_BRINGUP_66_MHZ: u32 = 0x0000_0001;
pub const FT601_PROFILE_RELEASE_100_MHZ: u32 = 0x0000_0002;

const MAGIC: &[u8; 8] = b"FGRD3A61";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ft601FifoClockProfile {
    Bringup66Mhz,
    Release100Mhz,
}

impl Ft601FifoClockProfile {
    fn from_flags(flags: u32) -> io::Result<Self> {
        match flags {
            FT601_PROFILE_BRINGUP_66_MHZ => Ok(Self::Bringup66Mhz),
            FT601_PROFILE_RELEASE_100_MHZ => Ok(Self::Release100Mhz),
            _ => Err(invalid_data(
                "FT601 admission must select exactly one FIFO clock profile",
            )),
        }
    }

    pub fn configuration_raw(self) -> u8 {
        match self {
            Self::Bringup66Mhz => 1,
            Self::Release100Mhz => 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Ft601AdmissionReceiptV1 {
    fifo_clock_profile: Ft601FifoClockProfile,
    receipt_id: Id16,
    device_id: Id16,
    serial_number: String,
    library_sha256: Hash32,
    configuration_readback_sha256: Hash32,
    usb_descriptor_sha256: Hash32,
    hardware_protocol_hash: Hash32,
    hardware_build_sha256: Hash32,
    approval_authority_hash: Hash32,
    issued_unix_ns: u64,
    expires_unix_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFt601Admission {
    receipt: Ft601AdmissionReceiptV1,
    receipt_file_sha256: Hash32,
}

impl VerifiedFt601Admission {
    pub fn load(
        path: impl AsRef<Path>,
        expected_receipt_file_sha256: Hash32,
        expected_approval_authority_hash: Hash32,
        now_unix_ns: u64,
    ) -> io::Result<Self> {
        if expected_receipt_file_sha256 == [0; 32]
            || expected_approval_authority_hash == [0; 32]
            || now_unix_ns == 0
        {
            return Err(permission_denied(
                "protected receipt hash, authority hash and current time are required",
            ));
        }
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(invalid_input(
                "FT601 admission receipt path must be absolute",
            ));
        }
        let bytes = std::fs::read(path)?;
        if bytes.len() != FT601_ADMISSION_RECEIPT_LEN {
            return Err(invalid_data("FT601 admission receipt length is invalid"));
        }
        let receipt_file_sha256: Hash32 = Sha256::digest(&bytes).into();
        if receipt_file_sha256 != expected_receipt_file_sha256 {
            return Err(permission_denied(
                "FT601 admission receipt file hash is not approved",
            ));
        }
        let receipt = decode_receipt(&bytes)?;
        if receipt.approval_authority_hash != expected_approval_authority_hash {
            return Err(permission_denied(
                "FT601 admission authority hash is not approved",
            ));
        }
        if now_unix_ns < receipt.issued_unix_ns || now_unix_ns > receipt.expires_unix_ns {
            return Err(permission_denied(
                "FT601 admission receipt is not currently valid",
            ));
        }
        Ok(Self {
            receipt,
            receipt_file_sha256,
        })
    }

    pub fn receipt_id(&self) -> Id16 {
        self.receipt.receipt_id
    }

    pub fn device_id(&self) -> Id16 {
        self.receipt.device_id
    }

    pub fn serial_number(&self) -> &str {
        &self.receipt.serial_number
    }

    pub fn library_sha256(&self) -> Hash32 {
        self.receipt.library_sha256
    }

    pub fn configuration_readback_sha256(&self) -> Hash32 {
        self.receipt.configuration_readback_sha256
    }

    pub fn usb_descriptor_sha256(&self) -> Hash32 {
        self.receipt.usb_descriptor_sha256
    }

    pub fn hardware_protocol_hash(&self) -> Hash32 {
        self.receipt.hardware_protocol_hash
    }

    pub fn hardware_build_sha256(&self) -> Hash32 {
        self.receipt.hardware_build_sha256
    }

    pub fn fifo_clock_profile(&self) -> Ft601FifoClockProfile {
        self.receipt.fifo_clock_profile
    }

    pub fn approval_authority_hash(&self) -> Hash32 {
        self.receipt.approval_authority_hash
    }

    pub fn receipt_file_sha256(&self) -> Hash32 {
        self.receipt_file_sha256
    }

    pub fn require_valid_at(&self, now_unix_ns: u64) -> io::Result<()> {
        if now_unix_ns < self.receipt.issued_unix_ns || now_unix_ns > self.receipt.expires_unix_ns {
            Err(permission_denied(
                "FT601 admission receipt is not valid at reconnect time",
            ))
        } else {
            Ok(())
        }
    }
}

fn decode_receipt(bytes: &[u8]) -> io::Result<Ft601AdmissionReceiptV1> {
    if bytes.len() != FT601_ADMISSION_RECEIPT_LEN
        || bytes.get(0..8) != Some(MAGIC)
        || le_u16(bytes, 8)? != VERSION
        || le_u16(bytes, 10)? as usize != FT601_ADMISSION_RECEIPT_LEN
        || arr32(bytes, 16)? != FT601_ADMISSION_CONTRACT_HASH
        || bytes[304..316].iter().any(|value| *value != 0)
        || le_u32(bytes, 316)? != crc32c(&bytes[..316])
    {
        return Err(invalid_data(
            "FT601 admission receipt header or CRC is invalid",
        ));
    }

    let receipt = Ft601AdmissionReceiptV1 {
        fifo_clock_profile: Ft601FifoClockProfile::from_flags(le_u32(bytes, 12)?)?,
        receipt_id: arr16(bytes, 48)?,
        device_id: arr16(bytes, 64)?,
        serial_number: decode_serial(&bytes[80..96])?,
        library_sha256: arr32(bytes, 96)?,
        configuration_readback_sha256: arr32(bytes, 128)?,
        usb_descriptor_sha256: arr32(bytes, 160)?,
        hardware_protocol_hash: arr32(bytes, 192)?,
        hardware_build_sha256: arr32(bytes, 224)?,
        approval_authority_hash: arr32(bytes, 256)?,
        issued_unix_ns: le_u64(bytes, 288)?,
        expires_unix_ns: le_u64(bytes, 296)?,
    };
    if receipt.receipt_id == [0; 16]
        || receipt.device_id == [0; 16]
        || receipt.library_sha256 == [0; 32]
        || receipt.configuration_readback_sha256 == [0; 32]
        || receipt.usb_descriptor_sha256 == [0; 32]
        || receipt.hardware_protocol_hash != PROTOCOL_HASH
        || receipt.hardware_build_sha256 == [0; 32]
        || receipt.approval_authority_hash == [0; 32]
        || receipt.issued_unix_ns == 0
        || receipt.issued_unix_ns >= receipt.expires_unix_ns
    {
        return Err(invalid_data(
            "FT601 admission receipt invariants are invalid",
        ));
    }
    Ok(receipt)
}

fn decode_serial(bytes: &[u8]) -> io::Result<String> {
    let Some(nul) = bytes.iter().position(|value| *value == 0) else {
        return Err(invalid_data("FT601 admission serial is not NUL-terminated"));
    };
    if nul == 0
        || bytes[nul..].iter().any(|value| *value != 0)
        || !bytes[..nul]
            .iter()
            .all(|value| value.is_ascii_graphic() && *value != b'\\')
    {
        return Err(invalid_data("FT601 admission serial is invalid"));
    }
    String::from_utf8(bytes[..nul].to_vec())
        .map_err(|_| invalid_data("FT601 admission serial is not ASCII"))
}

fn arr16(bytes: &[u8], offset: usize) -> io::Result<Id16> {
    bytes
        .get(offset..offset + 16)
        .ok_or_else(|| invalid_data("truncated FT601 admission receipt"))?
        .try_into()
        .map_err(|_| invalid_data("truncated FT601 admission receipt"))
}

fn arr32(bytes: &[u8], offset: usize) -> io::Result<Hash32> {
    bytes
        .get(offset..offset + 32)
        .ok_or_else(|| invalid_data("truncated FT601 admission receipt"))?
        .try_into()
        .map_err(|_| invalid_data("truncated FT601 admission receipt"))
}

fn le_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(|| invalid_data("truncated FT601 admission receipt"))?
            .try_into()
            .map_err(|_| invalid_data("truncated FT601 admission receipt"))?,
    ))
}

fn le_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(|| invalid_data("truncated FT601 admission receipt"))?
            .try_into()
            .map_err(|_| invalid_data("truncated FT601 admission receipt"))?,
    ))
}

fn le_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or_else(|| invalid_data("truncated FT601 admission receipt"))?
            .try_into()
            .map_err(|_| invalid_data("truncated FT601 admission receipt"))?,
    ))
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn permission_denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;

    fn encode_fixture() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FT601_ADMISSION_RECEIPT_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(FT601_ADMISSION_RECEIPT_LEN as u16).to_le_bytes());
        bytes.extend_from_slice(&FT601_PROFILE_BRINGUP_66_MHZ.to_le_bytes());
        bytes.extend_from_slice(&FT601_ADMISSION_CONTRACT_HASH);
        bytes.extend_from_slice(&[1; 16]);
        bytes.extend_from_slice(&[2; 16]);
        let mut serial = [0_u8; 16];
        serial[..14].copy_from_slice(b"FORGEPOD000001");
        bytes.extend_from_slice(&serial);
        bytes.extend_from_slice(&[3; 32]);
        bytes.extend_from_slice(&[4; 32]);
        bytes.extend_from_slice(&[5; 32]);
        bytes.extend_from_slice(&PROTOCOL_HASH);
        bytes.extend_from_slice(&[6; 32]);
        bytes.extend_from_slice(&[7; 32]);
        bytes.extend_from_slice(&100_u64.to_le_bytes());
        bytes.extend_from_slice(&200_u64.to_le_bytes());
        bytes.extend_from_slice(&[0; 12]);
        let checksum = crc32c(&bytes);
        bytes.extend_from_slice(&checksum.to_le_bytes());
        assert_eq!(bytes.len(), FT601_ADMISSION_RECEIPT_LEN);
        bytes
    }

    fn write_new_fixture(bytes: &[u8]) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "forge-ft601-admission-{}-{nonce}.bin",
            std::process::id(),
        ));
        let _ = std::fs::remove_file(&path);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        path
    }

    #[test]
    fn contract_hash_matches_lf_normalized_idl() {
        let source = include_bytes!("../schema/forge_ft601_admission_receipt_v1.idl");
        let normalized = String::from_utf8_lossy(source)
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(
            Sha256::digest(normalized.as_bytes()).as_slice(),
            FT601_ADMISSION_CONTRACT_HASH
        );
    }

    #[test]
    fn exact_receipt_hash_authority_time_and_protocol_are_required() {
        let bytes = encode_fixture();
        let hash: Hash32 = Sha256::digest(&bytes).into();
        let path = write_new_fixture(&bytes);
        let receipt = VerifiedFt601Admission::load(&path, hash, [7; 32], 150).unwrap();
        assert_eq!(receipt.serial_number(), "FORGEPOD000001");
        assert_eq!(receipt.device_id(), [2; 16]);
        assert_eq!(receipt.hardware_protocol_hash(), PROTOCOL_HASH);
        assert_eq!(receipt.hardware_build_sha256(), [6; 32]);
        assert_eq!(
            receipt.fifo_clock_profile(),
            Ft601FifoClockProfile::Bringup66Mhz
        );
        assert_eq!(receipt.receipt_file_sha256(), hash);
        assert!(VerifiedFt601Admission::load(&path, [0; 32], [7; 32], 150).is_err());
        assert!(VerifiedFt601Admission::load(&path, hash, [8; 32], 150).is_err());
        assert!(VerifiedFt601Admission::load(&path, hash, [7; 32], 99).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn every_mutation_and_truncation_fails_closed() {
        let original = encode_fixture();
        for length in 0..original.len() {
            assert!(decode_receipt(&original[..length]).is_err());
        }
        for index in 0..original.len() {
            let mut changed = original.clone();
            changed[index] ^= 1;
            assert!(decode_receipt(&changed).is_err());
        }
    }

    #[test]
    fn crc_valid_semantic_mutations_fail_closed() {
        fn replace_crc(bytes: &mut [u8]) {
            let checksum = crc32c(&bytes[..316]);
            bytes[316..320].copy_from_slice(&checksum.to_le_bytes());
        }

        for mutation in 0..8 {
            let mut changed = encode_fixture();
            match mutation {
                0 => changed[64..80].fill(0),
                1 => changed[80] = 0,
                2 => changed[192] ^= 1,
                3 => changed[224..256].fill(0),
                4 => changed[256..288].fill(0),
                5 => changed[296..304].copy_from_slice(&100_u64.to_le_bytes()),
                6 => changed[12..16].copy_from_slice(&0_u32.to_le_bytes()),
                _ => changed[12..16].copy_from_slice(
                    &(FT601_PROFILE_BRINGUP_66_MHZ | FT601_PROFILE_RELEASE_100_MHZ).to_le_bytes(),
                ),
            }
            replace_crc(&mut changed);
            assert!(decode_receipt(&changed).is_err());
        }
    }
}
