//! Exact, fail-closed FT600 admission receipt for one Receiver Pod.
//!
//! This deployment evidence binds a particular FT600 16-bit board/RTL build to
//! protected receipt and approval-authority hashes.  It is not a device
//! attestation, FTDI licence, timing result or release authorization.

use std::io;
use std::path::Path;

use forge_protocol_v1::{crc32c, Hash32, Id16, PROTOCOL_HASH};
use sha2::{Digest, Sha256};

pub const FT600_ADMISSION_RECEIPT_LEN: usize = 320;
pub const FT600_ADMISSION_CONTRACT_HASH_HEX: &str =
    "2505502d919b1db42fcb8d7634e942abc8bbe731ea5796987364f83c0083a2ac";
pub const FT600_ADMISSION_CONTRACT_HASH: Hash32 = [
    0x25, 0x05, 0x50, 0x2d, 0x91, 0x9b, 0x1d, 0xb4, 0x2f, 0xcb, 0x8d, 0x76, 0x34, 0xe9, 0x42, 0xab,
    0xc8, 0xbb, 0xe7, 0x31, 0xea, 0x57, 0x96, 0x98, 0x73, 0x64, 0xf8, 0x3c, 0x00, 0x83, 0xa2, 0xac,
];
pub const FT600_PROFILE_BRINGUP_66_MHZ: u32 = 1;
pub const FT600_PROFILE_RELEASE_100_MHZ: u32 = 2;

const MAGIC: &[u8; 8] = b"FGRD3A60";
const VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ft600FifoClockProfile {
    Bringup66Mhz,
    Release100Mhz,
}

impl Ft600FifoClockProfile {
    fn from_flags(flags: u32) -> io::Result<Self> {
        match flags {
            FT600_PROFILE_BRINGUP_66_MHZ => Ok(Self::Bringup66Mhz),
            FT600_PROFILE_RELEASE_100_MHZ => Ok(Self::Release100Mhz),
            _ => Err(invalid_data(
                "FT600 admission must select exactly one FIFO clock profile",
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
struct Ft600AdmissionReceiptV2 {
    fifo_clock_profile: Ft600FifoClockProfile,
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

/// A verified FT600 V2 receipt.  It has no public constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFt600Admission {
    receipt: Ft600AdmissionReceiptV2,
    receipt_file_sha256: Hash32,
}

impl VerifiedFt600Admission {
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
                "FT600 admission receipt path must be absolute",
            ));
        }
        let bytes = std::fs::read(path)?;
        if bytes.len() != FT600_ADMISSION_RECEIPT_LEN {
            return Err(invalid_data("FT600 admission receipt length is invalid"));
        }
        let receipt_file_sha256: Hash32 = Sha256::digest(&bytes).into();
        if receipt_file_sha256 != expected_receipt_file_sha256 {
            return Err(permission_denied(
                "FT600 admission receipt file hash is not approved",
            ));
        }
        let receipt = decode_receipt(&bytes)?;
        if receipt.approval_authority_hash != expected_approval_authority_hash {
            return Err(permission_denied(
                "FT600 admission authority hash is not approved",
            ));
        }
        if now_unix_ns < receipt.issued_unix_ns || now_unix_ns > receipt.expires_unix_ns {
            return Err(permission_denied(
                "FT600 admission receipt is not currently valid",
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
    pub fn fifo_clock_profile(&self) -> Ft600FifoClockProfile {
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
                "FT600 admission receipt is not valid at reconnect time",
            ))
        } else {
            Ok(())
        }
    }
}

fn decode_receipt(bytes: &[u8]) -> io::Result<Ft600AdmissionReceiptV2> {
    if bytes.len() != FT600_ADMISSION_RECEIPT_LEN
        || bytes.get(0..8) != Some(MAGIC)
        || le_u16(bytes, 8)? != VERSION
        || le_u16(bytes, 10)? as usize != FT600_ADMISSION_RECEIPT_LEN
        || arr32(bytes, 16)? != FT600_ADMISSION_CONTRACT_HASH
        || bytes[304..316].iter().any(|value| *value != 0)
        || le_u32(bytes, 316)? != crc32c(&bytes[..316])
    {
        return Err(invalid_data(
            "FT600 admission receipt header or CRC is invalid",
        ));
    }
    let receipt = Ft600AdmissionReceiptV2 {
        fifo_clock_profile: Ft600FifoClockProfile::from_flags(le_u32(bytes, 12)?)?,
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
            "FT600 admission receipt invariants are invalid",
        ));
    }
    Ok(receipt)
}

fn decode_serial(bytes: &[u8]) -> io::Result<String> {
    let Some(nul) = bytes.iter().position(|value| *value == 0) else {
        return Err(invalid_data("FT600 admission serial is not NUL-terminated"));
    };
    if nul == 0
        || bytes[nul..].iter().any(|value| *value != 0)
        || !bytes[..nul]
            .iter()
            .all(|value| value.is_ascii_graphic() && *value != b'\\')
    {
        return Err(invalid_data("FT600 admission serial is invalid"));
    }
    String::from_utf8(bytes[..nul].to_vec())
        .map_err(|_| invalid_data("FT600 admission serial is not ASCII"))
}
fn arr16(bytes: &[u8], offset: usize) -> io::Result<Id16> {
    bytes
        .get(offset..offset + 16)
        .ok_or_else(|| invalid_data("truncated FT600 admission receipt"))?
        .try_into()
        .map_err(|_| invalid_data("truncated FT600 admission receipt"))
}
fn arr32(bytes: &[u8], offset: usize) -> io::Result<Hash32> {
    bytes
        .get(offset..offset + 32)
        .ok_or_else(|| invalid_data("truncated FT600 admission receipt"))?
        .try_into()
        .map_err(|_| invalid_data("truncated FT600 admission receipt"))
}
fn le_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(|| invalid_data("truncated FT600 admission receipt"))?
            .try_into()
            .map_err(|_| invalid_data("truncated FT600 admission receipt"))?,
    ))
}
fn le_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(|| invalid_data("truncated FT600 admission receipt"))?
            .try_into()
            .map_err(|_| invalid_data("truncated FT600 admission receipt"))?,
    ))
}
fn le_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or_else(|| invalid_data("truncated FT600 admission receipt"))?
            .try_into()
            .map_err(|_| invalid_data("truncated FT600 admission receipt"))?,
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

// Source compatibility for protected deployment code during the FT600 ABI
// migration.  New code must use the FT600 names above; these aliases do not
// accept FT601 receipts because the decoder is strictly V2/FT600.
pub type VerifiedFt601Admission = VerifiedFt600Admission;
pub type Ft601FifoClockProfile = Ft600FifoClockProfile;
pub const FT601_ADMISSION_RECEIPT_LEN: usize = FT600_ADMISSION_RECEIPT_LEN;
pub const FT601_ADMISSION_CONTRACT_HASH: Hash32 = FT600_ADMISSION_CONTRACT_HASH;
pub const FT601_ADMISSION_CONTRACT_HASH_HEX: &str = FT600_ADMISSION_CONTRACT_HASH_HEX;
pub const FT601_PROFILE_BRINGUP_66_MHZ: u32 = FT600_PROFILE_BRINGUP_66_MHZ;
pub const FT601_PROFILE_RELEASE_100_MHZ: u32 = FT600_PROFILE_RELEASE_100_MHZ;

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FT600_ADMISSION_RECEIPT_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(FT600_ADMISSION_RECEIPT_LEN as u16).to_le_bytes());
        bytes.extend_from_slice(&FT600_PROFILE_RELEASE_100_MHZ.to_le_bytes());
        bytes.extend_from_slice(&FT600_ADMISSION_CONTRACT_HASH);
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
        bytes.extend_from_slice(&crc32c(&bytes).to_le_bytes());
        bytes
    }
    #[test]
    fn contract_hash_matches_lf_normalized_idl() {
        let source = include_bytes!("../schema/forge_ft600_admission_receipt_v2.idl");
        let normalized = String::from_utf8_lossy(source)
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        assert_eq!(
            Sha256::digest(normalized.as_bytes()).as_slice(),
            FT600_ADMISSION_CONTRACT_HASH
        );
    }
    #[test]
    fn v2_rejects_every_mutation() {
        let original = fixture();
        for index in 0..original.len() {
            let mut changed = original.clone();
            changed[index] ^= 1;
            assert!(decode_receipt(&changed).is_err());
        }
    }
    #[test]
    fn protected_file_hash_authority_and_validity_window_are_required() {
        let bytes = fixture();
        let hash: Hash32 = Sha256::digest(&bytes).into();
        let path = std::env::temp_dir().join(format!(
            "forge-ft600-admission-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::write(&path, &bytes).unwrap();
        let receipt = VerifiedFt600Admission::load(&path, hash, [7; 32], 150).unwrap();
        assert_eq!(receipt.hardware_build_sha256(), [6; 32]);
        assert_eq!(
            receipt.fifo_clock_profile(),
            Ft600FifoClockProfile::Release100Mhz
        );
        assert!(VerifiedFt600Admission::load(&path, [0; 32], [7; 32], 150).is_err());
        assert!(VerifiedFt600Admission::load(&path, hash, [8; 32], 150).is_err());
        assert!(VerifiedFt600Admission::load(&path, hash, [7; 32], 99).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
