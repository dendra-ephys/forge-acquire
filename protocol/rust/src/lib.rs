//! Forge host-internal protocol v1.
//!
//! This crate is deliberately dependency-free and allocation-bounded at the
//! decode boundary. It is not a claim that current FPGA/D3XX firmware speaks
//! this format.

mod events;
mod hash;
mod safety;
mod types;
mod wire;

pub use events::*;
pub use hash::sha256;
pub use safety::{validate_stim_command, validate_stim_intent, SafetyError};
pub use types::*;
pub use wire::{
    crc32c, decode_low_speed, decode_record, encode_low_speed, encode_record, CodecError,
    DecodedLowSpeed, DecodedRecord,
};

pub const PROTOCOL_VERSION: u16 = 1;
pub const PROTOCOL_HASH_HEX: &str =
    "4e3db23e15a1480707132d28bdc820f36fdabbb5d20d9d84850ae89166b3efa0";
pub const PROTOCOL_HASH: Hash32 = [
    0x4e, 0x3d, 0xb2, 0x3e, 0x15, 0xa1, 0x48, 0x07, 0x07, 0x13, 0x2d, 0x28, 0xbd, 0xc8, 0x20, 0xf3,
    0x6f, 0xda, 0xbb, 0xb5, 0xd2, 0x0d, 0x9d, 0x84, 0x85, 0x0a, 0xe8, 0x91, 0x66, 0xb3, 0xef, 0xa0,
];
