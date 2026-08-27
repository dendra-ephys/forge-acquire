//! Protected Windows named mapping for one live ForgeAnalysisRingV1 branch.
//!
//! The acquisition service is the sole producer and each authenticated worker
//! receives a distinct mapping. The mapping is pagefile-backed, local-session
//! scoped, non-inheritable, first-instance-only, and protected by an explicit
//! DACL. It never contains a second sample format: every slot carries one
//! complete canonical SampleBlock record.

use std::ffi::c_void;
use std::fmt;
use std::io;
use std::mem::{size_of, zeroed};
use std::ptr::{null_mut, NonNull};
use std::sync::atomic::{AtomicU64, Ordering};

use forge_protocol_v1::{
    crc32c, decode_record, Id16, RecordKind, MAX_RECORD_PAYLOAD_LEN, PROTOCOL_HASH,
    RECORD_HEADER_LEN,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, VirtualQuery,
    FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS,
    PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

use crate::analysis_ring::{
    AnalysisRingError, ConsumedAnalysisRecord, ANALYSIS_RING_HEADER_BYTES, ANALYSIS_RING_MAGIC,
    ANALYSIS_RING_SLOT_HEADER_BYTES, ANALYSIS_RING_VERSION,
};
use crate::ipc::{canonical_sid_string, token_has_sid};

const MIN_SLOT_COUNT: usize = 2;
const MAX_SLOT_COUNT: usize = 65_536;
const MAX_MAPPING_BYTES: usize = 1024 * 1024 * 1024;
const EMPTY_SLOT: u64 = u64::MAX;
const FAULT_RING_FULL: u64 = 1;
const FAULT_CONTRADICTION: u64 = 2;
const KNOWN_FAULT_FLAGS: u64 = FAULT_RING_FULL | FAULT_CONTRADICTION;

const PUBLISHED_OFFSET: usize = 128;
const CONSUMED_OFFSET: usize = 136;
const DROPPED_OFFSET: usize = 144;
const PRODUCER_HEARTBEAT_OFFSET: usize = 152;
const CONSUMER_HEARTBEAT_OFFSET: usize = 160;
const FAULT_FLAGS_OFFSET: usize = 168;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisMappingConfig {
    pub slot_count: usize,
    pub payload_capacity: usize,
    pub run_id: Id16,
    pub consumer_id: Id16,
    pub producer_epoch: u64,
}

impl AnalysisMappingConfig {
    pub(crate) fn layout(self) -> io::Result<(usize, usize)> {
        if !(MIN_SLOT_COUNT..=MAX_SLOT_COUNT).contains(&self.slot_count)
            || !(RECORD_HEADER_LEN..=RECORD_HEADER_LEN + MAX_RECORD_PAYLOAD_LEN)
                .contains(&self.payload_capacity)
            || self.run_id == [0; 16]
            || self.consumer_id == [0; 16]
            || self.producer_epoch == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid analysis mapping configuration",
            ));
        }
        let slot_stride = align64(
            ANALYSIS_RING_SLOT_HEADER_BYTES
                .checked_add(self.payload_capacity)
                .ok_or_else(mapping_too_large)?,
        )
        .ok_or_else(mapping_too_large)?;
        let total_bytes = ANALYSIS_RING_HEADER_BYTES
            .checked_add(
                self.slot_count
                    .checked_mul(slot_stride)
                    .ok_or_else(mapping_too_large)?,
            )
            .ok_or_else(mapping_too_large)?;
        if total_bytes > MAX_MAPPING_BYTES {
            return Err(mapping_too_large());
        }
        Ok((slot_stride, total_bytes))
    }
}

pub struct MappedAnalysisRing {
    _handle: OwnedHandle,
    view: OwnedView,
    total_bytes: usize,
    slot_count: usize,
    payload_capacity: usize,
    slot_stride: usize,
    run_id: Id16,
    consumer_id: Id16,
    producer_epoch: u64,
}

// The view and kernel handle are exclusively owned by this value. Moving the
// producer to the replay worker thread does not create another Rust alias;
// external consumers use independent MapViewOfFile views and the frozen atomic
// protocol.
unsafe impl Send for MappedAnalysisRing {}

impl fmt::Debug for MappedAnalysisRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MappedAnalysisRing")
            .field("total_bytes", &self.total_bytes)
            .field("slot_count", &self.slot_count)
            .field("payload_capacity", &self.payload_capacity)
            .field("slot_stride", &self.slot_stride)
            .field("run_id", &self.run_id)
            .field("consumer_id", &self.consumer_id)
            .field("producer_epoch", &self.producer_epoch)
            .finish_non_exhaustive()
    }
}

impl MappedAnalysisRing {
    /// Production creator. The service SID must be enabled in this process
    /// token; merely supplying an SDDL identity is insufficient.
    pub fn create_service(
        mapping_name: &str,
        service_sid: &str,
        worker_sid: &str,
        config: AnalysisMappingConfig,
    ) -> io::Result<Self> {
        let service_sid = canonical_sid_string(service_sid)?;
        if !token_has_sid(&service_sid)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "analysis mapping service SID is not enabled in the current token",
            ));
        }
        let worker_sid = canonical_sid_string(worker_sid)?;
        Self::create_with_sids(mapping_name, &service_sid, &worker_sid, config)
    }

    /// Test-only creator using the interactive test identity for both roles.
    #[cfg(test)]
    pub(crate) fn create_test(
        mapping_name: &str,
        current_sid: &str,
        config: AnalysisMappingConfig,
    ) -> io::Result<Self> {
        let sid = canonical_sid_string(current_sid)?;
        Self::create_with_sids(mapping_name, &sid, &sid, config)
    }

    #[cfg(test)]
    fn create_worker_only_test(
        mapping_name: &str,
        worker_sid: &str,
        config: AnalysisMappingConfig,
    ) -> io::Result<Self> {
        let worker_sid = canonical_sid_string(worker_sid)?;
        Self::create_with_sids(mapping_name, "SY", &worker_sid, config)
    }

    fn create_with_sids(
        mapping_name: &str,
        owner_sid: &str,
        worker_sid: &str,
        config: AnalysisMappingConfig,
    ) -> io::Result<Self> {
        validate_mapping_name(mapping_name)?;
        let (slot_stride, total_bytes) = config.layout()?;
        let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;{owner_sid})(A;;GRGW;;;{worker_sid})");
        let descriptor = SecurityDescriptor::from_sddl(&sddl)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let name = wide(mapping_name);
        let size = total_bytes as u64;
        let raw_handle = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                &attributes,
                PAGE_READWRITE,
                (size >> 32) as u32,
                size as u32,
                name.as_ptr(),
            )
        };
        let handle = OwnedHandle::new(raw_handle)?;
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "analysis mapping name is already owned",
            ));
        }
        let view = OwnedView::map(handle.0, total_bytes)?;
        let mut ring = Self {
            _handle: handle,
            view,
            total_bytes,
            slot_count: config.slot_count,
            payload_capacity: config.payload_capacity,
            slot_stride,
            run_id: config.run_id,
            consumer_id: config.consumer_id,
            producer_epoch: config.producer_epoch,
        };
        ring.bytes_mut().fill(0);
        ring.initialize_header(config.consumer_id, config.producer_epoch);
        for index in 0..config.slot_count {
            ring.atomic_store(ring.slot_offset(index), EMPTY_SLOT, Ordering::Relaxed);
        }
        Ok(ring)
    }

    /// Opens an existing mapping. The kernel DACL authenticates access; the
    /// immutable identities are then checked before any mutable field is used.
    pub fn open(
        mapping_name: &str,
        expected_run_id: Id16,
        expected_consumer_id: Id16,
        expected_producer_epoch: u64,
    ) -> io::Result<Self> {
        validate_mapping_name(mapping_name)?;
        if expected_run_id == [0; 16]
            || expected_consumer_id == [0; 16]
            || expected_producer_epoch == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected analysis mapping identity is invalid",
            ));
        }
        let name = wide(mapping_name);
        let handle = OwnedHandle::new(unsafe {
            OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, 0, name.as_ptr())
        })?;
        let view = OwnedView::map(handle.0, 0)?;
        let region_bytes = view.region_bytes()?;
        if region_bytes < ANALYSIS_RING_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "analysis mapping is smaller than its global header",
            ));
        }
        let header = unsafe {
            std::slice::from_raw_parts(view.0.as_ptr().cast_const(), ANALYSIS_RING_HEADER_BYTES)
        };
        let (slot_count, payload_capacity, slot_stride, total_bytes) = validate_header(
            header,
            expected_run_id,
            expected_consumer_id,
            expected_producer_epoch,
        )?;
        if total_bytes > region_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "analysis mapping header exceeds the mapped region",
            ));
        }
        Ok(Self {
            _handle: handle,
            view,
            total_bytes,
            slot_count,
            payload_capacity,
            slot_stride,
            run_id: expected_run_id,
            consumer_id: expected_consumer_id,
            producer_epoch: expected_producer_epoch,
        })
    }

    pub fn try_publish(
        &mut self,
        encoded_record: &[u8],
        journal_sequence: u64,
        producer_heartbeat_monotonic_ns: u64,
    ) -> Result<u64, AnalysisRingError> {
        let decoded =
            decode_record(encoded_record).map_err(|_| AnalysisRingError::InvalidCanonicalRecord)?;
        if decoded.envelope.record_kind != RecordKind::SampleBlock {
            return Err(AnalysisRingError::NonSampleRecord);
        }
        if decoded.envelope.run_id != self.run_id {
            return Err(AnalysisRingError::InvalidCanonicalRecord);
        }
        if encoded_record.len() > self.payload_capacity {
            return Err(AnalysisRingError::RecordTooLarge);
        }
        let published = self.atomic_load(PUBLISHED_OFFSET, Ordering::Relaxed);
        let consumed = self.atomic_load(CONSUMED_OFFSET, Ordering::Acquire);
        let outstanding = published
            .checked_sub(consumed)
            .ok_or_else(|| self.contradiction())?;
        if outstanding >= self.slot_count as u64 {
            self.atomic_fetch_add(DROPPED_OFFSET, 1, Ordering::Relaxed);
            self.atomic_fetch_or(FAULT_FLAGS_OFFSET, FAULT_RING_FULL, Ordering::Release);
            return Err(AnalysisRingError::Full);
        }
        let base = self.slot_offset(published as usize % self.slot_count);
        if self.atomic_load(base, Ordering::Acquire) != EMPTY_SLOT {
            return Err(self.contradiction());
        }
        let previous_len = self.read_u32(base + 8) as usize;
        if previous_len > encoded_record.len() && previous_len <= self.payload_capacity {
            self.bytes_mut()[base + 64 + encoded_record.len()..base + 64 + previous_len].fill(0);
        }
        self.write_u32(base + 8, encoded_record.len() as u32);
        self.write_u32(base + 12, crc32c(encoded_record));
        self.write_u64(base + 16, journal_sequence);
        self.write_u64(base + 24, decoded.envelope.record_sequence);
        self.write_u64(base + 32, decoded.envelope.global_time_start_ns);
        self.write_u32(base + 40, decoded.envelope.flags);
        self.write_u32(base + 44, 0);
        self.write_u64(base + 48, !published);
        self.write_u64(base + 56, 0);
        self.bytes_mut()[base + 64..base + 64 + encoded_record.len()]
            .copy_from_slice(encoded_record);
        self.atomic_store(base, published, Ordering::Release);
        self.atomic_store(PUBLISHED_OFFSET, published + 1, Ordering::Release);
        self.atomic_store(
            PRODUCER_HEARTBEAT_OFFSET,
            producer_heartbeat_monotonic_ns,
            Ordering::Release,
        );
        Ok(published)
    }

    pub fn try_consume(
        &mut self,
        consumer_heartbeat_monotonic_ns: u64,
    ) -> Result<Option<ConsumedAnalysisRecord>, AnalysisRingError> {
        let published = self.atomic_load(PUBLISHED_OFFSET, Ordering::Acquire);
        let consumed = self.atomic_load(CONSUMED_OFFSET, Ordering::Relaxed);
        if published == consumed {
            self.atomic_store(
                CONSUMER_HEARTBEAT_OFFSET,
                consumer_heartbeat_monotonic_ns,
                Ordering::Release,
            );
            return Ok(None);
        }
        let outstanding = published
            .checked_sub(consumed)
            .ok_or_else(|| self.contradiction())?;
        if outstanding > self.slot_count as u64 {
            return Err(self.contradiction());
        }
        let base = self.slot_offset(consumed as usize % self.slot_count);
        if self.atomic_load(base, Ordering::Acquire) != consumed
            || self.read_u64(base + 48) != !consumed
        {
            return Err(self.contradiction());
        }
        let encoded_len = self.read_u32(base + 8) as usize;
        if !(RECORD_HEADER_LEN..=self.payload_capacity).contains(&encoded_len) {
            return Err(self.contradiction());
        }
        let encoded_record = self.bytes()[base + 64..base + 64 + encoded_len].to_vec();
        if crc32c(&encoded_record) != self.read_u32(base + 12) {
            return Err(self.contradiction());
        }
        let decoded = decode_record(&encoded_record).map_err(|_| self.contradiction())?;
        if decoded.envelope.record_kind != RecordKind::SampleBlock
            || decoded.envelope.run_id != self.run_id
            || decoded.envelope.record_sequence != self.read_u64(base + 24)
            || decoded.envelope.global_time_start_ns != self.read_u64(base + 32)
            || decoded.envelope.flags != self.read_u32(base + 40)
        {
            return Err(self.contradiction());
        }
        let journal_sequence = self.read_u64(base + 16);
        self.atomic_store(base, EMPTY_SLOT, Ordering::Release);
        self.atomic_store(CONSUMED_OFFSET, consumed + 1, Ordering::Release);
        self.atomic_store(
            CONSUMER_HEARTBEAT_OFFSET,
            consumer_heartbeat_monotonic_ns,
            Ordering::Release,
        );
        Ok(Some(ConsumedAnalysisRecord {
            ring_sequence: consumed,
            journal_sequence,
            encoded_record,
        }))
    }

    pub fn dropped_records(&self) -> u64 {
        self.atomic_load(DROPPED_OFFSET, Ordering::Acquire)
    }

    pub fn fault_flags(&self) -> u64 {
        self.atomic_load(FAULT_FLAGS_OFFSET, Ordering::Acquire)
    }

    pub fn run_id(&self) -> Id16 {
        self.run_id
    }

    pub fn consumer_id(&self) -> Id16 {
        self.consumer_id
    }

    pub fn producer_epoch(&self) -> u64 {
        self.producer_epoch
    }

    fn initialize_header(&mut self, consumer_id: Id16, producer_epoch: u64) {
        let run_id = self.run_id;
        self.bytes_mut()[0..8].copy_from_slice(ANALYSIS_RING_MAGIC);
        self.write_u16(8, ANALYSIS_RING_VERSION);
        self.write_u16(10, ANALYSIS_RING_HEADER_BYTES as u16);
        self.write_u16(12, ANALYSIS_RING_SLOT_HEADER_BYTES as u16);
        self.write_u16(14, 0);
        self.write_u32(16, self.slot_count as u32);
        self.write_u32(20, self.payload_capacity as u32);
        self.bytes_mut()[32..64].copy_from_slice(&PROTOCOL_HASH);
        self.bytes_mut()[64..80].copy_from_slice(&run_id);
        self.bytes_mut()[80..96].copy_from_slice(&consumer_id);
        self.write_u64(96, producer_epoch);
        self.write_u64(104, self.slot_stride as u64);
        self.write_u32(112, crc32c(&self.bytes()[..112]));
    }

    fn slot_offset(&self, index: usize) -> usize {
        ANALYSIS_RING_HEADER_BYTES + index * self.slot_stride
    }

    fn contradiction(&self) -> AnalysisRingError {
        self.atomic_fetch_or(FAULT_FLAGS_OFFSET, FAULT_CONTRADICTION, Ordering::Release);
        AnalysisRingError::Contradiction
    }

    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.view.0.as_ptr().cast_const(), self.total_bytes) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.view.0.as_ptr(), self.total_bytes) }
    }

    fn atomic(&self, offset: usize) -> &AtomicU64 {
        debug_assert_eq!(offset % size_of::<AtomicU64>(), 0);
        debug_assert!(offset + 8 <= self.total_bytes);
        unsafe { &*self.view.0.as_ptr().add(offset).cast::<AtomicU64>() }
    }

    fn atomic_load(&self, offset: usize, ordering: Ordering) -> u64 {
        self.atomic(offset).load(ordering)
    }
    fn atomic_store(&self, offset: usize, value: u64, ordering: Ordering) {
        self.atomic(offset).store(value, ordering);
    }
    fn atomic_fetch_add(&self, offset: usize, value: u64, ordering: Ordering) {
        self.atomic(offset).fetch_add(value, ordering);
    }
    fn atomic_fetch_or(&self, offset: usize, value: u64, ordering: Ordering) {
        self.atomic(offset).fetch_or(value, ordering);
    }
    fn read_u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes(
            self.bytes()[offset..offset + 4]
                .try_into()
                .expect("fixed slice"),
        )
    }
    fn read_u64(&self, offset: usize) -> u64 {
        u64::from_le_bytes(
            self.bytes()[offset..offset + 8]
                .try_into()
                .expect("fixed slice"),
        )
    }
    fn write_u16(&mut self, offset: usize, value: u16) {
        self.bytes_mut()[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn write_u32(&mut self, offset: usize, value: u32) {
        self.bytes_mut()[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn write_u64(&mut self, offset: usize, value: u64) {
        self.bytes_mut()[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}

fn validate_header(
    header: &[u8],
    run_id: Id16,
    consumer_id: Id16,
    producer_epoch: u64,
) -> io::Result<(usize, usize, usize, usize)> {
    if header[0..8] != ANALYSIS_RING_MAGIC[..]
        || u16::from_le_bytes(header[8..10].try_into().expect("fixed")) != ANALYSIS_RING_VERSION
        || u16::from_le_bytes(header[10..12].try_into().expect("fixed")) as usize
            != ANALYSIS_RING_HEADER_BYTES
        || u16::from_le_bytes(header[12..14].try_into().expect("fixed")) as usize
            != ANALYSIS_RING_SLOT_HEADER_BYTES
        || header[14..16] != [0; 2]
        || header[24..32] != [0; 8]
        || header[32..64] != PROTOCOL_HASH
        || header[64..80] != run_id
        || header[80..96] != consumer_id
        || u64::from_le_bytes(header[96..104].try_into().expect("fixed")) != producer_epoch
        || u32::from_le_bytes(header[112..116].try_into().expect("fixed")) != crc32c(&header[..112])
        || header[116..128] != [0; 12]
        || header[176..256] != [0; 80]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "analysis mapping immutable header contradiction",
        ));
    }
    let slot_count = u32::from_le_bytes(header[16..20].try_into().expect("fixed")) as usize;
    let payload_capacity = u32::from_le_bytes(header[20..24].try_into().expect("fixed")) as usize;
    let slot_stride = u64::from_le_bytes(header[104..112].try_into().expect("fixed")) as usize;
    let config = AnalysisMappingConfig {
        slot_count,
        payload_capacity,
        run_id,
        consumer_id,
        producer_epoch,
    };
    let (expected_stride, total_bytes) = config.layout()?;
    if slot_stride != expected_stride {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "analysis mapping slot stride contradicts its configuration",
        ));
    }
    let published = u64::from_le_bytes(header[128..136].try_into().expect("fixed"));
    let consumed = u64::from_le_bytes(header[136..144].try_into().expect("fixed"));
    let faults = u64::from_le_bytes(header[168..176].try_into().expect("fixed"));
    if consumed > published
        || published - consumed > slot_count as u64
        || faults & !KNOWN_FAULT_FLAGS != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "analysis mapping sequence/fault header contradiction",
        ));
    }
    Ok((slot_count, payload_capacity, slot_stride, total_bytes))
}

pub(crate) fn validate_mapping_name(name: &str) -> io::Result<()> {
    let suffix = name
        .strip_prefix(r"Local\ForgeAnalysisRing-")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "analysis mapping must use the local Forge namespace",
            )
        })?;
    if suffix.is_empty()
        || suffix.contains(['\\', '/'])
        || !suffix
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
        || name.encode_utf16().count() >= 192
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "analysis mapping name is not one bounded local component",
        ));
    }
    Ok(())
}

fn mapping_too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "analysis mapping exceeds the bounded one-GiB process profile",
    )
}

fn align64(value: usize) -> Option<usize> {
    value.checked_add(63).map(|rounded| rounded & !63)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct OwnedHandle(HANDLE);
impl OwnedHandle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }
}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct OwnedView(NonNull<u8>);
impl OwnedView {
    fn map(handle: HANDLE, bytes: usize) -> io::Result<Self> {
        let mapped = unsafe { MapViewOfFile(handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, bytes) };
        NonNull::new(mapped.Value.cast::<u8>())
            .map(Self)
            .ok_or_else(io::Error::last_os_error)
    }

    fn region_bytes(&self) -> io::Result<usize> {
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        let written = unsafe {
            VirtualQuery(
                self.0.as_ptr().cast::<c_void>(),
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written != size_of::<MEMORY_BASIC_INFORMATION>() {
            return Err(io::Error::last_os_error());
        }
        Ok(info.RegionSize)
    }
}
impl Drop for OwnedView {
    fn drop(&mut self) {
        unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.0.as_ptr().cast(),
            });
        }
    }
}

struct SecurityDescriptor(*mut c_void);
impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                SECURITY_DESCRIPTOR_REVISION,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid analysis mapping DACL: {}",
                    io::Error::last_os_error()
                ),
            ));
        }
        Ok(Self(descriptor))
    }
}
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::current_process_user_sid;
    use crate::source::{DeterministicReplayConfig, DeterministicReplaySource};
    use std::fs;
    use std::process::Command;

    const CHILD_MAPPING_NAME: &str = "FORGE_TEST_ANALYSIS_MAPPING_NAME";
    const CHILD_OUTPUT_PATH: &str = "FORGE_TEST_ANALYSIS_MAPPING_OUTPUT";

    fn mapping_name(label: &str) -> String {
        format!(
            r"Local\ForgeAnalysisRing-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        )
    }

    fn config() -> AnalysisMappingConfig {
        AnalysisMappingConfig {
            slot_count: 2,
            payload_capacity: 4096,
            run_id: [1; 16],
            consumer_id: [4; 16],
            producer_epoch: 7,
        }
    }

    fn record() -> Vec<u8> {
        let mut source = DeterministicReplaySource::new(DeterministicReplayConfig {
            run_id: [1; 16],
            pod_id: [2; 16],
            headstage_id: [3; 16],
            channel_layout_id: 1,
            channel_count: 2,
            samples_per_channel: 30,
            sample_rate_hz: 30_000,
            total_records: 1,
            seed: 9,
        })
        .expect("source");
        source.next_encoded_record().unwrap().unwrap()
    }

    #[test]
    fn cross_process_child_fixture() {
        let Ok(name) = std::env::var(CHILD_MAPPING_NAME) else {
            return;
        };
        let output = std::env::var_os(CHILD_OUTPUT_PATH).expect("child output path");
        let mut consumer = MappedAnalysisRing::open(&name, [1; 16], [4; 16], 7).unwrap();
        let received = consumer.try_consume(300).unwrap().unwrap();
        assert_eq!(received.journal_sequence, 31);
        fs::write(output, received.encoded_record).expect("write child receipt");
    }

    #[test]
    fn independent_process_opens_and_consumes_named_mapping() {
        let name = mapping_name("cross-process");
        let sid = current_process_user_sid().unwrap();
        let mut producer = MappedAnalysisRing::create_test(&name, &sid, config()).unwrap();
        let encoded = record();
        producer.try_publish(&encoded, 31, 100).unwrap();

        let output = std::env::temp_dir().join(format!(
            "forge-analysis-mapping-child-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        let status = Command::new(std::env::current_exe().expect("test executable"))
            .arg("analysis_mapping::tests::cross_process_child_fixture")
            .arg("--exact")
            .arg("--nocapture")
            .env(CHILD_MAPPING_NAME, &name)
            .env(CHILD_OUTPUT_PATH, &output)
            .status()
            .expect("spawn independent consumer process");
        let child_record = fs::read(&output);
        let _ = fs::remove_file(&output);
        assert!(status.success(), "consumer child failed with {status}");
        assert_eq!(child_record.expect("child receipt"), encoded);
        assert_eq!(producer.dropped_records(), 0);
        assert_eq!(producer.fault_flags(), 0);
    }

    #[test]
    fn live_mapping_round_trip_and_first_instance_are_enforced() {
        let name = mapping_name("roundtrip");
        let sid = current_process_user_sid().unwrap();
        let mut producer = MappedAnalysisRing::create_test(&name, &sid, config()).unwrap();
        let mut consumer = MappedAnalysisRing::open(&name, [1; 16], [4; 16], 7).unwrap();
        let encoded = record();
        producer.try_publish(&encoded, 12, 100).unwrap();
        let received = consumer.try_consume(200).unwrap().unwrap();
        assert_eq!(received.journal_sequence, 12);
        assert_eq!(received.encoded_record, encoded);
        assert!(consumer.try_consume(201).unwrap().is_none());
        assert_eq!(producer.dropped_records(), 0);
        assert_eq!(producer.fault_flags(), 0);
        assert_eq!(
            MappedAnalysisRing::create_test(&name, &sid, config())
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn worker_generic_read_write_acl_is_sufficient_without_owner_access() {
        let name = mapping_name("worker-grgw");
        let sid = current_process_user_sid().unwrap();
        let mut producer =
            MappedAnalysisRing::create_worker_only_test(&name, &sid, config()).unwrap();
        let mut consumer = MappedAnalysisRing::open(&name, [1; 16], [4; 16], 7).unwrap();
        let encoded = record();
        producer.try_publish(&encoded, 19, 100).unwrap();
        assert_eq!(
            consumer.try_consume(200).unwrap().unwrap().encoded_record,
            encoded
        );
    }

    #[test]
    fn production_creation_rejects_a_sid_not_enabled_in_the_token() {
        let name = mapping_name("service-gate");
        let sid = current_process_user_sid().unwrap();
        let error =
            MappedAnalysisRing::create_service(&name, "S-1-5-80-0", &sid, config()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn names_and_expected_identity_fail_closed() {
        let sid = current_process_user_sid().unwrap();
        assert!(MappedAnalysisRing::create_test("Global\\bad", &sid, config()).is_err());
        let name = mapping_name("identity");
        let _owner = MappedAnalysisRing::create_test(&name, &sid, config()).unwrap();
        assert!(MappedAnalysisRing::open(&name, [9; 16], [4; 16], 7).is_err());
        assert!(MappedAnalysisRing::open(&name, [1; 16], [9; 16], 7).is_err());
        assert!(MappedAnalysisRing::open(&name, [1; 16], [4; 16], 8).is_err());
    }
}
