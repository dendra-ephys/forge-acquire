//! Fail-closed Windows FTDI D3XX adapter foundation.
//!
//! The vendor DLL is loaded only from System32 or an explicit absolute path.
//! Production open is by a unique nonempty serial number, never by index.  A
//! device is not returned until exact FT601 type, SuperSpeed operation and the
//! receipt-selected 66-MHz bring-up or 100-MHz release 245/one-channel
//! configuration plus an approved readback hash agree.
//! No such approved readback hash is checked into the current project, so this
//! module cannot by itself make hardware acquisition available.

use std::collections::VecDeque;
use std::ffi::{c_char, c_void, CString, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::Arc;

use forge_protocol_v1::{decode_low_speed, Hash32, MessageKind, RunCommandV1, WireBody};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::d3xx_admission::{Ft601FifoClockProfile, VerifiedFt601Admission};

const FT_OK: u32 = 0;
const FT_IO_PENDING: u32 = 24;
const FT_IO_INCOMPLETE: u32 = 25;
const FT_DEVICE_601: u32 = 601;
const FT_FLAGS_OPENED: u32 = 1;
const FT_FLAGS_SUPERSPEED: u32 = 4;
const FT_OPEN_BY_SERIAL_NUMBER: u32 = 1;
const USB_DEVICE_DESCRIPTOR_TYPE: u8 = 1;
const USB_CONFIGURATION_DESCRIPTOR_TYPE: u8 = 2;
const USB_INTERFACE_DESCRIPTOR_TYPE: u8 = 4;
const FT_PIPE_TYPE_BULK: u32 = 2;
const FT601_DATA_INTERFACE: u8 = 1;
const FT601_OUT_PIPE_INDEX: u8 = 0;
const FT601_IN_PIPE_INDEX: u8 = 1;
const CONFIGURATION_FIFO_CLOCK_66_MHZ: u8 = 1;
const CONFIGURATION_FIFO_CLOCK_100_MHZ: u8 = 0;
const CONFIGURATION_FIFO_MODE_245: u8 = 0;
const CONFIGURATION_CHANNEL_CONFIG_1: u8 = 2;
const FT601_WRITE_PIPE: u8 = 0x02;
const FT601_READ_PIPE: u8 = 0x82;
const MAX_D3XX_DEVICES: u32 = 64;
const MIN_ASYNC_READ_BYTES: usize = 1_024;
const MAX_ASYNC_READ_BYTES: usize = 16 * 1024 * 1024;
const MAX_ASYNC_READ_QUEUE_DEPTH: usize = 64;
pub(crate) const MIN_D3XX_STREAM_PIPE_BYTES: u32 = 4_096;
pub(crate) const MAX_D3XX_STREAM_PIPE_BYTES: u32 = 16 * 1024 * 1024;

type FtHandle = *mut c_void;
type FtCreateDeviceInfoList = unsafe extern "system" fn(*mut u32) -> u32;
type FtGetDeviceInfoDetail = unsafe extern "system" fn(
    u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut c_char,
    *mut c_char,
    *mut FtHandle,
) -> u32;
type FtCreate = unsafe extern "system" fn(*mut c_void, u32, *mut FtHandle) -> u32;
type FtClose = unsafe extern "system" fn(FtHandle) -> u32;
type FtGetChipConfiguration = unsafe extern "system" fn(FtHandle, *mut c_void) -> u32;
type FtGetDeviceDescriptor = unsafe extern "system" fn(FtHandle, *mut FtDeviceDescriptor) -> u32;
type FtGetConfigurationDescriptor =
    unsafe extern "system" fn(FtHandle, *mut FtConfigurationDescriptor) -> u32;
type FtGetInterfaceDescriptor =
    unsafe extern "system" fn(FtHandle, u8, *mut FtInterfaceDescriptor) -> u32;
type FtGetPipeInformation =
    unsafe extern "system" fn(FtHandle, u8, u8, *mut FtPipeInformation) -> u32;
type FtSetStreamPipe = unsafe extern "system" fn(FtHandle, i32, i32, u8, u32) -> u32;
type FtClearStreamPipe = unsafe extern "system" fn(FtHandle, i32, i32, u8) -> u32;
type FtSetPipeTimeout = unsafe extern "system" fn(FtHandle, u8, u32) -> u32;
type FtAbortPipe = unsafe extern "system" fn(FtHandle, u8) -> u32;
type FtInitializeOverlapped = unsafe extern "system" fn(FtHandle, *mut OVERLAPPED) -> u32;
type FtReleaseOverlapped = unsafe extern "system" fn(FtHandle, *mut OVERLAPPED) -> u32;
type FtReadPipeEx =
    unsafe extern "system" fn(FtHandle, u8, *mut u8, u32, *mut u32, *mut OVERLAPPED) -> u32;
type FtWritePipeEx =
    unsafe extern "system" fn(FtHandle, u8, *mut u8, u32, *mut u32, *mut OVERLAPPED) -> u32;
type FtGetOverlappedResult =
    unsafe extern "system" fn(FtHandle, *mut OVERLAPPED, *mut u32, i32) -> u32;

#[repr(C)]
#[derive(Clone, Copy)]
struct Ft60xConfiguration {
    vendor_id: u16,
    product_id: u16,
    string_descriptors: [u8; 128],
    interval: u8,
    power_attributes: u8,
    power_consumption: u16,
    reserved2: u8,
    fifo_clock: u8,
    fifo_mode: u8,
    channel_config: u8,
    optional_feature_support: u16,
    battery_charging_gpio_config: u8,
    flash_eeprom_detection: u8,
    msio_control: u32,
    gpio_control: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct FtDeviceDescriptor {
    length: u8,
    descriptor_type: u8,
    bcd_usb: u16,
    device_class: u8,
    device_subclass: u8,
    device_protocol: u8,
    max_packet_size0: u8,
    vendor_id: u16,
    product_id: u16,
    bcd_device: u16,
    manufacturer_index: u8,
    product_index: u8,
    serial_index: u8,
    configuration_count: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct FtConfigurationDescriptor {
    length: u8,
    descriptor_type: u8,
    total_length: u16,
    interface_count: u8,
    configuration_value: u8,
    configuration_index: u8,
    attributes: u8,
    max_power: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct FtInterfaceDescriptor {
    length: u8,
    descriptor_type: u8,
    interface_number: u8,
    alternate_setting: u8,
    endpoint_count: u8,
    interface_class: u8,
    interface_subclass: u8,
    interface_protocol: u8,
    interface_index: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct FtPipeInformation {
    pipe_type: u32,
    pipe_id: u8,
    maximum_packet_size: u16,
    interval: u8,
}

impl Default for Ft60xConfiguration {
    fn default() -> Self {
        // The DLL initializes every documented field. Zeroing first also makes
        // the exact readback hash deterministic if a future DLL leaves reserved
        // bytes untouched.
        unsafe { std::mem::zeroed() }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct D3xxDeviceInfo {
    pub flags: u32,
    pub device_type: u32,
    pub usb_id: u32,
    pub location_id: u32,
    pub serial_number: String,
    pub description: String,
}

impl D3xxDeviceInfo {
    pub fn opened(&self) -> bool {
        self.flags & FT_FLAGS_OPENED != 0
    }

    pub fn superspeed(&self) -> bool {
        self.flags & FT_FLAGS_SUPERSPEED != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ft601ConfigurationEvidence {
    pub vendor_id: u16,
    pub product_id: u16,
    pub fifo_clock_raw: u8,
    pub fifo_mode_raw: u8,
    pub channel_config_raw: u8,
    pub readback_sha256: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ft601UsbDescriptorEvidence {
    pub bcd_usb: u16,
    pub bcd_device: u16,
    pub vendor_id: u16,
    pub product_id: u16,
    pub configuration_count: u8,
    pub interface_count: u8,
    pub configuration_attributes: u8,
    pub max_power: u8,
    pub data_interface_number: u8,
    pub data_endpoint_count: u8,
    pub out_pipe_type: u32,
    pub out_pipe_id: u8,
    pub out_maximum_packet_size: u16,
    pub in_pipe_type: u32,
    pub in_pipe_id: u8,
    pub in_maximum_packet_size: u16,
    pub descriptor_sha256: Hash32,
}

struct D3xxFunctions {
    create_device_info_list: FtCreateDeviceInfoList,
    get_device_info_detail: FtGetDeviceInfoDetail,
    create: FtCreate,
    close: FtClose,
    get_chip_configuration: FtGetChipConfiguration,
    get_device_descriptor: FtGetDeviceDescriptor,
    get_configuration_descriptor: FtGetConfigurationDescriptor,
    get_interface_descriptor: FtGetInterfaceDescriptor,
    get_pipe_information: FtGetPipeInformation,
    set_stream_pipe: FtSetStreamPipe,
    clear_stream_pipe: FtClearStreamPipe,
    set_pipe_timeout: FtSetPipeTimeout,
    abort_pipe: FtAbortPipe,
    initialize_overlapped: FtInitializeOverlapped,
    release_overlapped: FtReleaseOverlapped,
    read_pipe_ex: FtReadPipeEx,
    write_pipe_ex: FtWritePipeEx,
    get_overlapped_result: FtGetOverlappedResult,
}

struct OwnedModule(HMODULE);

impl Drop for OwnedModule {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeLibrary(self.0) };
        }
    }
}

pub struct D3xxLibrary {
    _module: OwnedModule,
    functions: D3xxFunctions,
    source_path: PathBuf,
    library_sha256: Hash32,
}

// The module stays loaded for the Arc lifetime and the resolved function table
// is immutable. D3XX device handles themselves remain single-owner and !Sync.
unsafe impl Send for D3xxLibrary {}
unsafe impl Sync for D3xxLibrary {}

impl D3xxLibrary {
    pub fn load_system32() -> io::Result<Arc<Self>> {
        let mut errors = Vec::new();
        for name in ["FTD3XXWU.dll", "FTD3XX.dll"] {
            match Self::load_named_system32(name) {
                Ok(value) => return Ok(Arc::new(value)),
                Err(error) => errors.push(format!("{name}: {error}")),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no supported D3XX library in System32 ({})",
                errors.join("; ")
            ),
        ))
    }

    pub fn load_absolute(path: impl AsRef<Path>) -> io::Result<Arc<Self>> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(invalid_input("D3XX library path must be absolute"));
        }
        let canonical = std::fs::canonicalize(path)?;
        if !canonical.is_file() {
            return Err(invalid_input("D3XX library path is not a file"));
        }
        let wide = wide_path(&canonical)?;
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        Self::finish_load(OwnedModule(module), canonical).map(Arc::new)
    }

    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    pub fn library_sha256(&self) -> Hash32 {
        self.library_sha256
    }

    pub fn enumerate(&self) -> io::Result<Vec<D3xxDeviceInfo>> {
        let mut count = 0_u32;
        status(
            unsafe { (self.functions.create_device_info_list)(&mut count) },
            "FT_CreateDeviceInfoList",
        )?;
        if count > MAX_D3XX_DEVICES {
            return Err(invalid_data("D3XX device count exceeds bounded policy"));
        }
        let mut devices = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut flags = 0;
            let mut device_type = 0;
            let mut usb_id = 0;
            let mut location_id = 0;
            let mut serial = [0_i8; 16];
            let mut description = [0_i8; 64];
            let mut ignored_handle = null_mut();
            status(
                unsafe {
                    (self.functions.get_device_info_detail)(
                        index,
                        &mut flags,
                        &mut device_type,
                        &mut usb_id,
                        &mut location_id,
                        serial.as_mut_ptr(),
                        description.as_mut_ptr(),
                        &mut ignored_handle,
                    )
                },
                "FT_GetDeviceInfoDetail",
            )?;
            devices.push(D3xxDeviceInfo {
                flags,
                device_type,
                usb_id,
                location_id,
                serial_number: fixed_ascii(&serial, "serial number")?,
                description: fixed_ascii(&description, "description")?,
            });
        }
        Ok(devices)
    }

    pub fn open_admitted_ft601(
        self: &Arc<Self>,
        admission: &VerifiedFt601Admission,
    ) -> io::Result<(
        D3xxDevice,
        Ft601ConfigurationEvidence,
        Ft601UsbDescriptorEvidence,
    )> {
        if self.library_sha256 != admission.library_sha256() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "loaded D3XX library hash does not match the admission receipt",
            ));
        }
        let serial_number = admission.serial_number();
        let devices = self.enumerate()?;
        let selected = select_unique_ft601(&devices, serial_number)?;
        validate_ft601_device_state(selected)?;
        validate_serial(serial_number)?;
        let serial =
            CString::new(serial_number).map_err(|_| invalid_input("D3XX serial contains NUL"))?;
        let mut handle = null_mut();
        status(
            unsafe {
                (self.functions.create)(
                    serial.as_ptr().cast_mut().cast(),
                    FT_OPEN_BY_SERIAL_NUMBER,
                    &mut handle,
                )
            },
            "FT_Create",
        )?;
        if handle.is_null() {
            return Err(invalid_data("FT_Create returned a null handle"));
        }
        let mut device = D3xxDevice {
            library: Arc::clone(self),
            handle,
            read_stream_configured: false,
            write_ready: false,
            pending_reads: VecDeque::new(),
            io_poisoned: false,
        };
        let configuration = match device.read_configuration() {
            Ok(value) => value,
            Err(error) => {
                device.close();
                return Err(error);
            }
        };
        let descriptors = match device.read_usb_descriptors() {
            Ok(value) => value,
            Err(error) => {
                device.close();
                return Err(error);
            }
        };
        if let Err(error) = validate_ft601_configuration(
            &configuration,
            admission.configuration_readback_sha256(),
            admission.fifo_clock_profile(),
        ) {
            device.close();
            return Err(error);
        }
        if let Err(error) = validate_ft601_usb_descriptors(
            &descriptors,
            &configuration,
            admission.usb_descriptor_sha256(),
        ) {
            device.close();
            return Err(error);
        }
        Ok((device, configuration, descriptors))
    }

    fn load_named_system32(name: &str) -> io::Result<Self> {
        let wide: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
        let module =
            unsafe { LoadLibraryExW(wide.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        let owned = OwnedModule(module);
        let path = module_path(module)?;
        Self::finish_load(owned, path)
    }

    fn finish_load(module: OwnedModule, source_path: PathBuf) -> io::Result<Self> {
        let functions = unsafe {
            D3xxFunctions {
                create_device_info_list: symbol(module.0, b"FT_CreateDeviceInfoList\0")?,
                get_device_info_detail: symbol(module.0, b"FT_GetDeviceInfoDetail\0")?,
                create: symbol(module.0, b"FT_Create\0")?,
                close: symbol(module.0, b"FT_Close\0")?,
                get_chip_configuration: symbol(module.0, b"FT_GetChipConfiguration\0")?,
                get_device_descriptor: symbol(module.0, b"FT_GetDeviceDescriptor\0")?,
                get_configuration_descriptor: symbol(module.0, b"FT_GetConfigurationDescriptor\0")?,
                get_interface_descriptor: symbol(module.0, b"FT_GetInterfaceDescriptor\0")?,
                get_pipe_information: symbol(module.0, b"FT_GetPipeInformation\0")?,
                set_stream_pipe: symbol(module.0, b"FT_SetStreamPipe\0")?,
                clear_stream_pipe: symbol(module.0, b"FT_ClearStreamPipe\0")?,
                set_pipe_timeout: symbol(module.0, b"FT_SetPipeTimeout\0")?,
                abort_pipe: symbol(module.0, b"FT_AbortPipe\0")?,
                initialize_overlapped: symbol(module.0, b"FT_InitializeOverlapped\0")?,
                release_overlapped: symbol(module.0, b"FT_ReleaseOverlapped\0")?,
                read_pipe_ex: symbol(module.0, b"FT_ReadPipeEx\0")?,
                write_pipe_ex: symbol(module.0, b"FT_WritePipeEx\0")?,
                get_overlapped_result: symbol(module.0, b"FT_GetOverlappedResult\0")?,
            }
        };
        let library_sha256 = sha256_file(&source_path)?;
        Ok(Self {
            _module: module,
            functions,
            source_path,
            library_sha256,
        })
    }
}

pub struct D3xxDevice {
    library: Arc<D3xxLibrary>,
    handle: FtHandle,
    read_stream_configured: bool,
    write_ready: bool,
    pending_reads: VecDeque<PendingD3xxRead>,
    io_poisoned: bool,
}

struct PendingD3xxRead {
    // Both allocations must retain stable addresses until D3XX reports the
    // transfer complete and FT_ReleaseOverlapped has returned.
    overlapped: Box<OVERLAPPED>,
    transferred: Box<u32>,
    buffer: Vec<u8>,
    completed_inline: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum D3xxReadPoll {
    Idle,
    Pending,
    Complete(Vec<u8>),
}

// A handle is exclusively owned and moved to one ingest thread. It is never
// shared concurrently through this type.
unsafe impl Send for D3xxDevice {}

impl D3xxDevice {
    pub fn prepare_duplex_pipes(
        &mut self,
        read_stream_bytes: u32,
        timeout_ms: u32,
    ) -> io::Result<()> {
        if self.handle.is_null()
            || self.read_stream_configured
            || self.write_ready
            || self.io_poisoned
        {
            return Err(invalid_input("D3XX pipes are closed or already configured"));
        }
        if !(MIN_D3XX_STREAM_PIPE_BYTES..=MAX_D3XX_STREAM_PIPE_BYTES).contains(&read_stream_bytes)
            || !read_stream_bytes.is_multiple_of(1_024)
            || timeout_ms == 0
            || timeout_ms > 60_000
        {
            return Err(invalid_input("invalid D3XX stream size or timeout"));
        }
        status(
            unsafe {
                (self.library.functions.set_pipe_timeout)(self.handle, FT601_READ_PIPE, timeout_ms)
            },
            "FT_SetPipeTimeout(IN)",
        )?;
        status(
            unsafe {
                (self.library.functions.set_pipe_timeout)(self.handle, FT601_WRITE_PIPE, timeout_ms)
            },
            "FT_SetPipeTimeout(OUT)",
        )?;
        status(
            unsafe {
                (self.library.functions.set_stream_pipe)(
                    self.handle,
                    0,
                    0,
                    FT601_READ_PIPE,
                    read_stream_bytes,
                )
            },
            "FT_SetStreamPipe(IN)",
        )?;
        self.read_stream_configured = true;
        self.write_ready = true;
        Ok(())
    }

    /// Queues one bounded asynchronous IN transfer while retaining exclusive
    /// ownership of the FT601 handle. Callers may queue several reads and may
    /// send an OUT control transaction between nonblocking polls. Completed
    /// reads are always returned in submission order so byte-stream ordering is
    /// preserved even when later transfers finish first.
    pub fn queue_read(&mut self, buffer_bytes: usize) -> io::Result<()> {
        if self.handle.is_null() || !self.read_stream_configured || self.io_poisoned {
            return Err(invalid_input("D3XX read pipe is not ready"));
        }
        validate_async_read_shape(buffer_bytes, self.pending_reads.len())?;
        self.pending_reads
            .try_reserve(1)
            .map_err(|_| io::Error::other("D3XX async read queue allocation failed"))?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(buffer_bytes)
            .map_err(|_| io::Error::other("D3XX async read buffer allocation failed"))?;
        buffer.resize(buffer_bytes, 0);

        let mut pending = PendingD3xxRead {
            overlapped: Box::new(unsafe { std::mem::zeroed() }),
            transferred: Box::new(0),
            buffer,
            completed_inline: false,
        };
        status(
            unsafe {
                (self.library.functions.initialize_overlapped)(
                    self.handle,
                    pending.overlapped.as_mut(),
                )
            },
            "FT_InitializeOverlapped(IN queue)",
        )
        .inspect_err(|_| self.io_poisoned = true)?;

        let initial = unsafe {
            (self.library.functions.read_pipe_ex)(
                self.handle,
                FT601_READ_PIPE,
                pending.buffer.as_mut_ptr(),
                pending.buffer.len() as u32,
                pending.transferred.as_mut(),
                pending.overlapped.as_mut(),
            )
        };
        match initial {
            FT_OK => pending.completed_inline = true,
            FT_IO_PENDING => {}
            value => {
                self.io_poisoned = true;
                let _ =
                    unsafe { (self.library.functions.abort_pipe)(self.handle, FT601_READ_PIPE) };
                let release = status(
                    unsafe {
                        (self.library.functions.release_overlapped)(
                            self.handle,
                            pending.overlapped.as_mut(),
                        )
                    },
                    "FT_ReleaseOverlapped(IN rejected queue)",
                );
                return match release {
                    Ok(()) => Err(status_error(value, "FT_ReadPipeEx(IN queue)")),
                    Err(release_error) => Err(io::Error::other(format!(
                        "FT_ReadPipeEx(IN queue) failed with FT_STATUS {value}; {release_error}"
                    ))),
                };
            }
        }
        self.pending_reads.push_back(pending);
        Ok(())
    }

    /// Polls the oldest queued IN transfer without blocking. `Pending` means
    /// D3XX returned FT_IO_INCOMPLETE; `Complete` owns exactly the transferred
    /// bytes and releases the corresponding OVERLAPPED resource first.
    pub fn poll_next_read(&mut self) -> io::Result<D3xxReadPoll> {
        if self.handle.is_null() || !self.read_stream_configured || self.io_poisoned {
            return Err(invalid_input("D3XX read pipe is not ready"));
        }
        let Some(front) = self.pending_reads.front_mut() else {
            return Ok(D3xxReadPoll::Idle);
        };
        if !front.completed_inline {
            let value = unsafe {
                (self.library.functions.get_overlapped_result)(
                    self.handle,
                    front.overlapped.as_mut(),
                    front.transferred.as_mut(),
                    0,
                )
            };
            match value {
                FT_OK => front.completed_inline = true,
                FT_IO_INCOMPLETE => return Ok(D3xxReadPoll::Pending),
                value => {
                    self.io_poisoned = true;
                    let _ = unsafe {
                        (self.library.functions.abort_pipe)(self.handle, FT601_READ_PIPE)
                    };
                    let mut failed = self.pending_reads.pop_front().unwrap();
                    let release = status(
                        unsafe {
                            (self.library.functions.release_overlapped)(
                                self.handle,
                                failed.overlapped.as_mut(),
                            )
                        },
                        "FT_ReleaseOverlapped(IN failed poll)",
                    );
                    return match release {
                        Ok(()) => Err(status_error(value, "FT_GetOverlappedResult(IN poll)")),
                        Err(release_error) => Err(io::Error::other(format!(
                            "FT_GetOverlappedResult(IN poll) failed with FT_STATUS {value}; {release_error}"
                        ))),
                    };
                }
            }
        }

        let mut completed = self.pending_reads.pop_front().unwrap();
        let release = status(
            unsafe {
                (self.library.functions.release_overlapped)(
                    self.handle,
                    completed.overlapped.as_mut(),
                )
            },
            "FT_ReleaseOverlapped(IN complete)",
        );
        if release.is_err() {
            self.io_poisoned = true;
            let _ = unsafe { (self.library.functions.abort_pipe)(self.handle, FT601_READ_PIPE) };
        }
        release?;
        let transferred = *completed.transferred as usize;
        if transferred > completed.buffer.len() {
            self.io_poisoned = true;
            let _ = unsafe { (self.library.functions.abort_pipe)(self.handle, FT601_READ_PIPE) };
            return Err(invalid_data(
                "D3XX returned an impossible async read length",
            ));
        }
        completed.buffer.truncate(transferred);
        Ok(D3xxReadPoll::Complete(completed.buffer))
    }

    pub fn queued_read_count(&self) -> usize {
        self.pending_reads.len()
    }

    pub fn is_io_poisoned(&self) -> bool {
        self.io_poisoned
    }

    /// Cancels every queued IN request and releases every initialized
    /// OVERLAPPED allocation. This is a terminal recovery action for the
    /// current pipe epoch; callers must not treat cancellation as a clean Run.
    pub fn cancel_queued_reads(&mut self) -> io::Result<()> {
        if self.pending_reads.is_empty() {
            return Ok(());
        }
        if self.handle.is_null() {
            return Err(invalid_input(
                "cannot release queued D3XX reads after the handle is closed",
            ));
        }
        self.io_poisoned = true;
        let mut first_error = status(
            unsafe { (self.library.functions.abort_pipe)(self.handle, FT601_READ_PIPE) },
            "FT_AbortPipe(IN queued reads)",
        )
        .err();
        while let Some(mut pending) = self.pending_reads.pop_front() {
            let release = status(
                unsafe {
                    (self.library.functions.release_overlapped)(
                        self.handle,
                        pending.overlapped.as_mut(),
                    )
                },
                "FT_ReleaseOverlapped(IN cancellation)",
            );
            if first_error.is_none() {
                first_error = release.err();
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.handle.is_null()
            || !self.read_stream_configured
            || buffer.is_empty()
            || !self.pending_reads.is_empty()
            || self.io_poisoned
        {
            return Err(invalid_input("D3XX read pipe is not ready"));
        }
        if buffer.len() > u32::MAX as usize {
            return Err(invalid_input("D3XX read buffer exceeds ULONG"));
        }
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        status(
            unsafe { (self.library.functions.initialize_overlapped)(self.handle, &mut overlapped) },
            "FT_InitializeOverlapped",
        )
        .inspect_err(|_| self.io_poisoned = true)?;
        let mut transferred = 0_u32;
        let initial = unsafe {
            (self.library.functions.read_pipe_ex)(
                self.handle,
                FT601_READ_PIPE,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut transferred,
                &mut overlapped,
            )
        };
        let transfer_result = if initial == FT_OK {
            Ok(())
        } else if initial == FT_IO_PENDING {
            status(
                unsafe {
                    (self.library.functions.get_overlapped_result)(
                        self.handle,
                        &mut overlapped,
                        &mut transferred,
                        1,
                    )
                },
                "FT_GetOverlappedResult",
            )
        } else {
            Err(status_error(initial, "FT_ReadPipeEx"))
        };
        if transfer_result.is_err() {
            self.io_poisoned = true;
            let _ = unsafe { (self.library.functions.abort_pipe)(self.handle, FT601_READ_PIPE) };
        }
        let release = status(
            unsafe { (self.library.functions.release_overlapped)(self.handle, &mut overlapped) },
            "FT_ReleaseOverlapped",
        );
        if release.is_err() {
            self.io_poisoned = true;
            let _ = unsafe { (self.library.functions.abort_pipe)(self.handle, FT601_READ_PIPE) };
        }
        transfer_result?;
        release?;
        if transferred as usize > buffer.len() {
            self.io_poisoned = true;
            return Err(invalid_data("D3XX returned an impossible transfer length"));
        }
        Ok(transferred as usize)
    }

    /// Sends one exact M0 acquisition-control message on the one-channel OUT
    /// endpoint. Arbitrary bytes, replies, worker messages and stimulation
    /// commands are not admitted by this M3 acquisition-only adapter.
    pub(crate) fn write_control(&mut self, message: &[u8]) -> io::Result<()> {
        if self.handle.is_null() || !self.write_ready || self.io_poisoned {
            return Err(invalid_input("D3XX write pipe is not ready"));
        }
        validate_outbound_control(message)?;
        if message.len() > u32::MAX as usize {
            return Err(invalid_input("D3XX write message exceeds ULONG"));
        }
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        status(
            unsafe { (self.library.functions.initialize_overlapped)(self.handle, &mut overlapped) },
            "FT_InitializeOverlapped(OUT)",
        )
        .inspect_err(|_| self.io_poisoned = true)?;
        let mut transferred = 0_u32;
        let initial = unsafe {
            (self.library.functions.write_pipe_ex)(
                self.handle,
                FT601_WRITE_PIPE,
                message.as_ptr().cast_mut(),
                message.len() as u32,
                &mut transferred,
                &mut overlapped,
            )
        };
        let transfer_result = if initial == FT_OK {
            Ok(())
        } else if initial == FT_IO_PENDING {
            status(
                unsafe {
                    (self.library.functions.get_overlapped_result)(
                        self.handle,
                        &mut overlapped,
                        &mut transferred,
                        1,
                    )
                },
                "FT_GetOverlappedResult(OUT)",
            )
        } else {
            Err(status_error(initial, "FT_WritePipeEx"))
        };
        if transfer_result.is_err() {
            self.io_poisoned = true;
            let _ = unsafe { (self.library.functions.abort_pipe)(self.handle, FT601_WRITE_PIPE) };
        }
        let release = status(
            unsafe { (self.library.functions.release_overlapped)(self.handle, &mut overlapped) },
            "FT_ReleaseOverlapped(OUT)",
        );
        if release.is_err() {
            self.io_poisoned = true;
            let _ = unsafe { (self.library.functions.abort_pipe)(self.handle, FT601_WRITE_PIPE) };
        }
        transfer_result?;
        release?;
        if transferred as usize != message.len() {
            self.io_poisoned = true;
            let _ = unsafe { (self.library.functions.abort_pipe)(self.handle, FT601_WRITE_PIPE) };
            return Err(invalid_data("D3XX control write was short"));
        }
        Ok(())
    }

    pub fn shutdown(mut self) -> io::Result<()> {
        let result = self.close_checked();
        self.handle = null_mut();
        self.read_stream_configured = false;
        self.write_ready = false;
        result
    }

    fn read_usb_descriptors(&mut self) -> io::Result<Ft601UsbDescriptorEvidence> {
        let mut device = FtDeviceDescriptor::default();
        let mut configuration = FtConfigurationDescriptor::default();
        let mut interface = FtInterfaceDescriptor::default();
        let mut out_pipe = FtPipeInformation::default();
        let mut in_pipe = FtPipeInformation::default();
        status(
            unsafe { (self.library.functions.get_device_descriptor)(self.handle, &mut device) },
            "FT_GetDeviceDescriptor",
        )?;
        status(
            unsafe {
                (self.library.functions.get_configuration_descriptor)(
                    self.handle,
                    &mut configuration,
                )
            },
            "FT_GetConfigurationDescriptor",
        )?;
        status(
            unsafe {
                (self.library.functions.get_interface_descriptor)(
                    self.handle,
                    FT601_DATA_INTERFACE,
                    &mut interface,
                )
            },
            "FT_GetInterfaceDescriptor",
        )?;
        status(
            unsafe {
                (self.library.functions.get_pipe_information)(
                    self.handle,
                    FT601_DATA_INTERFACE,
                    FT601_OUT_PIPE_INDEX,
                    &mut out_pipe,
                )
            },
            "FT_GetPipeInformation(OUT)",
        )?;
        status(
            unsafe {
                (self.library.functions.get_pipe_information)(
                    self.handle,
                    FT601_DATA_INTERFACE,
                    FT601_IN_PIPE_INDEX,
                    &mut in_pipe,
                )
            },
            "FT_GetPipeInformation(IN)",
        )?;

        validate_raw_usb_descriptors(&device, &configuration, &interface, &out_pipe, &in_pipe)?;

        let descriptor_sha256 =
            hash_usb_descriptors(&device, &configuration, &interface, &out_pipe, &in_pipe);
        Ok(Ft601UsbDescriptorEvidence {
            bcd_usb: device.bcd_usb,
            bcd_device: device.bcd_device,
            vendor_id: device.vendor_id,
            product_id: device.product_id,
            configuration_count: device.configuration_count,
            interface_count: configuration.interface_count,
            configuration_attributes: configuration.attributes,
            max_power: configuration.max_power,
            data_interface_number: interface.interface_number,
            data_endpoint_count: interface.endpoint_count,
            out_pipe_type: out_pipe.pipe_type,
            out_pipe_id: out_pipe.pipe_id,
            out_maximum_packet_size: out_pipe.maximum_packet_size,
            in_pipe_type: in_pipe.pipe_type,
            in_pipe_id: in_pipe.pipe_id,
            in_maximum_packet_size: in_pipe.maximum_packet_size,
            descriptor_sha256,
        })
    }

    fn read_configuration(&mut self) -> io::Result<Ft601ConfigurationEvidence> {
        let mut configuration = Ft60xConfiguration::default();
        status(
            unsafe {
                (self.library.functions.get_chip_configuration)(
                    self.handle,
                    (&mut configuration as *mut Ft60xConfiguration).cast(),
                )
            },
            "FT_GetChipConfiguration",
        )?;
        let raw = unsafe {
            std::slice::from_raw_parts(
                (&configuration as *const Ft60xConfiguration).cast::<u8>(),
                std::mem::size_of::<Ft60xConfiguration>(),
            )
        };
        Ok(Ft601ConfigurationEvidence {
            vendor_id: configuration.vendor_id,
            product_id: configuration.product_id,
            fifo_clock_raw: configuration.fifo_clock,
            fifo_mode_raw: configuration.fifo_mode,
            channel_config_raw: configuration.channel_config,
            readback_sha256: Sha256::digest(raw).into(),
        })
    }

    fn close(&mut self) {
        if self.handle.is_null() {
            return;
        }
        if !self.pending_reads.is_empty() {
            let _ = unsafe { (self.library.functions.abort_pipe)(self.handle, FT601_READ_PIPE) };
            while let Some(mut pending) = self.pending_reads.pop_front() {
                let _ = unsafe {
                    (self.library.functions.release_overlapped)(
                        self.handle,
                        pending.overlapped.as_mut(),
                    )
                };
            }
        }
        if self.read_stream_configured || self.write_ready {
            for pipe in [FT601_READ_PIPE, FT601_WRITE_PIPE] {
                let _ = unsafe { (self.library.functions.abort_pipe)(self.handle, pipe) };
            }
        }
        if self.read_stream_configured {
            let _ = unsafe {
                (self.library.functions.clear_stream_pipe)(self.handle, 0, 0, FT601_READ_PIPE)
            };
        }
        let _ = unsafe { (self.library.functions.close)(self.handle) };
        self.handle = null_mut();
        self.read_stream_configured = false;
        self.write_ready = false;
    }

    fn close_checked(&mut self) -> io::Result<()> {
        if self.handle.is_null() {
            return Ok(());
        }
        let mut first_error = self.cancel_queued_reads().err();
        if self.read_stream_configured || self.write_ready {
            for (value, operation) in [
                (
                    unsafe { (self.library.functions.abort_pipe)(self.handle, FT601_READ_PIPE) },
                    "FT_AbortPipe(IN)",
                ),
                (
                    unsafe { (self.library.functions.abort_pipe)(self.handle, FT601_WRITE_PIPE) },
                    "FT_AbortPipe(OUT)",
                ),
            ] {
                if value != FT_OK && first_error.is_none() {
                    first_error = Some(status_error(value, operation));
                }
            }
        }
        if self.read_stream_configured {
            let value = unsafe {
                (self.library.functions.clear_stream_pipe)(self.handle, 0, 0, FT601_READ_PIPE)
            };
            if value != FT_OK && first_error.is_none() {
                first_error = Some(status_error(value, "FT_ClearStreamPipe(IN)"));
            }
        }
        let close_status = unsafe { (self.library.functions.close)(self.handle) };
        if close_status != FT_OK && first_error.is_none() {
            first_error = Some(status_error(close_status, "FT_Close"));
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

impl Drop for D3xxDevice {
    fn drop(&mut self) {
        self.close();
    }
}

fn validate_outbound_control(message: &[u8]) -> io::Result<()> {
    let decoded = decode_low_speed(message)
        .map_err(|_| invalid_data("D3XX OUT message is not exact protocol v1"))?;
    match decoded.kind {
        MessageKind::RunCommand => {
            let command = RunCommandV1::decode_body(&decoded.body)
                .map_err(|_| invalid_data("D3XX OUT RunCommand is invalid"))?;
            if command.scope != 1 || !(1..=5).contains(&command.command) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "M3 D3XX adapter admits only acquisition Prepare through Abort commands",
                ));
            }
            Ok(())
        }
        MessageKind::ReplayRequest => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "message kind is not admitted on the M3 D3XX OUT pipe",
        )),
    }
}

pub fn select_unique_ft601<'a>(
    devices: &'a [D3xxDeviceInfo],
    serial_number: &str,
) -> io::Result<&'a D3xxDeviceInfo> {
    validate_serial(serial_number)?;
    let mut matches = devices
        .iter()
        .filter(|device| device.device_type == FT_DEVICE_601)
        .filter(|device| device.serial_number == serial_number);
    let selected = matches.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no FT601 has the requested unique serial number",
        )
    })?;
    if matches.next().is_some() {
        return Err(invalid_data("duplicate FT601 serial number"));
    }
    Ok(selected)
}

pub fn validate_ft601_device_state(device: &D3xxDeviceInfo) -> io::Result<()> {
    if device.device_type != FT_DEVICE_601 {
        return Err(invalid_data("selected device is not an FT601"));
    }
    if device.opened() {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "selected FT601 is already open",
        ));
    }
    if !device.superspeed() {
        return Err(invalid_data(
            "selected FT601 is not enumerated at SuperSpeed",
        ));
    }
    Ok(())
}

pub fn validate_ft601_configuration(
    evidence: &Ft601ConfigurationEvidence,
    expected_readback_sha256: Hash32,
    profile: Ft601FifoClockProfile,
) -> io::Result<()> {
    if expected_readback_sha256 == [0; 32] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "an approved nonzero FT601 configuration readback hash is required",
        ));
    }
    let expected_fifo_clock = match profile {
        Ft601FifoClockProfile::Bringup66Mhz => CONFIGURATION_FIFO_CLOCK_66_MHZ,
        Ft601FifoClockProfile::Release100Mhz => CONFIGURATION_FIFO_CLOCK_100_MHZ,
    };
    if evidence.fifo_clock_raw != expected_fifo_clock
        || evidence.fifo_mode_raw != CONFIGURATION_FIFO_MODE_245
        || evidence.channel_config_raw != CONFIGURATION_CHANNEL_CONFIG_1
        || evidence.readback_sha256 != expected_readback_sha256
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "FT601 configuration readback does not match the admitted clock/profile image",
        ));
    }
    Ok(())
}

pub fn validate_ft601_usb_descriptors(
    descriptors: &Ft601UsbDescriptorEvidence,
    configuration: &Ft601ConfigurationEvidence,
    expected_descriptor_sha256: Hash32,
) -> io::Result<()> {
    if expected_descriptor_sha256 == [0; 32] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "an approved nonzero FT601 USB descriptor hash is required",
        ));
    }
    if descriptors.vendor_id != configuration.vendor_id
        || descriptors.product_id != configuration.product_id
        || descriptors.descriptor_sha256 != expected_descriptor_sha256
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "FT601 USB descriptors do not match the admission receipt or configuration",
        ));
    }
    Ok(())
}

fn validate_raw_usb_descriptors(
    device: &FtDeviceDescriptor,
    configuration: &FtConfigurationDescriptor,
    interface: &FtInterfaceDescriptor,
    out_pipe: &FtPipeInformation,
    in_pipe: &FtPipeInformation,
) -> io::Result<()> {
    if device.length != 18
        || device.descriptor_type != USB_DEVICE_DESCRIPTOR_TYPE
        || device.bcd_usb < 0x0300
        || device.max_packet_size0 != 9
        || device.vendor_id == 0
        || device.product_id == 0
        || device.configuration_count != 1
        || configuration.length != 9
        || configuration.descriptor_type != USB_CONFIGURATION_DESCRIPTOR_TYPE
        || configuration.total_length < 32
        || configuration.interface_count != 2
        || configuration.configuration_value == 0
        || configuration.attributes & 0xc0 != 0xc0
        || interface.length != 9
        || interface.descriptor_type != USB_INTERFACE_DESCRIPTOR_TYPE
        || interface.interface_number != FT601_DATA_INTERFACE
        || interface.alternate_setting != 0
        || interface.endpoint_count != 2
        || out_pipe.pipe_type != FT_PIPE_TYPE_BULK
        || out_pipe.pipe_id != FT601_WRITE_PIPE
        || in_pipe.pipe_type != FT_PIPE_TYPE_BULK
        || in_pipe.pipe_id != FT601_READ_PIPE
    {
        return Err(invalid_data(
            "FT601 USB descriptor topology is not the released self-powered one-channel shape",
        ));
    }
    Ok(())
}

fn hash_usb_descriptors(
    device: &FtDeviceDescriptor,
    configuration: &FtConfigurationDescriptor,
    interface: &FtInterfaceDescriptor,
    out_pipe: &FtPipeInformation,
    in_pipe: &FtPipeInformation,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(b"FGRUSBD1");
    bytes.extend_from_slice(&[device.length, device.descriptor_type]);
    bytes.extend_from_slice(&device.bcd_usb.to_le_bytes());
    bytes.extend_from_slice(&[
        device.device_class,
        device.device_subclass,
        device.device_protocol,
        device.max_packet_size0,
    ]);
    bytes.extend_from_slice(&device.vendor_id.to_le_bytes());
    bytes.extend_from_slice(&device.product_id.to_le_bytes());
    bytes.extend_from_slice(&device.bcd_device.to_le_bytes());
    bytes.extend_from_slice(&[
        device.manufacturer_index,
        device.product_index,
        device.serial_index,
        device.configuration_count,
        configuration.length,
        configuration.descriptor_type,
    ]);
    bytes.extend_from_slice(&configuration.total_length.to_le_bytes());
    bytes.extend_from_slice(&[
        configuration.interface_count,
        configuration.configuration_value,
        configuration.configuration_index,
        configuration.attributes,
        configuration.max_power,
        interface.length,
        interface.descriptor_type,
        interface.interface_number,
        interface.alternate_setting,
        interface.endpoint_count,
        interface.interface_class,
        interface.interface_subclass,
        interface.interface_protocol,
        interface.interface_index,
    ]);
    for pipe in [out_pipe, in_pipe] {
        bytes.extend_from_slice(&pipe.pipe_type.to_le_bytes());
        bytes.push(pipe.pipe_id);
        bytes.extend_from_slice(&pipe.maximum_packet_size.to_le_bytes());
        bytes.push(pipe.interval);
    }
    Sha256::digest(bytes).into()
}

fn validate_serial(serial: &str) -> io::Result<()> {
    if serial.is_empty()
        || serial.len() > 15
        || !serial
            .bytes()
            .all(|value| value.is_ascii_graphic() && value != b'\\')
    {
        return Err(invalid_input("invalid production FT601 serial number"));
    }
    Ok(())
}

fn validate_async_read_shape(buffer_bytes: usize, queued_reads: usize) -> io::Result<()> {
    if !(MIN_ASYNC_READ_BYTES..=MAX_ASYNC_READ_BYTES).contains(&buffer_bytes)
        || !buffer_bytes.is_multiple_of(1_024)
    {
        return Err(invalid_input(
            "D3XX async read size must be a bounded 1024-byte multiple",
        ));
    }
    if queued_reads >= MAX_ASYNC_READ_QUEUE_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "D3XX async read queue is at its fixed maximum depth",
        ));
    }
    Ok(())
}

fn fixed_ascii<const N: usize>(bytes: &[i8; N], field: &str) -> io::Result<String> {
    let length = bytes.iter().position(|value| *value == 0).unwrap_or(N);
    let value: Vec<u8> = bytes[..length].iter().map(|value| *value as u8).collect();
    if value
        .iter()
        .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
    {
        return Err(invalid_data_owned(format!(
            "D3XX {field} is not printable ASCII"
        )));
    }
    String::from_utf8(value).map_err(|_| invalid_data_owned(format!("D3XX {field} is invalid")))
}

fn status(value: u32, operation: &'static str) -> io::Result<()> {
    if value == FT_OK {
        Ok(())
    } else {
        Err(status_error(value, operation))
    }
}

fn status_error(value: u32, operation: &'static str) -> io::Error {
    io::Error::other(format!("{operation} failed with FT_STATUS {value}"))
}

unsafe fn symbol<T: Copy>(module: HMODULE, name: &'static [u8]) -> io::Result<T> {
    let value = GetProcAddress(module, name.as_ptr());
    let value = value.ok_or_else(io::Error::last_os_error)?;
    Ok(std::mem::transmute_copy(&value))
}

fn module_path(module: HMODULE) -> io::Result<PathBuf> {
    let mut buffer = vec![0_u16; 32_768];
    let length = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(String::from_utf16(&buffer).map_err(
        |_| invalid_data("D3XX module path is not valid UTF-16"),
    )?))
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let value: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if value[..value.len() - 1].contains(&0) {
        return Err(invalid_input("D3XX library path contains NUL"));
    }
    Ok(value)
}

fn sha256_file(path: &Path) -> io::Result<Hash32> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(hasher.finalize().into())
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_data_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_protocol_v1::{encode_low_speed, AckV1};
    use std::collections::VecDeque;
    use std::sync::{Mutex, OnceLock};

    #[derive(Default)]
    struct MockD3xxState {
        read_statuses: VecDeque<u32>,
        poll_results: VecDeque<(u32, u32)>,
        initialize_count: usize,
        release_count: usize,
        abort_count: usize,
        write_count: usize,
    }

    fn mock_state() -> &'static Mutex<MockD3xxState> {
        static STATE: OnceLock<Mutex<MockD3xxState>> = OnceLock::new();
        STATE.get_or_init(|| Mutex::new(MockD3xxState::default()))
    }

    unsafe extern "system" fn mock_create_device_info_list(count: *mut u32) -> u32 {
        *count = 0;
        FT_OK
    }

    unsafe extern "system" fn mock_get_device_info_detail(
        _index: u32,
        _flags: *mut u32,
        _device_type: *mut u32,
        _usb_id: *mut u32,
        _location: *mut u32,
        _serial: *mut c_char,
        _description: *mut c_char,
        _handle: *mut FtHandle,
    ) -> u32 {
        FT_OK
    }

    unsafe extern "system" fn mock_create(
        _identity: *mut c_void,
        _flags: u32,
        _handle: *mut FtHandle,
    ) -> u32 {
        FT_OK
    }

    unsafe extern "system" fn mock_handle_only(_handle: FtHandle) -> u32 {
        FT_OK
    }

    unsafe extern "system" fn mock_get_configuration(
        _handle: FtHandle,
        _configuration: *mut c_void,
    ) -> u32 {
        FT_OK
    }

    unsafe extern "system" fn mock_get_device_descriptor(
        _handle: FtHandle,
        _descriptor: *mut FtDeviceDescriptor,
    ) -> u32 {
        FT_OK
    }

    unsafe extern "system" fn mock_get_configuration_descriptor(
        _handle: FtHandle,
        _descriptor: *mut FtConfigurationDescriptor,
    ) -> u32 {
        FT_OK
    }

    unsafe extern "system" fn mock_get_interface_descriptor(
        _handle: FtHandle,
        _interface: u8,
        _descriptor: *mut FtInterfaceDescriptor,
    ) -> u32 {
        FT_OK
    }

    unsafe extern "system" fn mock_get_pipe_information(
        _handle: FtHandle,
        _interface: u8,
        _index: u8,
        _information: *mut FtPipeInformation,
    ) -> u32 {
        FT_OK
    }

    unsafe extern "system" fn mock_set_stream_pipe(
        _handle: FtHandle,
        _all_write: i32,
        _all_read: i32,
        _pipe: u8,
        _bytes: u32,
    ) -> u32 {
        FT_OK
    }

    unsafe extern "system" fn mock_clear_stream_pipe(
        _handle: FtHandle,
        _all_write: i32,
        _all_read: i32,
        _pipe: u8,
    ) -> u32 {
        FT_OK
    }

    unsafe extern "system" fn mock_set_pipe_timeout(
        _handle: FtHandle,
        _pipe: u8,
        _timeout: u32,
    ) -> u32 {
        FT_OK
    }

    unsafe extern "system" fn mock_abort_pipe(_handle: FtHandle, _pipe: u8) -> u32 {
        mock_state().lock().unwrap().abort_count += 1;
        FT_OK
    }

    unsafe extern "system" fn mock_initialize_overlapped(
        _handle: FtHandle,
        _overlapped: *mut OVERLAPPED,
    ) -> u32 {
        mock_state().lock().unwrap().initialize_count += 1;
        FT_OK
    }

    unsafe extern "system" fn mock_release_overlapped(
        _handle: FtHandle,
        _overlapped: *mut OVERLAPPED,
    ) -> u32 {
        mock_state().lock().unwrap().release_count += 1;
        FT_OK
    }

    unsafe extern "system" fn mock_read_pipe_ex(
        _handle: FtHandle,
        _pipe: u8,
        _buffer: *mut u8,
        _length: u32,
        transferred: *mut u32,
        _overlapped: *mut OVERLAPPED,
    ) -> u32 {
        *transferred = 0;
        mock_state()
            .lock()
            .unwrap()
            .read_statuses
            .pop_front()
            .unwrap_or(FT_IO_PENDING)
    }

    unsafe extern "system" fn mock_write_pipe_ex(
        _handle: FtHandle,
        _pipe: u8,
        _buffer: *mut u8,
        length: u32,
        transferred: *mut u32,
        _overlapped: *mut OVERLAPPED,
    ) -> u32 {
        *transferred = length;
        mock_state().lock().unwrap().write_count += 1;
        FT_OK
    }

    unsafe extern "system" fn mock_get_overlapped_result(
        _handle: FtHandle,
        _overlapped: *mut OVERLAPPED,
        transferred: *mut u32,
        wait: i32,
    ) -> u32 {
        assert_eq!(wait, 0);
        let (status, bytes) = mock_state()
            .lock()
            .unwrap()
            .poll_results
            .pop_front()
            .unwrap();
        *transferred = bytes;
        status
    }

    fn mock_device() -> D3xxDevice {
        let functions = D3xxFunctions {
            create_device_info_list: mock_create_device_info_list,
            get_device_info_detail: mock_get_device_info_detail,
            create: mock_create,
            close: mock_handle_only,
            get_chip_configuration: mock_get_configuration,
            get_device_descriptor: mock_get_device_descriptor,
            get_configuration_descriptor: mock_get_configuration_descriptor,
            get_interface_descriptor: mock_get_interface_descriptor,
            get_pipe_information: mock_get_pipe_information,
            set_stream_pipe: mock_set_stream_pipe,
            clear_stream_pipe: mock_clear_stream_pipe,
            set_pipe_timeout: mock_set_pipe_timeout,
            abort_pipe: mock_abort_pipe,
            initialize_overlapped: mock_initialize_overlapped,
            release_overlapped: mock_release_overlapped,
            read_pipe_ex: mock_read_pipe_ex,
            write_pipe_ex: mock_write_pipe_ex,
            get_overlapped_result: mock_get_overlapped_result,
        };
        D3xxDevice {
            library: Arc::new(D3xxLibrary {
                _module: OwnedModule(null_mut()),
                functions,
                source_path: PathBuf::from("mock-ftd3xx.dll"),
                library_sha256: [0; 32],
            }),
            handle: 1_usize as FtHandle,
            read_stream_configured: true,
            write_ready: true,
            pending_reads: VecDeque::new(),
            io_poisoned: false,
        }
    }

    fn device(device_type: u32, serial: &str, flags: u32) -> D3xxDeviceInfo {
        D3xxDeviceInfo {
            flags,
            device_type,
            usb_id: 0x0403_601f,
            location_id: 1,
            serial_number: serial.to_owned(),
            description: "Forge Receiver Pod".to_owned(),
        }
    }

    #[test]
    fn official_ft60x_configuration_layout_is_exact() {
        assert_eq!(std::mem::size_of::<Ft60xConfiguration>(), 152);
        assert_eq!(std::mem::offset_of!(Ft60xConfiguration, fifo_clock), 137);
        assert_eq!(std::mem::offset_of!(Ft60xConfiguration, fifo_mode), 138);
        assert_eq!(
            std::mem::offset_of!(Ft60xConfiguration, channel_config),
            139
        );
    }

    #[test]
    fn official_usb_descriptor_layouts_are_exact() {
        assert_eq!(std::mem::size_of::<FtDeviceDescriptor>(), 18);
        assert_eq!(std::mem::size_of::<FtConfigurationDescriptor>(), 10);
        assert_eq!(std::mem::size_of::<FtInterfaceDescriptor>(), 9);
        assert_eq!(std::mem::size_of::<FtPipeInformation>(), 12);
        assert_eq!(std::mem::offset_of!(FtPipeInformation, pipe_id), 4);
        assert_eq!(
            std::mem::offset_of!(FtPipeInformation, maximum_packet_size),
            6
        );
    }

    #[test]
    fn asynchronous_read_queue_is_fixed_and_page_aligned() {
        assert!(validate_async_read_shape(256 * 1024, 0).is_ok());
        assert!(validate_async_read_shape(MIN_ASYNC_READ_BYTES, 0).is_ok());
        assert!(validate_async_read_shape(MAX_ASYNC_READ_BYTES, 0).is_ok());
        assert_eq!(
            validate_async_read_shape(1, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            validate_async_read_shape(1_025, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            validate_async_read_shape(256 * 1024, MAX_ASYNC_READ_QUEUE_DEPTH)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(FT_IO_PENDING, 24);
        assert_eq!(FT_IO_INCOMPLETE, 25);
    }

    #[test]
    fn asynchronous_duplex_queue_polls_in_order_and_releases_every_resource() {
        *mock_state().lock().unwrap() = MockD3xxState {
            read_statuses: VecDeque::from([FT_IO_PENDING, FT_IO_PENDING, FT_IO_PENDING]),
            poll_results: VecDeque::from([(FT_IO_INCOMPLETE, 0), (FT_OK, 3), (FT_OK, 2)]),
            ..MockD3xxState::default()
        };
        let mut device = mock_device();
        device.queue_read(1_024).unwrap();
        device.queue_read(1_024).unwrap();
        assert_eq!(device.queued_read_count(), 2);
        assert_eq!(device.poll_next_read().unwrap(), D3xxReadPoll::Pending);

        let control = encode_low_speed(
            0,
            7,
            11,
            &RunCommandV1 {
                command: 3,
                scope: 1,
                run_id: [1; 16],
                target_device_id: [2; 16],
                deadline_global_time_ns: 99,
                frozen_config_hash: [3; 32],
            },
        )
        .unwrap();
        device.write_control(&control).unwrap();

        assert_eq!(
            device.poll_next_read().unwrap(),
            D3xxReadPoll::Complete(vec![0; 3])
        );
        assert_eq!(
            device.poll_next_read().unwrap(),
            D3xxReadPoll::Complete(vec![0; 2])
        );
        assert_eq!(device.poll_next_read().unwrap(), D3xxReadPoll::Idle);
        assert_eq!(device.queued_read_count(), 0);

        device.queue_read(1_024).unwrap();
        device.cancel_queued_reads().unwrap();
        assert_eq!(device.queued_read_count(), 0);
        assert!(device.is_io_poisoned());
        device.shutdown().unwrap();

        let state = mock_state().lock().unwrap();
        assert_eq!(state.initialize_count, 4);
        assert_eq!(state.release_count, 4);
        assert_eq!(state.write_count, 1);
        assert!(state.abort_count >= 3);
    }

    #[test]
    fn selection_requires_exact_unique_ft601_serial() {
        let devices = [
            device(FT_DEVICE_601, "FORGEPOD000001", FT_FLAGS_SUPERSPEED),
            device(600, "LEGACYFT600001", FT_FLAGS_SUPERSPEED),
        ];
        assert_eq!(
            select_unique_ft601(&devices, "FORGEPOD000001")
                .unwrap()
                .device_type,
            FT_DEVICE_601
        );
        assert!(select_unique_ft601(&devices, "LEGACYFT600001").is_err());
        assert!(select_unique_ft601(&devices, "").is_err());
    }

    #[test]
    fn duplicate_serial_fails_closed() {
        let devices = [
            device(FT_DEVICE_601, "FORGEPOD000001", FT_FLAGS_SUPERSPEED),
            device(FT_DEVICE_601, "FORGEPOD000001", FT_FLAGS_SUPERSPEED),
        ];
        assert_eq!(
            select_unique_ft601(&devices, "FORGEPOD000001")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn relative_library_paths_are_never_searched() {
        let result = D3xxLibrary::load_absolute("FTD3XX.dll");
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidInput));
    }

    #[test]
    fn ft601_flags_are_separate_from_identity() {
        let opened = device(
            FT_DEVICE_601,
            "FORGEPOD000001",
            FT_FLAGS_OPENED | FT_FLAGS_SUPERSPEED,
        );
        assert!(opened.opened());
        assert!(opened.superspeed());
        assert_eq!(
            validate_ft601_device_state(&opened).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn configuration_gate_requires_exact_mode_and_nonzero_approved_hash() {
        let expected = [0x5a; 32];
        let evidence = Ft601ConfigurationEvidence {
            vendor_id: 0x0403,
            product_id: 0x601f,
            fifo_clock_raw: CONFIGURATION_FIFO_CLOCK_66_MHZ,
            fifo_mode_raw: CONFIGURATION_FIFO_MODE_245,
            channel_config_raw: CONFIGURATION_CHANNEL_CONFIG_1,
            readback_sha256: expected,
        };
        assert!(validate_ft601_configuration(
            &evidence,
            expected,
            Ft601FifoClockProfile::Bringup66Mhz
        )
        .is_ok());
        assert!(validate_ft601_configuration(
            &evidence,
            [0; 32],
            Ft601FifoClockProfile::Bringup66Mhz
        )
        .is_err());
        for field in 0..3 {
            let mut changed = evidence.clone();
            match field {
                0 => changed.fifo_clock_raw ^= 1,
                1 => changed.fifo_mode_raw ^= 1,
                _ => changed.channel_config_raw ^= 1,
            }
            assert!(validate_ft601_configuration(
                &changed,
                expected,
                Ft601FifoClockProfile::Bringup66Mhz
            )
            .is_err());
        }
        assert!(validate_ft601_configuration(
            &evidence,
            [0x5b; 32],
            Ft601FifoClockProfile::Bringup66Mhz
        )
        .is_err());
        assert!(validate_ft601_configuration(
            &evidence,
            expected,
            Ft601FifoClockProfile::Release100Mhz
        )
        .is_err());

        let mut release = evidence;
        release.fifo_clock_raw = CONFIGURATION_FIFO_CLOCK_100_MHZ;
        assert!(validate_ft601_configuration(
            &release,
            expected,
            Ft601FifoClockProfile::Release100Mhz
        )
        .is_ok());
    }

    #[test]
    fn descriptor_topology_and_receipt_hash_fail_closed() {
        let device = FtDeviceDescriptor {
            length: 18,
            descriptor_type: USB_DEVICE_DESCRIPTOR_TYPE,
            bcd_usb: 0x0300,
            max_packet_size0: 9,
            vendor_id: 0x0403,
            product_id: 0x601f,
            configuration_count: 1,
            ..FtDeviceDescriptor::default()
        };
        let configuration = FtConfigurationDescriptor {
            length: 9,
            descriptor_type: USB_CONFIGURATION_DESCRIPTOR_TYPE,
            total_length: 44,
            interface_count: 2,
            configuration_value: 1,
            attributes: 0xc0,
            ..FtConfigurationDescriptor::default()
        };
        let interface = FtInterfaceDescriptor {
            length: 9,
            descriptor_type: USB_INTERFACE_DESCRIPTOR_TYPE,
            interface_number: FT601_DATA_INTERFACE,
            endpoint_count: 2,
            ..FtInterfaceDescriptor::default()
        };
        let out_pipe = FtPipeInformation {
            pipe_type: FT_PIPE_TYPE_BULK,
            pipe_id: FT601_WRITE_PIPE,
            maximum_packet_size: 1_024,
            interval: 0,
        };
        let in_pipe = FtPipeInformation {
            pipe_type: FT_PIPE_TYPE_BULK,
            pipe_id: FT601_READ_PIPE,
            maximum_packet_size: 1_024,
            interval: 0,
        };
        validate_raw_usb_descriptors(&device, &configuration, &interface, &out_pipe, &in_pipe)
            .unwrap();
        let descriptor_sha256 =
            hash_usb_descriptors(&device, &configuration, &interface, &out_pipe, &in_pipe);
        let descriptor_evidence = Ft601UsbDescriptorEvidence {
            bcd_usb: device.bcd_usb,
            bcd_device: device.bcd_device,
            vendor_id: device.vendor_id,
            product_id: device.product_id,
            configuration_count: device.configuration_count,
            interface_count: configuration.interface_count,
            configuration_attributes: configuration.attributes,
            max_power: configuration.max_power,
            data_interface_number: interface.interface_number,
            data_endpoint_count: interface.endpoint_count,
            out_pipe_type: out_pipe.pipe_type,
            out_pipe_id: out_pipe.pipe_id,
            out_maximum_packet_size: out_pipe.maximum_packet_size,
            in_pipe_type: in_pipe.pipe_type,
            in_pipe_id: in_pipe.pipe_id,
            in_maximum_packet_size: in_pipe.maximum_packet_size,
            descriptor_sha256,
        };
        let configuration_evidence = Ft601ConfigurationEvidence {
            vendor_id: device.vendor_id,
            product_id: device.product_id,
            fifo_clock_raw: CONFIGURATION_FIFO_CLOCK_66_MHZ,
            fifo_mode_raw: CONFIGURATION_FIFO_MODE_245,
            channel_config_raw: CONFIGURATION_CHANNEL_CONFIG_1,
            readback_sha256: [8; 32],
        };
        validate_ft601_usb_descriptors(
            &descriptor_evidence,
            &configuration_evidence,
            descriptor_sha256,
        )
        .unwrap();
        assert!(validate_ft601_usb_descriptors(
            &descriptor_evidence,
            &configuration_evidence,
            [0; 32]
        )
        .is_err());

        let mut bus_powered = configuration;
        bus_powered.attributes = 0x80;
        assert!(validate_raw_usb_descriptors(
            &device,
            &bus_powered,
            &interface,
            &out_pipe,
            &in_pipe
        )
        .is_err());
        let mut wrong_pipe = in_pipe;
        wrong_pipe.pipe_id = 0x83;
        assert!(validate_raw_usb_descriptors(
            &device,
            &configuration,
            &interface,
            &out_pipe,
            &wrong_pipe
        )
        .is_err());
    }

    #[test]
    fn outbound_pipe_admits_only_exact_acquisition_control() {
        let acquisition = RunCommandV1 {
            command: 3,
            scope: 1,
            run_id: [1; 16],
            target_device_id: [2; 16],
            deadline_global_time_ns: 99,
            frozen_config_hash: [3; 32],
        };
        let encoded = encode_low_speed(0, 7, 11, &acquisition).unwrap();
        assert!(validate_outbound_control(&encoded).is_ok());

        let mut stimulation = acquisition.clone();
        stimulation.scope = 2;
        let stimulation = encode_low_speed(0, 8, 11, &stimulation).unwrap();
        assert_eq!(
            validate_outbound_control(&stimulation).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        for host_only_command in [6_u16, 7_u16] {
            let mut host_only = acquisition.clone();
            host_only.command = host_only_command;
            let encoded =
                encode_low_speed(0, 12 + u64::from(host_only_command), 11, &host_only).unwrap();
            assert_eq!(
                validate_outbound_control(&encoded).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }

        let reply = encode_low_speed(
            0,
            9,
            11,
            &AckV1 {
                acknowledged_request_id: 9,
                applied_epoch: 11,
                ack_code: 1,
                state_code: 2,
                receipt_hash: [4; 32],
            },
        )
        .unwrap();
        assert_eq!(
            validate_outbound_control(&reply).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        let mut corrupted = encoded;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert_eq!(
            validate_outbound_control(&corrupted).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
