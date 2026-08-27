use crate::{CodecError, PROTOCOL_HASH};

pub type Id16 = [u8; 16];
pub type Hash32 = [u8; 32];

pub const ZERO_ID: Id16 = [0; 16];
pub const ZERO_HASH: Hash32 = [0; 32];

pub const RECORD_HEADER_LEN: usize = 176;
pub const SAMPLE_BLOCK_HEADER_LEN: usize = 32;
pub const LOW_SPEED_HEADER_LEN: usize = 80;
pub const MAX_LOW_SPEED_MESSAGE_LEN: usize = 1_048_576;
pub const MAX_RECORD_PAYLOAD_LEN: usize = 1_048_576;

pub const RECORD_FLAG_DISCONTINUITY_BEFORE: u32 = 0x0000_0001;
pub const RECORD_FLAG_SOURCE_CRC_ERROR: u32 = 0x0000_0002;
pub const RECORD_FLAG_SOURCE_OVERFLOW: u32 = 0x0000_0004;
pub const RECORD_FLAG_CLOCK_UNLOCKED: u32 = 0x0000_0008;
pub const RECORD_FLAG_REPLAYED: u32 = 0x0000_0010;
pub const RECORD_FLAG_STIM_ARTIFACT: u32 = 0x0000_0020;
pub const RECORD_FLAGS_ALL: u32 = 0x0000_003f;

pub const SAMPLE_BLOCK_FLAG_COMPLETE: u32 = 0x0000_0001;
pub const SAMPLE_BLOCK_FLAG_HARDWARE_TIMESTAMPED: u32 = 0x0000_0002;
pub const SAMPLE_BLOCK_FLAGS_ALL: u32 = 0x0000_0003;

pub const CAP_ACK_REPLAY: u32 = 0x0000_0001;
pub const CAP_GLOBAL_TIME: u32 = 0x0000_0002;
pub const CAP_STOP_ACK: u32 = 0x0000_0004;
pub const CAP_STIM_RECEIPTS: u32 = 0x0000_0008;
pub const CAP_PHYSICAL_ENABLE_INTERLOCK: u32 = 0x0000_0010;
pub const CAP_PHYSICAL_INTERLOCK: u32 = CAP_PHYSICAL_ENABLE_INTERLOCK;
pub const CAP_HARDWARE_WATCHDOG: u32 = 0x0000_0020;
pub const CAP_NONCE_DEDUP: u32 = 0x0000_0040;
pub const CAP_NO_OVERLAP_STIM: u32 = 0x0000_0080;
pub const CAP_EMERGENCY_STOP_LOOP: u32 = 0x0000_0100;
pub const CAP_DEFAULT_OFF_STIM_POWER_GATE: u32 = 0x0000_0200;
pub const CAP_FLAGS_ALL: u32 = 0x0000_03ff;
pub const REQUIRED_STIM_CAPS: u32 = CAP_ACK_REPLAY
    | CAP_GLOBAL_TIME
    | CAP_STOP_ACK
    | CAP_STIM_RECEIPTS
    | CAP_PHYSICAL_ENABLE_INTERLOCK
    | CAP_HARDWARE_WATCHDOG
    | CAP_NONCE_DEDUP
    | CAP_NO_OVERLAP_STIM
    | CAP_EMERGENCY_STOP_LOOP
    | CAP_DEFAULT_OFF_STIM_POWER_GATE;

pub const RUNTIME_PHYSICAL_ENABLE_ASSERTED: u32 = 0x0000_0001;
pub const RUNTIME_INTERLOCK_CLOSED: u32 = RUNTIME_PHYSICAL_ENABLE_ASSERTED;
pub const RUNTIME_STIM_POWER_ENABLED: u32 = 0x0000_0002;
pub const RUNTIME_WATCHDOG_HEALTHY: u32 = 0x0000_0004;
pub const RUNTIME_COMPLIANCE_READY: u32 = 0x0000_0008;
pub const RUNTIME_CLOCK_LOCKED: u32 = 0x0000_0010;
pub const RUNTIME_LINK_HEALTHY: u32 = 0x0000_0020;
pub const RUNTIME_EMERGENCY_STOP_HEALTHY: u32 = 0x0000_0040;
pub const RUNTIME_FLAGS_ALL: u32 = 0x0000_007f;
pub const REQUIRED_STIM_RUNTIME: u32 = RUNTIME_PHYSICAL_ENABLE_ASSERTED
    | RUNTIME_STIM_POWER_ENABLED
    | RUNTIME_WATCHDOG_HEALTHY
    | RUNTIME_COMPLIANCE_READY
    | RUNTIME_CLOCK_LOCKED
    | RUNTIME_LINK_HEALTHY
    | RUNTIME_EMERGENCY_STOP_HEALTHY;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordKind {
    SampleBlock = 1,
    Marker = 2,
    Fault = 3,
    OnlineAnalysis = 4,
    StimIntent = 5,
    StimReceipt = 6,
}

impl TryFrom<u16> for RecordKind {
    type Error = CodecError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SampleBlock),
            2 => Ok(Self::Marker),
            3 => Ok(Self::Fault),
            4 => Ok(Self::OnlineAnalysis),
            5 => Ok(Self::StimIntent),
            6 => Ok(Self::StimReceipt),
            _ => Err(CodecError::UnknownKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageKind {
    DeviceCapabilities = 1,
    RunCommand = 2,
    SafetyProfile = 3,
    StimIntent = 4,
    StimCommand = 5,
    StimReceipt = 6,
    WorkerTokenLease = 7,
    Ack = 8,
    Nack = 9,
    ReplayRequest = 10,
}

impl MessageKind {
    pub fn body_len(self) -> usize {
        match self {
            Self::DeviceCapabilities => 84,
            Self::RunCommand => 80,
            Self::SafetyProfile => 288,
            Self::StimIntent => 240,
            Self::StimCommand => 232,
            Self::StimReceipt => 168,
            Self::WorkerTokenLease => 288,
            Self::Ack | Self::Nack => 60,
            Self::ReplayRequest => 96,
        }
    }
}

impl TryFrom<u16> for MessageKind {
    type Error = CodecError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DeviceCapabilities),
            2 => Ok(Self::RunCommand),
            3 => Ok(Self::SafetyProfile),
            4 => Ok(Self::StimIntent),
            5 => Ok(Self::StimCommand),
            6 => Ok(Self::StimReceipt),
            7 => Ok(Self::WorkerTokenLease),
            8 => Ok(Self::Ack),
            9 => Ok(Self::Nack),
            10 => Ok(Self::ReplayRequest),
            _ => Err(CodecError::UnknownKind),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRecordEnvelopeV1 {
    pub record_kind: RecordKind,
    pub flags: u32,
    pub run_id: Id16,
    pub pod_id: Id16,
    pub headstage_id: Id16,
    pub record_sequence: u64,
    pub frame_start: u64,
    pub frame_end_exclusive: u64,
    pub sample_start: u64,
    pub sample_end_exclusive: u64,
    pub global_time_start_ns: u64,
    pub global_time_end_exclusive_ns: u64,
    pub channel_layout_id: u32,
    pub channel_count: u16,
    pub sample_format: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleBlockV1 {
    pub flags: u32,
    pub samples_per_channel: u32,
    pub channel_count: u16,
    pub sample_format: u16,
    pub sample_rate_numerator_hz: u32,
    pub sample_rate_denominator: u32,
    pub first_sample_counter: u64,
    pub samples: Vec<i16>,
}

impl SampleBlockV1 {
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.flags & !SAMPLE_BLOCK_FLAGS_ALL != 0
            || self.samples_per_channel == 0
            || self.channel_count == 0
            || self.sample_format != 1
            || self.sample_rate_numerator_hz == 0
            || self.sample_rate_denominator == 0
        {
            return Err(CodecError::Invariant);
        }
        let expected = (self.samples_per_channel as usize)
            .checked_mul(self.channel_count as usize)
            .ok_or(CodecError::Length)?;
        if self.samples.len() != expected {
            return Err(CodecError::Length);
        }
        let mut out = Vec::with_capacity(SAMPLE_BLOCK_HEADER_LEN + expected * 2);
        put_u16(&mut out, 1);
        put_u16(&mut out, 32);
        put_u32(&mut out, self.flags);
        put_u32(&mut out, self.samples_per_channel);
        put_u16(&mut out, self.channel_count);
        put_u16(&mut out, self.sample_format);
        put_u32(&mut out, self.sample_rate_numerator_hz);
        put_u32(&mut out, self.sample_rate_denominator);
        put_u64(&mut out, self.first_sample_counter);
        for sample in &self.samples {
            out.extend_from_slice(&sample.to_le_bytes());
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < SAMPLE_BLOCK_HEADER_LEN {
            return Err(CodecError::Length);
        }
        if le_u16(bytes, 0)? != 1 {
            return Err(CodecError::Version);
        }
        if le_u16(bytes, 2)? as usize != SAMPLE_BLOCK_HEADER_LEN {
            return Err(CodecError::Length);
        }
        let flags = le_u32(bytes, 4)?;
        let samples_per_channel = le_u32(bytes, 8)?;
        let channel_count = le_u16(bytes, 12)?;
        let sample_format = le_u16(bytes, 14)?;
        let sample_rate_numerator_hz = le_u32(bytes, 16)?;
        let sample_rate_denominator = le_u32(bytes, 20)?;
        let first_sample_counter = le_u64(bytes, 24)?;
        let count = (samples_per_channel as usize)
            .checked_mul(channel_count as usize)
            .ok_or(CodecError::Length)?;
        let expected = SAMPLE_BLOCK_HEADER_LEN
            .checked_add(count.checked_mul(2).ok_or(CodecError::Length)?)
            .ok_or(CodecError::Length)?;
        if bytes.len() != expected {
            return Err(CodecError::Length);
        }
        let mut samples = Vec::with_capacity(count);
        for chunk in bytes[SAMPLE_BLOCK_HEADER_LEN..].chunks_exact(2) {
            samples.push(i16::from_le_bytes([chunk[0], chunk[1]]));
        }
        let block = Self {
            flags,
            samples_per_channel,
            channel_count,
            sample_format,
            sample_rate_numerator_hz,
            sample_rate_denominator,
            first_sample_counter,
            samples,
        };
        block.encode()?;
        Ok(block)
    }
}

pub trait WireBody: Sized {
    const KIND: MessageKind;
    fn encode_body(&self) -> Result<Vec<u8>, CodecError>;
    fn decode_body(bytes: &[u8]) -> Result<Self, CodecError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCapabilitiesV1 {
    pub device_id: Id16,
    pub transport: u8,
    pub max_pods: u8,
    pub max_channels_per_pod: u16,
    pub sample_format_mask: u32,
    pub min_sample_rate_hz: u32,
    pub max_sample_rate_hz: u32,
    pub stim_kind: u16,
    pub stim_channels: u16,
    pub max_sample_block_us: u32,
    pub capability_flags: u32,
    pub runtime_safety_flags: u32,
    pub hardware_protocol_hash: Hash32,
}

impl WireBody for DeviceCapabilitiesV1 {
    const KIND: MessageKind = MessageKind::DeviceCapabilities;
    fn encode_body(&self) -> Result<Vec<u8>, CodecError> {
        if !(1..=3).contains(&self.transport)
            || self.max_pods == 0
            || self.max_pods > 8
            || (self.transport == 1 && self.max_pods != 1)
            || self.max_channels_per_pod == 0
            || self.max_channels_per_pod > 256
            || self.sample_format_mask & !1 != 0
            || self.sample_format_mask == 0
            || self.min_sample_rate_hz == 0
            || self.min_sample_rate_hz > self.max_sample_rate_hz
            || !matches!(self.stim_kind, 0 | 1)
            || (self.stim_kind == 0 && self.stim_channels != 0)
            || (self.stim_kind == 1 && self.stim_channels != 16)
            || self.max_sample_block_us == 0
            || self.capability_flags & !CAP_FLAGS_ALL != 0
            || self.runtime_safety_flags & !RUNTIME_FLAGS_ALL != 0
        {
            return Err(CodecError::Invariant);
        }
        let mut out = body_prefix(84);
        out.extend_from_slice(&self.device_id);
        out.push(self.transport);
        out.push(self.max_pods);
        put_u16(&mut out, self.max_channels_per_pod);
        put_u32(&mut out, self.sample_format_mask);
        put_u32(&mut out, self.min_sample_rate_hz);
        put_u32(&mut out, self.max_sample_rate_hz);
        put_u16(&mut out, self.stim_kind);
        put_u16(&mut out, self.stim_channels);
        put_u32(&mut out, self.max_sample_block_us);
        put_u32(&mut out, self.capability_flags);
        put_u32(&mut out, self.runtime_safety_flags);
        out.extend_from_slice(&self.hardware_protocol_hash);
        debug_assert_eq!(out.len(), 84);
        Ok(out)
    }
    fn decode_body(b: &[u8]) -> Result<Self, CodecError> {
        check_body(b, 84)?;
        let value = Self {
            device_id: arr16(b, 4)?,
            transport: b[20],
            max_pods: b[21],
            max_channels_per_pod: le_u16(b, 22)?,
            sample_format_mask: le_u32(b, 24)?,
            min_sample_rate_hz: le_u32(b, 28)?,
            max_sample_rate_hz: le_u32(b, 32)?,
            stim_kind: le_u16(b, 36)?,
            stim_channels: le_u16(b, 38)?,
            max_sample_block_us: le_u32(b, 40)?,
            capability_flags: le_u32(b, 44)?,
            runtime_safety_flags: le_u32(b, 48)?,
            hardware_protocol_hash: arr32(b, 52)?,
        };
        value.encode_body()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCommandV1 {
    pub command: u16,
    pub scope: u16,
    pub run_id: Id16,
    pub target_device_id: Id16,
    pub deadline_global_time_ns: u64,
    pub frozen_config_hash: Hash32,
}
impl WireBody for RunCommandV1 {
    const KIND: MessageKind = MessageKind::RunCommand;
    fn encode_body(&self) -> Result<Vec<u8>, CodecError> {
        if !(1..=7).contains(&self.command)
            || !matches!(self.scope, 1 | 2)
            || is_zero_id(&self.run_id)
            || is_zero_id(&self.target_device_id)
            || self.deadline_global_time_ns == 0
            || is_zero_hash(&self.frozen_config_hash)
        {
            return Err(CodecError::Invariant);
        }
        let mut o = body_prefix(80);
        put_u16(&mut o, self.command);
        put_u16(&mut o, self.scope);
        o.extend_from_slice(&self.run_id);
        o.extend_from_slice(&self.target_device_id);
        put_u64(&mut o, self.deadline_global_time_ns);
        o.extend_from_slice(&self.frozen_config_hash);
        Ok(o)
    }
    fn decode_body(b: &[u8]) -> Result<Self, CodecError> {
        check_body(b, 80)?;
        let v = Self {
            command: le_u16(b, 4)?,
            scope: le_u16(b, 6)?,
            run_id: arr16(b, 8)?,
            target_device_id: arr16(b, 24)?,
            deadline_global_time_ns: le_u64(b, 40)?,
            frozen_config_hash: arr32(b, 48)?,
        };
        v.encode_body()?;
        Ok(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyProfileV1 {
    pub profile_id: Id16,
    pub approval_state: u8,
    pub electrode_material: u8,
    pub recovery_policy: u16,
    pub wire_diameter_nm: u32,
    pub exposed_area_um2: u32,
    pub impedance_min_ohm: u32,
    pub impedance_max_ohm: u32,
    pub max_current_na: u32,
    pub max_phase_width_us: u32,
    pub min_interphase_us: u32,
    pub max_frequency_millihz: u32,
    pub max_train_pulses: u32,
    pub max_train_duration_ms: u32,
    pub max_duty_cycle_ppm: u32,
    pub max_charge_per_phase_pc: u64,
    pub max_charge_density_pc_per_mm2: u64,
    pub compliance_min_uv: i32,
    pub compliance_max_uv: i32,
    pub experiment_protocol_hash: Hash32,
    pub electrode_geometry_hash: Hash32,
    pub hardware_build_hash: Hash32,
    pub software_build_hash: Hash32,
    pub approved_limits_hash: Hash32,
    pub approval_authority_hash: Hash32,
}
impl SafetyProfileV1 {
    pub fn validate_approved(&self) -> Result<(), CodecError> {
        if self.approval_state != 1
            || is_zero_id(&self.profile_id)
            || !matches!(self.electrode_material, 1..=5 | 255)
            || self.recovery_policy < 1
            || self.recovery_policy > 2
            || self.wire_diameter_nm == 0
            || self.exposed_area_um2 == 0
            || self.impedance_min_ohm == 0
            || self.impedance_min_ohm > self.impedance_max_ohm
            || self.max_current_na == 0
            || self.max_phase_width_us == 0
            || self.min_interphase_us == 0
            || self.max_frequency_millihz == 0
            || self.max_train_pulses == 0
            || self.max_train_duration_ms == 0
            || self.max_duty_cycle_ppm == 0
            || self.max_duty_cycle_ppm > 1_000_000
            || self.max_charge_per_phase_pc == 0
            || self.max_charge_density_pc_per_mm2 == 0
            || self.compliance_min_uv >= self.compliance_max_uv
            || [
                self.experiment_protocol_hash,
                self.electrode_geometry_hash,
                self.hardware_build_hash,
                self.software_build_hash,
                self.approved_limits_hash,
                self.approval_authority_hash,
            ]
            .iter()
            .any(is_zero_hash)
        {
            return Err(CodecError::Invariant);
        }
        Ok(())
    }
}
impl WireBody for SafetyProfileV1 {
    const KIND: MessageKind = MessageKind::SafetyProfile;
    fn encode_body(&self) -> Result<Vec<u8>, CodecError> {
        // Draft/revoked profiles remain encodable for audit, but malformed numeric/hash fields do not.
        if self.approval_state > 2
            || !matches!(self.electrode_material, 0..=5 | 255)
            || self.recovery_policy < 1
            || self.recovery_policy > 2
            || self.impedance_min_ohm > self.impedance_max_ohm
        {
            return Err(CodecError::Invariant);
        }
        let mut o = body_prefix(288);
        o.extend_from_slice(&self.profile_id);
        o.push(self.approval_state);
        o.push(self.electrode_material);
        put_u16(&mut o, self.recovery_policy);
        for x in [
            self.wire_diameter_nm,
            self.exposed_area_um2,
            self.impedance_min_ohm,
            self.impedance_max_ohm,
            self.max_current_na,
            self.max_phase_width_us,
            self.min_interphase_us,
            self.max_frequency_millihz,
            self.max_train_pulses,
            self.max_train_duration_ms,
            self.max_duty_cycle_ppm,
            0,
        ] {
            put_u32(&mut o, x)
        }
        put_u64(&mut o, self.max_charge_per_phase_pc);
        put_u64(&mut o, self.max_charge_density_pc_per_mm2);
        o.extend_from_slice(&self.compliance_min_uv.to_le_bytes());
        o.extend_from_slice(&self.compliance_max_uv.to_le_bytes());
        for h in [
            &self.experiment_protocol_hash,
            &self.electrode_geometry_hash,
            &self.hardware_build_hash,
            &self.software_build_hash,
            &self.approved_limits_hash,
            &self.approval_authority_hash,
        ] {
            o.extend_from_slice(h)
        }
        debug_assert_eq!(o.len(), 288);
        Ok(o)
    }
    fn decode_body(b: &[u8]) -> Result<Self, CodecError> {
        check_body(b, 288)?;
        if le_u32(b, 68)? != 0 {
            return Err(CodecError::Reserved);
        }
        let v = Self {
            profile_id: arr16(b, 4)?,
            approval_state: b[20],
            electrode_material: b[21],
            recovery_policy: le_u16(b, 22)?,
            wire_diameter_nm: le_u32(b, 24)?,
            exposed_area_um2: le_u32(b, 28)?,
            impedance_min_ohm: le_u32(b, 32)?,
            impedance_max_ohm: le_u32(b, 36)?,
            max_current_na: le_u32(b, 40)?,
            max_phase_width_us: le_u32(b, 44)?,
            min_interphase_us: le_u32(b, 48)?,
            max_frequency_millihz: le_u32(b, 52)?,
            max_train_pulses: le_u32(b, 56)?,
            max_train_duration_ms: le_u32(b, 60)?,
            max_duty_cycle_ppm: le_u32(b, 64)?,
            max_charge_per_phase_pc: le_u64(b, 72)?,
            max_charge_density_pc_per_mm2: le_u64(b, 80)?,
            compliance_min_uv: le_i32(b, 88)?,
            compliance_max_uv: le_i32(b, 92)?,
            experiment_protocol_hash: arr32(b, 96)?,
            electrode_geometry_hash: arr32(b, 128)?,
            hardware_build_hash: arr32(b, 160)?,
            software_build_hash: arr32(b, 192)?,
            approved_limits_hash: arr32(b, 224)?,
            approval_authority_hash: arr32(b, 256)?,
        };
        v.encode_body()?;
        Ok(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StimIntentV1 {
    pub run_id: Id16,
    pub source_worker_id: Id16,
    pub control_token_id: Id16,
    pub source_record_sequence: u64,
    pub source_sample_counter: u64,
    pub source_global_time_ns: u64,
    pub algorithm_hash: Hash32,
    pub config_hash: Hash32,
    pub template_hash: Hash32,
    pub channel_map_hash: Hash32,
    pub target_channel: u16,
    pub template_id: u16,
    pub intent_flags: u32,
    pub deadline_global_time_ns: u64,
    pub intent_nonce: Id16,
}
impl WireBody for StimIntentV1 {
    const KIND: MessageKind = MessageKind::StimIntent;
    fn encode_body(&self) -> Result<Vec<u8>, CodecError> {
        if [
            self.run_id,
            self.source_worker_id,
            self.control_token_id,
            self.intent_nonce,
        ]
        .iter()
        .any(is_zero_id)
            || [
                self.algorithm_hash,
                self.config_hash,
                self.template_hash,
                self.channel_map_hash,
            ]
            .iter()
            .any(is_zero_hash)
            || self.template_id == 0
            || self.intent_flags != 0
            || self.deadline_global_time_ns <= self.source_global_time_ns
        {
            return Err(CodecError::Invariant);
        }
        let mut o = body_prefix(240);
        for x in [&self.run_id, &self.source_worker_id, &self.control_token_id] {
            o.extend_from_slice(x)
        }
        for x in [
            self.source_record_sequence,
            self.source_sample_counter,
            self.source_global_time_ns,
        ] {
            put_u64(&mut o, x)
        }
        for h in [
            &self.algorithm_hash,
            &self.config_hash,
            &self.template_hash,
            &self.channel_map_hash,
        ] {
            o.extend_from_slice(h)
        }
        put_u16(&mut o, self.target_channel);
        put_u16(&mut o, self.template_id);
        put_u32(&mut o, self.intent_flags);
        put_u32(&mut o, 0);
        put_u64(&mut o, self.deadline_global_time_ns);
        o.extend_from_slice(&self.intent_nonce);
        Ok(o)
    }
    fn decode_body(b: &[u8]) -> Result<Self, CodecError> {
        check_body(b, 240)?;
        if le_u32(b, 212)? != 0 {
            return Err(CodecError::Reserved);
        }
        let v = Self {
            run_id: arr16(b, 4)?,
            source_worker_id: arr16(b, 20)?,
            control_token_id: arr16(b, 36)?,
            source_record_sequence: le_u64(b, 52)?,
            source_sample_counter: le_u64(b, 60)?,
            source_global_time_ns: le_u64(b, 68)?,
            algorithm_hash: arr32(b, 76)?,
            config_hash: arr32(b, 108)?,
            template_hash: arr32(b, 140)?,
            channel_map_hash: arr32(b, 172)?,
            target_channel: le_u16(b, 204)?,
            template_id: le_u16(b, 206)?,
            intent_flags: le_u32(b, 208)?,
            deadline_global_time_ns: le_u64(b, 216)?,
            intent_nonce: arr16(b, 224)?,
        };
        v.encode_body()?;
        Ok(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StimCommandV1 {
    pub run_id: Id16,
    pub command_id: Id16,
    pub intent_nonce: Id16,
    pub device_id: Id16,
    pub safety_profile_hash: Hash32,
    pub template_hash: Hash32,
    pub channel_map_hash: Hash32,
    pub target_channel: u16,
    pub template_id: u16,
    pub current_na: u32,
    pub cathodic_phase_us: u32,
    pub interphase_us: u32,
    pub anodic_phase_us: u32,
    pub frequency_millihz: u32,
    pub pulse_count: u32,
    pub deadline_global_time_ns: u64,
    pub execute_not_before_global_time_ns: u64,
    pub arm_epoch: u64,
    pub command_nonce: Id16,
}
impl WireBody for StimCommandV1 {
    const KIND: MessageKind = MessageKind::StimCommand;
    fn encode_body(&self) -> Result<Vec<u8>, CodecError> {
        if [
            self.run_id,
            self.command_id,
            self.intent_nonce,
            self.device_id,
            self.command_nonce,
        ]
        .iter()
        .any(is_zero_id)
            || [
                self.safety_profile_hash,
                self.template_hash,
                self.channel_map_hash,
            ]
            .iter()
            .any(is_zero_hash)
            || self.current_na == 0
            || self.cathodic_phase_us == 0
            || self.interphase_us == 0
            || self.anodic_phase_us == 0
            || self.frequency_millihz == 0
            || self.pulse_count == 0
            || self.template_id == 0
            || self.deadline_global_time_ns == 0
            || self.execute_not_before_global_time_ns == 0
            || self.execute_not_before_global_time_ns > self.deadline_global_time_ns
            || self.arm_epoch == 0
        {
            return Err(CodecError::Invariant);
        }
        let mut o = body_prefix(232);
        for x in [
            &self.run_id,
            &self.command_id,
            &self.intent_nonce,
            &self.device_id,
        ] {
            o.extend_from_slice(x)
        }
        for h in [
            &self.safety_profile_hash,
            &self.template_hash,
            &self.channel_map_hash,
        ] {
            o.extend_from_slice(h)
        }
        put_u16(&mut o, self.target_channel);
        put_u16(&mut o, self.template_id);
        for x in [
            self.current_na,
            self.cathodic_phase_us,
            self.interphase_us,
            self.anodic_phase_us,
            self.frequency_millihz,
            self.pulse_count,
        ] {
            put_u32(&mut o, x)
        }
        for x in [
            self.deadline_global_time_ns,
            self.execute_not_before_global_time_ns,
            self.arm_epoch,
        ] {
            put_u64(&mut o, x)
        }
        o.extend_from_slice(&self.command_nonce);
        Ok(o)
    }
    fn decode_body(b: &[u8]) -> Result<Self, CodecError> {
        check_body(b, 232)?;
        let v = Self {
            run_id: arr16(b, 4)?,
            command_id: arr16(b, 20)?,
            intent_nonce: arr16(b, 36)?,
            device_id: arr16(b, 52)?,
            safety_profile_hash: arr32(b, 68)?,
            template_hash: arr32(b, 100)?,
            channel_map_hash: arr32(b, 132)?,
            target_channel: le_u16(b, 164)?,
            template_id: le_u16(b, 166)?,
            current_na: le_u32(b, 168)?,
            cathodic_phase_us: le_u32(b, 172)?,
            interphase_us: le_u32(b, 176)?,
            anodic_phase_us: le_u32(b, 180)?,
            frequency_millihz: le_u32(b, 184)?,
            pulse_count: le_u32(b, 188)?,
            deadline_global_time_ns: le_u64(b, 192)?,
            execute_not_before_global_time_ns: le_u64(b, 200)?,
            arm_epoch: le_u64(b, 208)?,
            command_nonce: arr16(b, 216)?,
        };
        v.encode_body()?;
        Ok(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StimReceiptV1 {
    pub run_id: Id16,
    pub command_id: Id16,
    pub intent_nonce: Id16,
    pub device_id: Id16,
    pub result: u16,
    pub fault_code: u16,
    pub target_channel: u16,
    pub template_id: u16,
    pub actual_start_global_time_ns: u64,
    pub actual_end_global_time_ns: u64,
    pub measured_compliance_uv: i32,
    pub peak_current_na: u32,
    pub receipt_flags: u32,
    pub delivered_phase_charge_pc: u64,
    pub arm_epoch: u64,
    pub receipt_nonce: Id16,
    pub hardware_state_hash: Hash32,
}
impl WireBody for StimReceiptV1 {
    const KIND: MessageKind = MessageKind::StimReceipt;
    fn encode_body(&self) -> Result<Vec<u8>, CodecError> {
        if [
            self.run_id,
            self.command_id,
            self.intent_nonce,
            self.device_id,
            self.receipt_nonce,
        ]
        .iter()
        .any(is_zero_id)
            || is_zero_hash(&self.hardware_state_hash)
            || !(1..=8).contains(&self.result)
            || self.template_id == 0
            || self.receipt_flags != 0
            || self.arm_epoch == 0
        {
            return Err(CodecError::Invariant);
        }
        if self.result == 1
            && (self.actual_start_global_time_ns == 0
                || self.actual_end_global_time_ns < self.actual_start_global_time_ns)
        {
            return Err(CodecError::Invariant);
        }
        let mut o = body_prefix(168);
        for x in [
            &self.run_id,
            &self.command_id,
            &self.intent_nonce,
            &self.device_id,
        ] {
            o.extend_from_slice(x)
        }
        put_u16(&mut o, self.result);
        put_u16(&mut o, self.fault_code);
        put_u16(&mut o, self.target_channel);
        put_u16(&mut o, self.template_id);
        put_u64(&mut o, self.actual_start_global_time_ns);
        put_u64(&mut o, self.actual_end_global_time_ns);
        o.extend_from_slice(&self.measured_compliance_uv.to_le_bytes());
        put_u32(&mut o, self.peak_current_na);
        put_u32(&mut o, self.receipt_flags);
        put_u64(&mut o, self.delivered_phase_charge_pc);
        put_u64(&mut o, self.arm_epoch);
        o.extend_from_slice(&self.receipt_nonce);
        o.extend_from_slice(&self.hardware_state_hash);
        Ok(o)
    }
    fn decode_body(b: &[u8]) -> Result<Self, CodecError> {
        check_body(b, 168)?;
        let v = Self {
            run_id: arr16(b, 4)?,
            command_id: arr16(b, 20)?,
            intent_nonce: arr16(b, 36)?,
            device_id: arr16(b, 52)?,
            result: le_u16(b, 68)?,
            fault_code: le_u16(b, 70)?,
            target_channel: le_u16(b, 72)?,
            template_id: le_u16(b, 74)?,
            actual_start_global_time_ns: le_u64(b, 76)?,
            actual_end_global_time_ns: le_u64(b, 84)?,
            measured_compliance_uv: le_i32(b, 92)?,
            peak_current_na: le_u32(b, 96)?,
            receipt_flags: le_u32(b, 100)?,
            delivered_phase_charge_pc: le_u64(b, 104)?,
            arm_epoch: le_u64(b, 112)?,
            receipt_nonce: arr16(b, 120)?,
            hardware_state_hash: arr32(b, 136)?,
        };
        v.encode_body()?;
        Ok(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerTokenLeaseV1 {
    pub run_id: Id16,
    pub worker_id: Id16,
    pub token_id: Id16,
    pub role: u8,
    pub state: u8,
    pub arm_epoch: u64,
    pub issued_global_time_ns: u64,
    pub expires_global_time_ns: u64,
    pub safety_profile_id: Id16,
    pub safety_profile_hash: Hash32,
    pub algorithm_hash: Hash32,
    pub config_hash: Hash32,
    pub template_hash: Hash32,
    pub channel_map_hash: Hash32,
    pub worker_build_hash: Hash32,
}
impl WireBody for WorkerTokenLeaseV1 {
    const KIND: MessageKind = MessageKind::WorkerTokenLease;
    fn encode_body(&self) -> Result<Vec<u8>, CodecError> {
        if [
            self.run_id,
            self.worker_id,
            self.token_id,
            self.safety_profile_id,
        ]
        .iter()
        .any(is_zero_id)
            || [
                self.safety_profile_hash,
                self.algorithm_hash,
                self.config_hash,
                self.template_hash,
                self.channel_map_hash,
                self.worker_build_hash,
            ]
            .iter()
            .any(is_zero_hash)
            || !matches!(self.role, 1 | 2)
            || !matches!(self.state, 1..=3)
            || self.arm_epoch == 0
            || self.issued_global_time_ns >= self.expires_global_time_ns
        {
            return Err(CodecError::Invariant);
        }
        let mut o = body_prefix(288);
        for x in [&self.run_id, &self.worker_id, &self.token_id] {
            o.extend_from_slice(x)
        }
        o.push(self.role);
        o.push(self.state);
        put_u16(&mut o, 0);
        for x in [
            self.arm_epoch,
            self.issued_global_time_ns,
            self.expires_global_time_ns,
        ] {
            put_u64(&mut o, x)
        }
        o.extend_from_slice(&self.safety_profile_id);
        for h in [
            &self.safety_profile_hash,
            &self.algorithm_hash,
            &self.config_hash,
            &self.template_hash,
            &self.channel_map_hash,
            &self.worker_build_hash,
        ] {
            o.extend_from_slice(h)
        }
        Ok(o)
    }
    fn decode_body(b: &[u8]) -> Result<Self, CodecError> {
        check_body(b, 288)?;
        if le_u16(b, 54)? != 0 {
            return Err(CodecError::Reserved);
        }
        let v = Self {
            run_id: arr16(b, 4)?,
            worker_id: arr16(b, 20)?,
            token_id: arr16(b, 36)?,
            role: b[52],
            state: b[53],
            arm_epoch: le_u64(b, 56)?,
            issued_global_time_ns: le_u64(b, 64)?,
            expires_global_time_ns: le_u64(b, 72)?,
            safety_profile_id: arr16(b, 80)?,
            safety_profile_hash: arr32(b, 96)?,
            algorithm_hash: arr32(b, 128)?,
            config_hash: arr32(b, 160)?,
            template_hash: arr32(b, 192)?,
            channel_map_hash: arr32(b, 224)?,
            worker_build_hash: arr32(b, 256)?,
        };
        v.encode_body()?;
        Ok(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckV1 {
    pub acknowledged_request_id: u64,
    pub applied_epoch: u64,
    pub ack_code: u16,
    pub state_code: u16,
    pub receipt_hash: Hash32,
}
impl WireBody for AckV1 {
    const KIND: MessageKind = MessageKind::Ack;
    fn encode_body(&self) -> Result<Vec<u8>, CodecError> {
        if self.acknowledged_request_id == 0
            || self.applied_epoch == 0
            || is_zero_hash(&self.receipt_hash)
        {
            return Err(CodecError::Invariant);
        }
        let mut o = body_prefix(60);
        put_u64(&mut o, self.acknowledged_request_id);
        put_u64(&mut o, self.applied_epoch);
        put_u16(&mut o, self.ack_code);
        put_u16(&mut o, self.state_code);
        put_u32(&mut o, 0);
        o.extend_from_slice(&self.receipt_hash);
        Ok(o)
    }
    fn decode_body(b: &[u8]) -> Result<Self, CodecError> {
        check_body(b, 60)?;
        if le_u32(b, 24)? != 0 {
            return Err(CodecError::Reserved);
        }
        let v = Self {
            acknowledged_request_id: le_u64(b, 4)?,
            applied_epoch: le_u64(b, 12)?,
            ack_code: le_u16(b, 20)?,
            state_code: le_u16(b, 22)?,
            receipt_hash: arr32(b, 28)?,
        };
        v.encode_body()?;
        Ok(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NackV1 {
    pub rejected_request_id: u64,
    pub current_epoch: u64,
    pub error_code: u16,
    pub retryable: u8,
    pub detail_code: u32,
    pub state_hash: Hash32,
}
impl WireBody for NackV1 {
    const KIND: MessageKind = MessageKind::Nack;
    fn encode_body(&self) -> Result<Vec<u8>, CodecError> {
        if self.rejected_request_id == 0
            || self.current_epoch == 0
            || self.error_code == 0
            || self.retryable > 1
            || is_zero_hash(&self.state_hash)
        {
            return Err(CodecError::Invariant);
        }
        let mut o = body_prefix(60);
        put_u64(&mut o, self.rejected_request_id);
        put_u64(&mut o, self.current_epoch);
        put_u16(&mut o, self.error_code);
        o.push(self.retryable);
        o.push(0);
        put_u32(&mut o, self.detail_code);
        o.extend_from_slice(&self.state_hash);
        Ok(o)
    }
    fn decode_body(b: &[u8]) -> Result<Self, CodecError> {
        check_body(b, 60)?;
        if b[23] != 0 {
            return Err(CodecError::Reserved);
        }
        let v = Self {
            rejected_request_id: le_u64(b, 4)?,
            current_epoch: le_u64(b, 12)?,
            error_code: le_u16(b, 20)?,
            retryable: b[22],
            detail_code: le_u32(b, 24)?,
            state_hash: arr32(b, 28)?,
        };
        v.encode_body()?;
        Ok(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRequestV1 {
    pub run_id: Id16,
    pub pod_id: Id16,
    pub first_record_sequence: u64,
    pub last_record_sequence_exclusive: u64,
    pub deadline_global_time_ns: u64,
    pub reason_code: u16,
    pub request_context_hash: Hash32,
}
impl WireBody for ReplayRequestV1 {
    const KIND: MessageKind = MessageKind::ReplayRequest;
    fn encode_body(&self) -> Result<Vec<u8>, CodecError> {
        if is_zero_id(&self.run_id)
            || is_zero_id(&self.pod_id)
            || self.first_record_sequence >= self.last_record_sequence_exclusive
            || self.deadline_global_time_ns == 0
            || self.reason_code == 0
            || is_zero_hash(&self.request_context_hash)
        {
            return Err(CodecError::Invariant);
        }
        let mut o = body_prefix(96);
        o.extend_from_slice(&self.run_id);
        o.extend_from_slice(&self.pod_id);
        put_u64(&mut o, self.first_record_sequence);
        put_u64(&mut o, self.last_record_sequence_exclusive);
        put_u64(&mut o, self.deadline_global_time_ns);
        put_u16(&mut o, self.reason_code);
        put_u16(&mut o, 0);
        o.extend_from_slice(&self.request_context_hash);
        Ok(o)
    }
    fn decode_body(b: &[u8]) -> Result<Self, CodecError> {
        check_body(b, 96)?;
        if le_u16(b, 62)? != 0 {
            return Err(CodecError::Reserved);
        }
        let v = Self {
            run_id: arr16(b, 4)?,
            pod_id: arr16(b, 20)?,
            first_record_sequence: le_u64(b, 36)?,
            last_record_sequence_exclusive: le_u64(b, 44)?,
            deadline_global_time_ns: le_u64(b, 52)?,
            reason_code: le_u16(b, 60)?,
            request_context_hash: arr32(b, 64)?,
        };
        v.encode_body()?;
        Ok(v)
    }
}

pub(crate) fn body_prefix(len: usize) -> Vec<u8> {
    let mut o = Vec::with_capacity(len);
    put_u16(&mut o, 1);
    put_u16(&mut o, len as u16);
    o
}
pub(crate) fn check_body(b: &[u8], len: usize) -> Result<(), CodecError> {
    if b.len() != len {
        return Err(CodecError::Length);
    }
    if le_u16(b, 0)? != 1 {
        return Err(CodecError::Version);
    }
    if le_u16(b, 2)? as usize != len {
        return Err(CodecError::Length);
    }
    Ok(())
}
pub(crate) fn put_u16(o: &mut Vec<u8>, v: u16) {
    o.extend_from_slice(&v.to_le_bytes())
}
pub(crate) fn put_u32(o: &mut Vec<u8>, v: u32) {
    o.extend_from_slice(&v.to_le_bytes())
}
pub(crate) fn put_u64(o: &mut Vec<u8>, v: u64) {
    o.extend_from_slice(&v.to_le_bytes())
}
pub(crate) fn le_u16(b: &[u8], p: usize) -> Result<u16, CodecError> {
    let s = b.get(p..p + 2).ok_or(CodecError::Length)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
pub(crate) fn le_u32(b: &[u8], p: usize) -> Result<u32, CodecError> {
    let s = b.get(p..p + 4).ok_or(CodecError::Length)?;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}
pub(crate) fn le_i32(b: &[u8], p: usize) -> Result<i32, CodecError> {
    let s = b.get(p..p + 4).ok_or(CodecError::Length)?;
    Ok(i32::from_le_bytes(s.try_into().unwrap()))
}
pub(crate) fn le_u64(b: &[u8], p: usize) -> Result<u64, CodecError> {
    let s = b.get(p..p + 8).ok_or(CodecError::Length)?;
    Ok(u64::from_le_bytes(s.try_into().unwrap()))
}
pub(crate) fn arr16(b: &[u8], p: usize) -> Result<Id16, CodecError> {
    Ok(b.get(p..p + 16)
        .ok_or(CodecError::Length)?
        .try_into()
        .unwrap())
}
pub(crate) fn arr32(b: &[u8], p: usize) -> Result<Hash32, CodecError> {
    Ok(b.get(p..p + 32)
        .ok_or(CodecError::Length)?
        .try_into()
        .unwrap())
}
pub fn is_zero_id(v: &Id16) -> bool {
    *v == ZERO_ID
}
pub fn is_zero_hash(v: &Hash32) -> bool {
    *v == ZERO_HASH
}
pub fn protocol_bound(hash: &Hash32) -> bool {
    hash == &PROTOCOL_HASH
}
