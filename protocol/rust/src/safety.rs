use std::fmt;

use crate::types::*;
use crate::{sha256, PROTOCOL_HASH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyError {
    ProtocolHash,
    DeviceIdentity,
    StimNotCapable,
    MissingSafetyFeature,
    InterlockOrRuntimeHealth,
    MissingProfile,
    ProfileNotApproved,
    ProfileHash,
    MissingToken,
    TokenNotController,
    TokenNotGranted,
    TokenExpired,
    Epoch,
    RunIdentity,
    WorkerIdentity,
    TokenIdentity,
    FrozenHash,
    Deadline,
    SourceTime,
    TargetChannel,
    CommandIdentity,
    SafetyLimit,
}

impl fmt::Display for SafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for SafetyError {}

/// Validate an algorithm intent at the sole Rust SafetyArbiter boundary.
///
/// `profile_hash` is SHA-256 over the exact canonical SafetyProfileV1 body.
/// Hash computation lives at the artifact-loading boundary; this dependency-
/// free wire crate compares the already authenticated value byte-for-byte.
pub fn validate_stim_intent(
    capabilities: &DeviceCapabilitiesV1,
    profile: Option<&SafetyProfileV1>,
    profile_hash: &Hash32,
    token: Option<&WorkerTokenLeaseV1>,
    intent: &StimIntentV1,
    message_epoch: u64,
    now_global_time_ns: u64,
) -> Result<(), SafetyError> {
    if capabilities.hardware_protocol_hash != PROTOCOL_HASH {
        return Err(SafetyError::ProtocolHash);
    }
    if is_zero_id(&capabilities.device_id) {
        return Err(SafetyError::DeviceIdentity);
    }
    if capabilities.stim_kind != 1 || capabilities.stim_channels != 16 {
        return Err(SafetyError::StimNotCapable);
    }
    if capabilities.capability_flags & REQUIRED_STIM_CAPS != REQUIRED_STIM_CAPS {
        return Err(SafetyError::MissingSafetyFeature);
    }
    if capabilities.runtime_safety_flags & REQUIRED_STIM_RUNTIME != REQUIRED_STIM_RUNTIME {
        return Err(SafetyError::InterlockOrRuntimeHealth);
    }
    let profile = profile.ok_or(SafetyError::MissingProfile)?;
    if profile.validate_approved().is_err() {
        return Err(SafetyError::ProfileNotApproved);
    }
    if is_zero_hash(profile_hash) {
        return Err(SafetyError::ProfileHash);
    }
    let canonical_profile = profile
        .encode_body()
        .map_err(|_| SafetyError::ProfileNotApproved)?;
    if sha256(&canonical_profile) != *profile_hash {
        return Err(SafetyError::ProfileHash);
    }
    let token = token.ok_or(SafetyError::MissingToken)?;
    if token.role != 2 {
        return Err(SafetyError::TokenNotController);
    }
    if token.state != 1 {
        return Err(SafetyError::TokenNotGranted);
    }
    if now_global_time_ns < token.issued_global_time_ns
        || now_global_time_ns >= token.expires_global_time_ns
    {
        return Err(SafetyError::TokenExpired);
    }
    if message_epoch == 0 || message_epoch != token.arm_epoch {
        return Err(SafetyError::Epoch);
    }
    if intent.run_id != token.run_id {
        return Err(SafetyError::RunIdentity);
    }
    if intent.source_worker_id != token.worker_id {
        return Err(SafetyError::WorkerIdentity);
    }
    if intent.control_token_id != token.token_id {
        return Err(SafetyError::TokenIdentity);
    }
    if profile.profile_id != token.safety_profile_id || profile_hash != &token.safety_profile_hash {
        return Err(SafetyError::ProfileHash);
    }
    if intent.algorithm_hash != token.algorithm_hash
        || intent.config_hash != token.config_hash
        || intent.template_hash != token.template_hash
        || intent.channel_map_hash != token.channel_map_hash
        || is_zero_hash(&token.worker_build_hash)
    {
        return Err(SafetyError::FrozenHash);
    }
    if intent.source_global_time_ns > now_global_time_ns {
        return Err(SafetyError::SourceTime);
    }
    if now_global_time_ns >= intent.deadline_global_time_ns
        || intent.deadline_global_time_ns <= intent.source_global_time_ns
    {
        return Err(SafetyError::Deadline);
    }
    if intent.target_channel >= capabilities.stim_channels {
        return Err(SafetyError::TargetChannel);
    }
    Ok(())
}

pub fn validate_stim_command(
    capabilities: &DeviceCapabilitiesV1,
    profile: &SafetyProfileV1,
    profile_hash: &Hash32,
    token: &WorkerTokenLeaseV1,
    intent: &StimIntentV1,
    command: &StimCommandV1,
    now_global_time_ns: u64,
) -> Result<(), SafetyError> {
    validate_stim_intent(
        capabilities,
        Some(profile),
        profile_hash,
        Some(token),
        intent,
        command.arm_epoch,
        now_global_time_ns,
    )?;
    if command.run_id != intent.run_id
        || command.intent_nonce != intent.intent_nonce
        || command.device_id != capabilities.device_id
    {
        return Err(SafetyError::CommandIdentity);
    }
    if command.safety_profile_hash != *profile_hash
        || command.template_hash != intent.template_hash
        || command.channel_map_hash != intent.channel_map_hash
    {
        return Err(SafetyError::FrozenHash);
    }
    if command.target_channel != intent.target_channel || command.template_id != intent.template_id
    {
        return Err(SafetyError::TargetChannel);
    }
    if command.deadline_global_time_ns != intent.deadline_global_time_ns
        || command.execute_not_before_global_time_ns > command.deadline_global_time_ns
        || now_global_time_ns >= command.deadline_global_time_ns
    {
        return Err(SafetyError::Deadline);
    }

    if command.current_na == 0
        || command.current_na > profile.max_current_na
        || command.cathodic_phase_us == 0
        || command.cathodic_phase_us > profile.max_phase_width_us
        || command.anodic_phase_us == 0
        || command.anodic_phase_us > profile.max_phase_width_us
        || command.cathodic_phase_us != command.anodic_phase_us
        || command.interphase_us < profile.min_interphase_us
        || command.frequency_millihz == 0
        || command.frequency_millihz > profile.max_frequency_millihz
        || command.pulse_count == 0
        || command.pulse_count > profile.max_train_pulses
    {
        return Err(SafetyError::SafetyLimit);
    }

    let max_phase_us = command.cathodic_phase_us.max(command.anodic_phase_us) as u128;
    let charge_pc = div_ceil(command.current_na as u128 * max_phase_us, 1_000);
    if charge_pc > profile.max_charge_per_phase_pc as u128 {
        return Err(SafetyError::SafetyLimit);
    }
    let density_pc_per_mm2 = div_ceil(charge_pc * 1_000_000, profile.exposed_area_um2 as u128);
    if density_pc_per_mm2 > profile.max_charge_density_pc_per_mm2 as u128 {
        return Err(SafetyError::SafetyLimit);
    }
    let pulse_width_us = command.cathodic_phase_us as u128
        + command.interphase_us as u128
        + command.anodic_phase_us as u128;
    let duty_ppm = div_ceil(pulse_width_us * command.frequency_millihz as u128, 1_000);
    if duty_ppm > profile.max_duty_cycle_ppm as u128 {
        return Err(SafetyError::SafetyLimit);
    }
    let waveform_ms = div_ceil(pulse_width_us, 1_000);
    let period_ms = div_ceil(1_000_000, command.frequency_millihz as u128);
    let train_ms = (command.pulse_count.saturating_sub(1) as u128)
        .saturating_mul(period_ms)
        .saturating_add(waveform_ms);
    if train_ms > profile.max_train_duration_ms as u128 {
        return Err(SafetyError::SafetyLimit);
    }
    Ok(())
}

fn div_ceil(numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        return u128::MAX;
    }
    numerator / denominator + u128::from(!numerator.is_multiple_of(denominator))
}
