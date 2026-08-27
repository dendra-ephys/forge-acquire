use std::io;

use forge_protocol_v1::{
    encode_record, CanonicalRecordEnvelopeV1, Id16, RecordKind, SampleBlockV1,
    SAMPLE_BLOCK_FLAG_COMPLETE,
};

/// The synthetic LFP is an integer triangle wave so every implementation can
/// reproduce it without floating-point or platform-specific trigonometry.
pub const SYNTHETIC_SCENARIO_ID: &str = "forge.synthetic.neural.integer.v1";
pub const SYNTHETIC_DEFAULT_SEED: u64 = 9;
pub const SYNTHETIC_LFP_FREQUENCY_HZ: u32 = 8;
pub const SYNTHETIC_LFP_PEAK_COUNTS: i32 = 2_048;
pub const SYNTHETIC_LFP_CHANNEL_PHASE_DIVISOR: u32 = 32;
pub const SYNTHETIC_NOISE_PEAK_COUNTS: i32 = 64;
pub const SYNTHETIC_NOISE_LEVEL_COUNT: u32 = 129;
pub const SYNTHETIC_NOISE_SEED_HI_ROTATION: u32 = 16;
pub const SYNTHETIC_NOISE_SAMPLE_LO_MULTIPLIER: u32 = 0x9e37_79b9;
pub const SYNTHETIC_NOISE_SAMPLE_HI_MULTIPLIER: u32 = 0x85eb_ca6b;
pub const SYNTHETIC_NOISE_CHANNEL_MULTIPLIER: u32 = 0xc2b2_ae35;
pub const SYNTHETIC_NOISE_XOR_BIAS: u32 = 0xa341_316c;
pub const SYNTHETIC_NOISE_XORSHIFT_LEFT_A: u32 = 13;
pub const SYNTHETIC_NOISE_XORSHIFT_RIGHT: u32 = 17;
pub const SYNTHETIC_NOISE_XORSHIFT_LEFT_B: u32 = 5;
pub const SYNTHETIC_SPIKE_FIRST_CENTER_SAMPLE: u64 = 29;
pub const SYNTHETIC_SPIKE_CHANNEL_OFFSET_SAMPLES: u64 = 53;
pub const SYNTHETIC_SPIKE_PERIOD_DIVISOR: u32 = 10;
pub const SYNTHETIC_SPIKE_MIN_PERIOD_SAMPLES: u64 = 64;
pub const SYNTHETIC_SPIKE_CENTER_INDEX: usize = 5;
pub const SYNTHETIC_SPIKE_TEMPLATE: [i32; 11] = [
    0, -256, -1_024, -4_096, -16_000, -40_000, -16_000, -4_096, -1_024, -256, 0,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticSampleComponents {
    pub lfp_counts: i32,
    pub spike_counts: i32,
    pub noise_counts: i32,
    pub summed_counts: i32,
    pub adc_counts: i16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticOracleEvent {
    pub channel: u16,
    pub center_sample_counter: u64,
    pub waveform_start_sample_counter: u64,
    pub waveform_end_sample_counter_exclusive: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterministicReplayConfig {
    pub run_id: Id16,
    pub pod_id: Id16,
    pub headstage_id: Id16,
    pub channel_layout_id: u32,
    pub channel_count: u16,
    pub samples_per_channel: u32,
    pub sample_rate_hz: u32,
    pub total_records: u64,
    pub seed: u64,
}

impl DeterministicReplayConfig {
    pub fn validate(self) -> io::Result<Self> {
        if self.run_id == [0; 16]
            || self.pod_id == [0; 16]
            || self.headstage_id == [0; 16]
            || self.channel_layout_id == 0
            || self.channel_count == 0
            || self.samples_per_channel == 0
            || self.sample_rate_hz == 0
            || self.total_records == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid deterministic replay configuration",
            ));
        }
        (self.channel_count as usize)
            .checked_mul(self.samples_per_channel as usize)
            .and_then(|count| count.checked_mul(2))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "sample block overflow"))?;
        Ok(self)
    }
}

/// Deterministic canonical SampleBlock source. It has no device or stimulation
/// access and is suitable only for protected replay/synthetic qualification.
pub struct DeterministicReplaySource {
    config: DeterministicReplayConfig,
    next_record_sequence: u64,
}

impl DeterministicReplaySource {
    pub fn new(config: DeterministicReplayConfig) -> io::Result<Self> {
        Ok(Self {
            config: config.validate()?,
            next_record_sequence: 0,
        })
    }

    pub fn next_encoded_record(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.next_record_sequence >= self.config.total_records {
            return Ok(None);
        }
        let sequence = self.next_record_sequence;
        let sample_start = sequence
            .checked_mul(self.config.samples_per_channel as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "sample counter overflow"))?;
        let sample_end = sample_start
            .checked_add(self.config.samples_per_channel as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "sample counter overflow"))?;
        let count = self.config.channel_count as usize * self.config.samples_per_channel as usize;
        let mut samples = Vec::with_capacity(count);
        for sample_counter in sample_start..sample_end {
            for channel in 0..self.config.channel_count {
                samples.push(self.sample_at(sample_counter, channel)?);
            }
        }
        let block = SampleBlockV1 {
            // Software-derived time is deterministic, but it is not a
            // hardware timestamp receipt.
            flags: SAMPLE_BLOCK_FLAG_COMPLETE,
            samples_per_channel: self.config.samples_per_channel,
            channel_count: self.config.channel_count,
            sample_format: 1,
            sample_rate_numerator_hz: self.config.sample_rate_hz,
            sample_rate_denominator: 1,
            first_sample_counter: sample_start,
            samples,
        };
        let payload = block.encode().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to encode SampleBlockV1: {error}"),
            )
        })?;
        let start_ns = scale_time_ns(sample_start, self.config.sample_rate_hz)?;
        let end_ns = scale_time_ns(sample_end, self.config.sample_rate_hz)?;
        let envelope = CanonicalRecordEnvelopeV1 {
            record_kind: RecordKind::SampleBlock,
            flags: 0,
            run_id: self.config.run_id,
            pod_id: self.config.pod_id,
            headstage_id: self.config.headstage_id,
            record_sequence: sequence,
            frame_start: sample_start,
            frame_end_exclusive: sample_end,
            sample_start,
            sample_end_exclusive: sample_end,
            global_time_start_ns: start_ns,
            global_time_end_exclusive_ns: end_ns,
            channel_layout_id: self.config.channel_layout_id,
            channel_count: self.config.channel_count,
            sample_format: 1,
        };
        let encoded = encode_record(&envelope, &payload).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to encode CanonicalRecordEnvelopeV1: {error}"),
            )
        })?;
        self.next_record_sequence += 1;
        Ok(Some(encoded))
    }

    /// Returns one synthetic ADC value at an absolute sample counter. The
    /// result depends only on the immutable configuration, sample counter and
    /// channel, never on record boundaries or call order.
    pub fn sample_at(&self, sample_counter: u64, channel: u16) -> io::Result<i16> {
        Ok(self.components_at(sample_counter, channel)?.adc_counts)
    }

    /// Returns the independently inspectable components used to construct one
    /// ADC sample. `summed_counts` is the wide value before i16 saturation.
    pub fn components_at(
        &self,
        sample_counter: u64,
        channel: u16,
    ) -> io::Result<SyntheticSampleComponents> {
        if channel >= self.config.channel_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "synthetic channel is outside configured layout",
            ));
        }
        let lfp_counts = synthetic_lfp_counts(sample_counter, channel, self.config.sample_rate_hz);
        let spike_counts =
            synthetic_spike_counts(sample_counter, channel, self.config.sample_rate_hz);
        let noise_counts = synthetic_noise_counts(self.config.seed, sample_counter, channel);
        let summed_counts = lfp_counts + spike_counts + noise_counts;
        let adc_counts = summed_counts.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        Ok(SyntheticSampleComponents {
            lfp_counts,
            spike_counts,
            noise_counts,
            summed_counts,
            adc_counts,
        })
    }

    /// Returns spike-center truth events in `[sample_start,
    /// sample_end_exclusive)`, ordered by center and then channel. The oracle
    /// is separate from the encoded stream and is not consumed by analysis.
    pub fn oracle_events(
        &self,
        sample_start: u64,
        sample_end_exclusive: u64,
    ) -> io::Result<Vec<SyntheticOracleEvent>> {
        if sample_end_exclusive < sample_start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "synthetic oracle range is reversed",
            ));
        }
        let period = synthetic_spike_period_samples(self.config.sample_rate_hz);
        let mut events = Vec::new();
        for channel in 0..self.config.channel_count {
            let first_center = synthetic_spike_first_center(channel);
            let Some(mut center) = event_center_at_or_after(first_center, period, sample_start)
            else {
                continue;
            };
            while center < sample_end_exclusive {
                events.push(SyntheticOracleEvent {
                    channel,
                    center_sample_counter: center,
                    waveform_start_sample_counter: center
                        .saturating_sub(SYNTHETIC_SPIKE_CENTER_INDEX as u64),
                    waveform_end_sample_counter_exclusive: center.saturating_add(
                        (SYNTHETIC_SPIKE_TEMPLATE.len() - SYNTHETIC_SPIKE_CENTER_INDEX) as u64,
                    ),
                });
                let Some(next) = center.checked_add(period) else {
                    break;
                };
                center = next;
            }
        }
        events.sort_unstable_by_key(|event| (event.center_sample_counter, event.channel));
        Ok(events)
    }
}

pub const fn synthetic_spike_period_samples(sample_rate_hz: u32) -> u64 {
    let derived = (sample_rate_hz / SYNTHETIC_SPIKE_PERIOD_DIVISOR) as u64;
    if derived < SYNTHETIC_SPIKE_MIN_PERIOD_SAMPLES {
        SYNTHETIC_SPIKE_MIN_PERIOD_SAMPLES
    } else {
        derived
    }
}

pub const fn synthetic_spike_first_center(channel: u16) -> u64 {
    SYNTHETIC_SPIKE_FIRST_CENTER_SAMPLE + channel as u64 * SYNTHETIC_SPIKE_CHANNEL_OFFSET_SAMPLES
}

fn synthetic_lfp_counts(sample_counter: u64, channel: u16, sample_rate_hz: u32) -> i32 {
    let rate = sample_rate_hz as u64;
    let channel_phase = channel as u64 * (rate / SYNTHETIC_LFP_CHANNEL_PHASE_DIVISOR as u64);
    let phase =
        ((sample_counter % rate) * SYNTHETIC_LFP_FREQUENCY_HZ as u64 + channel_phase) % rate;
    let scaled = (4 * SYNTHETIC_LFP_PEAK_COUNTS as u64 * phase / rate) as i32;
    if phase * 2 < rate {
        -SYNTHETIC_LFP_PEAK_COUNTS + scaled
    } else {
        3 * SYNTHETIC_LFP_PEAK_COUNTS - scaled
    }
}

fn synthetic_noise_counts(seed: u64, sample_counter: u64, channel: u16) -> i32 {
    let seed_low = seed as u32;
    let seed_high = (seed >> 32) as u32;
    let sample_low = sample_counter as u32;
    let sample_high = (sample_counter >> 32) as u32;
    let mut word = seed_low
        ^ seed_high.rotate_left(SYNTHETIC_NOISE_SEED_HI_ROTATION)
        ^ sample_low.wrapping_mul(SYNTHETIC_NOISE_SAMPLE_LO_MULTIPLIER)
        ^ sample_high.wrapping_mul(SYNTHETIC_NOISE_SAMPLE_HI_MULTIPLIER)
        ^ (channel as u32).wrapping_mul(SYNTHETIC_NOISE_CHANNEL_MULTIPLIER)
        ^ SYNTHETIC_NOISE_XOR_BIAS;
    word ^= word << SYNTHETIC_NOISE_XORSHIFT_LEFT_A;
    word ^= word >> SYNTHETIC_NOISE_XORSHIFT_RIGHT;
    word ^= word << SYNTHETIC_NOISE_XORSHIFT_LEFT_B;
    (word % SYNTHETIC_NOISE_LEVEL_COUNT) as i32 - SYNTHETIC_NOISE_PEAK_COUNTS
}

fn synthetic_spike_counts(sample_counter: u64, channel: u16, sample_rate_hz: u32) -> i32 {
    let first_center = synthetic_spike_first_center(channel);
    let period = synthetic_spike_period_samples(sample_rate_hz);
    let index = if sample_counter < first_center {
        let distance = first_center - sample_counter;
        if distance > SYNTHETIC_SPIKE_CENTER_INDEX as u64 {
            return 0;
        }
        SYNTHETIC_SPIKE_CENTER_INDEX - distance as usize
    } else {
        let remainder = (sample_counter - first_center) % period;
        if remainder <= SYNTHETIC_SPIKE_CENTER_INDEX as u64 {
            SYNTHETIC_SPIKE_CENTER_INDEX + remainder as usize
        } else {
            let distance_to_next = period - remainder;
            if distance_to_next > SYNTHETIC_SPIKE_CENTER_INDEX as u64 {
                return 0;
            }
            SYNTHETIC_SPIKE_CENTER_INDEX - distance_to_next as usize
        }
    };
    SYNTHETIC_SPIKE_TEMPLATE[index]
}

fn event_center_at_or_after(first_center: u64, period: u64, sample_start: u64) -> Option<u64> {
    if sample_start <= first_center {
        return Some(first_center);
    }
    let distance = sample_start - first_center;
    let quotient = distance / period;
    let event_index = quotient.checked_add(u64::from(!distance.is_multiple_of(period)))?;
    first_center.checked_add(event_index.checked_mul(period)?)
}

fn scale_time_ns(sample: u64, sample_rate_hz: u32) -> io::Result<u64> {
    let numerator = (sample as u128) * 1_000_000_000_u128;
    u64::try_from(numerator / sample_rate_hz as u128)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "global time overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_protocol_v1::{decode_record, SampleBlockV1};

    fn config() -> DeterministicReplayConfig {
        DeterministicReplayConfig {
            run_id: [1; 16],
            pod_id: [2; 16],
            headstage_id: [3; 16],
            channel_layout_id: 1,
            channel_count: 2,
            samples_per_channel: 30,
            sample_rate_hz: 30_000,
            total_records: 2,
            seed: SYNTHETIC_DEFAULT_SEED,
        }
    }

    fn encoded_records(config: DeterministicReplayConfig) -> Vec<Vec<u8>> {
        let mut source = DeterministicReplaySource::new(config).unwrap();
        let mut records = Vec::new();
        while let Some(record) = source.next_encoded_record().unwrap() {
            records.push(record);
        }
        records
    }

    fn decoded_samples(config: DeterministicReplayConfig) -> Vec<i16> {
        encoded_records(config)
            .into_iter()
            .flat_map(|record| {
                let decoded = decode_record(&record).unwrap();
                SampleBlockV1::decode(&decoded.payload).unwrap().samples
            })
            .collect()
    }

    #[test]
    fn deterministic_source_emits_contiguous_canonical_records() {
        let mut first = DeterministicReplaySource::new(config()).unwrap();
        let a = first.next_encoded_record().unwrap().unwrap();
        let b = first.next_encoded_record().unwrap().unwrap();
        assert!(first.next_encoded_record().unwrap().is_none());
        let decoded_a = decode_record(&a).unwrap();
        let decoded_b = decode_record(&b).unwrap();
        assert_eq!(
            SampleBlockV1::decode(&decoded_a.payload).unwrap().flags,
            SAMPLE_BLOCK_FLAG_COMPLETE
        );
        assert_eq!(decoded_a.envelope.sample_end_exclusive, 30);
        assert_eq!(decoded_b.envelope.sample_start, 30);
        assert_eq!(decoded_b.envelope.global_time_start_ns, 1_000_000);

        let mut second = DeterministicReplaySource::new(config()).unwrap();
        assert_eq!(a, second.next_encoded_record().unwrap().unwrap());
    }

    #[test]
    fn same_seed_and_config_emit_identical_record_bytes() {
        let first = encoded_records(config());
        let second = encoded_records(config());
        assert_eq!(first, second);
        assert_eq!(first.len(), config().total_records as usize);
    }

    #[test]
    fn record_partition_does_not_change_underlying_sample_stream() {
        let mut blocks_of_30 = config();
        blocks_of_30.total_records = 4;
        let mut blocks_of_24 = blocks_of_30;
        blocks_of_24.samples_per_channel = 24;
        blocks_of_24.total_records = 5;

        let samples_30 = decoded_samples(blocks_of_30);
        let samples_24 = decoded_samples(blocks_of_24);
        assert_eq!(samples_30.len(), 120 * blocks_of_30.channel_count as usize);
        assert_eq!(samples_30, samples_24);

        let source = DeterministicReplaySource::new(blocks_of_30).unwrap();
        for sample_counter in 0..120_u64 {
            for channel in 0..blocks_of_30.channel_count {
                let index = sample_counter as usize * blocks_of_30.channel_count as usize
                    + channel as usize;
                assert_eq!(
                    samples_30[index],
                    source.sample_at(sample_counter, channel).unwrap()
                );
            }
        }
    }

    #[test]
    fn spike_oracle_and_waveform_cross_a_record_boundary() {
        let config = config();
        let source = DeterministicReplaySource::new(config).unwrap();
        let events = source.oracle_events(0, 60).unwrap();
        assert_eq!(
            events,
            vec![SyntheticOracleEvent {
                channel: 0,
                center_sample_counter: 29,
                waveform_start_sample_counter: 24,
                waveform_end_sample_counter_exclusive: 35,
            }]
        );

        let samples = decoded_samples(config);
        for sample_counter in 24..35_u64 {
            let components = source.components_at(sample_counter, 0).unwrap();
            assert_eq!(
                components.spike_counts,
                SYNTHETIC_SPIKE_TEMPLATE[(sample_counter - 24) as usize]
            );
            assert_eq!(
                samples[sample_counter as usize * config.channel_count as usize],
                components.adc_counts
            );
        }
        assert!(source.components_at(29, 0).unwrap().spike_counts < 0);
        assert!(source.components_at(30, 0).unwrap().spike_counts < 0);
    }

    #[test]
    fn component_api_exposes_bounded_noise_and_i16_saturation() {
        let source = DeterministicReplaySource::new(config()).unwrap();
        for sample_counter in 0..10_000 {
            let components = source.components_at(sample_counter, 1).unwrap();
            assert!(components.noise_counts >= -SYNTHETIC_NOISE_PEAK_COUNTS);
            assert!(components.noise_counts <= SYNTHETIC_NOISE_PEAK_COUNTS);
            assert_eq!(
                components.summed_counts,
                components.lfp_counts + components.spike_counts + components.noise_counts
            );
        }

        let saturated = source
            .components_at(SYNTHETIC_SPIKE_FIRST_CENTER_SAMPLE, 0)
            .unwrap();
        assert!(saturated.summed_counts < i16::MIN as i32);
        assert_eq!(saturated.adc_counts, i16::MIN);
        assert_eq!(
            source
                .sample_at(SYNTHETIC_SPIKE_FIRST_CENTER_SAMPLE, 0)
                .unwrap(),
            i16::MIN
        );
    }

    #[test]
    fn integer_component_formula_has_fixed_cross_language_goldens() {
        let source = DeterministicReplaySource::new(config()).unwrap();
        assert_eq!(SYNTHETIC_SCENARIO_ID, "forge.synthetic.neural.integer.v1");
        assert_eq!(SYNTHETIC_DEFAULT_SEED, 9);
        let cases = [
            (
                0,
                0,
                SyntheticSampleComponents {
                    lfp_counts: -2_048,
                    spike_counts: 0,
                    noise_counts: 59,
                    summed_counts: -1_989,
                    adc_counts: -1_989,
                },
            ),
            (
                29,
                0,
                SyntheticSampleComponents {
                    lfp_counts: -1_985,
                    spike_counts: -40_000,
                    noise_counts: -46,
                    summed_counts: -42_031,
                    adc_counts: i16::MIN,
                },
            ),
            (
                82,
                1,
                SyntheticSampleComponents {
                    lfp_counts: -1_614,
                    spike_counts: -40_000,
                    noise_counts: -44,
                    summed_counts: -41_658,
                    adc_counts: i16::MIN,
                },
            ),
            (
                (u32::MAX as u64) + 8,
                1,
                SyntheticSampleComponents {
                    lfp_counts: 858,
                    spike_counts: 0,
                    noise_counts: 38,
                    summed_counts: 896,
                    adc_counts: 896,
                },
            ),
        ];
        for (sample_counter, channel, expected) in cases {
            assert_eq!(
                source.components_at(sample_counter, channel).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn oracle_and_sample_access_validate_ranges() {
        let source = DeterministicReplaySource::new(config()).unwrap();
        assert!(source.sample_at(0, config().channel_count).is_err());
        assert!(source.oracle_events(2, 1).is_err());
        assert!(source.oracle_events(2, 2).unwrap().is_empty());
        assert_eq!(synthetic_spike_period_samples(30_000), 3_000);
        assert_eq!(synthetic_spike_period_samples(1), 64);
        assert_eq!(synthetic_spike_first_center(1), 82);
    }
}
