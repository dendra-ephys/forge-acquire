# Forge CHEM v1 acquisition contract

Status: frozen DHL payload contract; Host persistence and FPGA/AD5940 implementation
remain release-gated.

CHEM v1 is carried in DHL packet type `Chem=3`. It records AD5940 electrochemical
samples and the exact interval during which a fast electrochemical waveform may
contaminate simultaneous RHD electrophysiology. It never replaces or rewrites Neural
samples.

## Accepted acquisition modes

| Value | Mode | Rev A use |
|---:|---|---|
| 1 | AMPEROMETRY | constant-potential current recording |
| 2 | FSCV | repeated fast triangular scan, including dopamine FSCV |
| 3 | CV | reserved for conventional cyclic voltammetry |
| 4 | EIS | reserved; a future sample format is required for complex results |

Electrode-configuration values are TWO_ELECTRODE=1, THREE_ELECTRODE=2,
FOUR_WIRE=3 and FOUR_ELECTRODE_AUX=4. The Headstage exposes CE0, RE0, SE0 and
DE0 separately; a cable/adapter owns any two-electrode CE0/RE0 tie or remote
four-wire Force/Sense join.

## Combined electrophysiology and FSCV policy

- Electrochemistry and RHD2132 use separate working/recording electrodes and separate
  electrochemical and electrophysiology reference electrodes. Rev A does not share a
  carbon-fiber electrode between AD5940 and an RHD input.
- Hardware shall support 1, 2, 5 and 10 Hz FSCV repetition. Combined Ephys+FSCV starts
  at 5 Hz; the standard dopamine profile is 10 Hz, -0.4 V to +1.3 V and back at
  400 V/s. These are acquisition profiles, not a claim that the current AD5940 analog
  implementation has passed the required voltage-range, TIA-headroom or electrode HIL.
- RHD acquisition continues without deleting or interpolating samples. Every FSCV
  record marks an end-exclusive 25 MHz artifact interval. The interval begins at the
  first waveform transition and includes the entire scan plus the configured recovery
  guard. The direct scan interval is always invalid; the post-scan guard is selected
  from measured recovery, initially evaluated over 1 to 5 ms.
- FPGA/Host online sorting must ignore invalid samples and preserve the exposure mask;
  it must not count a masked interval as observed silence. LFP processing must not use
  a blind 10 Hz notch as the sole correction.
- RHD Fast Settle is available but defaults off. It may be enabled only after HIL shows
  that it shortens saturation recovery; its active interval is itself invalid data and
  is indicated by the CHEM flag.

## Payload

The fixed 104-byte prefix is followed by signed little-endian int16 ADC samples in
sample-major order. One or two raw channels are permitted; their physical meaning and
ADC-to-current calibration are bound by `chem_config_hash`.

| Offset | Width | Field |
|---:|---:|---|
| 0 | 2 | version (`1`) |
| 2 | 2 | prefix length (`104`) |
| 4 | 1 | acquisition mode |
| 5 | 1 | electrode configuration |
| 6 | 2 | sample format (`1` = signed int16 LE ADC count) |
| 8 | 4 | flags |
| 12 | 4 | acquisition sequence |
| 16 | 4 | sample count per channel |
| 20 | 2 | channel count (`1..2`) |
| 22 | 2 | reserved (`0`) |
| 24 | 4 | sample-rate numerator in Hz |
| 28 | 4 | sample-rate denominator |
| 32 | 8 | first electrochemical sample counter |
| 40 | 4 | holding potential in signed microvolts vs the configured reference |
| 44 | 4 | switching potential in signed microvolts vs the configured reference |
| 48 | 4 | scan rate in millivolts/second; zero for amperometry |
| 52 | 4 | repetition rate in millihertz; zero for amperometry |
| 56 | 8 | artifact start tick in the 25 MHz Headstage timebase |
| 64 | 8 | artifact end tick, exclusive, in the 25 MHz Headstage timebase |
| 72 | 32 | nonzero SHA-256 of the exact electrochemical configuration/calibration |

Flags are COMPLETE=bit0, HARDWARE_TIMESTAMPED=bit1,
EPHYS_ARTIFACT_WINDOW_VALID=bit2 and FAST_SETTLE_USED=bit3. Other bits are zero.

For AMPEROMETRY, holding and switching potential are equal and scan/repetition rate are
zero. A steady-state packet normally has no artifact window; a bias transition may set
the artifact-window flag and provide a measured interval. For FSCV, scan and repetition
rates are nonzero and the artifact-window flag is mandatory. The outer DHL timestamp is
the first electrochemical sample for AMPEROMETRY and the scan-start time for FSCV.

The raw stream is retained. Background subtraction, calibration, concentration
estimation and artifact-template subtraction are derived analysis products and must
carry their own configuration and algorithm hashes.

## Host boundary

The Pod validates this payload before crossing into the Host domain. Host persistence
must create both a typed electrochemical record and an exact Ephys artifact interval;
silently discarding CHEM, editing Neural sample values, or using USB arrival time is a
protocol violation. The already-frozen Host core protocol is not changed by this
document; its typed electrochem/artifact payload extension and NWB mapping remain an
implementation gate.
