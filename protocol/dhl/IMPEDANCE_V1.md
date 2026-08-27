# RHD electrode-impedance scan v1

This contract defines the Rev A diagnostic electrode-impedance scan for RHD2132
and RHD2164 Headstages. It is a **pre-recording checkout**, not a continuous
measurement stream and not a replacement for Neural data.

## Operating contract

- The Host sends zero-payload CTRL opcode `ELECTRODE_IMPEDANCE_SCAN` (`0x73`).
- The Headstage accepts it only after Neural acquisition has stopped and the RHD
  bus is quiescent. A scan in progress makes `NEURAL_START` return `NOT_READY`.
- Channels are measured sequentially in native order. The RHD `conn_all` bit is
  always zero; all electrodes are never driven together.
- Rev A uses a 1 kHz, 30-point sine, the RHD on-chip 1 pF injection capacitor,
  DAC amplitude code 127, two warm-up cycles and eight averaged cycles.
- RHD2132 scans channels 0..31 through its single return lane. RHD2164 scans
  channels 0..31 through lane A and 32..63 through lane B.
- The test DAC is returned to midscale and the impedance-test path is disabled
  before the channel result is published.
- Any command timeout, missed phase deadline or transport error fails closed
  until the link/reset epoch is restarted.

The RHD2000-series data sheet is the electrical authority for registers 5, 6
and 7, the 0.1/1/10 pF on-chip test capacitors and the two-command response
pipeline. The checked-in source is
`Forge/docs/sources/Intan_RHD2000_series_datasheet.pdf`.

## DHL packet

Packet type `ELECTRODE_IMPEDANCE=10` carries one complete channel result. The
payload is exactly 88 bytes, little-endian:

| Offset | Width | Field |
|---:|---:|---|
| 0 | 2 | payload version (`1`) |
| 2 | 2 | zero-based channel index |
| 4 | 2 | total channel count (`32` or `64`) |
| 6 | 2 | phase sample count (`30`) |
| 8 | 4 | test frequency (`1000` Hz) |
| 12 | 4 | phase sample rate (`30000` Hz) |
| 16 | 4 | originating CTRL sequence |
| 20 | 1 | Zcheck scale code (`1` = 1 pF) |
| 21 | 1 | DAC amplitude code (`127`) |
| 22 | 1 | warm-up cycles (`2`) |
| 23 | 1 | averaged cycles (`8`) |
| 24 | 2 | clipped raw conversion count |
| 26 | 2 | flags (`0x0007`) |
| 28 | 60 | 30 unsigned 16-bit phase-averaged ADC samples |

Flag bit 0 says the individual channel result is structurally complete; bit 1
marks the pre-recording-only contract; bit 2 says the payload contains raw phase
averages. Scan completion is determined by receiving every channel exactly once
in ascending order, not by using DHL/USB arrival time.

## Host interpretation and release boundary

The FPGA intentionally returns raw phase data. The Host may estimate the complex
1 kHz response and convert it to ohms only through a versioned calibration profile
that covers the injection capacitor, analog transfer function and fixture/electrode
path. Until open/short/known-load and populated-board HIL establish that profile,
the UI and persisted result must say **uncalibrated** and must not present the value
as an absolute electrode impedance.

RTL simulation and codec tests prove command ordering, lane selection, packet bytes
and mutual exclusion. They do not prove injection-current tolerance, analog accuracy,
electrode safety, absolute impedance, or behavior on a populated Headstage.
