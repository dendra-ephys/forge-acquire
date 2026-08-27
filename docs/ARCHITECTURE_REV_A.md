# Forge CABLINE Rev A

Status: candidate architecture under coupon validation. It is not production-ready.

## System

```text
Headstage -- I-PEX CABLINE-UY 10P -- Receiver Pod -- standard USB 3 Type-C -- PC
                                                     |
                                                     +-- optional 1-8 Pod Aggregator -- 10GbE
```

The Headstage-to-Pod link replaces the previous RG178/PoC/FPD-Link architecture. The
only supported recovery source for that previous hardware is the remote cold branch
`origin/codex/dev-cold-forge-pre-redesign-20260816` at
`b4b3378b83909315b7dc9f2e0e124bca87e36498`.

## CABLINE-UY 10P contract

Both boards use the I-PEX `20854-010E-02` 10-position receptacle (LCSC
`C21291250`). The 1 m mixed cable assembly remains a custom qualified harness.

| Pin | Net | Direction | Medium |
|---:|---|---|---|
| 1 | GND_GUARD_0 | reference | ground |
| 2 | DATA_P | Headstage to Pod | AWG40/42 micro-coax |
| 3 | DATA_N | Headstage to Pod | AWG40/42 micro-coax |
| 4 | GND_GUARD_1 | reference | ground |
| 5 | CTRL_P | Pod to Headstage | AWG40/42 micro-coax |
| 6 | CTRL_N | Pod to Headstage | AWG40/42 micro-coax |
| 7 | GND_PWR | return | AWG36 |
| 8 | PWR_MAIN_5V | Pod to Headstage | AWG36 |
| 9 | VSTIM_P7V | Pod to Headstage | AWG36 |
| 10 | VSTIM_N7V | Pod to Headstage | AWG36 |

- DATA is continuous 1.25 Gbit/s 8b/10b and 100-ohm differential.
- CTRL is 20 Mbaud Manchester, approximately 10 Mbit/s payload before framing, and
  100-ohm differential.
- DATA is AC-coupled at the Pod SerDes input. CTRL is terminated at the Headstage
  receiver.
- The 1 m mixed harness is custom and remains unqualified until the coupon gates pass.
- CABLINE-UY has no mechanical lock. Both enclosures shall provide cable capture,
  strain relief, and a load path which bypasses the connector contacts.

## Frozen silicon and clocks

| Location | Device | Clock contract |
|---|---|---|
| Headstage | LFD2NX-17-9MG121I | ECS `ECS-3225MV-250-CN-TR`, 25 MHz, 3.3 V CMOS |
| Receiver Pod | LFE5UM-25F-8MG285I | Microchip `DSC1123CI2-125.0000`, 125 MHz LVDS SerDes reference |
| USB bridge | FT601Q-B-T | 32-bit 245 FIFO, VCCIO=2.5 V |

FT601 bring-up uses 66.666667 MHz. The release target is 100 MHz and requires routed
STA plus sustained hardware throughput evidence. The Pod has an external 12 V input
and supplies 5 V over the harness. The Headstage locally generates 3.3 V, 1.8 V, and
1.0 V using the provisional compact `RY1303` triple-buck topology under `DEC-PWR-002`.

## Product variants

The common Headstage core is instantiated by separate physical boards:

- one or two RHD2132 devices: 32 or 64 channels;
- one or two RHD2164 devices: 64 or 128 channels;
- one or two RHS2116 devices: 16 or 32 channels.

RHD and RHS devices shall not be mixed on one board. AD5940 and IMU are DNP options.
The Receiver Pod generates and owns the VSTIM rail-level disconnect, monitoring,
discharge, watchdog and hardware-permit functions. RHS Headstages receive those rails
on contacts 9/10 and implement the compact Intan M4016/M4032 reference support only:
direct VSTIM distribution, one 100 nF/25 V local bypass per rail and RHS2116, and
`STIM_EN` tied to 3.3 V. Stimulation remains off after RHS2116 power-up until the
documented register unlock/configuration sequence is issued. RHD recording-only
Headstages omit all VSTIM devices/nets and leave contacts 9/10 NC.

## Boundaries

- The Pod is a standard self-powered USB 3 device. SBU pins are unused.
- The Aggregator is optional and presents standard USB Host ports; its detailed PCB is
  deferred.
- DHL v1 is the Headstage-to-Pod inner protocol. The Pod validates DHL and translates
  it into the existing Forge Host protocol. Existing journal, replay, and NWB contracts
  remain authoritative at the Host boundary.
- Every lock epoch begins with Descriptor then Component Inventory. Inventory reports
  detected-ready component models/capabilities and binds the deterministic global,
  Intan-native and connector-contact channel map. Existing Rev A profiles never mix
  RHD and RHS devices on one Headstage.
- Rev A uses industrial-grade FPGA orderable parts but only claims laboratory
  validation over approximately 0 to 50 degrees C.

## Release boundary

Full Headstage and Pod PCB drafting may proceed after the design ECAD gate under
`DEC-PHY-001`. The Headstage drafting baseline is the accepted 0.8 mm/eight-layer
`JLC08081H-1080` stack in `DEC-PCB-002`; CABLINE DATA/CTRL and local Intan LVDS remain
on its controlled outer layers. Neither board may be released until completed-board
PCB/DFM and the cross-family PHY coupon gates pass. A passing schematic, installed
rule baseline, simulation, or nominal coupon does not imply production readiness.
