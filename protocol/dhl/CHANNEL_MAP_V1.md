# Forge channel identity v1

This document is the normative interpretation of a Neural sample vector. A channel is
never identified only by its position in a USB packet or by which Intan part happened
to answer first.

The machine-readable companion is [`channel_maps_v1.json`](channel_maps_v1.json).

## Three identities

Every Neural channel has all three of the following identities:

1. `global_channel`: the zero-based index in every sample-major Neural row;
2. `component_instance` plus `native_channel`: the physical Intan instance and that
   device's data-sheet channel number;
3. `electrode_contact`: the board connector contact, when the connector for that
   assembly has been frozen.

The Headstage emits an Inventory packet immediately after Descriptor. Its neural-AFE
entries bind a contiguous global range to a model and instance. The Inventory also
carries the SHA-256 of the exact assembly channel-map artifact. A Host that does not
recognize that hash may store raw data, but shall label connector contacts as unknown;
it must not guess a pin map.

## Rev A logical channel order

Instances are ordered by formal SKiDL reference: `U300`, then `U301`. Native channels
are always ascending. Therefore:

| Profile | Global range | Intan instance | Native range |
|---|---:|---|---:|
| RHD2132 x1 | 0..31 | U300 / instance 0 | 0..31 |
| RHD2132 x2 | 0..31 | U300 / instance 0 | 0..31 |
|  | 32..63 | U301 / instance 1 | 0..31 |
| RHD2164 x1 | 0..63 | U300 / instance 0 | 0..63 |
| RHD2164 x2 | 0..63 | U300 / instance 0 | 0..63 |
|  | 64..127 | U301 / instance 1 | 0..63 |
| RHS2116 x1 | 0..15 | U300 / instance 0 | 0..15 |
| RHS2116 x2 | 0..15 | U300 / instance 0 | 0..15 |
|  | 16..31 | U301 / instance 1 | 0..15 |
| RHD2132 x1 + RHS2116 x1 | 0..31 | U300 / instance 0 / RHD2132 | 0..31 |
|  | 32..47 | U301 / instance 1 / RHS2116 | 0..15 |
| RHD2164 x1 + RHS2116 x1 | 0..63 | U300 / instance 0 / RHD2164 | 0..63 |
|  | 64..79 | U301 / instance 1 / RHS2116 | 0..15 |

Mixed RHD/RHS boards use dedicated profile IDs 7 and 8 and explicit model identity per
Inventory entry. They do not reuse a pure-family profile. IMU and AD5940 are separate
IMU/Chem packet sources and do not consume Neural global-channel numbers.

## Frozen physical connector maps

### RHD2132 x1, 34-contact `5033763410`

The connector order is intentionally not the same as Neural channel order:

| Native/global channel | J400 contact |
|---:|---:|
| 0..5 | 33..28 descending |
| 6..22 | 17..1 descending |
| 23..31 | 26..18 descending |

Contact 27 is `GND`; contact 34 is `REF_ELEC`. Thus, for example, Neural vector index
0 is U300 channel 0 at J400.33, while vector index 31 is U300 channel 31 at J400.18.

### RHD2132 x1 + IMU + electrochem, 40-contact `5033764010`

| Native/global channel | J400 contact |
|---:|---:|
| 0..15 | 1..16 ascending |
| 16..31 | 21..36 ascending |

Contact 17 is `REF_ELEC`; 18/19 are `CHEM_CE0/CHEM_RE0`; 20, 39 and 40 are GND;
37/38 are `CHEM_SE0/CHEM_DE0`. IMU axes and electrochemical streams keep their own
typed payload identities and are not appended to the 32-channel Neural vector.

Physical electrode-contact maps for the remaining connector-open Rev A neural profiles remain open
until their connectors are selected. Their logical global-to-instance mapping above is
already frozen.

### RHS2116 x1/x2, 34-contact `5033763410`

The one-chip product uses contacts 1..16 for `ELEC0..15`, contact 17 for REF and
contact 18 for GND; 19..34 are reserved. The two-chip product follows the accepted
routed permutation: contact 1 is `GND_HS`; contacts 2..17 carry U300 `ELEC15..0`;
contacts 18..25 carry U301 `ELEC0..7`; contact 26 is the shared low-impedance REF;
contacts 27..34 carry U301 `ELEC8..15`. Both RHS2116 `STIM_GND` and `SENSE_GND`
pins use `GND_HS`; the optional global return-current detector is disabled because
the compact connector has no spare isolated return contact.

### RHD2132 x1 + RHS2116 x1, 50-contact `5033765020`

Contacts 1..32 are RHD2132 channels, contacts 33..48 are RHS2116 channels, contact 49
is the shared low-impedance electrode reference and contact 50 is GND. This numbered
map is electrically frozen, but it is not active-PCB-ready until the exact connector
Symbol/Footprint/STEP and shared-reference bench gate pass. The two chips' `ADC_REF`
pins are never shared.

## Mixed-family rule

Every deliberately mixed board requires its own board profile ID, explicit Inventory
entry for every instance, channel-map hash and reviewed Host layout. A new mixed board
may not reuse another mixed or pure profile and may not infer component order from
probe timing.
