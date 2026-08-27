# Forge host protocol v1

This subtree freezes the first **host-internal** binary contract shared by
`forge-acqd`, the restartable NWB/analysis workers, and the C++/Python SDKs.
It does not claim that the Receiver Pod FPGA, FTDI D3XX transport, or
Aggregator firmware already speaks this format.

The normative source is [`schema/forge_protocol_v1.idl`](schema/forge_protocol_v1.idl).
Every frame is little-endian, versioned, bounded, checksummed with CRC-32C,
and bound to the SHA-256 protocol-contract hash. Rust, Python, and C++
bindings share the same exact layouts and golden byte vectors.

Frozen v1 contract hash (SHA-256 over the IDL after newline normalization to
UTF-8 LF):

`4e3db23e15a1480707132d28bdc820f36fdabbb5d20d9d84850ae89166b3efa0`

Typed Marker, Fault, Gap, and OnlineAnalysis bodies use the companion
[`schema/forge_event_payload_v1.idl`](schema/forge_event_payload_v1.idl)
extension. It is independently self-hashed so the already-frozen parent
record/control bytes remain unchanged. Its LF-normalized SHA-256 is:

`68ad1bf0c16c57ddcad79cc8e5a950513d8e54a2c874cbe4b56cea054b7dd6d8`

`StimIntentV1` and `StimReceiptV1` records carry the existing exact v1 bodies,
not a second event representation. The Rust, Python and read-only C++ parsers
validate both hashes and share four additional typed-event golden vectors.

Safety is fail-closed. A real stimulation intent is rejected unless all of
the following are simultaneously true:

- the message and device protocol hashes match this contract;
- the device advertises RHS2116 stimulation and all required safety features;
- a fresh runtime snapshot independently says physical ENABLE is asserted,
  the emergency-stop loop is healthy, stimulation power is enabled, the
  watchdog is healthy, and the compliance path is ready;
- an approved, non-placeholder `SafetyProfileV1` is frozen for the active arm
  epoch;
- the caller holds the single unexpired controller token for that epoch;
- algorithm, config, template, mapping, worker-build, and safety-profile
  identities match the frozen token;
- the intent is not expired and every generated command is within the frozen
  integer safety limits.

CRC is an integrity check, not authentication. The Windows named pipe still
requires service ACL/SID authorization, and device transports require their
own authenticated identity and replay protection.

## Layout

- `schema/` — normative IDL and hash policy;
- `rust/` — dependency-free Rust codec and safety validation;
- `python/` — dependency-free Python codec and safety validation;
- `cpp/` — allocation-free C++20 read-only views/parser and golden verifier;
- `golden/` — exact canonical wire bytes and deliberately illegal examples.

## Scoped checks

From `Forge/host_app/protocol`:

```powershell
pixi run --manifest-path ..\pixi.toml cargo test --manifest-path rust\Cargo.toml
pixi run --manifest-path ..\pixi.toml cargo fmt --manifest-path rust\Cargo.toml -- --check
pixi run --manifest-path ..\pixi.toml cargo clippy --manifest-path rust\Cargo.toml --all-targets -- -D warnings
pixi run --manifest-path ..\pixi.toml python -m unittest discover -s python\tests -v
pixi run --manifest-path ..\pixi.toml g++ -std=c++20 -Wall -Wextra -Werror `
  -Icpp\include cpp\tests\golden_test.cpp -o cpp\tests\golden_test.exe
cpp\tests\golden_test.exe golden
```

The C++ executable is a local build artifact and is not source evidence.

The Rust crate is the production SafetyArbiter codec surface. The Python
binding is the worker/SDK reference. The C++20 surface is deliberately
read-only in v1: it parses and validates received records/control messages but
cannot construct `StimCommandV1`; algorithms may only submit `StimIntentV1`
through a future separately qualified authenticated controller boundary. The
current analysis-worker registration contract is observer-only and rejects
controller authority.
