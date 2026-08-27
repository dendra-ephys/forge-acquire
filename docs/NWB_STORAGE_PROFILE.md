# Forge NWB storage profile

Status: first-release container baseline frozen; chunk geometry still requires benchmark evidence

## Current implementation evidence

The optional `nwb` pixi profile is locked to h5py 3.16.0/HDF5 2.1.0,
PyNWB 4.1.0, and NWB Inspector 0.7.2. Its current backend creates a new
generation-specific, uncompressed `.nwb.inprogress`, precreates one
`ElectricalSeries` per Pod plus provenance/event tables, then enables SWMR.
Twelve synthetic tests prove append/flush visibility to a concurrent h5py
reader, exact PyNWB replay, schema validation, no critical Inspector findings,
closed-generation hash/provenance/count reconciliation with tamper rejection,
rebuild into a new generation after an interrupted writer, a deterministic
durable-checkpoint/EOF concurrency race, one real child-process kill whose
generation-1 artifact remains byte-identical while generation 2 replays from
sequence zero, and a real
Python-`forge-nwbd` to Rust-`forge-acqd` validation-receipt handoff. The Rust
side independently stream-hashes the bound artifacts, publishes through a
same-directory no-overwrite link plus frozen receipt, exercises idempotent
retry, and rejects subsequent NWB tampering. A two-Pod interleaved fixture uses
different two- and three-channel geometries, two SampleBlocks per Pod and a
legitimate discontinuity flag. It compares every HDF5 raw sample block against
the canonical journal payload as exact little-endian signed-16-bit,
sample-major `[sample, channel]` bytes; a one-byte Pod-2 HDF5 mutation prevents
both a passing report and a validation receipt. One mixed-record test appends
one SampleBlock plus Marker, Fault, Gap, OnlineAnalysis, StimIntent and
StimReceipt, reconciles all seven sealed journal records, and does not count
the six typed events as neural samples.

The Rust owner verifier binds the worker report to the actual journal, NWB,
manifest, checkpoint and report hashes, and independently checks the manifest's
per-Pod channel geometry, sample/block maps, byte arithmetic and digest keys.
It does not itself decode HDF5. Therefore this closes the current worker-format
raw-byte policy, but production trust still requires the qualified worker
executable, ACL/stable-handle supervision and the remaining release gates.

This is format/behavior evidence on a tiny software fixture. It is not the
production supervised `forge-nwbd` service and is not throughput, endurance,
the required 100-kill qualification, directory-metadata, NTFS/PLP, or power-loss
evidence. The local
publisher's passing tests do not by themselves authorize a release claim.
The default development environment continues to report NWB unavailable so an
optional dependency cannot silently become part of the acquisition path.

## Answer to “can NWB save during acquisition?”

Yes. NWB/HDF5 supports extendible, chunked datasets that can be appended while acquisition continues. SWMR permits one writer and multiple readers to observe data after writer flushes. It does not permit multiple independent writers to modify the same file, and it does not preserve an unflushed tail after a crash.

Forge therefore uses “synchronous saving” to mean concurrent saving by an independent writer, not blocking the hardware-receive thread on compression or disk I/O:

```text
acquisition thread → durable journal
                         └→ asynchronous/restartable NWB materializer
```

## Container baseline

- final exchange container: NWB 2.x in local HDF5;
- one experimental Run per file;
- continuous raw voltage in acquisition `ElectricalSeries` datasets;
- raw sample type preserved as lossless integer data with physical-unit conversion metadata;
- hardware sample/frame/global-time identity and gap/fault events retained separately from USB/Ethernet arrival time;
- all groups, datasets, attributes, marker columns, and integrity-event columns needed during a Run are created before entering SWMR;
- write slabs align exactly with HDF5 chunk boundaries;
- local NTFS NVMe only for first-release live recording; network shares are outside the live-write contract;
- NWB-Zarr remains an optional later export because the official HDMF-Zarr backend is still described as experimental.

The official AqNWB C++ acquisition API is relevant but its overview currently warns that it is still under active development and should not yet be relied on as a production guarantee. Forge may evaluate it behind the restartable materializer boundary; it must not become the sole acquisition truth source.

## Compression

NWB does not define one compression algorithm or a universal compression ratio. HDF5 applies filters per chunk. Neural-signal compression depends strongly on ADC effective bits, noise, referencing, stimulation artefacts, channel correlation, and chunk geometry.

Production candidates, in order of portability:

1. no compression — safety and throughput baseline;
2. shuffle + GZIP level 1 — portable candidate;
3. shuffle + GZIP level 4 — ratio-oriented portable candidate;
4. LZF or packaged LZ4/Zstandard filters — only after reader portability and installer packaging are proven.

No lossy filter is allowed for raw acquisition. A codec profile is enabled only if the uncompressed journal remains protected and the materializer passes its throughput/fault gate.

The first-release live profile is deliberately **uncompressed HDF5 SWMR**.
There is exactly one writer and only local readers on the acquisition PC are
supported during a Run. The target flush cadence is two seconds; it is a
visibility bound, not a durability or zero-loss guarantee. Any later compressed
profile is a new evidence-bound codec profile and cannot silently replace this
baseline.

The current `forge-nwbd --mode live` scheduler defaults to 250 ms and rejects
configured poll intervals outside 1..2000 ms. It flushes after every non-empty
bounded batch and never signals the acquisition writer. This is an implemented
scheduler bound, not measured proof that storage and HDF5 append latency remain
below two seconds at the release load.

## Capacity facts

The planned eight-Pod stream is 126.72 MB/s. Before container overhead and using decimal units, that is:

| Duration | Uncompressed payload |
|---:|---:|
| 1 hour | 456.192 GB |
| 8 hours | 3.649536 TB |
| 24 hours | 10.948608 TB |

The internal stress target is at least 190.08 MB/s sustained (1.5× planned input). This is a Forge engineering gate, not an NWB performance claim.

At that stress rate, one uncompressed 24-hour stream is `16.423 TB` (decimal). Keeping both the authoritative journal and a concurrent uncompressed NWB generation requires `32.846 TB` before container/checkpoint overhead. Applying a 20% operating reserve gives `39.416 TB`; the release fixture therefore requires at least **40 TB formatted usable** on local NTFS storage with power-loss protection. Its sustained physical-write qualification floor is `437.184 MB/s`: the `380.16 MB/s` two-copy payload rate plus 15% engineering headroom for filesystem, journal, checkpoint, metadata and flush overhead. Capacity arithmetic is not write-performance evidence; the exact target volume still requires an evidence-bound end-to-end qualification receipt.

## Benchmark matrix

Use representative Forge `int16` recordings and compare:

- no compression;
- shuffle + GZIP-1;
- shuffle + GZIP-4;
- any bundled fast filter proposed for release.

Start with 256 KiB, 1 MiB, 4 MiB, and 8 MiB aligned chunks; keep the acquisition slab equal to one or an integer number of chunks. For each profile measure:

- payload and physical write MB/s;
- compression ratio;
- CPU and memory;
- p50, p99, and maximum append latency;
- journal and NWB backlog watermarks;
- durable lag;
- sample/frame counters, gaps, CRC errors, and recovery tail;
- performance on a cold drive, after SLC-cache exhaustion, near full disk, and with normal Windows Defender activity.

Run at least 8 hours for codec selection and 24 hours for the release gate. Kill the NWB worker during the test and prove that it can rebuild the identical logical dataset from the journal.

## Finalize gate

1. stop input at an acknowledged complete-frame boundary;
2. drain through the last expected sequence;
3. cross a journal durability barrier and seal it;
4. materialize or catch up `.nwb.inprogress`;
5. flush, finalize, and close the HDF5 writer;
6. reopen and reconcile dataset shapes and sample/frame ranges;
7. run PyNWB schema validation;
8. run NWB Inspector;
9. atomically create and flush the no-overwrite final `.nwb` on the same directory/volume;
10. commit and verify the publication receipt, then bind it to the sealed Run ledger;
11. retain the journal until publication and backup policy both succeed.

Schema and Inspector success prove format compliance and best-practice checks; they do not prove that no hardware frame was lost. Forge counter/CRC reconciliation is an independent mandatory gate.

## Official references

- [PyNWB iterative streaming write](https://pynwb.readthedocs.io/en/stable/tutorials/advanced_io/plot_iterative_write.html)
- [PyNWB chunking and compression](https://pynwb.readthedocs.io/en/stable/tutorials/advanced_io/h5dataio.html)
- [h5py datasets and filter pipeline](https://docs.h5py.org/en/stable/high/dataset.html)
- [h5py SWMR](https://docs.h5py.org/en/stable/swmr.html)
- [PyNWB validation](https://pynwb.readthedocs.io/en/stable/validation.html)
- [HDMF-Zarr status](https://hdmf-zarr.readthedocs.io/en/stable/overview.html)
- [AqNWB status](https://nwb.org/aqnwb/index.html)
