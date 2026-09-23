# Forge Acquire

Forge Acquire is the private desktop acquisition, recording, replay, and analysis
application for the Dendra Forge neural-recording system.

The operator flow keeps Preview separate from Recording. Recording setup exposes the
Run root and name, forbids overwriting an existing target, and requires adapter-authored
preflight and arm receipts. The embedded Run-directory browser is a bounded desktop
filesystem view; browsing alone does not create a Run or prove storage readiness.

## Run and validate

```powershell
pixi run install
pixi run dev
pixi run check-all
```

The exact-version NWB profile is a separate gate:

```powershell
pixi run -e nwb test-nwb
```

## Product boundary

The simulator and protected software-replay paths are implemented. Direct hardware and
Aggregator adapters remain unavailable until their independent deployment, transport,
and HIL evidence gates pass. A successful software test, bundle, or mock receipt is not
evidence that native acquisition files were produced by qualified hardware.

See `REPOSITORY_CONTRACT.md` for repository provenance and release semantics, and the
documents under `docs/` for the detailed architecture and open qualification gates.

## License

Forge Acquire is licensed under the GNU General Public License version 3 only
(`GPL-3.0-only`). See [LICENSE](LICENSE).
