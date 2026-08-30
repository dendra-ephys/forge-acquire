# Repository contract

This private repository contains the Forge Host application's product-owned source,
tests, documentation, and build inputs. Tool caches and regenerable outputs such as
`target/`, `node_modules/`, Tauri-generated schemas, and TypeScript build-info files are
excluded.

Every synchronization records its base product revision, clean source-freeze revision,
path-level provenance, and a content-addressed repository snapshot. Files retained from
an earlier product revision remain explicitly attributed to that revision.

Presence in this repository is engineering working state, not a product release. It does
not by itself establish deployed-service behavior, native D3XX acquisition, NWB
publication, fault endurance, hardware qualification, or regulatory readiness.
