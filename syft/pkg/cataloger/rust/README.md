# Rust development dependencies

The Cargo lockfile cataloger includes development dependencies by default. To
exclude dependencies used only for tests, examples, and benchmarks, configure:

```yaml
rust:
  include-dev-dependencies: false
```

The equivalent environment variable is `SYFT_RUST_INCLUDE_DEV_DEPENDENCIES=false`.

Filtering requires the project's `Cargo.toml` and any relevant workspace or path
dependency manifests in the scan source. Syft removes development-only dependency
edges and their exclusive transitive dependencies. Dependencies also needed by
normal or build dependencies remain included, as do workspace member packages.

Cargo configuration patches found in the scan source, including ancestor,
member, and subdirectory configuration files, make source comparisons
conservative so patched runtime dependencies remain included. Since the Cargo
invocation directory is unknown, a patch under one member is treated as a
possible override for the entire workspace. Both modern and legacy Cargo
configuration files are supported.

Root-level Cargo `[replace]` overrides also make source comparisons conservative
across workspace members, preserving runtime replacements shared with development
dependencies.

Filtering is conservative: missing manifests or ambiguous dependency scopes can
leave additional packages in the SBOM. This does not reproduce Cargo's selection
of features or target platforms. The auditable binary cataloger is unaffected.
