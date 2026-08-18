# Developing Syft

This guide covers common contributor workflows that live in this repository.
For environment setup, PR process, and sign-off requirements, see [CONTRIBUTING.md](CONTRIBUTING.md)
and the [Syft contribution guide](https://oss.anchore.com/docs/contributing/syft/).

## Adding a new package cataloger

Catalogers discover packages (and related artifacts) from a `file.Resolver`.
Most catalogers live under `syft/pkg/cataloger/<ecosystem>/` and implement
`pkg.Cataloger`:

```go
type Cataloger interface {
	Name() string
	Catalog(context.Context, file.Resolver) ([]Package, []artifact.Relationship, error)
}
```

### 1. Prefer `generic.NewCataloger`

For ecosystem formats that map files to parsers, use the generic helper
(`syft/pkg/cataloger/generic`). Example pattern from the Alpine DB cataloger:

```go
func NewDBCataloger() pkg.Cataloger {
	return generic.NewCataloger("apk-db-cataloger").
		WithParserByGlobs(parseApkDB, pkg.ApkDBGlob)
}
```

Implement the parser (see `generic.Parser`) so it:

- Reads the matched file contents from the resolver
- Returns one or more `pkg.Package` values with correct `Type`, `Name`, `Version`,
  locations, and ecosystem metadata
- Returns relationships when the format encodes dependency edges

### 2. Package layout

Create a package under `syft/pkg/cataloger/<ecosystem>/` with at least:

| File | Purpose |
|------|---------|
| `cataloger.go` | Constructor(s) and cataloger name |
| parser / decode files | Format-specific parsing |
| `cataloger_test.go` | Tests (prefer `pkgtest` helpers used by sibling catalogers) |
| `test-fixtures/` or `test-data/` | Small real input files |

Mirror conventions from a similar ecosystem cataloger (for example `python`,
`javascript`, or `debian`) rather than inventing a new layout.

### 3. Register the cataloger

Wire the constructor into the default task list in
[`internal/task/package_tasks.go`](internal/task/package_tasks.go) with the tags
that control when it runs:

- `pkgcataloging.ImageTag` / `DirectoryTag` / `InstalledTag` — which source kinds
- ecosystem tags such as `python`, `javascript`, `os`, language names
- selection labels users pass to `--select-catalogers`

Use `newSimplePackageTaskFactory` when the cataloger needs no extra config, or
the config-aware factory helpers already used in that file when it does.

### 4. Capabilities metadata

Catalogers ship machine-readable capability docs. After adding the cataloger:

1. Run tests so observations are produced when applicable
2. Run `go generate ./internal/capabilities`
3. Fill in manual fields in the generated `capabilities.yaml` (ecosystem,
   capability descriptions)
4. Validate with `SYFT_ENABLE_COMPLETENESS_TESTS=true go test ./internal/capabilities/...`

Details: [`internal/capabilities/generate/README.md`](internal/capabilities/generate/README.md).

### 5. Custom catalogers outside the default set

Library users can attach catalogers without editing Syft internals via
`syft.CreateSBOMConfig.WithCatalogers(...)` (see
`examples/create_custom_sbom`). Built-in registration is only required when the
cataloger should run as part of the standard Syft CLI cataloger set.

### 6. Checklist

- [ ] Constructor name and `Name()` string are stable and unique
- [ ] Registered in `internal/task/package_tasks.go` with correct tags
- [ ] Unit/integration tests with fixtures
- [ ] Capability YAML updated and validated
- [ ] Manual smoke test: `go run ./cmd/syft <fixture> -o table` shows expected packages
