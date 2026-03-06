# gotestdata

This directory contains test fixtures that require Go tooling to process them.

## Why `internal/`?

This directory is inside `internal/` to prevent external packages from importing anything
from here. Go's import restrictions on `internal/` directories ensure these fixtures are
only accessible to tests within this package.

## Why not use `testdata`?

Go's build system and module tooling **explicitly ignores directories named `testdata`**. This is documented behavior - when running commands like `go list`, `go mod`, or using `golang.org/x/tools/go/packages`, Go skips any directory named `testdata`.

This becomes a problem for tests that:
- Use `packages.Load()` to resolve Go module dependencies
- Need `go mod` commands to work on fixture `go.mod` files
- Rely on any Go tooling that traverses the module graph

## What goes here?

Place fixtures here that contain `go.mod` files and need Go's module resolution to work. For example:
- `go-source/` - fixtures for testing Go source cataloging with dependency resolution
- Any fixture that uses `WithUsePackagesLib(true)` in tests

## What stays in `testdata`?

Fixtures that don't require Go tooling can remain in `testdata`:
- Static file parsing tests (e.g., parsing `go.mod` without resolution)
- Binary fixtures
- Golden files and snapshots
- Any test using `WithUsePackagesLib(false)`
