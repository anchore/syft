package main

import (
	"path/filepath"
	"runtime"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/file"
	"github.com/anchore/go-make/lang"
	"github.com/anchore/go-make/run"
	"github.com/anchore/go-make/tasks/golint"
	"github.com/anchore/go-make/tasks/goreleaser"
	"github.com/anchore/go-make/tasks/gotask"
	"github.com/anchore/go-make/tasks/gotest"
)

func main() {
	Makefile(
		// shared anchore tasks
		golint.Tasks(),
		goreleaser.Tasks(),

		// unit tests: exclude packages under any test/ directory (matches the syft
		// Taskfile's prior `grep -v` against test paths). Coverage threshold of 62%
		// preserves the prior coverage gate that used to live in scripts/coverage.py.
		gotest.Tasks(
			gotest.Name("unit"),
			gotest.ExcludeGlob("**/test/**"),
			gotest.CoverageThreshold(62),
		),

		// integration tests: native go-make Task. The race-detector smoke against a
		// real image stays bundled here (RunsOn integration) so `make integration`
		// behaves like the Taskfile version did.
		gotest.Tasks(
			gotest.Name("integration"),
			gotest.IncludeGlob("./cmd/syft/internal/test/integration/..."),
			gotest.Verbose(),
			gotest.NoCoverage(),
		),
		Task{
			Name:        "integration:race-smoke",
			Description: "exercise the CLI with the race detector",
			RunsOn:      lang.List("integration"),
			Run: func() {
				Run("go run -race cmd/syft/main.go anchore/test_images:grype-quality-dotnet-69f15d2")
			},
		},

		// cli tests: native go-make Task. Runs SYFT_BINARY_LOCATION at an *absolute*
		// path to the snapshot binary. Builds the snapshot only when the binary is
		// missing rather than depending on the snapshot task unconditionally: in
		// validations.yaml CI we download a pre-built snapshot artifact, so the binary
		// already exists and rebuilding would both burn ~10m and clobber it. When
		// `make test` runs cold (e.g. the release pipeline) or locally with no
		// snapshot, we build a single-target snapshot (current OS/arch only) since
		// that's all the CLI tests need.
		Task{
			Name:        "cli",
			Description: "Run CLI tests",
			RunsOn:      lang.List("test"),
			Run: func() {
				bin := snapshotBinPath()
				if !file.Exists(bin) {
					Log("snapshot binary not found at %s; building single-target snapshot", bin)
					Run("make snapshot:single-target")
				}
				Log("testing binary: %s", bin)
				Run(
					"go test -count=1 -timeout=15m -v ./test/cli",
					run.Env("SYFT_BINARY_LOCATION", bin),
				)
			},
		},

		// default validation pipeline (replaces Taskfile `default`/`pr-validations`/`validations`).
		Task{
			Name:         "default",
			Description:  "Run all validation tasks",
			Dependencies: Deps("static-analysis", "test", "install-test"),
		},

		// --- everything else is implemented in Taskfile.yaml. gotask.Tasks()
		// discovers every (non-internal) Taskfile task — including the namespaced
		// `generate:cpe-index:*` tasks from the included task.d file — and surfaces
		// them as first-class go-make tasks (with their canonical names and `desc:`)
		// that forward to `task <name>`. Descriptions live in Taskfile.yaml as the
		// single source of truth; no per-task wrapping needed here.
		gotask.Tasks(),

		// gotask.Tasks() discovers canonical task names only, not Taskfile aliases,
		// so re-expose `refresh-fixtures`'s `fixtures` alias for manual use.
		Task{
			Name:         "fixtures",
			Description:  "Clear and fetch all test fixture cache (alias of refresh-fixtures)",
			Dependencies: Deps("refresh-fixtures"),
		},

		// gotask.Tasks() can't attach RunsOn labels, so wire the syft-specific
		// Taskfile tasks into go-make's native phases here. These thin hooks have
		// no body and no description (hidden from `make help`); they only pull the
		// discovered tasks in when the labeled phase runs.
		Task{
			Name:         "static-analysis:syft",
			RunsOn:       lang.List("static-analysis"),
			Dependencies: Deps("check-json-schema-drift", "check-binary-fixture-size"),
		},
		Task{
			Name:         "test:syft",
			RunsOn:       lang.List("test"),
			Dependencies: Deps("validate-cyclonedx-schema", "test-utils", "check-docker-cache"),
		},
		// refresh-fixtures hooks into "unit" so `make unit` triggers the stale-cache
		// detection + download just like `task unit` did on main (its
		// `deps: [tmpdir, fixtures]` is what kept the fixture cache fresh).
		Task{
			Name:         "unit:syft",
			RunsOn:       lang.List("unit"),
			Dependencies: Deps("refresh-fixtures"),
		},
		Task{
			Name:   "clean:syft",
			RunsOn: lang.List("clean"),
			Dependencies: Deps(
				"clean-snapshot",
				"clean-docker-cache",
				"clean-oras-cache",
				"clean-cache",
				"clean-test-observations",
			),
		},
	)
}

// snapshotBinPath replicates the SNAPSHOT_BIN computation from the prior Taskfile:
// <repoRoot>/snapshot/<os>-build_<os>_<arch>/syft, where arch maps amd64->amd64_v1
// and arm64->arm64_v8.0 to match goreleaser's per-target output directory naming.
// Returns an absolute path: the cli tests' getSyftBinaryLocation contract requires
// SYFT_BINARY_LOCATION to be absolute because subtests run with cmd.Dir = t.TempDir().
func snapshotBinPath() string {
	osName := runtime.GOOS
	var arch string
	switch runtime.GOARCH {
	case "amd64":
		arch = "amd64_v1"
	case "arm64":
		arch = "arm64_v8.0"
	default:
		arch = runtime.GOARCH
	}
	return filepath.Join(RootDir(), "snapshot", osName+"-build_"+osName+"_"+arch, "syft")
}
