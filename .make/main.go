package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/goccy/go-yaml"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/file"
	"github.com/anchore/go-make/git"
	"github.com/anchore/go-make/lang"
	"github.com/anchore/go-make/run"
	"github.com/anchore/go-make/tasks/golint"
	"github.com/anchore/go-make/tasks/goreleaser"
	"github.com/anchore/go-make/tasks/gotest"
)

// taskfileDescriptions maps Taskfile.yaml task names to their `desc:` field.
// Loaded at package init so wrap() can use Taskfile.yaml as the single source
// of truth for wrapped-task descriptions.
var taskfileDescriptions = mustReadTaskfileDescriptions()

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

		// --- everything below is implemented in Taskfile.yaml and surfaced here
		// via wrap(). Descriptions come from Taskfile.yaml (single source of truth).

		// static analysis extras
		wrap("check-json-schema-drift").RunOn("static-analysis"),
		wrap("check-capability-drift"),
		wrap("check-binary-fixture-size").RunOn("static-analysis"),

		// test extras
		wrap("validate-cyclonedx-schema").RunOn("test"),
		wrap("test-utils").RunOn("test"),
		wrap("check-docker-cache").RunOn("test"),
		wrap("snapshot-smoke-test"),

		// update commands
		wrap("update-format-golden-files"),

		// fixture cache plumbing (heavy ORAS logic, lives in Taskfile).
		// refresh-fixtures hooks into "unit" so `make unit` triggers the
		// stale-cache detection + download just like `task unit` did on main
		// (its `deps: [tmpdir, fixtures]` is what kept the fixture cache fresh).
		wrap("fingerprints"),
		wrap("refresh-fixtures").RunOn("unit"),
		wrap("fixtures"),
		wrap("build-fixtures"),
		wrap("download-test-fixture-cache"),
		wrap("upload-test-fixture-cache"),
		wrap("show-test-image-cache"),

		// install-script tests (delegates to test/install/Makefile)
		wrap("install-test"),
		wrap("install-test-cache-save"),
		wrap("install-test-cache-load"),
		wrap("install-test-ci-mac"),

		// compare tests
		wrap("generate-compare-file"),
		wrap("compare-mac"),
		wrap("compare-linux"),
		wrap("compare-test-deb-package-install"),
		wrap("compare-test-rpm-package-install"),

		// code/data generation (umbrella + per-target; each lives in Taskfile)
		wrap("generate"),
		wrap("generate-json-schema"),
		wrap("generate-license-list"),
		wrap("generate-cpe-dictionary-index"),
		wrap("generate-capabilities"),

		// cleanup (each hooks into go-make's built-in `clean` label)
		wrap("clean-snapshot").RunOn("clean"),
		wrap("clean-docker-cache").RunOn("clean"),
		wrap("clean-oras-cache").RunOn("clean"),
		wrap("clean-cache").RunOn("clean"),
		wrap("clean-test-observations").RunOn("clean"),
	)
}

// wrap creates a go-make Task that delegates execution to `task <name>`. The
// task's description is pulled from Taskfile.yaml's `desc:` field — descriptions
// for wrapped tasks must always live in Taskfile.yaml, never here.
func wrap(name string) Task {
	desc, ok := taskfileDescriptions[name]
	if !ok || desc == "" {
		// loud-fail at startup so missing descs can't sneak through review.
		panic(fmt.Sprintf("Taskfile.yaml task %q is missing a `desc:` field; please add one", name))
	}
	return Task{
		Name:        name,
		Description: desc,
		Run:         func() { Run("task " + name) },
	}
}

// mustReadTaskfileDescriptions parses Taskfile.yaml at the repo root and returns
// a map of task name -> desc. Runs at package init time so wrap() can use it.
func mustReadTaskfileDescriptions() map[string]string {
	root := git.Root()
	if root == "" {
		return nil
	}
	path := filepath.Join(root, "Taskfile.yaml")
	data, err := os.ReadFile(path) //nolint:gosec // G304: path resolved from git.Root()
	if err != nil {
		return nil
	}
	var tf struct {
		Tasks map[string]struct {
			Desc    string   `yaml:"desc"`
			Aliases []string `yaml:"aliases"`
		} `yaml:"tasks"`
	}
	lang.Throw(yaml.Unmarshal(data, &tf))
	out := make(map[string]string, len(tf.Tasks))
	for name, t := range tf.Tasks {
		out[name] = t.Desc
		// aliases inherit the canonical task's description so wrap() can find them.
		for _, alias := range t.Aliases {
			out[alias] = t.Desc
		}
	}
	return out
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
