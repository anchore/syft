package cataloger_test

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	gosync "github.com/anchore/go-sync"
	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

const (
	// per-input limits. These are generous on purpose: the net is for inputs that take seconds or
	// hundreds of MB, not for small inefficiencies.
	fuzzTimeout = 10 * time.Second
	// fuzzHangSlack is how long past fuzzTimeout a parser that ignores ctx gets before the process is taken down,
	// so a ctx-aware parser always reports its timeout through the normal path first
	fuzzHangSlack     = 5 * time.Second
	fuzzAllocBase     = 256 << 20
	fuzzAllocPerByte  = 1024
	fuzzMaxSeedBytes  = 256 << 10
	fuzzMaxSeedsPerFn = 8
)

type fuzzTarget struct {
	cataloger string
	glob      string
	path      string // a concrete relative path that matches glob
	dir       string // the cataloger package directory, relative to this package, for seeds
	task      task.Task
}

func (ft fuzzTarget) String() string { return ft.cataloger + " " + ft.glob }

// FuzzGenericParsers feeds one input at a time to each glob-selected parser of every generic cataloger, by writing
// it to a path the parser's glob matches and running the cataloger task over that directory. Catalogers that are not
// generic, and processor panics (which the generic cataloger only logs), are not covered.
//
// # What fuzzing is
//
// A fuzz test is a test whose input is generated. Go's fuzzer starts from a set of example inputs (the seed corpus),
// mutates them (flipping bytes, splicing pieces together, inserting values) and keeps any mutation that reaches code
// it has not reached before, so over time it works its way into parser branches that hand-written tests never try.
// Each input is one parser and one file's worth of bytes. An input fails when the parser:
//
//   - panics (including a panic the generic cataloger recovers and reports as an unknown)
//   - takes longer than fuzzTimeout
//   - allocates much more than the input size warrants (see fuzzAllocBase and fuzzAllocPerByte)
//
// A parser returning an error is fine: rejecting bad input is the correct behavior.
//
// # Plain go test (no fuzzing)
//
// Without -fuzz, go test does not generate anything. It runs every seed once, like a table test, and reports them
// as subtests named seed#0, seed#1, ... (go names seeds by position; the failure message says which parser it was).
// The seeds are each parser's own testdata files plus a few inputs built from the string literals in its package,
// which give the parser its own key names and prefixes to trip over. This is what runs in CI, and takes seconds.
// It also replays every saved failure in testdata/fuzz/FuzzGenericParsers/ (see below).
//
// # Running the fuzzer
//
// Fuzzing is only done on demand, locally. Pick one parser with SYFT_FUZZ_TARGET, a regexp over
// "<cataloger> <glob>" (cataloger names are listed by `syft cataloger list`), and give it a time budget:
//
//	SYFT_FUZZ_TARGET='^apk-db-cataloger ' go test ./syft/pkg/cataloger -run '^$' -fuzz FuzzGenericParsers -fuzztime 60s
//
// -run '^$' skips the ordinary tests, and -fuzztime bounds the run (without it the fuzzer runs until stopped).
// Without SYFT_FUZZ_TARGET every parser shares one run, so each gets a small slice of the time. The fuzzer's
// "new interesting" inputs are kept in the go build cache, not the repo, so later runs pick up where earlier ones
// left off.
//
// # When the fuzzer finds a failure
//
// It shrinks the input to a small version that still fails, prints the failure, and writes it to
// testdata/fuzz/FuzzGenericParsers/<hash>. That file is two lines of text, the parser name and the input bytes, so
// it can be read in review. From then on plain go test replays it as the subtest FuzzGenericParsers/<hash>, and it
// can be run alone:
//
//	go test ./syft/pkg/cataloger -run 'FuzzGenericParsers/<hash>'
//
// The lifecycle of a failure:
//
//  1. fix the parser so the input is rejected with an error (or parsed correctly) rather than panicking or hanging
//  2. commit the saved file in the same change as the fix, as the regression test for it; do not commit one without
//     its fix, since it fails every test run until the fix lands
//  3. fuzz that parser again, since one fix often uncovers the next failure behind it
//
// Saved files are kept indefinitely, like any other regression test. Delete one only when it no longer means
// anything (for example, the parser it names was removed). A test case in the parser's own _test.go is an equally
// good home for the input, and reads better there.
func FuzzGenericParsers(f *testing.F) {
	targets := fuzzTargets(f)
	if len(targets) == 0 {
		f.Skip("no targets selected")
	}

	// inputs name their target rather than index it, so a saved crasher keeps pointing at the same parser when
	// the target list changes or is filtered
	byName := map[string]fuzzTarget{}
	for _, ft := range targets {
		byName[ft.String()] = ft
		for _, seed := range fuzzSeeds(ft) {
			f.Add(ft.String(), seed)
		}
	}

	f.Fuzz(func(t *testing.T, name string, data []byte) {
		ft, ok := byName[name]
		if !ok {
			// while fuzzing, the mutator rewrites names too, and a filter deliberately drops targets. Otherwise this
			// is a saved input whose target was renamed or removed, and skipping it would silently drop a regression.
			if os.Getenv("SYFT_FUZZ_TARGET") == "" && flag.Lookup("test.fuzz").Value.String() == "" {
				t.Fatalf("saved fuzz input names unknown target %q: update or remove it", name)
			}
			t.Skip("not a selected target")
		}
		runFuzzTarget(t, ft, data)
	})
}

func runFuzzTarget(t *testing.T, ft fuzzTarget, data []byte) {
	root := t.TempDir()
	p := filepath.Join(root, filepath.FromSlash(ft.path))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := src.FileResolver(source.AllLayersScope)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(pkgtest.Context(t), fuzzTimeout)
	defer cancel()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	// the heap metric is process-wide and counts unswept garbage, so collect first and measure growth from there
	heap := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	runtime.GC()
	metrics.Read(heap)
	heapBase := heap[0].Value.Uint64()

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic: %v\n%s", r, debug.Stack())
			}
		}()
		done <- ft.task.Execute(ctx, resolver, sbomsync.NewBuilder(&sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}))
	}()

	limit := uint64(fuzzAllocBase + fuzzAllocPerByte*len(data))
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(fuzzTimeout + fuzzHangSlack)
wait:
	for {
		select {
		case err = <-done:
			break wait
		case <-tick.C:
			// the after-the-fact TotalAlloc check below can't stop a parser that is on its way to exhausting the
			// machine, so watch heap growth while it runs and take the process down once it passes the limit
			metrics.Read(heap)
			if grown := heap[0].Value.Uint64() - min(heapBase, heap[0].Value.Uint64()); grown > limit {
				_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
				panic(fmt.Sprintf("%s: input of %d bytes grew the heap by %d MB (limit %d MB)", ft, len(data), grown>>20, limit>>20))
			}
		case <-deadline:
			// not every parser watches ctx, so a hung one keeps running and would skew every later input in this
			// process. Dump where it is stuck and take the process down; the fuzz engine records that as a crasher.
			_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
			panic(fmt.Sprintf("%s: input of %d bytes did not finish within %s", ft, len(data), fuzzTimeout+fuzzHangSlack))
		}
	}

	if ctx.Err() != nil {
		t.Fatalf("%s: input of %d bytes did not finish within %s", ft, len(data), fuzzTimeout)
	}

	// a panic recovered further down (a go-sync PanicError, or the generic per-file recover) still surfaces as an error
	if errors.As(err, &gosync.PanicError{}) || hasRecoveredPanic(err) {
		t.Fatalf("%s: %v", ft, err)
	}

	// TotalAlloc is cumulative, so this bounds churn rather than peak, and it is read after the fact: a single huge
	// allocation kills the process before this check, which the fuzz engine still records as a crasher
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > limit {
		t.Fatalf("%s: input of %d bytes allocated %d MB (limit %d MB)", ft, len(data), alloc>>20, limit>>20)
	}
}

// hasRecoveredPanic finds an error anywhere in the tree that starts with "recovered from panic", the wording of the
// generic per-file recover (and of the golang and license recovers). Matching on the start of a node keeps parse
// errors that echo the input from counting.
func hasRecoveredPanic(err error) bool {
	if err == nil {
		return false
	}
	if strings.HasPrefix(err.Error(), "recovered from panic") {
		return true
	}
	switch u := err.(type) {
	case *unknown.CoordinateError:
		// per-file errors arrive wrapped with their location, and CoordinateError does not unwrap
		return hasRecoveredPanic(u.Reason)
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			if hasRecoveredPanic(e) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return hasRecoveredPanic(u.Unwrap())
	}
	return false
}

// fuzzTargets pairs every glob-selected parser in the capabilities data with the task that runs its cataloger.
func fuzzTargets(tb testing.TB) []fuzzTarget {
	tasks, err := task.DefaultPackageTaskFactories().Tasks(task.DefaultCatalogingFactoryConfig())
	if err != nil {
		tb.Fatal(err)
	}
	byName := map[string]task.Task{}
	for _, tsk := range tasks {
		byName[tsk.Name()] = tsk
	}

	entries, err := capabilities.Packages()
	if err != nil {
		tb.Fatal(err)
	}

	var filter *regexp.Regexp
	if v := os.Getenv("SYFT_FUZZ_TARGET"); v != "" {
		if filter, err = regexp.Compile(v); err != nil {
			tb.Fatalf("SYFT_FUZZ_TARGET: %v", err)
		}
	}

	var targets []fuzzTarget
	for _, e := range entries {
		tsk, ok := byName[e.Name]
		if e.Type != "generic" || !ok {
			continue
		}
		for _, p := range e.Parsers {
			// glob parsers only. The mimetype parsers (binary classifiers) need a real executable
			// header to be selected at all; add them if a mutating seed turns out to be worth it.
			if p.Detector.Method != capabilities.GlobDetection {
				continue
			}
			for _, g := range p.Detector.Criteria {
				ft := fuzzTarget{
					cataloger: e.Name,
					glob:      g,
					path:      concretePath(g),
					dir:       strings.TrimPrefix(filepath.Dir(e.Source.File), "syft/pkg/cataloger/"),
					task:      tsk,
				}
				if ok, _ := doublestar.Match(g, "/"+ft.path); !ok || !filepath.IsLocal(ft.path) {
					tb.Logf("skipping %s: no concrete path for glob", ft)
					continue
				}
				if filter != nil && !filter.MatchString(ft.String()) {
					continue
				}
				targets = append(targets, ft)
			}
		}
	}
	if filter != nil && len(targets) == 0 {
		tb.Fatalf("SYFT_FUZZ_TARGET %q matches no target", filter)
	}
	return targets
}

var braceAlt = regexp.MustCompile(`\{([^,}]*)[^}]*\}`)

// concretePath turns a glob into one relative path it matches, e.g. `**/*.gguf` -> `x.gguf`.
func concretePath(glob string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(glob, "**/"), "/")
	s = braceAlt.ReplaceAllString(s, "$1")
	s = strings.ReplaceAll(s, "**", "x")
	return strings.ReplaceAll(s, "*", "x")
}

// fuzzSeeds is the parser's own testdata that matches its glob, plus a few inputs built from the string literals in
// its package. Random bytes rarely produce the exact key names a parser branches on, the literals give the mutator
// something to splice.
func fuzzSeeds(ft fuzzTarget) [][]byte {
	var seeds [][]byte
	// the CLI's malformed fixtures are deliberately not seeds here: before their fixes land some of them allocate
	// gigabytes, which in-process means swapping the machine rather than failing a check. The CLI test runs them in
	// a subprocess under a memory limit instead.
	_ = filepath.WalkDir(ft.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || len(seeds) >= fuzzMaxSeedsPerFn {
			return fs.SkipAll
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if ok, _ := doublestar.Match(ft.glob, "/"+filepath.ToSlash(p)); !ok {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > fuzzMaxSeedBytes {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil {
			seeds = append(seeds, b)
		}
		return nil
	})

	lits := stringLiterals(ft.dir)
	if len(lits) == 0 {
		return append(seeds, []byte{})
	}
	obj := map[string]string{}
	var lines, kv strings.Builder
	for _, l := range lits {
		obj[l] = l
		lines.WriteString(l + "\n")
		kv.WriteString(strconv.Quote(l) + ": " + strconv.Quote(l) + "\n")
	}
	js, _ := json.Marshal(obj)
	return append(seeds, []byte(lines.String()), []byte(kv.String()), js)
}

// stringLiterals returns the distinct short string literals in the non-test go files of a package directory.
func stringLiterals(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	set := map[string]struct{}{}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				if s, err := strconv.Unquote(bl.Value); err == nil && len(s) > 1 && len(s) <= 64 {
					set[s] = struct{}{}
				}
			}
			return true
		})
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
