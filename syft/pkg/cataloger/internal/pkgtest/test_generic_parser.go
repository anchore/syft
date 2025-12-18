package pkgtest

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/licensecheck"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/internal/cmptest"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/anchore/syft/syft/source/filesource"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

var (
	once           sync.Once
	licenseScanner *licenses.Scanner
)

type CatalogTester struct {
	expectedPkgs                   []pkg.Package
	expectedRelationships          []artifact.Relationship
	assertResultExpectations       bool
	expectedPathResponses          []string // this is a minimum set, the resolver may return more that just this list
	expectedContentQueries         []string // this is a full set, any other queries are unexpected (and will fail the test)
	ignoreUnfulfilledPathResponses map[string][]string
	ignoreAnyUnfulfilledPaths      []string
	env                            *generic.Environment
	reader                         file.LocationReadCloser
	resolver                       file.Resolver
	wantErr                        require.ErrorAssertionFunc
	compareOptions                 []cmp.Option
	locationComparer               cmptest.LocationComparer
	licenseComparer                cmptest.LicenseComparer
	packageStringer                func(pkg.Package) string
	customAssertions               []func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship)
	context                        context.Context
	skipTestObservations           bool
}

func Context() context.Context {
	once.Do(func() {
		// most of the time in testing is initializing the scanner. Let's do that just once
		sc := &licenses.ScannerConfig{Scanner: licensecheck.Scan, CoverageThreshold: 75}
		scanner, err := licenses.NewScanner(sc)
		if err != nil {
			panic("unable to setup licences scanner for testing")
		}
		licenseScanner = &scanner
	})

	return licenses.SetContextLicenseScanner(context.Background(), *licenseScanner)
}

func NewCatalogTester() *CatalogTester {
	return &CatalogTester{
		context:          Context(),
		locationComparer: cmptest.DefaultLocationComparer,
		licenseComparer:  cmptest.DefaultLicenseComparer,
		packageStringer:  stringPackage,
		resolver:         fileresolver.Empty{},
		ignoreUnfulfilledPathResponses: map[string][]string{
			"FilesByPath": {
				// most catalogers search for a linux release, which will not be fulfilled in testing
				"/etc/os-release",
				"/usr/lib/os-release",
				"/etc/system-release-cpe",
				"/etc/redhat-release",
				"/bin/busybox",
			},
		},
	}
}

func (p *CatalogTester) WithContext(ctx context.Context) *CatalogTester {
	p.context = ctx
	return p
}

func (p *CatalogTester) FromDirectory(t *testing.T, path string) *CatalogTester {
	t.Helper()

	if path == "" {
		return p
	}

	s, err := directorysource.NewFromPath(path)
	require.NoError(t, err)

	resolver, err := s.FileResolver(source.AllLayersScope)
	require.NoError(t, err)

	p.resolver = resolver
	return p
}

func (p *CatalogTester) FromFileSource(t *testing.T, path string) *CatalogTester {
	t.Helper()

	s, err := filesource.NewFromPath(path)
	require.NoError(t, err)
	resolver, err := s.FileResolver(source.AllLayersScope)
	require.NoError(t, err)

	p.resolver = resolver
	return p
}

func (p *CatalogTester) FromFile(t *testing.T, path string) *CatalogTester {
	t.Helper()

	if path == "" {
		return p
	}

	absPath, err := filepath.Abs(path)
	require.NoError(t, err)

	fixture, err := os.Open(path)
	require.NoError(t, err)

	p.reader = file.LocationReadCloser{
		Location:   file.NewVirtualLocationFromDirectory(fixture.Name(), fixture.Name(), *stereofile.NewFileReference(stereofile.Path(absPath))),
		ReadCloser: fixture,
	}
	return p
}

func (p *CatalogTester) FromString(location, data string) *CatalogTester {
	p.reader = file.LocationReadCloser{
		Location:   file.NewLocation(location),
		ReadCloser: io.NopCloser(strings.NewReader(data)),
	}
	return p
}

func (p *CatalogTester) WithLinuxRelease(r linux.Release) *CatalogTester {
	if p.env == nil {
		p.env = &generic.Environment{}
	}
	p.env.LinuxRelease = &r
	return p
}

func (p *CatalogTester) WithEnv(env *generic.Environment) *CatalogTester {
	p.env = env
	return p
}

func (p *CatalogTester) WithError() *CatalogTester {
	p.wantErr = require.Error
	return p
}

func (p *CatalogTester) WithErrorAssertion(a require.ErrorAssertionFunc) *CatalogTester {
	p.wantErr = a
	return p
}

func (p *CatalogTester) WithResolver(r file.Resolver) *CatalogTester {
	p.resolver = r
	return p
}

func (p *CatalogTester) WithImageResolver(t *testing.T, fixtureName string) *CatalogTester {
	t.Helper()

	if fixtureName == "" {
		return p
	}

	img := imagetest.GetFixtureImage(t, "docker-archive", fixtureName)

	s := stereoscopesource.New(img, stereoscopesource.ImageConfig{
		Reference: fixtureName,
	})

	r, err := s.FileResolver(source.SquashedScope)
	require.NoError(t, err)
	p.resolver = r
	return p
}

func (p *CatalogTester) ExpectsAssertion(a func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship)) *CatalogTester {
	p.customAssertions = append(p.customAssertions, a)
	return p
}

func (p *CatalogTester) IgnoreLocationLayer() *CatalogTester {
	p.locationComparer = cmptest.LocationComparerWithoutLayer
	p.licenseComparer = cmptest.LicenseComparerWithoutLocationLayer
	return p
}

func (p *CatalogTester) IgnorePackageFields(fields ...string) *CatalogTester {
	p.compareOptions = append(p.compareOptions, cmpopts.IgnoreFields(pkg.Package{}, fields...))
	return p
}

func (p *CatalogTester) WithCompareOptions(opts ...cmp.Option) *CatalogTester {
	p.compareOptions = append(p.compareOptions, opts...)
	return p
}

func (p *CatalogTester) Expects(pkgs []pkg.Package, relationships []artifact.Relationship) *CatalogTester {
	p.assertResultExpectations = true
	p.expectedPkgs = pkgs
	p.expectedRelationships = relationships
	return p
}

func (p *CatalogTester) WithPackageStringer(fn func(pkg.Package) string) *CatalogTester {
	p.packageStringer = fn
	return p
}

func (p *CatalogTester) ExpectsPackageStrings(expected []string) *CatalogTester {
	return p.ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
		diffPackages(t, expected, pkgs, p.packageStringer)
	})
}

func (p *CatalogTester) ExpectsRelationshipStrings(expected []string) *CatalogTester {
	return p.ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
		diffRelationships(t, expected, relationships, pkgs, p.packageStringer)
	})
}

func (p *CatalogTester) ExpectsResolverPathResponses(locations []string) *CatalogTester {
	p.expectedPathResponses = locations
	return p
}

func (p *CatalogTester) ExpectsResolverContentQueries(locations []string) *CatalogTester {
	p.expectedContentQueries = locations
	return p
}

func (p *CatalogTester) IgnoreUnfulfilledPathResponses(paths ...string) *CatalogTester {
	p.ignoreAnyUnfulfilledPaths = append(p.ignoreAnyUnfulfilledPaths, paths...)
	return p
}

func (p *CatalogTester) WithoutTestObserver() *CatalogTester {
	p.skipTestObservations = true
	return p
}

func (p *CatalogTester) TestParser(t *testing.T, parser generic.Parser) {
	t.Helper()
	pkgs, relationships, err := parser(p.context, p.resolver, p.env, p.reader)

	// only test for errors if explicitly requested
	if p.wantErr != nil {
		p.wantErr(t, err)
	}

	// track metadata types for cataloger discovery
	p.trackParserMetadata(t, parser, pkgs, relationships)

	p.assertPkgs(t, pkgs, relationships)
}

func (p *CatalogTester) TestCataloger(t *testing.T, cataloger pkg.Cataloger) {
	t.Helper()

	resolver := NewObservingResolver(p.resolver)

	pkgs, relationships, err := cataloger.Catalog(p.context, resolver)

	// this is a minimum set, the resolver may return more that just this list
	for _, path := range p.expectedPathResponses {
		assert.Truef(t, resolver.ObservedPathResponses(path), "expected path query for %q was not observed", path)
	}

	// this is a full set, any other queries are unexpected (and will fail the test)
	if len(p.expectedContentQueries) > 0 {
		assert.ElementsMatchf(t, p.expectedContentQueries, resolver.AllContentQueries(), "unexpected content queries observed: diff %s", cmp.Diff(p.expectedContentQueries, resolver.AllContentQueries()))
	}

	// only test for errors if explicitly requested
	if p.wantErr != nil {
		p.wantErr(t, err)
	}

	// track metadata types for cataloger discovery
	p.trackCatalogerMetadata(t, cataloger, pkgs, relationships)

	if p.assertResultExpectations {
		p.assertPkgs(t, pkgs, relationships)
	}

	for _, a := range p.customAssertions {
		a(t, pkgs, relationships)
	}

	if !p.assertResultExpectations && len(p.customAssertions) == 0 && p.wantErr == nil {
		resolver.PruneUnfulfilledPathResponses(p.ignoreUnfulfilledPathResponses, p.ignoreAnyUnfulfilledPaths...)

		// if we aren't testing the results, we should focus on what was searched for (for glob-centric tests)
		assert.Falsef(t, resolver.HasUnfulfilledPathRequests(), "unfulfilled path requests: \n%v", resolver.PrettyUnfulfilledPathRequests())
	}
}

func (p *CatalogTester) assertPkgs(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
	t.Helper()

	p.compareOptions = append(p.compareOptions, cmptest.BuildOptions(p.licenseComparer, p.locationComparer)...)

	{
		r := cmptest.NewDiffReporter()
		var opts []cmp.Option

		opts = append(opts, p.compareOptions...)
		opts = append(opts, cmp.Reporter(&r))

		// order should not matter
		pkg.Sort(p.expectedPkgs)
		pkg.Sort(pkgs)

		if diff := cmp.Diff(p.expectedPkgs, pkgs, opts...); diff != "" {
			t.Log("Specific Differences:\n" + r.String())
			t.Errorf("unexpected packages from parsing (-expected +actual)\n%s", diff)
		}
	}
	{
		r := cmptest.NewDiffReporter()
		var opts []cmp.Option

		opts = append(opts, p.compareOptions...)
		opts = append(opts, cmp.Reporter(&r))

		// ignore the "FoundBy" field on relationships as it is set in the generic cataloger before it's presence on the relationship
		opts = append(opts, cmpopts.IgnoreFields(pkg.Package{}, "FoundBy"))

		// order should not matter
		relationship.Sort(p.expectedRelationships)
		relationship.Sort(relationships)

		if diff := cmp.Diff(p.expectedRelationships, relationships, opts...); diff != "" {
			t.Log("Specific Differences:\n" + r.String())

			t.Errorf("unexpected relationships from parsing (-expected +actual)\n%s", diff)
		}
	}
}

func TestFileParser(t *testing.T, fixturePath string, parser generic.Parser, expectedPkgs []pkg.Package, expectedRelationships []artifact.Relationship) {
	t.Helper()
	NewCatalogTester().FromFile(t, fixturePath).Expects(expectedPkgs, expectedRelationships).TestParser(t, parser)
}

func TestCataloger(t *testing.T, fixtureDir string, cataloger pkg.Cataloger, expectedPkgs []pkg.Package, expectedRelationships []artifact.Relationship) {
	t.Helper()
	NewCatalogTester().FromDirectory(t, fixtureDir).Expects(expectedPkgs, expectedRelationships).TestCataloger(t, cataloger)
}

func TestCatalogerFromFileSource(t *testing.T, fixturePath string, cataloger pkg.Cataloger, expectedPkgs []pkg.Package, expectedRelationships []artifact.Relationship) {
	t.Helper()
	NewCatalogTester().FromFileSource(t, fixturePath).Expects(expectedPkgs, expectedRelationships).TestCataloger(t, cataloger)
}

func TestFileParserWithEnv(t *testing.T, fixturePath string, parser generic.Parser, env *generic.Environment, expectedPkgs []pkg.Package, expectedRelationships []artifact.Relationship) {
	t.Helper()

	NewCatalogTester().FromFile(t, fixturePath).WithEnv(env).Expects(expectedPkgs, expectedRelationships).TestParser(t, parser)
}

func AssertPackagesEqual(t *testing.T, a, b pkg.Package, userOpts ...cmp.Option) {
	t.Helper()
	opts := cmptest.DefaultOptions()
	opts = append(opts, userOpts...)

	if diff := cmp.Diff(a, b, opts...); diff != "" {
		t.Errorf("unexpected packages from parsing (-expected +actual)\n%s", diff)
	}
}

func AssertPackagesEqualIgnoreLayers(t *testing.T, a, b pkg.Package, userOpts ...cmp.Option) {
	t.Helper()
	opts := cmptest.DefaultIgnoreLocationLayerOptions()
	opts = append(opts, userOpts...)

	if diff := cmp.Diff(a, b, opts...); diff != "" {
		t.Errorf("unexpected packages from parsing (-expected +actual)\n%s", diff)
	}
}

func diffPackages(t *testing.T, expected []string, actual []pkg.Package, pkgStringer func(pkg.Package) string) {
	t.Helper()
	sort.Strings(expected)
	if d := cmp.Diff(expected, stringPackages(actual, pkgStringer)); d != "" {
		t.Errorf("unexpected package strings (-want, +got): %s", d)
	}
}

func diffRelationships(t *testing.T, expected []string, actual []artifact.Relationship, pkgs []pkg.Package, pkgStringer func(pkg.Package) string) {
	t.Helper()
	pkgsByID := make(map[artifact.ID]pkg.Package)
	for _, p := range pkgs {
		pkgsByID[p.ID()] = p
	}
	sort.Strings(expected)
	if d := cmp.Diff(expected, stringRelationships(actual, pkgsByID, pkgStringer)); d != "" {
		t.Errorf("unexpected relationship strings (-want, +got): %s", d)
	}
}

func stringRelationships(relationships []artifact.Relationship, nameLookup map[artifact.ID]pkg.Package, pkgStringer func(pkg.Package) string) []string {
	var result []string
	for _, r := range relationships {
		var fromName, toName string
		{
			fromPkg, ok := nameLookup[r.From.ID()]
			if !ok {
				fromName = string(r.From.ID())
			} else {
				fromName = pkgStringer(fromPkg)
			}
		}

		{
			toPkg, ok := nameLookup[r.To.ID()]
			if !ok {
				toName = string(r.To.ID())
			} else {
				toName = pkgStringer(toPkg)
			}
		}

		result = append(result, fromName+" ["+string(r.Type)+"] "+toName)
	}
	sort.Strings(result)
	return result
}

func stringPackages(pkgs []pkg.Package, pkgStringer func(pkg.Package) string) []string {
	var result []string
	for _, p := range pkgs {
		result = append(result, pkgStringer(p))
	}
	sort.Strings(result)
	return result
}

func stringPackage(p pkg.Package) string {
	locs := p.Locations.ToSlice()
	var loc string
	if len(locs) > 0 {
		loc = p.Locations.ToSlice()[0].RealPath
	}

	return fmt.Sprintf("%s @ %s (%s)", p.Name, p.Version, loc)
}

// getFunctionName extracts the function name from a function pointer using reflection
func getFunctionName(fn interface{}) string {
	// get the function pointer
	ptr := reflect.ValueOf(fn).Pointer()

	// get the function details
	funcForPC := runtime.FuncForPC(ptr)
	if funcForPC == nil {
		return ""
	}

	fullName := funcForPC.Name()

	// extract just the function name from the full path
	// e.g., "github.com/anchore/syft/syft/pkg/cataloger/python.parseRequirementsTxt"
	//   -> "parseRequirementsTxt"
	parts := strings.Split(fullName, ".")
	if len(parts) > 0 {
		name := parts[len(parts)-1]
		// strip the -fm suffix that Go's reflection adds for methods
		// e.g., "parsePackageLock-fm" -> "parsePackageLock"
		return strings.TrimSuffix(name, "-fm")
	}

	return fullName
}

// getCatalogerName extracts the cataloger name from the test context or cataloger name
func getCatalogerName(_ *testing.T, cataloger pkg.Cataloger) string {
	// use the cataloger's name method if available
	return cataloger.Name()
}

// getPackagePath extracts the package path from a function name
// e.g., "github.com/anchore/syft/syft/pkg/cataloger/python.parseRequirementsTxt" -> "python"
func getPackagePath(fn interface{}) string {
	ptr := reflect.ValueOf(fn).Pointer()
	funcForPC := runtime.FuncForPC(ptr)
	if funcForPC == nil {
		return ""
	}

	fullName := funcForPC.Name()

	// extract package name from path
	// e.g., "github.com/anchore/syft/syft/pkg/cataloger/python.parseRequirementsTxt"
	//   -> "python"
	if strings.Contains(fullName, "/cataloger/") {
		parts := strings.Split(fullName, "/cataloger/")
		if len(parts) > 1 {
			// get the next segment after "/cataloger/"
			remaining := parts[1]
			// split by "." to get package name
			pkgParts := strings.Split(remaining, ".")
			if len(pkgParts) > 0 {
				return pkgParts[0]
			}
		}
	}

	return ""
}

// getPackagePathFromCataloger extracts the package path from the caller's file path
// For generic catalogers, the cataloger type is from the generic package, but we need
// the package where the test is defined (e.g., rust, python, etc.)
func getPackagePathFromCataloger(_ pkg.Cataloger) string {
	// walk up the call stack to find the test file
	// we're looking for a file in the cataloger directory structure
	for i := 0; i < 10; i++ {
		_, file, _, ok := runtime.Caller(i)
		if !ok {
			break
		}

		// extract package name from file path
		// e.g., "/Users/.../syft/pkg/cataloger/rust/cataloger_test.go" -> "rust"
		if strings.Contains(file, "/cataloger/") {
			parts := strings.Split(file, "/cataloger/")
			if len(parts) > 1 {
				// get the next segment after "/cataloger/"
				remaining := parts[1]
				// split by "/" to get package name
				pkgParts := strings.Split(remaining, "/")
				if len(pkgParts) > 0 && pkgParts[0] != "internal" {
					return pkgParts[0]
				}
			}
		}
	}

	return ""
}

// trackParserMetadata records metadata types for a parser function
func (p *CatalogTester) trackParserMetadata(t *testing.T, parser generic.Parser, pkgs []pkg.Package, relationships []artifact.Relationship) {
	if p.skipTestObservations {
		return
	}

	parserName := getFunctionName(parser)
	if parserName == "" {
		return
	}

	// try to infer package name from function path
	packageName := getPackagePath(parser)
	if packageName == "" {
		return
	}

	tracker := getTracker()

	// old tracking (still used by metadata discovery)
	for _, pkg := range pkgs {
		tracker.RecordParserPackageMetadata(packageName, parserName, pkg)
	}

	// new unified observations with capability tracking
	tracker.RecordParserObservations(packageName, parserName, pkgs, relationships)

	// ensure results are written when tests complete
	t.Cleanup(func() {
		_ = WriteResultsIfEnabled()
	})
}

// trackCatalogerMetadata records metadata types for a cataloger
func (p *CatalogTester) trackCatalogerMetadata(t *testing.T, cataloger pkg.Cataloger, pkgs []pkg.Package, relationships []artifact.Relationship) {
	if p.skipTestObservations {
		return
	}

	catalogerName := getCatalogerName(t, cataloger)
	if catalogerName == "" {
		return
	}

	// try to infer package name from cataloger type
	packageName := getPackagePathFromCataloger(cataloger)
	if packageName == "" {
		return
	}

	tracker := getTracker()

	// old tracking (still used by metadata discovery)
	for _, pkg := range pkgs {
		tracker.RecordCatalogerPackageMetadata(catalogerName, pkg)
	}

	// new unified observations with capability tracking
	tracker.RecordCatalogerObservations(packageName, catalogerName, pkgs, relationships)

	// ensure results are written when tests complete
	t.Cleanup(func() {
		_ = WriteResultsIfEnabled()
	})
}
