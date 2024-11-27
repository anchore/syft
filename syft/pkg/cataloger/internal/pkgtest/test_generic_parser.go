package pkgtest

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/internal/cmptest"
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/anchore/syft/syft/source/stereoscopesource"
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
}

func NewCatalogTester() *CatalogTester {
	return &CatalogTester{
		locationComparer: cmptest.DefaultLocationComparer,
		licenseComparer:  cmptest.DefaultLicenseComparer,
		packageStringer:  stringPackage,
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

func (p *CatalogTester) FromDirectory(t *testing.T, path string) *CatalogTester {
	t.Helper()

	s, err := directorysource.NewFromPath(path)
	require.NoError(t, err)

	resolver, err := s.FileResolver(source.AllLayersScope)
	require.NoError(t, err)

	p.resolver = resolver
	return p
}

func (p *CatalogTester) FromFile(t *testing.T, path string) *CatalogTester {
	t.Helper()

	fixture, err := os.Open(path)
	require.NoError(t, err)

	p.reader = file.LocationReadCloser{
		Location:   file.NewLocation(fixture.Name()),
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
	p.locationComparer = func(x, y file.Location) bool {
		return cmp.Equal(x.Coordinates.RealPath, y.Coordinates.RealPath) && cmp.Equal(x.AccessPath, y.AccessPath)
	}

	// we need to update the license comparer to use the ignored location layer
	p.licenseComparer = func(x, y pkg.License) bool {
		return cmp.Equal(x, y, cmp.Comparer(p.locationComparer), cmp.Comparer(
			func(x, y file.LocationSet) bool {
				xs := x.ToSlice()
				ys := y.ToSlice()
				if len(xs) != len(ys) {
					return false
				}
				for i, xe := range xs {
					ye := ys[i]
					if !p.locationComparer(xe, ye) {
						return false
					}
				}

				return true
			}))
	}
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

func (p *CatalogTester) TestParser(t *testing.T, parser generic.Parser) {
	t.Helper()
	pkgs, relationships, err := parser(context.Background(), p.resolver, p.env, p.reader)
	// only test for errors if explicitly requested
	if p.wantErr != nil {
		p.wantErr(t, err)
	}
	p.assertPkgs(t, pkgs, relationships)
}

func (p *CatalogTester) TestCataloger(t *testing.T, cataloger pkg.Cataloger) {
	t.Helper()

	resolver := NewObservingResolver(p.resolver)

	pkgs, relationships, err := cataloger.Catalog(context.Background(), resolver)

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

	p.compareOptions = append(p.compareOptions, cmptest.CommonOptions(p.licenseComparer, p.locationComparer)...)

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

func TestFileParserWithEnv(t *testing.T, fixturePath string, parser generic.Parser, env *generic.Environment, expectedPkgs []pkg.Package, expectedRelationships []artifact.Relationship) {
	t.Helper()

	NewCatalogTester().FromFile(t, fixturePath).WithEnv(env).Expects(expectedPkgs, expectedRelationships).TestParser(t, parser)
}

func AssertPackagesEqual(t *testing.T, a, b pkg.Package) {
	t.Helper()
	opts := []cmp.Option{
		cmpopts.IgnoreFields(pkg.Package{}, "id"), // note: ID is not deterministic for test purposes
		cmp.Comparer(
			func(x, y file.LocationSet) bool {
				xs := x.ToSlice()
				ys := y.ToSlice()

				if len(xs) != len(ys) {
					return false
				}
				for i, xe := range xs {
					ye := ys[i]
					if !cmptest.DefaultLocationComparer(xe, ye) {
						return false
					}
				}

				return true
			},
		),
		cmp.Comparer(
			func(x, y pkg.LicenseSet) bool {
				xs := x.ToSlice()
				ys := y.ToSlice()

				if len(xs) != len(ys) {
					return false
				}
				for i, xe := range xs {
					ye := ys[i]
					if !cmptest.DefaultLicenseComparer(xe, ye) {
						return false
					}
				}

				return true
			},
		),
		cmp.Comparer(
			cmptest.DefaultLocationComparer,
		),
		cmp.Comparer(
			cmptest.DefaultLicenseComparer,
		),
	}

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
