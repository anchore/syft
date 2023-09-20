package pkgtest

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sanity-io/litter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

type locationComparer func(x, y file.Location) bool
type licenseComparer func(x, y pkg.License) bool

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
	locationComparer               locationComparer
	licenseComparer                licenseComparer
}

func NewCatalogTester() *CatalogTester {
	return &CatalogTester{
		wantErr:          require.NoError,
		locationComparer: DefaultLocationComparer,
		licenseComparer:  DefaultLicenseComparer,
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

func DefaultLocationComparer(x, y file.Location) bool {
	return cmp.Equal(x.Coordinates, y.Coordinates) && cmp.Equal(x.VirtualPath, y.VirtualPath)
}

func DefaultLicenseComparer(x, y pkg.License) bool {
	return cmp.Equal(x, y, cmp.Comparer(DefaultLocationComparer), cmp.Comparer(
		func(x, y file.LocationSet) bool {
			xs := x.ToSlice()
			ys := y.ToSlice()
			if len(xs) != len(ys) {
				return false
			}
			for i, xe := range xs {
				ye := ys[i]
				if !DefaultLocationComparer(xe, ye) {
					return false
				}
			}
			return true
		},
	))
}

func (p *CatalogTester) FromDirectory(t *testing.T, path string) *CatalogTester {
	t.Helper()

	s, err := source.NewFromDirectoryPath(path)
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
	p.assertResultExpectations = true
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

	s, err := source.NewFromStereoscopeImageObject(img, fixtureName, nil)
	require.NoError(t, err)

	r, err := s.FileResolver(source.SquashedScope)
	require.NoError(t, err)
	p.resolver = r
	return p
}

func (p *CatalogTester) IgnoreLocationLayer() *CatalogTester {
	p.locationComparer = func(x, y file.Location) bool {
		return cmp.Equal(x.Coordinates.RealPath, y.Coordinates.RealPath) && cmp.Equal(x.VirtualPath, y.VirtualPath)
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
	pkgs, relationships, err := parser(p.resolver, p.env, p.reader)
	p.wantErr(t, err)
	p.assertPkgs(t, pkgs, relationships)
}

func (p *CatalogTester) TestCataloger(t *testing.T, cataloger pkg.Cataloger) {
	t.Helper()

	resolver := NewObservingResolver(p.resolver)

	pkgs, relationships, err := cataloger.Catalog(resolver)

	// this is a minimum set, the resolver may return more that just this list
	for _, path := range p.expectedPathResponses {
		assert.Truef(t, resolver.ObservedPathResponses(path), "expected path query for %q was not observed", path)
	}

	// this is a full set, any other queries are unexpected (and will fail the test)
	if len(p.expectedContentQueries) > 0 {
		assert.ElementsMatchf(t, p.expectedContentQueries, resolver.AllContentQueries(), "unexpected content queries observed: diff %s", cmp.Diff(p.expectedContentQueries, resolver.AllContentQueries()))
	}

	if p.assertResultExpectations {
		p.wantErr(t, err)
		p.assertPkgs(t, pkgs, relationships)
	} else {
		resolver.PruneUnfulfilledPathResponses(p.ignoreUnfulfilledPathResponses, p.ignoreAnyUnfulfilledPaths...)

		// if we aren't testing the results, we should focus on what was searched for (for glob-centric tests)
		assert.Falsef(t, resolver.HasUnfulfilledPathRequests(), "unfulfilled path requests: \n%v", resolver.PrettyUnfulfilledPathRequests())
	}
}

var relationshipStringer = litter.Options{
	Compact:           true,
	StripPackageNames: false,
	HidePrivateFields: true, // we want to ignore package IDs
	HideZeroValues:    true,
	StrictGo:          true,
	//FieldExclusions: ...  // these can be added for future values that need to be ignored
	//FieldFilter: ...
}

func relationshipLess(x, y artifact.Relationship) bool {
	// we just need a stable sort, the ordering does not need to be sensible
	xStr := relationshipStringer.Sdump(x)
	yStr := relationshipStringer.Sdump(y)
	return xStr < yStr
}

// nolint:funlen
func (p *CatalogTester) assertPkgs(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
	t.Helper()

	p.compareOptions = append(p.compareOptions,
		cmpopts.IgnoreFields(pkg.Package{}, "id"), // note: ID is not deterministic for test purposes
		cmpopts.SortSlices(pkg.Less),
		cmpopts.SortSlices(relationshipLess),
		cmp.Comparer(
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
					if !p.licenseComparer(xe, ye) {
						return false
					}
				}

				return true
			},
		),
		cmp.Comparer(
			p.locationComparer,
		),
		cmp.Comparer(
			p.licenseComparer,
		),
	)

	{
		var r diffReporter
		var opts []cmp.Option

		opts = append(opts, p.compareOptions...)
		opts = append(opts, cmp.Reporter(&r))

		if diff := cmp.Diff(p.expectedPkgs, pkgs, opts...); diff != "" {
			t.Log("Specific Differences:\n" + r.String())
			t.Errorf("unexpected packages from parsing (-expected +actual)\n%s", diff)
		}
	}
	{
		var r diffReporter
		var opts []cmp.Option

		opts = append(opts, p.compareOptions...)
		opts = append(opts, cmp.Reporter(&r))

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
					if !DefaultLocationComparer(xe, ye) {
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
					if !DefaultLicenseComparer(xe, ye) {
						return false
					}
				}

				return true
			},
		),
		cmp.Comparer(
			DefaultLocationComparer,
		),
		cmp.Comparer(
			DefaultLicenseComparer,
		),
	}

	if diff := cmp.Diff(a, b, opts...); diff != "" {
		t.Errorf("unexpected packages from parsing (-expected +actual)\n%s", diff)
	}
}

// diffReporter is a simple custom reporter that only records differences detected during comparison.
type diffReporter struct {
	path  cmp.Path
	diffs []string
}

func (r *diffReporter) PushStep(ps cmp.PathStep) {
	r.path = append(r.path, ps)
}

func (r *diffReporter) Report(rs cmp.Result) {
	if !rs.Equal() {
		vx, vy := r.path.Last().Values()
		r.diffs = append(r.diffs, fmt.Sprintf("%#v:\n\t-: %+v\n\t+: %+v\n", r.path, vx, vy))
	}
}

func (r *diffReporter) PopStep() {
	r.path = r.path[:len(r.path)-1]
}

func (r *diffReporter) String() string {
	return strings.Join(r.diffs, "\n")
}
