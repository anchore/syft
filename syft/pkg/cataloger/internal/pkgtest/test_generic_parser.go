package pkgtest

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

type locationComparer func(x, y source.Location) bool

type CatalogTester struct {
	expectedPkgs          []pkg.Package
	expectedRelationships []artifact.Relationship
	env                   *generic.Environment
	reader                source.LocationReadCloser
	resolver              source.FileResolver
	wantErr               require.ErrorAssertionFunc
	compareOptions        []cmp.Option
	locationComparer      locationComparer
}

func NewCatalogTester() *CatalogTester {
	return &CatalogTester{
		wantErr:          require.NoError,
		locationComparer: DefaultLocationComparer,
	}
}

func DefaultLocationComparer(x, y source.Location) bool {
	return cmp.Equal(x.Coordinates, y.Coordinates) && cmp.Equal(x.VirtualPath, y.VirtualPath)
}

func (p *CatalogTester) FromDirectory(t *testing.T, path string) *CatalogTester {
	t.Helper()

	s, err := source.NewFromDirectory(path)
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

	p.reader = source.LocationReadCloser{
		Location:   source.NewLocation(fixture.Name()),
		ReadCloser: fixture,
	}
	return p
}

func (p *CatalogTester) FromString(location, data string) *CatalogTester {
	p.reader = source.LocationReadCloser{
		Location:   source.NewLocation(location),
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

func (p *CatalogTester) WithResolver(r source.FileResolver) *CatalogTester {
	p.resolver = r
	return p
}

func (p *CatalogTester) WithImageResolver(t *testing.T, fixtureName string) *CatalogTester {
	t.Helper()
	img := imagetest.GetFixtureImage(t, "docker-archive", fixtureName)

	s, err := source.NewFromImage(img, fixtureName)
	require.NoError(t, err)

	r, err := s.FileResolver(source.SquashedScope)
	require.NoError(t, err)
	p.resolver = r
	return p
}

func (p *CatalogTester) IgnoreLocationLayer() *CatalogTester {
	p.locationComparer = func(x, y source.Location) bool {
		return cmp.Equal(x.Coordinates.RealPath, y.Coordinates.RealPath) && cmp.Equal(x.VirtualPath, y.VirtualPath)
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
	p.expectedPkgs = pkgs
	p.expectedRelationships = relationships
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
	pkgs, relationships, err := cataloger.Catalog(p.resolver)
	p.wantErr(t, err)
	p.assertPkgs(t, pkgs, relationships)
}

func (p *CatalogTester) assertPkgs(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
	t.Helper()

	p.compareOptions = append(p.compareOptions,
		cmpopts.IgnoreFields(pkg.Package{}, "id"), // note: ID is not deterministic for test purposes
		cmpopts.SortSlices(pkg.Less),
		cmp.Comparer(
			func(x, y source.LocationSet) bool {
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
	)

	if diff := cmp.Diff(p.expectedPkgs, pkgs, p.compareOptions...); diff != "" {
		t.Errorf("unexpected packages from parsing (-expected +actual)\n%s", diff)
	}

	if diff := cmp.Diff(p.expectedRelationships, relationships, p.compareOptions...); diff != "" {
		t.Errorf("unexpected relationships from parsing (-expected +actual)\n%s", diff)
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
			func(x, y source.LocationSet) bool {
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
	}

	if diff := cmp.Diff(a, b, opts...); diff != "" {
		t.Errorf("unexpected packages from parsing (-expected +actual)\n%s", diff)
	}
}
