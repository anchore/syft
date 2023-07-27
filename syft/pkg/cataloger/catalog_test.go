package cataloger

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

func Test_CatalogPanicHandling(t *testing.T) {
	catalog, relationships, err := Catalog(
		file.NewMockResolverForPaths(),
		&linux.Release{},
		1,
		panickingCataloger{},
		returningCataloger{},
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "catalog_test.go")
	require.Len(t, catalog.Sorted(), 2)
	require.Len(t, relationships, 1)
}

type panickingCataloger struct{}

func (p panickingCataloger) Name() string {
	return "panicking-cataloger"
}

func (p panickingCataloger) Catalog(_ file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	panic("something bad happened")
}

var _ pkg.Cataloger = (*panickingCataloger)(nil)

type returningCataloger struct{}

func (p returningCataloger) Name() string {
	return "returning-cataloger"
}

func (p returningCataloger) Catalog(_ file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	pkg1 := pkg.Package{
		Name:    "package-1",
		Version: "1.0",
	}
	pkg1.SetID()
	pkg2 := pkg.Package{
		Name:    "package-2",
		Version: "2.0",
	}
	pkg2.SetID()
	return []pkg.Package{pkg1, pkg2}, []artifact.Relationship{
		{
			From: pkg1,
			To:   pkg2,
			Type: artifact.DependencyOfRelationship,
		},
	}, nil
}

var _ pkg.Cataloger = (*returningCataloger)(nil)
