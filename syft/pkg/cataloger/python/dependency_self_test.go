package python

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
)

func Test_wheelEggRelationships_selfReferentialExtra(t *testing.T) {
	newPkg := func(name string, requires ...string) pkg.Package {
		p := pkg.Package{
			Name: name,
			Type: pkg.PythonPkg,
			Locations: file.NewLocationSet(file.NewLocation("/site-packages/"+name+".dist-info/METADATA").
				WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			Metadata: pkg.PythonPackage{Name: name, RequiresDist: requires},
		}
		p.SetID()
		return p
	}
	self := newPkg("build", `build[uv, virtualenv]; extra == "test"`, "packaging>=19.1")
	provider := newPkg("packaging")
	packages := []pkg.Package{self, provider}

	gotPkgs, rels, err := wheelEggRelationships(context.Background(), fileresolver.Empty{}, packages, nil, nil)
	require.NoError(t, err)
	require.ElementsMatch(t, packages, gotPkgs)
	require.Len(t, rels, 1)
	require.Equal(t, provider.ID(), rels[0].From.ID())
	require.Equal(t, self.ID(), rels[0].To.ID())
}
