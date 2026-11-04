package embeddedsbom

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestRelationships(t *testing.T) {
	p := pkg.Package{Name: "postgresql"}
	flat := file.NewLocation("/opt/app.jar")
	nested := file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/app.jar", FullPath: "/app.jar!/lib/a.jar"})
	root := file.NewLocation("")

	keep := []artifact.Relationship{
		{From: p, To: p, Type: artifact.DependencyOfRelationship},
		{From: p, To: flat, Type: artifact.ContainsRelationship},
		{From: p, To: flat.Coordinates, Type: artifact.ContainsRelationship},
	}
	drop := []artifact.Relationship{
		{From: p, To: nested, Type: artifact.ContainsRelationship},
		{From: p, To: nested.Coordinates, Type: artifact.ContainsRelationship},
		{From: p, To: root, Type: artifact.ContainsRelationship},
		{From: p, To: file.NewLocation("/"), Type: artifact.ContainsRelationship},
		{From: root, To: flat, Type: artifact.ContainsRelationship},
	}

	assert.Equal(t, keep, Relationships(append(append([]artifact.Relationship{}, keep...), drop...)))
}
