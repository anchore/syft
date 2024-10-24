package terraform

import (
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestTerraformCataloger(t *testing.T) {
	c := NewTerraformCataloger()

	fileLoc := file.NewLocation(".terraform.lock.hcl")
	location := fileLoc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)

	awsProviderPkg := pkg.Package{
		Name:      "registry.terraform.io/hashicorp/aws",
		Version:   "5.72.1",
		FoundBy:   "terraform-cataloger",
		Locations: file.NewLocationSet(location),
		Type:      pkg.TerraformPkg,
		PURL:      "pkg:terraform/registry.terraform.io/hashicorp/aws@5.72.1",
		Metadata: []pkg.KeyValue{
			{
				Key:   "constraints",
				Value: "5.72.1",
			},
		},
	}
	awsProviderPkg.SetID()

	gcpProviderPkg := pkg.Package{
		Name:      "registry.terraform.io/hashicorp/google",
		Version:   "6.8.0",
		FoundBy:   "terraform-cataloger",
		Locations: file.NewLocationSet(location),
		Type:      pkg.TerraformPkg,
		PURL:      "pkg:terraform/registry.terraform.io/hashicorp/google@6.8.0",
		Metadata: []pkg.KeyValue{
			{
				Key:   "constraints",
				Value: "6.8.0",
			},
		},
	}
	gcpProviderPkg.SetID()

	tests := []struct {
		name     string
		expected []pkg.Package
	}{
		{
			name: "two-providers",
			expected: []pkg.Package{
				awsProviderPkg,
				gcpProviderPkg,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				WithResolver(fileresolver.NewFromUnindexedDirectory(filepath.Join("test-fixtures", tt.name))).
				Expects(tt.expected, nil).
				TestCataloger(t, c)
		})
	}
}
