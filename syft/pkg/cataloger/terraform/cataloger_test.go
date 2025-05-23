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
	c := NewLockCataloger()

	fileLoc := file.NewLocation(".terraform.lock.hcl")
	location := fileLoc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)

	awsProviderPkg := pkg.Package{
		Name:      "registry.terraform.io/hashicorp/aws",
		Version:   "5.72.1",
		FoundBy:   "terraform-lock-cataloger",
		Locations: file.NewLocationSet(location),
		Type:      pkg.TerraformPkg,
		Language:  pkg.Go,
		Metadata: pkg.TerraformLockProviderEntry{
			URL:         "registry.terraform.io/hashicorp/aws",
			Version:     "5.72.1",
			Constraints: "> 5.72.0",
			Hashes: []string{
				"h1:jhd5O5o0CfZCNEwwN0EiDAzb7ApuFrtxJqa6HXW4EKE=",
				"zh:0dea6843836e926d33469b48b948744079023816d16a2ff7666bcfb6aa3522d4",
				"zh:195fa9513f75800a0d62797ebec75ee73e9b8c28d713fe9b63d3b1d1eec129b3",
				"zh:1ed92f3961715bf0e024bcde3c12dfbdc50b00c1f8a43cc00802cfc45a256208",
				"zh:2ac687e3a52606466cae4a6813e81d923042488df88d2424e28d3f8530f091bb",
				"zh:32e7ca75f9314557daada3c44628fe1f3bf964a4f833bfb4b2295d833fe64b6f",
				"zh:374ee0e6b4327cc6ef666908ce5d6450a3a56e90cd2b785e83c2bcfc100021d2",
				"zh:5500fd6fdac44f96411fcf9c6d01691159ec35455ed127eb4c3a498e1cc92a64",
				"zh:723a2dc4b064c12e7ee62ad4fbfd72fa5e025206ea47b735994ef53f3c373152",
				"zh:89d97b87605f1d734f27e642567cbecf785b521af8ea81dac55c77ccde876221",
				"zh:951ee1e5731e8d65d521d71b95927e55055b3c4656eef6d46fa580a63328befc",
				"zh:9b12af85486a96aedd8d7984b0ff811a4b42e3d88dad1a3fb4c0b580d04fa425",
				"zh:9b2b362470b64ec227b2da64762ab8bc4111c6b80365fd9d82fc5e1e33f44038",
				"zh:aa6e57d0cb974ff0da5dee5d43ad2745cbbc4a2b507d4c799839b9fa96daf688",
				"zh:ba0d14c4a6b7aa844a830d47c0bf995b632e37f0795394b5b60c638b62b7fc03",
				"zh:c9764065a9c5d324db0b02bd201b9e3a2118e49c4960884acdeea377173302e9",
			},
		},
	}
	awsProviderPkg.SetID()

	gcpProviderPkg := pkg.Package{
		Name:      "registry.terraform.io/hashicorp/google",
		Version:   "6.8.0",
		FoundBy:   "terraform-lock-cataloger",
		Locations: file.NewLocationSet(location),
		Type:      pkg.TerraformPkg,
		Language:  pkg.Go,
		Metadata: pkg.TerraformLockProviderEntry{
			URL:         "registry.terraform.io/hashicorp/google",
			Version:     "6.8.0",
			Constraints: "",
			Hashes: []string{
				"h1:GlCaVPk6eKMg2ZbRY7C5tUeHGNIABT+qFtMl8+XWZHM=",
				"zh:1b78f4451f1617092eb6891c9c13eda79671060601c40947feea6794c732157a",
				"zh:4c6d7231ce32c6ff2a98218ef363c133d27d423b009354e7fe18459d9feb41d4",
				"zh:6ae0112e9c733ab6c72436a334ffe3f197a613bb04f49538462b83b236d37a2d",
				"zh:8bd5651838ad674e0a173a453b76c80b94d08ebcb8ea0b6263ce6da0599b42f5",
				"zh:94ee7bcd77b0b7c2777113e35282da014e61e813fe46c058a49bf3d616fecdf4",
				"zh:c0bf014422c2971985d34ad45ddb6aa737373398f83b325884ea5608ac1264aa",
				"zh:c2cbbf0c249c3d1842ad0ad77fb7ef85bd3e92c688618c4087173bc1d69cd098",
				"zh:cefa3e06cb353d08b83dafa6135cd78e17540ae735b7c5687833cc1925c3fd8e",
				"zh:d20bc0216bf7f054f6318467d3902ced05e9f0bfa500ee55bf43b1b41ef0b854",
				"zh:e54ad5959e53b9e9acafc243d6f4039ab5005cec32c7435a122da964888d184c",
				"zh:e833c8de147268b3ffc14c60915eccb9347ade5f25b37b3771240a4d68b6aac4",
				"zh:f569b65999264a9416862bca5cd2a6177d94ccb0424f3a4ef424428912b9cb3c",
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
