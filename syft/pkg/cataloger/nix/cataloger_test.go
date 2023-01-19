package nix

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestCataloger_Catalog(t *testing.T) {

	tests := []struct {
		fixture  string
		wantPkgs []pkg.Package
		wantRel  []artifact.Relationship
	}{
		{
			fixture: "test-fixtures/fixture-1",
			wantPkgs: []pkg.Package{
				{
					Name:         "glibc",
					Version:      "2.34-210",
					PURL:         "pkg:nix/glibc@2.34-210?output=bin&hash=h0cnbmfcn93xm5dg2x27ixhag1cwndga",
					Locations:    source.NewLocationSet(source.NewLocation("nix/store/h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin")),
					FoundBy:      catalogerName,
					Type:         pkg.NixStorePkg,
					MetadataType: pkg.NixStoreMetadataType,
					Metadata: pkg.NixStoreMetadata{
						Hash:   "h0cnbmfcn93xm5dg2x27ixhag1cwndga",
						Output: "bin",
						Files: []string{
							"nix/store/h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin/lib",
							"nix/store/h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin/lib/glibc.so",
							"nix/store/h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin/share",
							"nix/store/h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin/share/man",
							"nix/store/h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin/share/man/glibc.1",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			c := NewStoreCataloger()

			pkgtest.NewCatalogTester().
				WithDirectoryResolver(t, tt.fixture).
				Expects(tt.wantPkgs, tt.wantRel).
				TestCataloger(t, c)
		})
	}
}
