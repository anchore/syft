package nix

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestStoreCataloger_Image(t *testing.T) {
	tests := []struct {
		fixture  string
		wantPkgs []string
		wantRel  []string
	}{
		{
			// $ nix-store -q --tree $(which jq)
			//
			// /nix/store/nzwfgsp28vgxv7n2gl5fxqkca9awh4dz-jq-1.6-bin3.4
			// ├───/nix/store/02mqs1by2vab9yzw0qc4j7463w78p3ps-glibc-2.37-8
			// │   ├───/nix/store/cw8fpl8r1x9rmaqj55fwbfnnrgw7b40k-libidn2-2.3.4
			// │   │   ├───/nix/store/h1ysk4vvw48winwmh38rvnsj0dlsz7c1-libunistring-1.1
			// │   │   │   └───/nix/store/h1ysk4vvw48winwmh38rvnsj0dlsz7c1-libunistring-1.1 [...]
			// │   │   └───/nix/store/cw8fpl8r1x9rmaqj55fwbfnnrgw7b40k-libidn2-2.3.4 [...]
			// │   ├───/nix/store/fmz62d844wf4blb11k21f4m0q6n6hdfp-xgcc-12.3.0-libgcc
			// │   └───/nix/store/02mqs1by2vab9yzw0qc4j7463w78p3ps-glibc-2.37-8 [...]
			// ├───/nix/store/mzj90j6m3c3a1vv8j9pl920f98i2yz9q-oniguruma-6.9.8-lib
			// │   ├───/nix/store/02mqs1by2vab9yzw0qc4j7463w78p3ps-glibc-2.37-8 [...]
			// │   └───/nix/store/mzj90j6m3c3a1vv8j9pl920f98i2yz9q-oniguruma-6.9.8-lib [...]
			// └───/nix/store/1x3s2v9wc9m302cspfqcn2iwar0b5w99-jq-1.6-lib
			//     ├───/nix/store/02mqs1by2vab9yzw0qc4j7463w78p3ps-glibc-2.37-8 [...]
			//     ├───/nix/store/mzj90j6m3c3a1vv8j9pl920f98i2yz9q-oniguruma-6.9.8-lib [...]
			//     └───/nix/store/1x3s2v9wc9m302cspfqcn2iwar0b5w99-jq-1.6-lib [...]
			fixture: "image-nixos-jq-pkg-store",
			wantPkgs: []string{
				"glibc @ 2.37-8 (/nix/store/02mqs1by2vab9yzw0qc4j7463w78p3ps-glibc-2.37-8)",
				"jq @ 1.6 (/nix/store/1x3s2v9wc9m302cspfqcn2iwar0b5w99-jq-1.6-lib)",
				"jq @ 1.6 (/nix/store/nzwfgsp28vgxv7n2gl5fxqkca9awh4dz-jq-1.6-bin)",
				"libidn2 @ 2.3.4 (/nix/store/cw8fpl8r1x9rmaqj55fwbfnnrgw7b40k-libidn2-2.3.4)",
				"libunistring @ 1.1 (/nix/store/h1ysk4vvw48winwmh38rvnsj0dlsz7c1-libunistring-1.1)",
				"oniguruma @ 6.9.8 (/nix/store/mzj90j6m3c3a1vv8j9pl920f98i2yz9q-oniguruma-6.9.8-lib)",
				"xgcc @ 12.3.0 (/nix/store/fmz62d844wf4blb11k21f4m0q6n6hdfp-xgcc-12.3.0-libgcc)",
			},
			wantRel: []string{
				// note: parsing all relationships from only derivations results in partial results! (this is why the DB cataloger exists)
				"libidn2 @ 2.3.4 (/nix/store/cw8fpl8r1x9rmaqj55fwbfnnrgw7b40k-libidn2-2.3.4) [dependency-of] glibc @ 2.37-8 (/nix/store/02mqs1by2vab9yzw0qc4j7463w78p3ps-glibc-2.37-8)",
				"libunistring @ 1.1 (/nix/store/h1ysk4vvw48winwmh38rvnsj0dlsz7c1-libunistring-1.1) [dependency-of] libidn2 @ 2.3.4 (/nix/store/cw8fpl8r1x9rmaqj55fwbfnnrgw7b40k-libidn2-2.3.4)",
				"xgcc @ 12.3.0 (/nix/store/fmz62d844wf4blb11k21f4m0q6n6hdfp-xgcc-12.3.0-libgcc) [dependency-of] glibc @ 2.37-8 (/nix/store/02mqs1by2vab9yzw0qc4j7463w78p3ps-glibc-2.37-8)",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			c := NewStoreCataloger()
			pkgtest.NewCatalogTester().
				WithImageResolver(t, tt.fixture).
				ExpectsPackageStrings(tt.wantPkgs).
				ExpectsRelationshipStrings(tt.wantRel).
				TestCataloger(t, c)
		})
	}
}

func TestStoreCataloger_Directory(t *testing.T) {

	tests := []struct {
		fixture  string
		wantPkgs []pkg.Package
		wantRel  []artifact.Relationship
	}{
		{
			fixture: "test-fixtures/fixture-1",
			wantPkgs: []pkg.Package{
				{
					Name:      "glibc",
					Version:   "2.34-210",
					PURL:      "pkg:nix/glibc@2.34-210?output=bin&outputhash=h0cnbmfcn93xm5dg2x27ixhag1cwndga",
					Locations: file.NewLocationSet(file.NewLocation("nix/store/h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin")),
					FoundBy:   storeCatalogerName,
					Type:      pkg.NixPkg,
					Metadata: pkg.NixStoreEntry{
						Derivation: "5av396z8xa13jg89g9jws145c0k26k2x-glibc-2.34-210.drv",
						OutputHash: "h0cnbmfcn93xm5dg2x27ixhag1cwndga",
						Output:     "bin",
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
				FromDirectory(t, tt.fixture).
				Expects(tt.wantPkgs, tt.wantRel).
				TestCataloger(t, c)
		})
	}
}
