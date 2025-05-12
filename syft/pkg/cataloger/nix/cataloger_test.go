package nix

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestCataloger_Image(t *testing.T) {
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
			fixture: "image-nixos-jq-pkg-db",
			wantPkgs: []string{
				"glibc @ 2.37-8 (/nix/var/nix/db/db.sqlite)",
				"jq @ 1.6 (/nix/var/nix/db/db.sqlite)", // lib output
				"jq @ 1.6 (/nix/var/nix/db/db.sqlite)", // bin output
				"libidn2 @ 2.3.4 (/nix/var/nix/db/db.sqlite)",
				"libunistring @ 1.1 (/nix/var/nix/db/db.sqlite)",
				"oniguruma @ 6.9.8 (/nix/var/nix/db/db.sqlite)",
				"xgcc @ 12.3.0 (/nix/var/nix/db/db.sqlite)",
			},
			wantRel: []string{
				// used the DB cataloger, thus has a complete dependency graph
				"glibc @ 2.37-8 (/nix/var/nix/db/db.sqlite) [dependency-of] jq @ 1.6 (/nix/var/nix/db/db.sqlite)", // jq bin output
				"glibc @ 2.37-8 (/nix/var/nix/db/db.sqlite) [dependency-of] jq @ 1.6 (/nix/var/nix/db/db.sqlite)", // jq lib output
				"glibc @ 2.37-8 (/nix/var/nix/db/db.sqlite) [dependency-of] oniguruma @ 6.9.8 (/nix/var/nix/db/db.sqlite)",
				"jq @ 1.6 (/nix/var/nix/db/db.sqlite) [dependency-of] jq @ 1.6 (/nix/var/nix/db/db.sqlite)", // jq bin to lib output dependency
				"libidn2 @ 2.3.4 (/nix/var/nix/db/db.sqlite) [dependency-of] glibc @ 2.37-8 (/nix/var/nix/db/db.sqlite)",
				"libunistring @ 1.1 (/nix/var/nix/db/db.sqlite) [dependency-of] libidn2 @ 2.3.4 (/nix/var/nix/db/db.sqlite)",
				"oniguruma @ 6.9.8 (/nix/var/nix/db/db.sqlite) [dependency-of] jq @ 1.6 (/nix/var/nix/db/db.sqlite)", // jq bin output
				"oniguruma @ 6.9.8 (/nix/var/nix/db/db.sqlite) [dependency-of] jq @ 1.6 (/nix/var/nix/db/db.sqlite)", // jq lib output
				"xgcc @ 12.3.0 (/nix/var/nix/db/db.sqlite) [dependency-of] glibc @ 2.37-8 (/nix/var/nix/db/db.sqlite)",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				WithImageResolver(t, tt.fixture).
				ExpectsPackageStrings(tt.wantPkgs).
				ExpectsRelationshipStrings(tt.wantRel).
				TestCataloger(t, NewCataloger(DefaultConfig()))
		})
	}
}

func TestCataloger_Image_FilesListing(t *testing.T) {
	tests := []struct {
		fixture      string
		wantPkgFiles map[string][]string
	}{
		{
			fixture: "image-nixos-jq-pkg-db",
			wantPkgFiles: map[string][]string{
				"libidn2": {
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/lib/libidn2.la",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/lib/libidn2.so.0.3.8",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/cs/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/da/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/de/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/eo/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/es/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/fi/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/fr/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/fur/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/hr/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/hu/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/id/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/it/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/ja/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/ka/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/ko/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/nl/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/pl/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/pt_BR/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/ro/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/ru/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/sr/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/sv/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/uk/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/vi/LC_MESSAGES/libidn2.mo",
					"/nix/store/k8ivghpggjrq1n49xp8sj116i4sh8lia-libidn2-2.3.4/share/locale/zh_CN/LC_MESSAGES/libidn2.mo",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				WithImageResolver(t, tt.fixture).
				ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
					found := strset.New()
					for _, p := range pkgs {
						if files, ok := tt.wantPkgFiles[p.Name]; ok {
							m, ok := p.Metadata.(pkg.NixStoreEntry)
							require.True(t, ok)
							if d := cmp.Diff(files, m.Files); d != "" {
								t.Errorf("unexpected files for package %q: %s", p.Name, d)
							}
							found.Add(p.Name)
						}
					}
					expected := strset.New()
					for n := range tt.wantPkgFiles {
						expected.Add(n)
					}
					assert.ElementsMatch(t, expected.List(), found.List())
				}).
				TestCataloger(t, NewCataloger(Config{CaptureOwnedFiles: true}))
		})
	}
}

func TestCataloger_Directory(t *testing.T) {

	tests := []struct {
		fixture  string
		wantPkgs []pkg.Package
		wantRel  []artifact.Relationship
	}{
		{
			fixture: "test-fixtures/fixture-1",
			wantPkgs: []pkg.Package{
				{
					Name:    "glibc",
					Version: "2.34-210",
					PURL:    "pkg:nix/glibc@2.34-210?drvpath=5av396z8xa13jg89g9jws145c0k26k2x-glibc-2.34-210.drv&output=bin&outputhash=h0cnbmfcn93xm5dg2x27ixhag1cwndga",
					Locations: file.NewLocationSet(
						file.NewLocation("nix/store/h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
						file.NewLocation("nix/store/5av396z8xa13jg89g9jws145c0k26k2x-glibc-2.34-210.drv").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation),
					),
					FoundBy: "nix-cataloger",
					Type:    pkg.NixPkg,
					Metadata: pkg.NixStoreEntry{
						Path: "/nix/store/h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin",
						Derivation: pkg.NixDerivation{
							Path:   "nix/store/5av396z8xa13jg89g9jws145c0k26k2x-glibc-2.34-210.drv",
							System: "aarch64-linux",
							InputDerivations: []pkg.NixDerivationReference{
								{
									Path:    "/nix/store/1zi0k7y01rhqr2gfqb42if0icswg65sj-locale-C.diff.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/45j86ggi8mlpfslcrgvjf7m6phia21fp-raw.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/4fnfsd9sc7bam6886hwyaprdsww66dg3-bison-3.8.2.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/51azdrrvcqrk2hbky7ryphlwd99yz25d-linux-headers-5.18.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/67s0qc21gyarmdwc181bqmjc3qzv8zkz-libidn2-2.3.2.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/9rhliwskh3mrrs5nfzgz0x6wrccyfg7k-bootstrap-stage0-glibc-bootstrap.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/cl1wcw2v1ifzjlkzi50h32a6lms9m25s-binutils-2.38.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/ghjc8bkfk8lh53z14mk2nk7h059zh7vx-python3-minimal-3.10.5.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/k3786wfzw637r7sylccdmm92saqp73d8-glibc-2.34.tar.xz.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/l5zr5m1agvvnic49fg6qc44g5fgj3la1-glibc-reinstate-prlimit64-fallback.patch?id=eab07e78b691ae7866267fc04d31c7c3ad6b0eeb.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/mf5kz6d01ab8h0rswzyr04mbcd6g5x9n-bootstrap-stage2-stdenv-linux.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/nd1zy67vp028707pbh466qhrfqh4cpq6-bootstrap-stage2-gcc-wrapper-.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/ra77ww7p2xx8jh8n4m9vmj6wc8wxijdb-bootstrap-tools.drv",
									Outputs: []string{"out"},
								},
								{
									Path:    "/nix/store/wlldapf5bg58kivw520ll5bw0fmlaid7-raw.drv",
									Outputs: []string{"out"},
								},
							},
							InputSources: []string{
								"/nix/store/001gp43bjqzx60cg345n2slzg7131za8-nix-nss-open-files.patch",
								"/nix/store/7kw224hdyxd7115lrqh9a4dv2x8msq2s-fix-x64-abi.patch",
								"/nix/store/8haph3ng4mgsqr6p4024vj8k6kg3mqc4-nix-locale-archive.patch",
								"/nix/store/95hp6hs9g73h93safadb8x6vajyqkv6q-0001-Revert-Remove-all-usage-of-BASH-or-BASH-in-installed.patch",
								"/nix/store/9krlzvny65gdc8s7kpb6lkx8cd02c25b-default-builder.sh",
								"/nix/store/b1w7zbvm39ff1i52iyjggyvw2rdxz104-dont-use-system-ld-so-cache.patch",
								"/nix/store/ikmqczy0y20n04a2b8qfflzwihv8139g-separate-debug-info.sh",
								"/nix/store/mgx19wbmgrh3rblbxhs6vi47sha15n11-2.34-master.patch.gz",
								"/nix/store/mnglr8rr7nl444h7p50ysyq8qd0fm1lm-dont-use-system-ld-so-preload.patch",
								"/nix/store/xkd50xxii6k7l1kmw4l5x6xzbhamcs87-allow-kernel-2.6.32.patch",
								"/nix/store/za0pg7fmysrcwrqcal26fnmzw6vycgdn-fix_path_attribute_in_getconf.patch",
							},
						},
						OutputHash: "h0cnbmfcn93xm5dg2x27ixhag1cwndga",
						Output:     "bin",
						Files:      nil, // default cataloger configure does not capture owned files
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, tt.fixture).
				Expects(tt.wantPkgs, tt.wantRel).
				TestCataloger(t, NewCataloger(DefaultConfig()))
		})
	}
}
