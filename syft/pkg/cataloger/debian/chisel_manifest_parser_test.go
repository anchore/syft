package debian

import (
	"context"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/canonical/chisel-manifest/public/manifest"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

func TestParseChiselManifest(t *testing.T) {
	tests := []struct {
		name       string
		compressed bool
	}{
		{
			// chisel writes the manifest zstd-compressed, so compress the fixture the same way
			name:       "zstd-compressed manifest",
			compressed: true,
		},
		{
			name:       "uncompressed manifest",
			compressed: false,
		},
	}

	sha256Digest := func(value string) *file.Digest {
		return &file.Digest{Algorithm: "sha256", Value: value}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := "testdata/chisel/manifest-uncompressed.wall"
			if tt.compressed {
				fixture = zstdCompressedCopy(t, fixture)
			}

			locations := file.NewLocationSet(
				file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			)

			newExpectedPackage := func(name, version string, files []pkg.DpkgFileRecord) pkg.Package {
				return pkg.Package{
					Name:      name,
					Version:   version,
					Locations: locations,
					PURL:      "pkg:deb/ubuntu/" + name + "@" + url.QueryEscape(version) + "?arch=arm64&distro=ubuntu-24.04",
					Type:      pkg.DebPkg,
					Metadata: pkg.DpkgDBEntry{
						Package:      name,
						Version:      version,
						Architecture: "arm64",
						Files:        files,
					},
				}
			}

			expected := []pkg.Package{
				newExpectedPackage("base-files", "13ubuntu10.4", []pkg.DpkgFileRecord{
					// symlinks carry no digest in the chisel manifest; directory entries are excluded
					{Path: "/lib"},
					{Path: "/usr/share/doc/base-files/copyright", Digest: sha256Digest("fd7e4aae7e7b05f217bcf2d02322825c360e66c52c4c2f1b28d784d6297a1c23")},
					{Path: "/var/lib/chisel/manifest.wall"},
					{Path: "/var/run"},
				}),
				newExpectedPackage("binutils-common", "2.42-4ubuntu2.10", []pkg.DpkgFileRecord{
					{Path: "/usr/share/doc/binutils-common/copyright", Digest: sha256Digest("a81bdd422c2c015deca84bf6ad249bf0d7d19885fc01d1894463291b0b7313e1")},
				}),
				newExpectedPackage("binutils-x86-64-linux-gnu", "2.42-4ubuntu2.10", []pkg.DpkgFileRecord{
					{Path: "/usr/bin/x86_64-linux-gnu-ld"},
					{Path: "/usr/bin/x86_64-linux-gnu-ld.bfd", Digest: sha256Digest("a3ef754c93653b732af112fd93cd5912a1c5c7de10004fea140b82e6aa75787c")},
					{Path: "/usr/lib/aarch64-linux-gnu/libbfd-2.42-amd64.so", Digest: sha256Digest("66cbefe348f23ce6fc98f5c8f13e8167428786fae9c816e0bdbdfa4037336bd7")},
					{Path: "/usr/lib/aarch64-linux-gnu/libctf-amd64.so"},
					{Path: "/usr/lib/aarch64-linux-gnu/libctf-amd64.so.0"},
					{Path: "/usr/lib/aarch64-linux-gnu/libctf-amd64.so.0.0.0", Digest: sha256Digest("1b6b5b49356cbe0ccf95301e713cb0a5a96207ec3ca5ec88d80f266a04d6a667")},
					{Path: "/usr/lib/aarch64-linux-gnu/libopcodes-2.42-amd64.so", Digest: sha256Digest("f480951bee32f8aa513752c495ae0ac26cabc402c1cefeb15698cbf8289b0249")},
					{Path: "/usr/share/doc/binutils-x86-64-linux-gnu/copyright", Digest: sha256Digest("a81bdd422c2c015deca84bf6ad249bf0d7d19885fc01d1894463291b0b7313e1")},
					{Path: "/usr/x86_64-linux-gnu/bin/ld"},
					{Path: "/usr/x86_64-linux-gnu/bin/ld.bfd"},
				}),
				newExpectedPackage("libbinutils", "2.42-4ubuntu2.10", []pkg.DpkgFileRecord{
					{Path: "/usr/lib/aarch64-linux-gnu/libbfd-2.42-system.so", Digest: sha256Digest("d9d9cc536c3a752ce0fd09e554ce2e31f98a5d42201984a608ed1e577e4ad0de")},
					{Path: "/usr/lib/aarch64-linux-gnu/libopcodes-2.42-system.so", Digest: sha256Digest("50dd8b3da6956c691363f04fcd3b3774083749cef2108f152747839f13adcef8")},
					{Path: "/usr/share/doc/libbinutils"},
				}),
				newExpectedPackage("libc6", "2.39-0ubuntu8.7", []pkg.DpkgFileRecord{
					{Path: "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", Digest: sha256Digest("393384096ffa869e1be20d2f91fdf08dfadb9f3e531dfe724085d8501d3f85d9")},
					{Path: "/usr/lib/aarch64-linux-gnu/libBrokenLocale.so.1", Digest: sha256Digest("dd5cf7cd6896cb0dba6dfd0f9f059ac53aff36f9fa41e56d4a925a45223868bd")},
					{Path: "/usr/lib/aarch64-linux-gnu/libanl.so.1", Digest: sha256Digest("eff563ba656636b2e14bc60c22a998fffb17340a7ae319465771262ca422c80b")},
					{Path: "/usr/lib/aarch64-linux-gnu/libc.so.6", Digest: sha256Digest("fe5966a43e068ad7cb389c3affa069f4ee6f296e07d7ccc0398a23cfde4f0b7e")},
					{Path: "/usr/lib/aarch64-linux-gnu/libc_malloc_debug.so.0", Digest: sha256Digest("a0159ade69e229087fda61d5a898c60367087a5f3bffa1a74cc858bc12cc54d9")},
					{Path: "/usr/lib/aarch64-linux-gnu/libdl.so.2", Digest: sha256Digest("97387fb55ccfc0cc109dfe99b81de2b7bbaac723d1c215107dc69a068c4b1fae")},
					{Path: "/usr/lib/aarch64-linux-gnu/libm.so.6", Digest: sha256Digest("d5b262e559d38769e4959f036a1cc2c4009fa60b4ec836a7a19ca8554aebf5a5")},
					{Path: "/usr/lib/aarch64-linux-gnu/libmemusage.so", Digest: sha256Digest("237bb5dae96c6c64a5a9760a545deaeaf2945afadf556f6dbd79b6683a2484e7")},
					{Path: "/usr/lib/aarch64-linux-gnu/libmvec.so.1", Digest: sha256Digest("2deff7f312324fc2e3228443f1074377a214db4f60783e97c78e1bab7bf2c851")},
					{Path: "/usr/lib/aarch64-linux-gnu/libnsl.so.1", Digest: sha256Digest("0e90ffa991b2158df4faa56bfdf8f2f5d6b016b7395ec60cf1fd0ffd2b99a1a3")},
					{Path: "/usr/lib/aarch64-linux-gnu/libnss_compat.so.2", Digest: sha256Digest("900b42ffed3dd8bcfb512ebb92ee2d44aaa285db405fad654c85ef2d0f79b89b")},
					{Path: "/usr/lib/aarch64-linux-gnu/libnss_dns.so.2", Digest: sha256Digest("6154da3e8d1db22b0459cf684fb9e847a19004fa18e6d2ca5a6a6374dea6aa86")},
					{Path: "/usr/lib/aarch64-linux-gnu/libnss_files.so.2", Digest: sha256Digest("a1f8b05e5acdf9d9f5690006463ba06d31df2a4bb9cf36a05228a3d5d41946ca")},
					{Path: "/usr/lib/aarch64-linux-gnu/libnss_hesiod.so.2", Digest: sha256Digest("b373b73318f93996e0c48512725822836ebcddd47da0be96653ba769ac5df44f")},
					{Path: "/usr/lib/aarch64-linux-gnu/libpcprofile.so", Digest: sha256Digest("5adcd0cef0cb19c1b4c5d27df49a3d38d798aad89fe88de9fe75dd7ea2aea7a3")},
					{Path: "/usr/lib/aarch64-linux-gnu/libpthread.so.0", Digest: sha256Digest("97b288827c0ab29659dfcdcfab6c2e9e1225c19fc5abfe106d8a53c2c7b34402")},
					{Path: "/usr/lib/aarch64-linux-gnu/libresolv.so.2", Digest: sha256Digest("e79ba5df3dc6e7d1bc67b16a49f13337ba46bbb01be1c896f0bdfd8e91c8e9f7")},
					{Path: "/usr/lib/aarch64-linux-gnu/librt.so.1", Digest: sha256Digest("4b38331a53bc2bd10c1ecf4f02a71c913c40bad13f5fbf93bee5a0e1f25dd493")},
					{Path: "/usr/lib/aarch64-linux-gnu/libthread_db.so.1", Digest: sha256Digest("d010bff4473da0b7984f69699f5eab7df5345f4a41d5e01fcd01fb51f896eb76")},
					{Path: "/usr/lib/aarch64-linux-gnu/libutil.so.1", Digest: sha256Digest("fe15c414e7e585bf749be683eba39d2f8db556b678ed8253f6884be660caac31")},
					{Path: "/usr/lib/ld-linux-aarch64.so.1"},
					{Path: "/usr/share/doc/libc6/copyright", Digest: sha256Digest("d3c95b56fa33e28b57860580f0baf4e4f4de2a268a2b80f1d031a5191bade265")},
				}),
				newExpectedPackage("libctf0", "2.42-4ubuntu2.10", []pkg.DpkgFileRecord{
					{Path: "/usr/lib/aarch64-linux-gnu/libctf.so.0"},
					{Path: "/usr/lib/aarch64-linux-gnu/libctf.so.0.0.0", Digest: sha256Digest("be124ffe36abc3d3068092e5a05300aee0c7b9fa6f59acbb289aedae788ddbae")},
					{Path: "/usr/share/doc/libctf0"},
				}),
				newExpectedPackage("libjansson4", "2.14-2build2", []pkg.DpkgFileRecord{
					{Path: "/usr/lib/aarch64-linux-gnu/libjansson.so.4"},
					{Path: "/usr/lib/aarch64-linux-gnu/libjansson.so.4.14.0", Digest: sha256Digest("ec0e6c38dd7f4979d61563777872de4c9983b0cfb15bbba9b0d9d90e4d736907")},
					{Path: "/usr/share/doc/libjansson4/copyright", Digest: sha256Digest("29347e2528ab31d20e8582b09aa89cd878d306c59a273541141c9aede1903cb8")},
				}),
				newExpectedPackage("libsframe1", "2.42-4ubuntu2.10", []pkg.DpkgFileRecord{
					{Path: "/usr/lib/aarch64-linux-gnu/libsframe.so.1"},
					{Path: "/usr/lib/aarch64-linux-gnu/libsframe.so.1.0.0", Digest: sha256Digest("c56f579c7f266b5bfcbdc9d448d2a8f1a8223483b390d98e311526598bf29a5d")},
					{Path: "/usr/share/doc/libsframe1/copyright", Digest: sha256Digest("a81bdd422c2c015deca84bf6ad249bf0d7d19885fc01d1894463291b0b7313e1")},
				}),
				newExpectedPackage("libzstd1", "1.5.5+dfsg2-2build1.1", []pkg.DpkgFileRecord{
					{Path: "/usr/lib/aarch64-linux-gnu/libzstd.so.1"},
					{Path: "/usr/lib/aarch64-linux-gnu/libzstd.so.1.5.5", Digest: sha256Digest("fe726238b170b83aa83bf1f8a79109b8b61b9eb45234304511d093bbe5f5fb20")},
					{Path: "/usr/share/doc/libzstd1/copyright", Digest: sha256Digest("35e85e8e9bbb71492c5f5dddf39ed65b68775a02ad8d710c25d097b497f06c49")},
				}),
				newExpectedPackage("zlib1g", "1:1.3.dfsg-3.1ubuntu2.1", []pkg.DpkgFileRecord{
					{Path: "/usr/lib/aarch64-linux-gnu/libz.so.1"},
					{Path: "/usr/lib/aarch64-linux-gnu/libz.so.1.3", Digest: sha256Digest("170380b4e7ab28ec86eb090b48df90f84089392cb72fecd5067e5b7a4dc5239f")},
					{Path: "/usr/share/doc/zlib1g/copyright", Digest: sha256Digest("9e5b96d63773a5d177ba264254390f792be07e41748ebd94730981c6cac31cc6")},
				}),
			}

			pkgtest.NewCatalogTester().
				FromFile(t, fixture).
				WithLinuxRelease(linux.Release{
					ID:        "ubuntu",
					IDLike:    []string{"debian"},
					VersionID: "24.04",
				}).
				Expects(expected, nil).
				TestParser(t, parseChiselManifest)
		})
	}
}

func TestChiselEntriesByPackage_FinalSHA256(t *testing.T) {
	// a path that was mutated after installation records both the original digest (sha256) and the
	// resulting digest (final_sha256); the final digest should win
	content := `{"jsonwall":"1.0","schema":"1.0","count":4}
{"kind":"package","name":"base-files","version":"13ubuntu10.4","sha256":"1b22f149ae67c1995615be284899e7b6bb1eed32884944905ab8414f44bbcf0a","arch":"arm64"}
{"kind":"path","path":"/usr/lib/os-release","mode":"0644","slices":["base-files_release-info"],"sha256":"2a09846222b17bbcbbbbdcbc23a2274a341bb5f4fcf0c7f22bcdb45d2a276b13","final_sha256":"a4442dc4dd6a678f059ce0eb1848b4e4e2e39334e64a0e10c8c1d7b607b62ba0","size":386}
{"kind":"slice","name":"base-files_release-info"}
`
	m, err := manifest.Read(strings.NewReader(content))
	require.NoError(t, err)

	entriesByPackage, err := chiselEntriesByPackage(m)
	require.NoError(t, err)

	require.Equal(t, map[string]*chiselPackageEntries{
		"base-files": {
			files: []pkg.DpkgFileRecord{
				{
					Path: "/usr/lib/os-release",
					Digest: &file.Digest{
						Algorithm: "sha256",
						Value:     "a4442dc4dd6a678f059ce0eb1848b4e4e2e39334e64a0e10c8c1d7b607b62ba0",
					},
				},
			},
		},
	}, entriesByPackage)
}

func TestParseChiselManifest_CopyrightLicenses(t *testing.T) {
	s, err := directorysource.NewFromPath("testdata/chisel-rootfs")
	require.NoError(t, err)
	resolver, err := s.FileResolver(source.SquashedScope)
	require.NoError(t, err)

	pkgs, _, err := NewDBCataloger().Catalog(context.Background(), resolver)
	require.NoError(t, err)
	require.Len(t, pkgs, 3)

	licensesByPackage := make(map[string][]string)
	locationsByPackage := make(map[string][]string)
	for _, p := range pkgs {
		var licenses []string
		for _, l := range p.Licenses.ToSlice() {
			licenses = append(licenses, l.Value)
		}
		licensesByPackage[p.Name] = licenses

		var locations []string
		for _, l := range p.Locations.ToSlice() {
			locations = append(locations, l.RealPath)
		}
		sort.Strings(locations)
		locationsByPackage[p.Name] = locations
	}

	require.Equal(t, map[string][]string{
		// copyright file recorded directly in the manifest
		"pkg-a": {"GPL-2"},
		// copyright slice points at a symlinked doc directory (/usr/share/doc/pkg-b -> pkg-a)
		"pkg-b": {"GPL-2"},
		// no copyright slice in the manifest: found via the conventional /usr/share/doc/<pkg>/copyright fallback
		"pkg-c": {"MIT"},
	}, licensesByPackage)

	require.Equal(t, map[string][]string{
		"pkg-a": {"usr/share/doc/pkg-a/copyright", "var/lib/chisel/manifest.wall"},
		"pkg-b": {"usr/share/doc/pkg-a/copyright", "var/lib/chisel/manifest.wall"},
		"pkg-c": {"usr/share/doc/pkg-c/copyright", "var/lib/chisel/manifest.wall"},
	}, locationsByPackage)
}

// zstdCompressedCopy writes a zstd-compressed copy of the given file to a temp dir and returns its path.
func zstdCompressedCopy(t *testing.T, path string) string {
	t.Helper()

	in, err := os.Open(path)
	require.NoError(t, err)
	defer internal.CloseAndLogError(in, path)

	compressedPath := filepath.Join(t.TempDir(), "manifest.wall")
	out, err := os.Create(compressedPath)
	require.NoError(t, err)
	defer internal.CloseAndLogError(out, compressedPath)

	w, err := zstd.NewWriter(out)
	require.NoError(t, err)

	_, err = io.Copy(w, in)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return compressedPath
}
