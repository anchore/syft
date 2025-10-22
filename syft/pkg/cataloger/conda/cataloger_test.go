package conda

import (
	"context"
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_CondaCataloger(t *testing.T) {
	ctx := context.TODO()

	tests := []struct {
		name             string
		fixture          string
		expectedPackages []pkg.Package
		wantErr          require.ErrorAssertionFunc
	}{
		{
			name:    "multiple packages in conda meta (python, c binaries, ...)",
			fixture: "test-fixtures/conda-meta-python-c-etc",
			wantErr: require.NoError,
			expectedPackages: []pkg.Package{
				{
					Name:    "jupyterlab",
					Version: "4.4.3",
					FoundBy: "conda-meta-cataloger",
					Locations: file.NewLocationSet(
						file.NewLocation("conda-meta/jupyterlab-4.4.3-pyhd8ed1ab_0.json"),
					),
					Language: pkg.UnknownLanguage,
					Type:     pkg.CondaPkg,
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "BSD-3-Clause", file.NewLocation("conda-meta/jupyterlab-4.4.3-pyhd8ed1ab_0.json")),
					),
					Metadata: pkg.CondaMetaPackage{
						Name:                "jupyterlab",
						Version:             "4.4.3",
						Build:               "pyhd8ed1ab_0",
						BuildNumber:         0,
						Channel:             "https://conda.anaconda.org/conda-forge/",
						Subdir:              "noarch",
						Noarch:              "python",
						License:             "BSD-3-Clause",
						LicenseFamily:       "BSD",
						MD5:                 "4861a0c2a5a5d0481a450a9dfaf9febe",
						SHA256:              "fc0235a71d852734fe92183a78cb91827367573450eba82465ae522c64230736",
						Size:                8236973,
						Timestamp:           1748273017680,
						Filename:            "jupyterlab-4.4.3-pyhd8ed1ab_0.conda",
						URL:                 "https://conda.anaconda.org/conda-forge/noarch/jupyterlab-4.4.3-pyhd8ed1ab_0.conda",
						ExtractedPackageDir: "/Users/example-user/Library/Caches/rattler/cache/pkgs/jupyterlab-4.4.3-pyhd8ed1ab_0",
						Depends: []string{
							"async-lru >=1.0.0",
							"httpx >=0.25.0",
							"importlib-metadata >=4.8.3",
							"ipykernel >=6.5.0",
							"jinja2 >=3.0.3",
							"jupyter-lsp >=2.0.0",
							"jupyter_core",
							"jupyter_server >=2.4.0,<3",
							"jupyterlab_server >=2.27.1,<3",
							"notebook-shim >=0.2",
							"packaging",
							"python >=3.9",
							"setuptools >=41.1.0",
							"tomli >=1.2.2",
							"tornado >=6.2.0",
							"traitlets",
						},
						Files: []string{
							"lib/python3.13/site-packages/jupyterlab/schemas/@jupyterlab/apputils-extension/kernels-settings.json",
							"lib/python3.13/site-packages/jupyterlab/schemas/@jupyterlab/apputils-extension/notification.json",
						},
						PathsData: &pkg.CondaPathsData{
							PathsVersion: 1,
							Paths: []pkg.CondaPathData{
								{
									Path:           "lib/python3.13/site-packages/jupyterlab/schemas/@jupyterlab/apputils-extension/kernels-settings.json",
									PathType:       "hardlink",
									SHA256:         "081a7e126deffbcd596863f3349a19416fbbe1fd570ab392270315f7cf5a8c27",
									SHA256InPrefix: "081a7e126deffbcd596863f3349a19416fbbe1fd570ab392270315f7cf5a8c27",
									SizeInBytes:    935,
								},
								{
									Path:           "lib/python3.13/site-packages/jupyterlab/schemas/@jupyterlab/apputils-extension/notification.json",
									PathType:       "hardlink",
									SHA256:         "f9f42636592f62cdd03e3d5552b020811e3f8be6fc47c03d5a92396941b8d5d8",
									SHA256InPrefix: "f9f42636592f62cdd03e3d5552b020811e3f8be6fc47c03d5a92396941b8d5d8",
									SizeInBytes:    1565,
								},
							},
						},
						Link: &pkg.CondaLink{
							Source: "/Users/example-user/Library/Caches/rattler/cache/pkgs/jupyterlab-4.4.3-pyhd8ed1ab_0",
							Type:   1,
						},
					},
				},
				{
					Name:    "zlib",
					Version: "1.2.11",
					FoundBy: "conda-meta-cataloger",
					Locations: file.NewLocationSet(
						file.NewLocation("conda-meta/zlib-1.2.11-h90dfc92_1014.json"),
					),
					Language: pkg.UnknownLanguage,
					Type:     pkg.CondaPkg,
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "Zlib", file.NewLocation("conda-meta/zlib-1.2.11-h90dfc92_1014.json")),
					),
					Metadata: pkg.CondaMetaPackage{
						Arch:                "arm64",
						Name:                "zlib",
						Version:             "1.2.11",
						Build:               "h90dfc92_1014",
						BuildNumber:         1014,
						Channel:             "https://conda.anaconda.org/conda-forge/",
						Subdir:              "osx-arm64",
						Noarch:              "",
						License:             "Zlib",
						LicenseFamily:       "Other",
						MD5:                 "348a30b1350c9d91a4dbf05f5e46e0bb",
						SHA256:              "a70c028fd3b9af1d7ea3d7099d810f3d2588096237bb472db331a51a36f931c0",
						Size:                86757,
						Timestamp:           1648307332172,
						Filename:            "zlib-1.2.11-h90dfc92_1014.tar.bz2",
						URL:                 "https://conda.anaconda.org/conda-forge/osx-arm64/zlib-1.2.11-h90dfc92_1014.tar.bz2",
						ExtractedPackageDir: "/Users/example-user/Library/Caches/rattler/cache/pkgs/zlib-1.2.11-h90dfc92_1014",
						Depends: []string{
							"libzlib 1.2.11 h90dfc92_1014",
						},
						Files: []string{
							"include/zconf.h",
							"include/zlib.h",
							"lib/pkgconfig/zlib.pc",
							"lib/libz.a",
							"lib/libz.dylib",
						},
						PathsData: &pkg.CondaPathsData{
							PathsVersion: 1,
							Paths: []pkg.CondaPathData{
								{
									Path:           "include/zconf.h",
									PathType:       "hardlink",
									SHA256:         "77304005ceb5f0d03ad4c37eb8386a10866e4ceeb204f7c3b6599834c7319541",
									SHA256InPrefix: "77304005ceb5f0d03ad4c37eb8386a10866e4ceeb204f7c3b6599834c7319541",
									SizeInBytes:    16262,
								},
								{
									Path:           "include/zlib.h",
									PathType:       "hardlink",
									SHA256:         "4ddc82b4af931ab55f44d977bde81bfbc4151b5dcdccc03142831a301b5ec3c8",
									SHA256InPrefix: "4ddc82b4af931ab55f44d977bde81bfbc4151b5dcdccc03142831a301b5ec3c8",
									SizeInBytes:    96239,
								},
								{
									Path:           "lib/pkgconfig/zlib.pc",
									PathType:       "hardlink",
									SHA256:         "357773df3c44a5ebd77fdadd0869b5b06394bbf556c2d6c9736dd53e9df3b2c2",
									SHA256InPrefix: "5b4eb6062f97875eaadb3b6c7cf8cfeff3808798ecbf2bfc095f18dcecc509bf",
									SizeInBytes:    285,
								},
								{
									Path:           "lib/libz.a",
									PathType:       "hardlink",
									SHA256:         "40c056a5d8155d9b3f42adfe35f7fc6e5fa15cc6588ffad0f09fe67517feada0",
									SHA256InPrefix: "40c056a5d8155d9b3f42adfe35f7fc6e5fa15cc6588ffad0f09fe67517feada0",
									SizeInBytes:    107128,
								},
								{
									Path:           "lib/libz.dylib",
									PathType:       "softlink",
									SHA256:         "67ed489e2f378880f72fb1c0d1cc916e184b9632eccf2b5c1b34ddf01ed1701c",
									SHA256InPrefix: "09e47dbc60aa970e153913fe84551ad7f5aa51c21907591340a0cc999adab859",
									SizeInBytes:    122478,
								},
							},
						},
						Link: &pkg.CondaLink{
							Source: "/Users/example-user/Library/Caches/rattler/cache/pkgs/zlib-1.2.11-h90dfc92_1014",
							Type:   1,
						},
					},
				},
			},
		},
		{
			name:             "badly formatted conda meta json file",
			fixture:          "test-fixtures/conda-meta-bad-json",
			expectedPackages: nil,
			wantErr: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "failed to parse conda-meta package file at conda-meta/package-1.2.3-pyhd8ed1ab_0.json")
				require.Contains(t, err.Error(), "invalid character")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				Expects(test.expectedPackages, nil).
				WithErrorAssertion(test.wantErr).
				TestCataloger(t, NewCondaMetaCataloger())
		})
	}
}

func TestCondaMetaPackageMetadata_FileOwner(t *testing.T) {
	tests := []struct {
		metadata pkg.CondaMetaPackage
		expected []string
	}{
		{
			metadata: pkg.CondaMetaPackage{
				Files: []string{
					"include/zconf.h",
					"include/zlib.h",
					"lib/pkgconfig/zlib.pc",
					"lib/libz.a",
					"lib/libz.dylib",
				},
			},
			expected: []string{
				"include/zconf.h",
				"include/zlib.h",
				"lib/libz.a",
				"lib/libz.dylib",
				"lib/pkgconfig/zlib.pc",
			},
		},
	}

	for _, test := range tests {
		t.Run(strings.Join(test.expected, ","), func(t *testing.T) {
			actual := test.metadata.OwnedFiles()
			for _, d := range deep.Equal(test.expected, actual) {
				t.Errorf("diff: %+v", d)
			}
		})
	}
}
