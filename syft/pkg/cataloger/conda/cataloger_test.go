package conda

import (
	"context"
	"fmt"
	"testing"

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
	}{
		{
			name:    "regular python package",
			fixture: "test-fixtures/conda-meta-jupyterlab",
			expectedPackages: []pkg.Package{
				{
					Name:    "jupyterlab",
					Version: "4.4.3",
					FoundBy: "conda-meta-cataloger",
					PURL:    "pkg:generic/jupyterlab@4.4.3", // TODO CONDAPKG: We do not have conda-specific grype support yet, so we use generic.
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
						ExtractedPackageDir: "/Users/simeon/Library/Caches/rattler/cache/pkgs/jupyterlab-4.4.3-pyhd8ed1ab_0",
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
							Source: "/Users/simeon/Library/Caches/rattler/cache/pkgs/jupyterlab-4.4.3-pyhd8ed1ab_0",
							Type:   1,
						},
					},
				},
			},
		},
	}

	fmt.Println("Hello from the test!")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			(pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				Expects(test.expectedPackages, nil).
				TestCataloger(t, NewCondaMetaCataloger()))
		})
	}
}
