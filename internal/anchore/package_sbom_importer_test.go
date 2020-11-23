package anchore

import (
	"testing"

	"github.com/anchore/syft/syft/source"

	"github.com/anchore/syft/syft/pkg"
)

func must(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func TestPackageSbomToModel(t *testing.T) {
	tests := []struct {
		name string
		p    pkg.Package
	}{
		{
			p: pkg.Package{
				Name:    "name",
				Version: "version",
				FoundBy: "foundBy",
				Locations: []source.Location{
					{
						Path:         "path",
						FileSystemID: "layerID",
					},
				},
				Licenses: []string{"license"},
				Language: pkg.Python,
				Type:     pkg.PythonPkg,
				CPEs: []pkg.CPE{
					must(pkg.NewCPE("cpe:2.3:*:some:package:1:*:*:*:*:*:*:*")),
				},
				PURL:         "purl",
				MetadataType: pkg.PythonPackageMetadataType,
				Metadata: pkg.PythonPackageMetadata{
					Name:        "p-name",
					Version:     "p-version",
					License:     "p-license",
					Author:      "p-author",
					AuthorEmail: "p-email",
					Platform:    "p-platform",
					Files: []pkg.PythonFileRecord{
						{
							Path: "p-path",
							Digest: &pkg.PythonFileDigest{
								Algorithm: "p-alg",
								Value:     "p-digest",
							},
							Size: "p-size",
						},
					},
					SitePackagesRootPath: "p-site-packages-root",
					TopLevelPackages:     []string{"top-level"},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			importer := NewPackageSBOMImporter(pkg.NewCatalog(test.p))
			model, err := importer.model()
			if err != nil {
				t.Fatalf("unable to generate model from source material: %+v", err)
			}

			//fmt.Println(reflect.DeepEqual(model, test.p))
			//t.Errorf("sure")

		})
	}

}

//func TestPackageSbomUpload(t *testing.T) {
//	tests := []struct{
//		p *pkg.Package
//	} {
//
//	}
//}
