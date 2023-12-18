package binary

import (
	"reflect"
	"strings"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackage(classifier classifier, location file.Location, matchMetadata map[string]string) *pkg.Package {
	var version string

	version, ok := matchMetadata["version"]
	if !ok {
		major, ok1 := matchMetadata["major"]
		minor, ok2 := matchMetadata["minor"]
		patch, ok3 := matchMetadata["patch"]

		if ok1 && ok2 && ok3 {
			version = strings.Join([]string{major, minor, patch}, ".")
		} else {
			return nil
		}
	}

	update := matchMetadata["update"]

	var cpes []cpe.CPE
	for _, c := range classifier.CPEs {
		c.Version = version
		c.Update = update
		cpes = append(cpes, c)
	}

	p := pkg.Package{
		Name:    classifier.Package,
		Version: version,
		Locations: file.NewLocationSet(
			location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Type:    pkg.BinaryPkg,
		CPEs:    cpes,
		FoundBy: catalogerName,
		Metadata: pkg.BinarySignature{
			Matches: []pkg.ClassifierMatch{
				{
					Classifier: classifier.Class,
					Location:   location,
				},
			},
		},
	}

	if classifier.Type != "" {
		p.Type = classifier.Type
	}

	if !reflect.DeepEqual(classifier.PURL, emptyPURL) {
		purl := classifier.PURL
		purl.Version = version
		p.PURL = purl.ToString()
	}

	if classifier.Language != "" {
		p.Language = classifier.Language
	}

	p.SetID()

	return &p
}
