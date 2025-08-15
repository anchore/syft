package binutils

import (
	"bytes"
	"reflect"
	"text/template"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

var emptyPURL = packageurl.PackageURL{}

func NewClassifierPackage(classifier Classifier, location file.Location, matchMetadata map[string]string, catalogerName string) *pkg.Package {
	version, ok := matchMetadata["version"]
	if !ok {
		return nil
	}

	update := matchMetadata["update"]

	var cpes []cpe.CPE
	for _, c := range classifier.CPEs {
		c.Attributes.Version = templatedUpdate(c.Attributes.Version, matchMetadata, version)
		c.Attributes.Update = templatedUpdate(c.Attributes.Update, matchMetadata, update)
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

	if !reflect.DeepEqual(classifier.PURL, emptyPURL) {
		purl := classifier.PURL
		purl.Version = version
		p.PURL = purl.ToString()
	}

	p.SetID()

	return &p
}

func templatedUpdate(providedValue string, matchMetadata map[string]string, defaultValue string) string {
	// if no template provided, just use the value directly
	if providedValue == "" {
		return defaultValue
	}
	// support templated updates
	t, err := template.New("").Option("missingkey=zero").Parse(providedValue)
	if err != nil {
		log.Debugf("unable to parse classifier template=%q : %w", providedValue, err)
	} else {
		update := bytes.Buffer{}
		err = t.Execute(&update, matchMetadata)
		if err != nil {
			log.Debugf("unable to render template: %w", err)
		} else {
			// only use the template result if it's non-empty
			providedValue = update.String()
			if providedValue != "" {
				return providedValue
			}
		}
	}
	return defaultValue
}
