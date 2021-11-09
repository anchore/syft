package cyclonedx12xml

import (
	"encoding/xml"
	"time"

	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/formats/cyclonedx12xml/model"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

// toFormatModel creates and populates a new in-memory representation of a CycloneDX 1.2 document
func toFormatModel(s sbom.SBOM) model.Document {
	versionInfo := version.FromBuild()

	doc := model.Document{
		XMLNs:         "http://cyclonedx.org/schema/bom/1.2",
		Version:       1,
		SerialNumber:  uuid.New().URN(),
		BomDescriptor: toBomDescriptor(internal.ApplicationName, versionInfo.Version, s.Source),
	}

	// attach components
	for _, p := range s.Artifacts.PackageCatalog.Sorted() {
		doc.Components = append(doc.Components, toComponent(p))
	}

	return doc
}

func toComponent(p pkg.Package) model.Component {
	return model.Component{
		Type:       "library", // TODO: this is not accurate
		Name:       p.Name,
		Version:    p.Version,
		PackageURL: p.PURL,
		Licenses:   toLicenses(p.Licenses),
	}
}

// NewBomDescriptor returns a new BomDescriptor tailored for the current time and "syft" tool details.
func toBomDescriptor(name, version string, srcMetadata source.Metadata) *model.BomDescriptor {
	return &model.BomDescriptor{
		XMLName:   xml.Name{},
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: []model.BomDescriptorTool{
			{
				Vendor:  "anchore",
				Name:    name,
				Version: version,
			},
		},
		Component: toBomDescriptorComponent(srcMetadata),
	}
}

func toBomDescriptorComponent(srcMetadata source.Metadata) *model.BomDescriptorComponent {
	switch srcMetadata.Scheme {
	case source.ImageScheme:
		return &model.BomDescriptorComponent{
			Component: model.Component{
				Type:    "container",
				Name:    srcMetadata.ImageMetadata.UserInput,
				Version: srcMetadata.ImageMetadata.ManifestDigest,
			},
		}
	case source.DirectoryScheme:
		return &model.BomDescriptorComponent{
			Component: model.Component{
				Type: "file",
				Name: srcMetadata.Path,
			},
		}
	}
	return nil
}

func toLicenses(licenses []string) *[]model.License {
	if len(licenses) == 0 {
		return nil
	}

	var result []model.License
	for _, licenseName := range licenses {
		result = append(result, model.License{
			Name: licenseName,
		})
	}
	return &result
}
