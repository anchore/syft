package cyclonedx12json

import (
	"encoding/json"
	"io"
	"time"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/formats/cyclonedx12json/model"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

func encoder(output io.Writer, catalog *pkg.Catalog, srcMetadata *source.Metadata, d *distro.Distro, scope source.Scope) error {
	enc := json.NewEncoder(output)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	err := enc.Encode(toFormatModel(catalog, srcMetadata, d, scope))
	if err != nil {
		return err
	}

	_, err = output.Write([]byte("\n"))
	return err
}

func toFormatModel(catalog *pkg.Catalog, srcMetadata *source.Metadata, _ *distro.Distro, _ source.Scope) model.Document {
	versionInfo := version.FromBuild()

	doc := model.Document{
		Version:       1,
		SerialNumber:  uuid.New().URN(),
		BomDescriptor: toBomDescriptor(internal.ApplicationName, versionInfo.Version, srcMetadata),
	}

	// attach components
	for _, p := range catalog.Sorted() {
		doc.Components = append(doc.Components, toComponent(p))
	}

	return doc
}

// NewBomDescriptor returns a new BomDescriptor tailored for the current time and "syft" tool details.
func toBomDescriptor(name, version string, srcMetadata *source.Metadata) *model.BomDescriptor {
	return &model.BomDescriptor{
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

func toComponent(p *pkg.Package) model.Component {
	return model.Component{
		Type:       "library", // TODO: this is not accurate
		Name:       p.Name,
		Version:    p.Version,
		PackageURL: p.PURL,
		Licenses:   toLicenses(p.Licenses),
	}
}

func toBomDescriptorComponent(srcMetadata *source.Metadata) *model.BomDescriptorComponent {
	if srcMetadata == nil {
		return nil
	}
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
