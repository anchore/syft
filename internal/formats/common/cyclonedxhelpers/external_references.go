package cyclonedxhelpers

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
)

func ExternalReferences(p pkg.Package) *[]cyclonedx.ExternalReference {
	refs := []cyclonedx.ExternalReference{}
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkMetadata:
			if metadata.URL != "" {
				refs = append(refs, cyclonedx.ExternalReference{
					URL:  metadata.URL,
					Type: cyclonedx.ERTypeDistribution,
				})
			}
		case pkg.NpmPackageJSONMetadata:
			if metadata.URL != "" {
				refs = append(refs, cyclonedx.ExternalReference{
					URL:  metadata.URL,
					Type: cyclonedx.ERTypeDistribution,
				})
			}
			if metadata.Homepage != "" {
				refs = append(refs, cyclonedx.ExternalReference{
					URL:  metadata.Homepage,
					Type: cyclonedx.ERTypeWebsite,
				})
			}
		case pkg.GemMetadata:
			if metadata.Homepage != "" {
				refs = append(refs, cyclonedx.ExternalReference{
					URL:  metadata.Homepage,
					Type: cyclonedx.ERTypeWebsite,
				})
			}
		case pkg.PythonPackageMetadata:
			if metadata.DirectURLOrigin != nil && metadata.DirectURLOrigin.URL != "" {
				refs = append(refs, cyclonedx.ExternalReference{
					URL:     metadata.DirectURLOrigin.URL,
					Type:    cyclonedx.ERTypeVCS,
					Comment: fmt.Sprintf("commit: %s", metadata.DirectURLOrigin.CommitID),
				})
			}
		}
	}
	if len(refs) > 0 {
		return &refs
	}
	return nil
}
