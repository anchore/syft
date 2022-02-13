package cyclonedxhelpers

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/facebookincubator/nvdtools/wfn"
)

func ExternalReferences(p pkg.Package) *[]cyclonedx.ExternalReference {
	refs := []cyclonedx.ExternalReference{}
	if len(p.CPEs) > 0 {
		refs = append(refs, generateCPERefs(p.CPEs)...)
	}
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkMetadata:
			if metadata.URL != "" {
				refs = append(refs, cyclonedx.ExternalReference{
					URL:  metadata.URL,
					Type: cyclonedx.ERTypeDistribution,
				})
			}
		case pkg.CargoPackageMetadata:
			if metadata.Source != "" {
				refs = append(refs, cyclonedx.ExternalReference{
					URL:  metadata.Source,
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
				ref := cyclonedx.ExternalReference{
					URL:  metadata.DirectURLOrigin.URL,
					Type: cyclonedx.ERTypeVCS,
				}
				if metadata.DirectURLOrigin.CommitID != "" {
					ref.Comment = fmt.Sprintf("commit: %s", metadata.DirectURLOrigin.CommitID)
				}
				refs = append(refs, ref)
			}
		}
	}
	if len(refs) > 0 {
		return &refs
	}
	return nil
}

func generateCPERefs(cpes []wfn.Attributes) []cyclonedx.ExternalReference {
	cpeRefs := []cyclonedx.ExternalReference{}
	for _, cpe := range cpes {
		cpeRefs = append(cpeRefs, cyclonedx.ExternalReference{
			URL:     pkg.CPEURI(cpe),
			Type:    cyclonedx.ERTypeAdvisories,
			Comment: "cpe",
		})
	}
	return cpeRefs
}
