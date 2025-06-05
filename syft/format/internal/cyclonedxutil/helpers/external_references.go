package helpers

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/pkg"
)

//nolint:gocognit
func encodeExternalReferences(p pkg.Package) *[]cyclonedx.ExternalReference {
	var refs []cyclonedx.ExternalReference
	if hasMetadata(p) {
		// Skip adding extracted URL and Homepage metadata
		// as "external_reference" if the metadata isn't IRI-compliant
		switch metadata := p.Metadata.(type) {
		case pkg.ApkDBEntry:
			if metadata.URL != "" && isValidExternalRef(metadata.URL) {
				refs = append(refs, cyclonedx.ExternalReference{
					URL:  metadata.URL,
					Type: cyclonedx.ERTypeDistribution,
				})
			}
		case pkg.RustCargoLockEntry:
			if metadata.Source != "" {
				refs = append(refs, cyclonedx.ExternalReference{
					URL:  metadata.Source,
					Type: cyclonedx.ERTypeDistribution,
				})
			}
		case pkg.NpmPackage:
			if metadata.URL != "" && isValidExternalRef(metadata.URL) {
				refs = append(refs, cyclonedx.ExternalReference{
					URL:  metadata.URL,
					Type: cyclonedx.ERTypeDistribution,
				})
			}
			if metadata.Homepage != "" && isValidExternalRef(metadata.Homepage) {
				refs = append(refs, cyclonedx.ExternalReference{
					URL:  metadata.Homepage,
					Type: cyclonedx.ERTypeWebsite,
				})
			}
		case pkg.RubyGemspec:
			if metadata.Homepage != "" && isValidExternalRef(metadata.Homepage) {
				refs = append(refs, cyclonedx.ExternalReference{
					URL:  metadata.Homepage,
					Type: cyclonedx.ERTypeWebsite,
				})
			}
		case pkg.JavaArchive:
			//TODO: add support for java archive external references
		case pkg.PythonPackage:
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

func decodeExternalReferences(c *cyclonedx.Component, metadata interface{}) {
	if c.ExternalReferences == nil {
		return
	}
	switch meta := metadata.(type) {
	case *pkg.ApkDBEntry:
		meta.URL = refURL(c, cyclonedx.ERTypeDistribution)
	case *pkg.RustCargoLockEntry:
		meta.Source = refURL(c, cyclonedx.ERTypeDistribution)
	case *pkg.NpmPackage:
		meta.URL = refURL(c, cyclonedx.ERTypeDistribution)
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.RubyGemspec:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.JavaArchive:
		//TODO: add support for java archive external references
	case *pkg.PythonPackage:
		if meta.DirectURLOrigin == nil {
			meta.DirectURLOrigin = &pkg.PythonDirectURLOriginInfo{}
		}
		meta.DirectURLOrigin.URL = refURL(c, cyclonedx.ERTypeVCS)
		meta.DirectURLOrigin.CommitID = strings.TrimPrefix(refComment(c, cyclonedx.ERTypeVCS), "commit: ")
	}
}

func findExternalRef(c *cyclonedx.Component, typ cyclonedx.ExternalReferenceType) *cyclonedx.ExternalReference {
	if c.ExternalReferences != nil {
		for _, r := range *c.ExternalReferences {
			if r.Type == typ {
				return &r
			}
		}
	}
	return nil
}

func refURL(c *cyclonedx.Component, typ cyclonedx.ExternalReferenceType) string {
	if r := findExternalRef(c, typ); r != nil {
		return r.URL
	}
	return ""
}

func refComment(c *cyclonedx.Component, typ cyclonedx.ExternalReferenceType) string {
	if r := findExternalRef(c, typ); r != nil {
		return r.Comment
	}
	return ""
}

// isValidExternalRef checks for IRI-comppliance for input string to be added into "external_reference"
func isValidExternalRef(s string) bool {
	parsed, err := url.Parse(s)
	return err == nil && parsed != nil && parsed.Host != ""
}
