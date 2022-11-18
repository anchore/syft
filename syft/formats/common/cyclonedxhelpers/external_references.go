package cyclonedxhelpers

import (
	"fmt"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	syftFile "github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

//nolint:gocognit
func encodeExternalReferences(p pkg.Package) *[]cyclonedx.ExternalReference {
	var refs []cyclonedx.ExternalReference
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
		case pkg.JavaMetadata:
			if len(metadata.ArchiveDigests) > 0 {
				for _, digest := range metadata.ArchiveDigests {
					refs = append(refs, cyclonedx.ExternalReference{
						URL:  "",
						Type: cyclonedx.ERTypeBuildMeta,
						Hashes: &[]cyclonedx.Hash{{
							Algorithm: toCycloneDXAlgorithm(digest.Algorithm),
							Value:     digest.Value,
						}},
					})
				}
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

// supported algorithm in cycloneDX as of 1.4
// "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
// "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE3"
// syft supported digests: cmd/syft/cli/eventloop/tasks.go
// MD5, SHA1, SHA256
func toCycloneDXAlgorithm(algorithm string) cyclonedx.HashAlgorithm {
	validMap := map[string]cyclonedx.HashAlgorithm{
		"sha1":   cyclonedx.HashAlgorithm("SHA-1"),
		"md5":    cyclonedx.HashAlgorithm("MD5"),
		"sha256": cyclonedx.HashAlgorithm("SHA-256"),
	}

	return validMap[algorithm]
}

func decodeExternalReferences(c *cyclonedx.Component, metadata interface{}) {
	if c.ExternalReferences == nil {
		return
	}
	switch meta := metadata.(type) {
	case *pkg.ApkMetadata:
		meta.URL = refURL(c, cyclonedx.ERTypeDistribution)
	case *pkg.CargoPackageMetadata:
		meta.Source = refURL(c, cyclonedx.ERTypeDistribution)
	case *pkg.NpmPackageJSONMetadata:
		meta.URL = refURL(c, cyclonedx.ERTypeDistribution)
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.GemMetadata:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.JavaMetadata:
		var digests []syftFile.Digest
		if ref := findExternalRef(c, cyclonedx.ERTypeBuildMeta); ref != nil {
			if ref.Hashes != nil {
				for _, hash := range *ref.Hashes {
					digests = append(digests, syftFile.Digest{
						Algorithm: syftFile.CleanDigestAlgorithmName(string(hash.Algorithm)),
						Value:     hash.Value,
					})
				}
			}
		}

		meta.ArchiveDigests = digests
	case *pkg.PythonPackageMetadata:
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
