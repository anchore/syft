package helpers

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/internal/file"
	syftFile "github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal"
	"github.com/anchore/syft/syft/pkg"
)

//nolint:gocognit
func encodeExternalReferences(p pkg.Package) *[]cyclonedx.ExternalReference {
	var refs []cyclonedx.ExternalReference
	if hasMetadata(p) {
		// Skip adding extracted URL and Homepage metadata
		// as "external_reference" if the metadata isn't IRI-compliant
		switch metadata := p.Metadata.(type) {
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
		refs = append(refs, encodeHomepageRefs(p)...)
	}
	if len(refs) > 0 {
		return &refs
	}
	return nil
}

// encodeHomepageRefs emits a "website" external reference from the shared project-homepage source for
// ecosystems whose metadata carries one. It is kept separate from the distribution- and digest-reference
// cases in encodeExternalReferences, and from the ruby/npm cases there that already emit their own
// website reference. internal.Homepage is the single source of truth shared with the SPDX homepage
// encoder so the two formats stay in lockstep.
func encodeHomepageRefs(p pkg.Package) []cyclonedx.ExternalReference {
	return websiteRef(internal.Homepage(p))
}

// websiteRef returns the given URL as a single "website" external reference when it is a valid,
// IRI-compliant URL, or nil otherwise.
func websiteRef(u string) []cyclonedx.ExternalReference {
	if u != "" && isValidExternalRef(u) {
		return []cyclonedx.ExternalReference{{
			URL:  u,
			Type: cyclonedx.ERTypeWebsite,
		}}
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

	return validMap[strings.ToLower(algorithm)]
}

func decodeExternalReferences(c *cyclonedx.Component, metadata any) {
	if c.ExternalReferences == nil {
		return
	}
	switch meta := metadata.(type) {
	case *pkg.ApkDBEntry:
		meta.URL = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.DpkgDBEntry:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.DpkgArchiveEntry:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.RustCargoLockEntry:
		meta.Source = refURL(c, cyclonedx.ERTypeDistribution)
	case *pkg.NpmPackage:
		meta.URL = refURL(c, cyclonedx.ERTypeDistribution)
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.RubyGemspec:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.RpmDBEntry:
		meta.URL = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.RpmArchive:
		meta.URL = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.AlpmDBEntry:
		meta.URL = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.HomebrewFormula:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.LuaRocksPackage:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.OpamPackage:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.PhpComposerInstalledEntry:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.PhpComposerLockEntry:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.DartPubspec:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.SwiplPackEntry:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.CondaMetaPackage:
		meta.URL = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.RDescription:
		if u := refURL(c, cyclonedx.ERTypeWebsite); u != "" {
			meta.URL = []string{u}
		}
	case *pkg.JavaArchive:
		decodeJavaArchiveRefs(c, meta)
	case *pkg.PythonPackage:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
		if meta.DirectURLOrigin == nil {
			meta.DirectURLOrigin = &pkg.PythonDirectURLOriginInfo{}
		}
		meta.DirectURLOrigin.URL = refURL(c, cyclonedx.ERTypeVCS)
		meta.DirectURLOrigin.CommitID = strings.TrimPrefix(refComment(c, cyclonedx.ERTypeVCS), "commit: ")
	}
}

// decodeJavaArchiveRefs restores a JavaArchive's build-metadata digests and its pom project homepage
// from the component's external references.
func decodeJavaArchiveRefs(c *cyclonedx.Component, meta *pkg.JavaArchive) {
	var digests []syftFile.Digest
	if ref := findExternalRef(c, cyclonedx.ERTypeBuildMeta); ref != nil && ref.Hashes != nil {
		for _, hash := range *ref.Hashes {
			digests = append(digests, syftFile.Digest{
				Algorithm: file.CleanDigestAlgorithmName(string(hash.Algorithm)),
				Value:     hash.Value,
			})
		}
	}
	meta.ArchiveDigests = digests

	if u := refURL(c, cyclonedx.ERTypeWebsite); u != "" {
		if meta.PomProject == nil {
			meta.PomProject = &pkg.JavaPomProject{}
		}
		meta.PomProject.URL = u
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
