package helpers

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/file"
	syftFile "github.com/anchore/syft/syft/file"
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
	}

	if len(refs) > 0 {
		return &refs
	}
	return nil
}

func encodeSourcePackageExternalReference(p pkg.Package) *cyclonedx.ExternalReference {
	name, version, arch := sourceCoordinates(p)
	if name == "" || version == "" {
		return nil
	}
	if p.PURL == "" {
		return nil
	}

	pkgPurl, err := packageurl.FromString(p.PURL)
	if err != nil {
		return nil
	}

	qualifiers := pkgPurl.Qualifiers.Map()
	delete(qualifiers, pkg.PURLQualifierUpstream)
	delete(qualifiers, pkg.PURLQualifierArch)

	if arch != "" {
		qualifiers[pkg.PURLQualifierArch] = arch
	}

	srcPurl := packageurl.NewPackageURL(
		pkgPurl.Type,
		pkgPurl.Namespace,
		name,
		version,
		packageurl.QualifiersFromMap(qualifiers),
		pkgPurl.Subpath,
	)

	return &cyclonedx.ExternalReference{
		Type: cyclonedx.ERTypeSourceDistribution,
		URL:  srcPurl.ToString(),
	}
}

func sourceCoordinates(p pkg.Package) (name, version, arch string) {
	switch metadata := p.Metadata.(type) {
	case pkg.ApkDBEntry:
		if metadata.OriginPackage != "" && metadata.OriginPackage != metadata.Package {
			return metadata.OriginPackage, metadata.Version, ""
		}
	case pkg.DpkgDBEntry:
		return dpkgSourceCoordinates(metadata)
	case pkg.DpkgArchiveEntry:
		return dpkgSourceCoordinates(pkg.DpkgDBEntry(metadata))
	case pkg.RpmDBEntry:
		return rpmSourceCoordinates(metadata.SourceRpm)
	case pkg.RpmArchive:
		return rpmSourceCoordinates(metadata.SourceRpm)
	case pkg.AlpmDBEntry:
		if metadata.BasePackage != "" {
			return metadata.BasePackage, metadata.Version, ""
		}
	}
	return "", "", ""
}

func dpkgSourceCoordinates(entry pkg.DpkgDBEntry) (name, version, arch string) {
	if entry.Source == "" {
		return "", "", ""
	}
	if entry.SourceVersion != "" {
		return entry.Source, entry.SourceVersion, "source"
	}
	return entry.Source, entry.Version, "source"
}

func rpmSourceCoordinates(sourceRpm string) (name, version, arch string) {
	// <name>-<version>-<release>.src.rpm
	sourceRpm = strings.TrimSuffix(sourceRpm, ".rpm")
	sourceRpm = strings.TrimSuffix(strings.TrimSuffix(sourceRpm, ".src"), ".nosrc")
	release := strings.LastIndex(sourceRpm, "-")
	if release < 0 {
		return "", "", ""
	}
	ver := strings.LastIndex(sourceRpm[:release], "-")
	if ver < 0 {
		return "", "", ""
	}
	return sourceRpm[:ver], sourceRpm[ver+1:], "src"
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
		meta.URL = refURL(c, cyclonedx.ERTypeDistribution)
	case *pkg.RustCargoLockEntry:
		meta.Source = refURL(c, cyclonedx.ERTypeDistribution)
	case *pkg.NpmPackage:
		meta.URL = refURL(c, cyclonedx.ERTypeDistribution)
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.RubyGemspec:
		meta.Homepage = refURL(c, cyclonedx.ERTypeWebsite)
	case *pkg.JavaArchive:
		var digests []syftFile.Digest
		if ref := findExternalRef(c, cyclonedx.ERTypeBuildMeta); ref != nil {
			if ref.Hashes != nil {
				for _, hash := range *ref.Hashes {
					digests = append(digests, syftFile.Digest{
						Algorithm: file.CleanDigestAlgorithmName(string(hash.Algorithm)),
						Value:     hash.Value,
					})
				}
			}
		}

		meta.ArchiveDigests = digests
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
