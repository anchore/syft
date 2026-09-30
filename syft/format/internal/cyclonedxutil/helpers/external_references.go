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
	if srcRef := encodeSourcePackageExternalReference(p); srcRef != nil {
		refs = append(refs, *srcRef)
	}
	if len(refs) > 0 {
		return &refs
	}
	return nil
}

// encodeSourcePackageExternalReference returns a "source-distribution" reference holding the PURL of the distro
// source package that a binary OS package was built from (e.g. libpam-runtime -> pkg:deb/debian/pam@...?arch=source).
// It is only emitted when the source differs from the binary package (by name or version) and when the package PURL
// is of the type implied by the metadata. The main consumer is vulnerability matching, since distros tend to report
// vulnerabilities against the source package rather than each binary package built from it.
//
// why an external reference and not pedigree: `component.pedigree.ancestors` looks like the obvious spot for "this
// binary came from that source", but pedigree describes code lineage (forks, patched variants, and the patches that
// separate them). A binary built unmodified from its own distro source package is the same code in a different form,
// not a fork, and CycloneDX components are deliberately agnostic to source vs binary form (see the comments from the
// CycloneDX maintainers in https://github.com/CycloneDX/specification/issues/612#issuecomment-2958800363). The
// ancestor slot is better left for the upstream project a distro patched (e.g. Linux-PAM for Debian's pam), which
// syft does not know today.
//
// why "source-distribution": the spec defines it as "the location where the source code distributable can be
// obtained", and a deb/rpm source package is exactly that distributable (a .dsc and tarballs in the Debian source
// pool, a .src.rpm in an SRPMS repo). The value is a PURL (an identifier) rather than a download URL, which the
// schema allows since external reference URLs are URIs of any scheme, and a CycloneDX maintainer confirmed this exact
// shape is valid in https://github.com/CycloneDX/specification/issues/612#issuecomment-5428057874. A first-class
// "source" component type was discussed in that issue and deferred to CycloneDX 2.0.
func encodeSourcePackageExternalReference(p pkg.Package) *cyclonedx.ExternalReference {
	if p.PURL == "" {
		return nil
	}
	src := sourcePackageOf(p)
	if src == nil {
		return nil
	}

	// the binary PURL is only consulted for the namespace and a small set of qualifiers (e.g. distro), everything
	// else describes the binary package and must not be restated as a fact about the source package.
	binPurl, err := packageurl.FromString(p.PURL)
	if err != nil || binPurl.Type != src.purlType {
		return nil
	}

	qualifiers := map[string]string{}
	for _, q := range binPurl.Qualifiers {
		if src.keepQualifier(q.Key) {
			qualifiers[q.Key] = q.Value
		}
	}
	if src.arch != "" {
		qualifiers[pkg.PURLQualifierArch] = src.arch
	}

	srcPurl := packageurl.NewPackageURL(
		src.purlType,
		binPurl.Namespace,
		src.name,
		src.version,
		packageurl.QualifiersFromMap(qualifiers),
		"",
	)

	return &cyclonedx.ExternalReference{
		Type: cyclonedx.ERTypeSourceDistribution,
		URL:  srcPurl.ToString(),
	}
}

// sourcePackage is the identity of the source package a binary OS package was built from.
type sourcePackage struct {
	purlType string
	name     string
	version  string
	// arch is the ecosystem's source architecture marker ("source" for deb, "src" or "nosrc" for rpm)
	arch string
}

func (s sourcePackage) keepQualifier(key string) bool {
	switch key {
	case pkg.PURLQualifierDistro:
		return true
	case pkg.PURLQualifierEpoch, pkg.PURLQualifierRpmModularity:
		return s.purlType == pkg.RpmPkg.PackageURLType()
	}
	return false
}

// sourcePackageOf returns the source package for p, or nil when there is none or it is the same as the binary.
//
// only deb and rpm are supported, since those are the ecosystems that publish real source packages with their own
// PURL identity (arch=source / arch=src). apk (origin) and alpm (pkgbase) are intentionally left out: there the
// "source" is a build recipe rather than a published source distributable, and its name is usually also the name of
// a real binary package (e.g. pkg:apk/alpine/libc-dev@0.7.2-r3 is an installable package, not a source archive), so
// a "source-distribution" reference would point at a binary package. Whether those ecosystems have a meaningful
// source PURL is still an open question, and until then the `upstream` PURL qualifier continues to carry that info.
func sourcePackageOf(p pkg.Package) *sourcePackage {
	var src sourcePackage
	var binName, binVersion string
	switch m := p.Metadata.(type) {
	case pkg.DpkgDBEntry:
		src = dpkgSourcePackage(m)
		binName, binVersion = m.Package, m.Version
	case pkg.DpkgArchiveEntry:
		src = dpkgSourcePackage(pkg.DpkgDBEntry(m))
		binName, binVersion = m.Package, m.Version
	case pkg.RpmDBEntry:
		src = rpmSourcePackage(m.SourceRpm)
		binName, binVersion = m.Name, m.Version+"-"+m.Release
	case pkg.RpmArchive:
		src = rpmSourcePackage(m.SourceRpm)
		binName, binVersion = m.Name, m.Version+"-"+m.Release
	default:
		return nil
	}
	if src.name == "" || src.version == "" {
		return nil
	}
	if src.name == binName && src.version == binVersion {
		return nil
	}
	return &src
}

func dpkgSourcePackage(entry pkg.DpkgDBEntry) sourcePackage {
	version := entry.SourceVersion
	if version == "" {
		version = entry.Version
	}
	return sourcePackage{purlType: pkg.DebPkg.PackageURLType(), name: entry.Source, version: version, arch: "source"}
}

// rpmSourcePackage parses a source RPM filename of the form <name>-<version>-<release>.(no)src.rpm.
func rpmSourcePackage(sourceRpm string) sourcePackage {
	var arch string
	switch {
	case strings.HasSuffix(sourceRpm, ".src.rpm"):
		arch = "src"
	case strings.HasSuffix(sourceRpm, ".nosrc.rpm"):
		arch = "nosrc"
	default:
		return sourcePackage{}
	}
	nvr := strings.TrimSuffix(sourceRpm, "."+arch+".rpm")
	release := strings.LastIndex(nvr, "-")
	if release < 0 {
		return sourcePackage{}
	}
	ver := strings.LastIndex(nvr[:release], "-")
	if ver < 0 {
		return sourcePackage{}
	}
	return sourcePackage{purlType: pkg.RpmPkg.PackageURLType(), name: nvr[:ver], version: nvr[ver+1:], arch: arch}
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
