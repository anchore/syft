package internal

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

// Backfill takes all information present in the package and attempts to fill in any missing information
// from any available sources, such as the Metadata and PURL.
//
// Backfill does not call p.SetID(), but this needs to be called later to ensure it's up to date
func Backfill(p *pkg.Package) {
	if p.PURL == "" {
		return
	}

	purl, err := packageurl.FromString(p.PURL)
	if err != nil {
		log.Debugf("unable to parse purl: %s: %w", p.PURL, err)
		return
	}

	var cpes []cpe.CPE
	epoch := ""

	for _, qualifier := range purl.Qualifiers {
		switch qualifier.Key {
		case pkg.PURLQualifierCPES:
			rawCpes := strings.Split(qualifier.Value, ",")
			for _, rawCpe := range rawCpes {
				c, err := cpe.New(rawCpe, cpe.DeclaredSource)
				if err != nil {
					log.Debugf("unable to decode cpe %s in purl %s: %w", rawCpe, p.PURL, err)
					continue
				}
				cpes = append(cpes, c)
			}
		case pkg.PURLQualifierEpoch:
			epoch = qualifier.Value
		}
	}

	if p.Type == "" {
		p.Type = pkg.TypeFromPURL(p.PURL)
	}
	if p.Language == "" {
		p.Language = pkg.LanguageFromPURL(p.PURL)
	}
	if p.Name == "" {
		p.Name = nameFromPurl(purl)
	}

	setVersionFromPurl(p, purl, epoch)

	if p.Language == pkg.Java {
		setJavaMetadataFromPurl(p, purl)
	}

	for _, c := range cpes {
		if slices.Contains(p.CPEs, c) {
			continue
		}
		p.CPEs = append(p.CPEs, c)
	}
}

func setJavaMetadataFromPurl(p *pkg.Package, _ packageurl.PackageURL) {
	if p.Type != pkg.JavaPkg {
		return
	}
	if p.Metadata == nil {
		// since we don't know if the purl elements directly came from pom properties or the manifest,
		// we can only go as far as to set the type to JavaArchive, but not fill in the group id and artifact id
		p.Metadata = pkg.JavaArchive{}
	}
}

func setVersionFromPurl(p *pkg.Package, purl packageurl.PackageURL, epoch string) {
	if p.Version == "" {
		p.Version = purl.Version
	}

	if epoch != "" && p.Type == pkg.RpmPkg && !epochPrefix.MatchString(p.Version) {
		p.Version = fmt.Sprintf("%s:%s", epoch, p.Version)
	}
}

var epochPrefix = regexp.MustCompile(`^\d+:`)

// nameFromPurl returns the syft package name of the package from the purl. If the purl includes a namespace,
// the name is prefixed as appropriate based on the PURL type
func nameFromPurl(purl packageurl.PackageURL) string {
	if !nameExcludesPurlNamespace(purl.Type) && purl.Namespace != "" {
		return fmt.Sprintf("%s/%s", purl.Namespace, purl.Name)
	}
	return purl.Name
}

func nameExcludesPurlNamespace(purlType string) bool {
	switch purlType {
	case packageurl.TypeAlpine,
		packageurl.TypeAlpm,
		packageurl.TypeConan,
		packageurl.TypeCpan,
		packageurl.TypeDebian,
		packageurl.TypeMaven,
		packageurl.TypeQpkg,
		packageurl.TypeRPM,
		packageurl.TypeSWID:
		return true
	}
	return false
}
