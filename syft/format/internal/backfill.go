package internal

import (
	"fmt"
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
		log.Debug("unable to parse purl: %s: %w", p.PURL, err)
		return
	}

	var cpes []cpe.CPE
	epoch := "0"

	for _, qualifier := range purl.Qualifiers {
		switch qualifier.Key {
		case pkg.PURLQualifierCPES:
			rawCpes := strings.Split(qualifier.Value, ",")
			for _, rawCpe := range rawCpes {
				c, err := cpe.New(rawCpe, "")
				if err != nil {
					log.Debugf("unable to decode cpe %s in purl %s: %w", rawCpe, p.PURL, err)
				}
				cpes = append(cpes, c)
			}
		case pkg.PURLQualifierEpoch:
			epoch = qualifier.Value
		}
	}

	if p.Type == "" {
		setTypeFromPurl(p)
	}
	if p.Language == "" {
		setLanguageFromPurl(p)
	}
	if p.Name == "" {
		setNameFromPurl(p, purl)
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

func setTypeFromPurl(p *pkg.Package) {
	if p.Type == "" {
		p.Type = pkg.TypeFromPURL(p.PURL)
	}
}

func setLanguageFromPurl(p *pkg.Package) {
	if p.Language == "" {
		p.Language = pkg.LanguageFromPURL(p.PURL)
	}
}

func setJavaMetadataFromPurl(p *pkg.Package, purl packageurl.PackageURL) {
	if p.Type != pkg.JavaPkg {
		return
	}
	if purl.Namespace != "" {
		javaMetadata := &pkg.JavaArchive{}
		if p.Metadata != nil {
			javaMetadata, _ = p.Metadata.(*pkg.JavaArchive)
		} else {
			p.Metadata = javaMetadata
		}
		if javaMetadata != nil {
			props := javaMetadata.PomProperties
			if props == nil {
				props = &pkg.JavaPomProperties{}
				javaMetadata.PomProperties = props
			}
			// capture the group id from the purl if it is not already set
			if props.ArtifactID == "" {
				props.ArtifactID = purl.Name
			}
			if props.GroupID == "" {
				props.GroupID = purl.Namespace
			}
			if props.Version == "" {
				props.Version = purl.Version
			}
		}
	}
}

func setVersionFromPurl(p *pkg.Package, purl packageurl.PackageURL, epoch string) {
	if p.Version == "" {
		p.Version = purl.Version
	}

	if epoch != "" {
		if p.Type == pkg.RpmPkg && !strings.HasPrefix(p.Version, fmt.Sprintf("%s:", epoch)) {
			p.Version = fmt.Sprintf("%s:%s", epoch, p.Version)
		}
	}
}

func setNameFromPurl(p *pkg.Package, purl packageurl.PackageURL) {
	if p.Name == "" {
		switch {
		// Java packages
		case p.Type != pkg.JavaPkg && purl.Namespace != "":
			p.Name = fmt.Sprintf("%s/%s", purl.Namespace, purl.Name)
		default:
			p.Name = purl.Name
		}
	}
}
