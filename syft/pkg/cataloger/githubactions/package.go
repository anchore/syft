package githubactions

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newGithubActionPackageUsage(name, version string, workflowLocation file.Location) *pkg.Package {
	p := &pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(workflowLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      packageURL(name, version),
		Type:      pkg.GithubActionPkg,
	}

	p.SetID()

	return p
}

func packageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers
	var subPath string
	var namespace string

	fields := strings.SplitN(name, "/", 3)
	switch len(fields) {
	case 1:
		return ""
	case 2:
		namespace = fields[0]
		name = fields[1]
	case 3:
		namespace = fields[0]
		name = fields[1]
		subPath = fields[2]
	}
	if namespace == "." {
		// this is a local composite action, which is unclear how to represent in a PURL without more information
		return ""
	}

	// there isn't a github actions PURL but there is a github PURL type for referencing github repos, which is the
	// next best thing until there is a supported type.
	return packageurl.NewPackageURL(
		packageurl.TypeGithub,
		namespace,
		name,
		version,
		qualifiers,
		subPath,
	).ToString()
}
