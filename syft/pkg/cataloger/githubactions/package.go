package githubactions

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackageFromUsageStatement(use string, location file.Location) *pkg.Package {
	name, version := parseStepUsageStatement(use)

	if name == "" {
		log.WithFields("file", location.RealPath, "statement", use).Trace("unable to parse github action usage statement")
		return nil
	}

	if strings.Contains(name, ".github/workflows/") {
		return newGithubActionWorkflowPackageUsage(name, version, location)
	}

	return newGithubActionPackageUsage(name, version, location)
}

func newGithubActionWorkflowPackageUsage(name, version string, workflowLocation file.Location) *pkg.Package {
	p := &pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(workflowLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      packageURL(name, version),
		Type:      pkg.GithubActionWorkflowPkg,
	}

	p.SetID()

	return p
}

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

func parseStepUsageStatement(use string) (string, string) {
	// from octo-org/another-repo/.github/workflows/workflow.yml@v1 get octo-org/another-repo/.github/workflows/workflow.yml and v1
	// from ./.github/workflows/workflow-2.yml interpret as only the name

	// from actions/cache@v3 get actions/cache and v3

	fields := strings.Split(use, "@")
	switch len(fields) {
	case 1:
		return use, ""
	case 2:
		return fields[0], fields[1]
	}
	return "", ""
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
