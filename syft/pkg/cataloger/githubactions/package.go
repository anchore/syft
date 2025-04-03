package githubactions

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackageFromUsageStatement(use, comment string, location file.Location) (*pkg.Package, error) {
	name, version := parseStepUsageStatement(use, comment)

	if name == "" {
		log.WithFields("file", location.RealPath, "statement", use).Trace("unable to parse github action usage statement")
		return nil, fmt.Errorf("unable to parse github action usage statement")
	}

	if strings.Contains(name, ".github/workflows/") {
		return newGithubActionWorkflowPackageUsage(name, version, location, pkg.GitHubActionsUseStatement{Value: use, Comment: comment}), nil
	}

	return newGithubActionPackageUsage(name, version, location, pkg.GitHubActionsUseStatement{Value: use, Comment: comment}), nil
}

func newGithubActionWorkflowPackageUsage(name, version string, workflowLocation file.Location, m pkg.GitHubActionsUseStatement) *pkg.Package {
	p := &pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(workflowLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      packageURL(name, version),
		Type:      pkg.GithubActionWorkflowPkg,
		Metadata:  m,
	}

	p.SetID()

	return p
}

func newGithubActionPackageUsage(name, version string, workflowLocation file.Location, m pkg.GitHubActionsUseStatement) *pkg.Package {
	p := &pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(workflowLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      packageURL(name, version),
		Type:      pkg.GithubActionPkg,
		Metadata:  m,
	}

	p.SetID()

	return p
}

func parseStepUsageStatement(use, comment string) (string, string) {
	// from "octo-org/another-repo/.github/workflows/workflow.yml@v1" get octo-org/another-repo/.github/workflows/workflow.yml and v1
	// from "./.github/workflows/workflow-2.yml" interpret as only the name
	// from "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 #v4.2.2" get actions/checkout and v4.2.2
	// from "actions/cache@v3" get actions/cache and v3

	fields := strings.Split(use, "@")
	name := use
	version := ""

	if len(fields) == 2 {
		name = fields[0]
		version = fields[1]
	}

	// if version looks like a commit hash and we have a comment, try to extract version from comment
	if version != "" && regexp.MustCompile(`^[0-9a-f]{7,}$`).MatchString(version) && comment != "" {
		versionRegex := regexp.MustCompile(`v?\d+\.\d+\.\d+`)
		matches := versionRegex.FindStringSubmatch(comment)

		if len(matches) >= 1 {
			return name, matches[0]
		}
	}

	return name, version
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
