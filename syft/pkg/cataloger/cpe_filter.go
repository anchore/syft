package cataloger

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/facebookincubator/nvdtools/wfn"
)

const jenkinsName = "jenkins"

type filterFn func(cpe pkg.CPE, p pkg.Package) bool

var cpeFilters = []filterFn{
	jiraClientPackageFilter,
	jenkinsPackageNameFilter,
	jenkinsPluginFilter,
}

// jenkins plugins should not match against jenkins
func jenkinsPluginFilter(cpe pkg.CPE, p pkg.Package) bool {
	if p.Type == pkg.JenkinsPluginPkg && cpe.Product == jenkinsName {
		return true
	}
	return false
}

// filter to account that packages that are not for jenkins but have a CPE generated that will match against jenkins
func jenkinsPackageNameFilter(cpe pkg.CPE, p pkg.Package) bool {
	// jenkins server should only match against a product with the name jenkins
	if cpe.Product == jenkinsName && !strings.Contains(strings.ToLower(p.Name), jenkinsName) {
		if cpe.Vendor == wfn.Any || cpe.Vendor == jenkinsName || cpe.Vendor == "cloudbees" {
			return true
		}
	}
	return false
}

// filter to account for packages which are jira client packages but have a CPE that will match against jira
func jiraClientPackageFilter(cpe pkg.CPE, p pkg.Package) bool {
	// jira / atlassian should not apply to clients
	if cpe.Product == "jira" && strings.Contains(strings.ToLower(p.Name), "client") {
		if cpe.Vendor == wfn.Any || cpe.Vendor == "jira" || cpe.Vendor == "atlassian" {
			return true
		}
	}
	return false
}
