package cpegenerate

import (
	"strings"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

const jenkinsName = "jenkins"

// filterFn instances should return true if the given CPE should be removed from a collection for the given package
type filterFn func(cpe cpe.CPE, p pkg.Package) bool

var cpeFilters = []filterFn{
	disallowJiraClientServerMismatch,
	disallowJenkinsServerCPEForPluginPackage,
	disallowJenkinsCPEsNotAssociatedWithJenkins,
	disallowNonParseableCPEs,
}

func filter(cpes []cpe.CPE, p pkg.Package, filters ...filterFn) (result []cpe.CPE) {
cpeLoop:
	for _, c := range cpes {
		for _, fn := range filters {
			if fn(c, p) {
				continue cpeLoop
			}
		}
		// all filter functions passed on filtering this CPE
		result = append(result, c)
	}
	return result
}

func disallowNonParseableCPEs(c cpe.CPE, _ pkg.Package) bool {
	v := c.String()
	_, err := cpe.New(v)

	cannotParse := err != nil

	return cannotParse
}

// jenkins plugins should not match against jenkins
func disallowJenkinsServerCPEForPluginPackage(c cpe.CPE, p pkg.Package) bool {
	if p.Type == pkg.JenkinsPluginPkg && c.Product == jenkinsName {
		return true
	}
	return false
}

// filter to account that packages that are not for jenkins but have a CPE generated that will match against jenkins
func disallowJenkinsCPEsNotAssociatedWithJenkins(c cpe.CPE, p pkg.Package) bool {
	// jenkins server should only match against a product with the name jenkins
	if c.Product == jenkinsName && !strings.Contains(strings.ToLower(p.Name), jenkinsName) {
		if c.Vendor == cpe.Any || c.Vendor == jenkinsName || c.Vendor == "cloudbees" {
			return true
		}
	}
	return false
}

// filter to account for packages which are jira client packages but have a CPE that will match against jira
func disallowJiraClientServerMismatch(c cpe.CPE, p pkg.Package) bool {
	// jira / atlassian should not apply to clients
	if c.Product == "jira" && strings.Contains(strings.ToLower(p.Name), "client") {
		if c.Vendor == cpe.Any || c.Vendor == "jira" || c.Vendor == "atlassian" {
			return true
		}
	}
	return false
}
