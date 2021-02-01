package cpe

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/facebookincubator/nvdtools/wfn"
)

// this is functionally equivalent to "*" and consistent with no input given (thus easier to test)
const any = ""

func newCPE(product, vendor, version, update, targetSW string) wfn.Attributes {
	item := *(wfn.NewAttributesWithAny())
	item.Part = "a"
	item.Product = product
	item.Vendor = vendor
	item.Update = update
	item.Version = version
	item.TargetSW = targetSW

	return item
}

func candidateTargetSoftwareAttrs(p pkg.Package) []string {
	// TODO: would be great to allow these to be overridden by user data/config
	var targetSw []string
	switch p.Language {
	case pkg.Java:
		if p.Type == pkg.JenkinsPluginPkg {
			targetSw = append(targetSw, "jenkins", "cloudbees_jenkins")
		} else {
			if strings.HasSuffix(p.Name, "-maven-plugin") {
				targetSw = append(targetSw, "maven")
			} else {
				targetSw = append(targetSw, "java")
			}
		}
	case pkg.JavaScript:
		targetSw = append(targetSw, "node.js", "nodejs")
	case pkg.Ruby:
		targetSw = append(targetSw, "ruby", "rails")
	case pkg.Python:
		targetSw = append(targetSw, "python")
	}
	return targetSw
}

func extractVersionAndUpdate(p pkg.Package) (string, string) {
	versionParts := strings.Split(p.Version, "-")
	version := endingCharacterRegexp.ReplaceAllString(versionParts[0], "")
	var update string
	if len(versionParts) >= 2 {
		update = versionParts[1]
	}
	return strings.TrimSuffix(version, "."), update
}
