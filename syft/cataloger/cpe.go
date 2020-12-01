package cataloger

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/facebookincubator/nvdtools/wfn"
)

// this is functionally equivalent to "*" and consistent with no input given (thus easier to test)
const any = ""

// generatePackageCPEs Create a list of CPEs, trying to guess the vendor, product tuple and setting TargetSoftware if possible
func generatePackageCPEs(p pkg.Package) []pkg.CPE {
	targetSws := candidateTargetSoftwareAttrs(p)
	vendors := candidateVendors(p)
	products := candidateProducts(p)

	keys := internal.NewStringSet()
	cpes := make([]pkg.CPE, 0)
	for _, product := range products {
		for _, vendor := range append([]string{any}, vendors...) {
			for _, targetSw := range append([]string{any}, targetSws...) {
				// prevent duplicate entries...
				key := fmt.Sprintf("%s|%s|%s|%s", product, vendor, p.Version, targetSw)
				if keys.Contains(key) {
					continue
				}
				keys.Add(key)

				// add a new entry...
				candidateCpe := wfn.NewAttributesWithAny()
				candidateCpe.Part = "a"
				candidateCpe.Product = product
				candidateCpe.Vendor = vendor
				candidateCpe.Version = p.Version
				candidateCpe.TargetSW = targetSw

				cpes = append(cpes, *candidateCpe)
			}
		}
	}

	return cpes
}

func candidateTargetSoftwareAttrs(p pkg.Package) []string {
	// TODO: would be great to allow these to be overridden by user data/config
	var targetSw []string
	switch p.Language {
	case pkg.Java:
		targetSw = append(targetSw, "java", "maven")
	case pkg.JavaScript:
		targetSw = append(targetSw, "node.js", "nodejs")
	case pkg.Ruby:
		targetSw = append(targetSw, "ruby", "rails")
	case pkg.Python:
		targetSw = append(targetSw, "python")
	}

	if p.Type == pkg.JenkinsPluginPkg {
		targetSw = append(targetSw, "jenkins", "cloudbees_jenkins")
	}

	return targetSw
}

func candidateVendors(p pkg.Package) []string {
	vendors := candidateProducts(p)
	switch p.Language {
	case pkg.Python:
		vendors = append(vendors, fmt.Sprintf("python-%s", p.Name))
	case pkg.Java:
		if p.MetadataType == pkg.JavaMetadataType {
			if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok && metadata.PomProperties != nil {
				// derive the vendor from the groupID (e.g. org.sonatype.nexus --> sonatype)
				if strings.HasPrefix(metadata.PomProperties.GroupID, "org.") || strings.HasPrefix(metadata.PomProperties.GroupID, "com.") {
					fields := strings.Split(metadata.PomProperties.GroupID, ".")
					if len(fields) >= 3 {
						vendors = append(vendors, fields[1])
					}
				}
			}
		}
	}
	return vendors
}

func candidateProducts(p pkg.Package) []string {
	var products = []string{p.Name}
	switch p.Language {
	case pkg.Java:
		if p.MetadataType == pkg.JavaMetadataType {
			if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok && metadata.PomProperties != nil {
				// derive the product from the groupID (e.g. org.sonatype.nexus --> nexus)
				if strings.HasPrefix(metadata.PomProperties.GroupID, "org.") || strings.HasPrefix(metadata.PomProperties.GroupID, "com.") {
					fields := strings.Split(metadata.PomProperties.GroupID, ".")
					if len(fields) >= 3 {
						products = append(products, fields[2])
					}
				}
			}
		}
	default:
		return products
	}
	return products
}
