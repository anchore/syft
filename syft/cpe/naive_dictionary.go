package cpe

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
)

type NaiveDictionary struct {
}

func (d NaiveDictionary) IdentifyPackageCPEs(p pkg.Package) []pkg.CPE {
	vendors := d.candidateVendors(p)
	products := d.candidateProducts(p)
	targetSws := candidateTargetSoftwareAttrs(p)
	version, update := extractVersionAndUpdate(p)

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
				c := newCPE(product, vendor, version, update, targetSw)
				cpes = append(cpes, c)
			}
		}
	}

	sort.Sort(ByCPESpecificity(cpes))

	return cpes
}

func (d NaiveDictionary) Close() error {
	return nil
}

func (d NaiveDictionary) candidateVendors(p pkg.Package) []string {
	vendors := d.candidateProducts(p)
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

func (d NaiveDictionary) candidateProducts(p pkg.Package) []string {
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
