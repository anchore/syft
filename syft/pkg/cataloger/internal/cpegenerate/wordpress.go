package cpegenerate

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
)

var (
	vendorFromURLRegexp = regexp.MustCompile(`^https?://(www.)?(?P<vendor>.+)\.\w/?`)
)

func candidateVendorsForWordpressPlugin(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.WordpressPluginEntry)
	if !ok {
		return nil
	}

	vendors := newFieldCandidateSet()

	if metadata.Author != "" {
		vendors.addValue(strings.ToLower(metadata.Author))
	}

	if metadata.AuthorURI != "" {
		matchMap := internal.MatchNamedCaptureGroups(vendorFromURLRegexp, metadata.AuthorURI)
		if vendor, ok := matchMap["vendor"]; ok && vendor != "" {
			vendors.addValue(strings.ToLower(vendor))
		}
	}

	if len(vendors) == 0 {
		// add plugin_name + _project as a vendor if no Author URI found
		vendors.addValue(fmt.Sprintf("%s_project", normalizeWordpressPluginName(p.Name)))
	}

	return vendors
}

func candidateProductsForWordpressPlugin(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.WordpressPluginEntry)
	if !ok {
		return nil
	}
	products := newFieldCandidateSet()

	products.addValue(normalizeWordpressPluginName(p.Name))
	products.addValue(normalizeWordpressPluginName(metadata.PluginInstallDirectory))

	return products
}

func normalizeWordpressPluginName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	for _, value := range []string{" "} {
		name = strings.ReplaceAll(name, value, "_")
	}
	return name
}
