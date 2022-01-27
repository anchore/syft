package pkg

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

const (
	purlArchQualifier   = "arch"
	purlDistroQualifier = "distro"
	purlEpochQualifier  = "epoch"
	purlVCSURLQualifier = "vcs_url"

	// this qualifier is not in the pURL spec, but is used by grype to perform indirect matching based on source information
	purlUpstreamQualifier = "upstream"

	purlCargoPkgType  = "cargo"
	purlGradlePkgType = "gradle"
)

type urlIdentifier interface {
	PackageURL(*linux.Release) string
}

func URL(p Package, release *linux.Release) string {
	if p.Metadata != nil {
		if i, ok := p.Metadata.(urlIdentifier); ok {
			return i.PackageURL(release)
		}
	}

	// the remaining cases are primarily reserved for packages without metadata struct instances

	var purlType = p.Type.PackageURLType()
	var name = p.Name
	var namespace = ""

	switch {
	case purlType == "":
		// there is no purl type, don't attempt to craft a purl
		// TODO: should this be a "generic" purl type instead?
		return ""
	case p.Type == GoModulePkg:
		re := regexp.MustCompile(`(/)[^/]*$`)
		fields := re.Split(p.Name, -1)
		namespace = fields[0]
		name = strings.TrimPrefix(p.Name, namespace+"/")
	}

	// generate a purl from the package data
	return packageurl.NewPackageURL(
		purlType,
		namespace,
		name,
		p.Version,
		nil,
		"",
	).ToString()
}

func purlQualifiers(vars map[string]string, release *linux.Release) (q packageurl.Qualifiers) {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		val := vars[k]
		if val == "" {
			continue
		}
		q = append(q, packageurl.Qualifier{
			Key:   k,
			Value: vars[k],
		})
	}

	if release != nil && release.ID != "" && release.VersionID != "" {
		q = append(q, packageurl.Qualifier{
			Key:   purlDistroQualifier,
			Value: fmt.Sprintf("%s-%s", release.ID, release.VersionID),
		})
	}

	return q
}
