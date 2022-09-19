package pkg

import (
	"regexp"
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

const (
	PURLQualifierArch   = "arch"
	PURLQualifierDistro = "distro"
	PURLQualifierEpoch  = "epoch"
	PURLQualifierVCSURL = "vcs_url"

	// PURLQualifierUpstream this qualifier is not in the pURL spec, but is used by grype to perform indirect matching based on source information
	PURLQualifierUpstream = "upstream"

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
		purlType = packageurl.TypeGeneric
	case p.Type == GoModulePkg:
		re := regexp.MustCompile(`(/)[^/]*$`)
		fields := re.Split(p.Name, -1)
		if len(fields) > 1 {
			namespace = fields[0]
			name = strings.TrimPrefix(p.Name, namespace+"/")
		}
	case p.Type == NpmPkg:
		fields := strings.SplitN(p.Name, "/", 2)
		if len(fields) > 1 {
			namespace = fields[0]
			name = fields[1]
		}
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

	distroQualifiers := []string{}

	if release == nil {
		return q
	}

	if release.OSID != "" {
		distroQualifiers = append(distroQualifiers, release.OSID)
	}

	if release.VersionID != "" {
		distroQualifiers = append(distroQualifiers, release.VersionID)
	} else if release.BuildID != "" {
		distroQualifiers = append(distroQualifiers, release.BuildID)
	}

	q = append(q, packageurl.Qualifier{
		Key:   PURLQualifierDistro,
		Value: strings.Join(distroQualifiers, "-"),
	})

	return q
}
