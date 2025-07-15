package pkg

import (
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

const (
	PURLQualifierArch   = "arch"
	PURLQualifierCPES   = "cpes"
	PURLQualifierDistro = "distro"
	PURLQualifierEpoch  = "epoch"
	PURLQualifierVCSURL = "vcs_url"

	// PURLQualifierUpstream this qualifier is not in the pURL spec, but is used by grype to perform indirect matching based on source information
	PURLQualifierUpstream = "upstream"

	purlCargoPkgType  = "cargo"
	purlGradlePkgType = "gradle"
)

func PURLQualifiers(vars map[string]string, release *linux.Release) (q packageurl.Qualifiers) {
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

	var distroQualifiers []string

	if release == nil {
		return q
	}

	if release.ID != "" {
		distroQualifiers = append(distroQualifiers, release.ID)
	}

	if release.VersionID != "" {
		distroQualifiers = append(distroQualifiers, release.VersionID)
	} else if release.BuildID != "" {
		distroQualifiers = append(distroQualifiers, release.BuildID)
	}

	if len(distroQualifiers) > 0 {
		q = append(q, packageurl.Qualifier{
			Key:   PURLQualifierDistro,
			Value: strings.Join(distroQualifiers, "-"),
		})
	}

	return q
}
