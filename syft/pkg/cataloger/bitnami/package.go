package bitnami

import (
	"fmt"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"

	version "github.com/bitnami/go-version/pkg/version"
)

func parseBitnamiPURL(p string) (*pkg.BitnamiEntry, error) {
	purl, err := packageurl.FromString(p)
	if err != nil {
		return nil, err
	}

	v, err := version.Parse(purl.Version)
	if err != nil {
		return nil, err
	}

	entry := pkg.BitnamiEntry{
		Name:     purl.Name,
		Version:  strings.TrimSuffix(v.String(), fmt.Sprintf("-%s", v.Revision().String())),
		Revision: v.Revision().String(),
	}

	for _, q := range purl.Qualifiers {
		switch q.Key {
		case "arch":
			entry.Architecture = q.Value
		case "distro":
			entry.Distro = q.Value
		}
	}

	return &entry, nil
}
