package pkg

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

type DartPubMetadata struct {
	Name      string `mapstructure:"name" json:"name"`
	Version   string `mapstructure:"version" json:"version"`
	HostedURL string `mapstructure:"hosted_url" json:"hosted_url,omitempty"`
	VcsURL    string `mapstructure:"vcs_url" json:"vcs_url,omitempty"`
}

func (m DartPubMetadata) PackageURL(_ *linux.Release) string {
	var qualifiers packageurl.Qualifiers

	if m.HostedURL != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "hosted_url",
			Value: m.HostedURL,
		})
	} else if m.VcsURL != "" { // Default to using Hosted if somehow both are provided
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "vcs_url",
			Value: m.VcsURL,
		})
	}

	return packageurl.NewPackageURL(
		packageurl.TypePub,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
