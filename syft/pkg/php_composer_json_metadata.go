package pkg

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

var _ urlIdentifier = (*PhpComposerJSONMetadata)(nil)

// PhpComposerJSONMetadata represents information found from composer v1/v2 "installed.json" files as well as composer.lock files
type PhpComposerJSONMetadata struct {
	Name            string                       `json:"name"`
	Version         string                       `json:"version"`
	Source          PhpComposerExternalReference `json:"source"`
	Dist            PhpComposerExternalReference `json:"dist"`
	Require         map[string]string            `json:"require,omitempty"`
	Provide         map[string]string            `json:"provide,omitempty"`
	RequireDev      map[string]string            `json:"require-dev,omitempty"`
	Suggest         map[string]string            `json:"suggest,omitempty"`
	Type            string                       `json:"type,omitempty"`
	NotificationURL string                       `json:"notification-url,omitempty"`
	Bin             []string                     `json:"bin,omitempty"`
	License         []string                     `json:"license,omitempty"`
	Authors         []PhpComposerAuthors         `json:"authors,omitempty"`
	Description     string                       `json:"description,omitempty"`
	Homepage        string                       `json:"homepage,omitempty"`
	Keywords        []string                     `json:"keywords,omitempty"`
	Time            string                       `json:"time,omitempty"`
}

type PhpComposerExternalReference struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
	Shasum    string `json:"shasum,omitempty"`
}

type PhpComposerAuthors struct {
	Name     string `json:"name"`
	Email    string `json:"email,omitempty"`
	Homepage string `json:"homepage,omitempty"`
}

func (m PhpComposerJSONMetadata) PackageURL(_ *linux.Release) string {
	var name, vendor string
	fields := strings.Split(m.Name, "/")
	switch len(fields) {
	case 0:
		return ""
	case 1:
		name = m.Name
	case 2:
		vendor = fields[0]
		name = fields[1]
	default:
		vendor = fields[0]
		name = strings.Join(fields[1:], "-")
	}

	pURL := packageurl.NewPackageURL(
		packageurl.TypeComposer,
		vendor,
		name,
		m.Version,
		nil,
		"")
	return pURL.ToString()
}
