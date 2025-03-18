package gitlab

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	catalogerName       = "gitlab-cataloger"
	versionManifestGlob = "**/opt/gitlab/version-manifest.json"
)

func NewGitLabCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseVersionManifest, versionManifestGlob)
}
