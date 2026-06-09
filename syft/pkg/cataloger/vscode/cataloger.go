/*
Package vscode provides a Cataloger for installed Visual Studio Code extensions,
sourced from the user-extensions registry file at .vscode/extensions/extensions.json.
*/
package vscode

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	catalogerName    = "vscode-extensions-cataloger"
	extensionsGlob   = "**/.vscode/extensions/extensions.json"
	extensionsServerGlob = "**/.vscode-server/extensions/extensions.json"
)

// NewExtensionsCataloger returns a Cataloger that finds VSCode extensions
// installed in user profiles. It also matches the .vscode-server registry
// path used by remote/SSH/Codespaces installs since the JSON shape is
// identical there.
func NewExtensionsCataloger() pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseExtensionsJSON, extensionsGlob, extensionsServerGlob)
}
