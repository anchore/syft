package electron

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "electron-cataloger"

// NewCataloger returns a cataloger for packaged Electron apps.
func NewCataloger() pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseAsarArchive,
			"**/app.asar",
			"**/Contents/Resources/app.asar",              // macOS
			"**/Contents/Resources/electron.asar",         // macOS alt
			"**/Contents/Resources/app/node_modules.asar", // macOS VS Code style
			"**/resources/app.asar",                       // Linux/Win
			"**/resources/electron.asar",                  // Linux/Win alt
			"**/resources/app/node_modules.asar",          // Linux/Win VS Code style
		).
		WithParserByGlobs(parsePackageJSON,
			"**/Contents/Resources/app/node_modules/*/package.json",     // macOS
			"**/Contents/Resources/app/node_modules/*/*/package.json",   // macOS scoped
			"**/Contents/Resources/app/node_modules/*/*/*/package.json", // macOS nested
			"**/resources/app/node_modules/*/package.json",              // Linux/Win
			"**/resources/app/node_modules/*/*/package.json",            // Linux/Win scoped
			"**/resources/app/node_modules/*/*/*/package.json",          // Linux/Win nested
		)
}
