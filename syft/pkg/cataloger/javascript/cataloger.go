/*
Package javascript provides a concrete Cataloger implementation for JavaScript ecosystem files (yarn and npm).
*/
package javascript

import (
	"encoding/json"
	"io"
	"path"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/anchore/syft/syft/source"
)

// NewJavascriptPackageCataloger returns a new JavaScript cataloger object based on detection of npm based packages.
func NewJavascriptPackageCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/package.json": parsePackageJSON,
	}

	return common.NewGenericCataloger(nil, globParsers, "javascript-package-cataloger")
}

// NewJavascriptLockCataloger returns a new Javascript cataloger object base on package lock files.
func NewJavascriptLockCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/package-lock.json": parsePackageLock,
		"**/yarn.lock":         parseYarnLock,
	}

	return common.NewGenericCataloger(nil, globParsers, "javascript-lock-cataloger", addLicenses)
}

func addLicenses(resolver source.FileResolver, location source.Location, p *pkg.Package) error {
	dir := path.Dir(location.RealPath)
	pkgPath := []string{dir, "node_modules"}
	pkgPath = append(pkgPath, strings.Split(p.Name, "/")...)
	pkgPath = append(pkgPath, "package.json")
	pkgFile := path.Join(pkgPath...)
	locations, err := resolver.FilesByPath(pkgFile)
	if err != nil {
		log.Debugf("an error occurred attempting to read: %s - %+v", pkgFile, err)
		return nil
	}

	if len(locations) == 0 {
		return nil
	}

	for _, location := range locations {
		contentReader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			log.Debugf("error getting file content reader for %s: %v", pkgFile, err)
			return nil
		}

		contents, err := io.ReadAll(contentReader)
		if err != nil {
			log.Debugf("error reading file contents for %s: %v", pkgFile, err)
			return nil
		}

		var pkgJSON packageJSON
		err = json.Unmarshal(contents, &pkgJSON)
		if err != nil {
			log.Debugf("error parsing %s: %v", pkgFile, err)
			return nil
		}

		licenses, err := pkgJSON.licensesFromJSON()
		if err != nil {
			log.Debugf("error getting licenses from %s: %v", pkgFile, err)
			return nil
		}

		p.Licenses = append(p.Licenses, licenses...)
	}

	return nil
}
