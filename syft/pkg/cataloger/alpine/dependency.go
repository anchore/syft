package alpine

import (
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var _ dependency.Specifier = dbEntryDependencySpecifier

func dbEntryDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.ApkDBEntry)
	if !ok {
		log.Tracef("cataloger failed to extract apk metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	provides := []string{p.Name}
	provides = append(provides, stripVersionSpecifiers(meta.Provides)...)

	return dependency.Specification{
		Provides: provides,
		Requires: stripVersionSpecifiers(meta.Dependencies),
	}
}

func stripVersionSpecifiers(given []string) []string {
	var keys []string
	for _, key := range given {
		key = stripVersionSpecifier(key)
		if key == "" {
			continue
		}
		keys = append(keys, key)
	}
	return keys
}

func stripVersionSpecifier(s string) string {
	// examples:
	// musl>=1                 --> musl
	// cmd:scanelf=1.3.4-r0    --> cmd:scanelf

	return strings.TrimSpace(internal.SplitAny(s, "<>=")[0])
}
