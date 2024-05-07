package debian

import (
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var _ dependency.Prosumer = (*dpkgDBEntryProsumer)(nil)

type dpkgDBEntryProsumer struct{}

func newDBProsumer() dpkgDBEntryProsumer {
	return dpkgDBEntryProsumer{}
}

func (ps dpkgDBEntryProsumer) Provides(p pkg.Package) []string {
	meta, ok := p.Metadata.(pkg.DpkgDBEntry)
	if !ok {
		log.Warnf("cataloger failed to extract dpkg 'provides' metadata for package %+v", p.Name)
		return nil
	}
	keys := []string{p.Name}
	for _, provides := range meta.Provides {
		keys = append(keys, stripVersionSpecifier(provides))
	}
	return keys
}

func (ps dpkgDBEntryProsumer) Requires(p pkg.Package) []string {
	meta, ok := p.Metadata.(pkg.DpkgDBEntry)
	if !ok {
		log.Warnf("cataloger failed to extract dpkg 'requires' metadata for package %+v", p.Name)
		return nil
	}

	var allDeps []string
	allDeps = append(allDeps, meta.Depends...)
	allDeps = append(allDeps, meta.PreDepends...)

	var keys []string
	for _, depSpecifier := range allDeps {
		keys = append(keys, splitPackageChoice(depSpecifier)...)
	}
	return keys
}

func stripVersionSpecifier(s string) string {
	// examples:
	// libgmp10 (>= 2:6.2.1+dfsg1)         -->  libgmp10
	// libgmp10                            -->  libgmp10
	// foo [i386]                          -->  foo
	// default-mta | mail-transport-agent  -->  default-mta | mail-transport-agent
	// kernel-headers-2.2.10 [!hurd-i386]  -->  kernel-headers-2.2.10

	items := internal.SplitAny(s, "[(<>=")
	if len(items) == 0 {
		return s
	}

	return strings.TrimSpace(items[0])
}

func splitPackageChoice(s string) (ret []string) {
	fields := strings.Split(s, "|")
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			ret = append(ret, stripVersionSpecifier(field))
		}
	}
	return ret
}
