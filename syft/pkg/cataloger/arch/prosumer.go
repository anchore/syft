package arch

import (
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var _ dependency.Prosumer = (*alpmDBEntryProsumer)(nil)

type alpmDBEntryProsumer struct{}

func newDBProsumer() alpmDBEntryProsumer {
	return alpmDBEntryProsumer{}
}

func (ps alpmDBEntryProsumer) Provides(p pkg.Package) []string {
	meta, ok := p.Metadata.(pkg.AlpmDBEntry)
	if !ok {
		log.Warnf("cataloger failed to extract alpm 'provides' metadata for package %+v", p.Name)
		return nil
	}
	keys := []string{p.Name}
	for _, provides := range meta.Provides {
		keys = append(keys, provides, stripVersionSpecifier(provides))
	}
	return keys
}

func (ps alpmDBEntryProsumer) Requires(p pkg.Package) []string {
	meta, ok := p.Metadata.(pkg.AlpmDBEntry)
	if !ok {
		log.Warnf("cataloger failed to extract alpm 'requires' metadata for package %+v", p.Name)
		return nil
	}

	return meta.Depends
}

func stripVersionSpecifier(s string) string {
	// examples:
	// gcc-libs                  -->  gcc-libs
	// libtree-sitter.so=0-64    -->  libtree-sitter.so

	items := strings.Split(s, "=")
	if len(items) == 0 {
		return s
	}

	return strings.TrimSpace(items[0])
}
