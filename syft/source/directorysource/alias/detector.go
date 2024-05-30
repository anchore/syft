package alias

import "github.com/anchore/syft/syft/source"

// Identifier is used by certain sources (directory, file) to attempt to identify the name and version of a scan target
type Identifier func(src source.Source) *source.Alias

func DefaultIdentifiers() []Identifier {
	return []Identifier{
		NPMPackageAliasIdentifier,
		MavenProjectDirIdentifier,
	}
}
