package nix

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newNixStorePackage(storePath nixStorePath, locations ...source.Location) pkg.Package {
	p := pkg.Package{
		Name:         storePath.name,
		Version:      storePath.version,
		FoundBy:      catalogerName,
		Locations:    source.NewLocationSet(locations...),
		Type:         pkg.NixStorePkg,
		PURL:         packageURL(storePath),
		MetadataType: pkg.NixStoreMetadataType,
		Metadata: pkg.NixStoreMetadata{
			Hash:   storePath.hash,
			Output: storePath.output,
		},
	}

	p.SetID()

	return p
}

func packageURL(storePath nixStorePath) string {
	var qualifiers packageurl.Qualifiers
	if storePath.output != "" {
		// since there is no nix pURL type yet, this is a guess, however, it is reasonable to assume that
		// if only a single output is installed the pURL should be able to express this.
		qualifiers = append(qualifiers,
			packageurl.Qualifier{
				Key:   "output",
				Value: storePath.output,
			},
		)
	}
	if storePath.hash != "" {
		// it's not immediately clear if the hash found in the store path should be encoded in the pURL
		qualifiers = append(qualifiers,
			packageurl.Qualifier{
				Key:   "hash",
				Value: storePath.hash,
			},
		)
	}
	pURL := packageurl.NewPackageURL(
		// TODO: nix pURL type has not been accepted yet (only proposed at this time)
		"nix",
		"",
		storePath.name,
		storePath.version,
		qualifiers,
		"")
	return pURL.ToString()
}
