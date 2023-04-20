package nix

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newNixStorePackage(storePath nixStorePath, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:         storePath.name,
		Version:      storePath.version,
		FoundBy:      catalogerName,
		Locations:    file.NewLocationSet(locations...),
		Type:         pkg.NixPkg,
		PURL:         packageURL(storePath),
		MetadataType: pkg.NixStoreMetadataType,
		Metadata: pkg.NixStoreMetadata{
			OutputHash: storePath.outputHash,
			Output:     storePath.output,
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
	if storePath.outputHash != "" {
		// it's not immediately clear if the hash found in the store path should be encoded in the pURL
		qualifiers = append(qualifiers,
			packageurl.Qualifier{
				Key:   "outputhash",
				Value: storePath.outputHash,
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
