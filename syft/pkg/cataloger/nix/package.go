package nix

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type nixStorePackage struct {
	Location *file.Location
	Files    []string
	nixStorePath
}

func newNixStorePackage(pp nixStorePackage, derivationPath string, catalogerName string) pkg.Package {
	p := pkg.Package{
		Name:      pp.Name,
		Version:   pp.Version,
		FoundBy:   catalogerName,
		Locations: file.NewLocationSet(*pp.Location),
		Type:      pkg.NixPkg,
		PURL:      packageURL(pp.nixStorePath),
		Metadata: pkg.NixStoreEntry{
			Derivation: derivationPath,
			OutputHash: pp.OutputHash,
			Output:     pp.Output,
			Files:      pp.Files,
		},
	}

	p.SetID()

	return p
}

func newDBPackage(entry *dbPackageEntry, catalogerName string) pkg.Package {
	sp := parseNixStorePath(entry.StorePath)
	var purl string
	if sp != nil {
		purl = packageURL(*sp)
	}
	p := pkg.Package{
		Name:      entry.Name,
		Version:   entry.Version,
		FoundBy:   catalogerName,
		Locations: file.NewLocationSet(*entry.Location),
		Type:      pkg.NixPkg,
		PURL:      purl,
		Metadata: pkg.NixStoreEntry{
			Derivation: entry.DeriverPath,
			OutputHash: entry.OutputHash,
			Output:     entry.Output,
			Files:      entry.Files,
		},
	}

	p.SetID()

	return p
}

func packageURL(storePath nixStorePath) string {
	var qualifiers packageurl.Qualifiers
	if storePath.Output != "" {
		// since there is no nix pURL type yet, this is a guess, however, it is reasonable to assume that
		// if only a single output is installed the pURL should be able to express this.
		qualifiers = append(qualifiers,
			packageurl.Qualifier{
				Key:   "output",
				Value: storePath.Output,
			},
		)
	}
	if storePath.OutputHash != "" {
		// it's not immediately clear if the hash found in the store path should be encoded in the pURL
		qualifiers = append(qualifiers,
			packageurl.Qualifier{
				Key:   "outputhash",
				Value: storePath.OutputHash,
			},
		)
	}
	pURL := packageurl.NewPackageURL(
		// TODO: nix pURL type has not been accepted yet (only proposed at this time)
		"nix",
		"",
		storePath.Name,
		storePath.Version,
		qualifiers,
		"")
	return pURL.ToString()
}
