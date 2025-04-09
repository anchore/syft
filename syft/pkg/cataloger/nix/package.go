package nix

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newNixStorePackage(storePath nixStorePath, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      storePath.name,
		Version:   storePath.version,
		FoundBy:   catalogerName,
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.NixPkg,
		PURL:      packageURL(storePath),
		Metadata: pkg.NixStoreEntry{
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

// deduplicateNixPackages combines information from packages with the same name and version
func deduplicateNixPackages(pkgs []pkg.Package) []pkg.Package {
	if len(pkgs) == 0 {
		return pkgs
	}

	// Use map to group by name+version
	packageMap := make(map[string]*pkg.Package)

	for i := range pkgs {
		p := &pkgs[i]
		key := p.Name + ":" + p.Version

		existing, exists := packageMap[key]
		if !exists {
			// First time seeing this name+version
			packageMap[key] = p
			continue
		}

		// Merge information from this package into the existing one
		mergePackageInfo(existing, p)
	}

	// Convert map back to slice
	result := make([]pkg.Package, 0, len(packageMap))
	for _, p := range packageMap {
		result = append(result, *p)
	}

	return result
}

// mergePackageInfo combines information from src into dest
func mergePackageInfo(dest, src *pkg.Package) {
	// Merge locations
	for _, loc := range src.Locations.ToSlice() {
		dest.Locations.Add(loc)
	}

	// Merge metadata if both have NixStoreEntry type
	destMeta, destOk := dest.Metadata.(pkg.NixStoreEntry)
	srcMeta, srcOk := src.Metadata.(pkg.NixStoreEntry)

	if destOk && srcOk {
		// Combine files lists
		destMeta.Files = append(destMeta.Files, srcMeta.Files...)

		// Prefer non-empty fields from src
		if destMeta.License == "" && srcMeta.License != "" {
			destMeta.License = srcMeta.License
		}
		if destMeta.Homepage == "" && srcMeta.Homepage != "" {
			destMeta.Homepage = srcMeta.Homepage
		}
		if destMeta.Description == "" && srcMeta.Description != "" {
			destMeta.Description = srcMeta.Description
		}

		// Update the metadata
		dest.Metadata = destMeta
	}
}
