package nix

import (
	"path"
	"sort"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type nixStorePackage struct {
	Location *file.Location
	Files    []string
	*derivationFile
	nixStorePath
}

func newNixStorePackage(pp nixStorePackage, catalogerName string) pkg.Package {
	locations := file.NewLocationSet(pp.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	var derivationPath string
	if pp.derivationFile != nil {
		derivationPath = pp.derivationFile.Location.RealPath
		locations.Add(pp.derivationFile.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
	}

	p := pkg.Package{
		Name:      pp.Name,
		Version:   pp.Version,
		FoundBy:   catalogerName,
		Locations: locations,
		Type:      pkg.NixPkg,
		PURL:      packageURL(pp.nixStorePath, derivationPath),
		Metadata: pkg.NixStoreEntry{
			Path:       pp.StorePath,
			Derivation: newDerivation(pp.derivationFile),
			OutputHash: pp.OutputHash,
			Output:     pp.Output,
			Files:      pp.Files,
		},
	}

	p.SetID()

	return p
}

func newDBPackage(entry *dbPackageEntry, catalogerName string) pkg.Package {
	locations := file.NewLocationSet(
		entry.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		file.NewLocation(entry.StorePath).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation),
	)
	if entry.derivationFile != nil {
		locations.Add(entry.derivationFile.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
	}

	p := pkg.Package{
		Name:      entry.Name,
		Version:   entry.Version,
		FoundBy:   catalogerName,
		Locations: locations,
		Type:      pkg.NixPkg,
		PURL:      packageURL(entry.nixStorePath, entry.DeriverPath),
		Metadata: pkg.NixStoreEntry{
			Path:       entry.StorePath,
			Derivation: newDerivation(entry.derivationFile),
			OutputHash: entry.OutputHash,
			Output:     entry.Output,
			Files:      entry.Files,
		},
	}

	p.SetID()

	return p
}

func newDerivation(df *derivationFile) pkg.NixDerivation {
	if df == nil {
		return pkg.NixDerivation{}
	}

	var inputDerivations []pkg.NixDerivationReference
	for drvPath, names := range df.InputDerivations {
		sort.Strings(names)
		inputDerivations = append(inputDerivations, pkg.NixDerivationReference{
			Path:    drvPath,
			Outputs: names,
		})
	}
	sort.Slice(inputDerivations, func(i, j int) bool {
		return inputDerivations[i].Path < inputDerivations[j].Path
	})

	sources := df.InputSources
	sort.Strings(sources)

	return pkg.NixDerivation{
		Path:             df.Location.RealPath,
		System:           df.Platform,
		InputDerivations: inputDerivations,
		InputSources:     sources,
	}
}

func packageURL(storePath nixStorePath, drvPath string) string {
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
		qualifiers = append(qualifiers,
			packageurl.Qualifier{
				Key:   "outputhash",
				Value: storePath.OutputHash,
			},
		)
	}

	if drvPath != "" {
		qualifiers = append(qualifiers,
			packageurl.Qualifier{
				Key:   "drvpath",
				Value: path.Base(drvPath),
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
