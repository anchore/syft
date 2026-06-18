package helpers

import "github.com/anchore/syft/syft/pkg"

// Homepage returns the upstream project homepage for a package, derived from whatever URL/homepage
// field the package metadata provides. This populates the SPDX PackageHomePage field.
func Homepage(p pkg.Package) string {
	if !hasMetadata(p) {
		return ""
	}

	switch metadata := p.Metadata.(type) {
	case pkg.RubyGemspec:
		return metadata.Homepage
	case pkg.NpmPackage:
		return metadata.Homepage
	case pkg.RpmDBEntry:
		return metadata.URL
	case pkg.RpmArchive:
		return metadata.URL
	case pkg.AlpmDBEntry:
		return metadata.URL
	case pkg.ApkDBEntry:
		return metadata.URL
	case pkg.HomebrewFormula:
		return metadata.Homepage
	case pkg.LuaRocksPackage:
		return firstNonEmpty(metadata.Homepage, metadata.URL)
	case pkg.OpamPackage:
		return firstNonEmpty(metadata.Homepage, metadata.URL)
	case pkg.PhpComposerInstalledEntry:
		return metadata.Homepage
	case pkg.PhpComposerLockEntry:
		return metadata.Homepage
	case pkg.DartPubspec:
		return firstNonEmpty(metadata.Homepage, metadata.Repository)
	case pkg.SwiplPackEntry:
		return metadata.Homepage
	case pkg.CondaMetaPackage:
		return metadata.URL
	case pkg.RDescription:
		if len(metadata.URL) > 0 {
			return metadata.URL[0]
		}
		return metadata.Repository
	case pkg.JavaArchive:
		if metadata.PomProject != nil {
			return metadata.PomProject.URL
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
