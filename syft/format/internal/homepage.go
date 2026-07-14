package internal

import "github.com/anchore/syft/syft/pkg"

// Homepage returns the upstream project homepage for the ecosystems that expose a single dedicated
// homepage/URL field. It is the shared source of truth behind the SPDX PackageHomePage encoder and the
// CycloneDX "website" external-reference encoder, so the two stay in lockstep as ecosystems are added.
//
// Ecosystems that a specific format special-cases are intentionally absent here: CycloneDX maps ruby and
// npm to their own website/distribution references, and the SPDX encoder layers those two on top of this
// set. Add an ecosystem here only when both formats should treat its URL as a plain homepage.
func Homepage(p pkg.Package) string {
	switch metadata := p.Metadata.(type) {
	case pkg.RpmDBEntry:
		return metadata.URL
	case pkg.RpmArchive:
		return metadata.URL
	case pkg.AlpmDBEntry:
		return metadata.URL
	case pkg.ApkDBEntry:
		return metadata.URL
	case pkg.DpkgDBEntry:
		return metadata.Homepage
	case pkg.DpkgArchiveEntry:
		return metadata.Homepage
	case pkg.PythonPackage:
		return metadata.Homepage
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
