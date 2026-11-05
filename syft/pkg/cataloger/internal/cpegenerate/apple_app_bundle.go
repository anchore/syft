package cpegenerate

import (
	"regexp"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

// appleAppBundleCPE associates the bundle identifier of a well-known Apple application bundle
// with the vendor and product recorded for that application in the NVD CPE dictionary.
//
// The bundle identifier (a stable reverse-DNS key, e.g. "com.google.Chrome") is used instead of
// the user-facing display name: display names drift across localizations and marketing changes,
// and CPEs built from them essentially never match an NVD record (and sometimes match the wrong
// one, e.g. Docker Desktop matching Docker Engine CVEs). This follows the same approach as
// curated CPE translation tables used by other vulnerability scanners (e.g. Fleet's
// cpe_translations.json for osquery app inventory).
type appleAppBundleCPE struct {
	vendor  string
	product string
}

// knownAppBundleCPEs is intentionally small: it only records vendor/product pairs that were
// verified against the NVD dictionary. Applications that are not listed here get no CPE at all
// rather than a guessed one (a guessed CPE can only contribute false positives and negatives).
var knownAppBundleCPEs = map[string]appleAppBundleCPE{
	// Google Chrome: NVD records the desktop application as google:chrome
	"com.google.Chrome": {vendor: "google", product: "chrome"},
	// Docker Desktop: NVD records docker:desktop; the display name "Docker" instead matches
	// 2018-2019 Docker Engine and runc CVEs (e.g. CVE-2018-10892, CVE-2019-13139)
	"com.docker.docker": {vendor: "docker", product: "desktop"},
	// Zoom: NVD records zoom:zoom
	"us.zoom.xos": {vendor: "zoom", product: "zoom"},
}

// appBundleBuildSuffix matches a trailing parenthesized build number on a marketing version,
// e.g. the " (88465)" of "7.2.2 (88465)". Only the CPE version is cleaned; the package keeps the
// full CFBundleShortVersionString value.
var appBundleBuildSuffix = regexp.MustCompile(`[[:space:]]*\([^()]*\)$`)

// appBundleCPESet generates the CPEs for an Apple application bundle package. Only applications
// with a known bundle identifier mapping get a CPE; all others intentionally get none since the
// display name is not a valid source for a CPE.
func appBundleCPESet(p pkg.Package) []cpe.CPE {
	metadata, ok := p.Metadata.(pkg.AppleAppBundleEntry)
	if !ok {
		return nil
	}

	mapped, ok := knownAppBundleCPEs[metadata.BundleIdentifier]
	if !ok {
		return nil
	}

	version := appBundleBuildSuffix.ReplaceAllString(p.Version, "")
	if version == "" {
		return nil
	}

	c := newCPE(mapped.product, mapped.vendor, version, cpe.Any)
	if c == nil {
		return nil
	}

	return []cpe.CPE{{Attributes: *c, Source: cpe.GeneratedSource}}
}
