package os

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func DetectFeatures(_ context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
	builder.(sbomsync.Accessor).WriteToSBOM(func(s *sbom.SBOM) {
		if s.Artifacts.LinuxDistribution == nil {
			return
		}

		if err := findRhelFeatures(resolver, s.Artifacts.LinuxDistribution); err != nil {
			log.WithFields("error", err, "release", s.Artifacts.LinuxDistribution).Trace("error searching for extended support")
		}

		if err := findUbuntuFeatures(resolver, s.Artifacts.LinuxDistribution, s.Artifacts.Packages); err != nil {
			log.WithFields("error", err, "release", s.Artifacts.LinuxDistribution).Trace("error searching for extended support")
		}
	})

	return nil
}

// rhelEUSPatterns match a RHEL content manifest referencing an extended-update-support (EUS) repo.
var rhelEUSPatterns = []*regexp.Regexp{regexp.MustCompile(`baseos-eus`), regexp.MustCompile(`baseos-eus|appstream-eus`)}

func findRhelFeatures(resolver file.Resolver, release *linux.Release) error {
	if release == nil || release.ID != "rhel" {
		return nil
	}
	contentManifestFiles, err := resolver.FilesByGlob("/root/buildinfo/content_manifests/*.json")
	if err != nil {
		return fmt.Errorf("unable to find content manifests: %w", err)
	}
	for _, contentManifestFile := range contentManifestFiles {
		found, err := fileMatchesAny(resolver, contentManifestFile, rhelEUSPatterns...)
		if err != nil {
			return fmt.Errorf("unable to read content manifest from %s: %w", contentManifestFile.RealPath, err)
		}
		if found {
			release.ExtendedSupport = true
			break
		}
	}
	return nil
}

// Ubuntu Pro (formerly Ubuntu Advantage) is Canonical's subscription that unlocks Expanded Security
// Maintenance (ESM): security fixes past a package's standard support window. we detect the two base ESM
// streams, esm-infra (the `main` repo) and esm-apps (`universe`), and collapse them into one ExtendedSupport
// signal; the infra-vs-apps split is disambiguated by the downstream consumer, not by this boolean.
//
// the other Pro streams on the same host (esm.ubuntu.com/fips, /fips-updates, /realtime) are deliberately
// excluded: they are separate compliance products with their own downstream channels, and a host can run
// them with base ESM disabled, so folding them in would be unsound.
//
// detection is deliberately forgiving: apt/status evidence disappears when ESM is disabled, but an installed
// +esmN package is durable proof ESM content is on disk. so ExtendedSupport means "ESM was or is in effect
// for this host or its content", not "currently entitled" (mere eligibility, without evidence, is not enough).

// esmAptSourcePattern matches an uncommented apt source (classic or DEB822) or auth entry pointing at the
// plain ESM streams esm.ubuntu.com/infra or /apps. it deliberately scopes to /(infra|apps) so the other
// Pro streams served from the same host (/fips, /fips-updates, /realtime) are never folded into the base
// esm channel. the [^#\n]* before the host ensures a leading `#` (comment) can never satisfy the match.
var esmAptSourcePattern = regexp.MustCompile(`(?m)^[^#\n]*esm\.ubuntu\.com/(infra|apps)`)

// esmVersionPattern matches a dpkg version carrying a numbered ESM pocket suffix, e.g. `...+esm1` or
// `...~esm2`. the trailing \d scopes this to the ESM pocket and excludes other Pro pockets (e.g. +fips).
var esmVersionPattern = regexp.MustCompile(`[~+]esm\d`)

func findUbuntuFeatures(resolver file.Resolver, release *linux.Release, packages *pkg.Collection) error {
	if release == nil || release.ID != "ubuntu" {
		return nil
	}

	// an uncommented esm.ubuntu.com apt source or an active pro esm service both prove Pro/ESM was enabled.
	// these are the durable, file-based signals present on attached hosts. a read error in one signal must
	// not suppress the others, so errors are collected and detection continues to the next signal.
	var errs error
	for _, check := range []func() (bool, error){
		func() (bool, error) { return hasUbuntuESMAptEvidence(resolver) },
		func() (bool, error) { return hasActiveUbuntuESMService(resolver) },
	} {
		found, err := check()
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		if found {
			release.ExtendedSupport = true
			return errs
		}
	}

	// fallback for images (typically not pro-attached): an installed package whose version carries an
	// +esm/~esm suffix was pulled from an ESM pocket, so ESM was in effect when it was installed.
	if hasInstalledESMPackage(packages) {
		release.ExtendedSupport = true
	}
	return errs
}

// hasUbuntuESMAptEvidence reports whether any apt source (classic .list or DEB822 .sources) or auth entry
// references esm.ubuntu.com via an uncommented line.
func hasUbuntuESMAptEvidence(resolver file.Resolver) (bool, error) {
	// apt source files live in a directory (classic .list or DEB822 .sources), the credentials file is a fixed path.
	sourceLocations, err := resolver.FilesByGlob("/etc/apt/sources.list.d/*")
	if err != nil {
		return false, fmt.Errorf("unable to find apt esm sources: %w", err)
	}
	authLocations, err := resolver.FilesByPath("/etc/apt/auth.conf.d/90ubuntu-advantage")
	if err != nil {
		return false, fmt.Errorf("unable to find apt esm auth: %w", err)
	}

	// ponytail: a DEB822 source with `Enabled: no` would still match; the pro client removes/comments the
	// file on disable rather than toggling that key, so this is an accepted false-positive ceiling. the
	// auth.conf.d entry is deleted by the pro client on disable, so it is a durable positive-only signal.
	for _, location := range append(sourceLocations, authLocations...) {
		match, err := fileMatchesAny(resolver, location, esmAptSourcePattern)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// hasActiveUbuntuESMService reports whether the ubuntu-advantage/pro status cache shows an enabled esm service.
func hasActiveUbuntuESMService(resolver file.Resolver) (bool, error) {
	locations, err := resolver.FilesByPath("/var/lib/ubuntu-advantage/status.json")
	if err != nil {
		return false, fmt.Errorf("unable to find ubuntu-advantage status: %w", err)
	}
	for _, location := range locations {
		enabled, err := hasEnabledESMServiceInStatus(resolver, location)
		if err != nil {
			return false, err
		}
		if enabled {
			return true, nil
		}
	}
	return false, nil
}

func hasEnabledESMServiceInStatus(resolver file.Resolver, location file.Location) (bool, error) {
	contents, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return false, fmt.Errorf("unable to read ubuntu-advantage status from %s: %w", location.RealPath, err)
	}
	defer internal.CloseAndLogError(contents, location.RealPath)

	var status struct {
		Services []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"services"`
	}
	if err := json.NewDecoder(contents).Decode(&status); err != nil {
		return false, fmt.Errorf("unable to parse ubuntu-advantage status from %s: %w", location.RealPath, err)
	}

	// pro status values are enabled/disabled/n-a/warning/—; only "enabled" proves the stream is active.
	// warning/expired states are intentionally excluded here and left to the apt-source and installed-package signals.
	for _, svc := range status.Services {
		if (svc.Name == "esm-infra" || svc.Name == "esm-apps") && svc.Status == "enabled" {
			return true, nil
		}
	}
	return false, nil
}

// hasInstalledESMPackage reports whether any installed dpkg package version carries an ESM pocket suffix.
func hasInstalledESMPackage(packages *pkg.Collection) bool {
	if packages == nil {
		return false
	}
	for p := range packages.Enumerate(pkg.DebPkg) {
		if esmVersionPattern.MatchString(p.Version) {
			return true
		}
	}
	return false
}

func fileMatchesAny(resolver file.Resolver, location file.Location, patterns ...*regexp.Regexp) (bool, error) {
	contents, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return false, fmt.Errorf("unable to read %s: %w", location.RealPath, err)
	}
	defer internal.CloseAndLogError(contents, location.RealPath)
	return internal.MatchAnyFromReader(contents, patterns...)
}
