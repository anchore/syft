package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source/directorysource"
)

func SourcePackagesInput(t testing.TB, dir string) sbom.SBOM {
	path := filepath.Join(dir, "some", "path")
	require.NoError(t, os.MkdirAll(path, 0755))

	src, err := directorysource.New(
		directorysource.Config{
			Path: path,
			Base: dir,
		},
	)
	require.NoError(t, err)

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: newSourcePackageCatalog(),
		},
		Source: src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v0.42.0-bogus",
		},
	}
}

//nolint:funlen
func newSourcePackageCatalog() *pkg.Collection {
	epoch := 32

	catalog := pkg.NewCollection()

	// apk: the origin differs from the package name, and shares its version
	catalog.Add(pkg.Package{
		Name:      "libc-utils",
		Version:   "0.7.2-r3",
		Type:      pkg.ApkPkg,
		FoundBy:   "apk-db-cataloger",
		Locations: file.NewLocationSet(file.NewLocation("/lib/apk/db/installed")),
		PURL:      "pkg:apk/alpine/libc-utils@0.7.2-r3?arch=x86_64&distro=alpine-3.16.3&upstream=libc-dev",
		Metadata: pkg.ApkDBEntry{
			Package:       "libc-utils",
			OriginPackage: "libc-dev",
			Version:       "0.7.2-r3",
			Architecture:  "x86_64",
		},
	})

	// apk: negative control -- the package is its own origin, so no source reference is expected
	catalog.Add(pkg.Package{
		Name:      "busybox",
		Version:   "1.35.0-r17",
		Type:      pkg.ApkPkg,
		FoundBy:   "apk-db-cataloger",
		Locations: file.NewLocationSet(file.NewLocation("/lib/apk/db/installed")),
		PURL:      "pkg:apk/alpine/busybox@1.35.0-r17?arch=x86_64&distro=alpine-3.16.3",
		Metadata: pkg.ApkDBEntry{
			Package:       "busybox",
			OriginPackage: "busybox",
			Version:       "1.35.0-r17",
			Architecture:  "x86_64",
		},
	})

	// deb: source name differs, and the source version is implied by the binary version
	catalog.Add(pkg.Package{
		Name:      "libpam-runtime",
		Version:   "1.5.2-6+deb12u1",
		Type:      pkg.DebPkg,
		FoundBy:   "dpkg-db-cataloger",
		Locations: file.NewLocationSet(file.NewLocation("/var/lib/dpkg/status")),
		PURL:      "pkg:deb/debian/libpam-runtime@1.5.2-6%2Bdeb12u1?arch=all&distro=debian-12&upstream=pam",
		Metadata: pkg.DpkgDBEntry{
			Package:      "libpam-runtime",
			Version:      "1.5.2-6+deb12u1",
			Source:       "pam",
			Architecture: "all",
		},
	})

	// deb: the source version differs from the binary version
	catalog.Add(pkg.Package{
		Name:      "attr",
		Version:   "1:2.4.47-2+b1",
		Type:      pkg.DebPkg,
		FoundBy:   "dpkg-db-cataloger",
		Locations: file.NewLocationSet(file.NewLocation("/var/lib/dpkg/status")),
		PURL:      "pkg:deb/debian/attr@1%3A2.4.47-2%2Bb1?arch=amd64&distro=debian-12&upstream=attr%401%3A2.4.47-2",
		Metadata: pkg.DpkgDBEntry{
			Package:       "attr",
			Version:       "1:2.4.47-2+b1",
			Source:        "attr",
			SourceVersion: "1:2.4.47-2",
			Architecture:  "amd64",
		},
	})

	// rpm: name and version both come out of the source RPM filename, and the epoch is carried over
	catalog.Add(pkg.Package{
		Name:      "bind-export-libs",
		Version:   "32:9.11.13-3.el8",
		Type:      pkg.RpmPkg,
		FoundBy:   "rpm-db-cataloger",
		Locations: file.NewLocationSet(file.NewLocation("/var/lib/rpm/Packages")),
		PURL:      "pkg:rpm/centos/bind-export-libs@9.11.13-3.el8?arch=x86_64&distro=centos-8&epoch=32&upstream=bind-9.11.13-3.el8.src.rpm",
		Metadata: pkg.RpmDBEntry{
			Name:      "bind-export-libs",
			Version:   "9.11.13",
			Release:   "3.el8",
			Epoch:     &epoch,
			Arch:      "x86_64",
			SourceRpm: "bind-9.11.13-3.el8.src.rpm",
		},
	})

	// alpm: the base package differs from the package name, and shares its version
	catalog.Add(pkg.Package{
		Name:      "gcc-libs",
		Version:   "13.2.1-3",
		Type:      pkg.AlpmPkg,
		FoundBy:   "alpm-db-cataloger",
		Locations: file.NewLocationSet(file.NewLocation("/var/lib/pacman/local/gcc-libs-13.2.1-3/desc")),
		PURL:      "pkg:alpm/arch/gcc-libs@13.2.1-3?arch=x86_64&distro=arch-rolling&upstream=gcc",
		Metadata: pkg.AlpmDBEntry{
			Package:      "gcc-libs",
			Version:      "13.2.1-3",
			BasePackage:  "gcc",
			Architecture: "x86_64",
		},
	})

	return catalog
}
