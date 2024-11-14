package rust

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseCargoLock(t *testing.T) {
	fixture := "test-fixtures/Cargo.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	ansiTerm := pkg.Package{
		Name:      "ansi_term",
		Version:   "0.12.1",
		PURL:      "pkg:cargo/ansi_term@0.12.1",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:     "ansi_term",
			Version:  "0.12.1",
			Source:   "registry+https://github.com/rust-lang/crates.io-index",
			Checksum: "d52a9bb7ec0cf484c551830a7ce27bd20d67eac647e1befb56b0be4ee39a55d2",
			Dependencies: []string{
				"winapi",
			},
		},
	}
	errno := pkg.Package{
		Name:      "errno",
		Version:   "0.3.9",
		PURL:      "pkg:cargo/errno@0.3.9",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:     "errno",
			Version:  "0.3.9",
			Source:   "registry+https://github.com/rust-lang/crates.io-index",
			Checksum: "534c5cf6194dfab3db3242765c03bbe257cf92f22b38f6bc0c58d59108a820ba",
			Dependencies: []string{
				"windows-sys 0.52.0",
			},
		},
	}
	matches := pkg.Package{
		Name:      "matches",
		Version:   "0.1.8",
		PURL:      "pkg:cargo/matches@0.1.8",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:         "matches",
			Version:      "0.1.8",
			Source:       "registry+https://github.com/rust-lang/crates.io-index",
			Checksum:     "7ffc5c5338469d4d3ea17d269fa8ea3512ad247247c30bd2df69e68309ed0a08",
			Dependencies: []string{},
		},
	}
	memchr := pkg.Package{
		Name:      "memchr",
		Version:   "2.3.3",
		PURL:      "pkg:cargo/memchr@2.3.3",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:         "memchr",
			Version:      "2.3.3",
			Source:       "registry+https://github.com/rust-lang/crates.io-index",
			Checksum:     "3728d817d99e5ac407411fa471ff9800a778d88a24685968b36824eaf4bee400",
			Dependencies: []string{},
		},
	}

	natord := pkg.Package{
		Name:      "natord",
		Version:   "1.0.9",
		PURL:      "pkg:cargo/natord@1.0.9",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:         "natord",
			Version:      "1.0.9",
			Source:       "registry+https://github.com/rust-lang/crates.io-index",
			Checksum:     "308d96db8debc727c3fd9744aac51751243420e46edf401010908da7f8d5e57c",
			Dependencies: []string{},
		},
	}

	nom := pkg.Package{
		Name:      "nom",
		Version:   "4.2.3",
		PURL:      "pkg:cargo/nom@4.2.3",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:     "nom",
			Version:  "4.2.3",
			Source:   "registry+https://github.com/rust-lang/crates.io-index",
			Checksum: "2ad2a91a8e869eeb30b9cb3119ae87773a8f4ae617f41b1eb9c154b2905f7bd6",
			Dependencies: []string{
				"memchr",
				"version_check",
			},
		},
	}
	schannel := pkg.Package{
		Name:      "schannel",
		Version:   "0.1.26",
		PURL:      "pkg:cargo/schannel@0.1.26",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:     "schannel",
			Version:  "0.1.26",
			Source:   "registry+https://github.com/rust-lang/crates.io-index",
			Checksum: "01227be5826fa0690321a2ba6c5cd57a19cf3f6a09e76973b58e61de6ab9d1c1",
			Dependencies: []string{
				"windows-sys 0.59.0",
			},
		},
	}

	unicodeBidi := pkg.Package{
		Name:      "unicode-bidi",
		Version:   "0.3.4",
		PURL:      "pkg:cargo/unicode-bidi@0.3.4",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:     "unicode-bidi",
			Version:  "0.3.4",
			Source:   "registry+https://github.com/rust-lang/crates.io-index",
			Checksum: "49f2bd0c6468a8230e1db229cff8029217cf623c767ea5d60bfbd42729ea54d5",
			Dependencies: []string{
				"matches",
				"bogus", // a bad dependency to test error handling
			},
		},
	}

	versionCheck := pkg.Package{
		Name:      "version_check",
		Version:   "0.1.5",
		PURL:      "pkg:cargo/version_check@0.1.5",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:         "version_check",
			Version:      "0.1.5",
			Source:       "registry+https://github.com/rust-lang/crates.io-index",
			Checksum:     "914b1a6776c4c929a602fafd8bc742e06365d4bcbe48c30f9cca5824f70dc9dd",
			Dependencies: []string{},
		},
	}

	winapi := pkg.Package{
		Name:      "winapi",
		Version:   "0.3.9",
		PURL:      "pkg:cargo/winapi@0.3.9",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:     "winapi",
			Version:  "0.3.9",
			Source:   "registry+https://github.com/rust-lang/crates.io-index",
			Checksum: "5c839a674fcd7a98952e593242ea400abe93992746761e38641405d28b00f419",
			Dependencies: []string{
				"winapi-i686-pc-windows-gnu",
				"winapi-x86_64-pc-windows-gnu",
			},
		},
	}

	winAPIi686PCWindowsGNU := pkg.Package{
		Name:      "winapi-i686-pc-windows-gnu",
		Version:   "0.4.0",
		PURL:      "pkg:cargo/winapi-i686-pc-windows-gnu@0.4.0",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:         "winapi-i686-pc-windows-gnu",
			Version:      "0.4.0",
			Source:       "registry+https://github.com/rust-lang/crates.io-index",
			Checksum:     "ac3b87c63620426dd9b991e5ce0329eff545bccbbb34f3be09ff6fb6ab51b7b6",
			Dependencies: []string{},
		},
	}

	winAPIx8664PCWindowsGNU := pkg.Package{
		Name:      "winapi-x86_64-pc-windows-gnu",
		Version:   "0.4.0",
		PURL:      "pkg:cargo/winapi-x86_64-pc-windows-gnu@0.4.0",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:         "winapi-x86_64-pc-windows-gnu",
			Version:      "0.4.0",
			Source:       "registry+https://github.com/rust-lang/crates.io-index",
			Checksum:     "712e227841d057c1ee1cd2fb22fa7e5a5461ae8e48fa2ca79ec42cfc1931183f",
			Dependencies: []string{},
		},
	}

	windowsSys52 := pkg.Package{
		Name:      "windows-sys",
		Version:   "0.52.0",
		PURL:      "pkg:cargo/windows-sys@0.52.0",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:         "windows-sys",
			Version:      "0.52.0",
			Source:       "registry+https://github.com/rust-lang/crates.io-index",
			Checksum:     "282be5f36a8ce781fad8c8ae18fa3f9beff57ec1b52cb3de0789201425d9a33d",
			Dependencies: []string{},
		},
	}

	windowsSys59 := pkg.Package{
		Name:      "windows-sys",
		Version:   "0.59.0",
		PURL:      "pkg:cargo/windows-sys@0.59.0",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:         "windows-sys",
			Version:      "0.59.0",
			Source:       "registry+https://github.com/rust-lang/crates.io-index",
			Checksum:     "1e38bc4d79ed67fd075bcc251a1c39b32a1776bbe92e5bef1f0bf1f8c531853b",
			Dependencies: []string{},
		},
	}
	expectedPkgs := []pkg.Package{
		ansiTerm,
		errno,
		matches,
		memchr,
		natord,
		nom,
		schannel,
		unicodeBidi,
		versionCheck,
		winapi,
		winAPIi686PCWindowsGNU,
		winAPIx8664PCWindowsGNU,
		windowsSys52,
		windowsSys59,
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: ansiTerm,
			To:   winapi,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: errno,
			To:   windowsSys52,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: nom,
			To:   memchr,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: nom,
			To:   versionCheck,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: schannel,
			To:   windowsSys59,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: unicodeBidi,
			To:   matches,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: winapi,
			To:   winAPIi686PCWindowsGNU,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: winapi,
			To:   winAPIx8664PCWindowsGNU,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseCargoLock, expectedPkgs, expectedRelationships)
}

func Test_corruptCargoLock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/src/Cargo.lock").
		WithError().
		TestParser(t, parseCargoLock)
}
