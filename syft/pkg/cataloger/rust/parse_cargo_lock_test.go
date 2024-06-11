package rust

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/rust"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseCargoLock(t *testing.T) {
	fixture := "test-fixtures/Cargo.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	//goland:noinspection GoSnakeCaseUsage
	ansi_term := pkg.Package{
		Name:      "ansi_term",
		Version:   "0.12.1",
		PURL:      "pkg:cargo/ansi_term@0.12.1",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT")),
		Metadata: rust.RustCargoLockEntry{
			Name:     "ansi_term",
			Version:  "0.12.1",
			Source:   "registry+https://github.com/rust-lang/crates.io-index",
			Checksum: "d52a9bb7ec0cf484c551830a7ce27bd20d67eac647e1befb56b0be4ee39a55d2",
			Dependencies: []string{
				"winapi",
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
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT")),
		Metadata: rust.RustCargoLockEntry{
			Name:         "matches",
			Version:      "0.1.8",
			Source:       "sparse+https://index.crates.io",
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
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("Unlicense/MIT")),
		Metadata: rust.RustCargoLockEntry{
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
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT")),
		Metadata: rust.RustCargoLockEntry{
			Name:         "natord",
			Version:      "1.0.9",
			Source:       "sparse+https://index.crates.io",
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
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT")),
		Metadata: rust.RustCargoLockEntry{
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
	//goland:noinspection GoSnakeCaseUsage
	unicode_bidi := pkg.Package{
		Name:      "unicode-bidi",
		Version:   "0.3.4",
		PURL:      "pkg:cargo/unicode-bidi@0.3.4",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT / Apache-2.0")),
		Metadata: rust.RustCargoLockEntry{
			Name:     "unicode-bidi",
			Version:  "0.3.4",
			Source:   "sparse+https://index.crates.io",
			Checksum: "49f2bd0c6468a8230e1db229cff8029217cf623c767ea5d60bfbd42729ea54d5",
			Dependencies: []string{
				"matches",
			},
		},
	}
	//goland:noinspection GoSnakeCaseUsage
	version_check := pkg.Package{
		Name:      "version_check",
		Version:   "0.1.5",
		PURL:      "pkg:cargo/version_check@0.1.5",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT/Apache-2.0")),
		Metadata: rust.RustCargoLockEntry{
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
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT/Apache-2.0")),
		Metadata: rust.RustCargoLockEntry{
			Name:     "winapi",
			Version:  "0.3.9",
			Source:   "sparse+https://index.crates.io",
			Checksum: "5c839a674fcd7a98952e593242ea400abe93992746761e38641405d28b00f419",
			Dependencies: []string{
				"winapi-i686-pc-windows-gnu",
				"winapi-x86_64-pc-windows-gnu",
			},
		},
	}
	//goland:noinspection GoSnakeCaseUsage
	winapi_i686_pc_windows_gnu := pkg.Package{
		Name:      "winapi-i686-pc-windows-gnu",
		Version:   "0.4.0",
		PURL:      "pkg:cargo/winapi-i686-pc-windows-gnu@0.4.0",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT/Apache-2.0")),
		Metadata: rust.RustCargoLockEntry{
			Name:         "winapi-i686-pc-windows-gnu",
			Version:      "0.4.0",
			Source:       "registry+https://github.com/rust-lang/crates.io-index",
			Checksum:     "ac3b87c63620426dd9b991e5ce0329eff545bccbbb34f3be09ff6fb6ab51b7b6",
			Dependencies: []string{},
		},
	}
	//goland:noinspection GoSnakeCaseUsage
	winapi_x86_64_pc_windows_gnu := pkg.Package{
		Name:      "winapi-x86_64-pc-windows-gnu",
		Version:   "0.4.0",
		PURL:      "pkg:cargo/winapi-x86_64-pc-windows-gnu@0.4.0",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT/Apache-2.0")),
		Metadata: rust.RustCargoLockEntry{
			Name:         "winapi-x86_64-pc-windows-gnu",
			Version:      "0.4.0",
			Source:       "sparse+https://index.crates.io",
			Checksum:     "712e227841d057c1ee1cd2fb22fa7e5a5461ae8e48fa2ca79ec42cfc1931183f",
			Dependencies: []string{},
		},
	}
	//goland:noinspection GoSnakeCaseUsage
	accesskit_winit := pkg.Package{
		Name:      "accesskit_winit",
		Version:   "0.16.1",
		PURL:      "pkg:cargo/accesskit_winit@0.16.1",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("Apache-2.0")),
		Metadata: rust.RustCargoLockEntry{
			Name:     "accesskit_winit",
			Version:  "0.16.1",
			Source:   "sparse+https://index.crates.io",
			Checksum: "5284218aca17d9e150164428a0ebc7b955f70e3a9a78b4c20894513aabf98a67",
			// in reality that's not correct, but let's play pretend. (it's fine, if it's consistent, right?)
			// Some of the code logs Warns, if there are dependencies, which are not themselves declared
			// in the Cargo.lock file
			Dependencies: []string{},
		},
	}
	expectedPkgs := []pkg.Package{
		ansi_term,
		matches,
		memchr,
		natord,
		nom,
		unicode_bidi,
		version_check,
		winapi,
		winapi_i686_pc_windows_gnu,
		winapi_x86_64_pc_windows_gnu,
		accesskit_winit,
	}

	var expectedRelationships = []artifact.Relationship{
		{
			From: matches,
			To:   unicode_bidi,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: memchr,
			To:   nom,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: version_check,
			To:   nom,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: winapi,
			To:   ansi_term,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: winapi_i686_pc_windows_gnu,
			To:   winapi,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: winapi_x86_64_pc_windows_gnu,
			To:   winapi,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseCargoLock, expectedPkgs, expectedRelationships)

}
