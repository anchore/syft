package rust

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParseCargoLock(t *testing.T) {
	expected := []*pkg.Package{
		{
			Name:         "ansi_term",
			Version:      "0.12.1",
			Language:     pkg.Rust,
			Type:         pkg.RustPkg,
			MetadataType: pkg.RustCargoPackageMetadataType,
			Licenses:     nil,
			Metadata: pkg.CargoPackageMetadata{
				Name:     "ansi_term",
				Version:  "0.12.1",
				Source:   "registry+https://github.com/rust-lang/crates.io-index",
				Checksum: "d52a9bb7ec0cf484c551830a7ce27bd20d67eac647e1befb56b0be4ee39a55d2",
				Dependencies: []string{
					"winapi",
				},
			},
		},
		{
			Name:         "matches",
			Version:      "0.1.8",
			Language:     pkg.Rust,
			Type:         pkg.RustPkg,
			MetadataType: pkg.RustCargoPackageMetadataType,
			Licenses:     nil,
			Metadata: pkg.CargoPackageMetadata{
				Name:         "matches",
				Version:      "0.1.8",
				Source:       "registry+https://github.com/rust-lang/crates.io-index",
				Checksum:     "7ffc5c5338469d4d3ea17d269fa8ea3512ad247247c30bd2df69e68309ed0a08",
				Dependencies: []string{},
			},
		},
		{
			Name:         "memchr",
			Version:      "2.3.3",
			Language:     pkg.Rust,
			Type:         pkg.RustPkg,
			MetadataType: pkg.RustCargoPackageMetadataType,
			Licenses:     nil,
			Metadata: pkg.CargoPackageMetadata{
				Name:         "memchr",
				Version:      "2.3.3",
				Source:       "registry+https://github.com/rust-lang/crates.io-index",
				Checksum:     "3728d817d99e5ac407411fa471ff9800a778d88a24685968b36824eaf4bee400",
				Dependencies: []string{},
			},
		},
		{
			Name:         "natord",
			Version:      "1.0.9",
			Language:     pkg.Rust,
			Type:         pkg.RustPkg,
			MetadataType: pkg.RustCargoPackageMetadataType,
			Licenses:     nil,
			Metadata: pkg.CargoPackageMetadata{
				Name:         "natord",
				Version:      "1.0.9",
				Source:       "registry+https://github.com/rust-lang/crates.io-index",
				Checksum:     "308d96db8debc727c3fd9744aac51751243420e46edf401010908da7f8d5e57c",
				Dependencies: []string{},
			},
		},
		{
			Name:         "nom",
			Version:      "4.2.3",
			Language:     pkg.Rust,
			Type:         pkg.RustPkg,
			MetadataType: pkg.RustCargoPackageMetadataType,
			Licenses:     nil,
			Metadata: pkg.CargoPackageMetadata{
				Name:     "nom",
				Version:  "4.2.3",
				Source:   "registry+https://github.com/rust-lang/crates.io-index",
				Checksum: "2ad2a91a8e869eeb30b9cb3119ae87773a8f4ae617f41b1eb9c154b2905f7bd6",
				Dependencies: []string{
					"memchr",
					"version_check",
				},
			},
		},
		{
			Name:         "unicode-bidi",
			Version:      "0.3.4",
			Language:     pkg.Rust,
			Type:         pkg.RustPkg,
			MetadataType: pkg.RustCargoPackageMetadataType,
			Licenses:     nil,
			Metadata: pkg.CargoPackageMetadata{
				Name:     "unicode-bidi",
				Version:  "0.3.4",
				Source:   "registry+https://github.com/rust-lang/crates.io-index",
				Checksum: "49f2bd0c6468a8230e1db229cff8029217cf623c767ea5d60bfbd42729ea54d5",
				Dependencies: []string{
					"matches",
				},
			},
		},
		{
			Name:         "version_check",
			Version:      "0.1.5",
			Language:     pkg.Rust,
			Type:         pkg.RustPkg,
			MetadataType: pkg.RustCargoPackageMetadataType,
			Licenses:     nil,
			Metadata: pkg.CargoPackageMetadata{
				Name:         "version_check",
				Version:      "0.1.5",
				Source:       "registry+https://github.com/rust-lang/crates.io-index",
				Checksum:     "914b1a6776c4c929a602fafd8bc742e06365d4bcbe48c30f9cca5824f70dc9dd",
				Dependencies: []string{},
			},
		},
		{
			Name:         "winapi",
			Version:      "0.3.9",
			Language:     pkg.Rust,
			Type:         pkg.RustPkg,
			MetadataType: pkg.RustCargoPackageMetadataType,
			Licenses:     nil,
			Metadata: pkg.CargoPackageMetadata{
				Name:     "winapi",
				Version:  "0.3.9",
				Source:   "registry+https://github.com/rust-lang/crates.io-index",
				Checksum: "5c839a674fcd7a98952e593242ea400abe93992746761e38641405d28b00f419",
				Dependencies: []string{
					"winapi-i686-pc-windows-gnu",
					"winapi-x86_64-pc-windows-gnu",
				},
			},
		},
		{
			Name:         "winapi-i686-pc-windows-gnu",
			Version:      "0.4.0",
			Language:     pkg.Rust,
			Type:         pkg.RustPkg,
			MetadataType: pkg.RustCargoPackageMetadataType,
			Licenses:     nil,
			Metadata: pkg.CargoPackageMetadata{
				Name:         "winapi-i686-pc-windows-gnu",
				Version:      "0.4.0",
				Source:       "registry+https://github.com/rust-lang/crates.io-index",
				Checksum:     "ac3b87c63620426dd9b991e5ce0329eff545bccbbb34f3be09ff6fb6ab51b7b6",
				Dependencies: []string{},
			},
		},
		{
			Name:         "winapi-x86_64-pc-windows-gnu",
			Version:      "0.4.0",
			Language:     pkg.Rust,
			Type:         pkg.RustPkg,
			MetadataType: pkg.RustCargoPackageMetadataType,
			Licenses:     nil,
			Metadata: pkg.CargoPackageMetadata{
				Name:         "winapi-x86_64-pc-windows-gnu",
				Version:      "0.4.0",
				Source:       "registry+https://github.com/rust-lang/crates.io-index",
				Checksum:     "712e227841d057c1ee1cd2fb22fa7e5a5461ae8e48fa2ca79ec42cfc1931183f",
				Dependencies: []string{},
			},
		},
	}

	fixture, err := os.Open("test-fixtures/Cargo.lock")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseCargoLock(fixture.Name(), fixture)
	if err != nil {
		t.Error(err)
	}

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
