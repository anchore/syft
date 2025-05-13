package rust

import (
	"testing"

	"github.com/stretchr/testify/assert"

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
			To:   ansiTerm,
			From: winapi,
			Type: artifact.DependencyOfRelationship,
		},
		{
			To:   errno,
			From: windowsSys52,
			Type: artifact.DependencyOfRelationship,
		},
		{
			To:   nom,
			From: memchr,
			Type: artifact.DependencyOfRelationship,
		},
		{
			To:   nom,
			From: versionCheck,
			Type: artifact.DependencyOfRelationship,
		},
		{
			To:   schannel,
			From: windowsSys59,
			Type: artifact.DependencyOfRelationship,
		},
		{
			To:   unicodeBidi,
			From: matches,
			Type: artifact.DependencyOfRelationship,
		},
		{
			To:   winapi,
			From: winAPIi686PCWindowsGNU,
			Type: artifact.DependencyOfRelationship,
		},
		{
			To:   winapi,
			From: winAPIx8664PCWindowsGNU,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseCargoLock, expectedPkgs, expectedRelationships)
}

func TestCargoLockWithGitDependencies(t *testing.T) {
	fixture := "test-fixtures/Cargo.lock-with-git-deps"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	ahoCorasick := pkg.Package{
		Name:      "aho-corasick",
		Version:   "1.1.3",
		PURL:      "pkg:cargo/aho-corasick@1.1.3",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:     "aho-corasick",
			Version:  "1.1.3",
			Source:   "registry+https://github.com/rust-lang/crates.io-index",
			Checksum: "8e60d3430d3a69478ad0993f19238d2df97c507009a52b3c10addcd7f6bcb916",
			Dependencies: []string{
				"memchr",
			},
		},
	}

	helloWorld := pkg.Package{
		Name:      "hello_world",
		Version:   "0.1.0",
		PURL:      "pkg:cargo/hello_world@0.1.0",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:    "hello_world",
			Version: "0.1.0",
			Dependencies: []string{
				"nom-regex",
				"regex 1.11.1 (git+https://github.com/rust-lang/regex.git)",
			},
		},
	}

	memchr := pkg.Package{
		Name:      "memchr",
		Version:   "2.7.4",
		PURL:      "pkg:cargo/memchr@2.7.4",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:         "memchr",
			Version:      "2.7.4",
			Source:       "registry+https://github.com/rust-lang/crates.io-index",
			Checksum:     "78ca9ab1a0babb1e7d5695e3530886289c18cf2f87ec19a575a0abdce112e3a3",
			Dependencies: []string{},
		},
	}

	minimalLexical := pkg.Package{
		Name:      "minimal-lexical",
		Version:   "0.2.1",
		PURL:      "pkg:cargo/minimal-lexical@0.2.1",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:         "minimal-lexical",
			Version:      "0.2.1",
			Source:       "registry+https://github.com/rust-lang/crates.io-index",
			Checksum:     "68354c5c6bd36d73ff3feceb05efa59b6acb7626617f4962be322a825e61f79a",
			Dependencies: []string{},
		},
	}

	nom := pkg.Package{
		Name:      "nom",
		Version:   "7.1.3",
		PURL:      "pkg:cargo/nom@7.1.3",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:     "nom",
			Version:  "7.1.3",
			Source:   "registry+https://github.com/rust-lang/crates.io-index",
			Checksum: "d273983c5a657a70a3e8f2a01329822f3b8c8172b73826411a55751e404a0a4a",
			Dependencies: []string{
				"memchr",
				"minimal-lexical",
			},
		},
	}

	nomRegex := pkg.Package{
		Name:      "nom-regex",
		Version:   "0.2.0",
		PURL:      "pkg:cargo/nom-regex@0.2.0",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:     "nom-regex",
			Version:  "0.2.0",
			Source:   "registry+https://github.com/rust-lang/crates.io-index",
			Checksum: "72e5c7731c4c1370b61604ed52a2475e861aac9e08dec9f23903d4ddfdc91c18",
			Dependencies: []string{
				"nom",
				"regex 1.11.1 (registry+https://github.com/rust-lang/crates.io-index)",
			},
		},
	}

	regexCrates := pkg.Package{
		Name:      "regex",
		Version:   "1.11.1",
		PURL:      "pkg:cargo/regex@1.11.1",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:     "regex",
			Version:  "1.11.1",
			Source:   "registry+https://github.com/rust-lang/crates.io-index",
			Checksum: "b544ef1b4eac5dc2db33ea63606ae9ffcfac26c1416a2806ae0bf5f56b201191",
			Dependencies: []string{
				"aho-corasick",
				"memchr",
				"regex-automata 0.4.9 (registry+https://github.com/rust-lang/crates.io-index)",
				"regex-syntax 0.8.5 (registry+https://github.com/rust-lang/crates.io-index)",
			},
		},
	}

	regexGit := pkg.Package{
		Name:      "regex",
		Version:   "1.11.1",
		PURL:      "pkg:cargo/regex@1.11.1",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:    "regex",
			Version: "1.11.1",
			Source:  "git+https://github.com/rust-lang/regex.git#1a069b9232c607b34c4937122361aa075ef573fa",
			Dependencies: []string{
				"aho-corasick",
				"memchr",
				"regex-automata 0.4.9 (git+https://github.com/rust-lang/regex.git)",
				"regex-syntax 0.8.5 (git+https://github.com/rust-lang/regex.git)",
			},
		},
	}

	regexAutomataCrates := pkg.Package{
		Name:      "regex-automata",
		Version:   "0.4.9",
		PURL:      "pkg:cargo/regex-automata@0.4.9",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:     "regex-automata",
			Version:  "0.4.9",
			Source:   "registry+https://github.com/rust-lang/crates.io-index",
			Checksum: "809e8dc61f6de73b46c85f4c96486310fe304c434cfa43669d7b40f711150908",
			Dependencies: []string{
				"aho-corasick",
				"memchr",
				"regex-syntax 0.8.5 (registry+https://github.com/rust-lang/crates.io-index)",
			},
		},
	}

	regexAutomataGit := pkg.Package{
		Name:      "regex-automata",
		Version:   "0.4.9",
		PURL:      "pkg:cargo/regex-automata@0.4.9",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:    "regex-automata",
			Version: "0.4.9",
			Source:  "git+https://github.com/rust-lang/regex.git#1a069b9232c607b34c4937122361aa075ef573fa",
			Dependencies: []string{
				"aho-corasick",
				"memchr",
				"regex-syntax 0.8.5 (git+https://github.com/rust-lang/regex.git)",
			},
		},
	}

	regexSyntaxCrates := pkg.Package{
		Name:      "regex-syntax",
		Version:   "0.8.5",
		PURL:      "pkg:cargo/regex-syntax@0.8.5",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:         "regex-syntax",
			Version:      "0.8.5",
			Source:       "registry+https://github.com/rust-lang/crates.io-index",
			Checksum:     "2b15c43186be67a4fd63bee50d0303afffcef381492ebe2c5d87f324e1b8815c",
			Dependencies: []string{},
		},
	}

	regexSyntaxGit := pkg.Package{
		Name:      "regex-syntax",
		Version:   "0.8.5",
		PURL:      "pkg:cargo/regex-syntax@0.8.5",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata: pkg.RustCargoLockEntry{
			Name:         "regex-syntax",
			Version:      "0.8.5",
			Source:       "git+https://github.com/rust-lang/regex.git#1a069b9232c607b34c4937122361aa075ef573fa",
			Dependencies: []string{},
		},
	}

	expectedPkgs := []pkg.Package{
		ahoCorasick, helloWorld, memchr, minimalLexical, nom, nomRegex, regexCrates, regexGit,
		regexAutomataCrates, regexAutomataGit, regexSyntaxCrates, regexSyntaxGit,
	}
	expectedRelationships := []artifact.Relationship{
		{
			From: memchr,
			To:   ahoCorasick,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: nomRegex,
			To:   helloWorld,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: regexGit,
			To:   helloWorld,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: memchr,
			To:   nom,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: minimalLexical,
			To:   nom,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: nom,
			To:   nomRegex,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: regexCrates,
			To:   nomRegex,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: ahoCorasick,
			To:   regexCrates,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: memchr,
			To:   regexCrates,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: regexAutomataCrates,
			To:   regexCrates,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: regexSyntaxCrates,
			To:   regexCrates,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: regexSyntaxCrates,
			To:   regexAutomataCrates,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: ahoCorasick,
			To:   regexGit,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: memchr,
			To:   regexGit,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: regexAutomataGit,
			To:   regexGit,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: regexSyntaxGit,
			To:   regexAutomataGit,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: regexSyntaxGit,
			To:   regexGit,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: ahoCorasick,
			To:   regexAutomataCrates,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: memchr,
			To:   regexAutomataCrates,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: ahoCorasick,
			To:   regexAutomataGit,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: memchr,
			To:   regexAutomataGit,
			Type: artifact.DependencyOfRelationship,
		},
	}
	// what I know so far - it's not sorting, it's not

	pkgtest.TestFileParser(t, fixture, parseCargoLock, expectedPkgs, expectedRelationships)
}

func TestCargoLockDependencySpecification(t *testing.T) {
	tests := []struct {
		name     string
		p        pkg.Package
		provides []string
		requires []string
	}{
		{
			name: "requires git source",
			p: pkg.Package{
				Name:      "hello_world",
				Version:   "0.1.0",
				PURL:      "pkg:cargo/hello_world@0.1.0",
				Locations: file.NewLocationSet(),
				Language:  pkg.Rust,
				Type:      pkg.RustPkg,
				Licenses:  pkg.NewLicenseSet(),
				Metadata: pkg.RustCargoLockEntry{
					Name:    "hello_world",
					Version: "0.1.0",
					Dependencies: []string{
						"nom-regex",
						"regex 1.11.1 (git+https://github.com/rust-lang/regex.git)",
					},
				},
			},
			provides: []string{
				"hello_world",
				"hello_world 0.1.0",
			},
			requires: []string{
				"nom-regex",
				"regex 1.11.1 (git+https://github.com/rust-lang/regex.git)",
			},
		},
		{
			name: "provides git source",
			p: pkg.Package{
				Name:      "regex-automata",
				Version:   "0.4.9",
				PURL:      "pkg:cargo/regex-automata@0.4.9",
				Locations: file.NewLocationSet(),
				Language:  pkg.Rust,
				Type:      pkg.RustPkg,
				Licenses:  pkg.NewLicenseSet(),
				Metadata: pkg.RustCargoLockEntry{
					Name:    "regex-automata",
					Version: "0.4.9",
					Source:  "git+https://github.com/rust-lang/regex.git#1a069b9232c607b34c4937122361aa075ef573fa",
					Dependencies: []string{
						"aho-corasick",
						"memchr",
						"regex-syntax 0.8.5 (git+https://github.com/rust-lang/regex.git)",
					},
				},
			},
			provides: []string{
				"regex-automata",
				"regex-automata 0.4.9",
				"regex-automata 0.4.9 (git+https://github.com/rust-lang/regex.git)",
			},
			requires: []string{
				"aho-corasick",
				"memchr",
				"regex-syntax 0.8.5 (git+https://github.com/rust-lang/regex.git)",
			},
		},
		{
			name: "regex-automata git",
			p: pkg.Package{
				Name:      "regex-automata",
				Version:   "0.4.9",
				PURL:      "pkg:cargo/regex-automata@0.4.9",
				Locations: file.NewLocationSet(),
				Language:  pkg.Rust,
				Type:      pkg.RustPkg,
				Licenses:  pkg.NewLicenseSet(),
				Metadata: pkg.RustCargoLockEntry{
					Name:    "regex-automata",
					Version: "0.4.9",
					Source:  "git+https://github.com/rust-lang/regex.git#1a069b9232c607b34c4937122361aa075ef573fa",
					Dependencies: []string{
						"aho-corasick",
						"memchr",
						"regex-syntax 0.8.5 (git+https://github.com/rust-lang/regex.git)",
					},
				},
			},
			provides: []string{
				"regex-automata",
				"regex-automata 0.4.9",
				"regex-automata 0.4.9 (git+https://github.com/rust-lang/regex.git)",
			},
			requires: []string{
				"aho-corasick",
				"memchr",
				"regex-syntax 0.8.5 (git+https://github.com/rust-lang/regex.git)",
			},
		},
		{
			name: "regex-syntax git",
			p: pkg.Package{
				Name:      "regex-syntax",
				Version:   "0.8.5",
				PURL:      "pkg:cargo/regex-syntax@0.8.5",
				Locations: file.NewLocationSet(),
				Language:  pkg.Rust,
				Type:      pkg.RustPkg,
				Licenses:  pkg.NewLicenseSet(),
				Metadata: pkg.RustCargoLockEntry{
					Name:         "regex-syntax",
					Version:      "0.8.5",
					Source:       "git+https://github.com/rust-lang/regex.git#1a069b9232c607b34c4937122361aa075ef573fa",
					Dependencies: []string{},
				},
			},
			provides: []string{
				"regex-syntax",
				"regex-syntax 0.8.5",
				"regex-syntax 0.8.5 (git+https://github.com/rust-lang/regex.git)",
			},
			requires: []string{},
		},
		{
			name: "regex-syntax crates",
			p: pkg.Package{
				Name:      "regex-syntax",
				Version:   "0.8.5",
				PURL:      "pkg:cargo/regex-syntax@0.8.5",
				Locations: file.NewLocationSet(),
				Language:  pkg.Rust,
				Type:      pkg.RustPkg,
				Licenses:  pkg.NewLicenseSet(),
				Metadata: pkg.RustCargoLockEntry{
					Name:         "regex-syntax",
					Version:      "0.8.5",
					Source:       "registry+https://github.com/rust-lang/crates.io-index",
					Checksum:     "2b15c43186be67a4fd63bee50d0303afffcef381492ebe2c5d87f324e1b8815c",
					Dependencies: []string{},
				},
			},
			provides: []string{
				"regex-syntax",
				"regex-syntax 0.8.5",
				"regex-syntax 0.8.5 (registry+https://github.com/rust-lang/crates.io-index)",
			},
			requires: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := dependencySpecification(test.p)
			assert.Equal(t, test.provides, spec.Provides)
			assert.Equal(t, test.requires, spec.Requires)
		})
	}
}

func Test_corruptCargoLock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/src/Cargo.lock").
		WithError().
		TestParser(t, parseCargoLock)
}
