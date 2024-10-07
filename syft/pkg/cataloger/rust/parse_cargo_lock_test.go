package rust

import (
	"fmt"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/pkg/cataloger/rust/internal/cargo"
)

type registryLink string

const (
	officialRegistry registryLink = "registry+https://github.com/rust-lang/crates.io-index"
	officialSparse   registryLink = "sparse+https://index.crates.io"
)

type packageInfo struct {
	pkg.Package
	RustMeta              cargo.LockEntry
	CoordinatePathPrepend string
}

func newPackage(
	t *testing.T,
	name string,
	version string,
	locations file.LocationSet,
	toml cargo.CargoToml,
	registry registryLink,
	checksum string,
	dependencies []string,
	pathSha1Hashes map[string]string, //#nosec G505 G401 -- sha1 is used as a required hash function for SPDX, not a crypto function
) packageInfo {
	t.Helper()

	crateInfo := cargo.CrateInfo{
		DownloadLink:   fmt.Sprintf("https://static.crates.io/crates/%s/%s/download", name, version),
		DownloadSha:    checksum,
		Licenses:       []string{toml.Package.License},
		CargoToml:      toml,
		PathSha1Hashes: pathSha1Hashes,
	}

	lockEntry := cargo.LockEntry{
		RustCargoLockEntry: pkg.RustCargoLockEntry{
			Name:         name,
			Version:      version,
			Source:       string(registry),
			Checksum:     checksum,
			Dependencies: dependencies,
		},
		RegistryInfo: &cargo.RegistryInfo{
			IsLocalFile: false,
			RepositoryConfig: cargo.RepositoryConfig{
				Download: "https://static.crates.io/crates",
			},
		},
		CrateInfo: &crateInfo,
	}
	return packageInfo{
		Package: pkg.Package{
			Name:      name,
			Version:   version,
			PURL:      fmt.Sprintf("pkg:cargo/%s@%s", name, version),
			Locations: locations,
			Language:  pkg.Rust,
			Type:      pkg.RustPkg,
			Licenses:  pkg.NewLicenseSet(pkg.NewLicense(toml.Package.License)),
			Metadata: pkg.RustCargo{
				CargoEntry: &pkg.RustCargoEntry{
					DownloadURL:    crateInfo.DownloadLink,
					DownloadDigest: checksum,
					Description:    crateInfo.CargoToml.Package.Description,
					Homepage:       crateInfo.CargoToml.Package.Homepage,
					Repository:     crateInfo.CargoToml.Package.Repository,
				},
				LockEntry: &lockEntry.RustCargoLockEntry,
			},
		},
		RustMeta:              lockEntry,
		CoordinatePathPrepend: fmt.Sprintf("%s-%s/", name, version),
	}
}

// The dependencies in this test are not correct.
// They have been altered in a consistent way, to avoid having an excessive amount of relations.
func TestParseCargoLock(t *testing.T) {
	fixture := "test-fixtures/Cargo.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	ansiTerm := newPackage(
		t,
		"ansi_term",
		"0.12.1",
		locations,
		cargo.CargoToml{
			Package: cargo.TomlPackage{
				Description: "Library for ANSI terminal colours and styles (bold, underline)",
				Homepage:    "https://github.com/ogham/rust-ansi-term",
				Repository:  "https://github.com/ogham/rust-ansi-term",
				License:     "MIT",
				LicenseFile: "",
			},
		},
		officialRegistry,
		"d52a9bb7ec0cf484c551830a7ce27bd20d67eac647e1befb56b0be4ee39a55d2",
		nil, // see comment at the head of the function
		map[string]string{
			"ansi_term-0.12.1/.appveyor.yml":             "c42d6a3f7e5034faa6575ffb3fbdbbdff1c7ae36",
			"ansi_term-0.12.1/.cargo_vcs_info.json":      "216d8c4b73c5c920e50b9381799fabeeb6db9e2b",
			"ansi_term-0.12.1/.gitignore":                "a61a3e6e96c70bfd3e7317e273e4bc73966cd206",
			"ansi_term-0.12.1/.rustfmt.toml":             "c5764722079c8d29355b51c529d33aa987308d96",
			"ansi_term-0.12.1/.travis.yml":               "87b6300a2c64fd5c277b239ccf3a197ac93330a9",
			"ansi_term-0.12.1/Cargo.lock":                "4fe4f31ecf5587749ef36a0d737520505e2b738a",
			"ansi_term-0.12.1/Cargo.toml":                "0293cdba284ead161e8bb22810df81da7e0d4d46",
			"ansi_term-0.12.1/Cargo.toml.orig":           "028652d42e04c077101de1915442bc91b969b0b8",
			"ansi_term-0.12.1/LICENCE":                   "7293920aac55f4d275cef83ba10d706585622a53",
			"ansi_term-0.12.1/README.md":                 "0256097d83afe02e629b924538e64daa5cc96cfc",
			"ansi_term-0.12.1/examples/256_colours.rs":   "69e1803a4e8ceb7b9ac824105e132e36dac5f83d",
			"ansi_term-0.12.1/examples/basic_colours.rs": "1b012d37d1821eb962781e3b70f8a1049568a684",
			"ansi_term-0.12.1/examples/rgb_colours.rs":   "fe54d6382de09f91056cd0f0e23ee0cf08f4a465",
			"ansi_term-0.12.1/src/ansi.rs":               "a44febd838c3c6a083ad7855f8f256120f5910e5",
			"ansi_term-0.12.1/src/debug.rs":              "9a144eac569faadf3476394b6ccb14c535d5a4b3",
			"ansi_term-0.12.1/src/difference.rs":         "b27f3d41bbaa70b427a6be965b203d14b02b461f",
			"ansi_term-0.12.1/src/display.rs":            "0c0a49ac7f10fed51312844f0736d9b27b21e289",
			"ansi_term-0.12.1/src/lib.rs":                "685f66c3d2fd0487dead77764d8d4a1d882aad38",
			"ansi_term-0.12.1/src/style.rs":              "30e0f9157760b374caff3ebcdcb0b932115fc49f",
			"ansi_term-0.12.1/src/util.rs":               "ec085dabb9f7103ecf9c3c150d1f57cf33a4c6eb",
			"ansi_term-0.12.1/src/windows.rs":            "a2271341a4248916eebaf907b27be2170c12d45c",
			"ansi_term-0.12.1/src/write.rs":              "ac7f435f78ef8c2ed733573c62c428c7a9794038",
		},
	)
	matches := newPackage(
		t,
		"matches",
		"0.1.8",
		locations,
		cargo.CargoToml{
			Package: cargo.TomlPackage{
				Description: "A macro to evaluate, as a boolean, whether an expression matches a pattern.",
				Homepage:    "",
				Repository:  "https://github.com/SimonSapin/rust-std-candidates",
				License:     "MIT",
				LicenseFile: "",
			},
		},
		officialSparse,
		"7ffc5c5338469d4d3ea17d269fa8ea3512ad247247c30bd2df69e68309ed0a08",
		nil,
		map[string]string{
			"matches-0.1.8/Cargo.toml":             "ae580adb71d8a07fe5865cd9951bc6886ab3e3a4",
			"matches-0.1.8/Cargo.toml.orig":        "818c35d1d78008a9d8e2e7b33bb316eea02d7711",
			"matches-0.1.8/LICENSE":                "1b0e913d41a66c988376898aa995d6c2f45bb50c",
			"matches-0.1.8/lib.rs":                 "c6329ef2162b8b59dd2bcda7402151c47a7cf99f",
			"matches-0.1.8/tests/macro_use_one.rs": "faad095b6182c15929020d79581661f1a331daa3",
		},
	)
	memchr := newPackage(
		t,
		"memchr",
		"2.3.3",
		locations,
		cargo.CargoToml{
			Package: cargo.TomlPackage{
				Description: "Safe interface to memchr.",
				Homepage:    "https://github.com/BurntSushi/rust-memchr",
				Repository:  "https://github.com/BurntSushi/rust-memchr",
				License:     "Unlicense/MIT",
				LicenseFile: "",
			},
		},
		officialRegistry,
		"3728d817d99e5ac407411fa471ff9800a778d88a24685968b36824eaf4bee400",
		nil,
		map[string]string{
			"memchr-2.3.3/.cargo_vcs_info.json":     "b1ecb8751a0d53cccb6be606ede175736d51da04",
			"memchr-2.3.3/.github/workflows/ci.yml": "987372cc6a27668c02b8e9a9fe68e767cd4c658c",
			"memchr-2.3.3/.gitignore":               "556d32e5cb6dfbdbfc67e2dd06f948b76fe8b9d3",
			"memchr-2.3.3/.ignore":                  "e48305d030f8aebbe1a89fcb84f4ac19bb073975",
			"memchr-2.3.3/COPYING":                  "dd445710e6e4caccc4f8a587a130eaeebe83f6f6",
			"memchr-2.3.3/Cargo.toml":               "395d46c2216bc3a5092b37c3dc7516566467dfd4",
			"memchr-2.3.3/Cargo.toml.orig":          "fe0739eacb9577f22fa4cd9c35096c2ac11ead76",
			"memchr-2.3.3/LICENSE-MIT":              "4c8990add9180fc59efa5b0d8faf643c9709501e",
			"memchr-2.3.3/README.md":                "802d3bfea6ff17d5f082ecceb511913021390699",
			"memchr-2.3.3/UNLICENSE":                "ff007ce11f3ff7964f1a5b04202c4e95b5c82c85",
			"memchr-2.3.3/build.rs":                 "59fca6951275d4feba14c07109c4bb351da187d5",
			"memchr-2.3.3/rustfmt.toml":             "558a7c72e415544f0b8790cd8c752690d0bc05c6",
			"memchr-2.3.3/src/c.rs":                 "c75095493e42affe48a23e7de9c77c95ec139c7c",
			"memchr-2.3.3/src/fallback.rs":          "7f13c3502f300646a24e58172d99d78033e339b2",
			"memchr-2.3.3/src/iter.rs":              "b01cc89987d9c2f61baa97f7465ca2b81ce80b52",
			"memchr-2.3.3/src/lib.rs":               "35fac0bea520bfeb99197cfd97056bed99582ce2",
			"memchr-2.3.3/src/naive.rs":             "fcb709375bf7a20ddd97388982050d5d5da5f15f",
			"memchr-2.3.3/src/tests/iter.rs":        "daaf6a0b800563deb45227b2e7fb6fdae464ae84",
			"memchr-2.3.3/src/tests/memchr.rs":      "37f44dc29c8efb1d19eea6f2924a19ba86c14b3b",
			"memchr-2.3.3/src/tests/miri.rs":        "c6569d55c18255a52f5a75256f95167101d9dbeb",
			"memchr-2.3.3/src/tests/mod.rs":         "cdd9c0085ceccf76090bc327840e6a9315499acc",
			"memchr-2.3.3/src/x86/avx.rs":           "4bc56ed4faa1b026b399c169790a678b6af6a941",
			"memchr-2.3.3/src/x86/mod.rs":           "be8644c7bad1427b23436e6d5992c16e5129c216",
			"memchr-2.3.3/src/x86/sse2.rs":          "d2b640c77a0223812fa6a6f550e61ff4269320f0",
			"memchr-2.3.3/src/x86/sse42.rs":         "f053482427712918edf50aea0cb7e2fb95a2ccc1",
		},
	)
	natord := newPackage(
		t,
		"natord",
		"1.0.9",
		locations,
		cargo.CargoToml{
			Package: cargo.TomlPackage{
				Description: "Natural ordering for Rust",
				Homepage:    "https://github.com/lifthrasiir/rust-natord",
				Repository:  "https://github.com/lifthrasiir/rust-natord",
				License:     "MIT",
				LicenseFile: "",
			},
		},
		officialSparse,
		"308d96db8debc727c3fd9744aac51751243420e46edf401010908da7f8d5e57c",
		nil,
		map[string]string{
			"natord-1.0.9/.gitignore":  "3254b5d5538166f1fd5a0bb41f7f3d3bbd455c56",
			"natord-1.0.9/.travis.yml": "4eadee39324e1cc0e156d4c1632fc417f9ed8a7e",
			"natord-1.0.9/Cargo.toml":  "bffdbe1b6b2576ae1b17d4693545aa0145b435be",
			"natord-1.0.9/LICENSE.txt": "bf18c5cc6c1db93eb4e2e95b11352e4660408fec",
			"natord-1.0.9/README.md":   "c2958854fdc10329e409906292506d6e24dd78b5",
			"natord-1.0.9/lib.rs":      "83320272b3d922f5bed408d04fb18954c34958b0",
		},
	)
	nom := newPackage(
		t,
		"nom",
		"4.2.3",
		locations,
		cargo.CargoToml{
			Package: cargo.TomlPackage{
				Description: "A byte-oriented, zero-copy, parser combinators library",
				Homepage:    "",
				Repository:  "https://github.com/Geal/nom",
				License:     "MIT",
				LicenseFile: "",
			},
		},
		officialRegistry,
		"2ad2a91a8e869eeb30b9cb3119ae87773a8f4ae617f41b1eb9c154b2905f7bd6",
		[]string{
			"memchr",
			"version_check",
		},
		map[string]string{
			"nom-4.2.3/.cargo_vcs_info.json":         "93ede0fafa3ccca217787167b2a7a9c22cdf0b88",
			"nom-4.2.3/CHANGELOG.md":                 "48ba21326a9a3bdf1504a642a42cf7f84a0076e8",
			"nom-4.2.3/Cargo.toml":                   "e041d8ad32b719e9ab49c3f7f187d2902ea491f9",
			"nom-4.2.3/Cargo.toml.orig":              "c1d374941ff23392f409b933c799e849bd948b0e",
			"nom-4.2.3/LICENSE":                      "e7b32657d4608cb4a57afa790801ecb9c2a037f5",
			"nom-4.2.3/build.rs":                     "c59d60b5509a470ff9445c43ee414a029724504e",
			"nom-4.2.3/src/bits.rs":                  "419bf0a257199204fbf7e98ca2904eafd99f2264",
			"nom-4.2.3/src/branch.rs":                "388f6ae6ce5d441dbe360bcc1be493315386e73a",
			"nom-4.2.3/src/bytes.rs":                 "483cae38a9eb9129e6a7958f1ca40be9d9bb2571",
			"nom-4.2.3/src/character.rs":             "a7ec8cc1042501dced6c35f436342e865aac97be",
			"nom-4.2.3/src/internal.rs":              "2ffaf19df16c691da9d250840d9fbdf56e2403bb",
			"nom-4.2.3/src/lib.rs":                   "39e4e967ce4a559fb08b3bb0d7b38f8c9429fe82",
			"nom-4.2.3/src/macros.rs":                "39a24461edd8adc74a28c36d14699b0728e90f9d",
			"nom-4.2.3/src/methods.rs":               "3b934d588ee14965b19d831efc7f0b63cf78e0a9",
			"nom-4.2.3/src/multi.rs":                 "098ba3b2faccdf3485491d88e521a3c9f5667ddc",
			"nom-4.2.3/src/nom.rs":                   "c74454752b17c2a7fa8abe398093617f8141f6f7",
			"nom-4.2.3/src/regexp.rs":                "2875009ce9d7df6787d794a4a807a677a5f1e600",
			"nom-4.2.3/src/sequence.rs":              "1a496dbd1094e93f1409bad30b31867a566de089",
			"nom-4.2.3/src/simple_errors.rs":         "585ba0d774a4d6c48229f61e051368333ba16bf9",
			"nom-4.2.3/src/str.rs":                   "2e7303a42f0f31647c68c9b45c85e815c7c9d2f4",
			"nom-4.2.3/src/traits.rs":                "74ca43bd49a2b81799dfef4b8fbecfd1f77884e9",
			"nom-4.2.3/src/types.rs":                 "3032dba26cddcd7018c0e48295e30ae403902d7e",
			"nom-4.2.3/src/util.rs":                  "fc1a7dc1250b692c5f849f2bfb6b84241eff9d0a",
			"nom-4.2.3/src/verbose_errors.rs":        "4d5ee906c52b72080d8a6eee5a9227ab4e76506b",
			"nom-4.2.3/src/whitespace.rs":            "2d5cb62bf4c5e7107d122f120603cc6c38c747be",
			"nom-4.2.3/tests/arithmetic.rs":          "a85ef14df0e37e9455b2543ed0d43c5f7a600a7d",
			"nom-4.2.3/tests/arithmetic_ast.rs":      "1b752396f083d8ea500a04ea0ce799b78ff42098",
			"nom-4.2.3/tests/blockbuf-arithmetic.rs": "8b41afbcc779ce0410a1295b987b4340d30798b9",
			"nom-4.2.3/tests/complete_arithmetic.rs": "be31008788ba4ba2f901ecbf5337e55f6c20828e",
			"nom-4.2.3/tests/complete_float.rs":      "c1e4b10c80c261842e808517d85f98bff6ca006a",
			"nom-4.2.3/tests/css.rs":                 "a6bf483ae364c9820428c1b830e28c0e4eeddec3",
			"nom-4.2.3/tests/custom_errors.rs":       "41d94a408dfb23eed0142d7b9c982a4fdfbd293a",
			"nom-4.2.3/tests/float.rs":               "cbe19c77cd0b149198d610cbdb825a06d27c1ea4",
			"nom-4.2.3/tests/inference.rs":           "cee94e4224a72ceed0c21549ed2ef1341657fc32",
			"nom-4.2.3/tests/ini.rs":                 "6c51af96426032b9f442caeab542b900b1128719",
			"nom-4.2.3/tests/ini_str.rs":             "aa971f48e78b79766deba7217dfca78a9b960855",
			"nom-4.2.3/tests/issues.rs":              "5f61b69052fad5b413d9e588ffecab8004849788",
			"nom-4.2.3/tests/json.rs":                "b45c8b0db154180350c34c2d2086fa355b1b45e5",
			"nom-4.2.3/tests/mp4.rs":                 "7288433829b9b3f305761b240c8c9b60529f66a1",
			"nom-4.2.3/tests/multiline.rs":           "270c16ebaf0c3839e9ebe66cca28803fe64bbc05",
			"nom-4.2.3/tests/named_args.rs":          "f67ef99a7df44705eecf64de45f200c296ec4648",
			"nom-4.2.3/tests/overflow.rs":            "1ad7e1bdc3b070bd336680f39294f7400bf50d61",
			"nom-4.2.3/tests/reborrow_fold.rs":       "4ba89f2b42dcf803a2687b370c835e2134f11af1",
			"nom-4.2.3/tests/test1.rs":               "f7c223208509242a9b66d9fbfaccc509d2a14bef",
		},
	)

	unicodeBidi := newPackage(
		t,
		"unicode-bidi",
		"0.3.4",
		locations,
		cargo.CargoToml{
			Package: cargo.TomlPackage{
				Description: "Implementation of the Unicode Bidirectional Algorithm",
				Homepage:    "",
				Repository:  "https://github.com/servo/unicode-bidi",
				License:     "MIT / Apache-2.0",
				LicenseFile: "",
			},
		},
		officialSparse,
		"49f2bd0c6468a8230e1db229cff8029217cf623c767ea5d60bfbd42729ea54d5",
		[]string{
			"matches",
		},
		map[string]string{
			"unicode-bidi-0.3.4/.appveyor.yml":           "e6a4b71b2e461d29891f693815fb8d946a468dd5",
			"unicode-bidi-0.3.4/.gitignore":              "49b13a4aa553694185bb35d9ba508e55545ccb5c",
			"unicode-bidi-0.3.4/.rustfmt.toml":           "76a81d84fe870ade0d22f3e952a61d0d75eb5a87",
			"unicode-bidi-0.3.4/.travis.yml":             "e4acfec5e6f3afef42e8461a15a02348abd5d741",
			"unicode-bidi-0.3.4/AUTHORS":                 "05bb8f0c2d2c480ab371dfbc7d58cc44b9184403",
			"unicode-bidi-0.3.4/COPYRIGHT":               "871b9912ab96cf7d79cb8ae83ca0b08cd5d0cbfd",
			"unicode-bidi-0.3.4/Cargo.toml":              "f6b0f63bf80d80eb4d5df44f3c6d77947a930acb",
			"unicode-bidi-0.3.4/Cargo.toml.orig":         "51dcdeeaa5e96a9b02471b6ba8a1fdd08ec6aa03",
			"unicode-bidi-0.3.4/LICENSE-APACHE":          "5798832c31663cedc1618d18544d445da0295229",
			"unicode-bidi-0.3.4/LICENSE-MIT":             "60c3522081bf15d7ac1d4c5a63de425ef253e87a",
			"unicode-bidi-0.3.4/README.md":               "78d6f25691fa623f950efdf9d2a9aae129e30e2d",
			"unicode-bidi-0.3.4/src/char_data/mod.rs":    "7a08a46193d71df15da9d900c339a4dbce0a5f45",
			"unicode-bidi-0.3.4/src/char_data/tables.rs": "e495d79981929f5bb2f0457d452de8a4b52f6666",
			"unicode-bidi-0.3.4/src/deprecated.rs":       "43ac5028a8f1d5ddba76822147fb363ef0222601",
			"unicode-bidi-0.3.4/src/explicit.rs":         "eed6c9865990a33498339e5f0fe9ba63352d08f1",
			"unicode-bidi-0.3.4/src/format_chars.rs":     "468f7b50f5a290b6bdbb0707381dfb5a61e90012",
			"unicode-bidi-0.3.4/src/implicit.rs":         "1a47012f5da712a4f8d0418a54b93ac5e011cece",
			"unicode-bidi-0.3.4/src/level.rs":            "c9fabd87fb706e9ea6aa9bbfcff00cad11efae07",
			"unicode-bidi-0.3.4/src/lib.rs":              "7ea0fb0b66115b1ec766a9ad90b937496e6610ae",
			"unicode-bidi-0.3.4/src/prepare.rs":          "5030d5cbb328b1f04b79879ee8a455609b79f209",
		},
	)

	versionCheck := newPackage(
		t,
		"version_check",
		"0.1.5",
		locations,
		cargo.CargoToml{
			Package: cargo.TomlPackage{
				Description: "Tiny crate to check the version of the installed/running rustc.",
				Homepage:    "",
				Repository:  "https://github.com/SergioBenitez/version_check",
				License:     "MIT/Apache-2.0",
				LicenseFile: "",
			},
		},
		officialRegistry,
		"914b1a6776c4c929a602fafd8bc742e06365d4bcbe48c30f9cca5824f70dc9dd",
		nil,
		map[string]string{
			"version_check-0.1.5/.cargo_vcs_info.json": "c2cbaa20212e0f8eb1e2d1875be2a17d5ab223c2",
			"version_check-0.1.5/.gitignore":           "3254b5d5538166f1fd5a0bb41f7f3d3bbd455c56",
			"version_check-0.1.5/Cargo.toml":           "00d6f82ce931ab8de090f799be41afa120f23da7",
			"version_check-0.1.5/Cargo.toml.orig":      "fcdc047676e0857485f2834eeda27d97109e2438",
			"version_check-0.1.5/LICENSE-APACHE":       "5798832c31663cedc1618d18544d445da0295229",
			"version_check-0.1.5/LICENSE-MIT":          "cfcb552ef0afbe7ccb4128891c0de00685988a4b",
			"version_check-0.1.5/README.md":            "a88c576b3dc05d78012217f34a10fd9ae5a514da",
			"version_check-0.1.5/src/lib.rs":           "0b69c0dba2824a1bfd0b3f3da71c21ec2e2795fa",
		},
	)

	accesskitWinit := newPackage(
		t,
		"accesskit_winit",
		"0.16.1",
		locations,
		cargo.CargoToml{
			Package: cargo.TomlPackage{
				Description: "AccessKit UI accessibility infrastructure: winit adapter",
				Homepage:    "",
				Repository:  "https://github.com/AccessKit/accesskit",
				License:     "Apache-2.0",
				LicenseFile: "",
			},
		},
		officialSparse,
		"5284218aca17d9e150164428a0ebc7b955f70e3a9a78b4c20894513aabf98a67",
		nil, // see comment at the head of the function
		map[string]string{
			"accesskit_winit-0.16.1/.cargo_vcs_info.json":         "41670cdd89868caeaf12ac151ba726121a7f2fcb",
			"accesskit_winit-0.16.1/CHANGELOG.md":                 "736e12da4bf06f142c7815349fe4d9fc8d8a4e49",
			"accesskit_winit-0.16.1/Cargo.lock":                   "8c0ff30a7c7d824d6b4ff72cbfcc47aeb5de42ba",
			"accesskit_winit-0.16.1/Cargo.toml":                   "f6ee420b533c6a8b3682d1afe138e523c4cfb822",
			"accesskit_winit-0.16.1/Cargo.toml.orig":              "284301a6507e7701bad8c7b1606906ace5478600",
			"accesskit_winit-0.16.1/README.md":                    "19f731ae277aad4a740b23e00354cb53ddb50864",
			"accesskit_winit-0.16.1/examples/simple.rs":           "7cd864d6183b46b0e21378aaae2ecb0abc8acdd3",
			"accesskit_winit-0.16.1/src/lib.rs":                   "7d1e3bc6d8080e8f348d4690bdf6dc5d44b3c815",
			"accesskit_winit-0.16.1/src/platform_impl/macos.rs":   "b9cba69fa2902d2f6cc9b2319169fa5cf3975f05",
			"accesskit_winit-0.16.1/src/platform_impl/mod.rs":     "7aacdceafbe2c1bb920d6c84a685a354bacfd83d",
			"accesskit_winit-0.16.1/src/platform_impl/null.rs":    "ecd4209a6a4080a3c02bfd01c80f32a1c0251c66",
			"accesskit_winit-0.16.1/src/platform_impl/unix.rs":    "7010e6aad7fb9cbdc96bf384621816c0127276f8",
			"accesskit_winit-0.16.1/src/platform_impl/windows.rs": "6d80687a1b62767930efb8dffb4fa96452a77916",
		},
	)
	expectedPkgs := []pkg.Package{
		ansiTerm.Package,
		matches.Package,
		memchr.Package,
		natord.Package,
		nom.Package,
		unicodeBidi.Package,
		versionCheck.Package,
		accesskitWinit.Package,
	}
	for _, p := range expectedPkgs {
		p.SetID()
	}

	var expectedRelationships = []artifact.Relationship{
		{
			From: matches.Package,
			To:   unicodeBidi.Package,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: memchr.Package,
			To:   nom.Package,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: versionCheck.Package,
			To:   nom.Package,
			Type: artifact.DependencyOfRelationship,
		},
	}

	// TODO: this is invalid
	//for _, p := range []packageInfo{ansiTerm, matches,
	//	memchr,
	//	natord,
	//	nom,
	//	unicodeBidi,
	//	versionCheck,
	//	accesskitWinit,
	//} {
	//	for k, v := range p.RustMeta.CrateInfo.PathSha1Hashes {
	//		expectedRelationships = append(expectedRelationships, artifact.Relationship{
	//			From: p.Package,
	//			To:   file.NewCoordinates(k, p.RustMeta.CrateInfo.DownloadLink),
	//			Type: artifact.ContainsRelationship,
	//			Data: file.Digest{
	//				Algorithm: "sha1",
	//				Value:     v
	//			},
	//		})
	//	}
	//}

	pkgtest.TestFileParser(t, fixture, newCargoModCataloger(DefaultCargoLockCatalogerConfig()).parseCargoLock, expectedPkgs, expectedRelationships)
	//pkgtest.NewCatalogTester().WithCompareOptions(cm).FromFile(t, fixture).Expects(expectedPkgs, expectedRelationships).TestParser(t, parseCargoLock)

}
