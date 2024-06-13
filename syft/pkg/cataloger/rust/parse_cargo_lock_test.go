package rust

import (
	"fmt"
	"testing"

	"github.com/anchore/syft/syft/pkg/rust"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

type registryLink string

const (
	OfficialRegistry registryLink = "registry+https://github.com/rust-lang/crates.io-index"
	OfficialSparse   registryLink = "sparse+https://index.crates.io"
)

type packageInfo struct {
	pkg.Package
	downloadLocation      string
	coordinatePathPrepend string
}

func newPackage(name string, version string, locations file.LocationSet, license string, registry registryLink, checksum string, dependencies []string) packageInfo {
	return packageInfo{
		Package: pkg.Package{
			Name:      name,
			Version:   version,
			PURL:      fmt.Sprintf("pkg:cargo/%s@%s", name, version),
			Locations: locations,
			Language:  pkg.Rust,
			Type:      pkg.RustPkg,
			Licenses:  pkg.NewLicenseSet(pkg.NewLicense(license)),
			Metadata: rust.RustCargoLockEntry{
				Name:         name,
				Version:      version,
				Source:       string(registry),
				Checksum:     checksum,
				Dependencies: dependencies,
			},
		},
		downloadLocation:      fmt.Sprintf("https://static.crates.io/crates/%s/%s/download", name, version),
		coordinatePathPrepend: fmt.Sprintf("%s-%s/", name, version),
	}
}

// The dependencies in this test are not correct.
// They have been altered in a consistent way, to avoid having an excessive amount of relations.
func TestParseCargoLock(t *testing.T) {
	fixture := "test-fixtures/Cargo.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	//goland:noinspection GoSnakeCaseUsage
	ansi_term := newPackage(
		"ansi_term",
		"0.12.1",
		locations,
		"MIT",
		OfficialRegistry,
		"d52a9bb7ec0cf484c551830a7ce27bd20d67eac647e1befb56b0be4ee39a55d2",
		[]string{}, // see comment at the head of the function
	)
	matches := newPackage(
		"matches",
		"0.1.8",
		locations,
		"MIT",
		OfficialSparse,
		"7ffc5c5338469d4d3ea17d269fa8ea3512ad247247c30bd2df69e68309ed0a08",
		[]string{},
	)
	memchr := newPackage(
		"memchr",
		"2.3.3",
		locations,
		"Unlicense/MIT",
		OfficialRegistry,
		"3728d817d99e5ac407411fa471ff9800a778d88a24685968b36824eaf4bee400",
		[]string{},
	)
	natord := newPackage(
		"natord",
		"1.0.9",
		locations,
		"MIT",
		OfficialSparse,
		"308d96db8debc727c3fd9744aac51751243420e46edf401010908da7f8d5e57c",
		[]string{},
	)
	nom := newPackage(
		"nom",
		"4.2.3",
		locations,
		"MIT",
		OfficialRegistry,
		"2ad2a91a8e869eeb30b9cb3119ae87773a8f4ae617f41b1eb9c154b2905f7bd6",
		[]string{
			"memchr",
			"version_check",
		},
	)
	//goland:noinspection GoSnakeCaseUsage
	unicode_bidi := newPackage(
		"unicode-bidi",
		"0.3.4",
		locations,
		"MIT / Apache-2.0",
		OfficialSparse,
		"49f2bd0c6468a8230e1db229cff8029217cf623c767ea5d60bfbd42729ea54d5",
		[]string{
			"matches",
		},
	)
	//goland:noinspection GoSnakeCaseUsage
	version_check := newPackage(
		"version_check",
		"0.1.5",
		locations,
		"MIT/Apache-2.0",
		OfficialRegistry,
		"914b1a6776c4c929a602fafd8bc742e06365d4bcbe48c30f9cca5824f70dc9dd",
		[]string{},
	)
	//goland:noinspection GoSnakeCaseUsage
	accesskit_winit := newPackage(
		"accesskit_winit",
		"0.16.1",
		locations,
		"Apache-2.0",
		OfficialSparse,
		"5284218aca17d9e150164428a0ebc7b955f70e3a9a78b4c20894513aabf98a67",
		[]string{}, // see comment at the head of the function
	)
	expectedPkgs := []pkg.Package{
		ansi_term.Package,
		matches.Package,
		memchr.Package,
		natord.Package,
		nom.Package,
		unicode_bidi.Package,
		version_check.Package,
		accesskit_winit.Package,
	}
	for _, p := range expectedPkgs {
		p.SetID()
	}

	// all the contains relations were generated, by:
	// 1. downloading the crates via wget
	// wget https://static.crates.io/crates/ansi_term/0.12.1/download
	// wget https://static.crates.io/crates/matches/0.1.8/download
	// wget https://static.crates.io/crates/memchr/2.3.3/download
	// wget https://static.crates.io/crates/natord/1.0.9/download
	// wget https://static.crates.io/crates/nom/4.2.3/download
	// wget https://static.crates.io/crates/unicode-bidi/0.3.4/download
	// wget https://static.crates.io/crates/version_check/0.1.5/download
	// wget https://static.crates.io/crates/accesskit_winit/0.16.1/download
	// 2. extracting them via tar -xvf
	// for i in *; do tar -xvf $i; done
	// 3. deleting the downloads
	// rm download*
	// 4. mv unicode-bidi-0.3.4 unicode_bidi-0.3.4
	// 7. find -type f -exec sha1sum {} >> sums.sha1 +
	// 8. remove the last line, which contains the hash of sums.sha1 itself
	// 9. in sums.sha1 regex replacing "([0-9a-f]+)\s+\./(.*?)-[0-9]+\.[0-9]+\.[0-9]+/(.*)" to "\t\t{\n\t\t\tFrom: \2,\n\t\t\tTo: file.NewCoordinates(\2.coordinatePathPrepend+"\3", \2.downloadLocation),\n\t\t\tType: artifact.ContainsRelationship,\n\t\t\tData: file.Digest{\n\t\t\t\tAlgorithm: "sha1",\n\t\t\t\tValue: "\1",\n\t\t\t},\n\t\t},"
	var expectedRelationships = []artifact.Relationship{
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+".appveyor.yml", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "c42d6a3f7e5034faa6575ffb3fbdbbdff1c7ae36",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+".gitignore", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "a61a3e6e96c70bfd3e7317e273e4bc73966cd206",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+".rustfmt.toml", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "c5764722079c8d29355b51c529d33aa987308d96",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+".travis.yml", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "87b6300a2c64fd5c277b239ccf3a197ac93330a9",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"Cargo.toml.orig", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "028652d42e04c077101de1915442bc91b969b0b8",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"Cargo.toml", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "0293cdba284ead161e8bb22810df81da7e0d4d46",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"examples/256_colours.rs", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "69e1803a4e8ceb7b9ac824105e132e36dac5f83d",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"examples/basic_colours.rs", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "1b012d37d1821eb962781e3b70f8a1049568a684",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"examples/rgb_colours.rs", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "fe54d6382de09f91056cd0f0e23ee0cf08f4a465",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"LICENCE", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "7293920aac55f4d275cef83ba10d706585622a53",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"README.md", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "0256097d83afe02e629b924538e64daa5cc96cfc",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"src/ansi.rs", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "a44febd838c3c6a083ad7855f8f256120f5910e5",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"src/debug.rs", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "9a144eac569faadf3476394b6ccb14c535d5a4b3",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"src/difference.rs", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "b27f3d41bbaa70b427a6be965b203d14b02b461f",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"src/display.rs", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "0c0a49ac7f10fed51312844f0736d9b27b21e289",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"src/lib.rs", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "685f66c3d2fd0487dead77764d8d4a1d882aad38",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"src/style.rs", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "30e0f9157760b374caff3ebcdcb0b932115fc49f",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"src/util.rs", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "ec085dabb9f7103ecf9c3c150d1f57cf33a4c6eb",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"src/windows.rs", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "a2271341a4248916eebaf907b27be2170c12d45c",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"src/write.rs", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "ac7f435f78ef8c2ed733573c62c428c7a9794038",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+".cargo_vcs_info.json", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "216d8c4b73c5c920e50b9381799fabeeb6db9e2b",
			},
		},
		{
			From: ansi_term,
			To:   file.NewCoordinates(ansi_term.coordinatePathPrepend+"Cargo.lock", ansi_term.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "4fe4f31ecf5587749ef36a0d737520505e2b738a",
			},
		},
		{
			From: matches,
			To:   file.NewCoordinates(matches.coordinatePathPrepend+"Cargo.toml.orig", matches.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "818c35d1d78008a9d8e2e7b33bb316eea02d7711",
			},
		},
		{
			From: matches,
			To:   file.NewCoordinates(matches.coordinatePathPrepend+"Cargo.toml", matches.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "ae580adb71d8a07fe5865cd9951bc6886ab3e3a4",
			},
		},
		{
			From: matches,
			To:   file.NewCoordinates(matches.coordinatePathPrepend+"LICENSE", matches.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "1b0e913d41a66c988376898aa995d6c2f45bb50c",
			},
		},
		{
			From: matches,
			To:   file.NewCoordinates(matches.coordinatePathPrepend+"lib.rs", matches.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "c6329ef2162b8b59dd2bcda7402151c47a7cf99f",
			},
		},
		{
			From: matches,
			To:   file.NewCoordinates(matches.coordinatePathPrepend+"tests/macro_use_one.rs", matches.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "faad095b6182c15929020d79581661f1a331daa3",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+".cargo_vcs_info.json", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "41670cdd89868caeaf12ac151ba726121a7f2fcb",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+"CHANGELOG.md", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "736e12da4bf06f142c7815349fe4d9fc8d8a4e49",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+"Cargo.lock", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "8c0ff30a7c7d824d6b4ff72cbfcc47aeb5de42ba",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+"Cargo.toml", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "f6ee420b533c6a8b3682d1afe138e523c4cfb822",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+"Cargo.toml.orig", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "284301a6507e7701bad8c7b1606906ace5478600",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+"README.md", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "19f731ae277aad4a740b23e00354cb53ddb50864",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+"examples/simple.rs", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "7cd864d6183b46b0e21378aaae2ecb0abc8acdd3",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+"src/lib.rs", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "7d1e3bc6d8080e8f348d4690bdf6dc5d44b3c815",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+"src/platform_impl/macos.rs", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "b9cba69fa2902d2f6cc9b2319169fa5cf3975f05",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+"src/platform_impl/mod.rs", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "7aacdceafbe2c1bb920d6c84a685a354bacfd83d",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+"src/platform_impl/null.rs", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "ecd4209a6a4080a3c02bfd01c80f32a1c0251c66",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+"src/platform_impl/unix.rs", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "7010e6aad7fb9cbdc96bf384621816c0127276f8",
			},
		},
		{
			From: accesskit_winit,
			To:   file.NewCoordinates(accesskit_winit.coordinatePathPrepend+"src/platform_impl/windows.rs", accesskit_winit.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "6d80687a1b62767930efb8dffb4fa96452a77916",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+".github/workflows/ci.yml", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "987372cc6a27668c02b8e9a9fe68e767cd4c658c",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+".gitignore", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "556d32e5cb6dfbdbfc67e2dd06f948b76fe8b9d3",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+".ignore", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "e48305d030f8aebbe1a89fcb84f4ac19bb073975",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"COPYING", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "dd445710e6e4caccc4f8a587a130eaeebe83f6f6",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"Cargo.toml.orig", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "fe0739eacb9577f22fa4cd9c35096c2ac11ead76",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"Cargo.toml", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "395d46c2216bc3a5092b37c3dc7516566467dfd4",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"LICENSE-MIT", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "4c8990add9180fc59efa5b0d8faf643c9709501e",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"README.md", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "802d3bfea6ff17d5f082ecceb511913021390699",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"UNLICENSE", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "ff007ce11f3ff7964f1a5b04202c4e95b5c82c85",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"build.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "59fca6951275d4feba14c07109c4bb351da187d5",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"rustfmt.toml", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "558a7c72e415544f0b8790cd8c752690d0bc05c6",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/c.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "c75095493e42affe48a23e7de9c77c95ec139c7c",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/fallback.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "7f13c3502f300646a24e58172d99d78033e339b2",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/iter.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "b01cc89987d9c2f61baa97f7465ca2b81ce80b52",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/lib.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "35fac0bea520bfeb99197cfd97056bed99582ce2",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/naive.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "fcb709375bf7a20ddd97388982050d5d5da5f15f",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/tests/iter.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "daaf6a0b800563deb45227b2e7fb6fdae464ae84",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/tests/memchr.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "37f44dc29c8efb1d19eea6f2924a19ba86c14b3b",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/tests/miri.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "c6569d55c18255a52f5a75256f95167101d9dbeb",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/tests/mod.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "cdd9c0085ceccf76090bc327840e6a9315499acc",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/x86/avx.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "4bc56ed4faa1b026b399c169790a678b6af6a941",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/x86/mod.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "be8644c7bad1427b23436e6d5992c16e5129c216",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/x86/sse2.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "d2b640c77a0223812fa6a6f550e61ff4269320f0",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+"src/x86/sse42.rs", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "f053482427712918edf50aea0cb7e2fb95a2ccc1",
			},
		},
		{
			From: memchr,
			To:   file.NewCoordinates(memchr.coordinatePathPrepend+".cargo_vcs_info.json", memchr.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "b1ecb8751a0d53cccb6be606ede175736d51da04",
			},
		},
		{
			From: natord,
			To:   file.NewCoordinates(natord.coordinatePathPrepend+".gitignore", natord.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "3254b5d5538166f1fd5a0bb41f7f3d3bbd455c56",
			},
		},
		{
			From: natord,
			To:   file.NewCoordinates(natord.coordinatePathPrepend+".travis.yml", natord.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "4eadee39324e1cc0e156d4c1632fc417f9ed8a7e",
			},
		},
		{
			From: natord,
			To:   file.NewCoordinates(natord.coordinatePathPrepend+"Cargo.toml", natord.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "bffdbe1b6b2576ae1b17d4693545aa0145b435be",
			},
		},
		{
			From: natord,
			To:   file.NewCoordinates(natord.coordinatePathPrepend+"lib.rs", natord.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "83320272b3d922f5bed408d04fb18954c34958b0",
			},
		},
		{
			From: natord,
			To:   file.NewCoordinates(natord.coordinatePathPrepend+"LICENSE.txt", natord.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "bf18c5cc6c1db93eb4e2e95b11352e4660408fec",
			},
		},
		{
			From: natord,
			To:   file.NewCoordinates(natord.coordinatePathPrepend+"README.md", natord.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "c2958854fdc10329e409906292506d6e24dd78b5",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"CHANGELOG.md", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "48ba21326a9a3bdf1504a642a42cf7f84a0076e8",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"Cargo.toml.orig", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "c1d374941ff23392f409b933c799e849bd948b0e",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"Cargo.toml", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "e041d8ad32b719e9ab49c3f7f187d2902ea491f9",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"LICENSE", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "e7b32657d4608cb4a57afa790801ecb9c2a037f5",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"build.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "c59d60b5509a470ff9445c43ee414a029724504e",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/bits.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "419bf0a257199204fbf7e98ca2904eafd99f2264",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/branch.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "388f6ae6ce5d441dbe360bcc1be493315386e73a",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/bytes.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "483cae38a9eb9129e6a7958f1ca40be9d9bb2571",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/character.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "a7ec8cc1042501dced6c35f436342e865aac97be",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/internal.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "2ffaf19df16c691da9d250840d9fbdf56e2403bb",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/lib.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "39e4e967ce4a559fb08b3bb0d7b38f8c9429fe82",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/macros.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "39a24461edd8adc74a28c36d14699b0728e90f9d",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/methods.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "3b934d588ee14965b19d831efc7f0b63cf78e0a9",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/multi.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "098ba3b2faccdf3485491d88e521a3c9f5667ddc",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/nom.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "c74454752b17c2a7fa8abe398093617f8141f6f7",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/regexp.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "2875009ce9d7df6787d794a4a807a677a5f1e600",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/sequence.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "1a496dbd1094e93f1409bad30b31867a566de089",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/simple_errors.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "585ba0d774a4d6c48229f61e051368333ba16bf9",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/str.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "2e7303a42f0f31647c68c9b45c85e815c7c9d2f4",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/traits.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "74ca43bd49a2b81799dfef4b8fbecfd1f77884e9",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/types.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "3032dba26cddcd7018c0e48295e30ae403902d7e",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/util.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "fc1a7dc1250b692c5f849f2bfb6b84241eff9d0a",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/verbose_errors.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "4d5ee906c52b72080d8a6eee5a9227ab4e76506b",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"src/whitespace.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "2d5cb62bf4c5e7107d122f120603cc6c38c747be",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/arithmetic.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "a85ef14df0e37e9455b2543ed0d43c5f7a600a7d",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/arithmetic_ast.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "1b752396f083d8ea500a04ea0ce799b78ff42098",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/blockbuf-arithmetic.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "8b41afbcc779ce0410a1295b987b4340d30798b9",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/complete_arithmetic.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "be31008788ba4ba2f901ecbf5337e55f6c20828e",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/complete_float.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "c1e4b10c80c261842e808517d85f98bff6ca006a",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/css.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "a6bf483ae364c9820428c1b830e28c0e4eeddec3",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/custom_errors.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "41d94a408dfb23eed0142d7b9c982a4fdfbd293a",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/float.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "cbe19c77cd0b149198d610cbdb825a06d27c1ea4",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/inference.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "cee94e4224a72ceed0c21549ed2ef1341657fc32",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/ini.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "6c51af96426032b9f442caeab542b900b1128719",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/ini_str.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "aa971f48e78b79766deba7217dfca78a9b960855",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/issues.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "5f61b69052fad5b413d9e588ffecab8004849788",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/json.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "b45c8b0db154180350c34c2d2086fa355b1b45e5",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/mp4.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "7288433829b9b3f305761b240c8c9b60529f66a1",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/multiline.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "270c16ebaf0c3839e9ebe66cca28803fe64bbc05",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/named_args.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "f67ef99a7df44705eecf64de45f200c296ec4648",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/overflow.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "1ad7e1bdc3b070bd336680f39294f7400bf50d61",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/reborrow_fold.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "4ba89f2b42dcf803a2687b370c835e2134f11af1",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+"tests/test1.rs", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "f7c223208509242a9b66d9fbfaccc509d2a14bef",
			},
		},
		{
			From: nom,
			To:   file.NewCoordinates(nom.coordinatePathPrepend+".cargo_vcs_info.json", nom.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "93ede0fafa3ccca217787167b2a7a9c22cdf0b88",
			},
		},
		{
			From: version_check,
			To:   file.NewCoordinates(version_check.coordinatePathPrepend+".gitignore", version_check.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "3254b5d5538166f1fd5a0bb41f7f3d3bbd455c56",
			},
		},
		{
			From: version_check,
			To:   file.NewCoordinates(version_check.coordinatePathPrepend+"Cargo.toml.orig", version_check.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "fcdc047676e0857485f2834eeda27d97109e2438",
			},
		},
		{
			From: version_check,
			To:   file.NewCoordinates(version_check.coordinatePathPrepend+"Cargo.toml", version_check.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "00d6f82ce931ab8de090f799be41afa120f23da7",
			},
		},
		{
			From: version_check,
			To:   file.NewCoordinates(version_check.coordinatePathPrepend+"LICENSE-APACHE", version_check.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "5798832c31663cedc1618d18544d445da0295229",
			},
		},
		{
			From: version_check,
			To:   file.NewCoordinates(version_check.coordinatePathPrepend+"LICENSE-MIT", version_check.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "cfcb552ef0afbe7ccb4128891c0de00685988a4b",
			},
		},
		{
			From: version_check,
			To:   file.NewCoordinates(version_check.coordinatePathPrepend+"README.md", version_check.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "a88c576b3dc05d78012217f34a10fd9ae5a514da",
			},
		},
		{
			From: version_check,
			To:   file.NewCoordinates(version_check.coordinatePathPrepend+"src/lib.rs", version_check.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "0b69c0dba2824a1bfd0b3f3da71c21ec2e2795fa",
			},
		},
		{
			From: version_check,
			To:   file.NewCoordinates(version_check.coordinatePathPrepend+".cargo_vcs_info.json", version_check.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "c2cbaa20212e0f8eb1e2d1875be2a17d5ab223c2",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+".appveyor.yml", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "e6a4b71b2e461d29891f693815fb8d946a468dd5",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+".gitignore", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "49b13a4aa553694185bb35d9ba508e55545ccb5c",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+".rustfmt.toml", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "76a81d84fe870ade0d22f3e952a61d0d75eb5a87",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+".travis.yml", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "e4acfec5e6f3afef42e8461a15a02348abd5d741",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"AUTHORS", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "05bb8f0c2d2c480ab371dfbc7d58cc44b9184403",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"COPYRIGHT", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "871b9912ab96cf7d79cb8ae83ca0b08cd5d0cbfd",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"Cargo.toml.orig", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "51dcdeeaa5e96a9b02471b6ba8a1fdd08ec6aa03",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"Cargo.toml", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "f6b0f63bf80d80eb4d5df44f3c6d77947a930acb",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"LICENSE-APACHE", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "5798832c31663cedc1618d18544d445da0295229",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"LICENSE-MIT", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "60c3522081bf15d7ac1d4c5a63de425ef253e87a",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"README.md", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "78d6f25691fa623f950efdf9d2a9aae129e30e2d",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"src/char_data/mod.rs", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "7a08a46193d71df15da9d900c339a4dbce0a5f45",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"src/char_data/tables.rs", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "e495d79981929f5bb2f0457d452de8a4b52f6666",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"src/deprecated.rs", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "43ac5028a8f1d5ddba76822147fb363ef0222601",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"src/explicit.rs", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "eed6c9865990a33498339e5f0fe9ba63352d08f1",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"src/format_chars.rs", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "468f7b50f5a290b6bdbb0707381dfb5a61e90012",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"src/implicit.rs", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "1a47012f5da712a4f8d0418a54b93ac5e011cece",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"src/level.rs", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "c9fabd87fb706e9ea6aa9bbfcff00cad11efae07",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"src/lib.rs", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "7ea0fb0b66115b1ec766a9ad90b937496e6610ae",
			},
		},
		{
			From: unicode_bidi,
			To:   file.NewCoordinates(unicode_bidi.coordinatePathPrepend+"src/prepare.rs", unicode_bidi.downloadLocation),
			Type: artifact.ContainsRelationship,
			Data: file.Digest{
				Algorithm: "sha1",
				Value:     "5030d5cbb328b1f04b79879ee8a455609b79f209",
			},
		},
		{
			From: matches.Package,
			To:   unicode_bidi.Package,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: memchr.Package,
			To:   nom.Package,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: version_check.Package,
			To:   nom.Package,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseCargoLock, expectedPkgs, expectedRelationships)
	//pkgtest.NewCatalogTester().WithCompareOptions(cm).FromFile(t, fixture).Expects(expectedPkgs, expectedRelationships).TestParser(t, parseCargoLock)

}
