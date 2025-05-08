package cpp

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseConanLock(t *testing.T) {
	fixture := "test-fixtures/conan.lock"
	expected := []pkg.Package{
		{
			Name:      "mfast",
			Version:   "1.2.2",
			PURL:      "pkg:conan/my_user/mfast@1.2.2?channel=my_channel",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanV1LockEntry{
				Ref: "mfast/1.2.2@my_user/my_channel#c6f6387c9b99780f0ee05e25f99d0f39",
				Options: pkg.KeyValues{
					{Key: "fPIC", Value: "True"},
					{Key: "shared", Value: "False"},
					{Key: "with_sqlite3", Value: "False"},
					{Key: "boost:addr2line_location", Value: "/usr/bin/addr2line"},
					{Key: "boost:asio_no_deprecated", Value: "False"},
					{Key: "boost:buildid", Value: "None"},
					{Key: "boost:bzip2", Value: "True"},
					{Key: "boost:debug_level", Value: "0"},
					{Key: "boost:diagnostic_definitions", Value: "False"},
					{Key: "boost:error_code_header_only", Value: "False"},
					{Key: "boost:extra_b2_flags", Value: "None"},
					{Key: "boost:fPIC", Value: "True"},
					{Key: "boost:filesystem_no_deprecated", Value: "False"},
					{Key: "boost:header_only", Value: "False"},
					{Key: "boost:i18n_backend", Value: "deprecated"},
					{Key: "boost:i18n_backend_iconv", Value: "libc"},
					{Key: "boost:i18n_backend_icu", Value: "False"},
					{Key: "boost:layout", Value: "system"},
					{Key: "boost:lzma", Value: "False"},
					{Key: "boost:magic_autolink", Value: "False"},
					{Key: "boost:multithreading", Value: "True"},
					{Key: "boost:namespace", Value: "boost"},
					{Key: "boost:namespace_alias", Value: "False"},
					{Key: "boost:numa", Value: "True"},
					{Key: "boost:pch", Value: "True"},
					{Key: "boost:python_executable", Value: "None"},
					{Key: "boost:python_version", Value: "None"},
					{Key: "boost:segmented_stacks", Value: "False"},
					{Key: "boost:shared", Value: "False"},
					{Key: "boost:system_no_deprecated", Value: "False"},
					{Key: "boost:system_use_utf8", Value: "False"},
					{Key: "boost:visibility", Value: "hidden"},
					{Key: "boost:with_stacktrace_backtrace", Value: "True"},
					{Key: "boost:without_atomic", Value: "False"},
					{Key: "boost:without_chrono", Value: "False"},
					{Key: "boost:without_container", Value: "False"},
					{Key: "boost:without_context", Value: "False"},
					{Key: "boost:without_contract", Value: "False"},
					{Key: "boost:without_coroutine", Value: "False"},
					{Key: "boost:without_date_time", Value: "False"},
					{Key: "boost:without_exception", Value: "False"},
					{Key: "boost:without_fiber", Value: "False"},
					{Key: "boost:without_filesystem", Value: "False"},
					{Key: "boost:without_graph", Value: "False"},
					{Key: "boost:without_graph_parallel", Value: "True"},
					{Key: "boost:without_iostreams", Value: "False"},
					{Key: "boost:without_json", Value: "False"},
					{Key: "boost:without_locale", Value: "False"},
					{Key: "boost:without_log", Value: "False"},
					{Key: "boost:without_math", Value: "False"},
					{Key: "boost:without_mpi", Value: "True"},
					{Key: "boost:without_nowide", Value: "False"},
					{Key: "boost:without_program_options", Value: "False"},
					{Key: "boost:without_python", Value: "True"},
					{Key: "boost:without_random", Value: "False"},
					{Key: "boost:without_regex", Value: "False"},
					{Key: "boost:without_serialization", Value: "False"},
					{Key: "boost:without_stacktrace", Value: "False"},
					{Key: "boost:without_system", Value: "False"},
					{Key: "boost:without_test", Value: "False"},
					{Key: "boost:without_thread", Value: "False"},
					{Key: "boost:without_timer", Value: "False"},
					{Key: "boost:without_type_erasure", Value: "False"},
					{Key: "boost:without_wave", Value: "False"},
					{Key: "boost:zlib", Value: "True"},
					{Key: "boost:zstd", Value: "False"},
					{Key: "bzip2:build_executable", Value: "True"},
					{Key: "bzip2:fPIC", Value: "True"},
					{Key: "bzip2:shared", Value: "False"},
					{Key: "libbacktrace:fPIC", Value: "True"},
					{Key: "libbacktrace:shared", Value: "False"},
					{Key: "tinyxml2:fPIC", Value: "True"},
					{Key: "tinyxml2:shared", Value: "False"},
					{Key: "zlib:fPIC", Value: "True"},
					{Key: "zlib:shared", Value: "False"},
				},
				Context:   "host",
				PackageID: "9d1f076b471417647c2022a78d5e2c1f834289ac",
				Prev:      "0ca9799450422cc55a92ccc6ffd57fba",
			},
		},
		{
			Name:      "boost",
			Version:   "1.75.0",
			PURL:      "pkg:conan/boost@1.75.0",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanV1LockEntry{
				Ref: "boost/1.75.0#a9c318f067216f900900e044e7af4ab1",
				Options: pkg.KeyValues{
					{Key: "addr2line_location", Value: "/usr/bin/addr2line"},
					{Key: "asio_no_deprecated", Value: "False"},
					{Key: "buildid", Value: "None"},
					{Key: "bzip2", Value: "True"},
					{Key: "debug_level", Value: "0"},
					{Key: "diagnostic_definitions", Value: "False"},
					{Key: "error_code_header_only", Value: "False"},
					{Key: "extra_b2_flags", Value: "None"},
					{Key: "fPIC", Value: "True"},
					{Key: "filesystem_no_deprecated", Value: "False"},
					{Key: "header_only", Value: "False"},
					{Key: "i18n_backend", Value: "deprecated"},
					{Key: "i18n_backend_iconv", Value: "libc"},
					{Key: "i18n_backend_icu", Value: "False"},
					{Key: "layout", Value: "system"},
					{Key: "lzma", Value: "False"},
					{Key: "magic_autolink", Value: "False"},
					{Key: "multithreading", Value: "True"},
					{Key: "namespace", Value: "boost"},
					{Key: "namespace_alias", Value: "False"},
					{Key: "numa", Value: "True"},
					{Key: "pch", Value: "True"},
					{Key: "python_executable", Value: "None"},
					{Key: "python_version", Value: "None"},
					{Key: "segmented_stacks", Value: "False"},
					{Key: "shared", Value: "False"},
					{Key: "system_no_deprecated", Value: "False"},
					{Key: "system_use_utf8", Value: "False"},
					{Key: "visibility", Value: "hidden"},
					{Key: "with_stacktrace_backtrace", Value: "True"},
					{Key: "without_atomic", Value: "False"},
					{Key: "without_chrono", Value: "False"},
					{Key: "without_container", Value: "False"},
					{Key: "without_context", Value: "False"},
					{Key: "without_contract", Value: "False"},
					{Key: "without_coroutine", Value: "False"},
					{Key: "without_date_time", Value: "False"},
					{Key: "without_exception", Value: "False"},
					{Key: "without_fiber", Value: "False"},
					{Key: "without_filesystem", Value: "False"},
					{Key: "without_graph", Value: "False"},
					{Key: "without_graph_parallel", Value: "True"},
					{Key: "without_iostreams", Value: "False"},
					{Key: "without_json", Value: "False"},
					{Key: "without_locale", Value: "False"},
					{Key: "without_log", Value: "False"},
					{Key: "without_math", Value: "False"},
					{Key: "without_mpi", Value: "True"},
					{Key: "without_nowide", Value: "False"},
					{Key: "without_program_options", Value: "False"},
					{Key: "without_python", Value: "True"},
					{Key: "without_random", Value: "False"},
					{Key: "without_regex", Value: "False"},
					{Key: "without_serialization", Value: "False"},
					{Key: "without_stacktrace", Value: "False"},
					{Key: "without_system", Value: "False"},
					{Key: "without_test", Value: "False"},
					{Key: "without_thread", Value: "False"},
					{Key: "without_timer", Value: "False"},
					{Key: "without_type_erasure", Value: "False"},
					{Key: "without_wave", Value: "False"},
					{Key: "zlib", Value: "True"},
					{Key: "zstd", Value: "False"},
					{Key: "bzip2:build_executable", Value: "True"},
					{Key: "bzip2:fPIC", Value: "True"},
					{Key: "bzip2:shared", Value: "False"},
					{Key: "libbacktrace:fPIC", Value: "True"},
					{Key: "libbacktrace:shared", Value: "False"},
					{Key: "zlib:fPIC", Value: "True"},
					{Key: "zlib:shared", Value: "False"},
				},
				Context:   "host",
				PackageID: "dc8aedd23a0f0a773a5fcdcfe1ae3e89c4205978",
				Prev:      "b9d7912e6131dfa453c725593b36c808",
			},
		},
		{
			Name:      "zlib",
			Version:   "1.2.12",
			PURL:      "pkg:conan/zlib@1.2.12",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanV1LockEntry{
				Ref: "zlib/1.2.12#c67ce17f2e96b972d42393ce50a76a1a",
				Options: pkg.KeyValues{
					{
						Key:   "fPIC",
						Value: "True",
					},
					{
						Key:   "shared",
						Value: "False",
					},
				},
				Context:   "host",
				PackageID: "dfbe50feef7f3c6223a476cd5aeadb687084a646",
				Prev:      "7cd359d44f89ab08e33b5db75605002c",
			},
		},
		{
			Name:      "bzip2",
			Version:   "1.0.8",
			PURL:      "pkg:conan/bzip2@1.0.8",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanV1LockEntry{
				Ref: "bzip2/1.0.8#62a8031289639043797cf53fa876d0ef",
				Options: []pkg.KeyValue{
					{
						Key:   "build_executable",
						Value: "True",
					},
					{
						Key:   "fPIC",
						Value: "True",
					},
					{
						Key:   "shared",
						Value: "False",
					},
				},
				Context:   "host",
				PackageID: "c32092bf4d4bb47cf962af898e02823f499b017e",
				Prev:      "b746948bc999d6f17f52a1f76e729e80",
			},
		},
		{
			Name:      "libbacktrace",
			Version:   "cci.20210118",
			PURL:      "pkg:conan/libbacktrace@cci.20210118",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanV1LockEntry{
				Ref: "libbacktrace/cci.20210118#76e40b760e0bcd602d46db56b22820ab",
				Options: []pkg.KeyValue{
					{
						Key:   "fPIC",
						Value: "True",
					},
					{
						Key:   "shared",
						Value: "False",
					},
				},
				Context:   "host",
				PackageID: "dfbe50feef7f3c6223a476cd5aeadb687084a646",
				Prev:      "98a976f017e894c27e9a158b807ec0c7",
			},
		},
		{
			Name:      "tinyxml2",
			Version:   "9.0.0",
			PURL:      "pkg:conan/tinyxml2@9.0.0",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanV1LockEntry{
				Ref: "tinyxml2/9.0.0#9f13a36ebfc222cd55fe531a0a8d94d1",
				Options: []pkg.KeyValue{
					{
						Key:   "fPIC",
						Value: "True",
					},
					{
						Key:   "shared",
						Value: "False",
					},
				},
				Context: "host",
				// intentionally remove to test missing PackageID and Prev
				// PackageID: "6557f18ca99c0b6a233f43db00e30efaa525e27e",
				// Prev:      "548bb273d2980991baa519453d68e5cd",
			},
		},
	}

	// relationships require IDs to be set to be sorted similarly
	for i := range expected {
		expected[i].SetID()
	}

	var expectedRelationships = []artifact.Relationship{
		{
			From: expected[1], // boost
			To:   expected[0], // mfast
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: expected[5], // tinyxml2
			To:   expected[0], // mfast
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: expected[2], // zlib
			To:   expected[1], // boost
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: expected[3], // bzip2
			To:   expected[1], // boost
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: expected[4], // libbacktrace
			To:   expected[1], // boost
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseConanLock, expected, expectedRelationships)
}

func TestParseConanLockV2(t *testing.T) {
	fixture := "test-fixtures/conanlock-v2/conan.lock"
	expected := []pkg.Package{
		{
			Name:      "matrix",
			Version:   "1.1",
			PURL:      "pkg:conan/matrix@1.1",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanV2LockEntry{
				Ref:            "matrix/1.1#905c3f0babc520684c84127378fefdd0%1675278901.7527816",
				RecipeRevision: "905c3f0babc520684c84127378fefdd0",
				TimeStamp:      "1675278901.7527816",
			},
		},
		{
			Name:      "sound32",
			Version:   "1.0",
			PURL:      "pkg:conan/sound32@1.0",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanV2LockEntry{
				Ref:            "sound32/1.0#83d4b7bf607b3b60a6546f8b58b5cdd7%1675278904.0791488",
				RecipeRevision: "83d4b7bf607b3b60a6546f8b58b5cdd7",
				TimeStamp:      "1675278904.0791488",
			},
		},
	}

	// relationships require IDs to be set to be sorted similarly
	for i := range expected {
		expected[i].SetID()
	}

	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseConanLock, expected, expectedRelationships)
}

func Test_corruptConanlock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/conan.lock").
		WithError().
		TestParser(t, parseConanLock)
}
