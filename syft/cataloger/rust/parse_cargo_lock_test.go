package rust

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParseCargoLock(t *testing.T) {
	expected := []pkg.Package{
		{
			Name:     "ansi_term",
			Version:  "0.12.1",
			Language: pkg.Rust,
			Type:     pkg.RustPkg,
			Licenses: nil,
		},
		{
			Name:     "matches",
			Version:  "0.1.8",
			Language: pkg.Rust,
			Type:     pkg.RustPkg,
			Licenses: nil,
		},
		{
			Name:     "memchr",
			Version:  "2.3.3",
			Language: pkg.Rust,
			Type:     pkg.RustPkg,
			Licenses: nil,
		},
		{
			Name:     "natord",
			Version:  "1.0.9",
			Language: pkg.Rust,
			Type:     pkg.RustPkg,
			Licenses: nil,
		},
		{
			Name:     "nom",
			Version:  "4.2.3",
			Language: pkg.Rust,
			Type:     pkg.RustPkg,
			Licenses: nil,
		},
		{
			Name:     "unicode-bidi",
			Version:  "0.3.4",
			Language: pkg.Rust,
			Type:     pkg.RustPkg,
			Licenses: nil,
		},
		{
			Name:     "version_check",
			Version:  "0.1.5",
			Language: pkg.Rust,
			Type:     pkg.RustPkg,
			Licenses: nil,
		},
		{
			Name:     "winapi",
			Version:  "0.3.9",
			Language: pkg.Rust,
			Type:     pkg.RustPkg,
			Licenses: nil,
		},
		{
			Name:     "winapi-i686-pc-windows-gnu",
			Version:  "0.4.0",
			Language: pkg.Rust,
			Type:     pkg.RustPkg,
			Licenses: nil,
		},
		{
			Name:     "winapi-x86_64-pc-windows-gnu",
			Version:  "0.4.0",
			Language: pkg.Rust,
			Type:     pkg.RustPkg,
			Licenses: nil,
		},
	}

	fixture, err := os.Open("test-fixtures/Cargo.lock")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, err := parseCargoLock(fixture.Name(), fixture)
	if err != nil {
		t.Error(err)
	}

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
