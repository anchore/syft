package beam

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParseMixLock(t *testing.T) {
	expected := []*pkg.Package{
		{
			Name:     "castore",
			Version:  "0.1.17",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "connection",
			Version:  "1.1.0",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "cowboy",
			Version:  "2.9.0",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "cowboy_telemetry",
			Version:  "0.4.0",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "cowlib",
			Version:  "2.11.0",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "db_connection",
			Version:  "2.4.2",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "decimal",
			Version:  "2.0.0",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "earmark_parser",
			Version:  "1.4.25",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "ecto",
			Version:  "3.8.1",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "ecto_sql",
			Version:  "3.8.1",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "esbuild",
			Version:  "0.5.0",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "ex_doc",
			Version:  "0.28.4",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "gettext",
			Version:  "0.19.1",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "hpax",
			Version:  "0.1.1",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
		{
			Name:     "jason",
			Version:  "1.3.0",
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		},
	}

	fixture, err := os.Open("test-fixtures/mix.lock")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseMixLock(fixture.Name(), fixture)
	if err != nil {
		t.Error(err)
	}

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
