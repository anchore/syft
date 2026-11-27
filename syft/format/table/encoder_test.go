package table

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/go-test/deep"
	"github.com/muesli/termenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal/testutil"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

var updateSnapshot = flag.Bool("update-table", false, "update the *.golden files for table format")

func TestTableEncoder(t *testing.T) {
	testutil.AssertEncoderAgainstGoldenSnapshot(t,
		testutil.EncoderSnapshotTestConfig{
			Subject:                     testutil.DirectoryInput(t, t.TempDir()),
			Format:                      NewFormatEncoder(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
		},
	)
}

func TestTableEncoder_noANSIWhenWritingToFile(t *testing.T) {
	// simulate a process whose stdout is a color-capable terminal
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(termenv.Ascii) })

	s := sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(
		pkg.Package{Name: "a", Version: "1", Type: pkg.GemPkg, Locations: file.NewLocationSet(file.NewLocation("/one"))},
		pkg.Package{Name: "a", Version: "1", Type: pkg.GemPkg, Locations: file.NewLocationSet(file.NewLocation("/two"))},
		pkg.Package{Name: "b", Version: "1", Type: pkg.GemPkg},
	)}}

	f, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	require.NoError(t, err)
	defer f.Close()

	require.NoError(t, NewFormatEncoder().Encode(f, s))

	got, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	assert.Contains(t, string(got), "(+1 duplicate)")
	assert.NotContains(t, string(got), "\x1b[")
}

func Test_markDuplicateRows(t *testing.T) {
	data := [][]string{
		{"1", "2", "3"},
		{"a", "b", "c"},
		{"1", "2", "3"},
		{"a", "b", "c"},
		{"1", "2", "3"},
		{"4", "5", "6"},
		{"1", "2", "1"},
	}

	expected := [][]string{
		{"1", "2", "3", "(+2 duplicates)"},
		{"a", "b", "c", "(+1 duplicate)"},
		{"4", "5", "6", ""},
		{"1", "2", "1", ""},
	}

	actual := markDuplicateRows(data, lipgloss.DefaultRenderer())

	if diffs := deep.Equal(expected, actual); len(diffs) > 0 {
		t.Errorf("found diffs!")
		for _, d := range diffs {
			t.Errorf("   diff: %+v", d)
		}
	}

}
