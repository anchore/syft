package table

import (
	"flag"
	"testing"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/format/internal/testutil"
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

	actual := markDuplicateRows(data)

	if diffs := deep.Equal(expected, actual); len(diffs) > 0 {
		t.Errorf("found diffs!")
		for _, d := range diffs {
			t.Errorf("   diff: %+v", d)
		}
	}

}
