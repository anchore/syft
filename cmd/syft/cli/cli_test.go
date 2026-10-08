package cli

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/redact"
)

func TestCommandCanRunMultipleTimes(t *testing.T) {
	// https://github.com/anchore/syft/issues/2285
	t.Cleanup(redact.Reset)

	for i := 0; i < 2; i++ {
		_, cmd := create(clio.Identification{Name: "syft"}, io.Discard)
		cmd.SetArgs([]string{"cataloger", "list", "-o", "json"})
		require.NoError(t, cmd.Execute())

		// the store is released at the end of each run so the next one can set its own
		require.Nil(t, redact.Get())
	}
}
