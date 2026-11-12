package internal

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/go-logger/adapter/discard"
	gologgerredact "github.com/anchore/go-logger/adapter/redact"
	"github.com/anchore/syft/internal/redact"
)

func TestAppClioSetupConfigInitializerPanicsWhileRunInFlight(t *testing.T) {
	t.Cleanup(redact.Reset)

	cfg := AppClioSetupConfig(clio.Identification{Name: "syft"}, io.Discard)
	require.Len(t, cfg.Initializers, 1)

	newState := func() *clio.State {
		return &clio.State{Logger: discard.New(), RedactStore: gologgerredact.NewStore()}
	}

	require.NoError(t, cfg.Initializers[0](newState()))

	// a second run starting before the first has finished must not silently replace the store, otherwise
	// secrets added to the first store would no longer be redacted
	require.PanicsWithValue(t, "replace existing redaction store (probably unintentional)", func() {
		_ = cfg.Initializers[0](newState())
	})
}
