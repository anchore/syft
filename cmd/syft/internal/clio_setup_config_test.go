package internal

import (
	"io"
	"testing"

	"github.com/anchore/clio"
	"github.com/anchore/go-logger/adapter/discard"
	gologgerredact "github.com/anchore/go-logger/adapter/redact"
	"github.com/stretchr/testify/require"
)

func TestAppClioSetupConfigInitializerCanRunMultipleTimes(t *testing.T) {
	// https://github.com/anchore/syft/issues/2285
	// cli.Command() may be invoked more than once in the same process (e.g.
	// when syft is embedded as a library). Each invocation re-runs the clio
	// initializers; the redact store is process-global, so the second run
	// used to panic in internal/redact.Set with
	// "replace existing redaction store (probably unintentional)".
	cfg := AppClioSetupConfig(clio.Identification{Name: "syft"}, io.Discard)
	require.Len(t, cfg.Initializers, 1)

	state := &clio.State{
		Logger:      discard.New(),
		RedactStore: gologgerredact.NewStore(),
	}
	// First command execution.
	require.NoError(t, cfg.Initializers[0](state))
	// Second command execution in the same process.
	require.NoError(t, cfg.Initializers[0](state))
}
