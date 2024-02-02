package commands

import (
	"os"
	"testing"

	gologgerredact "github.com/anchore/go-logger/adapter/redact"
	"github.com/anchore/syft/internal/redact"
)

func TestMain(m *testing.M) {
	// Initialize global state needed to test clio/cobra commands directly
	// Should be kept minimal.

	// Initialize redact store once for all tests in the commands package
	// Redact store must be wired up here because syft will panic unless
	// a redact store is wired up exactly once
	redact.Set(gologgerredact.NewStore())
	os.Exit(m.Run())
}
