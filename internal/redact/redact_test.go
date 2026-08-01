package redact

import (
	"testing"

	gologgerredact "github.com/anchore/go-logger/adapter/redact"
	"github.com/stretchr/testify/assert"
)

// TestSet_ReplacingExistingStoreDoesNotPanic is a regression test for
// https://github.com/anchore/syft/issues/2285: library consumers that
// construct and execute a syft command more than once in the same process
// (e.g. https://github.com/anchore/syft/blob/main/cmd/syft/internal/clio_setup_config.go
// calling redact.Set on every clio initializer run) used to panic on the
// second call, because Set refused to replace an already-set store.
func TestSet_ReplacingExistingStoreDoesNotPanic(t *testing.T) {
	orig := store
	defer func() { store = orig }()

	Set(gologgerredact.NewStore())
	Add("first-secret")
	assert.Equal(t, "prefix ******* suffix", Apply("prefix first-secret suffix"))

	assert.NotPanics(t, func() {
		Set(gologgerredact.NewStore())
	})

	// the replaced store doesn't carry over redactions registered before the swap
	assert.Equal(t, "prefix first-secret suffix", Apply("prefix first-secret suffix"))

	// but works normally going forward
	Add("second-secret")
	assert.Equal(t, "prefix ******* suffix", Apply("prefix second-secret suffix"))
}
