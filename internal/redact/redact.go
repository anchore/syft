package redact

import "github.com/anchore/go-logger/adapter/redact"

var store redact.Store

// Set replaces the package-level redaction store. Library consumers that construct and execute a syft
// command more than once within the same process (each call getting its own fresh clio state, and thus
// its own redaction store) will legitimately call Set again; that's expected and simply swaps in the new
// store, consistent with how the sibling bus and log singleton packages behave on repeated Set calls.
// Redactions added to a store before it's replaced no longer apply to output produced afterwards.
func Set(s redact.Store) {
	store = s
}

func Get() redact.Store {
	return store
}

func Add(vs ...string) {
	if store == nil {
		// if someone is trying to add values that should never be output and we don't have a store then something is wrong.
		// we should never accidentally output values that should be redacted, thus we panic here.
		panic("cannot add redactions without a store")
	}
	store.Add(vs...)
}

func Apply(value string) string {
	if store == nil {
		// if someone is trying to add values that should never be output and we don't have a store then something is wrong.
		// we should never accidentally output values that should be redacted, thus we panic here.
		panic("cannot apply redactions without a store")
	}
	return store.RedactString(value)
}
