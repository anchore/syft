//go:build gorules

package rules

import "github.com/quasilyte/go-ruleguard/dsl"

// nolint:unused
func resourceCleanup(m dsl.Matcher) {
	m.Match(`$res, $err := $resolver.FileContentsByLocation($*_); if $*_ { $*_ }; $next`).
		Where(m["res"].Type.Implements(`io.Closer`) &&
			m["err"].Type.Implements(`error`) &&
			m["res"].Type.Implements(`io.Closer`) &&
			!m["next"].Text.Matches(`defer internal.CloseAndLogError`)).
		Report(`internal.CloseAndLogError should be deferred right after the error returned from $resolver.FileContentsByLocation is checked.`)
}
