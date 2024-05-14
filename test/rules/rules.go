//go:build gorules

package rules

import (
	"strings"

	"github.com/quasilyte/go-ruleguard/dsl"
)

type Relationship struct {
	From any
	To   any
	Type string
	Data any
}

// nolint:unused
func resourceCleanup(m dsl.Matcher) {
	// this rule defends against use of internal.CloseAndLogError() without a defer statement
	m.Match(`$res, $err := $resolver.FileContentsByLocation($loc); if $*_ { $*_ }; $next`).
		Where(m["res"].Type.Implements(`io.Closer`) &&
			m["res"].Type.Implements(`io.Reader`) &&
			m["err"].Type.Implements(`error`) &&
			!m["next"].Text.Matches(`defer internal.CloseAndLogError`)).
		Report(`please call "defer internal.CloseAndLogError($res, $loc.RealPath)" right after checking the error returned from $resolver.FileContentsByLocation.`)
}

// nolint:unused
func isPtr(ctx *dsl.VarFilterContext) bool {
	return strings.HasPrefix(ctx.Type.String(), "*") || strings.HasPrefix(ctx.Type.Underlying().String(), "*")
}

// nolint:unused
func packagesInRelationshipsAsValues(m dsl.Matcher) {
	// this rule defends against using pointers as values in artifact.Relationship
	m.Match(
		`$x.From = $y`, `$x.To = $y`,
		`$x.From = &$y`, `$x.To = &$y`,
		`artifact.Relationship{From: $y, $*_}`,
		`artifact.Relationship{To: $y, $*_}`,
	).
		Where(m["y"].Filter(isPtr)).
		Report("pointer used as a value for From/To field in artifact.Relationship")
}
