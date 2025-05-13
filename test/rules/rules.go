//go:build gorules

package rules

import (
	"strings"

	"github.com/quasilyte/go-ruleguard/dsl"
)

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
	m.Import("github.com/anchore/syft/syft/artifact")

	isRelationship := func(m dsl.Matcher) bool {
		return m["x"].Type.Is("artifact.Relationship")
	}

	hasPointerType := func(m dsl.Matcher) bool {
		return m["y"].Filter(isPtr)
	}

	// this rule defends against using pointers as values in artifact.Relationship
	m.Match(
		`$x{$*_, From: $y, $*_}`,
		`$x{$*_, To: $y, $*_}`,
		`$x.From = $y`,
		`$x.To = $y`,
	).
		Where(isRelationship(m) && hasPointerType(m)).
		Report("pointer used as a value for From/To field in artifact.Relationship (use values instead)")
}
