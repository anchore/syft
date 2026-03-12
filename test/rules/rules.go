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
func noUnboundedReads(m dsl.Matcher) {
	// flag io.ReadAll where the argument is not already wrapped in io.LimitReader
	m.Match(`io.ReadAll($reader)`).
		Where(!m["reader"].Text.Matches(`(?i)LimitReader|LimitedReader`)).
		Report("do not use unbounded io.ReadAll; wrap the reader with io.LimitReader or use a streaming parser")

	// flag io.Copy only when the destination is an in-memory buffer
	// io.Copy to files, hash writers, encoders, etc. is streaming and safe
	m.Match(`io.Copy($dst, $src)`).
		Where((m["dst"].Type.Is(`*bytes.Buffer`) || m["dst"].Type.Is(`*strings.Builder`)) && !m["src"].Text.Matches(`(?i)LimitReader|LimitedReader`)).
		Report("do not use unbounded io.Copy to in-memory buffer; wrap the source reader with io.LimitReader")
}

// nolint:unused
func noDirectTempFiles(m dsl.Matcher) {
	// catalogers must use tmpdir.FromContext(ctx) instead of creating temp files/dirs directly,
	// so that all temp storage is centrally managed and cleaned up
	m.Match(
		`os.CreateTemp($*_)`,
		`os.MkdirTemp($*_)`,
	).
		Where(m.File().PkgPath.Matches(`/cataloger/`)).
		Report("do not use os.CreateTemp/os.MkdirTemp in catalogers; use tmpdir.FromContext(ctx) instead")
}

// nolint:unused
func tmpCleanupDeferred(m dsl.Matcher) {
	// ensure the cleanup function returned by NewFile/NewChild is deferred, not discarded
	m.Match(
		`$_, $cleanup, $err := $x.NewFile($*_); if $*_ { $*_ }; $next`,
		`$_, $cleanup, $err = $x.NewFile($*_); if $*_ { $*_ }; $next`,
	).
		Where(!m["next"].Text.Matches(`^defer `)).
		Report("defer the cleanup function returned by NewFile immediately after the error check")

	m.Match(
		`$_, $cleanup, $err := $x.NewChild($*_); if $*_ { $*_ }; $next`,
		`$_, $cleanup, $err = $x.NewChild($*_); if $*_ { $*_ }; $next`,
	).
		Where(!m["next"].Text.Matches(`^defer `)).
		Report("defer the cleanup function returned by NewChild immediately after the error check")
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
