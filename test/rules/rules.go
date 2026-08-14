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
func noUnboundedAllocations(m dsl.Matcher) {
	// a make() length that is not a plain int almost always came off the wire: a size or count field
	// read out of a binary header, an archive record, or a length-prefixed frame. Those are
	// attacker-controlled, so a small crafted file can reserve gigabytes before a single byte is read.
	// Lengths from len() or from a constant are plain int / untyped const and do not match.
	m.Match(
		`make([]$_, $n)`,
		`make([]$_, $_, $n)`,
		`make(map[$_]$_, $n)`,
	).
		Where(!m["n"].Const && m["n"].Type.OfKind("integer") && !m["n"].Type.Is("int") && m["n"].Type.Size >= 4).
		Report("unbounded allocation: $n is not a plain int, so it likely comes from parsed input. read with io.ReadAll(io.LimitReader(r, n)) so the buffer grows to what the input actually holds, or clamp $n against the real file size before allocating")
}

// nolint:unused
func noUnboundedDecompression(m dsl.Matcher) {
	m.Import("github.com/mholt/archives")

	// compression ratios are unbounded (gzip does ~1032:1), so a decompressed stream must be capped
	// independently of the compressed input, which is already bounded by the file it came from.
	// The constructor is flagged rather than the consumer because the consumer is often a
	// third-party decoder that buffers the whole stream before parsing any of it.
	m.Match(
		`gzip.NewReader($_)`,
		`zlib.NewReader($_)`,
		`flate.NewReader($_)`,
		`bzip2.NewReader($_)`,
		`lzma.NewReader($_)`,
		`xz.NewReader($_)`,
	).
		Where(m.File().PkgPath.Matches(`/cataloger/`)).
		Report("unbounded decompression in a cataloger: wrap the decompressed stream in io.LimitReader before anything consumes it, or nolint with the bound that already applies. Note that a byte limit bounds the input, not what the consumer retains: a parser that keeps an object per line still needs a count bound")

	// the mholt/archives decompressors reach the same stdlib readers a layer down, so a site using them
	// is exactly as unbounded while matching none of the constructors above
	m.Match(`$d.OpenReader($_)`).
		Where(m.File().PkgPath.Matches(`/cataloger/`) &&
			m["d"].Type.Implements(`archives.Decompressor`)).
		Report("unbounded decompression in a cataloger: $d.OpenReader returns a stream with no ceiling. bound it before anything consumes it, or nolint with the bound that already applies")
}

// nolint:unused
func noOverflowingBoundsCheck(m dsl.Matcher) {
	// an offset+size bounds check on unsigned operands wraps rather than saturating, so a large
	// offset out of a file header can produce a small sum and pass a check it should have failed.
	// Written as a subtraction against the limit, there is nothing to wrap.
	m.Match(
		`$offset + $size > $limit`,
		`$offset + $size >= $limit`,
		`$offset + $size < $limit`,
		`$offset + $size <= $limit`,
	).
		Where((m["offset"].Type.OfKind("unsigned") || m["size"].Type.OfKind("unsigned")) &&
			// a constant addend cannot be attacker-controlled, which is the common safe shape of
			// stepping a loop cursor (`pos+4 <= uint32(len(buf))`)
			!m["offset"].Const && !m["size"].Const).
		Report("bounds check can overflow: $offset + $size wraps on unsigned operands. write it as a subtraction against the limit instead, e.g. `$offset > $limit || $size > $limit-$offset`")
}

// nolint:unused
func noSwallowedEOF(m dsl.Matcher) {
	// treating EOF as success hands the caller a zero value it cannot distinguish from real data. In a
	// loop that advances by however much was read, that is not just bad data but a cursor that never
	// moves, so a truncated record spins forever.
	m.Match(
		`if errors.Is($err, io.EOF) { return nil }`,
		`if errors.Is($err, io.EOF) { return nil, nil }`,
		`if $err == io.EOF { return nil }`,
		`if $err == io.EOF { return nil, nil }`,
	).
		Report("EOF returned as success: the caller gets a zero value it cannot tell from real data. return the error, or return an explicit sentinel the caller checks")
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
