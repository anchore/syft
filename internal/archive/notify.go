package archive

import (
	"github.com/anchore/syft/internal/log"
)

// Notify receives structured events from archive extraction. A nil Notify is the no-op.
//
// func(any) rather than typed callbacks so adding an event changes no signature: a handler asserts
// for the events it wants and ignores the rest. Boxing into an any allocates, so on this hot path
// guard the call rather than relying on a nil check inside the callee:
//
//	if notify != nil {
//		notify(EntriesOverflowed{Archive: name, Bytes: n})
//	}
type Notify func(msg any)

// OverflowReason says why content was written to disk rather than held.
type OverflowReason string

const (
	// MemoryLimitReached means the scan was already holding as much as the memory limit admits.
	MemoryLimitReached OverflowReason = "memory limit reached"

	// MemoryHoldsNothing means the memory limit is zero, so content goes to disk by policy rather than
	// under pressure.
	MemoryHoldsNothing OverflowReason = "memory limit is zero"
)

// ContentOverflowed reports that one archive's own bytes were written to disk rather than held in
// memory. Bytes is the size of the archive.
type ContentOverflowed struct {
	Archive string
	Bytes   int64
	Reason  OverflowReason
}

// EntriesOverflowed reports that the entries a store was holding were written to its overflow blob.
// Entries and Bytes are what moved in this spill, not the archive's totals: a store spills everything
// it holds at once, and may spill again as it refills.
type EntriesOverflowed struct {
	Archive string
	Entries int
	Bytes   int64
	Reason  OverflowReason
}

// Skipped reports that an archive contributed nothing, and why. The scan continues, but any packages
// inside that archive are absent from the SBOM.
type Skipped struct {
	Archive string
	Reason  string
}

// Truncated reports that an archive was cataloged from part of its contents, naming the bound that
// stopped it.
type Truncated struct {
	Archive string
	Reason  TruncationReason
}

// LogNotify is the default handler: it writes each known event to the debug log and ignores the rest.
func LogNotify(msg any) {
	switch e := msg.(type) {
	case ContentOverflowed:
		log.WithFields("archive", e.Archive, "bytes", e.Bytes, "reason", string(e.Reason)).
			Debug("archive content written to disk rather than held in memory")
	case EntriesOverflowed:
		log.WithFields("archive", e.Archive, "entries", e.Entries, "bytes", e.Bytes, "reason", string(e.Reason)).
			Debug("archive entries written to disk rather than held in memory")
	case Skipped:
		log.WithFields("archive", e.Archive, "reason", e.Reason).Debug("archive skipped")
	case Truncated:
		log.WithFields("archive", e.Archive, "reason", string(e.Reason)).Debug("archive cataloged from part of its contents")
	}
}
