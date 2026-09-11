package archive

import (
	"github.com/anchore/syft/internal/log"
)

// Notify receives structured events from archive extraction. A nil Notify is the no-op.
//
// The signature is deliberately `func(any)` rather than a set of typed callbacks or an interface with
// a method per event. Extraction is a hot path - a scan of a big image enters thousands of archives -
// and what instrumentation costs there has to be nothing when it is off. A single func field is one
// nil check, and a handler that cares about one event type asserts for it and ignores the rest, so
// adding an event never changes a signature or breaks a handler that did not ask for it.
//
// Guard the call rather than relying on a nil check inside the callee:
//
//	if notify != nil {
//		notify(EntriesOverflowed{Archive: name, Bytes: n})
//	}
//
// Building the event value is what costs - putting a struct in an `any` allocates - so the guard is
// what makes "off" free rather than merely cheap. Send exists for the paths where that does not
// matter.
type Notify func(msg any)

// Send delivers one event, doing nothing when there is no handler. Convenient, but it builds the
// event whether or not anyone is listening: on a hot path, guard the call instead.
func (n Notify) Send(msg any) {
	if n == nil {
		return
	}
	n(msg)
}

// Tee returns a Notify that delivers to each of the given handlers, skipping the nil ones, and nil
// when none of them are live - so a tee of nothing stays free.
func Tee(handlers ...Notify) Notify {
	var live []Notify
	for _, h := range handlers {
		if h != nil {
			live = append(live, h)
		}
	}
	switch len(live) {
	case 0:
		return nil
	case 1:
		return live[0]
	}
	return func(msg any) {
		for _, h := range live {
			h(msg)
		}
	}
}

// OverflowReason says why content was written to disk rather than held.
type OverflowReason string

const (
	// MemoryLimitReached means the scan was already holding as much as the memory limit admits.
	MemoryLimitReached OverflowReason = "memory limit reached"

	// MemoryHoldsNothing means the memory limit is zero, so nothing is ever held and every archive's
	// content goes to disk by policy rather than by pressure.
	MemoryHoldsNothing OverflowReason = "memory limit is zero"
)

// ContentOverflowed reports that one archive's own bytes were written to disk instead of being held in
// memory. Bytes is the size of the archive.
type ContentOverflowed struct {
	Archive string
	Bytes   int64
	Reason  OverflowReason
}

// EntriesOverflowed reports that the entries an archive's store was holding have been written to its
// overflow blob. Entries and Bytes are what moved, not what the archive holds in total: a store spills
// everything it is holding at once, and may spill more than once as it fills again.
type EntriesOverflowed struct {
	Archive string
	Entries int
	Bytes   int64
	Reason  OverflowReason
}

// Skipped reports that an archive contributed nothing, and why. Not a failure - the scan
// continues - but the packages inside it are absent from the SBOM, which is worth being able to see.
type Skipped struct {
	Archive string
	Reason  string
}

// Truncated reports that an archive was cataloged from part of its contents, naming the bound
// that stopped it.
type Truncated struct {
	Archive string
	Reason  TruncationReason
}

// LogNotify is the default handler: it writes each event to the debug log. Anything it does not
// recognize is ignored rather than logged blindly, so an event added for one consumer does not turn
// into noise for everyone.
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
