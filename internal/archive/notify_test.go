package archive

import (
	"archive/tar"
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recorder is what a consumer of these events looks like: one func, a type assertion for what it
// cares about, and silence for everything else.
type recorder struct {
	overflows []EntriesOverflowed
	other     int
}

func (r *recorder) notify(msg any) {
	if e, ok := msg.(EntriesOverflowed); ok {
		r.overflows = append(r.overflows, e)
		return
	}
	r.other++
}

func TestNotify_reportsWhichArchiveSpilledAndWhy(t *testing.T) {
	rec := &recorder{}
	s := NewEntryStore(t.TempDir(), "lib/app.jar", rec.notify)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	charge := memCharge(8)
	for _, body := range []string{"aaaa", "bbbbbb"} {
		_, err := s.Add(regularHeader(body+".txt", int64(len(body))), bytes.NewReader([]byte(body)), charge)
		require.NoError(t, err)
	}

	require.Len(t, rec.overflows, 1)
	assert.Equal(t, "lib/app.jar", rec.overflows[0].Archive, "the event has to name the archive, or it says nothing actionable")
	assert.Equal(t, MemoryLimitReached, rec.overflows[0].Reason)
	assert.Equal(t, 2, rec.overflows[0].Entries, "a store moves everything it is holding, not just the entry that did not fit")
	assert.Equal(t, int64(10), rec.overflows[0].Bytes)
}

func TestNotify_distinguishesPressureFromPolicy(t *testing.T) {
	// a scan at its memory bound and a scan whose bound is zero are different findings: the first says
	// the limit is biting, the second says nothing was ever going to be held
	rec := &recorder{}
	s := NewEntryStore(t.TempDir(), "app.jar", rec.notify)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	_, err := s.Add(regularHeader("a.txt", 3), bytes.NewReader([]byte("abc")), memCharge(0))
	require.NoError(t, err)

	require.Len(t, rec.overflows, 1)
	assert.Equal(t, MemoryHoldsNothing, rec.overflows[0].Reason)
}

func TestNotify_nilHandlerIsTheNoOp(t *testing.T) {
	s := NewEntryStore(t.TempDir(), "app.jar", nil)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	_, err := s.Add(regularHeader("a.txt", 3), bytes.NewReader([]byte("abc")), memCharge(0))
	assert.NoError(t, err, "no handler must not mean no extraction")
}

func TestNotify_teeDeliversToEveryLiveHandler(t *testing.T) {
	first, second := &recorder{}, &recorder{}
	tee := Tee(nil, first.notify, nil, second.notify)
	require.NotNil(t, tee)

	tee(EntriesOverflowed{Archive: "app.jar", Entries: 1})

	assert.Len(t, first.overflows, 1)
	assert.Len(t, second.overflows, 1)
}

func TestNotify_teeOfNothingIsNil(t *testing.T) {
	// a tee that would deliver to no one stays nil, so the guard at every call site keeps it free
	assert.Nil(t, Tee())
	assert.Nil(t, Tee(nil, nil))
}

func TestNotify_sendIsNilSafe(t *testing.T) {
	var n Notify
	n.Send(EntriesOverflowed{})
}

func TestNotify_directoryEntriesDoNotSpill(t *testing.T) {
	// a directory carries no content, so it can never be the thing that pushes a store to disk
	rec := &recorder{}
	s := NewEntryStore(t.TempDir(), "app.jar", rec.notify)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	_, err := s.Add(tar.Header{Name: "lib/", Typeflag: tar.TypeDir, Mode: 0o755}, nil, memCharge(0))
	require.NoError(t, err)
	assert.Empty(t, rec.overflows)
}
