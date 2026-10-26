package file

import "io"

// ReaderSize reports the number of bytes behind r. The bool is false when that cannot be determined, and
// callers must branch on it rather than treating the zero as a size.
//
// Binary parsers read sizes out of the files they are parsing and allocate against them. Those sizes are
// 32- and 64-bit fields under the control of whoever produced the file, so a truncated or hostile input
// can declare gigabytes that are not there. The read would fail afterwards either way; what matters is
// refusing before the allocation, and that needs a real byte count to weigh the claim against.
//
// The bool is the whole point of the signature. An earlier version returned 0 for every failure mode, and
// a caller that forgot to special-case it got a bound of "nothing is allowed" or, more often, silently
// fell back to an unbounded path. Making the caller name the failure keeps that from happening by
// omission.
//
// Both *bytes.Reader and *io.SectionReader answer directly. A file handle only has Seek, so fall back to
// a save-and-restore seek, which leaves the caller's cursor where it found it. That fallback is not
// atomic: it moves the cursor and puts it back, so a reader being read concurrently can observe the
// intermediate position.
//
// Neither answer is taken on faith, because a reader can report a length it cannot deliver: an
// *io.SectionReader answers with the length it was constructed with, and debug/elf and friends construct
// theirs with a nominal one, so io.NewSectionReader(r, 0, 1<<63-1) would otherwise report a bound that
// permits everything as if it had been measured. The last byte is read back to confirm the count, which is
// one ReadAt whatever the size, and the read is what the caller was going to weigh anyway.
//
// A wrapper that embeds io.ReaderAt as an interface promotes only ReadAt, so it answers no size here
// however sizable the reader underneath it is. A type meant to be bounded needs to forward Size() itself.
func ReaderSize(r io.ReaderAt) (int64, bool) {
	size, ok := reportedSize(r)
	if !ok {
		return 0, false
	}
	// ReadAt may return io.EOF alongside a full read, so the count is what says the byte is there
	var last [1]byte
	if n, _ := r.ReadAt(last[:], size-1); n != len(last) {
		return 0, false
	}
	return size, true
}

// reportedSize is what the reader says about itself, before ReaderSize checks whether it can back it up.
func reportedSize(r io.ReaderAt) (int64, bool) {
	if sr, ok := r.(interface{ Size() int64 }); ok {
		size := sr.Size()
		return size, size > 0
	}
	s, ok := r.(io.Seeker)
	if !ok {
		return 0, false
	}
	cur, err := s.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, false
	}
	size, err := s.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, false
	}
	if _, err := s.Seek(cur, io.SeekStart); err != nil {
		return 0, false
	}
	return size, size > 0
}
