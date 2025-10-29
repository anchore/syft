package file

import "io"

// LocationReadCloser combines a Location with a ReadCloser for accessing file content with location metadata.
type LocationReadCloser struct {
	Location
	io.ReadCloser
}

func NewLocationReadCloser(location Location, reader io.ReadCloser) LocationReadCloser {
	return LocationReadCloser{
		Location:   location,
		ReadCloser: reader,
	}
}
