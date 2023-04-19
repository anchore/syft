package file

import "io"

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
