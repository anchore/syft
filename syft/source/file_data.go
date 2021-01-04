package source

import "io"

type FileData struct {
	Location Location
	Contents io.ReadCloser
}
