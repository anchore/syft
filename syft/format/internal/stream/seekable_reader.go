package stream

import (
	"bytes"
	"fmt"
	"io"
)

func SeekableReader(reader io.Reader) (io.ReadSeeker, error) {
	if reader == nil {
		return nil, fmt.Errorf("no bytes provided")
	}

	if r, ok := reader.(io.ReadSeeker); ok {
		return r, nil
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(content), nil
}
