package secrets

import (
	"bufio"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLineCounter_ReadRune(t *testing.T) {
	counter := &newlineCounter{RuneReader: bufio.NewReader(strings.NewReader("hi\nwhat's the weather like today?\ndunno...\n"))}
	var err error
	for err == nil {
		_, _, err = counter.ReadRune()
	}
	if err != io.EOF {
		t.Fatalf("should have gotten an eof, got %+v", err)
	}
	assert.Equal(t, 3, len(counter.newLines), "bad line count")
	assert.Equal(t, []int64{3, 34, 43}, counter.newLines, "bad line positions")
}

func TestLineCounter_newlinesBefore(t *testing.T) {
	counter := &newlineCounter{RuneReader: bufio.NewReader(strings.NewReader("hi\nwhat's the weather like today?\ndunno...\n"))}
	var err error
	for err == nil {
		_, _, err = counter.ReadRune()
	}
	if err != io.EOF {
		t.Fatalf("should have gotten an eof, got %+v", err)
	}
	assert.Equal(t, 1, counter.newlinesBefore(10), "bad line count")
}
