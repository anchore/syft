package file

import "io"

type newlineCounter struct {
	io.RuneReader
	numBytes int64
	newLines []int64
}

func (c *newlineCounter) ReadRune() (r rune, size int, err error) {
	r, size, err = c.RuneReader.ReadRune()
	c.numBytes += int64(size)
	if r == '\n' {
		c.newLines = append(c.newLines, c.numBytes)
	}
	return
}

func (c *newlineCounter) newlinesBefore(pos int64) int {
	var result int
	for _, nlPos := range c.newLines {
		if nlPos <= pos {
			result++
		}
	}
	return result
}

func (c *newlineCounter) newlinePositionBefore(pos int64) int64 {
	var last int64
	for _, nlPos := range c.newLines {
		if nlPos > pos {
			break
		}
		last = nlPos
	}
	return last
}
