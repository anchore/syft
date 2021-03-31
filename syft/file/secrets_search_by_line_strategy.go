package file

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"

	"github.com/anchore/syft/syft/source"
)

func catalogLocationByLine(resolver source.FileResolver, location source.Location, patterns map[string]*regexp.Regexp) ([]Secret, error) {
	readCloser, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch reader for location=%q : %w", location, err)
	}
	defer readCloser.Close()

	var scanner = bufio.NewReader(readCloser)
	var position int64
	var allSecrets []Secret
	var lineNo int64
	var readErr error
	for !errors.Is(readErr, io.EOF) {
		lineNo++
		var line []byte
		// TODO: we're at risk of large memory usage for very long lines (and searching binaries)
		line, readErr = scanner.ReadBytes('\n')
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}

		lineSecrets, err := searchForSecretsWithinLine(resolver, location, patterns, line, lineNo, position)
		if err != nil {
			return nil, err
		}
		position += int64(len(line))
		allSecrets = append(allSecrets, lineSecrets...)
	}

	return allSecrets, nil
}

func searchForSecretsWithinLine(resolver source.FileResolver, location source.Location, patterns map[string]*regexp.Regexp, line []byte, lineNo int64, position int64) ([]Secret, error) {
	var secrets []Secret
	for name, pattern := range patterns {
		matches := pattern.FindAllIndex(line, -1)
		for i, match := range matches {
			if i%2 == 1 {
				// FindAllIndex returns pairs of numbers for each match, we are only interested in the starting (first)
				// position in each pair.
				continue
			}

			lineOffset := int64(match[0])
			secret, err := extractSecretFromPosition(resolver, location, name, pattern, lineNo, lineOffset, position+lineOffset)
			if err != nil {
				return nil, err
			}
			if secret != nil {
				secrets = append(secrets, *secret)
			}
		}
	}

	return secrets, nil
}

func extractSecretFromPosition(resolver source.FileResolver, location source.Location, name string, pattern *regexp.Regexp, lineNo, lineOffset, seekPosition int64) (*Secret, error) {
	readCloser, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch reader for location=%q : %w", location, err)
	}
	defer readCloser.Close()

	if seekPosition > 0 {
		n, err := io.CopyN(ioutil.Discard, readCloser, seekPosition)
		if err != nil {
			return nil, fmt.Errorf("unable to read contents for location=%q while searching for secrets: %w", location, err)
		}
		if n != seekPosition {
			return nil, fmt.Errorf("unexpected seek location for location=%q while searching for secrets: %d != %d", location, n, seekPosition)
		}
	}

	reader := &newlineCounter{RuneReader: bufio.NewReader(readCloser)}
	positions := pattern.FindReaderSubmatchIndex(reader)
	if len(positions) > 0 {
		index := pattern.SubexpIndex("value")
		var indexOffset int
		if index != -1 {
			// there is a capture group, use the capture group selection as the secret value. To do this we want to
			// use the position at the discovered offset. Note: all positions come in pairs, so you will need to adjust
			// the offset accordingly (multiply by 2).
			indexOffset = index * 2
		}
		// get the start and stop of the secret value. Note: this covers both when there is a capture group
		// and when there is not a capture group (full value match)
		start, stop := int64(positions[indexOffset]), int64(positions[indexOffset+1])

		// lineNoOfSecret are the number of lines which occur before the start of the secret value
		var lineNoOfSecret = lineNo + int64(reader.newlinesBefore(start))
		// lineOffsetOfSecret are the number of bytes that occur after the last newline but before the secret value.
		var lineOffsetOfSecret = start - reader.newlinePositionBefore(start)
		if lineNoOfSecret == lineNo {
			// the secret value starts in the same line as the overall match, so we must consider that line offset
			lineOffsetOfSecret += lineOffset
		}

		if start >= 0 && stop >= 0 {
			return &Secret{
				PatternName:  name,
				SeekPosition: start + seekPosition,
				Length:       stop - start,
				LineNumber:   lineNoOfSecret,
				LineOffset:   lineOffsetOfSecret,
			}, nil
		}
	}
	return nil, nil
}

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
