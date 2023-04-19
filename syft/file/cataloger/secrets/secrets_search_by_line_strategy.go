package secrets

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
)

func catalogLocationByLine(resolver file.Resolver, location file.Location, patterns map[string]*regexp.Regexp) ([]file.SearchResult, error) {
	readCloser, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch reader for location=%q : %w", location, err)
	}
	defer internal.CloseAndLogError(readCloser, location.VirtualPath)

	var scanner = bufio.NewReader(readCloser)
	var position int64
	var allSecrets []file.SearchResult
	var lineNo int64
	var readErr error
	for !errors.Is(readErr, io.EOF) {
		lineNo++
		var line []byte
		// TODO: we're at risk of large memory usage for very long lines
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

func searchForSecretsWithinLine(resolver file.Resolver, location file.Location, patterns map[string]*regexp.Regexp, line []byte, lineNo int64, position int64) ([]file.SearchResult, error) {
	var secrets []file.SearchResult
	for name, pattern := range patterns {
		matches := pattern.FindAllIndex(line, -1)
		for i, match := range matches {
			if i%2 == 1 {
				// FindAllIndex returns pairs of numbers for each match, we are only interested in the starting (first)
				// position in each pair.
				continue
			}

			lineOffset := int64(match[0])
			seekLocation := position + lineOffset
			reader, err := readerAtPosition(resolver, location, seekLocation)
			if err != nil {
				return nil, err
			}

			secret := extractSecretFromPosition(reader, name, pattern, lineNo, lineOffset, seekLocation)
			if secret != nil {
				secrets = append(secrets, *secret)
			}
			internal.CloseAndLogError(reader, location.VirtualPath)
		}
	}

	return secrets, nil
}

func readerAtPosition(resolver file.Resolver, location file.Location, seekPosition int64) (io.ReadCloser, error) {
	readCloser, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch reader for location=%q : %w", location, err)
	}
	if seekPosition > 0 {
		n, err := io.CopyN(io.Discard, readCloser, seekPosition)
		if err != nil {
			return nil, fmt.Errorf("unable to read contents for location=%q while searching for secrets: %w", location, err)
		}
		if n != seekPosition {
			return nil, fmt.Errorf("unexpected seek location for location=%q while searching for secrets: %d != %d", location, n, seekPosition)
		}
	}
	return readCloser, nil
}

func extractSecretFromPosition(readCloser io.ReadCloser, name string, pattern *regexp.Regexp, lineNo, lineOffset, seekPosition int64) *file.SearchResult {
	reader := &newlineCounter{RuneReader: bufio.NewReader(readCloser)}
	positions := pattern.FindReaderSubmatchIndex(reader)
	if len(positions) == 0 {
		// no matches found
		return nil
	}

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

	if start < 0 || stop < 0 {
		// no match location found. This can happen when there is a value capture group specified by the user
		// and there was a match on the overall regex, but not for the capture group (which is possible if the capture
		// group is optional).
		return nil
	}

	// lineNoOfSecret are the number of lines which occur before the start of the secret value
	var lineNoOfSecret = lineNo + int64(reader.newlinesBefore(start))
	// lineOffsetOfSecret are the number of bytes that occur after the last newline but before the secret value.
	var lineOffsetOfSecret = start - reader.newlinePositionBefore(start)
	if lineNoOfSecret == lineNo {
		// the secret value starts in the same line as the overall match, so we must consider that line offset
		lineOffsetOfSecret += lineOffset
	}

	return &file.SearchResult{
		Classification: name,
		SeekPosition:   start + seekPosition,
		Length:         stop - start,
		LineNumber:     lineNoOfSecret,
		LineOffset:     lineOffsetOfSecret,
	}
}
