package file

import (
	"bufio"
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

	scanner := bufio.NewReader(readCloser)
	var position int64
	var allSecrets []Secret
	var lineNo int64
	for {
		lineNo++
		// TODO: we're at risk of large memory usage for very long lines (and searching binaries)
		line, err := scanner.ReadBytes('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		lineSecrets, err := searchForSecretsWithinLine(resolver, location, patterns, line, lineNo, position)
		if err != nil {
			return nil, err
		}
		position += int64(len(line)) + 1 // content + newline
		allSecrets = append(allSecrets, lineSecrets...)
	}

	return allSecrets, nil
}

func searchForSecretsWithinLine(resolver source.FileResolver, location source.Location, patterns map[string]*regexp.Regexp, line []byte, lineNo int64, position int64) ([]Secret, error) {
	var secrets []Secret
	for name, pattern := range patterns {
		matches := pattern.FindAllIndex(line, -1)
		for _, match := range matches {
			var curPos = position
			for {
				secret, err := searchForSecretFromPosition(resolver, location, name, pattern, curPos)
				if err != nil {
					return nil, err
				}
				if secret == nil {
					break
				} else {
					secret.LineNumber = lineNo
					secret.LineOffset = int64(match[0])
					secrets = append(secrets, *secret)
					curPos = secret.Position + secret.Length
				}
			}
		}
	}

	return secrets, nil
}

func searchForSecretFromPosition(resolver source.FileResolver, location source.Location, name string, pattern *regexp.Regexp, position int64) (*Secret, error) {
	readCloser, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch reader for location=%q : %w", location, err)
	}
	defer readCloser.Close()

	if position > 0 {
		n, err := io.CopyN(ioutil.Discard, readCloser, position)
		if err != nil {
			return nil, fmt.Errorf("unable to read contents for location=%q while searching for secrets: %w", location, err)
		}
		if n != position {
			return nil, fmt.Errorf("unexpected seek location for location=%q while searching for secrets: %d != %d", location, n, position)
		}
	}

	positions := pattern.FindReaderSubmatchIndex(bufio.NewReader(readCloser))
	for len(positions) > 0 {
		index := pattern.SubexpIndex("value")
		if index == -1 {
			// there is no capture group, use the entire expression as the secret value
			start, stop := int64(positions[0]), int64(positions[1])
			return &Secret{
				PatternName: name,
				Position:    start + position,
				Length:      stop - start,
			}, nil
		}
		// use the capture group value
		start, stop := int64(positions[index*2]), int64(positions[index*2+1])
		return &Secret{
			PatternName: name,
			Position:    start + position,
			Length:      stop - start,
		}, nil
	}

	return nil, nil
}
