package internal

import (
	"io"
	"regexp"
)

const readerChunkSize = 1024 * 1024

// MatchNamedCaptureGroups takes a regular expression and string and returns all of the named capture group results in a map.
// This is only for the first match in the regex. Callers shouldn't be providing regexes with multiple capture groups with the same name.
func MatchNamedCaptureGroups(regEx *regexp.Regexp, content string) map[string]string {
	// note: we are looking across all matches and stopping on the first non-empty match. Why? Take the following example:
	// input: "cool something to match against" pattern: `((?P<name>match) (?P<version>against))?`. Since the pattern is
	// encapsulated in an optional capture group, there will be results for each character, but the results will match
	// on nothing. The only "true" match will be at the end ("match against").
	allMatches := regEx.FindAllStringSubmatch(content, -1)
	var results map[string]string
	for _, match := range allMatches {
		// fill a candidate results map with named capture group results, accepting empty values, but not groups with
		// no names
		for nameIdx, name := range regEx.SubexpNames() {
			if nameIdx > len(match) || len(name) == 0 {
				continue
			}
			if results == nil {
				results = make(map[string]string)
			}
			results[name] = match[nameIdx]
		}
		// note: since we are looking for the first best potential match we should stop when we find the first one
		// with non-empty results.
		if !isEmptyMap(results) {
			break
		}
	}
	return results
}

// MatchNamedCaptureGroupsFromReader matches named capture groups from a reader, assuming the pattern fits within
// 1.5x the reader chunk size (1MB * 1.5).
func MatchNamedCaptureGroupsFromReader(re *regexp.Regexp, r io.Reader) (map[string]string, error) {
	results := make(map[string]string)
	_, err := processReaderInChunks(r, readerChunkSize, matchNamedCaptureGroupsHandler(re, results))
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}
	return results, nil
}

// MatchAnyFromReader matches any of the provided regular expressions from a reader, assuming the pattern fits within
// 1.5x the reader chunk size (1MB * 1.5).
func MatchAnyFromReader(r io.Reader, res ...*regexp.Regexp) (bool, error) {
	return processReaderInChunks(r, readerChunkSize, matchAnyHandler(res))
}

func matchNamedCaptureGroupsHandler(re *regexp.Regexp, results map[string]string) func(data []byte) (bool, error) {
	return func(data []byte) (bool, error) {
		if match := re.FindSubmatch(data); match != nil {
			groupNames := re.SubexpNames()
			for i, name := range groupNames {
				if i > 0 && name != "" {
					results[name] = string(match[i])
				}
			}
			return true, nil
		}
		return false, nil
	}
}

func matchAnyHandler(res []*regexp.Regexp) func(data []byte) (bool, error) {
	return func(data []byte) (bool, error) {
		for _, re := range res {
			if re.Match(data) {
				return true, nil
			}
		}
		return false, nil
	}
}

// processReaderInChunks reads from the provided reader in chunks and calls the provided handler with each chunk + portion of the previous neighboring chunk.
// Note that we only overlap the last half of the previous chunk with the current chunk to avoid missing matches that span chunk boundaries.
func processReaderInChunks(rdr io.Reader, chunkSize int, handler func(data []byte) (bool, error)) (bool, error) {
	half := chunkSize / 2
	bufSize := chunkSize + half
	buf := make([]byte, bufSize)
	lastRead := 0

	for {
		offset := half
		if lastRead < half {
			offset = lastRead
		}
		start := half - offset
		if lastRead > 0 {
			copy(buf[start:], buf[half+offset:half+lastRead])
		}
		n, err := rdr.Read(buf[half:])
		if err != nil {
			break
		}

		// process the combined data with the handler
		matched, handlerErr := handler(buf[start : half+n])
		if handlerErr != nil {
			return false, handlerErr
		}
		if matched {
			return true, nil
		}

		lastRead = n
	}

	return false, nil
}

func isEmptyMap(m map[string]string) bool {
	if len(m) == 0 {
		return true
	}
	for _, value := range m {
		if value != "" {
			return false
		}
	}
	return true
}
