package yarn

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/key"
)

var (
	yarnPatternRegexp    = regexp.MustCompile(`^\s?\\?"?(?P<package>\S+?)@(?:(?P<protocol>\S+?):)?(?P<version>.+?)\\?"?:?$`)
	yarnVersionRegexp    = regexp.MustCompile(`^"?version:?"?\s+"?(?P<version>[^"]+)"?`)
	yarnDependencyRegexp = regexp.MustCompile(`\s{4,}"?(?P<package>.+?)"?:?\s"?(?P<version>[^"]+)"?`)
	yarnIntegrityRegexp  = regexp.MustCompile(`^"?integrity:?"?\s+"?(?P<integrity>[^"]+)"?`)
	yarnResolvedRegexp   = regexp.MustCompile(`^"?resolved:?"?\s+"?(?P<resolved>[^"]+)"?`)
)

type PkgRef struct {
	Name         string
	Version      string
	Integrity    string
	Resolved     string
	Patterns     []string
	Dependencies map[string]string
}

type LineScanner struct {
	*bufio.Scanner
	lineCount int
}

func newLineScanner(r io.Reader) *LineScanner {
	return &LineScanner{
		Scanner: bufio.NewScanner(r),
	}
}

func (s *LineScanner) Scan() bool {
	scan := s.Scanner.Scan()
	if scan {
		s.lineCount++
	}
	return scan
}

func (s *LineScanner) LineNum(prevNum int) int {
	return prevNum + s.lineCount - 1
}

func parseDependencies(scanner *LineScanner) map[string]string {
	deps := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		if name, version, err := parseDependency(line); err != nil {
			// finished dependencies block
			return deps
		} else {
			deps[name] = version
		}
	}

	return deps
}

func getDependency(target string) (name, version string, err error) {
	capture := yarnDependencyRegexp.FindStringSubmatch(target)
	if len(capture) < 3 {
		return "", "", errors.New("not dependency")
	}
	return capture[1], capture[2], nil
}

func getIntegrity(target string) (integrity string, err error) {
	capture := yarnIntegrityRegexp.FindStringSubmatch(target)
	if len(capture) < 2 {
		return "", errors.New("not integrity")
	}
	return capture[1], nil
}

func getResolved(target string) (resolved string, err error) {
	capture := yarnResolvedRegexp.FindStringSubmatch(target)
	if len(capture) < 2 {
		return "", errors.New("not resolved")
	}
	return capture[1], nil
}

func parseDependency(line string) (string, string, error) {
	if name, version, err := getDependency(line); err != nil {
		return "", "", err
	} else {
		return name, version, nil
	}
}

func getVersion(target string) (version string, err error) {
	capture := yarnVersionRegexp.FindStringSubmatch(target)
	if len(capture) < 2 {
		return "", fmt.Errorf("failed to parse version: '%s", target)
	}
	return capture[len(capture)-1], nil
}

func parsePattern(target string) (packagename, protocol, version string, err error) {
	capture := yarnPatternRegexp.FindStringSubmatch(target)
	if len(capture) < 3 {
		return "", "", "", errors.New("not package format")
	}
	for i, group := range yarnPatternRegexp.SubexpNames() {
		switch group {
		case "package":
			packagename = capture[i]
		case "protocol":
			protocol = capture[i]
		case "version":
			version = capture[i]
		}
	}
	return
}

func parsePackagePatterns(target string) (packagename, protocol string, patterns []string, err error) {
	patternsSplit := strings.Split(target, ", ")
	packagename, protocol, _, err = parsePattern(patternsSplit[0])
	if err != nil {
		return "", "", nil, err
	}

	var resultPatterns []string
	for _, pattern := range patternsSplit {
		_, _, version, _ := parsePattern(pattern)
		resultPatterns = append(resultPatterns, key.NpmPackageKey(packagename, version))
	}
	patterns = resultPatterns
	return
}

func validProtocol(protocol string) bool {
	switch protocol {
	case "npm", "":
		return true
	case "workspace":
		return true
	}
	return false
}

func ignoreProtocol(protocol string) bool {
	switch protocol {
	case "patch", "file", "link", "portal", "github", "git", "git+ssh", "git+http", "git+https", "git+file":
		return true
	}
	return false
}

func ParseBlock(block []byte, lineNum int) (pkg PkgRef, lineNumber int, err error) {
	var (
		emptyLines int // lib can start with empty lines first
		skipBlock  bool
	)

	scanner := newLineScanner(bytes.NewReader(block))
	for scanner.Scan() {
		line := scanner.Text()

		if len(line) == 0 {
			emptyLines++
			continue
		}

		if line[0] == '#' || skipBlock {
			continue
		}

		// Skip this block
		if strings.HasPrefix(line, "__metadata") {
			skipBlock = true
			continue
		}

		line = strings.TrimPrefix(strings.TrimSpace(line), "\"")

		switch {
		case strings.HasPrefix(line, "version"):
			if pkg.Version, err = getVersion(line); err != nil {
				skipBlock = true
			}
			continue
		case strings.HasPrefix(line, "integrity"):
			if pkg.Integrity, err = getIntegrity(line); err != nil {
				continue
			}
			continue
		case strings.HasPrefix(line, "resolved"):
			if pkg.Resolved, err = getResolved(line); err != nil {
				continue
			}
			continue
		case strings.HasPrefix(line, "dependencies:"):
			// start dependencies block
			deps := parseDependencies(scanner)
			pkg.Dependencies = deps
			continue
		}

		// try parse package patterns
		if name, protocol, patterns, patternErr := parsePackagePatterns(line); patternErr == nil {
			if patterns == nil || !validProtocol(protocol) {
				skipBlock = true
				if !ignoreProtocol(protocol) {
					// we need to calculate the last line of the block in order to correctly determine the line numbers of the next blocks
					// store the error. we will handle it later
					err = fmt.Errorf("unknown protocol: '%s', line: %s", protocol, line)
					continue
				}
				continue
			} else {
				pkg.Name = name
				pkg.Patterns = patterns
				continue
			}
		}
	}

	// in case an unsupported protocol is detected
	// show warning and continue parsing
	if err != nil {
		log.Debugf("failed to parse block: %s", err)
		return pkg, scanner.LineNum(lineNum), nil
	}

	if scanErr := scanner.Err(); scanErr != nil {
		err = scanErr
	}

	return pkg, scanner.LineNum(lineNum), err
}

func ScanBlocks(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		// We have a full newline-terminated line.
		return i + 2, data[0:i], nil
	} else if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return i + 4, data[0:i], nil
	}

	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}
