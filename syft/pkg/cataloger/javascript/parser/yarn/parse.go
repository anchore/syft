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
	yarnPatternRegexp     = regexp.MustCompile(`^\s?\\?"?(?P<package>\S+?)@(?:(?P<protocol>\S+?):)?(?P<version>.+?)\\?"?:?$`)
	yarnPatternHTTPRegexp = regexp.MustCompile(`^\s?\\?"?(?P<package>\S+?)@https:\/\/[^#]+#(?P<version>.+?)\\?"?:?$`)

	yarnVersionRegexp    = regexp.MustCompile(`^"?version:?"?\s+"?(?P<version>[^"]+)"?`)
	yarnDependencyRegexp = regexp.MustCompile(`\s{4,}"?(?P<package>.+?)"?:?\s"?(?P<version>[^"]+)"?`)
	yarnIntegrityRegexp  = regexp.MustCompile(`^"?integrity:?"?\s+"?(?P<integrity>[^"]+)"?`)
	yarnResolvedRegexp   = regexp.MustCompile(`^"?resolved:?"?\s+"?(?P<resolved>[^"]+)"?`)
	// yarnPackageURLExp matches the name and version of the dependency in yarn.lock
	// from the resolved URL, including scope/namespace prefix if any.
	// For example:
	//		`"https://registry.yarnpkg.com/async/-/async-3.2.3.tgz#ac53dafd3f4720ee9e8a160628f18ea91df196c9"`
	//			would return "async" and "3.2.3"
	//
	//		`"https://registry.yarnpkg.com/@4lolo/resize-observer-polyfill/-/resize-observer-polyfill-1.5.2.tgz#58868fc7224506236b5550d0c68357f0a874b84b"`
	//			would return "@4lolo/resize-observer-polyfill" and "1.5.2"
	yarnPackageURLExp = regexp.MustCompile(`^https://registry\.(?:yarnpkg\.com|npmjs\.org)/(.+?)/-/(?:.+?)-(\d+\..+?)\.tgz`)
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
		name, version, err := parseDependency(line)
		if err != nil {
			// finished dependencies block
			return deps
		}
		deps[name] = version
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
	name, version, err := getDependency(line)
	if err != nil {
		return "", "", err
	}
	return name, version, nil
}

func getVersion(target string) (version string, err error) {
	capture := yarnVersionRegexp.FindStringSubmatch(target)
	if len(capture) < 2 {
		return "", fmt.Errorf("failed to parse version: '%s", target)
	}
	return capture[len(capture)-1], nil
}

func getPackageNameFromResolved(resolution string) (pkgName string) {
	if matches := yarnPackageURLExp.FindStringSubmatch(resolution); len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func parsePattern(target string) (packagename, protocol, version string, err error) {
	var capture []string
	var names []string

	if strings.Contains(target, "https://") {
		capture = yarnPatternHTTPRegexp.FindStringSubmatch(target)
		protocol = "https"
		names = yarnPatternHTTPRegexp.SubexpNames()
	} else {
		capture = yarnPatternRegexp.FindStringSubmatch(target)
		names = yarnPatternRegexp.SubexpNames()
	}

	if len(capture) < 3 {
		return "", "", "", errors.New("not package format")
	}
	for i, group := range names {
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
	// example: "jhipster-core@npm:7.3.4":
	case "npm", "":
		return true
	// example: "my-pkg@workspace:."
	case "workspace":
		return true
	// example: "should-type@https://github.com/shouldjs/type.git#1.3.0"
	case "https":
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

func handleEmptyLinesAndComments(line string, skipBlock bool) (int, bool) {
	if len(line) == 0 {
		return 1, skipBlock
	}

	if line[0] == '#' || skipBlock {
		return 0, skipBlock
	}

	if strings.HasPrefix(line, "__metadata") {
		return 0, true
	}

	return 0, skipBlock
}

func handleLinePrefixes(line string, pkg *PkgRef, scanner *LineScanner) (err error) {
	switch {
	case strings.HasPrefix(line, "version"):
		pkg.Version, err = getVersion(line)
	case strings.HasPrefix(line, "integrity"):
		pkg.Integrity, err = getIntegrity(line)
	case strings.HasPrefix(line, "resolved"):
		pkg.Resolved, err = getResolved(line)
	case strings.HasPrefix(line, "dependencies:"):
		pkg.Dependencies = parseDependencies(scanner)
	}
	return
}

func ParseBlock(block []byte, lineNum int) (pkg PkgRef, lineNumber int, err error) {
	var (
		emptyLines int // lib can start with empty lines first
		skipBlock  bool
	)

	scanner := newLineScanner(bytes.NewReader(block))
	for scanner.Scan() {
		line := scanner.Text()

		var increment int
		increment, skipBlock = handleEmptyLinesAndComments(line, skipBlock)
		emptyLines += increment

		line = strings.TrimPrefix(strings.TrimSpace(line), "\"")

		if err := handleLinePrefixes(line, &pkg, scanner); err != nil {
			skipBlock = true
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
			}
			pkg.Name = name
			pkg.Patterns = patterns
			continue
		}
	}

	// handles the case of namespaces packages like @4lolo/resize-observer-polyfill
	// where the name might not be present in the name field, but only in the
	// resolved field
	resolvedPkgName := getPackageNameFromResolved(pkg.Resolved)
	if resolvedPkgName != "" {
		pkg.Name = resolvedPkgName
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
