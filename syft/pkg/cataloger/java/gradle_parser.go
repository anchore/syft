package java

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parseJaveGradle

func parseJaveGradle(_ string, reader io.Reader) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package

	dependencyScanner := bufio.NewScanner(reader)

	variables := make(map[string][]byte)

	// get each 'dependency {}' section
	onDependency := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
MAINLOOP:
		for advance = -1; advance < len(data) - 16; {
			// loop through each byte, stops looping once it gets near the end
			for _, char := range []byte{'d','e','p','e','n','d','e','n','c','i','e','s'} {
				// look for the string "dependencies"
				advance++
				if data[advance] != char {
					if char == 'p' && data[advance] == 'f' {
						// stupid way to parse variable definitions
						advance++
						for ; unicode.IsSpace(rune(data[advance])) && advance < len(data); advance++ {}
						// loop until the start of the variable name
						nameStart := advance
						// remember the starting index of the variable name
						for ; unicode.IsLetter(rune(data[advance])) && advance < len(data); advance++ {}
						// loop until the end and record variable name
						varName := string(data[nameStart:advance])
						var terminator byte = '\n'
						// character to read until. end of the quotes if there are any, else newline
						// has to be explicitly set to byte so it can be compared with data[advance]
						start := 0
						for ; start == 0 && advance < len(data); advance++ {
							// loop until the start of the variable('s value)
							if unicode.IsLetter(rune(data[advance])) {
								start = advance
							}
							for _, quote := range []byte{'"', '\''} {
								if data[advance] == quote {
									terminator = quote
									start = advance + 1
								}
							}
						}
						for ; data[advance] != terminator && advance < len(data); advance++ {}
						// loop until end of the variable and store it in the variables map
						variables[varName] = data[start:advance]
					}
					// go doesn't have for ... else so we use this
					continue MAINLOOP
				}
			}
			advance++
			for ; unicode.IsSpace(rune(data[advance])) && advance < len(data) - 2; advance++ {}
			// if it found "dependencies", loop through whitespace
			if data[advance] == '{' {
				advance++
				for start, nest := advance, 0; advance < len(data); advance++ {
					// we've found a group of dependencies, loop to find the end
					switch data[advance] {
					case '$':
						// if there's a `$`, try to insert a variable
						advance++
						varStart := advance
						cutStart := advance - 1
						cutEnd := 0
						if data[advance] == '{' {
							// if the next character is '', read until next ''
							varStart++
							cutEnd = 1
							for ; data[advance] != '}' && advance < len(data); advance++ {}
						} else {
							// else, read until it's not a letter
							for ; unicode.IsLetter(rune(data[advance]))&& advance < len(data); advance++ {}
						}
						variable := variables[string(data[varStart:advance])]
						// get the variable's value from the variables map
						// if it's not found, it just returns null
						tmp := make([]byte, cutStart + len(variable) + len(data) - advance - cutEnd)
						copy(tmp, data[:cutStart])
						copy(tmp[cutStart:], variable)
						copy(tmp[cutStart + len(variable):], data[advance + cutEnd:])
						data = tmp
						// stitch together the arrays to add the variable's value
					case '{':
						nest++
					case '}':
						if nest == 0 {
							token = data[start:advance]
							return
						}
						nest--
					}
				}
			}
			break
		}
		return 0, nil, nil
	}

	onEntry := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		for ; advance < len(data) - 8; advance++ {
			// split into individual strings
			for _, quote := range []byte{'"','\''} {
				// find beginning of the string by looping until there are quotes
				if data[advance] == quote {
					advance++
					for start := advance; advance < len(data); advance++ {
						if data[advance] == quote {
							token = data[start:advance]
							advance++
							return
						}
					}
				}
			}
		}
		return 0, nil, nil
	}

	dependencyScanner.Split(onDependency)
	for dependencyScanner.Scan() {
		 entryScanner := bufio.NewScanner(strings.NewReader(dependencyScanner.Text()))

		entryScanner.Split(onEntry)
		for entryScanner.Scan() {
			name, version, err := parseGradleEntry(entryScanner.Text())
			if err != nil {
				return nil, nil, err
			}
			if metadata != nil {
				packages = append(packages, pkg.Package{
					Name:         name,
					Version:      version,
					FoundBy:      "java-gradle-cataloger",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
				})
			}
		}
		if err := entryScanner.Err(); err != nil {
			return nil, nil, fmt.Errorf("failed to parse build.gradle file: %w", err)
		}
	}

	if err := dependencyScanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to parse build.gradle file: %w", err)
	}

	return packages, nil, nil
}

// nolint:funlen
// parseGradleEntry reads and parses a single pkg.GradleMetadata element from the stream, returning nil if the string is .
func parseGradleEntry(dependency string) (string, string, error) {
	substrings := strings.Split(dependency, ":")

	if len(substrings) != 3 {
		return "", "", nil
	}

	return substrings[1], substrings[2], nil
}
