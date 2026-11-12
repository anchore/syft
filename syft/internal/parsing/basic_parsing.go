package parsing

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
)

func IsWhitespace(c byte) bool {
	return unicode.IsSpace(rune(c))
}

func IsLiteral(c byte) bool {
	r := rune(c)
	return unicode.IsNumber(r) || unicode.IsLetter(r) || r == '.' || r == '_'
}

func SkipWhitespace(data []byte, i *int) {
	for *i < len(data) && IsWhitespace(data[*i]) {
		*i++
	}
}

// MaxDepth bounds nesting in the recursive hand-written parsers. Real files nest a handful of levels; without a
// bound, deep input overflows the goroutine stack, which is fatal rather than a recoverable panic.
const MaxDepth = 1000

// errorContext is how many bytes of each echoed line PrintError keeps around the error column, so an error in a
// huge single-line input stays small (and does not copy the file into the SBOM as an unknown).
const errorContext = 80

// PrintError describes where in data offset i is, echoing up to two lines of context clipped around the column.
func PrintError(data []byte, i int) string {
	line := 1
	char := 1

	prev := []string{}
	curr := bytes.Buffer{}

	for idx, c := range data {
		if c == '\n' {
			prev = append(prev, curr.String())
			curr.Reset()

			if idx >= i {
				break
			}

			line++
			char = 1
			continue
		}
		if idx < i {
			char++
		}
		curr.WriteByte(c)
	}

	l1 := fmt.Sprintf("%d", line-1)
	l2 := fmt.Sprintf("%d", line)

	if len(l1) < len(l2) {
		l1 = " " + l1
	}

	sep := ": "

	start := max(0, char-1-errorContext/2)
	clip := func(s string) string {
		if start >= len(s) {
			return ""
		}
		return s[start:min(len(s), start+errorContext)]
	}

	lines := ""
	if len(prev) > 1 {
		lines += fmt.Sprintf("%s%s%s\n", l1, sep, clip(prev[len(prev)-2]))
	}
	if len(prev) > 0 {
		lines += fmt.Sprintf("%s%s%s\n", l2, sep, clip(prev[len(prev)-1]))
	}

	pointer := strings.Repeat(" ", len(l2)+len(sep)+char-1-start) + "^"

	return fmt.Sprintf("line: %v, char: %v\n%s%s", line, char, lines, pointer)
}
