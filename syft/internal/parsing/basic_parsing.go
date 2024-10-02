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

	lines := ""
	if len(prev) > 1 {
		lines += fmt.Sprintf("%s%s%s\n", l1, sep, prev[len(prev)-2])
	}
	if len(prev) > 0 {
		lines += fmt.Sprintf("%s%s%s\n", l2, sep, prev[len(prev)-1])
	}

	pointer := strings.Repeat(" ", len(l2)+len(sep)+char-1) + "^"

	return fmt.Sprintf("line: %v, char: %v\n%s%s", line, char, lines, pointer)
}
