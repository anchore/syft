package lua

import (
	"bytes"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/internal/parsing"
)

type rockspec struct {
	value []rockspecNode
}

type rockspecNode struct {
	key   string
	value interface{}
}

func (r rockspecNode) Slice() []rockspecNode {
	out, ok := r.value.([]rockspecNode)
	if ok {
		return out
	}
	return nil
}

func (r rockspecNode) String() string {
	out, ok := r.value.(string)
	if ok {
		return out
	}
	return ""
}

var noReturn = rockspec{
	value: nil,
}

// parseRockspec basic parser for rockspec
func parseRockspecData(reader io.Reader) (rockspec, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return noReturn, err
	}

	i := 0
	locals := make(map[string]string)
	blocks, err := parseRockspecBlock(data, &i, locals)

	if err != nil {
		return noReturn, err
	}

	return rockspec{
		value: blocks,
	}, nil
}

func parseRockspecBlock(data []byte, i *int, locals map[string]string) ([]rockspecNode, error) {
	var out []rockspecNode
	var iterator func(data []byte, i *int, locals map[string]string) (*rockspecNode, error)

	parsing.SkipWhitespace(data, i)

	if *i >= len(data) && len(out) > 0 {
		return nil, fmt.Errorf("unexpected end of block at %d", *i)
	}

	c := data[*i]

	// Block starting with a comment
	if c == '-' {
		parseComment(data, i)
		parsing.SkipWhitespace(data, i)
		c = data[*i]
	}

	switch {
	case c == '"' || c == '\'':
		iterator = parseRockspecListItem
	case isLiteral(c):
		iterator = parseRockspecNode
	default:
		return nil, fmt.Errorf("unexpected character: %s", string(c))
	}

	for *i < len(data) {
		item, err := iterator(data, i, locals)
		if err != nil {
			return nil, fmt.Errorf("%w\n%s", err, parsing.PrintError(data, *i))
		}

		parsing.SkipWhitespace(data, i)

		if (item.key == "," || item.key == "-") && item.value == nil {
			continue
		}

		if item.key == "}" && item.value == nil {
			break
		}

		out = append(out, *item)
	}

	return out, nil
}

//nolint:funlen, gocognit
func parseRockspecNode(data []byte, i *int, locals map[string]string) (*rockspecNode, error) {
	parsing.SkipWhitespace(data, i)

	if *i >= len(data) {
		return nil, fmt.Errorf("unexpected end of node at %d", *i)
	}

	c := data[*i]

	if c == ',' || c == ';' || c == '}' {
		*i++
		return &rockspecNode{
			key: string(c),
		}, nil
	}

	if c == '-' {
		offset := *i + 1
		if offset >= len(data) {
			return nil, fmt.Errorf("unexpected character: %s", string(c))
		}
		c2 := data[offset]

		if c2 != '-' {
			return nil, fmt.Errorf("unexpected character: %s", string(c2))
		}

		parseComment(data, i)
		return &rockspecNode{
			key: string(c),
		}, nil
	}

	if !isLiteral(c) {
		return nil, fmt.Errorf("invalid literal character: %s", string(c))
	}

	key, err := parseRockspecLiteral(data, i, locals)
	if err != nil {
		return nil, err
	}

	parsing.SkipWhitespace(data, i)

	if *i >= len(data) {
		return nil, fmt.Errorf("unexpected end of node at %d", *i)
	}

	if key == "local" {
		err := parseLocal(data, i, locals)
		if err != nil {
			return nil, err
		}
		return &rockspecNode{
			key: ",",
		}, nil
	}

	c = data[*i]
	if c != '=' {
		return nil, fmt.Errorf("unexpected character: %s", string(c))
	}

	*i++
	parsing.SkipWhitespace(data, i)

	if *i >= len(data) {
		return nil, fmt.Errorf("unexpected end of node at %d", *i)
	}

	if key == "build" {
		skipBuildNode(data, i)

		return &rockspecNode{
			key: ",",
		}, nil
	}

	c = data[*i]

	switch c {
	case '{':
		offset := *i + 1
		parsing.SkipWhitespace(data, &offset)
		if offset >= len(data) {
			return nil, fmt.Errorf("unterminated block at %d", *i)
		}
		c2 := data[offset]

		// Add support for empty lists
		if c == '{' && c2 == '}' {
			*i = offset + 1
			return &rockspecNode{}, nil
		} else {
			*i = offset
		}

		parsing.SkipWhitespace(data, i)

		obj, err := parseRockspecBlock(data, i, locals)

		if err != nil {
			return nil, err
		}
		value := obj

		return &rockspecNode{
			key, value,
		}, nil
	case '(':
		skipExpression(data, i)
		return &rockspecNode{
			key: ",",
		}, nil
	case '[':
		offset := *i + 1
		if offset >= len(data) {
			return nil, fmt.Errorf("unterminated block at %d", *i)
		}
		c2 := data[offset]

		if c2 != '[' {
			return nil, fmt.Errorf("unexpected character: %s", string(c))
		}

		*i++

		str, err := parseRockspecString(data, i, locals)

		if err != nil {
			return nil, err
		}
		value := str.String()

		c = data[*i]

		if c != ']' {
			return nil, fmt.Errorf("unexpected character: %s", string(c))
		}

		*i++

		return &rockspecNode{
			key, value,
		}, nil
	}

	value, err := parseRockspecValue(data, i, locals, "")

	if err != nil {
		return nil, err
	}

	return &rockspecNode{
		key, value,
	}, nil
}

func parseRockspecListItem(data []byte, i *int, locals map[string]string) (*rockspecNode, error) {
	parsing.SkipWhitespace(data, i)

	if *i >= len(data) {
		return nil, fmt.Errorf("unexpected end of block at %d", *i)
	}

	c := data[*i]
	if c == ',' || c == ';' || c == '}' {
		*i++
		return &rockspecNode{
			key: string(c),
		}, nil
	}

	if c == '-' {
		offset := *i + 1
		if offset >= len(data) {
			return nil, fmt.Errorf("unexpected character: %s", string(c))
		}
		c2 := data[offset]

		if c2 != '-' {
			return nil, fmt.Errorf("unexpected character: %s", string(c2))
		}

		parseComment(data, i)
		return &rockspecNode{
			key: string(c),
		}, nil
	}

	str, err := parseRockspecString(data, i, locals)
	if err != nil {
		return nil, err
	}
	return str, nil
}

func parseRockspecValue(data []byte, i *int, locals map[string]string, initialValue string) (string, error) {
	c := data[*i]

	var value string

	switch c {
	case '"', '\'':
		str, err := parseRockspecString(data, i, locals)

		if err != nil {
			return "", err
		}
		value = str.value.(string)
	default:
		local, err := parseRockspecLiteral(data, i, locals)

		if err != nil {
			return "", err
		}

		l, ok := locals[local]

		if !ok {
			return "", fmt.Errorf("unknown local: %s", local)
		}

		value = l
	}

	value = fmt.Sprintf("%s%s", initialValue, value)

	skipWhitespaceNoNewLine(data, i)

	if len(data) > *i+2 {
		if data[*i] == '.' && data[*i+1] == '.' {
			*i += 2

			skipWhitespaceNoNewLine(data, i)

			if *i >= len(data) {
				return "", fmt.Errorf("unexpected end of expression at %d", *i)
			}

			v, err := parseRockspecValue(data, i, locals, value)

			if err != nil {
				return "", err
			}

			value = v
		}
	}

	return value, nil
}

func parseRockspecLiteral(data []byte, i *int, locals map[string]string) (string, error) {
	var buf bytes.Buffer
out:
	for *i < len(data) {
		c := data[*i]
		switch {
		case c == '[':
			*i++
			nested, err := parseRockspecString(data, i, locals)
			if err != nil {
				return "", err
			}
			c = data[*i]
			if c != ']' {
				return "", fmt.Errorf("unterminated literal at %d", *i)
			}
			buf.WriteString(fmt.Sprintf("[\"%s\"]", nested.String()))
		case isLiteral(c):
			buf.WriteByte(c)
		default:
			break out
		}
		*i++
	}
	return buf.String(), nil
}

func parseRockspecString(data []byte, i *int, _ map[string]string) (*rockspecNode, error) {
	delim := data[*i]
	var endDelim byte
	switch delim {
	case '"', '\'':
		endDelim = delim
	case '[':
		endDelim = ']'
	}

	*i++
	var buf bytes.Buffer
	for *i < len(data) {
		c := data[*i]
		if c == endDelim {
			*i++
			str := rockspecNode{value: buf.String()}
			return &str, nil
		}
		buf.WriteByte(c)
		*i++
	}
	return nil, fmt.Errorf("unterminated string at %d", *i)
}

func parseComment(data []byte, i *int) {
	for *i < len(data) {
		c := data[*i]

		*i++

		// Rest of a line is a comment. Deals with CR, LF and CR/LF
		if c == '\n' {
			break
		} else if c == '\r' && data[*i] == '\n' {
			*i++
			break
		}
	}
}

//nolint:funlen
func parseLocal(data []byte, i *int, locals map[string]string) error {
	keys := []string{}
	values := []string{}

keys:
	for {
		parsing.SkipWhitespace(data, i)

		key, err := parseRockspecLiteral(data, i, locals)
		if err != nil {
			return err
		}

		if key == "function" {
			err := skipFunction(data, i)
			if err != nil {
				return err
			}
			return nil
		}

		keys = append(keys, key)

		parsing.SkipWhitespace(data, i)

		c := data[*i]

		switch c {
		case ',':
			*i++
			continue
		case '=':
			*i++
			break keys
		default:
			return fmt.Errorf("unexpected character: %s", string(c))
		}
	}

values:
	for {
		skipWhitespaceNoNewLine(data, i)

		c := data[*i]

		switch c {
		case '"', '\'':
			value, err := parseRockspecString(data, i, locals)

			if err != nil {
				return err
			}
			values = append(values, value.value.(string))
		default:
			ref, err := parseRockspecLiteral(data, i, locals)
			if err != nil {
				return err
			}

			// Skip if it's an expression
			skipWhitespaceNoNewLine(data, i)
			c := data[*i]

			var value string

			if c != '\n' && c != '\r' {
				skipExpression(data, i)
				value = ""
			} else {
				value = locals[ref]
			}

			values = append(values, value)
		}

		skipWhitespaceNoNewLine(data, i)

		c = data[*i]

		switch c {
		case ',':
			*i++
			continue
		case '\n', '\r':
			parsing.SkipWhitespace(data, i)
			break values
		}
	}

	if len(keys) != len(values) {
		return fmt.Errorf("expected %d values got %d", len(keys), len(values))
	}

	for i := 0; i < len(keys); i++ {
		locals[keys[i]] = values[i]
	}

	return nil
}

func skipBuildNode(data []byte, i *int) {
	bracesCount := 0

	for *i < len(data) {
		c := data[*i]

		switch c {
		case '{':
			bracesCount++
		case '}':
			bracesCount--
		}

		if bracesCount == 0 {
			return
		}

		*i++
	}
}

func skipFunction(data []byte, i *int) error {
	blocks := 1

	for *i < len(data)-5 {
		if parsing.IsWhitespace(data[*i]) {
			switch {
			case string(data[*i+1:*i+3]) == "if" && parsing.IsWhitespace(data[*i+3]):
				blocks++
				*i += 3
			case string(data[*i+1:*i+4]) == "end" && parsing.IsWhitespace(data[*i+4]):
				blocks--
				*i += 4

				if blocks == 0 {
					return nil
				}
			default:
				*i++
			}
		} else {
			*i++
		}
	}

	return fmt.Errorf("unterminated function at %d", *i)
}

func skipExpression(data []byte, i *int) {
	parseComment(data, i)
}

func skipWhitespaceNoNewLine(data []byte, i *int) {
	for *i < len(data) && (data[*i] == ' ' || data[*i] == '\t') {
		*i++
	}
}

func isLiteral(c byte) bool {
	if c == '[' || c == ']' {
		return true
	}
	if c == '.' {
		return false
	}
	return parsing.IsLiteral(c)
}
