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
	blocks, err := parseRockspecBlock(data, &i)

	if err != nil {
		return noReturn, err
	}

	return rockspec{
		value: blocks,
	}, nil
}

func parseRockspecBlock(data []byte, i *int) ([]rockspecNode, error) {
	var out []rockspecNode
	var iterator func(data []byte, i *int) (*rockspecNode, error)

	parsing.SkipWhitespace(data, i)

	if *i >= len(data) && len(out) > 0 {
		return nil, fmt.Errorf("unexpected end of block at %d", *i)
	}

	c := data[*i]
	switch {
	case c == '"' || c == '\'':
		iterator = parseRockspecListItem
	case isLiteral(c):
		iterator = parseRockspecNode
	default:
		return nil, fmt.Errorf("unexpected character: %s", string(c))
	}

	for *i < len(data) {
		item, err := iterator(data, i)
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
func parseRockspecNode(data []byte, i *int) (*rockspecNode, error) {
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

	key, err := parseRockspecLiteral(data, i)
	if err != nil {
		return nil, err
	}

	parsing.SkipWhitespace(data, i)

	if *i >= len(data) {
		return nil, fmt.Errorf("unexpected end of node at %d", *i)
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

		obj, err := parseRockspecBlock(data, i)

		if err != nil {
			return nil, err
		}
		value := obj

		return &rockspecNode{
			key, value,
		}, nil
	case '"', '\'':
		str, err := parseRockspecString(data, i)

		if err != nil {
			return nil, err
		}
		value := str.value

		return &rockspecNode{
			key, value,
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

		str, err := parseRockspecString(data, i)

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

	return nil, nil
}

func parseRockspecListItem(data []byte, i *int) (*rockspecNode, error) {
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

	str, err := parseRockspecString(data, i)
	if err != nil {
		return nil, err
	}
	return str, nil
}

func parseRockspecLiteral(data []byte, i *int) (string, error) {
	var buf bytes.Buffer
out:
	for *i < len(data) {
		c := data[*i]
		switch {
		case c == '[':
			*i++
			nested, err := parseRockspecString(data, i)
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

func parseRockspecString(data []byte, i *int) (*rockspecNode, error) {
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

func isLiteral(c byte) bool {
	if c == '[' || c == ']' {
		return true
	}
	return parsing.IsLiteral(c)
}
