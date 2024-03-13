package erlang

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/internal/parsing"
)

type erlangNode struct {
	value interface{}
}

var errSkipComments = errors.New("")

func (e erlangNode) Slice() []erlangNode {
	out, ok := e.value.([]erlangNode)
	if ok {
		return out
	}
	return []erlangNode{}
}

func (e erlangNode) String() string {
	out, ok := e.value.(string)
	if ok {
		return out
	}
	return ""
}

func (e erlangNode) Get(index int) erlangNode {
	s := e.Slice()
	if len(s) > index {
		return s[index]
	}
	return erlangNode{}
}

func node(value interface{}) erlangNode {
	return erlangNode{
		value: value,
	}
}

// parseErlang basic parser for erlang, used by rebar.lock
func parseErlang(reader io.Reader) (erlangNode, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return node(nil), err
	}

	out := erlangNode{
		value: []erlangNode{},
	}

	i := 0
	for i < len(data) {
		item, err := parseErlangBlock(data, &i)
		if err == errSkipComments {
			parsing.SkipWhitespace(data, &i)
			continue
		}
		if err != nil {
			return node(nil), fmt.Errorf("%w\n%s", err, parsing.PrintError(data, i))
		}

		parsing.SkipWhitespace(data, &i)

		if i, ok := item.value.(string); ok && i == "." {
			continue
		}

		out.value = append(out.value.([]erlangNode), item)
	}
	return out, nil
}

func parseErlangBlock(data []byte, i *int) (erlangNode, error) {
	block, err := parseErlangNode(data, i)
	if err != nil {
		return node(nil), err
	}

	parsing.SkipWhitespace(data, i)
	*i++ // skip the trailing .
	return block, nil
}

func parseErlangNode(data []byte, i *int) (erlangNode, error) {
	parsing.SkipWhitespace(data, i)
	c := data[*i]
	switch c {
	case '[', '{':
		offset := *i + 1
		parsing.SkipWhitespace(data, &offset)
		c2 := data[offset]

		// Add support for empty lists
		if (c == '[' && c2 == ']') || (c == '{' && c2 == '}') {
			*i = offset + 1
			return node(nil), nil
		}

		return parseErlangList(data, i)
	case '"':
		fallthrough
	case '\'':
		return parseErlangString(data, i)
	case '<':
		return parseErlangAngleString(data, i)
	case '%':
		parseErlangComment(data, i)
		return node(nil), errSkipComments
	}

	if parsing.IsLiteral(c) {
		return parseErlangLiteral(data, i)
	}

	return erlangNode{}, fmt.Errorf("invalid literal character: %s", string(c))
}

func parseErlangLiteral(data []byte, i *int) (erlangNode, error) {
	var buf bytes.Buffer
	for *i < len(data) {
		c := data[*i]
		if parsing.IsLiteral(c) {
			buf.WriteByte(c)
		} else {
			break
		}
		*i++
	}
	return node(buf.String()), nil
}

func parseErlangAngleString(data []byte, i *int) (erlangNode, error) {
	*i += 2
	out, err := parseErlangString(data, i)
	*i += 2
	return out, err
}

func parseErlangString(data []byte, i *int) (erlangNode, error) {
	delim := data[*i]
	*i++
	var buf bytes.Buffer
	for *i < len(data) {
		c := data[*i]
		if c == delim {
			*i++
			return node(buf.String()), nil
		}
		if c == '\\' {
			*i++
			if len(data) >= *i {
				return node(nil), fmt.Errorf("invalid escape without closed string at %d", *i)
			}
			c = data[*i]
		}
		buf.WriteByte(c)
		*i++
	}
	return node(nil), fmt.Errorf("unterminated string at %d", *i)
}

func parseErlangList(data []byte, i *int) (erlangNode, error) {
	*i++
	out := erlangNode{
		value: []erlangNode{},
	}
	for *i < len(data) {
		item, err := parseErlangNode(data, i)
		if err != nil {
			if err == errSkipComments {
				parsing.SkipWhitespace(data, i)
				continue
			}
			return node(nil), err
		}
		out.value = append(out.value.([]erlangNode), item)
		parsing.SkipWhitespace(data, i)
		c := data[*i]
		switch c {
		case ',':
			*i++
			continue
		case '%':
			// Starts a new comment node
			continue
		case ']', '}':
			*i++
			return out, nil
		default:
			return node(nil), fmt.Errorf("unexpected character: %s", string(c))
		}
	}
	return out, nil
}

func parseErlangComment(data []byte, i *int) {
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
