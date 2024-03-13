package lua

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseRockspecData(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "basic valid content",
			content: `
foo = "bar"
hello = "world"
object = {
	foo = "bar",
	baz = "test",
	nested = {
		lorem = "ipsum"
	}
}
alice = "bob"
`,
		},
		{
			name: "lists",
			content: `
foo = "bar"
list = {"hello", "world" }
`,
		},
		{
			name: "empty list",
			content: `
foo = "bar"
list = {}
`,
		},
		{
			name: "different string delimiters",
			content: `
foo = 'bar'
hello = "world"
`,
		},
		{

			name: "multiline string",
			content: `
foo = "bar"
multiline = [[
	this is
	a multiline
	string
]]
`,
		},
		{
			name: "complex syntax",
			content: `
foo = "bar"
object = {
	["baz"] = "bar"
}
`,
		},
		{
			name: "content with comment",
			content: `
foo = "bar"
-- this is a comment
object = {
	hello = "world"
	-- this is another comment
}
`,
		},
		{
			name: "list with comment",
			content: `
list = {
	"foo",
	"bar",
	-- "baz"
	"hello"
}
`,
		},
		{
			name:    "invalid complex syntax",
			wantErr: require.Error,
			content: `
foo = "bar"
object = {
	["baz" = "bar"
	["hello"] = world
}
`,
		},
		{
			name:    "invalid string content",
			wantErr: require.Error,
			content: `
test = "unfinished
		`,
		},
		{
			name:    "mixed string delimiters",
			wantErr: require.Error,
			content: `
foo = "bar'
`,
		},
		{
			name:    "invalid multiline string content",
			wantErr: require.Error,
			content: `
test = [[
	unfinished
		`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := parseRockspecData(bytes.NewReader([]byte(test.content)))

			if test.wantErr == nil {
				require.NoError(t, err)
			} else {
				test.wantErr(t, err)
			}

			assert.IsType(t, rockspec{}, value)
		})
	}
}
