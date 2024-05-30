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
			name: "variables",
			content: `
local foo = "bar"
local baz = foo

hello = baz
`,
		},
		{
			name: "multiple variables in one line",
			content: `
local foo, bar = "hello", "world"
baz = foo
test = bar
`,
		},
		{
			name: "skip expressions",
			content: `
test = (hello == "world") and "foo" or "bar"
baz = "123"
`,
		},
		{
			name: "skip expressions in locals",
			content: `
local var1 = "foo"
local var2 = var1 == "foo" and "true" or ("false")

foo = "bar"
`,
		},
		{
			name: "concatenation",
			content: `
local foo = "bar"
local baz = "123"
hello = "world"..baz
baz = foo.." "..baz
test = foo .. baz
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
			name: "content start with comment",
			content: `
foo = "bar"
-- this is a comment
object = {
	-- this is another comment
	hello = "world"
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
			name: "skip build section",
			content: `
foo = "bar"
build = {
	a = {
		{
			content
		}
	}
}
bar = "baz"
`,
		},
		{
			name: "skip functions",
			content: `
local function test
	if foo == bar then
		if hello = world then
			blah
		end
	end
end
test = "blah"
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
			name:    "unterminated block",
			wantErr: require.Error,
			content: `
foo = "bar"
hello = "world"
object = {
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
			name:    "unterminated multiline string",
			wantErr: require.Error,
			content: `
		foo = "bar"
		hello = "world"
		object = [[
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
		{
			name:    "list with unterminated comment",
			wantErr: require.Error,
			content: `
list = {
	"foo",
	"bar",
	-`,
		},
		{
			name:    "undefined local",
			wantErr: require.Error,
			content: `
test = hello
		`,
		},
		{
			name:    "unterminated concatenation",
			wantErr: require.Error,
			content: `
local foo = "123"
hello = foo..  `,
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
