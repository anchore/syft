package erlang

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseErlang(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "basic valid content",
			content: `
{"1.2.0",
[{<<"bcrypt">>,{pkg,<<"bcrypt">>,<<"1.1.5">>},0},
 {<<"bson">>,
  {git,"https://github.com/comtihon/bson-erlang",
       {ref,"14308ab927cfa69324742c3de720578094e0bb19"}},
  1},
 {<<"syslog">>,{pkg,<<"syslog">>,<<"1.1.0">>},0},
 {<<"unicode_util_compat">>,{pkg,<<"unicode_util_compat">>,<<"0.7.0">>},1},
 {<<"vernemq_dev">>,
  {git,"https://github.com/vernemq/vernemq_dev.git",
       {ref,"6d622aa8c901ae7777433aef2bd049e380c474a6"}},
  0}]
}.
[
{pkg_hash,[
 {<<"bcrypt">>, <<"A6763BD4E1AF46D34776F85B7995E63A02978DE110C077E9570ED17006E03386">>},
 {<<"unicode_util_compat">>, <<"BC84380C9AB48177092F43AC89E4DFA2C6D62B40B8BD132B1059ECC7232F9A78">>}]},
{pkg_hash_ext,[
 {<<"bcrypt">>, <<"3418821BC17CE6E96A4A77D1A88D7485BF783E212069FACFC79510AFBFF95352">>},
 {<<"unicode_util_compat">>, <<"25EEE6D67DF61960CF6A794239566599B09E17E668D3700247BC498638152521">>}]}
].`,
		},
		{
			name: "empty list",
			content: `
{test, [
 {with_space, [ ]},
 {without_space, []}
]}`,
		},
		{
			name: "valid strings",
			content: `
{strings, [
 "foo", 'bar'
]}`,
		},
		{
			name:    "invalid string content",
			wantErr: require.Error,
			content: `
{"1.2.0
">>},
].`,
		},
		{
			name:    "string mismach",
			wantErr: require.Error,
			content: `
{bad_string, [
 'foo"
 ]}`,
		},
		{
			name:    "invalid content",
			wantErr: require.Error,
			content: `
{"1.2.0"}.
].`,
		},
		{
			name: "valid comments",
			content: `
{ comments, [
	{ foo, bar },
	%% this is a comment
	% this is also a comment
	{ hello, 'bar' }, %%inline comment
	{ baz }
]}`,
		},
		{
			name: "starts with a comments",
			content: `
%% starts with comment
{ comments, [
	{ foo, bar }
]}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := parseErlang(bytes.NewReader([]byte(test.content)))

			if test.wantErr == nil {
				require.NoError(t, err)
			} else {
				test.wantErr(t, err)
			}

			assert.IsType(t, erlangNode{}, value)
		})
	}
}
