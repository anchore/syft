package dotnet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getDepsJSONFilePrefix(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "windows-style full path",
			path: `C:\Code\Projects\My-Project\My.Rest.Project.deps.json`,
			want: "My.Rest.Project",
		},
		{
			name: "leading backslash",
			path: `\My.Project.deps.json`,
			want: "My.Project",
		},
		{
			name: "unix-style path with lots of prefixes",
			path: "/my/cool/project/cool-project.deps.json",
			want: "cool-project",
		},
		{
			name: "unix-style relative path",
			path: "cool-project/my-dotnet-project.deps.json",
			want: "my-dotnet-project",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, getDepsJSONFilePrefix(tt.path), "getDepsJSONFilePrefix(%v)", tt.path)
		})
	}
}
