package rust

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_packageURL(t *testing.T) {
	type args struct {
		name    string
		version string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "go case",
			args: args{
				name:    "name",
				version: "v0.1.0",
			},
			want: "pkg:cargo/name@v0.1.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, packageURL(tt.args.name, tt.args.version))
		})
	}
}
