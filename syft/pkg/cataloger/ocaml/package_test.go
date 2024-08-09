package ocaml

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
				name:    "ocaml-base-compiler",
				version: "5.2.0",
			},
			want: "pkg:opam/ocaml-base-compiler@5.2.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, opamPackageURL(tt.args.name, tt.args.version))
		})
	}
}
