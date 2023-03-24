package golang

import (
	"fmt"
	"io"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getBuildInfo(t *testing.T) {
	type args struct {
		r io.ReaderAt
	}
	tests := []struct {
		name    string
		args    args
		wantBi  *debug.BuildInfo
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "recover from panic",
			args: args{
				r: nil, // trying to use a nil reader will cause a panic
			},
			wantBi:  nil, // we should not return anything useful
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBi, err := getBuildInfo(tt.args.r)
			if !tt.wantErr(t, err, fmt.Sprintf("getBuildInfo(%v)", tt.args.r)) {
				return
			}
			assert.Equalf(t, tt.wantBi, gotBi, "getBuildInfo(%v)", tt.args.r)
		})
	}
}
