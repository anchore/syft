package fileresolver

import (
	"github.com/moby/sys/mountinfo"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_newPathSkipper(t *testing.T) {
	type setup struct {
		in0        string
		in1        string
		mountInfos []*mountinfo.Info
	}

	type expect struct {
		path    string
		wantErr error
	}
	tests := []struct {
		name  string
		setup setup
		want  []expect
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			visitor := newPathSkipper(tt.setup.in0, tt.setup.in1, tt.setup.mountInfos)
			for _, exp := range tt.want {
				if exp.wantErr == nil {
					assert.NoError(t, visitor("", exp.path, nil, nil))
					continue
				}
				assert.ErrorIs(t, exp.wantErr, visitor("", exp.path, nil, nil))
			}
		})
	}
}
