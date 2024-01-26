package cpe

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBySourceThenSpecificity_Len(t *testing.T) {
	tests := []struct {
		name string
		b    BySourceThenSpecificity
		want int
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.b.Len(), "Len()")
		})
	}
}

func TestBySourceThenSpecificity_Less(t *testing.T) {
	type args struct {
		i int
		j int
	}
	tests := []struct {
		name string
		b    BySourceThenSpecificity
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.b.Less(tt.args.i, tt.args.j), "Less(%v, %v)", tt.args.i, tt.args.j)
		})
	}
}

func TestBySourceThenSpecificity_Swap(t *testing.T) {
	type args struct {
		i int
		j int
	}
	tests := []struct {
		name string
		b    BySourceThenSpecificity
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.b.Swap(tt.args.i, tt.args.j)
		})
	}
}
