package golang

import (
	"debug/elf"
	"debug/macho"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_cleanElfArch(t *testing.T) {
	tests := []struct {
		machine elf.Machine
		want    string
	}{
		{
			machine: elf.EM_X86_64,
			want:    "x86_64",
		},
	}
	for _, test := range tests {
		t.Run(test.machine.String(), func(t *testing.T) {
			assert.Equalf(t, test.want, cleanElfArch(test.machine), "cleanElfArch(%v)", test.machine)
		})
	}
}

func Test_cleanMachoArch(t *testing.T) {
	tests := []struct {
		cpu  macho.Cpu
		want string
	}{
		{
			cpu:  macho.CpuAmd64,
			want: "amd64",
		},
	}
	for _, test := range tests {
		t.Run(test.cpu.String(), func(t *testing.T) {
			assert.Equalf(t, test.want, cleanMachoArch(test.cpu), "cleanMachoArch(%v)", test.cpu)
		})
	}
}
