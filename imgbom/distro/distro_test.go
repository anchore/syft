package distro

import (
	"fmt"
	"testing"
)

func TestDistro_FullVersion(t *testing.T) {

	tests := []struct {
		dist     Type
		version  string
		expected string
	}{
		{
			version:  "8",
			expected: "8",
		},
		{
			version:  "18.04",
			expected: "18.04",
		},
		{
			version:  "0",
			expected: "0",
		},
		{
			version:  "18.1.2",
			expected: "18.1.2",
		},
	}

	for _, test := range tests {
		name := fmt.Sprintf("%s:%s", test.dist, test.version)
		t.Run(name, func(t *testing.T) {
			d, err := NewDistro(test.dist, test.version)
			if err != nil {
				t.Errorf("could not create distro='%+v:%+v': %+v", test.dist, test.version, err)
			}

			actual := d.FullVersion()
			if actual != test.expected {
				t.Errorf("mismatched distro raw version: '%s'!='%s'", actual, test.expected)
			}
		})
	}

}

func TestDistro_MajorVersion(t *testing.T) {

	tests := []struct {
		dist     Type
		version  string
		expected string
	}{
		{
			version:  "8",
			expected: "8",
		},
		{
			version:  "18.04",
			expected: "18",
		},
		{
			version:  "0",
			expected: "0",
		},
		{
			version:  "18.1.2",
			expected: "18",
		},
	}

	for _, test := range tests {
		name := fmt.Sprintf("%s:%s", test.dist, test.version)
		t.Run(name, func(t *testing.T) {
			d, err := NewDistro(test.dist, test.version)
			if err != nil {
				t.Errorf("could not create distro='%+v:%+v': %+v", test.dist, test.version, err)
			}

			actual := d.MajorVersion()
			if actual != test.expected {
				t.Errorf("mismatched major version: '%s'!='%s'", actual, test.expected)
			}
		})
	}

}
