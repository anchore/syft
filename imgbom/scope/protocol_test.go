package scope

import "testing"

func TestNewProtocol(t *testing.T) {
	testCases := []struct {
		desc     string
		input    string
		expType  protocolType
		expValue string
	}{
		{
			desc:     "directory protocol",
			input:    "dir:///opt/",
			expType:  directoryProtocol,
			expValue: "/opt/",
		},
		{
			desc:     "unknown protocol",
			input:    "s4:///opt/",
			expType:  imageProtocol,
			expValue: "s4:///opt/",
		},
		{
			desc:     "docker protocol",
			input:    "docker://ubuntu:20.04",
			expType:  imageProtocol,
			expValue: "docker://ubuntu:20.04",
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			p := newProtocol(test.input)
			if p.Type != test.expType {
				t.Errorf("mismatched type in protocol: '%v' != '%v'", p.Type, test.expType)
			}
			if p.Value != test.expValue {
				t.Errorf("mismatched protocol value: '%s' != '%s'", p.Value, test.expValue)
			}

		})
	}
}
