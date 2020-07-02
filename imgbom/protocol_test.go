package imgbom

import "testing"

func TestNewProtocol(t *testing.T) {
	testCases := []struct {
		desc     string
		input    string
		expType  ProtocolType
		expValue string
	}{
		{
			desc:     "directory protocol",
			input:    "dir:///opt/",
			expType:  DirProtocol,
			expValue: "/opt/",
		},
		{
			desc:     "unknown protocol",
			input:    "s4:///opt/",
			expType:  ImageProtocol,
			expValue: "s4:///opt/",
		},
		{
			desc:     "docker protocol",
			input:    "docker://ubuntu:20.04",
			expType:  ImageProtocol,
			expValue: "docker://ubuntu:20.04",
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			p := NewProtocol(test.input)
			if p.Type != test.expType {
				t.Errorf("mismatched type in protocol: '%v' != '%v'", p.Type, test.expType)
			}
			if p.Value != test.expValue {
				t.Errorf("mismatched protocol value: '%s' != '%s'", p.Value, test.expValue)
			}

		})
	}
}
