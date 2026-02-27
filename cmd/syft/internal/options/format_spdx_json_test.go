package options

import (
	"testing"
)

func TestFormatSPDXJSON_buildConfig(t *testing.T) {
	// assert when building the config that we respond to all possible fields

	ft := &FormatSPDXJSON{}
	ft = setAllToNonZero(t, ft).(*FormatSPDXJSON)

	subject := ft.config("Version")
	assertExpectedValue(t, subject)
}

func TestFormatSPDXJSON_Validate(t *testing.T) {
	tests := []struct {
		name        string
		createdTime *int64
		wantErr     bool
	}{
		{
			name:        "nil timestamp is valid",
			createdTime: nil,
			wantErr:     false,
		},
		{
			name:        "positive timestamp is valid",
			createdTime: ptr(int64(1234567890)),
			wantErr:     false,
		},
		{
			name:        "zero timestamp is valid",
			createdTime: ptr(int64(0)),
			wantErr:     false,
		},
		{
			name:        "negative timestamp is invalid",
			createdTime: ptr(int64(-1)),
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := FormatSPDXJSON{
				CreatedTime: tt.createdTime,
			}
			err := o.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
