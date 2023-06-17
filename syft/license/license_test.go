package license

import "testing"

func TestParseExpression(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		want       string
		wantErr    bool
	}{
		{
			name:       "valid single ID expression returns SPDX ID",
			expression: "mit",
			want:       "MIT",
			wantErr:    false,
		},
		{
			name:       "Valid SPDX expression returns SPDX expression",
			expression: "MIT OR Apache-2.0",
			want:       "MIT OR Apache-2.0",
		},
		{
			name:       "Invalid SPDX expression returns error",
			expression: "MIT OR Apache-2.0 OR invalid",
			want:       "",
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseExpression(tt.expression)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseExpression() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseExpression() got = %v, want %v", got, tt.want)
			}
		})
	}
}
