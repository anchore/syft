package cpe

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_New(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected CPE
	}{
		{
			name:     "gocase",
			input:    `cpe:/a:10web:form_maker:1.0.0::~~~wordpress~~`,
			expected: Must(`cpe:2.3:a:10web:form_maker:1.0.0:*:*:*:*:wordpress:*:*`),
		},
		{
			name:     "dashes",
			input:    `cpe:/a:7-zip:7-zip:4.56:beta:~~~windows~~`,
			expected: Must(`cpe:2.3:a:7-zip:7-zip:4.56:beta:*:*:*:windows:*:*`),
		},
		{
			name:     "URL escape characters",
			input:    `cpe:/a:%240.99_kindle_books_project:%240.99_kindle_books:6::~~~android~~`,
			expected: Must(`cpe:2.3:a:\$0.99_kindle_books_project:\$0.99_kindle_books:6:*:*:*:*:android:*:*`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := New(test.input)
			if err != nil {
				t.Fatalf("got an error while creating CPE: %+v", err)
			}

			if String(actual) != String(test.expected) {
				t.Errorf("mismatched entries:\n\texpected:%+v\n\t  actual:%+v\n", String(test.expected), String(actual))
			}

		})
	}
}

func Test_normalizeCpeField(t *testing.T) {

	tests := []struct {
		field    string
		expected string
	}{
		{
			field:    "something",
			expected: "something",
		},
		{
			field:    "some\\thing",
			expected: `some\thing`,
		},
		{
			field:    "*",
			expected: "",
		},
		{
			field:    "",
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.field, func(t *testing.T) {
			assert.Equal(t, test.expected, normalizeField(test.field))
		})
	}
}

func Test_CPEParser(t *testing.T) {
	var testCases []struct {
		CPEString string `json:"cpe-string"`
		CPEUrl    string `json:"cpe-url"`
		WFN       CPE    `json:"wfn"`
	}
	out, err := os.ReadFile("test-fixtures/cpe-data.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(out, &testCases))

	for _, test := range testCases {
		t.Run(test.CPEString, func(t *testing.T) {
			c1, err := New(test.CPEString)
			assert.NoError(t, err)
			c2, err := New(test.CPEUrl)
			assert.NoError(t, err)
			assert.Equal(t, c1, c2)
			assert.Equal(t, c1, test.WFN)
			assert.Equal(t, c2, test.WFN)
			assert.Equal(t, String(test.WFN), test.CPEString)
		})
	}
}

func Test_InvalidCPE(t *testing.T) {
	type testcase struct {
		name        string
		in          string
		expected    string
		expectedErr bool
	}

	tests := []testcase{
		{
			// 5.3.2: The underscore (x5f) MAY be used, and it SHOULD be used in place of whitespace characters (which SHALL NOT be used)
			name:     "translates spaces",
			in:       "cpe:2.3:a:some-vendor:name:1 2:*:*:*:*:*:*:*",
			expected: "cpe:2.3:a:some-vendor:name:1_2:*:*:*:*:*:*:*",
		},
		{
			// it isn't easily possible in the string formatted string to detect improper escaping of : (it will fail parsing)
			name:        "unescaped ':' cannot be helped -- too many fields",
			in:          "cpe:2.3:a:some-vendor:name:::*:*:*:*:*:*:*",
			expectedErr: true,
		},
		{
			name:     "too few fields",
			in:       "cpe:2.3:a:some-vendor:name:*:*:*:*:*:*:*",
			expected: "cpe:2.3:a:some-vendor:name:*:*:*:*:*:*:*:*",
		},
		// Note: though the CPE spec does not allow for ? and * as escaped character input, these seem to be allowed in
		// the NVD CPE validator for this reason these edge cases were removed
	}

	// the wfn library does not account for escapes of . and -
	exceptions := ".-"
	// it isn't easily possible in the string formatted string to detect improper escaping of : (it will fail parsing)
	skip := ":"

	// make escape exceptions for section 5.3.2 of the CPE spec (2.3)
	for _, char := range allowedCPEPunctuation {
		if strings.Contains(skip, string(char)) {
			continue
		}

		in := fmt.Sprintf("cpe:2.3:a:some-vendor:name:*:%s:*:*:*:*:*:*", string(char))
		exp := fmt.Sprintf(`cpe:2.3:a:some-vendor:name:*:\%s:*:*:*:*:*:*`, string(char))
		if strings.Contains(exceptions, string(char)) {
			exp = in
		}

		tests = append(tests, testcase{
			name:        fmt.Sprintf("allowes future escape of character (%s)", string(char)),
			in:          in,
			expected:    exp,
			expectedErr: false,
		})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, err := New(test.in)
			if test.expectedErr {
				assert.Error(t, err)
				if t.Failed() {
					t.Logf("got CPE: %q details: %+v", String(c), c)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expected, String(c))
		})
	}
}

func Test_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		cpe       string
		parsedCPE CPE
	}{
		{
			name: "normal",
			cpe:  "cpe:2.3:a:some-vendor:name:3.2:*:*:*:*:*:*:*",
			parsedCPE: CPE{
				Part:    "a",
				Vendor:  "some-vendor",
				Product: "name",
				Version: "3.2",
			},
		},
		{
			name: "escaped colon",
			cpe:  "cpe:2.3:a:some-vendor:name:1\\:3.2:*:*:*:*:*:*:*",
			parsedCPE: CPE{
				Part:    "a",
				Vendor:  "some-vendor",
				Product: "name",
				Version: "1:3.2",
			},
		},
		{
			name: "escaped forward slash",
			cpe:  "cpe:2.3:a:test\\/some-vendor:name:3.2:*:*:*:*:*:*:*",
			parsedCPE: CPE{
				Part:    "a",
				Vendor:  "test/some-vendor",
				Product: "name",
				Version: "3.2",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// CPE string must be preserved through a round trip
			assert.Equal(t, test.cpe, String(Must(test.cpe)))
			// The parsed CPE must be the same after a round trip
			assert.Equal(t, Must(test.cpe), Must(String(Must(test.cpe))))
			// The test case parsed CPE must be the same after parsing the input string
			assert.Equal(t, test.parsedCPE, Must(test.cpe))
			// The test case parsed CPE must produce the same string as the input cpe
			assert.Equal(t, String(test.parsedCPE), test.cpe)
		})
	}
}
