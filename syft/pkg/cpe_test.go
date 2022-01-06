package pkg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func must(c CPE, e error) CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func TestNewCPE(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected CPE
	}{
		{
			name:     "gocase",
			input:    `cpe:/a:10web:form_maker:1.0.0::~~~wordpress~~`,
			expected: must(NewCPE(`cpe:2.3:a:10web:form_maker:1.0.0:*:*:*:*:wordpress:*:*`)),
		},
		{
			name:     "dashes",
			input:    `cpe:/a:7-zip:7-zip:4.56:beta:~~~windows~~`,
			expected: must(NewCPE(`cpe:2.3:a:7-zip:7-zip:4.56:beta:*:*:*:windows:*:*`)),
		},
		{
			name:     "URL escape characters",
			input:    `cpe:/a:%240.99_kindle_books_project:%240.99_kindle_books:6::~~~android~~`,
			expected: must(NewCPE(`cpe:2.3:a:\$0.99_kindle_books_project:\$0.99_kindle_books:6:*:*:*:*:android:*:*`)),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := NewCPE(test.input)
			if err != nil {
				t.Fatalf("got an error while creating CPE: %+v", err)
			}

			if CPEString(actual) != CPEString(test.expected) {
				t.Errorf("mismatched entries:\n\texpected:%+v\n\t  actual:%+v\n", CPEString(test.expected), CPEString(actual))
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
			assert.Equal(t, test.expected, normalizeCpeField(test.field))
		})
	}
}

func Test_CPEParser(t *testing.T) {
	testCases := []struct {
		CPEString string `json:"cpe-string"`
		CPEUrl    string `json:"cpe-url"`
		WFN       CPE    `json:"wfn"`
	}{}
	out, err := ioutil.ReadFile("test-fixtures/cpe-data.json")
	if err != nil {
		t.Fatal("Unable to read test-fixtures/cpe-data.json: ", err)
	}
	json.Unmarshal(out, &testCases)
	for _, test := range testCases {
		t.Run(test.CPEString, func(t *testing.T) {
			c1, err := NewCPE(test.CPEString)
			assert.NoError(t, err)
			c2, err := NewCPE(test.CPEUrl)
			assert.NoError(t, err)
			assert.Equal(t, c1, c2)
			assert.Equal(t, c1, test.WFN)
			assert.Equal(t, c2, test.WFN)
			assert.Equal(t, CPEString(test.WFN), test.CPEString)
		})
	}
}

func Test_InvalidCPE(t *testing.T) {

	testCases := []string{
		"cpe:2.3:a:some-vendor:name:1:3.2:*:*:*:*:*:*:*",
		"cpe:2.3:a:some-vendor:name:1^:*:*:*:*:*:*:*",
		"cpe:2.3:a:some-vendor:name:**:*:*:*:*:*:*:*",
		"cpe:2.3:a:some-vendor:name:*\\:*:*:*:*:*:*:*",
	}

	for _, test := range testCases {
		t.Run(test, func(t *testing.T) {
			_, err := NewCPE(test)
			assert.Error(t, err)
			assert.Contains(t, fmt.Sprint(err), "regex")
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
			assert.Equal(t, test.cpe, CPEString(MustCPE(test.cpe)))
			// The parsed CPE must be the same after a round trip
			assert.Equal(t, MustCPE(test.cpe), MustCPE(CPEString(MustCPE(test.cpe))))
			// The test case parsed CPE must be the same after parsing the input string
			assert.Equal(t, test.parsedCPE, MustCPE(test.cpe))
			// The test case parsed CPE must produce the same string as the input cpe
			assert.Equal(t, CPEString(test.parsedCPE), test.cpe)
		})
	}
}
