package secrets

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/file"
)

func TestSecretsCataloger(t *testing.T) {
	tests := []struct {
		name           string
		fixture        string
		reveal         bool
		maxSize        int64
		patterns       map[string]string
		expected       []file.SearchResult
		constructorErr bool
		catalogErr     bool
	}{
		{
			name:    "go-case-find-and-reveal",
			fixture: "test-fixtures/secrets/simple.txt",
			reveal:  true,
			patterns: map[string]string{
				"simple-secret-key": `^secret_key=.*`,
			},
			expected: []file.SearchResult{
				{
					Classification: "simple-secret-key",
					LineNumber:     2,
					LineOffset:     0,
					SeekPosition:   34,
					Length:         21,
					Value:          "secret_key=clear_text",
				},
			},
		},
		{
			name:    "dont-reveal-secret-value",
			fixture: "test-fixtures/secrets/simple.txt",
			reveal:  false,
			patterns: map[string]string{
				"simple-secret-key": `^secret_key=.*`,
			},
			expected: []file.SearchResult{
				{
					Classification: "simple-secret-key",
					LineNumber:     2,
					LineOffset:     0,
					SeekPosition:   34,
					Length:         21,
					Value:          "",
				},
			},
		},
		{
			name:    "reveal-named-capture-group",
			fixture: "test-fixtures/secrets/simple.txt",
			reveal:  true,
			patterns: map[string]string{
				"simple-secret-key": `^secret_key=(?P<value>.*)`,
			},
			expected: []file.SearchResult{
				{
					Classification: "simple-secret-key",
					LineNumber:     2,
					LineOffset:     11,
					SeekPosition:   45,
					Length:         10,
					Value:          "clear_text",
				},
			},
		},
		{
			name:    "multiple-secret-instances",
			fixture: "test-fixtures/secrets/multiple.txt",
			reveal:  true,
			patterns: map[string]string{
				"simple-secret-key": `secret_key=.*`,
			},
			expected: []file.SearchResult{
				{
					Classification: "simple-secret-key",
					LineNumber:     1,
					LineOffset:     0,
					SeekPosition:   0,
					Length:         22,
					Value:          "secret_key=clear_text1",
				},
				{
					Classification: "simple-secret-key",
					LineNumber:     3,
					LineOffset:     0,
					SeekPosition:   57,
					Length:         22,
					Value:          "secret_key=clear_text2",
				},
				{
					Classification: "simple-secret-key",
					LineNumber:     4,
					// note: this test captures a line offset case
					LineOffset:   1,
					SeekPosition: 81,
					Length:       22,
					Value:        "secret_key=clear_text3",
				},
				{
					Classification: "simple-secret-key",
					LineNumber:     6,
					LineOffset:     0,
					SeekPosition:   139,
					Length:         22,
					Value:          "secret_key=clear_text4",
				},
			},
		},
		{
			name:    "multiple-secret-instances-with-capture-group",
			fixture: "test-fixtures/secrets/multiple.txt",
			reveal:  true,
			patterns: map[string]string{
				"simple-secret-key": `secret_key=(?P<value>.*)`,
			},
			expected: []file.SearchResult{
				{
					Classification: "simple-secret-key",
					LineNumber:     1,
					// note: value capture group location
					LineOffset:   11,
					SeekPosition: 11,
					Length:       11,
					Value:        "clear_text1",
				},
				{
					Classification: "simple-secret-key",
					LineNumber:     3,
					LineOffset:     11,
					SeekPosition:   68,
					Length:         11,
					Value:          "clear_text2",
				},
				{
					Classification: "simple-secret-key",
					LineNumber:     4,
					// note: value capture group location + offset
					LineOffset:   12,
					SeekPosition: 92,
					Length:       11,
					Value:        "clear_text3",
				},
				{
					Classification: "simple-secret-key",
					LineNumber:     6,
					LineOffset:     11,
					SeekPosition:   150,
					Length:         11,
					Value:          "clear_text4",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			regexObjs := make(map[string]*regexp.Regexp)
			for name, pattern := range test.patterns {
				// always assume given patterns should be multiline
				obj, err := regexp.Compile(`` + pattern)
				if err != nil {
					t.Fatalf("unable to parse regex: %+v", err)
				}
				regexObjs[name] = obj
			}

			c, err := NewCataloger(regexObjs, test.reveal, test.maxSize)
			if err != nil && !test.constructorErr {
				t.Fatalf("could not create cataloger (but should have been able to): %+v", err)
			} else if err == nil && test.constructorErr {
				t.Fatalf("expected constructor error but did not get one")
			} else if test.constructorErr && err != nil {
				return
			}

			resolver := file.NewMockResolverForPaths(test.fixture)

			actualResults, err := c.Catalog(resolver)
			if err != nil && !test.catalogErr {
				t.Fatalf("could not catalog (but should have been able to): %+v", err)
			} else if err == nil && test.catalogErr {
				t.Fatalf("expected catalog error but did not get one")
			} else if test.catalogErr && err != nil {
				return
			}

			loc := file.NewLocation(test.fixture)
			if _, exists := actualResults[loc.Coordinates]; !exists {
				t.Fatalf("could not find location=%q in results", loc)
			}

			assert.Equal(t, test.expected, actualResults[loc.Coordinates], "mismatched secrets")
		})
	}
}

func TestSecretsCataloger_DefaultSecrets(t *testing.T) {
	regexObjs, err := GenerateSearchPatterns(DefaultSecretsPatterns, nil, nil)
	if err != nil {
		t.Fatalf("unable to get patterns: %+v", err)
	}

	tests := []struct {
		fixture  string
		expected []file.SearchResult
	}{
		{
			fixture: "test-fixtures/secrets/default/aws.env",
			expected: []file.SearchResult{
				{
					Classification: "aws-access-key",
					LineNumber:     2,
					LineOffset:     25,
					SeekPosition:   64,
					Length:         20,
					Value:          "AKIAIOSFODNN7EXAMPLE",
				},
				{
					Classification: "aws-secret-key",
					LineNumber:     3,
					LineOffset:     29,
					SeekPosition:   114,
					Length:         40,
					Value:          "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				},
			},
		},
		{
			fixture: "test-fixtures/secrets/default/aws.ini",
			expected: []file.SearchResult{
				{
					Classification: "aws-access-key",
					LineNumber:     3,
					LineOffset:     18,
					SeekPosition:   67,
					Length:         20,
					Value:          "AKIAIOSFODNN7EXAMPLE",
				},
				{
					Classification: "aws-secret-key",
					LineNumber:     4,
					LineOffset:     22,
					SeekPosition:   110,
					Length:         40,
					Value:          "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				},
			},
		},
		{
			fixture: "test-fixtures/secrets/default/private-key.pem",
			expected: []file.SearchResult{
				{
					Classification: "pem-private-key",
					LineNumber:     2,
					LineOffset:     27,
					SeekPosition:   66,
					Length:         351,
					Value: `
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBj08sp5++4anG
cmQxJjAkBgNVBAoTHVByb2dyZXNzIFNvZnR3YXJlIENvcnBvcmF0aW9uMSAwHgYD
VQQDDBcqLmF3cy10ZXN0LnByb2dyZXNzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
bml6YXRpb252YWxzaGEyZzIuY3JsMIGgBggrBgEFBQcBAQSBkzCBkDBNBggrBgEF
BQcwAoZBaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nvcmdh
z3P668YfhUbKdRF6S42Cg6zn
`,
				},
			},
		},
		{
			fixture: "test-fixtures/secrets/default/private-key-openssl.pem",
			expected: []file.SearchResult{
				{
					Classification: "pem-private-key",
					LineNumber:     2,
					LineOffset:     35,
					SeekPosition:   74,
					Length:         351,
					Value: `
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBj08sp5++4anG
cmQxJjAkBgNVBAoTHVByb2dyZXNzIFNvZnR3YXJlIENvcnBvcmF0aW9uMSAwHgYD
VQQDDBcqLmF3cy10ZXN0LnByb2dyZXNzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
bml6YXRpb252YWxzaGEyZzIuY3JsMIGgBggrBgEFBQcBAQSBkzCBkDBNBggrBgEF
BQcwAoZBaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nvcmdh
z3P668YfhUbKdRF6S42Cg6zn
`,
				},
			},
		},
		{
			// note: this test proves that the PEM regex matches the smallest possible match
			// since the test catches two adjacent secrets
			fixture: "test-fixtures/secrets/default/private-keys.pem",
			expected: []file.SearchResult{
				{
					Classification: "pem-private-key",
					LineNumber:     1,
					LineOffset:     35,
					SeekPosition:   35,
					Length:         351,
					Value: `
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBj08sp5++4anG
cmQxJjAkBgNVBAoTHVByb2dyZXNzIFNvZnR3YXJlIENvcnBvcmF0aW9uMSAwHgYD
VQQDDBcqLmF3cy10ZXN0LnByb2dyZXNzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
bml6YXRpb252YWxzaGEyZzIuY3JsMIGgBggrBgEFBQcBAQSBkzCBkDBNBggrBgEF
BQcwAoZBaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nvcmdh
z3P668YfhUbKdRF6S42Cg6zn
`,
				},
				{
					Classification: "pem-private-key",
					LineNumber:     9,
					LineOffset:     35,
					SeekPosition:   455,
					Length:         351,
					Value: `
MIIEvgTHISISNOTAREALKEYoIBAQDBj08DBj08DBj08DBj08DBj08DBsp5++4an3
cmQxJjAkBgNVBAoTHVByb2dyZXNzIFNvZnR3YXJlIENvcnBvcmF0aW9uMSAwHgY5
VQQDDBcqLmF3cy10ZXN0SISNOTAREALKEYoIBAQDBj08DfffKoZIhvcNAQEBBQA7
bml6SISNOTAREALKEYoIBAQDBj08DdssBggrBgEFBQcBAQSBkzCBkDBNBggrBgE8
BQcwAoZBaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nvcmd1
j4f668YfhUbKdRF6S6734856
`,
				},
			},
		},
		{
			fixture:  "test-fixtures/secrets/default/private-key-false-positive.pem",
			expected: nil,
		},
		{
			// this test represents:
			// 1. a docker config
			// 2. a named capture group with the correct line number and line offset case
			// 3. the named capture group is in a different line than the match start, and both the match start and the capture group have different line offsets
			fixture: "test-fixtures/secrets/default/docker-config.json",
			expected: []file.SearchResult{
				{
					Classification: "docker-config-auth",
					LineNumber:     5,
					LineOffset:     15,
					SeekPosition:   100,
					Length:         10,
					Value:          "tOpsyKreTz",
				},
			},
		},
		{
			fixture:  "test-fixtures/secrets/default/not-docker-config.json",
			expected: nil,
		},
		{
			fixture: "test-fixtures/secrets/default/api-key.txt",
			expected: []file.SearchResult{
				{
					Classification: "generic-api-key",
					LineNumber:     2,
					LineOffset:     7,
					SeekPosition:   33,
					Length:         20,
					Value:          "12345A7a901b34567890",
				},
				{
					Classification: "generic-api-key",
					LineNumber:     3,
					LineOffset:     9,
					SeekPosition:   63,
					Length:         30,
					Value:          "12345A7a901b345678901234567890",
				},
				{
					Classification: "generic-api-key",
					LineNumber:     4,
					LineOffset:     10,
					SeekPosition:   104,
					Length:         40,
					Value:          "12345A7a901b3456789012345678901234567890",
				},
				{
					Classification: "generic-api-key",
					LineNumber:     5,
					LineOffset:     10,
					SeekPosition:   156,
					Length:         50,
					Value:          "12345A7a901b34567890123456789012345678901234567890",
				},
				{
					Classification: "generic-api-key",
					LineNumber:     6,
					LineOffset:     16,
					SeekPosition:   224,
					Length:         60,
					Value:          "12345A7a901b345678901234567890123456789012345678901234567890",
				},
				{
					Classification: "generic-api-key",
					LineNumber:     14,
					LineOffset:     8,
					SeekPosition:   502,
					Length:         20,
					Value:          "11111111111111111111",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {

			c, err := NewCataloger(regexObjs, true, 10*intFile.MB)
			if err != nil {
				t.Fatalf("could not create cataloger: %+v", err)
			}

			resolver := file.NewMockResolverForPaths(test.fixture)

			actualResults, err := c.Catalog(resolver)
			if err != nil {
				t.Fatalf("could not catalog: %+v", err)
			}

			loc := file.NewLocation(test.fixture)
			if _, exists := actualResults[loc.Coordinates]; !exists && test.expected != nil {
				t.Fatalf("could not find location=%q in results", loc)
			} else if !exists && test.expected == nil {
				return
			}

			assert.Equal(t, test.expected, actualResults[loc.Coordinates], "mismatched secrets")
		})
	}
}
