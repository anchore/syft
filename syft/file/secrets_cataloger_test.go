package file

import (
	"regexp"
	"testing"

	"github.com/anchore/syft/internal/file"

	"github.com/anchore/syft/syft/source"

	"github.com/stretchr/testify/assert"
)

func TestSecretsCataloger(t *testing.T) {
	tests := []struct {
		name           string
		fixture        string
		reveal         bool
		maxSize        int64
		patterns       map[string]string
		expected       []Secret
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
			expected: []Secret{
				{
					PatternName: "simple-secret-key",
					Position:    34,
					Length:      21,
					Value:       "secret_key=clear_text",
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
			expected: []Secret{
				{
					PatternName: "simple-secret-key",
					Position:    34,
					Length:      21,
					Value:       "",
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
			expected: []Secret{
				{
					PatternName: "simple-secret-key",
					Position:    45,
					Length:      10,
					Value:       "clear_text",
				},
			},
		},
		{
			name:    "multiple-secret-instances",
			fixture: "test-fixtures/secrets/multiple.txt",
			reveal:  true,
			patterns: map[string]string{
				"simple-secret-key": `^secret_key=.*`,
			},
			expected: []Secret{
				{
					PatternName: "simple-secret-key",
					Position:    0,
					Length:      22,
					Value:       "secret_key=clear_text1",
				},
				{
					PatternName: "simple-secret-key",
					Position:    57,
					Length:      22,
					Value:       "secret_key=clear_text2",
				},
				{
					PatternName: "simple-secret-key",
					Position:    80,
					Length:      22,
					Value:       "secret_key=clear_text3",
				},
				{
					PatternName: "simple-secret-key",
					Position:    138,
					Length:      22,
					Value:       "secret_key=clear_text4",
				},
			},
		},
		{
			name:    "multiple-secret-instances-with-capture-group",
			fixture: "test-fixtures/secrets/multiple.txt",
			reveal:  true,
			patterns: map[string]string{
				"simple-secret-key": `^secret_key=(?P<value>.*)`,
			},
			expected: []Secret{
				{
					PatternName: "simple-secret-key",
					Position:    11,
					Length:      11,
					Value:       "clear_text1",
				},
				{
					PatternName: "simple-secret-key",
					Position:    68,
					Length:      11,
					Value:       "clear_text2",
				},
				{
					PatternName: "simple-secret-key",
					Position:    91,
					Length:      11,
					Value:       "clear_text3",
				},
				{
					PatternName: "simple-secret-key",
					Position:    149,
					Length:      11,
					Value:       "clear_text4",
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

			c, err := NewSecretsCataloger(regexObjs, test.reveal, test.maxSize)
			if err != nil && !test.constructorErr {
				t.Fatalf("could not create cataloger (but should have been able to): %+v", err)
			} else if err == nil && test.constructorErr {
				t.Fatalf("expected constructor error but did not get one")
			} else if test.constructorErr && err != nil {
				return
			}

			resolver := source.NewMockResolverForPaths(test.fixture)

			actualResults, err := c.Catalog(resolver)
			if err != nil && !test.catalogErr {
				t.Fatalf("could not catalog (but should have been able to): %+v", err)
			} else if err == nil && test.catalogErr {
				t.Fatalf("expected catalog error but did not get one")
			} else if test.catalogErr && err != nil {
				return
			}

			loc := source.NewLocation(test.fixture)
			if _, exists := actualResults[loc]; !exists {
				t.Fatalf("could not find location=%q in results", loc)
			}

			assert.Equal(t, test.expected, actualResults[loc], "mismatched secrets")
		})
	}
}

func TestCombineSecretPatterns(t *testing.T) {
	tests := []struct {
		name       string
		base       map[string]string
		additional map[string]string
		exclude    []string
		expected   map[string]string
	}{
		{
			name: "use-base-set",
			base: map[string]string{
				"in-default": `^secret_key=.*`,
			},
			expected: map[string]string{
				"in-default": `^secret_key=.*`,
			},
		},
		{
			name: "exclude-from-base-set",
			base: map[string]string{
				"in-default":      `^secret_key=.*`,
				"also-in-default": `^also-in-default=.*`,
			},
			exclude: []string{"also-in-default"},
			expected: map[string]string{
				"in-default": `^secret_key=.*`,
			},
		},
		{
			name: "exclude-all",
			base: map[string]string{
				"in-default":      `^secret_key=.*`,
				"also-in-default": `^also-in-default=.*`,
			},
			exclude:  []string{"*"},
			expected: map[string]string{},
		},
		{
			name: "exclude-some",
			base: map[string]string{
				"real":            `^real=.*`,
				"in-default":      `^secret_key=.*`,
				"also-in-default": `^also-in-default=.*`,
			},
			exclude: []string{"*-default"},
			expected: map[string]string{
				"real": `^real=.*`,
			},
		},
		{
			name: "additional-pattern-unison",
			base: map[string]string{
				"in-default": `^secret_key=.*`,
			},
			additional: map[string]string{
				"additional": `^additional=.*`,
			},
			expected: map[string]string{
				"in-default": `^secret_key=.*`,
				"additional": `^additional=.*`,
			},
		},
		{
			name: "override",
			base: map[string]string{
				"in-default": `^secret_key=.*`,
			},
			additional: map[string]string{
				"in-default": `^additional=.*`,
			},
			expected: map[string]string{
				"in-default": `^additional=.*`,
			},
		},
		{
			name: "exclude-and-override",
			base: map[string]string{
				"in-default": `^secret_key=.*`,
			},
			exclude: []string{"in-default"},
			additional: map[string]string{
				"in-default": `^additional=.*`,
			},
			expected: map[string]string{
				"in-default": `^additional=.*`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualObj, err := CombineSecretPatterns(test.base, test.additional, test.exclude)
			if err != nil {
				t.Fatalf("unable to combine: %+v", err)
			}

			actual := make(map[string]string)
			for n, v := range actualObj {
				actual[n] = v.String()
			}

			assert.Equal(t, test.expected, actual, "mismatched combination")
		})
	}
}

func TestSecretsCataloger_DefaultSecrets(t *testing.T) {
	regexObjs, err := CombineSecretPatterns(DefaultSecretsPatterns, nil, nil)
	if err != nil {
		t.Fatalf("unable to get patterns: %+v", err)
	}

	tests := []struct {
		fixture  string
		expected []Secret
	}{
		{
			fixture: "test-fixtures/secrets/default/aws.env",
			expected: []Secret{
				{
					PatternName: "aws-access-key",
					Position:    64,
					Length:      20,
					Value:       "AKIAIOSFODNN7EXAMPLE",
				},
				{
					PatternName: "aws-secret-key",
					Position:    114,
					Length:      40,
					Value:       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				},
			},
		},
		{
			fixture: "test-fixtures/secrets/default/aws.ini",
			expected: []Secret{
				{
					PatternName: "aws-access-key",
					Position:    67,
					Length:      20,
					Value:       "AKIAIOSFODNN7EXAMPLE",
				},
				{
					PatternName: "aws-secret-key",
					Position:    110,
					Length:      40,
					Value:       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				},
			},
		},
		{
			fixture: "test-fixtures/secrets/default/private-key.pem",
			expected: []Secret{
				{
					PatternName: "pem-private-key",
					Position:    39,
					Length:      403,
					Value: `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBj08sp5++4anG
cmQxJjAkBgNVBAoTHVByb2dyZXNzIFNvZnR3YXJlIENvcnBvcmF0aW9uMSAwHgYD
VQQDDBcqLmF3cy10ZXN0LnByb2dyZXNzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
bml6YXRpb252YWxzaGEyZzIuY3JsMIGgBggrBgEFBQcBAQSBkzCBkDBNBggrBgEF
BQcwAoZBaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nvcmdh
z3P668YfhUbKdRF6S42Cg6zn
-----END PRIVATE KEY-----`,
				},
			},
		},
		{
			fixture: "test-fixtures/secrets/default/private-key-openssl.pem",
			expected: []Secret{
				{
					PatternName: "pem-private-key",
					Position:    39,
					Length:      419,
					Value: `-----BEGIN OPENSSL PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBj08sp5++4anG
cmQxJjAkBgNVBAoTHVByb2dyZXNzIFNvZnR3YXJlIENvcnBvcmF0aW9uMSAwHgYD
VQQDDBcqLmF3cy10ZXN0LnByb2dyZXNzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
bml6YXRpb252YWxzaGEyZzIuY3JsMIGgBggrBgEFBQcBAQSBkzCBkDBNBggrBgEF
BQcwAoZBaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nvcmdh
z3P668YfhUbKdRF6S42Cg6zn
-----END OPENSSL PRIVATE KEY-----`,
				},
			},
		},
		{
			fixture: "test-fixtures/secrets/default/docker-config.json",
			expected: []Secret{
				{
					PatternName: "docker-config-auth",
					Position:    100,
					Length:      10,
					Value:       "tOpsyKreTz",
				},
			},
		},
		{
			fixture:  "test-fixtures/secrets/default/not-docker-config.json",
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {

			c, err := NewSecretsCataloger(regexObjs, true, 10*file.MB)
			if err != nil {
				t.Fatalf("could not create cataloger: %+v", err)
			}

			resolver := source.NewMockResolverForPaths(test.fixture)

			actualResults, err := c.Catalog(resolver)
			if err != nil {
				t.Fatalf("could not catalog: %+v", err)
			}

			loc := source.NewLocation(test.fixture)
			if _, exists := actualResults[loc]; !exists {
				t.Fatalf("could not find location=%q in results", loc)
			}

			assert.Equal(t, test.expected, actualResults[loc], "mismatched secrets")
		})
	}
}
