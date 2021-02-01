package anchore

import "testing"

func TestHasScheme(t *testing.T) {
	cases := []struct {
		url      string
		expected bool
	}{
		{
			url:      "http://localhost",
			expected: true,
		},
		{
			url:      "https://anchore.com:8443",
			expected: true,
		},
		{
			url:      "google.com",
			expected: false,
		},
		{
			url:      "",
			expected: false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.url, func(t *testing.T) {
			result := hasScheme(testCase.url)

			if testCase.expected != result {
				t.Errorf("expected %t but got %t", testCase.expected, result)
			}
		})
	}
}

func TestEnsureURLHasScheme(t *testing.T) {
	cases := []struct {
		url      string
		expected string
	}{
		{
			url:      "http://localhost",
			expected: "http://localhost",
		},
		{
			url:      "https://anchore.com:8443",
			expected: "https://anchore.com:8443",
		},
		{
			url:      "google.com:1234/v1/",
			expected: "http://google.com:1234/v1/",
		},
		{
			url:      "localhost",
			expected: "http://localhost",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.url, func(t *testing.T) {
			result := ensureURLHasScheme(testCase.url)

			if testCase.expected != result {
				t.Errorf("expected '%s' but got '%s'", testCase.expected, result)
			}
		})
	}
}
