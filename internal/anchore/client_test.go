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

func TestPrepareBaseURLForClient(t *testing.T) {
	cases := []struct {
		inputURL    string
		expectedURL string
		expectedErr error
	}{
		{
			inputURL:    "",
			expectedURL: "",
			expectedErr: ErrInvalidBaseURLInput,
		},
		{
			inputURL:    "localhost",
			expectedURL: "http://localhost/v1",
			expectedErr: nil,
		},
		{
			inputURL:    "https://localhost",
			expectedURL: "https://localhost/v1",
			expectedErr: nil,
		},
		{
			inputURL:    "https://localhost/",
			expectedURL: "https://localhost/v1",
			expectedErr: nil,
		},
		{
			inputURL:    "https://localhost/v1/",
			expectedURL: "https://localhost/v1",
			expectedErr: nil,
		},
		{
			inputURL:    "https://localhost/v1//",
			expectedURL: "https://localhost/v1",
			expectedErr: nil,
		},
		{
			inputURL:    "http://something.com/platform/v1/services/anchore",
			expectedURL: "http://something.com/platform/v1/services/anchore/v1",
			expectedErr: nil,
		},
		{
			inputURL:    "my-host:8228",
			expectedURL: "http://my-host:8228/v1",
			expectedErr: nil,
		},
		{
			inputURL:    "v1/v1",
			expectedURL: "http://v1/v1",
			expectedErr: nil,
		},
		{
			inputURL:    "/v1",
			expectedURL: "",
			expectedErr: ErrInvalidBaseURLInput,
		},
		{
			inputURL:    "/imports/images",
			expectedURL: "",
			expectedErr: ErrInvalidBaseURLInput,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.inputURL, func(t *testing.T) {
			resultURL, err := prepareBaseURLForClient(testCase.inputURL)
			if err != testCase.expectedErr {
				t.Errorf("expected err to be '%v' but got '%v'", testCase.expectedErr, err)
			}

			if resultURL != testCase.expectedURL {
				t.Errorf("expected URL to be '%v' but got '%v'", testCase.expectedURL, resultURL)
			}
		})
	}
}

func TestCheckBaseURLInput(t *testing.T) {
	cases := []struct {
		input    string
		expected error
	}{
		{
			input:    "",
			expected: ErrInvalidBaseURLInput,
		},
		{
			input:    "x",
			expected: nil,
		},
		{
			input:    "localhost:8000",
			expected: nil,
		},
		{
			input:    ":80",
			expected: ErrInvalidBaseURLInput,
		},
		{
			input:    "/v1",
			expected: ErrInvalidBaseURLInput,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.input, func(t *testing.T) {
			resultErr := checkBaseURLInput(testCase.input)

			if testCase.expected != resultErr {
				t.Errorf("expected err to be '%v' but got '%v'", testCase.expected, resultErr)
			}
		})
	}
}

func TestSplitSchemeFromURL(t *testing.T) {
	cases := []struct {
		input                    string
		expectedScheme           string
		expectedURLWithoutScheme string
	}{
		{
			input:                    "",
			expectedScheme:           "",
			expectedURLWithoutScheme: "",
		},
		{
			input:                    "localhost",
			expectedScheme:           "",
			expectedURLWithoutScheme: "localhost",
		},
		{
			input:                    "https://anchore.com/path",
			expectedScheme:           "https",
			expectedURLWithoutScheme: "anchore.com/path",
		},
		{
			input:                    "tcp://host:1234",
			expectedScheme:           "tcp",
			expectedURLWithoutScheme: "host:1234",
		},
		{
			input:                    "/hello",
			expectedScheme:           "",
			expectedURLWithoutScheme: "/hello",
		},
		{
			input:                    "://host",
			expectedScheme:           "",
			expectedURLWithoutScheme: "host",
		},
		{
			input:                    "http//localhost",
			expectedScheme:           "",
			expectedURLWithoutScheme: "http//localhost",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.input, func(t *testing.T) {
			resultScheme, resultURLWithoutScheme := splitSchemeFromURL(testCase.input)

			if testCase.expectedScheme != resultScheme {
				t.Errorf("expected scheme to be '%s' but got '%s'", testCase.expectedScheme, resultScheme)
			}

			if testCase.expectedURLWithoutScheme != resultURLWithoutScheme {
				t.Errorf("expected urlWithoutScheme to be '%s' but got '%s'", testCase.expectedURLWithoutScheme, resultURLWithoutScheme)
			}
		})
	}
}
