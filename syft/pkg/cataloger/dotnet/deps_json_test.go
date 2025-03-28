package dotnet

import (
	"testing"
)

func TestTrimLibPrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty path",
			input:    "",
			expected: "",
		},
		{
			name:     "simple .NET 6.0 path",
			input:    "lib/net6.0/Humanizer.dll",
			expected: "Humanizer.dll",
		},
		{
			name:     "locale-specific resource path",
			input:    "lib/net6.0/af/Humanizer.resources.dll",
			expected: "af/Humanizer.resources.dll",
		},
		{
			name:     "netstandard path",
			input:    "lib/netstandard2.0/Serilog.Sinks.Console.dll",
			expected: "Serilog.Sinks.Console.dll",
		},
		{
			name:     "runtime-specific path",
			input:    "runtimes/linux-arm/lib/netcoreapp2.2/System.Collections.Concurrent.dll",
			expected: "System.Collections.Concurrent.dll",
		},
		{
			name:     "runtime-specific path with locale",
			input:    "runtimes/win/lib/net6.0/fr-ME/re/Microsoft.Data.SqlClient.resources.dll",
			expected: "fr-ME/re/Microsoft.Data.SqlClient.resources.dll",
		},
		{
			name:     "subdirectories",
			input:    "lib/net7.0/Microsoft/Extensions/Logging.dll",
			expected: "Microsoft/Extensions/Logging.dll",
		},
		{
			name:     "doesn't match the pattern",
			input:    "content/styles/main.css",
			expected: "content/styles/main.css",
		},
		{
			name:     "different framework format",
			input:    "lib/net472/Newtonsoft.Json.dll",
			expected: "Newtonsoft.Json.dll",
		},
		{
			name:     "frameworkless lib",
			input:    "lib/Newtonsoft.Json.dll",
			expected: "lib/Newtonsoft.Json.dll", // should not match our pattern
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := trimLibPrefix(tc.input)
			if result != tc.expected {
				t.Errorf("trimLibPrefix(%q) = %q; want %q", tc.input, result, tc.expected)
			}
		})
	}
}
