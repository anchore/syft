package licenses

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type bytesReadCloser struct {
	bytes.Buffer
}

func (brc *bytesReadCloser) Close() error {
	return nil
}

func newBytesReadCloser(data []byte) *bytesReadCloser {
	return &bytesReadCloser{
		Buffer: *bytes.NewBuffer(data),
	}
}

func TestSearchFileLicenses(t *testing.T) {
	type expectation struct {
		yieldError bool
		licenses   []file.License
	}

	tests := []struct {
		name                        string
		in                          string
		includeUnkownLicenseContent bool
		expected                    expectation
	}{
		{
			name: "apache license 2.0",
			in:   "test-fixtures/apache-license-2.0",
			expected: expectation{
				yieldError: false,
				licenses: []file.License{
					{
						Value:          "Apache-2.0",
						SPDXExpression: "Apache-2.0",
						Type:           "concluded",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.TODO()
			content, err := os.ReadFile(test.in)
			require.NoError(t, err)
			s := testScanner(false, false)
			result, err := s.FileSearch(ctx, file.NewLocationReadCloser(file.NewLocation("LICENSE"), io.NopCloser(bytes.NewReader(content))))
			if test.expected.yieldError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				require.Len(t, result, len(test.expected.licenses))

				if len(test.expected.licenses) > 0 {
					require.Equal(t, test.expected.licenses, result)
				}
			}
		})
	}
}

type scannerOptions struct {
	includeUnknownLicenseContent bool
	includeFullText              bool
}

func TestSearchPkgLicenses(t *testing.T) {
	type expectation struct {
		wantErr  require.ErrorAssertionFunc
		licenses []pkg.License
	}

	testLocation := file.NewLocation("LICENSE")
	multiLicense := "test-fixtures/multi-license"
	tests := []struct {
		name          string
		in            string
		scannerConfig scannerOptions
		expected      expectation
	}{
		{
			name:          "apache license 2.0 all text options off",
			in:            "test-fixtures/apache-license-2.0",
			scannerConfig: scannerOptions{},
			expected: expectation{
				licenses: []pkg.License{
					{
						Value:          "Apache-2.0",
						SPDXExpression: "Apache-2.0",
						Type:           "concluded",
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
						Contents:       "",
					},
				},
				wantErr: nil,
			},
		},
		{
			name:          "custom license no content by default",
			in:            "test-fixtures/nvidia-software-and-cuda-supplement",
			scannerConfig: scannerOptions{},
			expected: expectation{
				licenses: []pkg.License{
					{
						Value:          "UNKNOWN",
						SPDXExpression: "UNKNOWN_eebcea3ab1d1a28e671de90119ffcfb35fe86951e4af1b17af52b7a82fcf7d0a",
						Type:           "declared",
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
						Contents:       "",
					},
				},
				wantErr: nil,
			},
		},
		{
			name: "custom license with content when scanner has content config",
			in:   "test-fixtures/nvidia-software-and-cuda-supplement",
			scannerConfig: scannerOptions{
				includeUnknownLicenseContent: true,
			},
			expected: expectation{
				licenses: []pkg.License{
					{
						Value:          "UNKNOWN",
						SPDXExpression: "UNKNOWN_eebcea3ab1d1a28e671de90119ffcfb35fe86951e4af1b17af52b7a82fcf7d0a",
						Type:           "declared",
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
						Contents:       string(mustOpen("test-fixtures/nvidia-software-and-cuda-supplement")),
					},
				},
				wantErr: nil,
			},
		},
		{
			name: "apache license 2.0 with full text when scanner has content config",
			in:   "test-fixtures/apache-license-2.0",
			scannerConfig: scannerOptions{
				includeFullText: true,
			},
			expected: expectation{
				licenses: []pkg.License{
					{
						Value:          "Apache-2.0",
						SPDXExpression: "Apache-2.0",
						Type:           "concluded",
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
						Contents:       string(mustOpen("test-fixtures/apache-license-2.0")),
					},
				},
				wantErr: nil,
			},
		},
		{
			name: "multiple licenses are returned from a single text with their full text when scanner has full text configured. duplicates with different contents are allowed",
			in:   multiLicense,
			scannerConfig: scannerOptions{
				includeFullText: true,
			},
			expected: expectation{
				licenses: []pkg.License{
					{
						SPDXExpression: "MIT",
						Value:          "MIT",
						Type:           "concluded",
						Contents:       mustReadOffsetContent(t, multiLicense, 758, 1844),
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
					},
					{
						SPDXExpression: "NCSA",
						Value:          "NCSA",
						Type:           "concluded",
						Contents:       mustReadOffsetContent(t, multiLicense, 1925, 3463),
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
					},
					{
						SPDXExpression: "MIT",
						Value:          "MIT",
						Type:           "concluded",
						Contents:       mustReadOffsetContent(t, multiLicense, 3708, 4932),
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
					},
					{
						SPDXExpression: "Apache-2.0",
						Value:          "Apache-2.0",
						Type:           "concluded",
						Contents:       mustReadOffsetContent(t, multiLicense, 5021, 16378),
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
					},
					{
						SPDXExpression: "Zlib",
						Value:          "Zlib",
						Type:           "concluded",
						Contents:       mustReadOffsetContent(t, multiLicense, 16484, 17390),
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
					},
					{
						SPDXExpression: "Unlicense",
						Value:          "Unlicense",
						Type:           "concluded",
						Contents:       mustReadOffsetContent(t, multiLicense, 17497, 18707),
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
					},
					{
						SPDXExpression: "BSD-2-Clause",
						Value:          "BSD-2-Clause",
						Type:           "concluded",
						Contents:       mustReadOffsetContent(t, multiLicense, 18908, 20298),
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
					},
					{
						SPDXExpression: "BSD-3-Clause",
						Value:          "BSD-3-Clause",
						Type:           "concluded",
						Contents:       mustReadOffsetContent(t, multiLicense, 20440, 21952),
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
					},
					{
						SPDXExpression: "BSD-2-Clause",
						Value:          "BSD-2-Clause",
						Type:           "concluded",
						Contents:       mustReadOffsetContent(t, multiLicense, 22033, 23335),
						URLs:           nil,
						Locations:      file.NewLocationSet(testLocation),
					},
				},
				wantErr: nil,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.TODO()
			content, err := os.ReadFile(test.in)
			require.NoError(t, err)
			s := testScanner(test.scannerConfig.includeUnknownLicenseContent, test.scannerConfig.includeFullText)
			result, err := s.PkgSearch(ctx, file.NewLocationReadCloser(file.NewLocation("LICENSE"), io.NopCloser(bytes.NewReader(content))))
			if test.expected.wantErr != nil {
				test.expected.wantErr(t, err)
			}
			require.NoError(t, err)

			require.Len(t, result, len(test.expected.licenses))

			if len(test.expected.licenses) > 0 {
				require.Equal(t, test.expected.licenses, result)
			}
		})
	}
}

func mustReadOffsetContent(t *testing.T, path string, start, end int64) string {
	t.Helper()

	if start < 0 || end < start {
		t.Fatalf("invalid offsets: start=%d, end=%d", start, end)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open file %q: %v", path, err)
	}
	defer file.Close()

	length := end - start
	buffer := make([]byte, length)

	_, err = file.Seek(start, io.SeekStart)
	if err != nil {
		t.Fatalf("failed to seek to offset %d: %v", start, err)
	}

	n, err := io.ReadFull(file, buffer)
	if err != nil {
		t.Fatalf("failed to read content: %v", err)
	}

	return string(buffer[:n])
}
