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
			s := testScanner(false)
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

func TestSearchPkgLicenses(t *testing.T) {
	type expectation struct {
		wantErr  require.ErrorAssertionFunc
		licenses []pkg.License
	}

	testLocation := file.NewLocation("LICENSE")
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
			name: "custom license no content by default",
			in:   "test-fixtures/nvidia-software-and-cuda-supplement",
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
			name:                        "custom license with content when scanner has content config",
			in:                          "test-fixtures/nvidia-software-and-cuda-supplement",
			includeUnkownLicenseContent: true,
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.TODO()
			content, err := os.ReadFile(test.in)
			require.NoError(t, err)
			s := testScanner(test.includeUnkownLicenseContent)
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
