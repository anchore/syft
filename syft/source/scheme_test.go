package source

import (
	"os"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestDetectScheme(t *testing.T) {
	type detectorResult struct {
		src image.Source
		ref string
		err error
	}

	testCases := []struct {
		name             string
		userInput        string
		dirs             []string
		files            []string
		detection        detectorResult
		expectedScheme   Scheme
		expectedLocation string
	}{
		{
			name:      "docker-image-ref",
			userInput: "wagoodman/dive:latest",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "wagoodman/dive:latest",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "wagoodman/dive:latest",
		},
		{
			name:      "docker-image-ref-no-tag",
			userInput: "wagoodman/dive",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "wagoodman/dive",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "wagoodman/dive",
		},
		{
			name:      "registry-image-explicit-scheme",
			userInput: "registry:wagoodman/dive:latest",
			detection: detectorResult{
				src: image.OciRegistrySource,
				ref: "wagoodman/dive:latest",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "wagoodman/dive:latest",
		},
		{
			name:      "docker-image-explicit-scheme",
			userInput: "docker:wagoodman/dive:latest",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "wagoodman/dive:latest",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "wagoodman/dive:latest",
		},
		{
			name:      "docker-image-explicit-scheme-no-tag",
			userInput: "docker:wagoodman/dive",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "wagoodman/dive",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "wagoodman/dive",
		},
		{
			name:      "docker-image-edge-case",
			userInput: "docker:latest",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "latest",
			},
			expectedScheme: ImageScheme,
			// we expected to be able to handle this case better, however, I don't see a way to do this
			// the user will need to provide more explicit input (docker:docker:latest)
			expectedLocation: "latest",
		},
		{
			name:      "docker-image-edge-case-explicit",
			userInput: "docker:docker:latest",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "docker:latest",
			},
			expectedScheme: ImageScheme,
			// we expected to be able to handle this case better, however, I don't see a way to do this
			// the user will need to provide more explicit input (docker:docker:latest)
			expectedLocation: "docker:latest",
		},
		{
			name:      "oci-tar",
			userInput: "some/path-to-file",
			detection: detectorResult{
				src: image.OciTarballSource,
				ref: "some/path-to-file",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "some/path-to-file",
		},
		{
			name:      "oci-dir",
			userInput: "some/path-to-dir",
			detection: detectorResult{
				src: image.OciDirectorySource,
				ref: "some/path-to-dir",
			},
			dirs:             []string{"some/path-to-dir"},
			expectedScheme:   ImageScheme,
			expectedLocation: "some/path-to-dir",
		},
		{
			name:      "guess-dir",
			userInput: "some/path-to-dir",
			detection: detectorResult{
				src: image.UnknownSource,
				ref: "",
			},
			dirs:             []string{"some/path-to-dir"},
			expectedScheme:   DirectoryScheme,
			expectedLocation: "some/path-to-dir",
		},
		{
			name:      "generic-dir-does-not-exist",
			userInput: "some/path-to-dir",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "some/path-to-dir",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "some/path-to-dir",
		},
		{
			name:      "found-podman-image-scheme",
			userInput: "podman:something:latest",
			detection: detectorResult{
				src: image.PodmanDaemonSource,
				ref: "something:latest",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "something:latest",
		},
		{
			name:      "explicit-dir",
			userInput: "dir:some/path-to-dir",
			detection: detectorResult{
				src: image.UnknownSource,
				ref: "",
			},
			dirs:             []string{"some/path-to-dir"},
			expectedScheme:   DirectoryScheme,
			expectedLocation: "some/path-to-dir",
		},
		{
			name:      "explicit-file",
			userInput: "file:some/path-to-file",
			detection: detectorResult{
				src: image.UnknownSource,
				ref: "",
			},
			files:            []string{"some/path-to-file"},
			expectedScheme:   FileScheme,
			expectedLocation: "some/path-to-file",
		},
		{
			name:      "implicit-file",
			userInput: "some/path-to-file",
			detection: detectorResult{
				src: image.UnknownSource,
				ref: "",
			},
			files:            []string{"some/path-to-file"},
			expectedScheme:   FileScheme,
			expectedLocation: "some/path-to-file",
		},
		{
			name:      "explicit-current-dir",
			userInput: "dir:.",
			detection: detectorResult{
				src: image.UnknownSource,
				ref: "",
			},
			expectedScheme:   DirectoryScheme,
			expectedLocation: ".",
		},
		{
			name:      "current-dir",
			userInput: ".",
			detection: detectorResult{
				src: image.UnknownSource,
				ref: "",
			},
			expectedScheme:   DirectoryScheme,
			expectedLocation: ".",
		},
		// we should support tilde expansion
		{
			name:      "tilde-expansion-image-implicit",
			userInput: "~/some-path",
			detection: detectorResult{
				src: image.OciDirectorySource,
				ref: "~/some-path",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "~/some-path",
		},
		{
			name:      "tilde-expansion-dir-implicit",
			userInput: "~/some-path",
			detection: detectorResult{
				src: image.UnknownSource,
				ref: "",
			},
			dirs:             []string{"~/some-path"},
			expectedScheme:   DirectoryScheme,
			expectedLocation: "~/some-path",
		},
		{
			name:             "tilde-expansion-dir-explicit-exists",
			userInput:        "dir:~/some-path",
			dirs:             []string{"~/some-path"},
			expectedScheme:   DirectoryScheme,
			expectedLocation: "~/some-path",
		},
		{
			name:             "tilde-expansion-dir-explicit-dne",
			userInput:        "dir:~/some-path",
			expectedScheme:   DirectoryScheme,
			expectedLocation: "~/some-path",
		},
		{
			name:             "tilde-expansion-dir-implicit-dne",
			userInput:        "~/some-path",
			expectedScheme:   UnknownScheme,
			expectedLocation: "",
		},
	}
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()

			for _, p := range test.dirs {
				expandedExpectedLocation, err := homedir.Expand(p)
				if err != nil {
					t.Fatalf("unable to expand path=%q: %+v", p, err)
				}
				err = fs.Mkdir(expandedExpectedLocation, os.ModePerm)
				if err != nil {
					t.Fatalf("failed to create dummy dir: %+v", err)
				}
			}

			for _, p := range test.files {
				expandedExpectedLocation, err := homedir.Expand(p)
				if err != nil {
					t.Fatalf("unable to expand path=%q: %+v", p, err)
				}
				_, err = fs.Create(expandedExpectedLocation)
				if err != nil {
					t.Fatalf("failed to create dummy file: %+v", err)
				}
			}

			imageDetector := func(string) (image.Source, string, error) {
				// lean on the users real home directory value
				switch test.detection.src {
				case image.OciDirectorySource, image.DockerTarballSource, image.OciTarballSource:
					expandedExpectedLocation, err := homedir.Expand(test.expectedLocation)
					if err != nil {
						t.Fatalf("unable to expand path=%q: %+v", test.expectedLocation, err)
					}
					return test.detection.src, expandedExpectedLocation, test.detection.err
				default:
					return test.detection.src, test.detection.ref, test.detection.err
				}
			}

			actualScheme, actualSource, actualLocation, err := DetectScheme(fs, imageDetector, test.userInput)
			if err != nil {
				t.Fatalf("unexpected err : %+v", err)
			}

			assert.Equal(t, test.detection.src, actualSource, "mismatched source")
			assert.Equal(t, test.expectedScheme, actualScheme, "mismatched scheme")

			// lean on the users real home directory value
			expandedExpectedLocation, err := homedir.Expand(test.expectedLocation)
			if err != nil {
				t.Fatalf("unable to expand path=%q: %+v", test.expectedLocation, err)
			}

			assert.Equal(t, expandedExpectedLocation, actualLocation, "mismatched location")
		})
	}
}
