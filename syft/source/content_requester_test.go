package source

import (
	"io/ioutil"
	"testing"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/sergi/go-diff/diffmatchpatch"
)

func TestContentRequester(t *testing.T) {
	tests := []struct {
		fixture          string
		expectedContents map[string]string
	}{
		{
			fixture: "image-simple",
			expectedContents: map[string]string{
				"/somefile-1.txt":           "this file has contents",
				"/somefile-2.txt":           "file-2 contents!",
				"/really/nested/file-3.txt": "another file!\nwith lines...",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			img, cleanup := imagetest.GetFixtureImage(t, "docker-archive", "image-simple")
			defer cleanup()

			resolver, err := NewAllLayersResolver(img)
			if err != nil {
				t.Fatalf("could not create resolver: %+v", err)
			}

			var data []*FileData
			for path := range test.expectedContents {

				locations, err := resolver.FilesByPath(path)
				if err != nil {
					t.Fatalf("could not build request: %+v", err)
				}
				if len(locations) != 1 {
					t.Fatalf("bad resolver paths: %+v", locations)
				}

				data = append(data, &FileData{
					Location: locations[0],
				})
			}

			if err := NewContentRequester(data...).Execute(resolver); err != nil {
				t.Fatalf("could not execute request: %+v", err)
			}

			for _, entry := range data {
				if expected, ok := test.expectedContents[entry.Location.Path]; ok {
					actualBytes, err := ioutil.ReadAll(entry.Contents)
					if err != nil {
						t.Fatalf("could not read %q: %+v", entry.Location.Path, err)
					}
					for expected != string(actualBytes) {
						t.Errorf("mismatched contents for %q", entry.Location.Path)
						dmp := diffmatchpatch.New()
						diffs := dmp.DiffMain(expected, string(actualBytes), true)
						t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
					}
					continue
				}
				t.Errorf("could not find %q", entry.Location.Path)
			}
		})
	}
}
