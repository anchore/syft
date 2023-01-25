package generic

import (
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/srctest"
	"github.com/anchore/syft/syft/source"
)

func TestSearchRequest_Execute(t *testing.T) {

	tests := []struct {
		name            string
		request         SearchRequest
		responsePath    string
		wantPathQueries map[string][]string
		wantLocations   []source.Location
	}{
		{
			name:         "search by glob",
			request:      NewSearch().ByGlob("**/*test?/*.txt"),
			responsePath: "result/will/match/x-test2/file.txt",
			wantPathQueries: map[string][]string{
				"FilesByGlob": {"**/*test?/*.txt"},
			},
			wantLocations: []source.Location{
				source.NewLocation("result/will/match/x-test2/file.txt"),
			},
		},
		{
			name:         "search by path",
			request:      NewSearch().ByPath("result/will/match/x-test2/file.txt"),
			responsePath: "result/will/match/x-test2/file.txt",
			wantPathQueries: map[string][]string{
				"FilesByPath": {"result/will/match/x-test2/file.txt"},
			},
			wantLocations: []source.Location{
				source.NewLocation("result/will/match/x-test2/file.txt"),
			},
		},
		{
			name:         "search by extension",
			request:      NewSearch().ByExtension(".txt").Request(),
			responsePath: "result/will/match/x-test2/file.txt",
			wantPathQueries: map[string][]string{
				"FilesByExtension": {".txt"},
			},
			wantLocations: []source.Location{
				source.NewLocation("result/will/match/x-test2/file.txt"),
			},
		},
		{
			name:         "search by extension, with matching requirement",
			request:      NewSearch().ByExtension(".txt").MustMatchGlob("**/*test?/*.txt"),
			responsePath: "result/will/match/x-test2/file.txt",
			wantPathQueries: map[string][]string{
				"FilesByExtension": {".txt"},
			},
			wantLocations: []source.Location{
				source.NewLocation("result/will/match/x-test2/file.txt"),
			},
		},
		{
			name:         "search by extension, with unmatched requirement",
			request:      NewSearch().ByExtension(".txt").MustMatchGlob("**/*test?/*.txt"),
			responsePath: "somewhere-else/file.txt",
			wantPathQueries: map[string][]string{
				"FilesByExtension": {".txt"},
			},
			wantLocations: nil,
		},
		{
			name:         "search by basename, with matching requirement",
			request:      NewSearch().ByBasename("file.txt").MustMatchGlob("**/*test?/*.txt"),
			responsePath: "result/will/match/x-test2/file.txt",
			wantPathQueries: map[string][]string{
				"FilesByBasename": {"file.txt"},
			},
			wantLocations: []source.Location{
				source.NewLocation("result/will/match/x-test2/file.txt"),
			},
		},
		{
			name:         "search by basename, with unmatched requirement",
			request:      NewSearch().ByBasename("file.txt").MustMatchGlob("**/*test?/*.txt"),
			responsePath: "somewhere-else/file.txt",
			wantPathQueries: map[string][]string{
				"FilesByBasename": {"file.txt"},
			},
			wantLocations: nil,
		},
		{
			name:         "search by basename glob, with matching requirement",
			request:      NewSearch().ByBasenameGlob("?i*.txt").MustMatchGlob("**/*test?/*.txt"),
			responsePath: "result/will/match/x-test2/file.txt",
			wantPathQueries: map[string][]string{
				"FilesByBasenameGlob": {"?i*.txt"},
			},
			wantLocations: []source.Location{
				source.NewLocation("result/will/match/x-test2/file.txt"),
			},
		},
		{
			name:         "search by basename glob, with unmatched requirement",
			request:      NewSearch().ByBasenameGlob("?i*.txt").MustMatchGlob("**/*test?/*.txt"),
			responsePath: "somewhere-else/file.txt",
			wantPathQueries: map[string][]string{
				"FilesByBasenameGlob": {"?i*.txt"},
			},
			wantLocations: nil,
		},
		{
			name:         "search by mimetype, with matching requirement",
			request:      NewSearch().ByMimeType("plain/text").MustMatchGlob("**/*test?/*.txt"),
			responsePath: "result/will/match/x-test2/file.txt",
			wantPathQueries: map[string][]string{
				"FilesByMIMEType": {"plain/text"},
			},
			wantLocations: []source.Location{
				source.NewLocation("result/will/match/x-test2/file.txt"),
			},
		},
		{
			name:         "search by mimetype, with unmatched requirement",
			request:      NewSearch().ByMimeType("plain/text").MustMatchGlob("**/*test?/*.txt"),
			responsePath: "somewhere-else/file.txt",
			wantPathQueries: map[string][]string{
				"FilesByMIMEType": {"plain/text"},
			},
			wantLocations: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &nopResolver{}
			if tt.responsePath != "" {
				n.loc = []source.Location{source.NewLocation(tt.responsePath)}
			}
			resolver := srctest.NewObservingResolver(n)

			locations, err := tt.request.Execute(resolver)
			require.NoError(t, err)

			assert.Equal(t, tt.wantLocations, locations)

			if d := cmp.Diff(tt.wantPathQueries, resolver.AllPathQueries()); d != "" {
				t.Errorf("unexpected path queries (-want +got):\n%s", d)
			}
		})
	}
}

func TestSearchRequest_Execute_ExceptionWithWildcard(t *testing.T) {

	tests := []struct {
		name            string
		request         SearchRequest
		responsePath    string
		wantPathQueries map[string][]string
		wantLocations   []source.Location
	}{
		{
			name:    "search by extension",
			request: NewSearch().ByExtension("*.txt").Request(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := srctest.NewObservingResolver(&nopResolver{})
			_, err := tt.request.Execute(resolver)
			require.Error(t, err)
		})
	}
}

var _ source.FileResolver = (*nopResolver)(nil)

type nopResolver struct {
	loc []source.Location
}

func (n nopResolver) FileContentsByLocation(_ source.Location) (io.ReadCloser, error) {
	return nil, nil
}

func (n nopResolver) HasPath(_ string) bool {
	return false
}

func (n nopResolver) FilesByPath(_ ...string) ([]source.Location, error) {
	return n.loc, nil
}

func (n nopResolver) FilesByGlob(_ ...string) ([]source.Location, error) {
	return n.loc, nil
}

func (n nopResolver) FilesByExtension(_ ...string) ([]source.Location, error) {
	return n.loc, nil
}

func (n nopResolver) FilesByBasename(_ ...string) ([]source.Location, error) {
	return n.loc, nil
}

func (n nopResolver) FilesByBasenameGlob(_ ...string) ([]source.Location, error) {
	return n.loc, nil
}

func (n nopResolver) FilesByMIMEType(_ ...string) ([]source.Location, error) {
	return n.loc, nil
}

func (n nopResolver) RelativeFileByPath(_ source.Location, _ string) *source.Location {
	return nil
}

func (n nopResolver) AllLocations() <-chan source.Location {
	return nil
}

func (n nopResolver) FileMetadataByLocation(_ source.Location) (source.FileMetadata, error) {
	return source.FileMetadata{}, nil
}
