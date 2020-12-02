package anchore

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/anchore/client-go/pkg/external"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/go-test/deep"
)

type mockManifestImportAPI struct {
	sessionID      string
	model          string
	httpResponse   *http.Response
	err            error
	ctx            context.Context
	responseDigest string
	wasCalled      bool
}

func (m *mockManifestImportAPI) ImportImageManifest(ctx context.Context, sessionID string, contents string) (external.ImageImportContentResponse, *http.Response, error) {
	m.wasCalled = true
	m.model = contents
	m.sessionID = sessionID
	m.ctx = ctx
	if m.httpResponse == nil {
		m.httpResponse = &http.Response{}
	}
	m.httpResponse.Body = ioutils.NewReadCloserWrapper(strings.NewReader(""), func() error { return nil })
	return external.ImageImportContentResponse{Digest: m.responseDigest}, m.httpResponse, m.err
}

func TestManifestImport(t *testing.T) {

	sessionID := "my-session"

	tests := []struct {
		name         string
		manifest     string
		api          *mockManifestImportAPI
		expectsError bool
		expectsCall  bool
	}{

		{
			name:     "Go case: import works",
			manifest: "the-manifest-contents!",
			api: &mockManifestImportAPI{
				httpResponse:   &http.Response{StatusCode: 200},
				responseDigest: "digest!",
			},
			expectsCall: true,
		},
		{
			name:        "No manifest provided",
			manifest:    "",
			api:         &mockManifestImportAPI{},
			expectsCall: false,
		},
		{
			name:     "API returns an error",
			manifest: "the-manifest-contents!",
			api: &mockManifestImportAPI{
				err: fmt.Errorf("api error, something went wrong"),
			},
			expectsError: true,
			expectsCall:  true,
		},
		{
			name:     "API HTTP-level error",
			manifest: "the-manifest-contents!",
			api: &mockManifestImportAPI{
				httpResponse: &http.Response{StatusCode: 404},
			},
			expectsError: true,
			expectsCall:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			digest, err := importManifest(context.TODO(), test.api, sessionID, []byte(test.manifest))

			// validate error handling
			if err != nil && !test.expectsError {
				t.Fatalf("did not expect an error, but got: %+v", err)
			} else if err == nil && test.expectsError {
				t.Fatalf("did expect an error, but got none")
			}

			if !test.api.wasCalled && test.expectsCall {
				t.Fatalf("was not called!")
			} else if test.api.wasCalled && !test.expectsCall {
				t.Fatalf("should not have been called")
			}

			if !test.expectsCall {
				return
			}

			if digest != test.api.responseDigest {
				t.Errorf("unexpected content digest: %q != %q", digest, test.api.responseDigest)
			}

			// validating that the mock got the right parameters
			if test.api.sessionID != sessionID {
				t.Errorf("different session ID: %s != %s", test.api.sessionID, sessionID)
			}

			for _, d := range deep.Equal(test.api.model, test.manifest) {
				t.Errorf("model difference: %s", d)
			}

		})
	}
}
