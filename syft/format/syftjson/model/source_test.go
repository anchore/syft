package model

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/sourcemetadata"
	"github.com/anchore/syft/syft/source"
)

func TestSource_UnmarshalJSON(t *testing.T) {
	tracker := sourcemetadata.NewCompletionTester(t)

	cases := []struct {
		name     string
		input    []byte
		expected *Source
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name: "directory",
			input: []byte(`{
				"id": "foobar",
				"type": "directory",
				"metadata": {"path": "/var/lib/foo", "base":"/nope"}
			}`),
			expected: &Source{
				ID:   "foobar",
				Type: "directory",
				Metadata: source.DirectoryMetadata{
					Path: "/var/lib/foo",
					//Base: "/nope", // note: should be ignored entirely
				},
			},
		},
		{
			name: "image",
			input: []byte(`{
				"id": "foobar",
				"type": "image",
				"metadata": {
					"userInput": "alpine:3.10",
					"imageID": "sha256:e7b300aee9f9bf3433d32bc9305bfdd22183beb59d933b48d77ab56ba53a197a",
					"manifestDigest": "sha256:e515aad2ed234a5072c4d2ef86a1cb77d5bfe4b11aa865d9214875734c4eeb3c",
					"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
					"tags": [],
					"imageSize": 5576169,
					"layers": [
						{
							"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
							"digest": "sha256:9fb3aa2f8b8023a4bebbf92aa567caf88e38e969ada9f0ac12643b2847391635",
							"size": 5576169
						}
					],
					"manifest": "ewogICAic2NoZW1hVmVyc2lvbiI6IDIsCiAgICJtZWRpYVR5cGUiOiAiYXBwbGljYXRpb24vdm5kLmRvY2tlci5kaXN0cmlidXRpb24ubWFuaWZlc3QudjIranNvbiIsCiAgICJjb25maWciOiB7CiAgICAgICJtZWRpYVR5cGUiOiAiYXBwbGljYXRpb24vdm5kLmRvY2tlci5jb250YWluZXIuaW1hZ2UudjEranNvbiIsCiAgICAgICJzaXplIjogMTQ3MiwKICAgICAgImRpZ2VzdCI6ICJzaGEyNTY6ZTdiMzAwYWVlOWY5YmYzNDMzZDMyYmM5MzA1YmZkZDIyMTgzYmViNTlkOTMzYjQ4ZDc3YWI1NmJhNTNhMTk3YSIKICAgfSwKICAgImxheWVycyI6IFsKICAgICAgewogICAgICAgICAibWVkaWFUeXBlIjogImFwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuaW1hZ2Uucm9vdGZzLmRpZmYudGFyLmd6aXAiLAogICAgICAgICAic2l6ZSI6IDI3OTgzMzgsCiAgICAgICAgICJkaWdlc3QiOiAic2hhMjU2OjM5NmMzMTgzNzExNmFjMjkwNDU4YWZjYjkyOGY2OGI2Y2MxYzdiZGQ2OTYzZmM3MmY1MmYzNjVhMmE4OWMxYjUiCiAgICAgIH0KICAgXQp9",
					"config": "eyJhcmNoaXRlY3R1cmUiOiJhbWQ2NCIsImNvbmZpZyI6eyJIb3N0bmFtZSI6IiIsIkRvbWFpbm5hbWUiOiIiLCJVc2VyIjoiIiwiQXR0YWNoU3RkaW4iOmZhbHNlLCJBdHRhY2hTdGRvdXQiOmZhbHNlLCJBdHRhY2hTdGRlcnIiOmZhbHNlLCJUdHkiOmZhbHNlLCJPcGVuU3RkaW4iOmZhbHNlLCJTdGRpbk9uY2UiOmZhbHNlLCJFbnYiOlsiUEFUSD0vdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4iXSwiQ21kIjpbIi9iaW4vc2giXSwiSW1hZ2UiOiJzaGEyNTY6ZWIyMDgwYzQ1NWU5NGMyMmFlMzViM2FlZjllMDc4YzQ5MmEwMDc5NTQxMmUwMjZlNGQ2YjQxZWY2NGJjN2RkOCIsIlZvbHVtZXMiOm51bGwsIldvcmtpbmdEaXIiOiIiLCJFbnRyeXBvaW50IjpudWxsLCJPbkJ1aWxkIjpudWxsLCJMYWJlbHMiOm51bGx9LCJjb250YWluZXIiOiJmZGI3ZTgwZTMzMzllOGQwNTk5MjgyZTYwNmM5MDdhYTU4ODFlZTRjNjY4YTY4MTM2MTE5ZTZkZmFjNmNlM2E0IiwiY29udGFpbmVyX2NvbmZpZyI6eyJIb3N0bmFtZSI6ImZkYjdlODBlMzMzOSIsIkRvbWFpbm5hbWUiOiIiLCJVc2VyIjoiIiwiQXR0YWNoU3RkaW4iOmZhbHNlLCJBdHRhY2hTdGRvdXQiOmZhbHNlLCJBdHRhY2hTdGRlcnIiOmZhbHNlLCJUdHkiOmZhbHNlLCJPcGVuU3RkaW4iOmZhbHNlLCJTdGRpbk9uY2UiOmZhbHNlLCJFbnYiOlsiUEFUSD0vdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4iXSwiQ21kIjpbIi9iaW4vc2giLCItYyIsIiMobm9wKSAiLCJDTUQgW1wiL2Jpbi9zaFwiXSJdLCJJbWFnZSI6InNoYTI1NjplYjIwODBjNDU1ZTk0YzIyYWUzNWIzYWVmOWUwNzhjNDkyYTAwNzk1NDEyZTAyNmU0ZDZiNDFlZjY0YmM3ZGQ4IiwiVm9sdW1lcyI6bnVsbCwiV29ya2luZ0RpciI6IiIsIkVudHJ5cG9pbnQiOm51bGwsIk9uQnVpbGQiOm51bGwsIkxhYmVscyI6e319LCJjcmVhdGVkIjoiMjAyMS0wNC0xNFQxOToyMDowNS4zMzgzOTc3NjFaIiwiZG9ja2VyX3ZlcnNpb24iOiIxOS4wMy4xMiIsImhpc3RvcnkiOlt7ImNyZWF0ZWQiOiIyMDIxLTA0LTE0VDE5OjIwOjA0Ljk4NzIxOTEyNFoiLCJjcmVhdGVkX2J5IjoiL2Jpbi9zaCAtYyAjKG5vcCkgQUREIGZpbGU6YzUzNzdlYWE5MjZiZjQxMmRkOGQ0YTA4YjBhMWYyMzk5Y2ZkNzA4NzQzNTMzYjBhYTAzYjUzZDE0Y2I0YmI0ZSBpbiAvICJ9LHsiY3JlYXRlZCI6IjIwMjEtMDQtMTRUMTk6MjA6MDUuMzM4Mzk3NzYxWiIsImNyZWF0ZWRfYnkiOiIvYmluL3NoIC1jICMobm9wKSAgQ01EIFtcIi9iaW4vc2hcIl0iLCJlbXB0eV9sYXllciI6dHJ1ZX1dLCJvcyI6ImxpbnV4Iiwicm9vdGZzIjp7InR5cGUiOiJsYXllcnMiLCJkaWZmX2lkcyI6WyJzaGEyNTY6OWZiM2FhMmY4YjgwMjNhNGJlYmJmOTJhYTU2N2NhZjg4ZTM4ZTk2OWFkYTlmMGFjMTI2NDNiMjg0NzM5MTYzNSJdfX0=",
					"repoDigests": [
						"index.docker.io/library/alpine@sha256:451eee8bedcb2f029756dc3e9d73bab0e7943c1ac55cff3a4861c52a0fdd3e98"
					]
				}
			}`),
			expected: &Source{
				ID:   "foobar",
				Type: "image",
				Metadata: source.ImageMetadata{
					UserInput:      "alpine:3.10",
					ID:             "sha256:e7b300aee9f9bf3433d32bc9305bfdd22183beb59d933b48d77ab56ba53a197a",
					ManifestDigest: "sha256:e515aad2ed234a5072c4d2ef86a1cb77d5bfe4b11aa865d9214875734c4eeb3c",
					MediaType:      "application/vnd.docker.distribution.manifest.v2+json",
					Tags:           []string{},
					Size:           5576169,
					Layers: []source.LayerMetadata{
						{
							MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
							Digest:    "sha256:9fb3aa2f8b8023a4bebbf92aa567caf88e38e969ada9f0ac12643b2847391635",
							Size:      5576169,
						},
					},
					RawManifest: []byte(`{
   "schemaVersion": 2,
   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
   "config": {
      "mediaType": "application/vnd.docker.container.image.v1+json",
      "size": 1472,
      "digest": "sha256:e7b300aee9f9bf3433d32bc9305bfdd22183beb59d933b48d77ab56ba53a197a"
   },
   "layers": [
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 2798338,
         "digest": "sha256:396c31837116ac290458afcb928f68b6cc1c7bdd6963fc72f52f365a2a89c1b5"
      }
   ]
}`),
					RawConfig: []byte(`{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"],"Image":"sha256:eb2080c455e94c22ae35b3aef9e078c492a00795412e026e4d6b41ef64bc7dd8","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"container":"fdb7e80e3339e8d0599282e606c907aa5881ee4c668a68136119e6dfac6ce3a4","container_config":{"Hostname":"fdb7e80e3339","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) ","CMD [\"/bin/sh\"]"],"Image":"sha256:eb2080c455e94c22ae35b3aef9e078c492a00795412e026e4d6b41ef64bc7dd8","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":{}},"created":"2021-04-14T19:20:05.338397761Z","docker_version":"19.03.12","history":[{"created":"2021-04-14T19:20:04.987219124Z","created_by":"/bin/sh -c #(nop) ADD file:c5377eaa926bf412dd8d4a08b0a1f2399cfd708743533b0aa03b53d14cb4bb4e in / "},{"created":"2021-04-14T19:20:05.338397761Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:9fb3aa2f8b8023a4bebbf92aa567caf88e38e969ada9f0ac12643b2847391635"]}}`),
					RepoDigests: []string{
						"index.docker." +
							"io/library/alpine@sha256:451eee8bedcb2f029756dc3e9d73bab0e7943c1ac55cff3a4861c52a0fdd3e98",
					},
				},
			},
		},
		{
			name: "file",
			input: []byte(`{
				"id": "foobar",
				"type": "file",
				"metadata": {
					"path": "/var/lib/foo/go.mod",
					"mimeType": "text/plain",
					"digests": [
						{
							"algorithm": "sha256",
							"value": 	 "e7b300aee9f9bf3433d32bc9305bfdd22183beb59d933b48d77ab56ba53a197a"
						}
					]
				}
			}`),
			expected: &Source{
				ID:   "foobar",
				Type: "file",
				Metadata: source.FileMetadata{
					Path: "/var/lib/foo/go.mod",
					Digests: []file.Digest{
						{
							Algorithm: "sha256",
							Value:     "e7b300aee9f9bf3433d32bc9305bfdd22183beb59d933b48d77ab56ba53a197a",
						},
					},
					MIMEType: "text/plain",
				},
			},
		},
		{
			name: "unknown source type",
			input: []byte(`{
				"id": "foobar",
				"type": "unknown-thing",
				"target":"/var/lib/foo"
			}`),
			expected: &Source{
				ID:   "foobar",
				Type: "unknown-thing",
			},
			wantErr: require.Error,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			var src Source
			err := json.Unmarshal(tt.input, &src)

			tt.wantErr(t, err)

			if diff := cmp.Diff(tt.expected, &src); diff != "" {
				t.Errorf("unexpected result from Source unmarshaling (-want +got)\n%s", diff)
			}

			tracker.Tested(t, tt.expected.Metadata)
		})
	}
}

func TestSource_UnmarshalJSON_PreSchemaV9(t *testing.T) {
	cases := []struct {
		name           string
		input          []byte
		expectedSource *Source
		errAssertion   assert.ErrorAssertionFunc
	}{
		{
			name: "abbreviated directory",
			input: []byte(`{
				"id": "foobar",
				"type": "dir",
				"target":"/var/lib/foo"
			}`),
			expectedSource: &Source{
				ID:   "foobar",
				Type: "directory",
				Metadata: source.DirectoryMetadata{
					Path: "/var/lib/foo",
				},
			},
			errAssertion: assert.NoError,
		},
		{
			name: "directory",
			input: []byte(`{
				"id": "foobar",
				"type": "directory",
				"target":"/var/lib/foo"
			}`),
			expectedSource: &Source{
				ID:   "foobar",
				Type: "directory",
				Metadata: source.DirectoryMetadata{
					Path: "/var/lib/foo",
				},
			},
			errAssertion: assert.NoError,
		},
		{
			name: "image",
			input: []byte(`{
				"id": "foobar",
				"type": "image",
				"target": {
					"userInput": "alpine:3.10",
					"imageID": "sha256:e7b300aee9f9bf3433d32bc9305bfdd22183beb59d933b48d77ab56ba53a197a",
					"manifestDigest": "sha256:e515aad2ed234a5072c4d2ef86a1cb77d5bfe4b11aa865d9214875734c4eeb3c",
					"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
					"tags": [],
					"imageSize": 5576169,
					"layers": [
						{
							"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
							"digest": "sha256:9fb3aa2f8b8023a4bebbf92aa567caf88e38e969ada9f0ac12643b2847391635",
							"size": 5576169
						}
					],
					"manifest": "ewogICAic2NoZW1hVmVyc2lvbiI6IDIsCiAgICJtZWRpYVR5cGUiOiAiYXBwbGljYXRpb24vdm5kLmRvY2tlci5kaXN0cmlidXRpb24ubWFuaWZlc3QudjIranNvbiIsCiAgICJjb25maWciOiB7CiAgICAgICJtZWRpYVR5cGUiOiAiYXBwbGljYXRpb24vdm5kLmRvY2tlci5jb250YWluZXIuaW1hZ2UudjEranNvbiIsCiAgICAgICJzaXplIjogMTQ3MiwKICAgICAgImRpZ2VzdCI6ICJzaGEyNTY6ZTdiMzAwYWVlOWY5YmYzNDMzZDMyYmM5MzA1YmZkZDIyMTgzYmViNTlkOTMzYjQ4ZDc3YWI1NmJhNTNhMTk3YSIKICAgfSwKICAgImxheWVycyI6IFsKICAgICAgewogICAgICAgICAibWVkaWFUeXBlIjogImFwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuaW1hZ2Uucm9vdGZzLmRpZmYudGFyLmd6aXAiLAogICAgICAgICAic2l6ZSI6IDI3OTgzMzgsCiAgICAgICAgICJkaWdlc3QiOiAic2hhMjU2OjM5NmMzMTgzNzExNmFjMjkwNDU4YWZjYjkyOGY2OGI2Y2MxYzdiZGQ2OTYzZmM3MmY1MmYzNjVhMmE4OWMxYjUiCiAgICAgIH0KICAgXQp9",
					"config": "eyJhcmNoaXRlY3R1cmUiOiJhbWQ2NCIsImNvbmZpZyI6eyJIb3N0bmFtZSI6IiIsIkRvbWFpbm5hbWUiOiIiLCJVc2VyIjoiIiwiQXR0YWNoU3RkaW4iOmZhbHNlLCJBdHRhY2hTdGRvdXQiOmZhbHNlLCJBdHRhY2hTdGRlcnIiOmZhbHNlLCJUdHkiOmZhbHNlLCJPcGVuU3RkaW4iOmZhbHNlLCJTdGRpbk9uY2UiOmZhbHNlLCJFbnYiOlsiUEFUSD0vdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4iXSwiQ21kIjpbIi9iaW4vc2giXSwiSW1hZ2UiOiJzaGEyNTY6ZWIyMDgwYzQ1NWU5NGMyMmFlMzViM2FlZjllMDc4YzQ5MmEwMDc5NTQxMmUwMjZlNGQ2YjQxZWY2NGJjN2RkOCIsIlZvbHVtZXMiOm51bGwsIldvcmtpbmdEaXIiOiIiLCJFbnRyeXBvaW50IjpudWxsLCJPbkJ1aWxkIjpudWxsLCJMYWJlbHMiOm51bGx9LCJjb250YWluZXIiOiJmZGI3ZTgwZTMzMzllOGQwNTk5MjgyZTYwNmM5MDdhYTU4ODFlZTRjNjY4YTY4MTM2MTE5ZTZkZmFjNmNlM2E0IiwiY29udGFpbmVyX2NvbmZpZyI6eyJIb3N0bmFtZSI6ImZkYjdlODBlMzMzOSIsIkRvbWFpbm5hbWUiOiIiLCJVc2VyIjoiIiwiQXR0YWNoU3RkaW4iOmZhbHNlLCJBdHRhY2hTdGRvdXQiOmZhbHNlLCJBdHRhY2hTdGRlcnIiOmZhbHNlLCJUdHkiOmZhbHNlLCJPcGVuU3RkaW4iOmZhbHNlLCJTdGRpbk9uY2UiOmZhbHNlLCJFbnYiOlsiUEFUSD0vdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4iXSwiQ21kIjpbIi9iaW4vc2giLCItYyIsIiMobm9wKSAiLCJDTUQgW1wiL2Jpbi9zaFwiXSJdLCJJbWFnZSI6InNoYTI1NjplYjIwODBjNDU1ZTk0YzIyYWUzNWIzYWVmOWUwNzhjNDkyYTAwNzk1NDEyZTAyNmU0ZDZiNDFlZjY0YmM3ZGQ4IiwiVm9sdW1lcyI6bnVsbCwiV29ya2luZ0RpciI6IiIsIkVudHJ5cG9pbnQiOm51bGwsIk9uQnVpbGQiOm51bGwsIkxhYmVscyI6e319LCJjcmVhdGVkIjoiMjAyMS0wNC0xNFQxOToyMDowNS4zMzgzOTc3NjFaIiwiZG9ja2VyX3ZlcnNpb24iOiIxOS4wMy4xMiIsImhpc3RvcnkiOlt7ImNyZWF0ZWQiOiIyMDIxLTA0LTE0VDE5OjIwOjA0Ljk4NzIxOTEyNFoiLCJjcmVhdGVkX2J5IjoiL2Jpbi9zaCAtYyAjKG5vcCkgQUREIGZpbGU6YzUzNzdlYWE5MjZiZjQxMmRkOGQ0YTA4YjBhMWYyMzk5Y2ZkNzA4NzQzNTMzYjBhYTAzYjUzZDE0Y2I0YmI0ZSBpbiAvICJ9LHsiY3JlYXRlZCI6IjIwMjEtMDQtMTRUMTk6MjA6MDUuMzM4Mzk3NzYxWiIsImNyZWF0ZWRfYnkiOiIvYmluL3NoIC1jICMobm9wKSAgQ01EIFtcIi9iaW4vc2hcIl0iLCJlbXB0eV9sYXllciI6dHJ1ZX1dLCJvcyI6ImxpbnV4Iiwicm9vdGZzIjp7InR5cGUiOiJsYXllcnMiLCJkaWZmX2lkcyI6WyJzaGEyNTY6OWZiM2FhMmY4YjgwMjNhNGJlYmJmOTJhYTU2N2NhZjg4ZTM4ZTk2OWFkYTlmMGFjMTI2NDNiMjg0NzM5MTYzNSJdfX0=",
					"repoDigests": [
						"index.docker.io/library/alpine@sha256:451eee8bedcb2f029756dc3e9d73bab0e7943c1ac55cff3a4861c52a0fdd3e98"
					]
				}
			}`),
			expectedSource: &Source{
				ID:   "foobar",
				Type: "image",
				Metadata: source.ImageMetadata{
					UserInput:      "alpine:3.10",
					ID:             "sha256:e7b300aee9f9bf3433d32bc9305bfdd22183beb59d933b48d77ab56ba53a197a",
					ManifestDigest: "sha256:e515aad2ed234a5072c4d2ef86a1cb77d5bfe4b11aa865d9214875734c4eeb3c",
					MediaType:      "application/vnd.docker.distribution.manifest.v2+json",
					Tags:           []string{},
					Size:           5576169,
					Layers: []source.LayerMetadata{
						{
							MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
							Digest:    "sha256:9fb3aa2f8b8023a4bebbf92aa567caf88e38e969ada9f0ac12643b2847391635",
							Size:      5576169,
						},
					},
					RawManifest: []byte(`{
   "schemaVersion": 2,
   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
   "config": {
      "mediaType": "application/vnd.docker.container.image.v1+json",
      "size": 1472,
      "digest": "sha256:e7b300aee9f9bf3433d32bc9305bfdd22183beb59d933b48d77ab56ba53a197a"
   },
   "layers": [
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 2798338,
         "digest": "sha256:396c31837116ac290458afcb928f68b6cc1c7bdd6963fc72f52f365a2a89c1b5"
      }
   ]
}`),
					RawConfig: []byte(`{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"],"Image":"sha256:eb2080c455e94c22ae35b3aef9e078c492a00795412e026e4d6b41ef64bc7dd8","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"container":"fdb7e80e3339e8d0599282e606c907aa5881ee4c668a68136119e6dfac6ce3a4","container_config":{"Hostname":"fdb7e80e3339","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) ","CMD [\"/bin/sh\"]"],"Image":"sha256:eb2080c455e94c22ae35b3aef9e078c492a00795412e026e4d6b41ef64bc7dd8","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":{}},"created":"2021-04-14T19:20:05.338397761Z","docker_version":"19.03.12","history":[{"created":"2021-04-14T19:20:04.987219124Z","created_by":"/bin/sh -c #(nop) ADD file:c5377eaa926bf412dd8d4a08b0a1f2399cfd708743533b0aa03b53d14cb4bb4e in / "},{"created":"2021-04-14T19:20:05.338397761Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:9fb3aa2f8b8023a4bebbf92aa567caf88e38e969ada9f0ac12643b2847391635"]}}`),
					RepoDigests: []string{
						"index.docker." +
							"io/library/alpine@sha256:451eee8bedcb2f029756dc3e9d73bab0e7943c1ac55cff3a4861c52a0fdd3e98",
					},
				},
			},
			errAssertion: assert.NoError,
		},
		{
			name: "file",
			input: []byte(`{
				"id": "foobar",
				"type": "file",
				"target":"/var/lib/foo/go.mod"
			}`),
			expectedSource: &Source{
				ID:   "foobar",
				Type: "file",
				Metadata: source.FileMetadata{
					Path: "/var/lib/foo/go.mod",
				},
			},
			errAssertion: assert.NoError,
		},
		{
			name: "unknown source type",
			input: []byte(`{
				"id": "foobar",
				"type": "unknown-thing",
				"target":"/var/lib/foo"
			}`),
			expectedSource: &Source{
				ID:   "foobar",
				Type: "unknown-thing",
			},
			errAssertion: assert.Error,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			src := new(Source)

			err := json.Unmarshal(testCase.input, src)

			testCase.errAssertion(t, err)
			if diff := cmp.Diff(testCase.expectedSource, src); diff != "" {
				t.Errorf("unexpected result from Source unmarshaling (-want +got)\n%s", diff)
			}
		})
	}
}
