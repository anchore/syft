package snapsource

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/afero"

	stereoFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/bus"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
)

type snapFile struct {
	Path     string
	Digests  []file.Digest
	MimeType string
	Cleanup  func() error
}

type remoteSnap struct {
	snapIdentity
	URL string
}

const NotSpecifiedRevision int = 0

type snapIdentity struct {
	Name         string
	Channel      string
	Architecture string
	Revision     int
}

func (s snapIdentity) String() string {
	parts := []string{s.Name}
	// revision will supersede channel
	if s.Revision != NotSpecifiedRevision {
		parts = append(parts, fmt.Sprintf(":%d", s.Revision))
	} else {
		if s.Channel != "" {
			parts = append(parts, fmt.Sprintf("@%s", s.Channel))
		}

		if s.Architecture != "" {
			parts = append(parts, fmt.Sprintf(" (%s)", s.Architecture))
		}
	}

	return strings.Join(parts, "")
}

func getRemoteSnapFile(ctx context.Context, fs afero.Fs, getter intFile.Getter, cfg Config) (*snapFile, error) {
	if cfg.Request == "" {
		return nil, fmt.Errorf("invalid request: %q", cfg.Request)
	}

	var architecture string
	if cfg.Platform != nil {
		architecture = cfg.Platform.Architecture
	}

	info, err := resolveRemoteSnap(cfg.Request, architecture)
	if err != nil {
		return nil, err
	}

	return newSnapFileFromRemote(ctx, fs, cfg, getter, info)
}

func newSnapFileFromRemote(ctx context.Context, fs afero.Fs, cfg Config, getter intFile.Getter, info *remoteSnap) (*snapFile, error) {
	t, err := afero.TempDir(fs, "", "syft-snap-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	snapFilePath := path.Join(t, path.Base(info.URL))
	err = downloadSnap(getter, info, snapFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to download snap file: %w", err)
	}

	closer := func() error {
		return fs.RemoveAll(t)
	}

	mimeType, digests, err := getSnapFileInfo(ctx, fs, snapFilePath, cfg.DigestAlgorithms)
	if err != nil {
		return nil, err
	}

	return &snapFile{
		Path:     snapFilePath,
		Digests:  digests,
		MimeType: mimeType,
		Cleanup:  closer,
	}, nil
}

func newSnapFromFile(ctx context.Context, fs afero.Fs, cfg Config) (*snapFile, error) {
	var architecture string
	if cfg.Platform != nil {
		architecture = cfg.Platform.Architecture
	}

	if architecture != "" {
		return nil, fmt.Errorf("architecture cannot be specified for local snap files: %q", cfg.Request)
	}

	absPath, err := filepath.Abs(cfg.Request)
	if err != nil {
		return nil, fmt.Errorf("unable to get absolute path of snap: %w", err)
	}

	mimeType, digests, err := getSnapFileInfo(ctx, fs, absPath, cfg.DigestAlgorithms)
	if err != nil {
		return nil, err
	}

	return &snapFile{
		Path:     absPath,
		Digests:  digests,
		MimeType: mimeType,
		// note: we have no closer since this is the user's file (never delete it)
	}, nil
}

func getSnapFileInfo(ctx context.Context, fs afero.Fs, path string, hashes []crypto.Hash) (string, []file.Digest, error) {
	fileMeta, err := fs.Stat(path)
	if err != nil {
		return "", nil, fmt.Errorf("unable to stat path=%q: %w", path, err)
	}

	if fileMeta.IsDir() {
		return "", nil, fmt.Errorf("given path is a directory, not a snap file: %q", path)
	}

	fh, err := fs.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("unable to open file=%q: %w", path, err)
	}
	defer fh.Close()

	mimeType := stereoFile.MIMEType(fh)
	if !isSquashFSFile(mimeType, path) {
		return "", nil, fmt.Errorf("not a valid squashfs/snap file: %q (mime-type=%q)", path, mimeType)
	}

	var digests []file.Digest
	if len(hashes) > 0 {
		if _, err := fh.Seek(0, 0); err != nil {
			return "", nil, fmt.Errorf("unable to reset file position: %w", err)
		}

		digests, err = intFile.NewDigestsFromFile(ctx, fh, hashes)
		if err != nil {
			return "", nil, fmt.Errorf("unable to calculate digests for file=%q: %w", path, err)
		}
	}

	return mimeType, digests, nil
}

// resolveRemoteSnap parses a snap request and returns the appropriate path or URL
// The request can be:
// - A snap name (e.g., "etcd")
// - A snap name with channel (e.g., "etcd@beta" or "etcd@2.3/stable")
// - A snap name with revision (e.g. etcd:249@stable)
func resolveRemoteSnap(request, architecture string) (*remoteSnap, error) {
	if architecture == "" {
		architecture = defaultArchitecture
	}

	snapName, revision, channel, err := parseSnapRequest(request)
	if err != nil {
		return nil, err
	}
	id := snapIdentity{
		Name:         snapName,
		Channel:      channel,
		Architecture: architecture,
		Revision:     revision,
	}

	client := newSnapcraftClient()

	downloadURL, err := client.GetSnapDownloadURL(id)
	if err != nil {
		return nil, err
	}

	log.WithFields("url", downloadURL, "name", snapName, "channel", channel, "architecture", architecture).Debugf("snap resolved")

	return &remoteSnap{
		snapIdentity: id,
		URL:          downloadURL,
	}, nil
}

// parseSnapRequest parses a snap request into name and revision/channel
// Examples:
// - "etcd" -> name="etcd", channel="stable" (default)
// - "etcd@beta" -> name="etcd", channel="beta"
// - "etcd@2.3/stable" -> name="etcd", channel="2.3/stable"
// - "etcd:249@2.3/stable" -> name="etcd" revision=249 (channel not working because revision has been assigned)
func parseSnapRequest(request string) (name string, revision int, channel string, err error) {
	parts := strings.SplitN(request, "@", 2)
	name = parts[0]

	divisions := strings.Split(parts[0], ":")
	// handle revision first
	if len(divisions) == 2 {
		name = divisions[0]
		revision, err = strconv.Atoi(divisions[1])
		if err != nil {
			return "", NotSpecifiedRevision, "", err
		}
		return name, revision, "", err
	}
	if len(parts) == 2 {
		channel = parts[1]
	}

	if channel == "" {
		channel = defaultChannel
	}
	return name, NotSpecifiedRevision, channel, err
}

func downloadSnap(getter intFile.Getter, info *remoteSnap, dest string) error {
	log.WithFields("url", info.URL, "destination", dest).Debug("downloading snap file")

	prog := bus.StartPullSourceTask(monitor.GenericTask{
		Title: monitor.Title{
			Default:      "Download snap",
			WhileRunning: "Downloading snap",
			OnSuccess:    "Downloaded snap",
		},
		HideOnSuccess:      false,
		HideStageOnSuccess: true,
		ID:                 "",
		ParentID:           "",
		Context:            info.String(),
	}, -1, "")

	if err := getter.GetFile(dest, info.URL, prog.Manual); err != nil {
		prog.SetError(err)
		return fmt.Errorf("failed to download snap file at %q: %w", info.URL, err)
	}

	prog.SetCompleted()
	return nil
}

// fileExists checks if a file exists and is not a directory
func fileExists(fs afero.Fs, path string) bool {
	info, err := fs.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && !info.IsDir()
}
