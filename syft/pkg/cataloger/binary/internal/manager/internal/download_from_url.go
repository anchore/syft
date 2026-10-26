package internal

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/internal/manager/internal/config"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/internal/manager/internal/ui"
)

var httpClient = &http.Client{Timeout: 30 * time.Minute}

// DownloadFromURL downloads each URL listed in the config entry and stores the
// resulting binary under dest. The platform for each target must be explicitly
// specified in the config.
func DownloadFromURL(dest string, cfg config.BinaryFromURL) error {
	t := ui.Title{Name: cfg.Name(), Version: cfg.Version}
	t.Start()

	if allURLTargetsExistAndNotStale(dest, cfg) {
		t.Skip("already exists")
		return nil
	}
	t.Update("stale, updating...")

	for _, target := range cfg.Targets {
		if err := downloadOneTarget(dest, cfg, target); err != nil {
			return fmt.Errorf("failed to download %s@%s from %s: %w", cfg.Name(), cfg.Version, target.URL, err)
		}
	}

	return nil
}

// allURLTargetsExistAndNotStale checks that every target's binary already exists
// at the expected store path and has a digest matching the current config.
func allURLTargetsExistAndNotStale(dest string, cfg config.BinaryFromURL) bool {
	currentDigest := cfg.Digest()

	for _, target := range cfg.Targets {
		storePath := cfg.StorePath(dest, config.PlatformAsValue(target.Platform))

		if _, err := os.Stat(storePath); err != nil {
			return false
		}

		digestPath := storePath + digestFileSuffix
		writtenDigest, err := os.ReadFile(digestPath)
		if err != nil || string(writtenDigest) != currentDigest {
			return false
		}
	}

	return true
}

func downloadOneTarget(dest string, cfg config.BinaryFromURL, target config.URLTarget) error {
	a := ui.Action{Msg: fmt.Sprintf("download %s", target.URL)}
	a.Start()

	//nolint:gocritic // reason: this is for processing test fixtures only, not used in production
	tmp, err := os.CreateTemp("", "syft-download-*")
	if err != nil {
		a.Done(err)
		return fmt.Errorf("unable to create temp file: %w", err)
	}
	// defer os.Remove is safe in all branches:
	// - If os.Rename succeeds, tmp.Name() no longer exists on disk, so Remove is a no-op.
	// - If the copyFile fallback is used instead, the temp file stays at its original path
	//   and must be removed here to avoid leaking it.
	defer os.Remove(tmp.Name())

	switch cfg.Format {
	case "tar.gz":
		err = downloadFromTarGz(target.URL, cfg.PathInArchive, tmp)
	default:
		err = downloadRaw(target.URL, tmp)
	}

	if err != nil {
		tmp.Close()
		a.Done(err)
		return err
	}

	if err := tmp.Close(); err != nil {
		a.Done(err)
		return fmt.Errorf("unable to close temp file: %w", err)
	}

	platform := config.PlatformAsValue(target.Platform)

	storePath := cfg.StorePath(dest, platform)

	if err = writeBinaryAndDigest(tmp.Name(), storePath, cfg.Digest()); err != nil {
		a.Done(err)
		return err
	}

	a.Done(nil)
	return nil
}

const maxDownloadSize = 2 * 1024 * 1024 * 1024 // 2GB

// downloadRaw fetches a URL and writes it to w.
func downloadRaw(rawURL string, w io.Writer) error {
	resp, err := httpClient.Get(rawURL)
	if err != nil {
		return fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d for %s", resp.StatusCode, rawURL)
	}

	_, err = io.Copy(w, io.LimitReader(resp.Body, maxDownloadSize))
	if err != nil {
		return fmt.Errorf("failed to write raw data: %w", err)
	}
	return nil
}

// downloadFromTarGz fetches a .tar.gz from rawURL, extracts the entry at
// pathInArchive, and writes it to w.
func downloadFromTarGz(rawURL, pathInArchive string, w io.Writer) error {
	resp, err := httpClient.Get(rawURL)
	if err != nil {
		return fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d for %s", resp.StatusCode, rawURL)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		if hdr.Name == pathInArchive {
			_, err = io.Copy(w, io.LimitReader(tr, maxDownloadSize))
			if err != nil {
				return fmt.Errorf("failed to write extracted data: %w", err)
			}
			return nil
		}
	}

	return fmt.Errorf("path %q not found in archive %s", pathInArchive, rawURL)
}

// writeBinaryAndDigest moves the temporary binary file to storePath and writes a digest sidecar file.
func writeBinaryAndDigest(tmpPath, storePath string, digest string) error {
	if err := os.MkdirAll(filepath.Dir(storePath), 0755); err != nil {
		return fmt.Errorf("unable to create destination directory: %w", err)
	}

	// Rename the temp file to the final destination
	if err := os.Rename(tmpPath, storePath); err != nil {
		// Fallback to io.Copy if os.Rename fails (e.g. cross-device link)
		if err := copyFile(tmpPath, storePath); err != nil {
			return fmt.Errorf("unable to move binary to %s: %w", storePath, err)
		}
	}

	if err := os.Chmod(storePath, 0600); err != nil {
		return fmt.Errorf("unable to chmod binary: %w", err)
	}

	digestPath := storePath + digestFileSuffix
	if err := os.WriteFile(digestPath, []byte(digest), 0600); err != nil {
		return fmt.Errorf("unable to write digest file: %w", err)
	}

	return nil
}

func copyFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	_, err = io.Copy(out, in)
	return err
}
