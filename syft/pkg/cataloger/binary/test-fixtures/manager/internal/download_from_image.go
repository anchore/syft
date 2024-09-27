package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/config"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/ui"
)

const digestFileSuffix = ".xxh64"

func DownloadFromImage(dest string, config config.BinaryFromImage) error {
	t := ui.Title{Name: config.Name(), Version: config.Version}
	t.Start()

	hostPaths := config.AllStorePaths(dest)
	if allPathsExist(hostPaths) {
		if !isDownloadStale(config, hostPaths) {
			t.Skip("already exists")
			return nil
		}
		t.Update("stale, updating...")
	}

	if err := pullDockerImages(config.Images); err != nil {
		return err
	}

	if err := copyBinariesFromDockerImages(config, dest); err != nil {
		return fmt.Errorf("failed to copy binary for %s@%s: %v", config.Name(), config.Version, err)
	}

	return nil
}

func isDownloadStale(config config.BinaryFromImage, binaryPaths []string) bool {
	currentDigest := config.Digest()

	for _, path := range binaryPaths {
		digestPath := path + digestFileSuffix
		if _, err := os.Stat(digestPath); err != nil {
			// missing a fingerprint file means the download is stale
			return true
		}

		writtenDigest, err := os.ReadFile(digestPath)
		if err != nil {
			// missing a fingerprint file means the download is stale
			return true
		}

		if string(writtenDigest) != currentDigest {
			// the fingerprint file does not match the current fingerprint, so the download is stale
			return true
		}
	}

	return false
}

func allPathsExist(paths []string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

func pullDockerImages(images []config.Image) error {
	for _, image := range images {
		if err := pullDockerImage(image.Reference, image.Platform); err != nil {
			return fmt.Errorf("failed to pull image %s for platform %s: %v", image.Reference, image.Platform, err)
		}
	}
	return nil
}

type imageInspect struct {
	OS           string `json:"Os"`
	Architecture string `json:"Architecture"`
}

func (i imageInspect) Platform() string {
	return fmt.Sprintf("%s/%s", i.OS, i.Architecture)
}

func pullDockerImage(imageReference, platform string) error {
	a := ui.Action{Msg: fmt.Sprintf("pull image %s (%s)", imageReference, platform)}
	a.Start()

	matches, _, _ := checkArchitecturesMatch(imageReference, platform)
	if matches {
		a.Skip(fmt.Sprintf("docker image already exists %q", imageReference))
		return nil
	}

	cmd := exec.Command("docker", "pull", "--platform", platform, imageReference)
	err := cmd.Run()
	if err != nil {
		// attach stderr to output message
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			err = fmt.Errorf("pull failed: %w:\n%s", err, exitErr.Stderr)
		}

		a.Done(err)
		return err
	}

	matches, gotPlatform, err := checkArchitecturesMatch(imageReference, platform)
	if !matches && err == nil {
		err = fmt.Errorf("image %q pulled but does not match expected platform %q != %q", imageReference, platform, gotPlatform)
	}

	a.Done(err)

	return err
}

func checkArchitecturesMatch(imageReference, platform string) (bool, string, error) {
	cmd := exec.Command("docker", "image", "inspect", imageReference)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, "", err
	}

	var inspect []imageInspect
	if err := json.Unmarshal(out, &inspect); err != nil {
		return false, "", fmt.Errorf("unable to unmarshal image inspect: %w", err)
	}

	if len(inspect) != 1 {
		return false, "", fmt.Errorf("expected 1 image inspect, got %d", len(inspect))
	}
	gotPlatform := inspect[0].Platform()

	return gotPlatform == platform, gotPlatform, nil
}

func copyBinariesFromDockerImages(config config.BinaryFromImage, destination string) (err error) {
	for _, image := range config.Images {
		if err := copyBinariesFromDockerImage(config, destination, image); err != nil {
			return err
		}
	}

	return nil
}

func copyBinariesFromDockerImage(config config.BinaryFromImage, destination string, image config.Image) (err error) {
	containerName := fmt.Sprintf("%s-%s-%s", config.Name(), strings.ReplaceAll(config.Version, "+", "-"), uuid.New().String())

	cmd := exec.Command("docker", "create", "--name", containerName, image.Reference)
	if err = cmd.Run(); err != nil {
		// attach stderr to output message
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			err = fmt.Errorf("%w:\n%s", err, exitErr.Stderr)
		}

		return err
	}

	defer func() {
		cmd := exec.Command("docker", "rm", containerName)
		cmd.Run() //nolint:errcheck
	}()

	for i, destinationPath := range config.AllStorePathsForImage(image, destination) {
		path := config.PathsInImage[i]
		if err := copyBinaryFromContainer(containerName, path, destinationPath, config.Digest()); err != nil {
			return err
		}
	}

	return nil
}

func copyBinaryFromContainer(containerName, containerPath, destinationPath, digest string) (err error) {
	a := ui.Action{Msg: fmt.Sprintf("extract %s", containerPath)}
	a.Start()

	defer func() {
		a.Done(err)
	}()

	if err := os.MkdirAll(filepath.Dir(destinationPath), 0755); err != nil {
		return err
	}

	cmd := exec.Command("docker", "cp", fmt.Sprintf("%s:%s", containerName, containerPath), destinationPath) //nolint:gosec
	// reason for gosec exception: this is for processing test fixtures only, not used in production
	if err := cmd.Run(); err != nil {
		// attach stderr to output message
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			err = fmt.Errorf("%w:\n%s", err, exitErr.Stderr)
		}

		return err
	}

	// ensure permissions are 600 for destination
	if err := os.Chmod(destinationPath, 0600); err != nil {
		return fmt.Errorf("unable to set permissions on file %q: %w", destinationPath, err)
	}

	// capture digest file
	digestPath := destinationPath + digestFileSuffix
	if err := os.WriteFile(digestPath, []byte(digest), 0600); err != nil {
		return fmt.Errorf("unable to write digest file: %w", err)
	}

	return nil
}
