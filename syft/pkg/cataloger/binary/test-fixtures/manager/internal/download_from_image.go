package internal

import (
	"fmt"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/config"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/ui"
	"github.com/google/uuid"
	"os"
	"os/exec"
	"path/filepath"
)

func DownloadFromImage(dest string, config config.BinaryFromImage) error {
	t := ui.Title{Name: config.Name(), Version: config.Version}
	t.Start()

	hostPaths := config.AllStorePaths(dest)
	if allPathsExist(hostPaths) {
		if !isDownloadStale(config, hostPaths) {
			t.Skip("already exists")
			return nil
		} else {
			t.Update("stale, updating...")
		}
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
	currentFingerprint := config.Fingerprint()

	for _, path := range binaryPaths {
		fingerprintPath := path + ".fingerprint"
		if _, err := os.Stat(fingerprintPath); err != nil {
			// missing a fingerprint file means the download is stale
			return true
		}

		writtenFingerprint, err := os.ReadFile(fingerprintPath)
		if err != nil {
			// missing a fingerprint file means the download is stale
			return true
		}

		if string(writtenFingerprint) != currentFingerprint {
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

func pullDockerImage(imageReference, platform string) error {
	a := ui.Action{Msg: fmt.Sprintf("pull image %s (%s)", imageReference, platform)}
	a.Start()
	cmd := exec.Command("docker", "image", "inspect", imageReference)
	if err := cmd.Run(); err == nil {
		a.Skip(fmt.Sprintf("docker image already exists %q", imageReference))

		return nil
	}

	cmd = exec.Command("docker", "pull", "--platform", platform, imageReference)
	err := cmd.Run()

	a.Done(err)

	return err
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
	containerName := fmt.Sprintf("%s-%s-%s", config.Name(), config.Version, uuid.New().String())

	cmd := exec.Command("docker", "create", "--name", containerName, image.Reference)
	if err = cmd.Run(); err != nil {
		return err
	}

	defer func() {
		cmd := exec.Command("docker", "rm", containerName)
		cmd.Run()
	}()

	for i, destinationPath := range config.AllStorePathsForImage(image, destination) {
		path := config.PathsInImage[i]
		if err := copyBinaryFromContainer(containerName, path, destinationPath, config.Fingerprint()); err != nil {
			return err
		}
	}

	return nil
}

func copyBinaryFromContainer(containerName, containerPath, destinationPath, fingerprint string) (err error) {

	a := ui.Action{Msg: fmt.Sprintf("extract %s", containerPath)}
	a.Start()

	defer func() {
		a.Done(err)
	}()

	if err := os.MkdirAll(filepath.Dir(destinationPath), 0755); err != nil {
		return err
	}

	cmd := exec.Command("docker", "cp", fmt.Sprintf("%s:%s", containerName, containerPath), destinationPath)
	if err := cmd.Run(); err != nil {
		return err
	}

	// capture fingerprint file
	fingerprintPath := destinationPath + ".fingerprint"
	if err := os.WriteFile(fingerprintPath, []byte(fingerprint), 0644); err != nil {
		return fmt.Errorf("unable to write fingerprint file: %w", err)
	}

	return nil
}
