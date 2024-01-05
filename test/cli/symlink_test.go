package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_RequestedPathIncludesSymlink(t *testing.T) {
	// path contains a symlink
	path := "test-fixtures/image-pkg-coverage/pkgs/java/example-java-app-maven-0.1.0.jar"
	_, stdout, _ := runSyft(t, nil, "scan", path)
	assert.Contains(t, stdout, "example-java-app-maven")
}
