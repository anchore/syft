package cpegenerate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArtifactIDToGroupID(t *testing.T) {
	tests := []struct {
		name       string
		artifactID string
		version    string
		want       string
		wantOK     bool
	}{
		{name: "unconditional entry", artifactID: "ant-antlr", version: "1.10.0", want: "org.apache.ant", wantOK: true},
		{name: "unknown artifact", artifactID: "not-a-real-artifact", version: "1.0.0"},
		{name: "groovy 4 migrates to apache", artifactID: "groovy", version: "4.0.33", want: "org.apache.groovy", wantOK: true},
		{name: "groovy 3 stays on codehaus", artifactID: "groovy", version: "3.0.22", want: "org.codehaus.groovy", wantOK: true},
		{name: "groovy without a version falls back to codehaus", artifactID: "groovy-json", want: "org.codehaus.groovy", wantOK: true},
		{name: "groovy-eclipse stays on codehaus at 4.x", artifactID: "groovy-eclipse-batch", version: "4.0.33-02", want: "org.codehaus.groovy", wantOK: true},
		{name: "apache-only groovy module", artifactID: "groovy-ginq", version: "4.0.33", want: "org.apache.groovy", wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ArtifactIDToGroupID(tt.artifactID, tt.version)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_majorVersion(t *testing.T) {
	tests := map[string]int{
		"4.0.33":        4,
		"4.0.0-alpha-1": 4,
		"4-SNAPSHOT":    4,
		"4":             4,
		"3.0.22":        3,
		"v4.0.33":       0,
		"":              0,
	}
	for version, expect := range tests {
		t.Run(version, func(t *testing.T) {
			assert.Equal(t, expect, majorVersion(version))
		})
	}
}
