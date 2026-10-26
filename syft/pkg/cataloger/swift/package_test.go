package swift

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_swiftPackageManagerPackageURL(t *testing.T) {
	tests := []struct {
		name      string
		pkgName   string
		version   string
		sourceURL string
		want      string
	}{
		{
			name:      "strips .git suffix and repeated name segment",
			pkgName:   "swift-nio-ssl",
			version:   "2.0.0",
			sourceURL: "https://github.com/apple/swift-nio-ssl.git",
			want:      "pkg:swift/github.com/apple/swift-nio-ssl@2.0.0",
		},
		{
			name:      "no .git suffix",
			pkgName:   "swift-numerics",
			version:   "1.0.2",
			sourceURL: "https://github.com/apple/swift-numerics",
			want:      "pkg:swift/github.com/apple/swift-numerics@1.0.2",
		},
		{
			name:      "mixed-case repo path with lowercased identity",
			pkgName:   "swift-nio",
			version:   "2.0.0",
			sourceURL: "https://github.com/Apple/Swift-NIO.git",
			want:      "pkg:swift/github.com/Apple/swift-nio@2.0.0",
		},
		{
			name:      "ssh scheme",
			pkgName:   "swift-nio",
			version:   "2.0.0",
			sourceURL: "git+ssh://github.com/apple/swift-nio.git",
			want:      "pkg:swift/github.com/apple/swift-nio@2.0.0",
		},
		{
			name:      "trailing segment differs from name is preserved",
			pkgName:   "nio",
			version:   "2.0.0",
			sourceURL: "https://github.com/apple/swift-nio.git",
			want:      "pkg:swift/github.com/apple/swift-nio/nio@2.0.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, swiftPackageManagerPackageURL(tt.pkgName, tt.version, tt.sourceURL))
		})
	}
}

func Test_cocoaPodsPackageURL(t *testing.T) {
	type args struct {
		name    string
		version string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "go case",
			args: args{
				name:    "name",
				version: "v0.1.0",
			},
			want: "pkg:cocoapods/name@v0.1.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, cocoaPodsPackageURL(tt.args.name, tt.args.version))
		})
	}
}
