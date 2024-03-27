package binary

import (
	"reflect"
	"testing"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

func TestNewDependencyRelationships(t *testing.T) {
	s := &sbom.SBOM{}
	tests := []struct {
		name     string
		resolver file.Resolver
		accessor sbomsync.Accessor
		want     []artifact.Relationship
	}{
		{
			name:     "blank sbom and accessor returns empty relationships",
			resolver: nil,
			accessor: sbomsync.NewBuilder(s).(sbomsync.Accessor),
			want:     make([]artifact.Relationship, 0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			relationships := NewDependencyRelationships(tt.resolver, tt.accessor)
			if !reflect.DeepEqual(relationships, tt.want) {
				t.Errorf("NewDependencyRelationships() = %v, want %v", relationships, tt.want)
			}
		})
	}
}
