package cpe

import (
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/spf13/afero"
)

func TestNewMetadataFromFile(t *testing.T) {
	tests := []struct {
		fixture  string
		expected Metadata
		err      bool
	}{
		{
			fixture: "test-fixtures/official-cpe-dictionary_v2.3.meta",
			expected: Metadata{
				Date:     time.Date(2021, 01, 01, 00, 39, 25, 0, time.UTC),
				Checksum: "sha256:dd6254c80ac1451859cb9afc979c578a7ad64822ba5f5fe2ca919f46de1a29c2",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			metadata, err := NewMetadataFromFile(afero.NewOsFs(), test.fixture)
			if err != nil && !test.err {
				t.Fatalf("failed to get metadata: %+v", err)
			} else if err == nil && test.err {
				t.Fatalf("expected error but got none")
			}

			for _, diff := range deep.Equal(metadata, test.expected) {
				t.Errorf("metadata difference: %s", diff)
			}
		})
	}
}

func TestNewMetadataFromDir(t *testing.T) {
	tests := []struct {
		fixture  string
		expected Metadata
		err      bool
	}{
		{
			fixture: "test-fixtures/old-metadata",
			expected: Metadata{
				Date:     time.Date(2020, 01, 23, 00, 39, 25, 0, time.UTC),
				Checksum: "sha256:dd6253c70ac0340748cb9afc979c578a7ad64822ba5f5fe2ca919f46de1a29c2",
				Count:    24320,
			},
		},
		{
			fixture: "test-fixtures/recent-metadata",
			expected: Metadata{
				Date:     time.Date(2021, 01, 23, 00, 39, 25, 0, time.UTC),
				Checksum: "sha256:dd6254c80ac1451859cb9afc979c578a7ad64822ba5f5fe2ca919f46de1a29c2",
				Count:    24326,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			metadata, err := NewMetadataFromDir(afero.NewOsFs(), test.fixture)
			if err != nil && !test.err {
				t.Fatalf("failed to get metadata: %+v", err)
			} else if err == nil && test.err {
				t.Fatalf("expected error but got none")
			}

			if metadata == nil {
				t.Fatalf("metadata not found: %+v", test.fixture)
			}

			for _, diff := range deep.Equal(*metadata, test.expected) {
				t.Errorf("metadata difference: %s", diff)
			}
		})
	}
}

func TestMetadataIsSupercededBy(t *testing.T) {
	tests := []struct {
		name                string
		current             *Metadata
		update              *Metadata
		expectedToSupercede bool
	}{
		{
			name:                "prefer later dates",
			expectedToSupercede: true,
			current: &Metadata{
				Date: time.Date(2020, 01, 23, 00, 39, 25, 0, time.UTC),
			},
			update: &Metadata{
				Date: time.Date(2021, 01, 23, 00, 39, 25, 0, time.UTC),
			},
		},
		{
			name:                "prefer something over nothing",
			expectedToSupercede: true,
			current:             nil,
			update: &Metadata{
				Date: time.Date(2020, 01, 23, 00, 39, 25, 0, time.UTC),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := test.current.IsSupersededBy(test.update)

			if test.expectedToSupercede != actual {
				t.Errorf("failed supercede assertion: got %+v", actual)
			}
		})
	}
}
