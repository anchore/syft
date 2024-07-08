package cargo

import (
	"fmt"
	"io"

	"github.com/pelletier/go-toml/v2"
)

type LockFile struct {
	CargoLockVersion int         `toml:"version"`
	Packages         []LockEntry `toml:"package"`
}

func ParseLockToml(reader io.Reader, entryFactory LockEntryHydrator) (*LockFile, error) {
	m := LockFile{}
	err := toml.NewDecoder(reader).Decode(&m)
	if err != nil {
		return nil, fmt.Errorf("unable to load or parse Cargo.lock: %w", err)
	}

	for i := range m.Packages {
		if err := entryFactory.hydrateLockEntry(&m.Packages[i], m.CargoLockVersion); err != nil {
			return nil, err
		}
	}
	return &m, nil
}
