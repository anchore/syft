package dpkg

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/mitchellh/mapstructure"
)

// TODO: consider keeping the remaining values as an embedded map
type DpkgEntry struct {
	Package        string `mapstructure:"Package"`
	Architecture   string `mapstructure:"Architecture"`
	DependsPkgs    string `mapstructure:"Depends"`
	InstalledSize  string `mapstructure:"Installed-Size"`
	Maintainer     string `mapstructure:"Maintainer"`
	Priority       string `mapstructure:"Priority"`
	ProvidesPkgs   string `mapstructure:"Provides"`
	RecommendsPkgs string `mapstructure:"Recommends"`
	ReplacesPkgs   string `mapstructure:"Replaces"`
	Status         string `mapstructure:"Status"`
	SuggestsPkgs   string `mapstructure:"Suggests"`
	Version        string `mapstructure:"Version"`
	ConfigFiles    string `mapstructure:"Conffiles"`
}

// dpkg-query recognized fields
//                  Architecture
//                  Bugs
//                  Conffiles (internal)
//                  Config-Version (internal)
//                  Conflicts
//                  Breaks
//                  Depends
//                  Description
//                  Enhances
//                  Essential
//                  Filename (internal, front-end related)
//                  Homepage
//                  Installed-Size
//                  MD5sum (internal, front-end related)
//                  MSDOS-Filename (internal, front-end related)
//                  Maintainer
//                  Origin
//                  Package
//                  Pre-Depends
//                  Priority
//                  Provides
//                  Recommends
//                  Replaces
//                  Revision (obsolete)
//                  Section
//                  Size (internal, front-end related)
//                  Source
//                  Status (internal)
//                  Suggests
//                  Tag (usually not in .deb but in repository Packages files)
//                  Triggers-Awaited (internal)
//                  Triggers-Pending (internal)
//                  Version
//

var EndOfPackages = fmt.Errorf("no more packages to read")

func Read(reader io.Reader) (entry DpkgEntry, err error) {
	buff := bufio.NewReader(reader)
	dpkgFields := make(map[string]string)
	var key string

	for {
		line, ioerr := buff.ReadString('\n')
		fmt.Printf("line:'%+v' err:'%+v'\n", line, ioerr)
		if ioerr != nil {
			if ioerr == io.EOF {
				return DpkgEntry{}, EndOfPackages
			}
			return DpkgEntry{}, ioerr
		}

		line = strings.TrimRight(line, "\n")

		// stop if there is no contents in line
		if len(line) == 0 {
			break
		}

		switch {
		case strings.HasPrefix(line, " "):
			// a field-body continuation
			if len(key) == 0 {
				return DpkgEntry{}, fmt.Errorf("no match for continuation: line: '%s'", line)
			}

			val, ok := dpkgFields[key]
			if !ok {
				return DpkgEntry{}, fmt.Errorf("no previous key exists, expecting: %s", key)
			}
			// concatenate onto previous value
			val = fmt.Sprintf("%s\n %s", val, strings.TrimSpace(line))
			dpkgFields[key] = val
		default:
			// parse a new key
			if i := strings.Index(line, ":"); i > 0 {
				key = strings.TrimSpace(line[0:i])
				val := strings.TrimSpace(line[i+1:])

				if _, ok := dpkgFields[key]; ok {
					return DpkgEntry{}, fmt.Errorf("duplicate key discovered: %s", key)
				}

				dpkgFields[key] = val
			} else {
				return DpkgEntry{}, fmt.Errorf("cannot parse field from line: '%s'", line)
			}
		}
	}

	fmt.Println("OUTOFLOOP")

	// map -> struct
	err = mapstructure.Decode(dpkgFields, &entry)
	if err != nil {
		return DpkgEntry{}, err
	}

	return entry, nil
}

func ReadAllDpkgEntries(reader io.Reader) ([]DpkgEntry, error) {
	var entries = make([]DpkgEntry, 0)

	for {
		// Read() until error
		entry, err := Read(reader)
		fmt.Printf("entry:'%+v'\n\terr:%+v\n", entry, err)
		if err != nil {
			if err == EndOfPackages {
				break
			}
			return nil, err
		}
		entries = append(entries, entry)
	}

	return entries, nil
}
