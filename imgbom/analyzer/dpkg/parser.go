package dpkg

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/mitchellh/mapstructure"
)

// TODO: consider keeping the remaining values as an embedded map
type Entry struct {
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

var endOfPackages = fmt.Errorf("no more packages to read")

func ParseEntries(reader io.Reader) ([]Entry, error) {
	buffedReader := bufio.NewReader(reader)
	var entries = make([]Entry, 0)

	for {
		entry, err := parseEntry(buffedReader)
		if err != nil {
			if err == endOfPackages {
				break
			}
			return nil, err
		}
		entries = append(entries, entry)
	}

	return entries, nil
}


func parseEntry(reader *bufio.Reader) (entry Entry, err error) {
	dpkgFields := make(map[string]string)
	var key string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return Entry{}, endOfPackages
			}
			return Entry{}, err
		}

		line = strings.TrimRight(line, "\n")

		// empty line indicates end of entry
		if len(line) == 0 {
			// if the entry has not started, keep parsing lines
			if len(dpkgFields) == 0{
				continue
			}
			break
		}

		switch {
		case strings.HasPrefix(line, " "):
			// a field-body continuation
			if len(key) == 0 {
				return Entry{}, fmt.Errorf("no match for continuation: line: '%s'", line)
			}

			val, ok := dpkgFields[key]
			if !ok {
				return Entry{}, fmt.Errorf("no previous key exists, expecting: %s", key)
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
					return Entry{}, fmt.Errorf("duplicate key discovered: %s", key)
				}

				dpkgFields[key] = val
			} else {
				return Entry{}, fmt.Errorf("cannot parse field from line: '%s'", line)
			}
		}
	}
	
	err = mapstructure.Decode(dpkgFields, &entry)
	if err != nil {
		return Entry{}, err
	}

	return entry, nil
}

