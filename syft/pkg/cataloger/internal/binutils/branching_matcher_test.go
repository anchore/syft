package binutils

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

func Test_BranchingMatcher(t *testing.T) {
	matchingTest := FileContentsVersionMatcher("", `my-verison:(?<version>\d+\.\d+)`)
	notMatchingTest := MatchPath("**/not-version*")

	tests := []struct {
		name                 string
		matcher              EvidenceMatcher
		expectedPackageNames []string
	}{
		{
			name: "not matching",
			matcher: BranchingEvidenceMatcher(
				Classifier{
					EvidenceMatcher: MatchAll(
						notMatchingTest,
						matchingTest,
					),
					Package: "a-pkg",
				},
			),
			expectedPackageNames: nil,
		},
		{
			name: "both match",
			matcher: BranchingEvidenceMatcher(
				Classifier{
					EvidenceMatcher: matchingTest,
					Package:         "a-pkg",
				},
				Classifier{
					EvidenceMatcher: matchingTest,
					Package:         "b-pkg",
				},
			),
			expectedPackageNames: []string{"a-pkg"},
		},
		{
			name: "first-does-not-match",
			matcher: BranchingEvidenceMatcher(
				Classifier{
					EvidenceMatcher: MatchAll(
						notMatchingTest,
						matchingTest,
					),
					Package: "b-pkg",
				},
				Classifier{
					EvidenceMatcher: matchingTest,
					Package:         "c-pkg",
				},
			),
			expectedPackageNames: []string{"c-pkg"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := file.NewMockResolverForPaths("test-fixtures/version.txt", "test-fixtures/version-parts.txt")
			locs, err := resolver.FilesByGlob("**/version.txt")
			require.NoError(t, err)
			require.Len(t, locs, 1)
			loc := locs[0]
			rdr, err := resolver.FileContentsByLocation(loc)
			require.NoError(t, err)
			urdr, err := unionreader.GetUnionReader(rdr)
			require.NoError(t, err)
			pkgs, err := test.matcher(Classifier{
				Package: "a-pkg",
			}, MatcherContext{
				Resolver: resolver,
				Location: loc,
				GetReader: func(resolver MatcherContext) (unionreader.UnionReader, error) {
					return urdr, nil
				},
			})
			require.NoError(t, err)
			var got []string
			for i := range pkgs {
				got = append(got, pkgs[i].Name)
			}
			require.EqualValues(t, test.expectedPackageNames, got)
		})
	}
}
