package javascript

import (
	"context"

	"github.com/anchore/go-sync"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloging"
)

// prefetchNpmLicenses warms the shared JavaScript license resolver cache so
// package construction does not serialize independent npm registry requests.
// The network executor provides the repository-wide concurrency bound.
func prefetchNpmLicenses(ctx context.Context, resolver javascriptLicenseResolver, pairs [][2]string) {
	if len(pairs) == 0 || !resolver.catalogerConfig.SearchRemoteLicenses {
		return
	}

	unique := make([][2]string, 0, len(pairs))
	seen := make(map[[2]string]struct{}, len(pairs))
	for _, pair := range pairs {
		if _, ok := seen[pair]; ok {
			continue
		}
		seen[pair] = struct{}{}
		unique = append(unique, pair)
	}

	err := sync.Collect(&ctx, cataloging.ExecutorNetwork, sync.ToSeq(unique), func(pair [2]string) (struct{}, error) {
		_, err := resolver.getLicensesFromRemote(pair[0], pair[1])
		return struct{}{}, err
	}, nil)
	if err != nil {
		log.Debugf("unable to prefetch JavaScript licenses from npm registry: %+v", err)
	}
}
