package syft

import (
	"context"
	"testing"

	"github.com/anchore/go-sync"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cataloging"
)

func TestSetContextExecutorsAddsNetworkExecutor(t *testing.T) {
	ctx := setContextExecutors(context.Background(), DefaultCreateSBOMConfig())

	assert.True(t, sync.HasContextExecutor(ctx, cataloging.ExecutorNetwork))
}
