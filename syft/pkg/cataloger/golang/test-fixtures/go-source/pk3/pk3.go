package pk3

import (
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func Zap() {
	sugar := zap.NewExample().Sugar()
	defer sugar.Sync()
	sugar.Infow("failed to fetch URL",
		"url", "http://example.com",
		"attempt", 3,
		"backoff", time.Second,
	)
	sugar.Infof("failed to fetch URL: %s", "http://example.com")
	viper.SetDefault("ContentDir", "content")
}
