package licenses

import (
	"context"
)

type licenseScannerKey struct{}

var ctxKey = licenseScannerKey{}

func SetContextLicenseScanner(ctx context.Context, s Scanner) context.Context {
	return context.WithValue(ctx, ctxKey, s)
}

func IsContextLicenseScannerSet(ctx context.Context) bool {
	_, ok := ctx.Value(ctxKey).(Scanner)
	return ok
}

func ContextLicenseScanner(ctx context.Context) (Scanner, error) {
	if s, ok := ctx.Value(ctxKey).(Scanner); ok {
		return s, nil
	}
	return NewDefaultScanner()
}
