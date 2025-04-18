package licenses

import (
	"context"
)

type LicenseScannerKey struct{}

var CtxKey = LicenseScannerKey{}

func SetContextLicenseScanner(ctx context.Context, s Scanner) context.Context {
	return context.WithValue(ctx, CtxKey, s)
}

func ContextLicenseScanner(ctx context.Context) (Scanner, error) {
	if s, ok := ctx.Value(CtxKey).(Scanner); ok {
		return s, nil
	}
	return NewDefaultScanner()
}
