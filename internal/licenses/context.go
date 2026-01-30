package licenses

import (
	"context"
	"errors"
)

type licenseScannerKey struct{}

var ctxKey = licenseScannerKey{}

var ErrNoLicenseScanner = errors.New("no license scanner set in context")

func SetContextLicenseScanner(ctx context.Context, s Scanner) context.Context {
	return context.WithValue(ctx, ctxKey, s)
}

func IsContextLicenseScannerSet(ctx context.Context) bool {
	_, ok := ctx.Value(ctxKey).(Scanner)
	return ok
}

func ContextLicenseScanner(ctx context.Context) (Scanner, error) {
	s, ok := ctx.Value(ctxKey).(Scanner)
	if !ok {
		return nil, ErrNoLicenseScanner
	}
	return s, nil
}
