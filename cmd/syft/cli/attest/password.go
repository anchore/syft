package attest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/sigstore/cosign/pkg/cosign"
)

func selectPassFunc(keypath, password string) (cosign.PassFunc, error) {
	keyContents, err := os.ReadFile(keypath)
	if err != nil {
		return nil, err
	}

	var fn cosign.PassFunc = func(bool) (b []byte, err error) { return nil, nil }

	_, err = cosign.LoadPrivateKey(keyContents, nil)
	if err != nil {
		fn = func(bool) (b []byte, err error) {
			return fetchPassword(password)
		}
	}

	return fn, nil
}

func fetchPassword(password string) (b []byte, err error) {
	potentiallyPipedInput, err := internal.IsPipedInput()
	if err != nil {
		log.Warnf("unable to determine if there is piped input: %+v", err)
	}

	switch {
	case password != "":
		return []byte(password), nil
	case potentiallyPipedInput:
		// handle piped in passwords
		pwBytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("unable to get password from stdin: %w", err)
		}
		// be resilient to input that may have newline characters (in case someone is using echo without -n)
		cleanPw := strings.TrimRight(string(pwBytes), "\n")
		return []byte(cleanPw), nil
	case internal.IsTerminal():
		return cosign.GetPassFromTerm(false)
	}

	return nil, errors.New("no method available to fetch password")
}
