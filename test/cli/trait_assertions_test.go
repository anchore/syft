package cli

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/acarl005/stripansi"
)

type traitAssertion func(tb testing.TB, stdout, stderr string, rc int)

func assertJsonReport(tb testing.TB, stdout, _ string, _ int) {
	tb.Helper()
	var data interface{}

	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		tb.Errorf("expected to find a JSON report, but was unmarshalable: %+v", err)
	}
}

func assertTableReport(tb testing.TB, stdout, _ string, _ int) {
	tb.Helper()
	if !strings.Contains(stdout, "NAME") || !strings.Contains(stdout, "VERSION") || !strings.Contains(stdout, "TYPE") {
		tb.Errorf("expected to find a table report, but did not")
	}
}

//func assertScope(scope source.Scope) traitAssertion {
//	return func(tb testing.TB, stdout, stderr string, rc int) {
//		tb.Helper()
//		// we can only verify source with the json report
//		assertJsonReport(tb, stdout, stderr, rc)
//
//		if !strings.Contains(stdout, fmt.Sprintf(`"scope": "%s"`, scope.String())) {
//			tb.Errorf("JSON report did not indicate the %q scope", scope)
//		}
//	}
//}

func assertLoggingLevel(level string) traitAssertion {
	// match examples:
	//  "[0000]  INFO"
	//  "[0012] DEBUG"
	logPattern := regexp.MustCompile(`(?m)^\[\d\d\d\d\]\s+` + strings.ToUpper(level))
	return func(tb testing.TB, _, stderr string, _ int) {
		tb.Helper()
		if !logPattern.MatchString(stripansi.Strip(stderr)) {
			tb.Errorf("output did not indicate the %q logging level", level)
		}
	}
}

func assertNotInOutput(data string) traitAssertion {
	return func(tb testing.TB, stdout, stderr string, _ int) {
		tb.Helper()
		if strings.Contains(stripansi.Strip(stderr), data) {
			tb.Errorf("data=%q was found in stderr, but should not have been there", data)
		}
		if strings.Contains(stripansi.Strip(stdout), data) {
			tb.Errorf("data=%q was found in stdout, but should not have been there", data)
		}
	}
}

func assertInOutput(data string) traitAssertion {
	return func(tb testing.TB, stdout, stderr string, _ int) {
		tb.Helper()
		if !strings.Contains(stripansi.Strip(stderr), data) && !strings.Contains(stripansi.Strip(stdout), data) {
			tb.Errorf("data=%q was NOT found in any output, but should have been there", data)
		}
	}
}

func assertStdoutLengthGreaterThan(length uint) traitAssertion {
	return func(tb testing.TB, stdout, _ string, _ int) {
		tb.Helper()
		if uint(len(stdout)) < length {
			tb.Errorf("not enough output (expected at least %d, got %d)", length, len(stdout))
		}
	}
}

func assertPackageCount(length uint) traitAssertion {
	return func(tb testing.TB, stdout, _ string, _ int) {
		tb.Helper()
		type partial struct {
			Artifacts []interface{} `json:"artifacts"`
		}
		var data partial

		if err := json.Unmarshal([]byte(stdout), &data); err != nil {
			tb.Errorf("expected to find a JSON report, but was unmarshalable: %+v", err)
		}

		if uint(len(data.Artifacts)) != length {
			tb.Errorf("expected package count of %d, but found %d", length, len(data.Artifacts))

		}
	}
}

func assertFailingReturnCode(tb testing.TB, _, _ string, rc int) {
	tb.Helper()
	if rc == 0 {
		tb.Errorf("expected a failure but got rc=%d", rc)
	}
}

func assertSuccessfulReturnCode(tb testing.TB, _, _ string, rc int) {
	tb.Helper()
	if rc != 0 {
		tb.Errorf("expected no failure but got rc=%d", rc)
	}
}

func assertFileExists(file string) traitAssertion {
	return func(tb testing.TB, _, _ string, _ int) {
		tb.Helper()
		if _, err := os.Stat(file); err != nil {
			tb.Errorf("expected file to exist %s", file)
		}
	}
}
