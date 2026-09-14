package javascript

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"
)

// The remote license lookup used to run inline in each package constructor, so a
// lockfile with N entries made N strictly sequential registry round-trips. These
// tests pin the concurrency behavior of the prefetch added for issue #5193.

func TestNpmLicensePrefetchIssuesAllRequests(t *testing.T) {
	mux, url, teardown := setupNpmRegistry()
	defer teardown()

	var mu sync.Mutex
	requested := make(map[string]int)
	mux.HandleFunc("/pkg-a/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested["pkg-a"]++
		mu.Unlock()
		w.Write([]byte(`{"license":"MIT"}`))
	})
	mux.HandleFunc("/pkg-b/2.0.0", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested["pkg-b"]++
		mu.Unlock()
		w.Write([]byte(`{"license":"Apache-2.0"}`))
	})

	prefetchNpmLicenses(context.Background(), CatalogerConfig{SearchRemoteLicenses: true, NPMBaseURL: url}, [][2]string{
		{"pkg-a", "1.0.0"},
		{"pkg-b", "2.0.0"},
	})

	if requested["pkg-a"] != 1 || requested["pkg-b"] != 1 {
		t.Fatalf("expected exactly one request per package, got %v", requested)
	}
}

func TestNpmLicensePrefetchSkipsWhenDisabled(t *testing.T) {
	mux, url, teardown := setupNpmRegistry()
	defer teardown()

	requests := 0
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Write([]byte(`{"license":"MIT"}`))
	})

	prefetchNpmLicenses(context.Background(), CatalogerConfig{NPMBaseURL: url}, [][2]string{{"pkg-a", "1.0.0"}})

	if requests != 0 {
		t.Fatalf("expected no requests when SearchRemoteLicenses is false, got %d", requests)
	}
}

func TestNpmLicensePrefetchIsConcurrent(t *testing.T) {
	mux, url, teardown := setupNpmRegistry()
	defer teardown()

	const n = 4
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(n)
	for i := 0; i < n; i++ {
		path := "/" + concurrencyTestPkg(i) + "/1.0.0"
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			started.Done()
			// hold every request open until all n have arrived: only passes if
			// the client issues them concurrently
			select {
			case <-release:
			case <-time.After(5 * time.Second):
			}
			w.Write([]byte(`{"license":"MIT"}`))
		})
	}

	go func() {
		started.Wait()
		close(release)
	}()

	pairs := make([][2]string, 0, n)
	for i := 0; i < n; i++ {
		pairs = append(pairs, [2]string{concurrencyTestPkg(i), "1.0.0"})
	}

	done := make(chan struct{})
	go func() {
		prefetchNpmLicenses(context.Background(), CatalogerConfig{SearchRemoteLicenses: true, NPMBaseURL: url}, pairs)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("prefetch did not complete; requests appear to be serialized")
	}
}

func TestNpmLicensePrefetchContinuesOnError(t *testing.T) {
	mux, url, teardown := setupNpmRegistry()
	defer teardown()

	var mu sync.Mutex
	goodRequests := 0
	mux.HandleFunc("/bad-pkg/1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	mux.HandleFunc("/good-pkg/1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		goodRequests++
		mu.Unlock()
		w.Write([]byte(`{"license":"MIT"}`))
	})

	prefetchNpmLicenses(context.Background(), CatalogerConfig{SearchRemoteLicenses: true, NPMBaseURL: url}, [][2]string{
		{"bad-pkg", "1.0.0"},
		{"good-pkg", "1.0.0"},
	})

	if goodRequests != 1 {
		t.Fatalf("expected a failed lookup not to prevent later lookups, good-pkg requested %d times", goodRequests)
	}
}

// concurrencyTestPkg gives each test case a distinct, URL-safe package name.
func concurrencyTestPkg(i int) string {
	return "concurrent-pkg-" + string(rune('a'+i)) + "-x"
}
