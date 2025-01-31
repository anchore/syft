package file

import (
	"errors"
	"io"
	"sync"

	gosync "github.com/anchore/go-sync"
)

type parallelWriter struct {
	executor gosync.Executor
	writers  []io.Writer
}

func newParallelWriter(executor gosync.Executor, writers ...io.Writer) *parallelWriter {
	return &parallelWriter{
		executor: executor,
		writers:  writers,
	}
}

func (w *parallelWriter) Write(p []byte) (int, error) {
	errs := gosync.List[error]{}
	wg := sync.WaitGroup{}
	wg.Add(len(w.writers))
	for _, writer := range w.writers {
		w.executor.Execute(func() {
			defer wg.Done()
			_, err := writer.Write(p)
			if err != nil {
				errs.Add(err)
			}
		})
	}
	wg.Wait()
	if errs.Len() > 0 {
		return 0, errors.Join(errs.Values()...)
	}
	return len(p), nil
}

var _ io.Writer = (*parallelWriter)(nil)
