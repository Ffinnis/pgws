// Package parallel runs independent maintenance work with bounded concurrency.
package parallel

import (
	"context"
	"errors"
	"sync"
)

// Run waits for admitted work and joins every error, including cancellation.
// An item failure does not cancel siblings. Each call has its own worker limit;
// callers retain responsibility for per-item deadlines.
func Run[T any](ctx context.Context, limit int, items []T, fn func(context.Context, T) error) error {
	if limit < 1 {
		panic("parallel: nonpositive worker limit")
	}
	failures := make([]error, len(items)+1)
	jobs := make(chan int)
	var group sync.WaitGroup
	for range min(limit, len(items)) {
		group.Go(func() {
			for i := range jobs {
				failures[i] = fn(ctx, items[i])
			}
		})
	}
submit:
	for i := range items {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break submit
		}
	}
	close(jobs)
	group.Wait()
	failures[len(items)] = ctx.Err()
	return errors.Join(failures...)
}
