package parallel

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunBoundsConcurrencyAndCollectsEveryError(t *testing.T) {
	for _, limit := range []int{8, 16} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			items := make([]error, limit*3)
			for i := range items {
				items[i] = fmt.Errorf("item %d", i)
			}
			started := make(chan struct{}, len(items))
			release := make(chan struct{})
			var active, peak atomic.Int32
			done := make(chan error, 1)
			go func() {
				done <- Run(context.Background(), limit, items, func(_ context.Context, err error) error {
					n := active.Add(1)
					for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
					}
					started <- struct{}{}
					<-release
					active.Add(-1)
					return err
				})
			}()
			for range limit {
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					close(release)
					t.Fatal("workers did not start")
				}
			}
			close(release)
			err := <-done
			if peak.Load() != int32(limit) || active.Load() != 0 {
				t.Fatalf("peak=%d active=%d", peak.Load(), active.Load())
			}
			for _, want := range items {
				if !errors.Is(err, want) {
					t.Fatalf("missing error %v", want)
				}
			}
		})
	}
}

func TestRunCancellationWaitsForAdmittedWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, release := make(chan struct{}, 1), make(chan struct{})
	done := make(chan error, 1)
	want := errors.New("admitted work failed")
	go func() {
		done <- Run(ctx, 1, []int{1, 2, 3}, func(context.Context, int) error {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			return want
		})
	}()
	<-started
	cancel()
	select {
	case <-done:
		close(release)
		t.Fatal("returned before admitted work finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) || !errors.Is(err, want) {
		t.Fatalf("lost cancellation or callback error: %v", err)
	}
}
