package monitor

import (
	"sync"

	"github.com/kahoon/netmon/internal/events"
)

type Subscription[T any] interface {
	Updates() <-chan T
	Close()
}

type subscription[T any] struct {
	updates chan T
	done    chan struct{}
	close   func()
	once    sync.Once
}

func (s *subscription[T]) Updates() <-chan T {
	return s.updates
}

func (s *subscription[T]) Close() {
	s.once.Do(func() {
		close(s.done)
		if s.close != nil {
			s.close()
		}
	})
}

func newSubscription[T any](sub *events.Subscription, buffer int, translate func(events.Event) (T, bool)) Subscription[T] {
	out := &subscription[T]{
		updates: make(chan T, buffer),
		done:    make(chan struct{}),
		close:   sub.Close,
	}

	go func() {
		defer close(out.updates)

		for {
			select {
			case <-out.done:
				return
			case event, ok := <-sub.Events():
				if !ok {
					return
				}

				value, ok := translate(event)
				if !ok {
					continue
				}

				select {
				case out.updates <- value:
				case <-out.done:
					return
				}
			}
		}
	}()

	return out
}
