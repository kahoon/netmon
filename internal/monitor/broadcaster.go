package monitor

import (
	"sync"

	"github.com/kahoon/ring"
)

type overflowPolicy int

const (
	overflowReplace overflowPolicy = iota
	overflowDropOldest
)

type broadcaster[T any] struct {
	mu       sync.Mutex
	counter  uint64
	subs     map[uint64]chan T
	buffer   int
	clone    func(T) T
	overflow overflowPolicy
	history  *ring.Queue[T]
}

type broadcasterSubscription[T any] struct {
	updates <-chan T
	close   func()
}

func (s *broadcasterSubscription[T]) Updates() <-chan T {
	return s.updates
}

func (s *broadcasterSubscription[T]) Close() {
	if s.close != nil {
		s.close()
	}
}

type BroadcasterOption[T any] func(*broadcasterOptions[T])

type broadcasterOptions[T any] struct {
	buffer          int
	clone           func(T) T
	overflow        overflowPolicy
	historyCapacity uint64
}

func newBroadcaster[T any](opt ...BroadcasterOption[T]) *broadcaster[T] {
	cfg := broadcasterOptions[T]{
		buffer:   1,
		overflow: overflowReplace,
	}
	for _, o := range opt {
		o(&cfg)
	}

	b := &broadcaster[T]{
		subs:     make(map[uint64]chan T),
		buffer:   cfg.buffer,
		clone:    cfg.clone,
		overflow: cfg.overflow,
	}
	if cfg.historyCapacity > 0 {
		b.history = ring.New[T](ring.WithMinCapacity[T](cfg.historyCapacity))
	}
	return b
}

func withClone[T any](clone func(T) T) BroadcasterOption[T] {
	return func(cfg *broadcasterOptions[T]) {
		cfg.clone = clone
	}
}

func withBuffer[T any](buffer int) BroadcasterOption[T] {
	return func(cfg *broadcasterOptions[T]) {
		cfg.buffer = buffer
	}
}

func withOverflow[T any](policy overflowPolicy) BroadcasterOption[T] {
	return func(cfg *broadcasterOptions[T]) {
		cfg.overflow = policy
	}
}

func withHistory[T any](capacity uint64) BroadcasterOption[T] {
	return func(cfg *broadcasterOptions[T]) {
		cfg.historyCapacity = capacity
	}
}

func (b *broadcaster[T]) Subscribe(initial ...T) *broadcasterSubscription[T] {
	b.mu.Lock()
	defer b.mu.Unlock()

	id := b.counter
	b.counter++

	buffer := 0
	if b.history != nil {
		buffer = b.history.Len()
	}
	capacity := max(b.buffer, len(initial)+buffer)
	ch := make(chan T, capacity)
	if b.history != nil {
		for item := range b.history.All() {
			b.seed(ch, *item)
		}
	}
	for _, item := range initial {
		b.seed(ch, item)
	}
	b.subs[id] = ch

	return &broadcasterSubscription[T]{
		updates: ch,
		close: func() {
			b.mu.Lock()
			delete(b.subs, id)
			b.mu.Unlock()
		},
	}
}

func (b *broadcaster[T]) Broadcast(value T) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Store the value in the history before broadcasting to ensure that new
	// subscribers receive the most recent value.
	if b.history != nil {
		b.history.Push(b.copy(value))
	}
	// Broadcast the value to all subscribers. The broadcasting logic will handle
	// any overflow according to the configured policy.
	for _, ch := range b.subs {
		b.live(ch, value)
	}
}

func (b *broadcaster[T]) seed(ch chan T, value T) {
	ch <- b.copy(value)
}

func (b *broadcaster[T]) live(ch chan T, value T) {
	next := b.copy(value)
	// Attempt to send the value to the subscriber's channel. If the channel is full,
	// handle the overflow according to the configured policy.
	select {
	case ch <- next:
	default:
		switch b.overflow {
		// If the policy is to drop the oldest value, attempt to read from the channel
		// to make room for the new value.
		case overflowDropOldest:
			select {
			case <-ch:
			default:
			}
		// If the policy is to replace the value, drain the channel until it's empty
		// as the latest value is the most relevant.
		case overflowReplace:
			for {
				select {
				case <-ch:
				default:
					goto drained
				}
			}
		}
	drained:
		select {
		case ch <- next:
		default:
		}
	}
}

func (b *broadcaster[T]) copy(value T) T {
	if b.clone == nil {
		return value
	}
	return b.clone(value)
}
