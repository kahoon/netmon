package events

import (
	"sync"

	"github.com/kahoon/ring"
)

type Filter func(Event) bool

type Option func(*hubOptions)

type hubOptions struct {
	buffer          int
	historyCapacity uint64
}

type subscriptionOptions struct {
	filter  Filter
	initial []Event
	replay  bool
}

type SubscriptionOption func(*subscriptionOptions)

type Hub struct {
	mu      sync.Mutex
	nextID  uint64
	subs    map[uint64]*subscriber
	buffer  int
	history *ring.Queue[Event]
}

type subscriber struct {
	filter Filter
	ch     chan Event
}

type Subscription struct {
	updates <-chan Event
	close   func()
}

func NewHub(opts ...Option) *Hub {
	cfg := hubOptions{buffer: 1}
	for _, opt := range opts {
		opt(&cfg)
	}

	hub := &Hub{
		subs:   make(map[uint64]*subscriber),
		buffer: cfg.buffer,
	}
	if cfg.historyCapacity > 0 {
		hub.history = ring.New[Event](ring.WithMinCapacity[Event](cfg.historyCapacity))
	}
	return hub
}

func WithBuffer(buffer int) Option {
	return func(cfg *hubOptions) {
		cfg.buffer = buffer
	}
}

func WithHistory(capacity uint64) Option {
	return func(cfg *hubOptions) {
		cfg.historyCapacity = capacity
	}
}

func WithFilter(filter Filter) SubscriptionOption {
	return func(cfg *subscriptionOptions) {
		cfg.filter = filter
	}
}

func WithInitial(initial ...Event) SubscriptionOption {
	return func(cfg *subscriptionOptions) {
		cfg.initial = append(cfg.initial, initial...)
	}
}

func WithoutReplay() SubscriptionOption {
	return func(cfg *subscriptionOptions) {
		cfg.replay = false
	}
}

func (h *Hub) Emit(event Event) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.history != nil {
		h.history.Push(event)
	}
	for _, sub := range h.subs {
		if !matches(sub.filter, event) {
			continue
		}
		live(sub.ch, event)
	}
}

func (h *Hub) Subscribe(opts ...SubscriptionOption) *Subscription {
	cfg := subscriptionOptions{replay: true}
	for _, opt := range opts {
		opt(&cfg)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	var seed []Event
	if cfg.replay {
		seed = h.seedLocked(cfg.filter)
	}
	capacity := max(h.buffer, len(seed)+len(cfg.initial))
	ch := make(chan Event, capacity)
	for _, event := range seed {
		ch <- event
	}
	for _, event := range cfg.initial {
		if !matches(cfg.filter, event) {
			continue
		}
		ch <- event
	}

	id := h.nextID
	h.nextID++
	h.subs[id] = &subscriber{
		filter: cfg.filter,
		ch:     ch,
	}

	var once sync.Once
	return &Subscription{
		updates: ch,
		close: func() {
			once.Do(func() {
				h.mu.Lock()
				sub, ok := h.subs[id]
				if ok {
					delete(h.subs, id)
					close(sub.ch)
				}
				h.mu.Unlock()
			})
		},
	}
}

func (s *Subscription) Events() <-chan Event {
	return s.updates
}

func (s *Subscription) Close() {
	if s.close != nil {
		s.close()
	}
}

func (h *Hub) seedLocked(filter Filter) []Event {
	if h.history == nil || h.history.Len() == 0 {
		return nil
	}

	seed := make([]Event, 0, h.history.Len())
	for event := range h.history.All() {
		if !matches(filter, *event) {
			continue
		}
		seed = append(seed, *event)
	}
	return seed
}

func matches(filter Filter, event Event) bool {
	if filter == nil {
		return true
	}
	return filter(event)
}

func live(ch chan Event, event Event) {
	select {
	case ch <- event:
	default:
		select {
		case <-ch:
		default:
		}
		select {
		case ch <- event:
		default:
		}
	}
}
