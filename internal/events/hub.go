package events

import (
	"fmt"
	"sync"

	"github.com/kahoon/ring"
)

type Filter func(Event) bool

type FeedConfig struct {
	Name    string
	Filter  Filter
	Buffer  int
	History uint64
}

type subscriptionOptions struct {
	initial []Event
	replay  bool
}

type SubscriptionOption func(*subscriptionOptions)

type Hub struct {
	mu     sync.Mutex
	nextID uint64
	feeds  map[string]*feed
}

type feed struct {
	filter  Filter
	buffer  int
	history *ring.Queue[Event]
	subs    map[uint64]*subscriber
}

type subscriber struct {
	ch chan Event
}

type Subscription struct {
	updates <-chan Event
	close   func()
}

func NewHub(feedConfigs ...FeedConfig) *Hub {
	hub := &Hub{
		feeds: make(map[string]*feed, len(feedConfigs)),
	}
	for _, cfg := range feedConfigs {
		if cfg.Name == "" {
			panic("events: feed name is required")
		}
		if _, exists := hub.feeds[cfg.Name]; exists {
			panic(fmt.Sprintf("events: duplicate feed %q", cfg.Name))
		}

		f := &feed{
			filter: cfg.Filter,
			buffer: max(cfg.Buffer, 1),
			subs:   make(map[uint64]*subscriber),
		}
		if cfg.History > 0 {
			f.history = ring.New[Event](ring.WithMinCapacity[Event](cfg.History))
		}
		hub.feeds[cfg.Name] = f
	}
	return hub
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

	for _, feed := range h.feeds {
		if !matches(feed.filter, event) {
			continue
		}
		if feed.history != nil {
			feed.history.Push(event)
		}
		for _, sub := range feed.subs {
			live(sub.ch, event)
		}
	}
}

func (h *Hub) Subscribe(feedName string, opts ...SubscriptionOption) *Subscription {
	cfg := subscriptionOptions{replay: true}
	for _, opt := range opts {
		opt(&cfg)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	feed, ok := h.feeds[feedName]
	if !ok {
		panic(fmt.Sprintf("events: unknown feed %q", feedName))
	}

	var seed []Event
	if cfg.replay {
		seed = feed.seedLocked()
	}
	capacity := max(feed.buffer, len(seed)+len(cfg.initial))
	ch := make(chan Event, capacity)
	for _, event := range seed {
		ch <- event
	}
	for _, event := range cfg.initial {
		ch <- event
	}

	id := h.nextID
	h.nextID++
	feed.subs[id] = &subscriber{ch: ch}

	var once sync.Once
	return &Subscription{
		updates: ch,
		close: func() {
			once.Do(func() {
				h.mu.Lock()
				sub, ok := feed.subs[id]
				if ok {
					delete(feed.subs, id)
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

func (f *feed) seedLocked() []Event {
	if f.history == nil || f.history.Len() == 0 {
		return nil
	}

	seed := make([]Event, 0, f.history.Len())
	for event := range f.history.All() {
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
