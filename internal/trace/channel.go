package trace

import "context"

type ChannelSink struct {
	ctx context.Context
	ch  chan Event
}

func NewChannelSink(ctx context.Context, buffer int) *ChannelSink {
	if buffer < 1 {
		buffer = 1
	}
	return &ChannelSink{
		ctx: ctx,
		ch:  make(chan Event, buffer),
	}
}

func (s *ChannelSink) Emit(event Event) {
	select {
	case <-s.ctx.Done():
		return
	case s.ch <- event:
	}
}

func (s *ChannelSink) Events() <-chan Event {
	return s.ch
}

func (s *ChannelSink) Close() {
	close(s.ch)
}
