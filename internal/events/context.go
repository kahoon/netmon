package events

import "context"

type Sink interface {
	Handle(Event)
}

type hubKey struct{}
type sinkKey struct{}

func WithHub(ctx context.Context, hub *Hub) context.Context {
	if hub == nil {
		return ctx
	}
	return context.WithValue(ctx, hubKey{}, hub)
}

func HubFromContext(ctx context.Context) *Hub {
	if ctx == nil {
		return nil
	}
	hub, _ := ctx.Value(hubKey{}).(*Hub)
	return hub
}

func WithSink(ctx context.Context, sink Sink) context.Context {
	if sink == nil {
		return ctx
	}
	return context.WithValue(ctx, sinkKey{}, sink)
}

func SinkFromContext(ctx context.Context) Sink {
	if ctx == nil {
		return nil
	}
	sink, _ := ctx.Value(sinkKey{}).(Sink)
	return sink
}

func Emit(ctx context.Context, event Event) {
	if hub := HubFromContext(ctx); hub != nil {
		hub.Emit(event)
	}
	if sink := SinkFromContext(ctx); sink != nil {
		sink.Handle(event)
	}
}
