package collector

import "context"

// Collector is the standard interface for all state collectors.
// Collect returns the collected state and any error. Partial state (e.g. from
// independent sub-probes that succeeded before a failure) may be returned
// alongside a non-nil error — callers should use both values.
type Collector[T any] interface {
	Collect(ctx context.Context) (T, error)
}
