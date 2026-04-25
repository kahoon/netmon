package monitor

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kahoon/netmon/internal/model"
	"github.com/kahoon/ring"
)

const (
	alertHistoryCapacity = 128
	alertFieldLimit      = 512
)

type AlertDeliveryStatus string

const (
	AlertDelivered    AlertDeliveryStatus = "delivered"
	AlertNotDelivered AlertDeliveryStatus = "not_delivered"
)

type AlertAttempt struct {
	At             time.Time
	DeliveryStatus AlertDeliveryStatus
	Severity       model.Severity
	Title          string
	Reason         string
	Summary        string
	DeliveryError  string
}

type Diagnostics struct {
	AlertHistoryInterval time.Duration
	Alerts               []AlertAttempt
}

type alerts struct {
	mu       sync.Mutex
	interval time.Duration
	attempts *ring.Queue[AlertAttempt]
}

func newAlerts(interval time.Duration) *alerts {
	return &alerts{
		interval: interval,
		attempts: ring.New[AlertAttempt](ring.WithMinCapacity[AlertAttempt](alertHistoryCapacity)),
	}
}

func (a *alerts) Record(attempt AlertAttempt) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.pruneLocked(attempt.At)
	if a.interval == 0 {
		return
	}

	attempt.Title = truncateAlertField(attempt.Title)
	attempt.Reason = truncateAlertField(attempt.Reason)
	attempt.Summary = truncateAlertField(attempt.Summary)
	attempt.DeliveryError = truncateAlertField(attempt.DeliveryError)
	a.attempts.Push(attempt)
}

func (a *alerts) Snapshot(now time.Time) Diagnostics {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.pruneLocked(now)

	alerts := make([]AlertAttempt, 0, a.attempts.Len())
	for attempt := range a.attempts.All() {
		alerts = append(alerts, *attempt)
	}
	return Diagnostics{
		AlertHistoryInterval: a.interval,
		Alerts:               alerts,
	}
}

func (a *alerts) SetInterval(interval time.Duration, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.interval = interval
	a.pruneLocked(now)
}

func (a *alerts) pruneLocked(now time.Time) {
	if a.interval == 0 {
		for {
			if _, ok := a.attempts.Pop(); !ok {
				return
			}
		}
	}

	cutoff := now.Add(-a.interval)
	for {
		attempt, ok := a.attempts.Peek()
		if !ok || !attempt.At.Before(cutoff) {
			return
		}
		a.attempts.Pop()
	}
}

func truncateAlertField(value string) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) <= alertFieldLimit {
		return value
	}
	return string(runes[:alertFieldLimit-1]) + "…"
}

func alertSummary(lines []string) string {
	switch len(lines) {
	case 0:
		return ""
	case 1:
		return lines[0]
	default:
		return fmt.Sprintf("%s (+%d more)", lines[0], len(lines)-1)
	}
}
