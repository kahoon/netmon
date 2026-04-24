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

type alertHistory struct {
	mu       sync.Mutex
	interval time.Duration
	attempts *ring.Queue[AlertAttempt]
}

func newAlertHistory(interval time.Duration) *alertHistory {
	return &alertHistory{
		interval: interval,
		attempts: ring.New[AlertAttempt](ring.WithMinCapacity[AlertAttempt](alertHistoryCapacity)),
	}
}

func (h *alertHistory) Record(attempt AlertAttempt) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.pruneLocked(attempt.At)
	if h.interval == 0 {
		return
	}

	attempt.Title = truncateAlertField(attempt.Title)
	attempt.Reason = truncateAlertField(attempt.Reason)
	attempt.Summary = truncateAlertField(attempt.Summary)
	attempt.DeliveryError = truncateAlertField(attempt.DeliveryError)
	h.attempts.Push(attempt)
}

func (h *alertHistory) Snapshot(now time.Time) Diagnostics {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.pruneLocked(now)

	alerts := make([]AlertAttempt, 0, h.attempts.Len())
	for attempt := range h.attempts.All() {
		alerts = append(alerts, *attempt)
	}
	return Diagnostics{
		AlertHistoryInterval: h.interval,
		Alerts:               alerts,
	}
}

func (h *alertHistory) SetInterval(interval time.Duration, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.interval = interval
	h.pruneLocked(now)
}

func (h *alertHistory) pruneLocked(now time.Time) {
	if h.interval == 0 {
		for {
			if _, ok := h.attempts.Pop(); !ok {
				return
			}
		}
	}

	cutoff := now.Add(-h.interval)
	for {
		attempt, ok := h.attempts.Peek()
		if !ok || !attempt.At.Before(cutoff) {
			return
		}
		h.attempts.Pop()
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
