package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type PiHoleClient interface {
	GetBlocking(ctx context.Context) (string, error)
	GetVersions(ctx context.Context) (core string, web string, ftl string, err error)
	GetUpstreams(ctx context.Context) ([]string, error)
	GetSummary(ctx context.Context) (PiHoleSummary, error)
}

type PiHoleSummary struct {
	QueriesTotal   uint64
	QueriesBlocked uint64
	CacheHits      uint64
	Forwarded      uint64
	ClientsActive  uint64
	GravityUpdated time.Time
	DomainsBlocked uint64
}

type piHoleAPIClient struct {
	baseURL  string
	password string
	client   *http.Client

	mu       sync.Mutex
	sid      string
	validity time.Time
}

func NewPiHoleClient(baseURL, password string, client *http.Client) PiHoleClient {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &piHoleAPIClient{
		baseURL:  strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		password: password,
		client:   client,
	}
}

func (c *piHoleAPIClient) GetBlocking(ctx context.Context) (string, error) {
	var payload map[string]any
	if err := c.getJSON(ctx, "/dns/blocking", &payload); err != nil {
		return "", err
	}

	switch value := payload["blocking"].(type) {
	case string:
		return strings.ToLower(strings.TrimSpace(value)), nil
	case bool:
		if value {
			return "enabled", nil
		}
		return "disabled", nil
	default:
		return "", fmt.Errorf("missing blocking status in response")
	}
}

func (c *piHoleAPIClient) GetVersions(ctx context.Context) (core string, web string, ftl string, err error) {
	var payload map[string]any
	if err := c.getJSON(ctx, "/info/version", &payload); err != nil {
		return "", "", "", err
	}

	core = firstStringPath(payload, []string{"version", "core", "local"}, []string{"version", "core", "version"})
	web = firstStringPath(payload, []string{"version", "web", "local"}, []string{"version", "web", "version"})
	ftl = firstStringPath(payload, []string{"version", "ftl", "local"}, []string{"version", "ftl", "version"})
	if core == "" && web == "" && ftl == "" {
		return "", "", "", fmt.Errorf("missing version data in response")
	}
	return core, web, ftl, nil
}

func (c *piHoleAPIClient) GetUpstreams(ctx context.Context) ([]string, error) {
	var payload map[string]any
	if err := c.getJSON(ctx, "/config", &payload); err != nil {
		return nil, err
	}

	upstreams := firstStringSlicePath(payload,
		[]string{"config", "dns", "upstreams"},
		[]string{"dns", "upstreams"},
	)
	if len(upstreams) == 0 {
		return nil, fmt.Errorf("missing upstream configuration in response")
	}
	return upstreams, nil
}

func (c *piHoleAPIClient) GetSummary(ctx context.Context) (PiHoleSummary, error) {
	var payload map[string]any
	if err := c.getJSON(ctx, "/stats/summary", &payload); err != nil {
		return PiHoleSummary{}, err
	}

	updated := int64ValueAt(payload, "gravity", "last_update")
	summary := PiHoleSummary{
		QueriesTotal:   uint64ValueAt(payload, "queries", "total"),
		QueriesBlocked: uint64ValueAt(payload, "queries", "blocked"),
		CacheHits:      uint64ValueAt(payload, "queries", "cached"),
		Forwarded:      uint64ValueAt(payload, "queries", "forwarded"),
		ClientsActive:  uint64ValueAt(payload, "clients", "active"),
		DomainsBlocked: uint64ValueAt(payload, "gravity", "domains_being_blocked"),
	}
	if updated > 0 {
		summary.GravityUpdated = time.Unix(updated, 0).Local()
	}
	return summary, nil
}

func (c *piHoleAPIClient) getJSON(ctx context.Context, path string, out any) error {
	if err := c.ensureSession(ctx); err != nil {
		return err
	}

	if err := c.doJSON(ctx, http.MethodGet, path, nil, out); err != nil {
		if !isUnauthorizedError(err) || strings.TrimSpace(c.password) == "" {
			return err
		}
		c.invalidate()
		if err := c.ensureSession(ctx); err != nil {
			return err
		}
		return c.doJSON(ctx, http.MethodGet, path, nil, out)
	}
	return nil
}

func (c *piHoleAPIClient) ensureSession(ctx context.Context) error {
	if strings.TrimSpace(c.password) == "" {
		return nil
	}

	c.mu.Lock()
	sid := c.sid
	validity := c.validity
	c.mu.Unlock()

	if sid != "" && time.Until(validity) > time.Minute {
		return nil
	}

	var resp struct {
		Session struct {
			Valid    bool   `json:"valid"`
			SID      string `json:"sid"`
			Validity int64  `json:"validity"`
		} `json:"session"`
	}

	if err := c.doJSON(ctx, http.MethodPost, "/auth", map[string]string{
		"password": c.password,
	}, &resp); err != nil {
		return err
	}
	if !resp.Session.Valid {
		return fmt.Errorf("Pi-hole authentication failed")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.sid = resp.Session.SID
	if resp.Session.Validity > 0 {
		c.validity = time.Now().Add(time.Duration(resp.Session.Validity) * time.Second)
	} else {
		c.validity = time.Time{}
	}
	return nil
}

func (c *piHoleAPIClient) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sid = ""
	c.validity = time.Time{}
}

func (c *piHoleAPIClient) doJSON(ctx context.Context, method, path string, payload any, out any) error {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.mu.Lock()
	if c.sid != "" {
		req.Header.Set("X-FTL-SID", c.sid)
	}
	c.mu.Unlock()

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodePiHoleError(resp)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type piHoleAPIError struct {
	Code    int
	Message string
}

func (e piHoleAPIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("Pi-hole API returned HTTP %d", e.Code)
	}
	return fmt.Sprintf("Pi-hole API returned HTTP %d: %s", e.Code, e.Message)
}

func isUnauthorizedError(err error) bool {
	var apiErr piHoleAPIError
	return errors.As(err, &apiErr) && apiErr.Code == http.StatusUnauthorized
}

func decodePiHoleError(resp *http.Response) error {
	var payload struct {
		Error struct {
			Message string `json:"message"`
			Hint    any    `json:"hint"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return piHoleAPIError{Code: resp.StatusCode, Message: resp.Status}
	}

	message := strings.TrimSpace(payload.Error.Message)
	if hint := strings.TrimSpace(fmt.Sprint(payload.Error.Hint)); hint != "" && hint != "<nil>" && hint != "null" {
		if message != "" {
			message += " (" + hint + ")"
		} else {
			message = hint
		}
	}
	return piHoleAPIError{Code: resp.StatusCode, Message: message}
}

func firstStringPath(payload map[string]any, paths ...[]string) string {
	for _, path := range paths {
		if value := stringValueAt(payload, path...); value != "" {
			return value
		}
	}
	return ""
}

func firstStringSlicePath(payload map[string]any, paths ...[]string) []string {
	for _, path := range paths {
		if values := stringSliceValueAt(payload, path...); len(values) > 0 {
			return values
		}
	}
	return nil
}

func stringValueAt(payload map[string]any, path ...string) string {
	value := valueAt(payload, path...)
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	default:
		return ""
	}
}

func stringSliceValueAt(payload map[string]any, path ...string) []string {
	value := valueAt(payload, path...)
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func uint64ValueAt(payload map[string]any, path ...string) uint64 {
	value := valueAt(payload, path...)
	switch v := value.(type) {
	case float64:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case int64:
		if v < 0 {
			return 0
		}
		return uint64(v)
	default:
		return 0
	}
}

func int64ValueAt(payload map[string]any, path ...string) int64 {
	value := valueAt(payload, path...)
	switch v := value.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	default:
		return 0
	}
}

func valueAt(payload map[string]any, path ...string) any {
	var current any = payload
	for _, key := range path {
		next, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = next[key]
	}
	return current
}
