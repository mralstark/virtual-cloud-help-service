package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
)

const defaultAttemptTimeout = 12 * time.Second
const defaultOverallTimeout = 60 * time.Second

var sourceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type Client struct {
	HTTP        *http.Client
	RootKey     ed25519.PublicKey
	Now         func() time.Time
	MaxAttempts int
	// AttemptTimeout bounds each mirror independently even when a custom HTTP
	// client has no timeout.
	AttemptTimeout time.Duration
	// OverallTimeout is shared fairly across all selected mirrors. A shorter caller
	// deadline always wins.
	OverallTimeout time.Duration
}

type Result struct {
	Document manifest.Document
	Trusted  manifest.TrustedState
	SourceID string
}

// Fetch tries signed discovery mirrors sequentially. Parallel probing is avoided on
// purpose: several observed DPI policies penalize bursts of similar TLS connections.
func (client Client) Fetch(ctx context.Context, sources []manifest.DiscoveryEndpoint, trusted manifest.TrustedState) (Result, error) {
	if len(client.RootKey) != ed25519.PublicKeySize {
		return Result{}, errors.New("discovery: a pinned offline root public key is required")
	}
	rootKey := append(ed25519.PublicKey(nil), client.RootKey...)
	if len(sources) == 0 || len(sources) > 16 {
		return Result{}, errors.New("discovery: sources must contain between 1 and 16 entries")
	}
	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = DefaultHTTPClient()
	}
	now := client.Now
	if now == nil {
		now = time.Now
	}
	maxAttempts := client.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = len(sources)
	}
	if maxAttempts < 1 || maxAttempts > 16 {
		return Result{}, errors.New("discovery: max attempts must be between 1 and 16")
	}
	attemptTimeout := client.AttemptTimeout
	if attemptTimeout == 0 {
		attemptTimeout = defaultAttemptTimeout
	}
	if attemptTimeout < time.Second || attemptTimeout > 30*time.Second {
		return Result{}, errors.New("discovery: attempt timeout must be between 1s and 30s")
	}
	overallTimeout := client.OverallTimeout
	if overallTimeout == 0 {
		overallTimeout = defaultOverallTimeout
	}
	if overallTimeout < 5*time.Second || overallTimeout > 5*time.Minute {
		return Result{}, errors.New("discovery: overall timeout must be between 5s and 5m")
	}
	seenIDs := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		if !sourceIDPattern.MatchString(source.ID) {
			return Result{}, fmt.Errorf("discovery: invalid source ID %q", source.ID)
		}
		if source.Priority == 0 || source.Priority > 1000 {
			return Result{}, fmt.Errorf("discovery: source %q priority must be between 1 and 1000", source.ID)
		}
		if _, exists := seenIDs[source.ID]; exists {
			return Result{}, fmt.Errorf("discovery: duplicate source ID %q", source.ID)
		}
		seenIDs[source.ID] = struct{}{}
		if _, err := validateSource(source); err != nil {
			return Result{}, fmt.Errorf("discovery: source %q: %w", source.ID, err)
		}
	}

	ordered := append([]manifest.DiscoveryEndpoint(nil), sources...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Priority == ordered[j].Priority {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].Priority < ordered[j].Priority
	})
	if len(ordered) > maxAttempts {
		ordered = ordered[:maxAttempts]
	}

	fetchContext, cancelFetch := context.WithTimeout(ctx, overallTimeout)
	defer cancelFetch()
	var failures []error
	for index, source := range ordered {
		attemptBudget := attemptTimeout
		if deadline, exists := fetchContext.Deadline(); exists {
			remainingBudget := time.Until(deadline)
			fairShare := remainingBudget / time.Duration(len(ordered)-index)
			if fairShare < attemptBudget {
				attemptBudget = fairShare
			}
		}
		if attemptBudget <= 0 {
			break
		}
		attemptContext, cancel := context.WithTimeout(fetchContext, attemptBudget)
		document, nextState, err := client.fetchOne(attemptContext, httpClient, rootKey, source, now(), trusted)
		cancel()
		if err == nil {
			return Result{Document: document, Trusted: nextState, SourceID: source.ID}, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", source.ID, err))
		if fetchContext.Err() != nil {
			break
		}
	}
	if len(failures) == 0 {
		return Result{}, errors.New("discovery: no sources were provided")
	}
	return Result{}, fmt.Errorf("discovery: all attempted sources failed: %w", errors.Join(failures...))
}

func (client Client) fetchOne(ctx context.Context, httpClient *http.Client, rootKey ed25519.PublicKey, source manifest.DiscoveryEndpoint, now time.Time, trusted manifest.TrustedState) (manifest.Document, manifest.TrustedState, error) {
	parsed, err := validateSource(source)
	if err != nil {
		return manifest.Document{}, trusted, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return manifest.Document{}, trusted, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "vchs-discovery/1")
	requestClient := *httpClient
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := requestClient.Do(request)
	if err != nil {
		return manifest.Document{}, trusted, fmt.Errorf("request manifest: %w", err)
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL.Scheme != "https" || !strings.EqualFold(response.Request.URL.Host, parsed.Host) {
		return manifest.Document{}, trusted, errors.New("redirected discovery response changed origin")
	}
	if response.StatusCode != http.StatusOK {
		return manifest.Document{}, trusted, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	contentType := response.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return manifest.Document{}, trusted, fmt.Errorf("unexpected Content-Type %q", contentType)
	}
	envelope, err := manifest.DecodeEnvelope(response.Body)
	if err != nil {
		return manifest.Document{}, trusted, err
	}
	document, nextState, err := manifest.Verify(envelope, rootKey, now, trusted)
	if err != nil {
		return manifest.Document{}, trusted, err
	}
	return document, nextState, nil
}

func validateSource(source manifest.DiscoveryEndpoint) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(source.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("source must be an HTTPS URL without credentials, query, or fragment")
	}
	return parsed, nil
}

func DefaultHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		MaxConnsPerHost:       2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
