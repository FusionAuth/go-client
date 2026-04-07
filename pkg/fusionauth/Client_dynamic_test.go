/*
* Copyright (c) 2019-2026, FusionAuth, All Rights Reserved
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
* either express or implied. See the License for the specific
* language governing permissions and limitations under the License.
 */

package fusionauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// roundTripFunc allows creating inline http.RoundTripper implementations in tests.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type readTrackingReader struct {
	data []byte
	read atomic.Bool
}

func (r *readTrackingReader) Read(p []byte) (int, error) {
	r.read.Store(true)
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

type responseBodyTrackingResponse struct {
	BaseHTTPResponse
	Value string `json:"value"`
}

type failOnDrainReadCloser struct {
	payload []byte
	closed  atomic.Bool
}

func (r *failOnDrainReadCloser) Read(p []byte) (int, error) {
	if len(r.payload) == 0 {
		return 0, fmt.Errorf("unexpected response body drain")
	}
	n := copy(p, r.payload)
	r.payload = r.payload[n:]
	return n, nil
}

func (r *failOnDrainReadCloser) Close() error {
	r.closed.Store(true)
	return nil
}

// newTestRC creates a restClient pointed at serverURL using the given RetryConfiguration and method.
// ResponseRef and ErrorRef are both set to &BaseHTTPResponse{} which satisfies StatusAble.
func newTestRC(serverURL *url.URL, cfg *RetryConfiguration, method string) *restClient {
	return &restClient{
		HTTPClient:         &http.Client{Timeout: 5 * time.Second},
		Headers:            make(map[string]string),
		RetryConfiguration: cfg,
		ResponseRef:        &BaseHTTPResponse{},
		ErrorRef:           &BaseHTTPResponse{},
		Method:             method,
		Uri:                serverURL,
	}
}

// newCountingServer returns a test server that serves responses[i] for the i-th request.
// Once all responses are consumed, the last entry is repeated.
func newCountingServer(t *testing.T, responses []int) (*httptest.Server, *int32) {
	t.Helper()
	var callCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := int(atomic.AddInt32(&callCount, 1)) - 1
		if idx >= len(responses) {
			idx = len(responses) - 1
		}
		w.WriteHeader(responses[idx])
	}))
	t.Cleanup(server.Close)
	return server, &callCount
}

// ---------------------------------------------------------------------------
// RetryConfiguration struct tests
// ---------------------------------------------------------------------------

func TestNewBasicRetryConfigurationDefaults(t *testing.T) {
	rc := NewBasicRetryConfiguration()

	if rc.BackoffMultiplier != 2.0 {
		t.Errorf("BackoffMultiplier: got %v, want 2.0", rc.BackoffMultiplier)
	}
	if rc.InitialDelay != 100*time.Millisecond {
		t.Errorf("InitialDelay: got %v, want 100ms", rc.InitialDelay)
	}
	if rc.Jitter != 0.20 {
		t.Errorf("Jitter: got %v, want 0.20", rc.Jitter)
	}
	if rc.MaxDelay != 30*time.Second {
		t.Errorf("MaxDelay: got %v, want 30s", rc.MaxDelay)
	}
	if rc.MaxRetries != 4 {
		t.Errorf("MaxRetries: got %d, want 4", rc.MaxRetries)
	}
	if !rc.RetryOnNetworkError {
		t.Error("RetryOnNetworkError: want true")
	}
	if rc.AllowNonIdempotentRetries {
		t.Error("AllowNonIdempotentRetries: want false")
	}
	for _, code := range []int{429, 500, 502, 503, 504} {
		if _, ok := rc.RetryableStatusCodes[code]; !ok {
			t.Errorf("RetryableStatusCodes: missing %d", code)
		}
	}
	if rc.RetryFunction == nil {
		t.Error("RetryFunction: want non-nil default")
	}
}

func TestRetryConfigurationValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RetryConfiguration
		wantErr bool
	}{
		{
			name: "zero value is valid",
			cfg:  RetryConfiguration{},
		},
		{
			name: "valid typical config",
			cfg: RetryConfiguration{
				BackoffMultiplier: 2.0,
				InitialDelay:      100 * time.Millisecond,
				Jitter:            0.20,
				MaxDelay:          30 * time.Second,
				MaxRetries:        4,
			},
		},
		{
			name: "jitter boundary 0.0",
			cfg:  RetryConfiguration{Jitter: 0.0},
		},
		{
			name: "jitter boundary 1.0",
			cfg:  RetryConfiguration{Jitter: 1.0},
		},
		{
			name:    "negative MaxRetries",
			cfg:     RetryConfiguration{MaxRetries: -1},
			wantErr: true,
		},
		{
			name:    "negative InitialDelay",
			cfg:     RetryConfiguration{InitialDelay: -1},
			wantErr: true,
		},
		{
			name:    "negative MaxDelay",
			cfg:     RetryConfiguration{MaxDelay: -1},
			wantErr: true,
		},
		{
			name:    "negative Jitter",
			cfg:     RetryConfiguration{Jitter: -0.01},
			wantErr: true,
		},
		{
			name:    "Jitter above 1.0",
			cfg:     RetryConfiguration{Jitter: 1.01},
			wantErr: true,
		},
		{
			name:    "negative BackoffMultiplier",
			cfg:     RetryConfiguration{BackoffMultiplier: -0.01},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRetryConfigurationCalculateDelay(t *testing.T) {
	cfg := &RetryConfiguration{
		InitialDelay:      100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		MaxDelay:          10 * time.Second,
		Jitter:            0, // no jitter for deterministic checks
	}

	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{5, 1600 * time.Millisecond},
	}

	for _, tc := range cases {
		got := cfg.calculateDelay(tc.attempt)
		if got != tc.want {
			t.Errorf("attempt %d: got %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestRetryConfigurationCalculateDelayMaxDelayCapped(t *testing.T) {
	cfg := &RetryConfiguration{
		InitialDelay:      1 * time.Second,
		BackoffMultiplier: 2.0,
		MaxDelay:          3 * time.Second,
		Jitter:            0,
	}

	for attempt := 1; attempt <= 6; attempt++ {
		got := cfg.calculateDelay(attempt)
		if got > 3*time.Second {
			t.Errorf("attempt %d: delay %v exceeds MaxDelay 3s", attempt, got)
		}
	}
}

func TestRetryConfigurationCalculateDelayWithJitter(t *testing.T) {
	cfg := &RetryConfiguration{
		InitialDelay:      100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		MaxDelay:          30 * time.Second,
		Jitter:            0.20,
	}

	// With 20% jitter the delay must be in [base, base * 1.20].
	base := 100 * time.Millisecond
	for attempt := 1; attempt <= 3; attempt++ {
		got := cfg.calculateDelay(attempt)
		lo := base
		hi := time.Duration(float64(base) * 1.20)
		if got < lo || got > hi {
			t.Errorf("attempt %d: delay %v outside expected range [%v, %v]", attempt, got, lo, hi)
		}
		base *= 2
	}
}

// ---------------------------------------------------------------------------
// Retry behaviour integration tests (httptest server)
// ---------------------------------------------------------------------------

func TestRetryOnRetryableStatusCodes(t *testing.T) {
	for _, code := range []int{429, 500, 502, 503, 504} {
		code := code
		t.Run(fmt.Sprintf("retries_on_%d", code), func(t *testing.T) {
			server, callCount := newCountingServer(t, []int{code, code, 200})
			serverURL, _ := url.Parse(server.URL)
			cfg := &RetryConfiguration{
				MaxRetries:           2,
				RetryableStatusCodes: map[int]struct{}{code: {}},
			}
			rc := newTestRC(serverURL, cfg, http.MethodGet)

			if err := rc.Do(context.Background()); err != nil {
				t.Fatalf("Do() unexpected error: %v", err)
			}
			if got := atomic.LoadInt32(callCount); got != 3 {
				t.Errorf("expected 3 calls, got %d", got)
			}
			if status := rc.ResponseRef.(*BaseHTTPResponse).StatusCode; status != 200 {
				t.Errorf("expected final status 200, got %d", status)
			}
		})
	}
}

func TestNoRetryOnSuccessResponse(t *testing.T) {
	server, callCount := newCountingServer(t, []int{200})
	serverURL, _ := url.Parse(server.URL)
	cfg := &RetryConfiguration{
		MaxRetries:           3,
		RetryableStatusCodes: map[int]struct{}{503: {}},
	}
	rc := newTestRC(serverURL, cfg, http.MethodGet)

	if err := rc.Do(context.Background()); err != nil {
		t.Fatalf("Do() unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(callCount); got != 1 {
		t.Errorf("expected 1 call (no retry on success), got %d", got)
	}
}

func TestNoRetryOnNonRetryableStatusCode(t *testing.T) {
	server, callCount := newCountingServer(t, []int{400})
	serverURL, _ := url.Parse(server.URL)
	cfg := &RetryConfiguration{
		MaxRetries:           3,
		RetryableStatusCodes: map[int]struct{}{503: {}},
	}
	rc := newTestRC(serverURL, cfg, http.MethodGet)

	if err := rc.Do(context.Background()); err != nil {
		t.Fatalf("Do() unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(callCount); got != 1 {
		t.Errorf("expected 1 call (400 is not retryable), got %d", got)
	}
}

func TestMaxRetriesRespected(t *testing.T) {
	server, callCount := newCountingServer(t, []int{503, 503, 503, 503, 503})
	serverURL, _ := url.Parse(server.URL)
	cfg := &RetryConfiguration{
		MaxRetries:           2,
		RetryableStatusCodes: map[int]struct{}{503: {}},
	}
	rc := newTestRC(serverURL, cfg, http.MethodGet)

	if err := rc.Do(context.Background()); err != nil {
		t.Fatalf("Do() unexpected error: %v", err)
	}
	// 1 initial + 2 retries = 3 total calls
	if got := atomic.LoadInt32(callCount); got != 3 {
		t.Errorf("expected 3 calls (1 initial + 2 retries), got %d", got)
	}
	// Final response should be the last 503
	if status := rc.ResponseRef.(*BaseHTTPResponse).StatusCode; status != 503 {
		t.Errorf("expected final status 503, got %d", status)
	}
}

func TestRetryOnNetworkError(t *testing.T) {
	var callCount int32
	u, _ := url.Parse("http://127.0.0.1:0")
	cfg := &RetryConfiguration{
		MaxRetries:           2,
		RetryOnNetworkError:  true,
		RetryableStatusCodes: map[int]struct{}{},
	}
	rc := &restClient{
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				atomic.AddInt32(&callCount, 1)
				return nil, fmt.Errorf("simulated network error")
			}),
		},
		Headers:            make(map[string]string),
		RetryConfiguration: cfg,
		ResponseRef:        &BaseHTTPResponse{},
		ErrorRef:           &BaseHTTPResponse{},
		Method:             http.MethodGet,
		Uri:                u,
	}

	err := rc.Do(context.Background())
	if err == nil {
		t.Fatal("expected error from network failure")
	}
	// 1 initial + 2 retries = 3 total
	if got := atomic.LoadInt32(&callCount); got != 3 {
		t.Errorf("expected 3 calls, got %d", got)
	}
}

func TestNoRetryOnNetworkErrorWhenDisabled(t *testing.T) {
	var callCount int32
	u, _ := url.Parse("http://127.0.0.1:0")
	cfg := &RetryConfiguration{
		MaxRetries:           2,
		RetryOnNetworkError:  false,
		RetryableStatusCodes: map[int]struct{}{},
	}
	rc := &restClient{
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				atomic.AddInt32(&callCount, 1)
				return nil, fmt.Errorf("simulated network error")
			}),
		},
		Headers:            make(map[string]string),
		RetryConfiguration: cfg,
		ResponseRef:        &BaseHTTPResponse{},
		ErrorRef:           &BaseHTTPResponse{},
		Method:             http.MethodGet,
		Uri:                u,
	}

	err := rc.Do(context.Background())
	if err == nil {
		t.Fatal("expected error from network failure")
	}
	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Errorf("expected 1 call (no network retry when disabled), got %d", got)
	}
}

func TestRetryFunctionRetryableConflict(t *testing.T) {
	var callCount int32
	conflictBody := `{"generalErrors":[{"code":"[retryableConflict]","message":"conflict"}]}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		if n < 3 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, conflictBody)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	serverURL, _ := url.Parse(server.URL)
	cfg := NewBasicRetryConfiguration()
	cfg.InitialDelay = 0 // no delay for fast tests

	rc := newTestRC(serverURL, cfg, http.MethodGet)
	if err := rc.Do(context.Background()); err != nil {
		t.Fatalf("Do() unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(&callCount); got != 3 {
		t.Errorf("expected 3 calls (2 conflict retries + 1 success), got %d", got)
	}
}

func TestRetryFunctionConflictWithoutRetryableCodeIsNotRetried(t *testing.T) {
	var callCount int32
	// 409 without [retryableConflict] in body should not be retried
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `{"generalErrors":[{"code":"[someOtherConflict]"}]}`)
	}))
	defer server.Close()

	serverURL, _ := url.Parse(server.URL)
	cfg := NewBasicRetryConfiguration()
	cfg.InitialDelay = 0

	rc := newTestRC(serverURL, cfg, http.MethodGet)
	if err := rc.Do(context.Background()); err != nil {
		t.Fatalf("Do() unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Errorf("expected 1 call (non-retryable 409), got %d", got)
	}
}

func TestNoRetryForPostByDefault(t *testing.T) {
	server, callCount := newCountingServer(t, []int{503, 503, 200})
	serverURL, _ := url.Parse(server.URL)
	cfg := &RetryConfiguration{
		MaxRetries:           2,
		RetryableStatusCodes: map[int]struct{}{503: {}},
		// AllowNonIdempotentRetries defaults to false
	}
	rc := newTestRC(serverURL, cfg, http.MethodPost)

	if err := rc.Do(context.Background()); err != nil {
		t.Fatalf("Do() unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(callCount); got != 1 {
		t.Errorf("expected 1 call (POST not retried by default), got %d", got)
	}
}

func TestAllowNonIdempotentRetriesEnablesPostRetry(t *testing.T) {
	server, callCount := newCountingServer(t, []int{503, 503, 200})
	serverURL, _ := url.Parse(server.URL)
	cfg := &RetryConfiguration{
		MaxRetries:                2,
		AllowNonIdempotentRetries: true,
		RetryableStatusCodes:      map[int]struct{}{503: {}},
	}
	rc := newTestRC(serverURL, cfg, http.MethodPost)

	if err := rc.Do(context.Background()); err != nil {
		t.Fatalf("Do() unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(callCount); got != 3 {
		t.Errorf("expected 3 calls (POST retried with AllowNonIdempotentRetries), got %d", got)
	}
}

func TestIdempotentMethodsAreRetried(t *testing.T) {
	for _, method := range []string{
		http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead,
	} {
		method := method
		t.Run(method, func(t *testing.T) {
			server, callCount := newCountingServer(t, []int{503, 200})
			serverURL, _ := url.Parse(server.URL)
			cfg := &RetryConfiguration{
				MaxRetries:           1,
				RetryableStatusCodes: map[int]struct{}{503: {}},
			}
			rc := newTestRC(serverURL, cfg, method)

			if err := rc.Do(context.Background()); err != nil {
				t.Fatalf("Do() [%s] unexpected error: %v", method, err)
			}
			if got := atomic.LoadInt32(callCount); got != 2 {
				t.Errorf("[%s] expected 2 calls, got %d", method, got)
			}
		})
	}
}

func TestContextCancelledDuringBackoff(t *testing.T) {
	server, _ := newCountingServer(t, []int{503, 200})
	serverURL, _ := url.Parse(server.URL)
	cfg := &RetryConfiguration{
		MaxRetries:           1,
		RetryableStatusCodes: map[int]struct{}{503: {}},
		InitialDelay:         10 * time.Second, // long enough that context fires first
		BackoffMultiplier:    1.0,
	}
	rc := newTestRC(serverURL, cfg, http.MethodGet)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := rc.Do(ctx)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestRetryBodyReplayedOnRetry(t *testing.T) {
	var mu sync.Mutex
	var receivedBodies []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]interface{}
		if decErr := json.NewDecoder(r.Body).Decode(&m); decErr == nil {
			if v, _ := m["key"].(string); v != "" {
				mu.Lock()
				receivedBodies = append(receivedBodies, v)
				mu.Unlock()
			}
		}

		mu.Lock()
		n := len(receivedBodies)
		mu.Unlock()

		if n < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	serverURL, _ := url.Parse(server.URL)
	cfg := &RetryConfiguration{
		MaxRetries:                2,
		AllowNonIdempotentRetries: true,
		RetryableStatusCodes:      map[int]struct{}{503: {}},
	}
	rc := newTestRC(serverURL, cfg, http.MethodPost)
	rc.WithJSONBody(map[string]string{"key": "hello"})

	if err := rc.Do(context.Background()); err != nil {
		t.Fatalf("Do() unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receivedBodies) < 2 {
		t.Fatalf("expected at least 2 requests with body, got %d", len(receivedBodies))
	}
	for i, body := range receivedBodies {
		if body != "hello" {
			t.Errorf("attempt %d: body key = %q, want %q", i+1, body, "hello")
		}
	}
}

func TestRequestBodyNotBufferedWhenRetriesDisabled(t *testing.T) {
	reader := &readTrackingReader{data: []byte(`{"key":"hello"}`)}
	roundTripper := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if reader.read.Load() {
			t.Fatal("expected request body to remain unread before RoundTrip")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		if string(body) != `{"key":"hello"}` {
			t.Fatalf("request body = %q, want %q", string(body), `{"key":"hello"}`)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(http.NoBody),
			Header:     make(http.Header),
		}, nil
	})

	rc := &restClient{
		HTTPClient:  &http.Client{Transport: roundTripper},
		Headers:     make(map[string]string),
		ResponseRef: &BaseHTTPResponse{},
		ErrorRef:    &BaseHTTPResponse{},
		Method:      http.MethodPost,
		Uri:         &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
		Body:        reader,
	}

	if err := rc.Do(context.Background()); err != nil {
		t.Fatalf("Do() unexpected error: %v", err)
	}
	if !reader.read.Load() {
		t.Fatal("expected request body to be consumed during request execution")
	}
}

func TestRequestBodyNotBufferedWhenMethodIsNotRetryable(t *testing.T) {
	reader := &readTrackingReader{data: []byte(`{"key":"hello"}`)}
	roundTripper := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if reader.read.Load() {
			t.Fatal("expected non-retryable method body to remain unread before RoundTrip")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		if string(body) != `{"key":"hello"}` {
			t.Fatalf("request body = %q, want %q", string(body), `{"key":"hello"}`)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(http.NoBody),
			Header:     make(http.Header),
		}, nil
	})

	rc := &restClient{
		HTTPClient: &http.Client{Transport: roundTripper},
		Headers:    make(map[string]string),
		RetryConfiguration: &RetryConfiguration{
			MaxRetries:           2,
			RetryOnNetworkError:  true,
			RetryableStatusCodes: map[int]struct{}{503: {}},
		},
		ResponseRef: &BaseHTTPResponse{},
		ErrorRef:    &BaseHTTPResponse{},
		Method:      http.MethodPost,
		Uri:         &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
		Body:        reader,
	}

	if err := rc.Do(context.Background()); err != nil {
		t.Fatalf("Do() unexpected error: %v", err)
	}
	if !reader.read.Load() {
		t.Fatal("expected request body to be consumed during request execution")
	}
}

func TestResponseBodyNotBufferedWhenRetriesAndDebugDisabled(t *testing.T) {
	body := &failOnDrainReadCloser{payload: []byte(`{"value":"ok"} `)}
	roundTripper := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       body,
			Header:     make(http.Header),
		}, nil
	})

	response := &responseBodyTrackingResponse{}
	rc := &restClient{
		HTTPClient:  &http.Client{Transport: roundTripper},
		Headers:     make(map[string]string),
		ResponseRef: response,
		ErrorRef:    &BaseHTTPResponse{},
		Method:      http.MethodGet,
		Uri:         &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
	}

	if err := rc.Do(context.Background()); err != nil {
		t.Fatalf("Do() unexpected error: %v", err)
	}
	if response.Value != "ok" {
		t.Fatalf("response value = %q, want %q", response.Value, "ok")
	}
	if !body.closed.Load() {
		t.Fatal("expected response body to be closed")
	}
}

func TestInvalidRetryConfigReturnsError(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:0")
	cfg := &RetryConfiguration{MaxRetries: -1}
	rc := &restClient{
		HTTPClient:         &http.Client{},
		Headers:            make(map[string]string),
		RetryConfiguration: cfg,
		ResponseRef:        &BaseHTTPResponse{},
		ErrorRef:           &BaseHTTPResponse{},
		Method:             http.MethodGet,
		Uri:                u,
	}
	if err := rc.Do(context.Background()); err == nil {
		t.Error("expected validation error for negative MaxRetries")
	}
}

func TestNilRetryConfigurationNoRetries(t *testing.T) {
	server, callCount := newCountingServer(t, []int{503, 503, 200})
	serverURL, _ := url.Parse(server.URL)
	rc := newTestRC(serverURL, nil, http.MethodGet)

	if err := rc.Do(context.Background()); err != nil {
		t.Fatalf("Do() unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(callCount); got != 1 {
		t.Errorf("expected 1 call (nil config = no retries), got %d", got)
	}
}

// ---------------------------------------------------------------------------
// RetryConfigurationFromEnv tests
// ---------------------------------------------------------------------------

func TestRetryConfigurationFromEnvNotSet(t *testing.T) {
	os.Unsetenv("FUSIONAUTH_ENABLE_RETRY")
	cfg := RetryConfigurationFromEnv()
	if cfg != nil {
		t.Errorf("expected nil when FUSIONAUTH_ENABLE_RETRY not set, got %+v", cfg)
	}
}

func TestRetryConfigurationFromEnvWrongValue(t *testing.T) {
	os.Setenv("FUSIONAUTH_ENABLE_RETRY", "1")
	defer os.Unsetenv("FUSIONAUTH_ENABLE_RETRY")
	cfg := RetryConfigurationFromEnv()
	if cfg != nil {
		t.Errorf("expected nil when FUSIONAUTH_ENABLE_RETRY=%q (not 'true'), got non-nil", "1")
	}
}

func TestRetryConfigurationFromEnvEnabled(t *testing.T) {
	os.Setenv("FUSIONAUTH_ENABLE_RETRY", "true")
	defer os.Unsetenv("FUSIONAUTH_ENABLE_RETRY")
	cfg := RetryConfigurationFromEnv()
	if cfg == nil {
		t.Fatal("expected non-nil RetryConfiguration when FUSIONAUTH_ENABLE_RETRY=true")
	}
	if cfg.MaxRetries != 4 {
		t.Errorf("MaxRetries: got %d, want 4", cfg.MaxRetries)
	}
	if cfg.InitialDelay != 100*time.Millisecond {
		t.Errorf("InitialDelay: got %v, want 100ms", cfg.InitialDelay)
	}
}
