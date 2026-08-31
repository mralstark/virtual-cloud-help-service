package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
)

func TestManifestEndpoint(t *testing.T) {
	want := manifest.Envelope{Algorithm: manifest.Algorithm, KeyID: "key", Payload: "payload", Signature: "signature"}
	handler := New(func() (manifest.Envelope, error) { return want, nil }, nil, 4)
	request := httptest.NewRequest(http.MethodGet, "/v1/manifest", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if !strings.Contains(response.Body.String(), `"algorithm":"Ed25519"`) {
		t.Fatalf("body = %q, want signed envelope", response.Body.String())
	}
}

func TestReadinessFailsClosed(t *testing.T) {
	handler := New(func() (manifest.Envelope, error) {
		return manifest.Envelope{}, errors.New("catalog invalid")
	}, nil, 4)
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
}

func TestRejectsWriteMethodsAndHeadOmitsBody(t *testing.T) {
	handler := New(func() (manifest.Envelope, error) { return manifest.Envelope{}, nil }, nil, 4)

	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", post.Code)
	}

	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/healthz", nil))
	if head.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", head.Code)
	}
	body, err := io.ReadAll(head.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 {
		t.Fatalf("HEAD body = %q, want empty", body)
	}
}

func TestExpensiveEndpointsHaveBoundedConcurrency(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	handler := New(func() (manifest.Envelope, error) {
		once.Do(func() { close(entered) })
		<-release
		return manifest.Envelope{}, nil
	}, nil, 1)

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/readyz", nil))
	}()
	<-entered

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/v1/manifest", nil))
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second concurrent status = %d, want 503", second.Code)
	}
	if second.Header().Get("Retry-After") != "1" {
		t.Fatal("busy response did not include Retry-After")
	}
	close(release)
	<-firstDone
}

func TestPilotAdminHandlerIsMountedOnlyWhenConfigured(t *testing.T) {
	admin := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	configured := NewWithPilotAdmin(func() (manifest.Envelope, error) { return manifest.Envelope{}, nil }, nil, 1, admin)
	response := httptest.NewRecorder()
	configured.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/admin/pilot/access", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("configured admin status = %d", response.Code)
	}

	disabled := New(func() (manifest.Envelope, error) { return manifest.Envelope{}, nil }, nil, 1)
	disabledResponse := httptest.NewRecorder()
	disabled.ServeHTTP(disabledResponse, httptest.NewRequest(http.MethodPost, "/admin/pilot/access", nil))
	if disabledResponse.Code != http.StatusNotFound {
		t.Fatalf("disabled admin status = %d", disabledResponse.Code)
	}
}

func TestReadinessChecksDependenciesWithoutBlockingManifest(t *testing.T) {
	dependencyErr := errors.New("database unavailable")
	handler := NewWithPilotAdminAndReadiness(
		func() (manifest.Envelope, error) { return manifest.Envelope{}, nil }, nil, 1, nil,
		func(context.Context) error { return dependencyErr },
	)
	readyResponse := httptest.NewRecorder()
	handler.ServeHTTP(readyResponse, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if readyResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness status = %d", readyResponse.Code)
	}
	manifestResponse := httptest.NewRecorder()
	handler.ServeHTTP(manifestResponse, httptest.NewRequest(http.MethodGet, "/v1/manifest", nil))
	if manifestResponse.Code != http.StatusOK {
		t.Fatalf("manifest status = %d", manifestResponse.Code)
	}
}
