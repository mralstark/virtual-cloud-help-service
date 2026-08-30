package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
)

type IssueFunc func() (manifest.Envelope, error)

type Handler struct {
	issue  IssueFunc
	logger *log.Logger
	limit  chan struct{}
}

func New(issue IssueFunc, logger *log.Logger, maxInFlight int) http.Handler {
	if maxInFlight < 1 {
		maxInFlight = 1
	}
	handler := &Handler{issue: issue, logger: logger, limit: make(chan struct{}, maxInFlight)}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handler.health)
	mux.HandleFunc("/readyz", handler.ready)
	mux.HandleFunc("/v1/manifest", handler.manifest)
	return securityHeaders(mux)
}

func (handler *Handler) health(writer http.ResponseWriter, request *http.Request) {
	if !allowReadMethod(writer, request) {
		return
	}
	writeText(writer, request, http.StatusOK, "ok\n")
}

func (handler *Handler) ready(writer http.ResponseWriter, request *http.Request) {
	if !allowReadMethod(writer, request) {
		return
	}
	if !handler.acquire(writer, request) {
		return
	}
	defer handler.release()
	if _, err := handler.issue(); err != nil {
		handler.logError("readiness check failed", err)
		writeText(writer, request, http.StatusServiceUnavailable, "not ready\n")
		return
	}
	writeText(writer, request, http.StatusOK, "ready\n")
}

func (handler *Handler) manifest(writer http.ResponseWriter, request *http.Request) {
	if !allowReadMethod(writer, request) {
		return
	}
	if !handler.acquire(writer, request) {
		return
	}
	defer handler.release()
	envelope, err := handler.issue()
	if err != nil {
		handler.logError("manifest issuance failed", err)
		writeText(writer, request, http.StatusServiceUnavailable, "manifest unavailable\n")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method == http.MethodHead {
		writer.WriteHeader(http.StatusOK)
		return
	}
	if err := json.NewEncoder(writer).Encode(envelope); err != nil {
		handler.logError("manifest response failed", err)
	}
}

func (handler *Handler) acquire(writer http.ResponseWriter, request *http.Request) bool {
	select {
	case handler.limit <- struct{}{}:
		return true
	default:
		writer.Header().Set("Retry-After", "1")
		writeText(writer, request, http.StatusServiceUnavailable, "busy\n")
		return false
	}
}

func (handler *Handler) release() {
	<-handler.limit
}

func (handler *Handler) logError(message string, err error) {
	if handler.logger != nil {
		handler.logger.Printf("%s: %v", message, err)
	}
}

func allowReadMethod(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method == http.MethodGet || request.Method == http.MethodHead {
		return true
	}
	writer.Header().Set("Allow", "GET, HEAD")
	http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func writeText(writer http.ResponseWriter, request *http.Request, status int, body string) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = writer.Write([]byte(body))
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}
