package pilotapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/pilotaccess"
	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

const (
	maxRequestBytes  = 8 << 10
	operationTimeout = 5 * time.Second
)

type AccessService interface {
	Register(context.Context, pilotaccess.RegisterInput) (pilotaccess.Access, error)
	Revoke(context.Context, string) (pilotaccess.Access, error)
}

type Handler struct {
	service AccessService
	token   [sha256.Size]byte
	logger  *log.Logger
}

type registerRequest struct {
	DeviceID          string            `json:"device_id"`
	NodeID            string            `json:"node_id"`
	Transport         vpnnode.Transport `json:"transport"`
	ExternalReference string            `json:"external_reference"`
	ExpiresAt         *time.Time        `json:"expires_at,omitempty"`
}

type accessResponse struct {
	ID                string             `json:"id"`
	DeviceID          string             `json:"device_id"`
	NodeID            string             `json:"node_id"`
	Transport         vpnnode.Transport  `json:"transport"`
	ExternalReference string             `json:"external_reference"`
	CreatedAt         time.Time          `json:"created_at"`
	ExpiresAt         *time.Time         `json:"expires_at,omitempty"`
	RevokedAt         *time.Time         `json:"revoked_at,omitempty"`
	Status            pilotaccess.Status `json:"status"`
}

func New(service AccessService, token string, logger *log.Logger) (http.Handler, error) {
	if service == nil {
		return nil, errors.New("pilot API: access service is required")
	}
	if len(token) < 32 || len(token) > 512 {
		return nil, errors.New("pilot API: admin token must contain between 32 and 512 bytes")
	}
	if strings.IndexFunc(token, func(character rune) bool { return character <= ' ' || character == 127 }) >= 0 {
		return nil, errors.New("pilot API: admin token must not contain whitespace or control characters")
	}
	return &Handler{service: service, token: sha256.Sum256([]byte(token)), logger: logger}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setHeaders(writer)
	if !handler.authorized(request) {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="pilot-admin"`)
		writeError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}

	switch {
	case request.URL.Path == "/admin/pilot/access":
		handler.register(writer, request)
	case strings.HasPrefix(request.URL.Path, "/admin/pilot/access/") && strings.HasSuffix(request.URL.Path, "/revoke"):
		handler.revoke(writer, request)
	default:
		writeError(writer, http.StatusNotFound, "not found")
	}
}

func (handler *Handler) register(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(writer, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var input registerRequest
	if err := decodeStrict(writer, request, &input); err != nil {
		var sizeError *http.MaxBytesError
		if errors.As(err, &sizeError) {
			writeError(writer, http.StatusRequestEntityTooLarge, "request too large")
			return
		}
		writeError(writer, http.StatusBadRequest, "invalid request")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), operationTimeout)
	defer cancel()
	access, err := handler.service.Register(ctx, pilotaccess.RegisterInput{
		DeviceID: input.DeviceID, NodeID: input.NodeID, Transport: input.Transport,
		ExternalReference: input.ExternalReference, ExpiresAt: input.ExpiresAt,
	})
	if err != nil {
		handler.serviceError(writer, "register pilot access", err)
		return
	}
	writeJSON(writer, http.StatusCreated, responseFromAccess(access))
}

func (handler *Handler) revoke(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	identifier := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/admin/pilot/access/"), "/revoke")
	if identifier == "" || strings.Contains(identifier, "/") {
		writeError(writer, http.StatusNotFound, "not found")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), operationTimeout)
	defer cancel()
	access, err := handler.service.Revoke(ctx, identifier)
	if err != nil {
		handler.serviceError(writer, "revoke pilot access", err)
		return
	}
	writeJSON(writer, http.StatusOK, responseFromAccess(access))
}

func (handler *Handler) authorized(request *http.Request) bool {
	scheme, presented, ok := strings.Cut(request.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || presented == "" ||
		strings.IndexFunc(presented, func(character rune) bool { return character <= ' ' || character == 127 }) >= 0 {
		return false
	}
	presentedHash := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(presentedHash[:], handler.token[:]) == 1
}

func (handler *Handler) serviceError(writer http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, pilotaccess.ErrInvalid):
		writeError(writer, http.StatusBadRequest, "invalid access metadata")
	case errors.Is(err, pilotaccess.ErrNotFound):
		writeError(writer, http.StatusNotFound, "access not found")
	case errors.Is(err, pilotaccess.ErrConflict):
		writeError(writer, http.StatusConflict, "access already exists")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(writer, http.StatusServiceUnavailable, "service temporarily unavailable")
	default:
		if handler.logger != nil {
			handler.logger.Printf("%s failed", operation)
		}
		writeError(writer, http.StatusInternalServerError, "internal error")
	}
}

func decodeStrict(writer http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("multiple JSON values")
}

func responseFromAccess(access pilotaccess.Access) accessResponse {
	return accessResponse{
		ID: access.ID, DeviceID: access.DeviceID, NodeID: access.NodeID,
		Transport: access.Transport, ExternalReference: access.ExternalReference,
		CreatedAt: access.CreatedAt, ExpiresAt: access.ExpiresAt,
		RevokedAt: access.RevokedAt, Status: access.Status,
	}
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}

func setHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
}
