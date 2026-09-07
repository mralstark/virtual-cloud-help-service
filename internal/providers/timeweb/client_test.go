package timeweb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetServerSanitizesProviderResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/servers/123" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("unexpected request")
		}
		fmt.Fprint(w, `{"server":{"id":123,"name":"pilot","status":"on","location":"de-1","availability_zone":"fra-1","root_pass":"DO-NOT-EXPOSE","vnc_pass":"DO-NOT-EXPOSE","networks":[{"type":"public","ips":[{"ip":"203.0.113.5"}]},{"type":"local","ips":[{"ip":"10.0.0.1"}]}]}}`)
	}))
	defer server.Close()
	client, _ := NewClient("test-token")
	client.baseURL = server.URL
	result, err := client.GetServer(context.Background(), 123)
	if err != nil {
		t.Fatal(err)
	}
	if result.AvailabilityZone != "fra-1" || len(result.PublicIPs) != 1 {
		t.Fatalf("unexpected inventory: %+v", result)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "DO-NOT-EXPOSE") {
		t.Fatal("provider secret exposed")
	}
}

func TestGetServerFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", 401, `{"error":"sensitive provider details"}`},
		{"rate limited", 429, `{}`},
		{"redirect", 302, `{}`},
		{"mismatched ID", 200, `{"server":{"id":124}}`},
		{"malformed", 200, `{"server":`},
		{"oversized", 200, strings.Repeat(" ", maxServerBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "https://example.invalid")
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			client, _ := NewClient("test-token")
			client.baseURL = server.URL
			_, err := client.GetServer(context.Background(), 123)
			if err == nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
}

func TestClientRejectsInvalidInput(t *testing.T) {
	for _, token := range []string{"", "a\nb", "a b", strings.Repeat("a", 8193)} {
		if _, err := NewClient(token); err == nil {
			t.Fatal("accepted invalid token")
		}
	}
	client, _ := NewClient("test-token")
	if _, err := client.GetServer(context.Background(), 0); err == nil {
		t.Fatal("accepted invalid server ID")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.GetServer(ctx, 123); err == nil {
		t.Fatal("ignored cancellation")
	}
}
