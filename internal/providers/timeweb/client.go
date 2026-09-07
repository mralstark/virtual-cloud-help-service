package timeweb

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const maxServerBytes = 1 << 20

// Client reads an existing server. It never creates billable resources or
// changes networking. Tokens and provider response bodies are never logged.
type Client struct {
	token   string
	client  *http.Client
	baseURL string
}

type Server struct {
	ID               int64    `json:"id"`
	Name             string   `json:"name"`
	Status           string   `json:"status"`
	Location         string   `json:"location"`
	AvailabilityZone string   `json:"availability_zone"`
	PublicIPs        []string `json:"public_ips"`
}

func NewClient(token string) (*Client, error) {
	if token == "" || len(token) > 8192 || strings.IndexFunc(token, func(r rune) bool { return r <= 32 || r == 127 }) >= 0 {
		return nil, errors.New("timeweb: TWC_TOKEN is missing or invalid")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Client{token: token, baseURL: "https://api.timeweb.cloud", client: &http.Client{
		Timeout: 15 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (client *Client) GetServer(ctx context.Context, id int64) (Server, error) {
	if id <= 0 {
		return Server{}, errors.New("timeweb: server ID must be positive")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+"/api/v1/servers/"+strconv.FormatInt(id, 10), nil)
	if err != nil {
		return Server{}, errors.New("timeweb: could not construct request")
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Accept", "application/json")
	response, err := client.client.Do(request)
	if err != nil {
		return Server{}, errors.New("timeweb: request failed (check connection, TLS and timeout)")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Server{}, fmt.Errorf("timeweb: API returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxServerBytes+1))
	if err != nil || len(body) > maxServerBytes {
		return Server{}, errors.New("timeweb: response unreadable or exceeds 1 MiB")
	}
	// Deliberately decode only safe fields: the full API response can include
	// root_pass, vnc_pass and cloud_init containing secrets.
	var envelope struct {
		Server struct {
			ID       int64  `json:"id"`
			Name     string `json:"name"`
			Status   string `json:"status"`
			Location string `json:"location"`
			Zone     string `json:"availability_zone"`
			Networks []struct {
				Type string `json:"type"`
				IPs  []struct {
					IP string `json:"ip"`
				} `json:"ips"`
			} `json:"networks"`
		} `json:"server"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Server.ID != id {
		return Server{}, errors.New("timeweb: invalid or mismatched server response")
	}
	raw := envelope.Server
	result := Server{ID: raw.ID, Name: raw.Name, Status: raw.Status, Location: raw.Location, AvailabilityZone: raw.Zone, PublicIPs: []string{}}
	for _, network := range raw.Networks {
		if network.Type != "public" {
			continue
		}
		for _, address := range network.IPs {
			ip, err := netip.ParseAddr(address.IP)
			if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			result.PublicIPs = append(result.PublicIPs, ip.String())
		}
	}
	return result, nil
}
