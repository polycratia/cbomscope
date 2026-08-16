package probe

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/polycratia/cbomscope/internal/asset"
)

// The probe is tested against a real TLS server started in-process: a real
// handshake, no network beyond the loopback interface.
func testServer(t *testing.T, configure func(*tls.Config)) string {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {}))
	server.TLS = &tls.Config{}
	if configure != nil {
		configure(server.TLS)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "https://")
}

func find(assets []asset.Asset, predicate func(asset.Asset) bool) (asset.Asset, bool) {
	for _, a := range assets {
		if predicate(a) {
			return a, true
		}
	}
	return asset.Asset{}, false
}

func TestEndpointReportsTheHandshake(t *testing.T) {
	address := testServer(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assets, err := Endpoint(ctx, address)
	if err != nil {
		t.Fatal(err)
	}

	protocol, ok := find(assets, func(a asset.Asset) bool { return a.Kind == asset.Protocol })
	if !ok {
		t.Fatalf("no protocol version reported; got %+v", assets)
	}
	if !strings.HasPrefix(protocol.Name, "TLS 1.") {
		t.Errorf("protocol = %q, want a TLS version", protocol.Name)
	}

	if _, ok := find(assets, func(a asset.Asset) bool { return a.Primitive == asset.KeyAgree }); !ok {
		t.Errorf("no key exchange group reported; got %+v", assets)
	}
	if _, ok := find(assets, func(a asset.Asset) bool { return a.Kind == asset.Certificate }); !ok {
		t.Errorf("no certificate signature algorithm reported; got %+v", assets)
	}

	for _, a := range assets {
		if a.Location.Host != address {
			t.Errorf("%s was attributed to %q, want %q", a.Name, a.Location.Host, address)
		}
		if a.Evidence == "" {
			t.Errorf("%s carries no evidence; the finding cannot be checked", a.Name)
		}
	}
}

// An older deployment must be readable too — that is the inventory that needs
// the attention.
func TestEndpointReadsAnOlderDeployment(t *testing.T) {
	address := testServer(t, func(c *tls.Config) {
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assets, err := Endpoint(ctx, address)
	if err != nil {
		t.Fatal(err)
	}

	protocol, _ := find(assets, func(a asset.Asset) bool { return a.Kind == asset.Protocol })
	if protocol.Name != "TLS 1.2" {
		t.Errorf("protocol = %q, want TLS 1.2", protocol.Name)
	}
	cipher, ok := find(assets, func(a asset.Asset) bool { return a.Algorithm == "AES" })
	if !ok {
		t.Fatalf("no AES cipher reported; got %+v", assets)
	}
	if cipher.KeySize != 128 {
		t.Errorf("AES key size = %d, want 128 read out of the suite name", cipher.KeySize)
	}
}

func TestEndpointRejectsAnAddressWithoutAPort(t *testing.T) {
	_, err := Endpoint(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Errorf("err = %v, want a message naming the expected form", err)
	}
}

func TestEndpointGivesUpWhenNobodyAnswers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// Port 1 on the loopback interface: reachable stack, nothing listening.
	if _, err := Endpoint(ctx, "127.0.0.1:1"); err == nil {
		t.Error("probing a closed port succeeded")
	}
}
