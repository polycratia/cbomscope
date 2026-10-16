package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"slices"
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

func probeOf(t *testing.T, address string) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := Endpoint(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	return result
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
	result := probeOf(t, address)
	assets := result.Assets

	protocol, ok := find(assets, func(a asset.Asset) bool { return a.Kind == asset.Protocol })
	if !ok {
		t.Fatalf("no protocol version reported; got %+v", assets)
	}
	if !strings.HasPrefix(protocol.Name, "TLS 1.") {
		t.Errorf("protocol = %q, want a TLS version", protocol.Name)
	}
	if result.Version != protocol.Name {
		t.Errorf("result version = %q, asset = %q", result.Version, protocol.Name)
	}

	if _, ok := find(assets, func(a asset.Asset) bool { return a.Primitive == asset.KeyAgree }); !ok {
		t.Errorf("no key exchange group reported; got %+v", assets)
	}
	if _, ok := find(assets, func(a asset.Asset) bool { return a.Kind == asset.Certificate }); !ok {
		t.Errorf("no certificate signature algorithm reported; got %+v", assets)
	}
	if result.Signature == "" {
		t.Errorf("no handshake signature reported; got %+v", result)
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

// The group is the whole reason to handshake: it is the only place an inventory
// can see that a deployment has started its migration, or that it has not.
func TestEndpointNamesTheGroupAndFlagsAClassicalOne(t *testing.T) {
	hybrid := probeOf(t, testServer(t, func(c *tls.Config) {
		c.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	}))
	if hybrid.Group != "X25519MLKEM768" || hybrid.KeyExchange != KeyExchangePostQuantum {
		t.Errorf("group = %q/%s, want X25519MLKEM768 read as post-quantum", hybrid.Group, hybrid.KeyExchange)
	}

	classical := probeOf(t, testServer(t, func(c *tls.Config) {
		c.CurvePreferences = []tls.CurveID{tls.X25519}
	}))
	if classical.Group != "X25519" || classical.KeyExchange != KeyExchangeClassical {
		t.Errorf("group = %q/%s, want X25519 read as classical", classical.Group, classical.KeyExchange)
	}

	group, ok := find(classical.Assets, func(a asset.Asset) bool { return a.Primitive == asset.KeyAgree })
	if !ok || !strings.Contains(group.Evidence, "0x001d") {
		t.Errorf("evidence = %q, want the codepoint a reader can look up", group.Evidence)
	}
}

// A classical answer is a finding about the endpoint only if a post-quantum
// group was on the table when it chose, so what was offered is recorded beside
// what was negotiated.
func TestTheProbeRecordsWhatItOffered(t *testing.T) {
	if len(OfferedPostQuantum()) == 0 {
		t.Fatal("no post-quantum group is offered, so a classical result says nothing about the endpoint")
	}

	classical := probeOf(t, testServer(t, func(c *tls.Config) {
		c.CurvePreferences = []tls.CurveID{tls.X25519}
	}))
	if !slices.Contains(classical.Offered, "X25519MLKEM768") {
		t.Errorf("offered = %v, want the hybrid group among them", classical.Offered)
	}
	if !slices.Contains(classical.Offered, classical.Group) {
		t.Errorf("negotiated %q, which is not in the offered list %v", classical.Group, classical.Offered)
	}

	group, _ := find(classical.Assets, func(a asset.Asset) bool { return a.Primitive == asset.KeyAgree })
	if !strings.Contains(group.Evidence, "X25519MLKEM768") {
		t.Errorf("evidence = %q, want it to name what was declined", group.Evidence)
	}
}

// A codepoint with no name must not be reported as classical: not knowing what
// a group is and knowing it is classical are different facts.
func TestAnUnrecognisedGroupIsNotCalledClassical(t *testing.T) {
	name, verdict := keyExchange(0x0abc)
	if verdict != KeyExchangeUnknown || !strings.Contains(name, "0x0abc") {
		t.Errorf("got %q/%s, want an unknown verdict naming the codepoint", name, verdict)
	}
	if _, verdict := keyExchange(0); verdict != KeyExchangeNone {
		t.Errorf("a handshake with no group = %s, want none", verdict)
	}
}

// Go does not expose the scheme the peer signed with, so what is reported is
// what the key and the version pin — and no more than that.
func TestHandshakeSignatureIsReportedOnlyAsFarAsItIsPinned(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{PublicKey: &ec.PublicKey}

	pinned, ok := signatureAsset(cert, tls.VersionTLS13, asset.Location{})
	if !ok || pinned.Name != "ecdsa_secp256r1_sha256" {
		t.Errorf("TLS 1.3 with a P-256 key = %q, want the one scheme that key can sign", pinned.Name)
	}
	loose, _ := signatureAsset(cert, tls.VersionTLS12, asset.Location{})
	if loose.Name != "ECDSA" {
		t.Errorf("TLS 1.2 with a P-256 key = %q, want the family: several digests remain possible", loose.Name)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pss, _ := signatureAsset(&x509.Certificate{PublicKey: &key.PublicKey}, tls.VersionTLS13, asset.Location{})
	if pss.Name != "RSA-PSS" || pss.KeySize != 2048 {
		t.Errorf("TLS 1.3 with an RSA key = %q/%d, want RSA-PSS with the modulus size", pss.Name, pss.KeySize)
	}
}

// An older deployment must be readable too — that is the inventory that needs
// the attention.
func TestEndpointReadsAnOlderDeployment(t *testing.T) {
	address := testServer(t, func(c *tls.Config) {
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	})
	assets := probeOf(t, address).Assets

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

// A client that offers only what a sound deployment would choose cannot
// handshake with an unsound one, and reports it as unreachable — which reads
// exactly like an endpoint that is not there.
func TestTheProbeOffersWhatAWeakEndpointWouldChoose(t *testing.T) {
	if MinimumVersion != tls.VersionTLS10 {
		t.Errorf("minimum version = %s, want TLS 1.0", versionName(MinimumVersion))
	}
	for _, want := range []struct {
		suite  uint16
		family string
	}{
		{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "forward-secret AEAD"},
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA, "RSA key transport with CBC"},
		{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "3DES"},
		{tls.TLS_RSA_WITH_RC4_128_SHA, "RC4"},
	} {
		if !slices.Contains(offeredSuites, want.suite) {
			t.Errorf("no %s suite is offered: an endpoint that speaks only that is refused rather than inventoried",
				want.family)
		}
	}
	if len(OfferedSuites()) != len(offeredSuites) {
		t.Errorf("OfferedSuites names %d of the %d suites offered", len(OfferedSuites()), len(offeredSuites))
	}
}

// The suite name is the only place a handshake states the cipher, so 3DES and
// RC4 are read out of it like AES is.
func TestTheSuiteNameNamesTheCipher(t *testing.T) {
	for _, c := range []struct {
		suite     uint16
		algorithm string
		keySize   int
		primitive asset.Primitive
		mode      asset.Mode
	}{
		{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "3DES", 168, asset.BlockCipher, asset.CBC},
		{tls.TLS_RSA_WITH_RC4_128_SHA, "RC4", 128, asset.StreamCipher, ""},
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA, "AES", 128, asset.BlockCipher, asset.CBC},
	} {
		got := cipherAsset(c.suite, asset.Location{})
		if got.Algorithm != c.algorithm || got.KeySize != c.keySize {
			t.Errorf("%s = %q/%d, want %s/%d", got.Name, got.Algorithm, got.KeySize, c.algorithm, c.keySize)
		}
		if got.Primitive != c.primitive || got.Mode != c.mode {
			t.Errorf("%s = %s/%s, want %s/%s", got.Name, got.Primitive, got.Mode, c.primitive, c.mode)
		}
	}
	if _, ok := keyTransportAsset(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil, asset.Location{}); ok {
		t.Error("an ECDHE suite was reported as RSA key transport")
	}
}

// A weak endpoint has to be inventoried rather than refused, and a suite with
// no forward secrecy carries a key exchange of its own: TLS_RSA_ negotiates no
// group, and reporting no key exchange at all is worse than naming RSA.
func TestEndpointInventoriesAWeakDeployment(t *testing.T) {
	inventoried := 0
	for _, c := range []struct {
		suite     uint16
		algorithm string
	}{
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA, "AES"},
		{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "3DES"},
		{tls.TLS_RSA_WITH_RC4_128_SHA, "RC4"},
	} {
		name := tls.CipherSuiteName(c.suite)
		t.Run(name, func(t *testing.T) {
			address := testServer(t, func(s *tls.Config) {
				s.MinVersion, s.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
				s.CipherSuites = []uint16{c.suite}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := Endpoint(ctx, address)
			if err != nil {
				// A suite this Go release will not serve either says nothing
				// about what the probe offers.
				t.Skipf("the in-process server would not negotiate %s: %v", name, err)
			}
			inventoried++

			cipher, ok := find(result.Assets, func(a asset.Asset) bool { return a.Algorithm == c.algorithm })
			if !ok {
				t.Fatalf("no %s asset; got %+v", c.algorithm, result.Assets)
			}
			if cipher.KeySize == 0 || !strings.Contains(cipher.Evidence, name) {
				t.Errorf("%s = %+v, want a key size and the suite it was read from", c.algorithm, cipher)
			}

			transport, ok := find(result.Assets, func(a asset.Asset) bool { return a.Primitive == asset.PKE })
			if !ok {
				t.Fatalf("a TLS_RSA_ handshake reported no key exchange at all; got %+v", result.Assets)
			}
			if transport.Algorithm != "RSA" || transport.KeySize == 0 {
				t.Errorf("key transport = %+v, want RSA with the modulus size of the certificate key", transport)
			}
			if !strings.Contains(transport.Evidence, name) {
				t.Errorf("evidence = %q, want it to name the suite the reading came from", transport.Evidence)
			}
			if result.Group != KeyTransport || result.KeyExchange != KeyExchangeClassical {
				t.Errorf("key exchange = %q/%s, want %q read as classical",
					result.Group, result.KeyExchange, KeyTransport)
			}
		})
	}
	if inventoried == 0 {
		t.Error("not one weak suite could be handshaked; the probe offers nothing such an endpoint would choose")
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
