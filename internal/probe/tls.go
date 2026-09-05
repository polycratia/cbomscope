// Package probe reads the cryptography a live TLS endpoint actually negotiates.
//
// Source code says what a program might do; a handshake says what it does. The
// two disagree often enough — a reverse proxy terminates TLS, a library default
// changed, a load balancer is older than the service behind it — that an
// inventory built from source alone is incomplete.
package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/polycratia/cbomscope/internal/asset"
)

// DefaultTimeout bounds a probe. An endpoint that will not answer in this long
// is reported as unreachable rather than held onto.
const DefaultTimeout = 10 * time.Second

// Endpoint probes host:port and reports what the handshake used.
//
// Certificate verification is deliberately switched off: the job is to see what
// an endpoint presents, including an expired or self-signed certificate, and
// refusing to look would hide exactly the inventory that needs attention. The
// connection carries no data and is closed immediately.
func Endpoint(ctx context.Context, address string) ([]asset.Asset, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, fmt.Errorf("probe %q: expected host:port", address)
	}
	dialer := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("probe %s: %w", address, err)
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	return fromState(address, state), nil
}

func fromState(address string, state tls.ConnectionState) []asset.Asset {
	at := asset.Location{Host: address}
	assets := []asset.Asset{
		{
			Name:     versionName(state.Version),
			Kind:     asset.Protocol,
			Location: at,
			Evidence: "negotiated protocol version",
		},
		cipherAsset(state.CipherSuite, at),
	}
	if group := groupName(state); group != "" {
		assets = append(assets, asset.Asset{
			Name:      group,
			Kind:      asset.Algorithm,
			Primitive: asset.KeyAgree,
			Algorithm: group,
			Location:  at,
			Evidence:  "negotiated key exchange group",
		})
	}
	if len(state.PeerCertificates) > 0 {
		assets = append(assets, certificateAssets(state.PeerCertificates[0], at)...)
	}
	return assets
}

// cipherAsset turns a negotiated suite into the bulk cipher it implies, with
// the mode the suite name states. The suite name is kept as evidence so a
// reader can check the reading.
func cipherAsset(suite uint16, at asset.Location) asset.Asset {
	name := tls.CipherSuiteName(suite)
	a := asset.Asset{
		Name:      name,
		Kind:      asset.Algorithm,
		Primitive: asset.BlockCipher,
		Mode:      cipherMode(name),
		Location:  at,
		Evidence:  "negotiated cipher suite " + name,
	}
	switch {
	case strings.Contains(name, "AES_256"), strings.Contains(name, "AES256"):
		a.Algorithm, a.KeySize = "AES", 256
	case strings.Contains(name, "AES_128"), strings.Contains(name, "AES128"):
		a.Algorithm, a.KeySize = "AES", 128
	case strings.Contains(name, "CHACHA20"):
		a.Algorithm, a.KeySize, a.Primitive = "ChaCha20-Poly1305", 256, asset.AE
	default:
		a.Algorithm = name
	}
	if a.Mode == asset.GCM || a.Mode == asset.CCM {
		a.Primitive = asset.AE
	}
	return a
}

// cipherMode reads the mode of operation out of the suite name, which is the
// only place a handshake states it.
func cipherMode(name string) asset.Mode {
	switch {
	case strings.Contains(name, "GCM"):
		return asset.GCM
	case strings.Contains(name, "CCM"):
		return asset.CCM
	case strings.Contains(name, "CBC"):
		return asset.CBC
	default:
		return ""
	}
}

func certificateAssets(cert *x509.Certificate, at asset.Location) []asset.Asset {
	subject := cert.Subject.CommonName
	if subject == "" && len(cert.DNSNames) > 0 {
		subject = cert.DNSNames[0]
	}
	if subject == "" {
		subject = "unnamed certificate"
	}

	key := asset.Asset{
		Kind:      asset.Algorithm,
		Primitive: asset.Signature,
		Location:  at,
		Evidence:  "public key of the presented certificate (" + subject + ")",
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		key.Algorithm, key.KeySize = "RSA", pub.N.BitLen()
		key.Name = fmt.Sprintf("RSA-%d", key.KeySize)
	case *ecdsa.PublicKey:
		key.Algorithm = "ECDSA"
		key.Curve = pub.Curve.Params().Name
		key.KeySize = pub.Curve.Params().BitSize
		key.Name = "ECDSA-" + key.Curve
	case ed25519.PublicKey:
		key.Algorithm, key.KeySize, key.Name = "Ed25519", 256, "Ed25519"
	default:
		key.Algorithm = cert.PublicKeyAlgorithm.String()
		key.Name = key.Algorithm
	}

	return []asset.Asset{
		key,
		{
			Name:      cert.SignatureAlgorithm.String(),
			Kind:      asset.Certificate,
			Primitive: asset.Signature,
			Algorithm: signatureFamily(cert.SignatureAlgorithm),
			Location:  at,
			Evidence:  "signature algorithm of the presented certificate (" + subject + ")",
		},
	}
}

// signatureFamily reduces "SHA256-RSA" to the family the classifier judges.
func signatureFamily(alg x509.SignatureAlgorithm) string {
	name := strings.ToUpper(alg.String())
	switch {
	case strings.Contains(name, "ED25519"):
		return "Ed25519"
	case strings.Contains(name, "ECDSA"):
		return "ECDSA"
	case strings.Contains(name, "RSA"):
		return "RSA"
	case strings.Contains(name, "DSA"):
		return "DSA"
	default:
		return alg.String()
	}
}

func versionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("TLS (unrecognised version 0x%04x)", version)
	}
}

// groupName names the key exchange group. The hybrid one is the reason this
// probe exists at all: it is the only place an inventory can see that a
// deployment has already started its post-quantum migration.
func groupName(state tls.ConnectionState) string {
	switch state.CurveID {
	case 0:
		return ""
	case tls.CurveP256:
		return "ECDH-P256"
	case tls.CurveP384:
		return "ECDH-P384"
	case tls.CurveP521:
		return "ECDH-P521"
	case tls.X25519:
		return "X25519"
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	default:
		return fmt.Sprintf("key exchange group %d", uint16(state.CurveID))
	}
}
