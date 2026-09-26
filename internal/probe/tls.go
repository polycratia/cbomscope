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

// KeyExchange is the reading of the negotiated group, in four states rather
// than two: a group nobody recognised is not evidence of a classical one, and a
// handshake that reported no group at all is a third thing again.
type KeyExchange string

const (
	// KeyExchangePostQuantum: post-quantum key material, alone or as one half of
	// a hybrid.
	KeyExchangePostQuantum KeyExchange = "post_quantum"
	// KeyExchangeClassical: the group rests entirely on a problem Shor's
	// algorithm solves.
	KeyExchangeClassical KeyExchange = "classical"
	// KeyExchangeUnknown: a codepoint this tool has no name for.
	KeyExchangeUnknown KeyExchange = "unknown"
	// KeyExchangeNone: the handshake reported no group.
	KeyExchangeNone KeyExchange = "none"
)

// Result is what one handshake said. The assets are the inventory; the fields
// beside them are the reading a migration plan starts from — which group was
// negotiated, whether any part of it was post-quantum, and what authenticated
// the exchange.
type Result struct {
	Address string `json:"address"`
	Version string `json:"version"`
	// Group is the negotiated key exchange group, empty when the handshake
	// reported none.
	Group       string      `json:"group,omitempty"`
	KeyExchange KeyExchange `json:"key_exchange"`
	// Offered are the groups the probe put on the table. Without them a
	// classical answer is not a finding about the endpoint: it reads the same as
	// a probe that never asked for anything better.
	Offered []string `json:"offered"`
	// Signature is what authenticated the handshake, as far as the handshake
	// pins it: a scheme where the version and the key allow only one, a family
	// where they do not.
	Signature string        `json:"signature,omitempty"`
	Assets    []asset.Asset `json:"assets"`
}

// offeredGroups is what the probe offers, hybrid first. It is written out here
// rather than left to the standard library's default because the default moves
// between releases and can be switched off by a GODEBUG setting: the absence of
// post-quantum key exchange is only an endpoint's answer if a post-quantum
// group was asked for.
var offeredGroups = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

// Offered names every key exchange group the probe puts on the table.
func Offered() []string {
	out := make([]string, 0, len(offeredGroups))
	for _, id := range offeredGroups {
		out = append(out, groups[id].name)
	}
	return out
}

// OfferedPostQuantum names the post-quantum groups among them. A classical
// result is read against this list: these are what the endpoint declined.
func OfferedPostQuantum() []string {
	var out []string
	for _, id := range offeredGroups {
		if g := groups[id]; g.postQuantum {
			out = append(out, g.name)
		}
	}
	return out
}

// Endpoint probes host:port and reports what the handshake used.
//
// Certificate verification is deliberately switched off: the job is to see what
// an endpoint presents, including an expired or self-signed certificate, and
// refusing to look would hide exactly the inventory that needs attention. The
// connection carries no data and is closed immediately.
func Endpoint(ctx context.Context, address string) (Result, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return Result{}, fmt.Errorf("probe %q: expected host:port", address)
	}
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true,
		CurvePreferences:   offeredGroups,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return Result{}, fmt.Errorf("probe %s: %w", address, err)
	}
	defer conn.Close()

	return fromState(address, conn.(*tls.Conn).ConnectionState()), nil
}

func fromState(address string, state tls.ConnectionState) Result {
	at := asset.Location{Host: address}
	result := Result{Address: address, Version: versionName(state.Version), Offered: Offered()}
	result.Assets = []asset.Asset{
		{
			Name:     result.Version,
			Kind:     asset.Protocol,
			Location: at,
			Evidence: "negotiated protocol version",
		},
		cipherAsset(state.CipherSuite, at),
	}

	result.Group, result.KeyExchange = keyExchange(state.CurveID)
	if result.Group != "" {
		result.Assets = append(result.Assets, asset.Asset{
			Name:      result.Group,
			Kind:      asset.Algorithm,
			Primitive: asset.KeyAgree,
			Algorithm: result.Group,
			Location:  at,
			Evidence: fmt.Sprintf("negotiated key exchange group (codepoint 0x%04x), chosen from %s",
				uint16(state.CurveID), strings.Join(result.Offered, ", ")),
		})
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		result.Assets = append(result.Assets, certificateAssets(leaf, at)...)
		if signature, ok := signatureAsset(leaf, state.Version, at); ok {
			result.Signature = signature.Name
			result.Assets = append(result.Assets, signature)
		}
	}
	return result
}

// group is a key exchange group as a handshake names it.
type group struct {
	name string
	// postQuantum is true when the group carries post-quantum key material,
	// alone or as one half of a hybrid.
	postQuantum bool
}

// groups names the key exchange groups by their registered codepoint rather
// than by the constants this Go release happens to define. The post-quantum
// ones are the reason: they are being assigned and deployed faster than any one
// TLS stack implements them, and an inventory that prints a number for the
// group it exists to look for is not an inventory.
var groups = map[tls.CurveID]group{
	tls.CurveP256:      {name: "ECDH-P256"},
	tls.CurveP384:      {name: "ECDH-P384"},
	tls.CurveP521:      {name: "ECDH-P521"},
	tls.X25519:         {name: "X25519"},
	0x001e:             {name: "X448"},
	tls.X25519MLKEM768: {name: "X25519MLKEM768", postQuantum: true},
	0x11eb:             {name: "SecP256r1MLKEM768", postQuantum: true},
	0x11ed:             {name: "SecP384r1MLKEM1024", postQuantum: true},
	0x0200:             {name: "MLKEM512", postQuantum: true},
	0x0201:             {name: "MLKEM768", postQuantum: true},
	0x0202:             {name: "MLKEM1024", postQuantum: true},
	0x6399:             {name: "X25519Kyber768Draft00", postQuantum: true},
	0x639a:             {name: "SecP256r1Kyber768Draft00", postQuantum: true},
}

// keyExchange names the negotiated group and says what it rests on. A group
// with no entry above is named by its codepoint and reported as unrecognised:
// calling it classical would be a verdict nobody took.
func keyExchange(id tls.CurveID) (string, KeyExchange) {
	if id == 0 {
		return "", KeyExchangeNone
	}
	if g, ok := groups[id]; ok {
		if g.postQuantum {
			return g.name, KeyExchangePostQuantum
		}
		return g.name, KeyExchangeClassical
	}
	return fmt.Sprintf("key exchange group 0x%04x", uint16(id)), KeyExchangeUnknown
}

// signatureAsset describes the signature that authenticated the handshake.
//
// Go's TLS stack does not expose the scheme the peer signed CertificateVerify
// with, so it is read off what constrains that choice: the leaf key and the
// protocol version. In TLS 1.3 an ECDSA P-256 key can sign nothing but
// ecdsa_secp256r1_sha256, and PKCS#1 v1.5 is forbidden, so an RSA key there is
// PSS. Where TLS 1.2 leaves several digests possible, the family is reported
// with no digest at all rather than the likely one.
func signatureAsset(cert *x509.Certificate, version uint16, at asset.Location) (asset.Asset, bool) {
	a := asset.Asset{Kind: asset.Algorithm, Primitive: asset.Signature, Location: at}
	tls13 := version == tls.VersionTLS13
	switch pub := cert.PublicKey.(type) {
	case ed25519.PublicKey:
		a.Name, a.Algorithm, a.KeySize = "ed25519", "Ed25519", 256
		a.Evidence = "handshake signature scheme, pinned by an Ed25519 certificate key"
	case *ecdsa.PublicKey:
		a.Algorithm = "ECDSA"
		a.Curve = pub.Curve.Params().Name
		a.KeySize = pub.Curve.Params().BitSize
		if scheme, ok := ecdsaSchemes[a.Curve]; ok && tls13 {
			a.Name = scheme
			a.Evidence = "handshake signature scheme, pinned by TLS 1.3 and an ECDSA " + a.Curve + " certificate key"
			break
		}
		a.Name = "ECDSA"
		a.Evidence = "handshake signature family; " + versionName(version) +
			" does not pin the digest and the handshake does not expose it"
	case *rsa.PublicKey:
		a.Algorithm, a.KeySize = "RSA", pub.N.BitLen()
		if tls13 {
			a.Name = "RSA-PSS"
			a.Evidence = "handshake signature family, pinned to PSS by TLS 1.3; the digest is not exposed"
			break
		}
		a.Name = "RSA"
		a.Evidence = "handshake signature family; " + versionName(version) +
			" pins neither the padding nor the digest"
	default:
		return asset.Asset{}, false
	}
	return a, true
}

// ecdsaSchemes is read backwards from the TLS 1.3 registry: there the curve of
// the key is the scheme.
var ecdsaSchemes = map[string]string{
	"P-256": "ecdsa_secp256r1_sha256",
	"P-384": "ecdsa_secp384r1_sha384",
	"P-521": "ecdsa_secp521r1_sha512",
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
