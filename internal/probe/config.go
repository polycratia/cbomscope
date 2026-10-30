package probe

import (
	"crypto/tls"
	"fmt"

	"github.com/polycratia/cbomscope/internal/asset"
)

// The three readings below take a crypto/tls constant as a source file spells
// it. A configuration written in code names its cryptography with the same
// constants a handshake reports back, so the readings are shared rather than
// written twice: a suite configured here and the same suite negotiated on the
// wire arrive in the inventory as one asset and not two.

// VersionAsset reads a protocol version constant — VersionTLS12 — into the
// protocol asset it names.
func VersionAsset(constant string, at asset.Location) (asset.Asset, bool) {
	version, ok := versionConstants[constant]
	if !ok {
		return asset.Asset{}, false
	}
	return asset.Asset{
		Name:     versionName(version),
		Kind:     asset.Protocol,
		Location: at,
		Evidence: "protocol version tls." + constant,
	}, true
}

var versionConstants = map[string]uint16{
	"VersionTLS10": tls.VersionTLS10,
	"VersionTLS11": tls.VersionTLS11,
	"VersionTLS12": tls.VersionTLS12,
	"VersionTLS13": tls.VersionTLS13,
}

// SuiteAsset reads a cipher suite constant — TLS_RSA_WITH_3DES_EDE_CBC_SHA —
// into the cipher it implies, by the reading a negotiated suite gets.
func SuiteAsset(constant string, at asset.Location) (asset.Asset, bool) {
	id, ok := suiteConstants[constant]
	if !ok {
		return asset.Asset{}, false
	}
	a := cipherAsset(id, at)
	a.Evidence = "cipher suite tls." + constant
	return a, true
}

// suiteConstants comes from the standard library's own listing rather than
// being written out: crypto/tls spells a suite constant exactly as
// CipherSuiteName prints it, so the suites it knows are the suites a source
// file can name.
var suiteConstants = func() map[string]uint16 {
	out := map[string]uint16{}
	for _, s := range tls.CipherSuites() {
		out[s.Name] = s.ID
	}
	for _, s := range tls.InsecureCipherSuites() {
		out[s.Name] = s.ID
	}
	return out
}()

// GroupAsset reads a key exchange group constant — X25519MLKEM768, CurveP256 —
// into the key agreement asset it names.
func GroupAsset(constant string, at asset.Location) (asset.Asset, bool) {
	id, ok := curveConstants[constant]
	if !ok {
		return asset.Asset{}, false
	}
	name, _ := keyExchange(id)
	return asset.Asset{
		Name:      name,
		Kind:      asset.Algorithm,
		Primitive: asset.KeyAgree,
		Algorithm: name,
		Location:  at,
		Evidence:  fmt.Sprintf("key exchange group tls.%s (codepoint 0x%04x)", constant, uint16(id)),
	}, true
}

// curveConstants is written out because crypto/tls publishes no listing of the
// groups it names, as it does for the cipher suites.
var curveConstants = map[string]tls.CurveID{
	"CurveP256":      tls.CurveP256,
	"CurveP384":      tls.CurveP384,
	"CurveP521":      tls.CurveP521,
	"X25519":         tls.X25519,
	"X25519MLKEM768": tls.X25519MLKEM768,
}
