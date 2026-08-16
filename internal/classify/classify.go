// Package classify judges how a cryptographic asset stands against a future
// quantum computer.
//
// The rules are the boring, published ones: Shor breaks factoring and discrete
// logarithms outright, so RSA, DSA, DH and everything elliptic-curve falls.
// Grover halves the effective strength of symmetric primitives, so AES-128
// drops to about 64 bits of quantum work while AES-256 stays comfortable.
// Nothing here is a prediction about when that computer arrives.
package classify

import (
	"fmt"
	"strings"

	"github.com/polycratia/cbomscope/internal/asset"
)

// Apply fills in Posture and Rationale, leaving everything else untouched.
func Apply(a asset.Asset) asset.Asset {
	a.Posture, a.Rationale = judge(a)
	return a
}

// ApplyAll classifies a slice in place order.
func ApplyAll(assets []asset.Asset) []asset.Asset {
	out := make([]asset.Asset, len(assets))
	for i, a := range assets {
		out[i] = Apply(a)
	}
	return out
}

// brokenToday lists what should already be out of use, quantum aside.
var brokenToday = map[string]string{
	"MD5":   "collisions are practical; unusable for signatures or integrity",
	"SHA-1": "collisions are practical; deprecated for signatures",
	"RC4":   "biases in the keystream make it unusable",
	"DES":   "56-bit keys are brute-forceable",
	"3DES":  "64-bit block size makes it vulnerable to birthday attacks on long sessions",
}

// shorBreaks lists the families whose hardness assumption Shor's algorithm
// removes: integer factorisation and discrete logarithms, elliptic or not.
var shorBreaks = map[string]string{
	"RSA":        "factoring",
	"DSA":        "discrete logarithm",
	"DH":         "discrete logarithm",
	"ECDSA":      "elliptic-curve discrete logarithm",
	"ECDH":       "elliptic-curve discrete logarithm",
	"ED25519":    "elliptic-curve discrete logarithm",
	"X25519":     "elliptic-curve discrete logarithm",
	"ECDSA-P256": "elliptic-curve discrete logarithm",
}

// postQuantum lists the NIST post-quantum standards by their standard names.
var postQuantum = map[string]string{
	"ML-KEM":    "FIPS 203",
	"ML-DSA":    "FIPS 204",
	"SLH-DSA":   "FIPS 205",
	"KYBER":     "pre-standard name of ML-KEM",
	"DILITHIUM": "pre-standard name of ML-DSA",
}

func judge(a asset.Asset) (asset.Posture, string) {
	name := strings.ToUpper(a.Algorithm)
	if name == "" {
		name = strings.ToUpper(a.Name)
	}
	if a.Kind == asset.Protocol {
		return protocol(name)
	}

	// A hybrid key exchange holds as long as either half holds, so it is called
	// out separately rather than being averaged into one of the other buckets.
	if isHybrid(name) {
		return asset.Hybrid, "classical and post-quantum key exchange combined: secure if either half holds"
	}
	for family, standard := range postQuantum {
		if strings.HasPrefix(name, family) {
			return asset.QuantumSafe, "post-quantum algorithm (" + standard + ")"
		}
	}
	if reason, ok := brokenToday[name]; ok {
		return asset.Broken, reason
	}
	for family, problem := range shorBreaks {
		if strings.HasPrefix(name, family) {
			return asset.QuantumVulnerable, "Shor's algorithm solves the underlying " + problem
		}
	}

	switch {
	case strings.HasPrefix(name, "AES"), strings.HasPrefix(name, "CHACHA"):
		return symmetric(a, name)
	case strings.HasPrefix(name, "SHA-3"), strings.HasPrefix(name, "SHA3"):
		return hash(a, name, 0)
	case strings.HasPrefix(name, "SHA-"), strings.HasPrefix(name, "SHA"):
		return hash(a, name, digestBits(name))
	case strings.HasPrefix(name, "HMAC"):
		return asset.QuantumReduced, "keyed hash: Grover halves the effective strength of the key"
	}
	return asset.PostureUnknown, "not in the classification table: judge this one by hand"
}

// protocol judges a protocol version. The version itself is not the thing a
// quantum computer attacks — the key exchange and the cipher it negotiates are,
// and those are reported as their own assets. What a version does tell you is
// whether it is deprecated today.
func protocol(name string) (asset.Posture, string) {
	switch {
	case strings.HasPrefix(name, "SSL"),
		strings.HasPrefix(name, "TLS 1.0"),
		strings.HasPrefix(name, "TLS 1.1"):
		return asset.Broken, "deprecated by RFC 8996: must not be negotiated"
	case strings.HasPrefix(name, "TLS 1.2"), strings.HasPrefix(name, "TLS 1.3"):
		return asset.NotApplicable,
			"a protocol version has no quantum posture of its own: see the key exchange and cipher it negotiated"
	default:
		return asset.PostureUnknown, "unrecognised protocol version"
	}
}

func isHybrid(name string) bool {
	// Named the way TLS reports them, e.g. X25519MLKEM768.
	return strings.Contains(name, "MLKEM") && strings.Contains(name, "X25519") ||
		strings.Contains(name, "HYBRID")
}

func symmetric(a asset.Asset, name string) (asset.Posture, string) {
	bits := a.KeySize
	if bits == 0 {
		bits = trailingBits(name)
	}
	switch {
	case bits == 0:
		return asset.PostureUnknown, "key size not determined: a 128-bit and a 256-bit key differ here"
	case bits >= 256:
		return asset.QuantumSafe, fmt.Sprintf("Grover leaves about %d bits of quantum work", bits/2)
	default:
		return asset.QuantumReduced, fmt.Sprintf(
			"Grover halves this to about %d bits of quantum work; %d-bit keys are the usual answer", bits/2, 256)
	}
}

func hash(a asset.Asset, name string, bits int) (asset.Posture, string) {
	if bits == 0 {
		bits = trailingBits(name)
	}
	switch {
	case bits == 0:
		return asset.PostureUnknown, "digest size not determined"
	case bits >= 384:
		return asset.QuantumSafe, fmt.Sprintf("about %d bits of collision resistance against a quantum search", bits/3)
	default:
		return asset.QuantumReduced, fmt.Sprintf(
			"%d-bit digest: quantum collision search reduces the margin; SHA-384 or larger is the usual answer", bits)
	}
}

// digestBits reads the size out of names like SHA-256 and SHA2-512.
func digestBits(name string) int { return trailingBits(name) }

func trailingBits(name string) int {
	digits := ""
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] >= '0' && name[i] <= '9' {
			digits = string(name[i]) + digits
			continue
		}
		break
	}
	n := 0
	for _, d := range digits {
		n = n*10 + int(d-'0')
	}
	// SHA-1 and friends: a trailing 1 is a version, not a size.
	if n < 64 {
		return 0
	}
	return n
}
