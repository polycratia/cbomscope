// Package classify judges how a cryptographic asset stands against a future
// quantum computer.
//
// Every verdict is read out of the table in table.go, and every row of that
// table names the published source it comes from: Shor for factoring and
// discrete logarithms, Grover for symmetric keys, the FIPS documents for the
// post-quantum standards, the RFCs for what is deprecated already. A family
// with no row is reported as unknown rather than judged by resemblance.
//
// Nothing here is a prediction about when that computer arrives.
package classify

import (
	"fmt"
	"strings"

	"github.com/polycratia/cbomscope/internal/asset"
)

// Apply fills in Posture, Rationale and Citation, leaving everything else
// untouched.
func Apply(a asset.Asset) asset.Asset {
	a.Posture, a.Rationale, a.Citation = judge(a)
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

func judge(a asset.Asset) (asset.Posture, string, string) {
	name := strings.ToUpper(a.Algorithm)
	if name == "" {
		name = strings.ToUpper(a.Name)
	}

	rule, ok := Lookup(name, a.Kind)
	if !ok {
		if a.Kind == asset.Protocol {
			return asset.PostureUnknown, "unrecognised protocol version: not in the classification table", ""
		}
		return asset.PostureUnknown, "not in the classification table: judge this one by hand", ""
	}
	if rule.size == nil {
		return rule.Posture, rule.Rationale, rule.Citation
	}

	posture, rationale := rule.size(a, name)
	if posture == asset.PostureUnknown {
		// The family was found, the size that decides it was not. A citation
		// beside an answer nobody has would make the gap look checked.
		return posture, rationale, ""
	}
	return posture, rationale, rule.Citation
}

func symmetricSize(a asset.Asset, name string) (asset.Posture, string) {
	bits := a.KeySize
	// ChaCha20 keys are 256-bit by definition; there is no other size to
	// determine. And its name must never reach trailingBits, which would read
	// the 1305 of Poly1305 as a key size and produce a confident nonsense
	// rationale ("about 652 bits of quantum work").
	if bits == 0 && strings.HasPrefix(name, "CHACHA") {
		bits = 256
	}
	if bits == 0 {
		bits = trailingBits(name)
		// A symmetric key is 128, 192 or 256 bits. Anything else scraped from a
		// name is a fragment of the name, not a size.
		if bits != 128 && bits != 192 && bits != 256 {
			bits = 0
		}
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

// digestSize reads the size out of names like SHA-256 and SHA3-512.
func digestSize(_ asset.Asset, name string) (asset.Posture, string) {
	bits := trailingBits(name)
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
