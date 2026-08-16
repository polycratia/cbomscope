// Package asset is the normalized view of a cryptographic asset: an algorithm,
// a protocol or a certificate, wherever it was found.
//
// Both discovery paths — reading source code and probing a live endpoint —
// produce these, so classification and CBOM output never have to know which
// one found what.
package asset

import "fmt"

// Kind is the category CycloneDX gives a cryptographic asset.
type Kind string

const (
	Algorithm   Kind = "algorithm"
	Protocol    Kind = "protocol"
	Certificate Kind = "certificate"
)

// Primitive is what the algorithm is for.
type Primitive string

const (
	PKE         Primitive = "pke"       // public-key encryption
	Signature   Primitive = "signature" //
	KEM         Primitive = "kem"       // key encapsulation
	KeyAgree    Primitive = "key-agree" //
	BlockCipher Primitive = "block-cipher"
	Hash        Primitive = "hash"
	MAC         Primitive = "mac"
	Unknown     Primitive = "unknown"
)

// Posture is how the asset stands against a future cryptanalytically relevant
// quantum computer — and, separately, against classical attacks that already
// work today.
type Posture string

const (
	// Broken: classically broken already. Quantum resistance is beside the point.
	Broken Posture = "broken"
	// QuantumVulnerable: Shor's algorithm breaks it outright.
	QuantumVulnerable Posture = "quantum_vulnerable"
	// QuantumReduced: Grover's algorithm halves the effective strength; still
	// usable at a large enough size.
	QuantumReduced Posture = "quantum_reduced"
	// QuantumSafe: no known quantum attack better than the classical one, or a
	// NIST post-quantum algorithm.
	QuantumSafe Posture = "quantum_safe"
	// Hybrid: a classical and a post-quantum algorithm used together, so the
	// result holds if either one holds.
	Hybrid Posture = "hybrid"
	// NotApplicable: the asset has no quantum posture of its own. A protocol
	// version is the case that matters: TLS 1.3 is neither safe nor vulnerable,
	// the algorithms it negotiates are, and those are reported separately.
	NotApplicable Posture = "not_applicable"
	// PostureUnknown: the asset was found but not enough is known to judge it.
	// This is a real answer, not a failure to produce one.
	PostureUnknown Posture = "unknown"
)

// Location is where an asset was found: a source position or a network address.
type Location struct {
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	Host string `json:"host,omitempty"`
}

func (l Location) String() string {
	switch {
	case l.File != "" && l.Line > 0:
		return fmt.Sprintf("%s:%d", l.File, l.Line)
	case l.File != "":
		return l.File
	case l.Host != "":
		return l.Host
	default:
		return "unknown"
	}
}

// Asset is one cryptographic thing in use.
type Asset struct {
	Name      string    `json:"name"`
	Kind      Kind      `json:"kind"`
	Primitive Primitive `json:"primitive,omitempty"`
	// Algorithm is the family: RSA, ECDSA, AES, SHA-256, ML-KEM.
	Algorithm string `json:"algorithm,omitempty"`
	// KeySize is in bits, 0 when the code did not say. A zero here means "not
	// determined", never "small".
	KeySize int `json:"key_size,omitempty"`
	// Curve, for elliptic-curve algorithms.
	Curve string `json:"curve,omitempty"`
	// Posture and Rationale are filled in by the classify package.
	Posture   Posture  `json:"posture"`
	Rationale string   `json:"rationale,omitempty"`
	Location  Location `json:"location"`
	// Evidence is the literal thing that was seen: the call, the cipher suite,
	// the certificate field. It lets a reader check the finding by hand.
	Evidence string `json:"evidence,omitempty"`
}
