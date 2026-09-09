package classify

import (
	"encoding/json"
	"strings"

	"github.com/polycratia/cbomscope/internal/asset"
)

// The published sources the rows are read from. A verdict a reader cannot
// check against a document is an opinion, and an inventory of opinions is what
// this tool exists to replace.
const (
	shor      = "Shor 1997, SIAM J. Comput. 26(5): polynomial-time factoring and discrete logarithms"
	grover    = "Grover 1996, STOC: a quadratic speedup for unstructured search"
	bht       = "Brassard, Hoyer and Tapp 1998, LATIN: quantum collision search in about 2^(n/3)"
	ir8547    = "NIST IR 8547: transition to post-quantum cryptography standards"
	fips203   = "NIST FIPS 203: ML-KEM, module-lattice key encapsulation"
	fips204   = "NIST FIPS 204: ML-DSA, module-lattice digital signatures"
	fips205   = "NIST FIPS 205: SLH-DSA, stateless hash-based digital signatures"
	sp800208  = "NIST SP 800-208: stateful hash-based signatures, LMS and XMSS"
	sp800131a = "NIST SP 800-131A Rev. 2: transitioning cryptographic algorithms and key lengths"
	rfc6151   = "RFC 6151: MD5 and HMAC-MD5 security considerations"
	rfc7465   = "RFC 7465: prohibiting RC4 cipher suites"
	rfc7568   = "RFC 7568: deprecating SSL 3.0"
	rfc8996   = "RFC 8996: deprecating TLS 1.0 and TLS 1.1"
	rfc5246   = "RFC 5246: TLS 1.2"
	rfc8446   = "RFC 8446: TLS 1.3"
	shattered = "Stevens et al., CRYPTO 2017: the first SHA-1 collision"
	sweet32   = "Bhargavan and Leurent, CCS 2016: birthday attacks on 64-bit block ciphers"
	hybridTLS = "draft-ietf-tls-hybrid-design: hybrid key exchange in TLS 1.3"

	// What the attack costs is one half of the answer; what a migration is
	// expected to do about it is the other.
	shorMigration   = shor + "; " + ir8547
	groverMigration = grover + "; " + ir8547
)

// sizeRule settles a verdict that only a stated key or digest size can settle.
type sizeRule func(a asset.Asset, name string) (asset.Posture, string)

// Rule is one row of the classification table.
type Rule struct {
	// Family is matched as a prefix against the uppercased algorithm name. The
	// longest matching family wins, so SHA-1 is not read as SHA.
	Family string
	// Kind narrows the row: a protocol row is never applied to an algorithm,
	// nor the other way round.
	Kind asset.Kind
	// Posture is empty on rows whose verdict depends on a size.
	Posture   asset.Posture
	Rationale string
	Citation  string

	// match replaces prefix matching where no prefix can find the family: a
	// hybrid group is named by concatenation, as in X25519MLKEM768.
	match func(name string) bool
	// size settles the verdict from a stated key or digest size.
	size sizeRule
}

// PostureLabel is the verdict for display. A row settled by a size says so
// rather than showing an empty column.
func (r Rule) PostureLabel() string {
	if r.Posture == "" {
		return "by size"
	}
	return string(r.Posture)
}

func (r Rule) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Family    string `json:"family"`
		Kind      string `json:"kind,omitempty"`
		Posture   string `json:"posture"`
		Rationale string `json:"rationale"`
		Citation  string `json:"citation"`
	}{r.Family, string(r.Kind), r.PostureLabel(), r.Rationale, r.Citation})
}

// Table is where every verdict comes from. It is data rather than a chain of
// conditions so that the gaps stay visible: a family with no row here is
// reported as unknown, and closing that gap is a row rather than a patch.
var Table = []Rule{
	// Hybrid first. It is the one family no prefix can find, and both of its
	// halves would otherwise match rows of their own.
	{
		Family:    "X25519MLKEM768",
		Posture:   asset.Hybrid,
		Rationale: "classical and post-quantum key exchange combined: secure if either half holds",
		Citation:  hybridTLS,
		match: func(name string) bool {
			return strings.Contains(name, "HYBRID") ||
				(strings.Contains(name, "MLKEM") && strings.Contains(name, "X25519"))
		},
	},

	// Post-quantum standards, under their standard names and under the names
	// they were submitted with, which is what deployed code still says.
	{Family: "ML-KEM", Posture: asset.QuantumSafe, Rationale: "post-quantum key encapsulation", Citation: fips203},
	{Family: "MLKEM", Posture: asset.QuantumSafe, Rationale: "post-quantum key encapsulation", Citation: fips203},
	{Family: "KYBER", Posture: asset.QuantumSafe, Rationale: "pre-standard name of ML-KEM", Citation: fips203},
	{Family: "ML-DSA", Posture: asset.QuantumSafe, Rationale: "post-quantum signature", Citation: fips204},
	{Family: "DILITHIUM", Posture: asset.QuantumSafe, Rationale: "pre-standard name of ML-DSA", Citation: fips204},
	{Family: "SLH-DSA", Posture: asset.QuantumSafe, Rationale: "post-quantum hash-based signature", Citation: fips205},
	{Family: "SPHINCS", Posture: asset.QuantumSafe, Rationale: "pre-standard name of SLH-DSA", Citation: fips205},
	{Family: "XMSS", Posture: asset.QuantumSafe, Rationale: "stateful hash-based signature: the state must never be reused", Citation: sp800208},
	{Family: "LMS", Posture: asset.QuantumSafe, Rationale: "stateful hash-based signature: the state must never be reused", Citation: sp800208},

	// What Shor's algorithm removes the hardness assumption of.
	{Family: "RSA", Posture: asset.QuantumVulnerable, Rationale: "Shor's algorithm solves the underlying factoring", Citation: shorMigration},
	{Family: "DSA", Posture: asset.QuantumVulnerable, Rationale: "Shor's algorithm solves the underlying discrete logarithm", Citation: shorMigration},
	{Family: "DH", Posture: asset.QuantumVulnerable, Rationale: "Shor's algorithm solves the underlying discrete logarithm", Citation: shorMigration},
	{Family: "ECDSA", Posture: asset.QuantumVulnerable, Rationale: "Shor's algorithm solves the underlying elliptic-curve discrete logarithm", Citation: shorMigration},
	{Family: "ECDH", Posture: asset.QuantumVulnerable, Rationale: "Shor's algorithm solves the underlying elliptic-curve discrete logarithm", Citation: shorMigration},
	{Family: "EDDSA", Posture: asset.QuantumVulnerable, Rationale: "Shor's algorithm solves the underlying elliptic-curve discrete logarithm", Citation: shorMigration},
	{Family: "ED25519", Posture: asset.QuantumVulnerable, Rationale: "Shor's algorithm solves the underlying elliptic-curve discrete logarithm", Citation: shorMigration},
	{Family: "ED448", Posture: asset.QuantumVulnerable, Rationale: "Shor's algorithm solves the underlying elliptic-curve discrete logarithm", Citation: shorMigration},
	{Family: "X25519", Posture: asset.QuantumVulnerable, Rationale: "Shor's algorithm solves the underlying elliptic-curve discrete logarithm", Citation: shorMigration},
	{Family: "X448", Posture: asset.QuantumVulnerable, Rationale: "Shor's algorithm solves the underlying elliptic-curve discrete logarithm", Citation: shorMigration},

	// Broken today, quantum aside.
	{Family: "MD5", Posture: asset.Broken, Rationale: "collisions are practical; unusable for signatures or integrity", Citation: rfc6151},
	{Family: "SHA-1", Posture: asset.Broken, Rationale: "collisions are practical; deprecated for signatures", Citation: shattered},
	{Family: "SHA1", Posture: asset.Broken, Rationale: "collisions are practical; deprecated for signatures", Citation: shattered},
	{Family: "RC4", Posture: asset.Broken, Rationale: "biases in the keystream make it unusable", Citation: rfc7465},
	{Family: "DES", Posture: asset.Broken, Rationale: "56-bit keys are brute-forceable", Citation: sp800131a},
	{Family: "3DES", Posture: asset.Broken, Rationale: "64-bit block size makes it vulnerable to birthday attacks on long sessions", Citation: sweet32},
	{Family: "TRIPLEDES", Posture: asset.Broken, Rationale: "64-bit block size makes it vulnerable to birthday attacks on long sessions", Citation: sweet32},

	// Families where the size is the verdict.
	{Family: "AES", Rationale: "Grover halves the effective strength of a symmetric key", Citation: groverMigration, size: symmetricSize},
	{Family: "CHACHA", Rationale: "Grover halves the effective strength of a symmetric key", Citation: groverMigration, size: symmetricSize},
	{Family: "SHA", Rationale: "quantum collision search costs about 2^(n/3) for an n-bit digest", Citation: bht, size: digestSize},
	{Family: "HMAC", Posture: asset.QuantumReduced, Rationale: "keyed hash: Grover halves the effective strength of the key", Citation: grover},

	// Protocol versions. A version is not what a quantum computer attacks — the
	// key exchange and cipher it negotiates are, and those are reported as their
	// own assets. What a version does say is whether it is deprecated today.
	{Family: "SSL", Kind: asset.Protocol, Posture: asset.Broken, Rationale: "deprecated: must not be negotiated", Citation: rfc7568},
	{Family: "TLS 1.0", Kind: asset.Protocol, Posture: asset.Broken, Rationale: "deprecated by RFC 8996: must not be negotiated", Citation: rfc8996},
	{Family: "TLS 1.1", Kind: asset.Protocol, Posture: asset.Broken, Rationale: "deprecated by RFC 8996: must not be negotiated", Citation: rfc8996},
	{Family: "TLS 1.2", Kind: asset.Protocol, Posture: asset.NotApplicable, Rationale: "a protocol version has no quantum posture of its own: see the key exchange and cipher it negotiated", Citation: rfc5246},
	{Family: "TLS 1.3", Kind: asset.Protocol, Posture: asset.NotApplicable, Rationale: "a protocol version has no quantum posture of its own: see the key exchange and cipher it negotiated", Citation: rfc8446},
}

// Lookup finds the row that covers name. Rows carrying their own matcher are
// tried first, then the longest matching family wins.
func Lookup(name string, kind asset.Kind) (Rule, bool) {
	name = strings.ToUpper(name)
	for _, r := range Table {
		if r.match != nil && r.applies(kind) && r.match(name) {
			return r, true
		}
	}
	best := -1
	for i, r := range Table {
		if r.match != nil || !r.applies(kind) || !strings.HasPrefix(name, r.Family) {
			continue
		}
		if best < 0 || len(r.Family) > len(Table[best].Family) {
			best = i
		}
	}
	if best < 0 {
		return Rule{}, false
	}
	return Table[best], true
}

func (r Rule) applies(kind asset.Kind) bool {
	if r.Kind == asset.Protocol {
		return kind == asset.Protocol
	}
	return kind != asset.Protocol
}
