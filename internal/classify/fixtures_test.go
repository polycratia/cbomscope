package classify

import (
	"strings"
	"testing"

	"github.com/polycratia/cbomscope/internal/asset"
)

// fixture is one name as it is actually spelled — in a call, in a cipher suite,
// on a wire — together with the verdict the table owes it and the document that
// verdict has to be read out of.
type fixture struct {
	name    string
	kind    asset.Kind
	keySize int
	posture asset.Posture
	// source is a phrase the citation has to name, so a row cannot pass by
	// carrying the right posture read out of the wrong document.
	source string
}

func (f fixture) asset() asset.Asset {
	a := asset.Asset{Name: f.name, Kind: f.kind, KeySize: f.keySize}
	if f.kind != asset.Protocol {
		a.Kind = asset.Algorithm
		a.Algorithm = f.name
	}
	return a
}

// fixtures reaches every row of the table, in the spellings that turn up in
// practice rather than the canonical ones alone: pre-standard names, fragments
// of suite names, and hybrid groups named by concatenation.
var fixtures = []fixture{
	{name: "RSA-2048", keySize: 2048, posture: asset.QuantumVulnerable, source: "Shor 1997"},
	{name: "DSA-2048", keySize: 2048, posture: asset.QuantumVulnerable, source: "Shor 1997"},
	{name: "DH-2048", keySize: 2048, posture: asset.QuantumVulnerable, source: "Shor 1997"},
	{name: "ECDSA-P-256", keySize: 256, posture: asset.QuantumVulnerable, source: "NIST IR 8547"},
	{name: "ECDH-P-384", keySize: 384, posture: asset.QuantumVulnerable, source: "Shor 1997"},
	{name: "EdDSA", posture: asset.QuantumVulnerable, source: "Shor 1997"},
	{name: "Ed25519", posture: asset.QuantumVulnerable, source: "Shor 1997"},
	{name: "Ed448", posture: asset.QuantumVulnerable, source: "Shor 1997"},
	{name: "X25519", posture: asset.QuantumVulnerable, source: "Shor 1997"},
	{name: "X448", posture: asset.QuantumVulnerable, source: "Shor 1997"},

	{name: "ML-KEM-768", posture: asset.QuantumSafe, source: "FIPS 203"},
	{name: "MLKEM768", posture: asset.QuantumSafe, source: "FIPS 203"},
	{name: "Kyber768", posture: asset.QuantumSafe, source: "FIPS 203"},
	{name: "ML-DSA-65", posture: asset.QuantumSafe, source: "FIPS 204"},
	{name: "Dilithium3", posture: asset.QuantumSafe, source: "FIPS 204"},
	{name: "SLH-DSA-SHA2-128s", posture: asset.QuantumSafe, source: "FIPS 205"},
	{name: "SPHINCS+-SHA2-128s", posture: asset.QuantumSafe, source: "FIPS 205"},
	{name: "XMSS-SHA2_10_256", posture: asset.QuantumSafe, source: "SP 800-208"},
	{name: "LMS-SHA256-M32-H5", posture: asset.QuantumSafe, source: "SP 800-208"},

	// All three of these hybrid spellings are live on the public internet, and
	// none of them is found by a prefix.
	{name: "X25519MLKEM768", posture: asset.Hybrid, source: "hybrid key exchange"},
	{name: "SecP256r1MLKEM768", posture: asset.Hybrid, source: "hybrid key exchange"},
	{name: "X25519Kyber768Draft00", posture: asset.Hybrid, source: "hybrid key exchange"},

	{name: "MD5", posture: asset.Broken, source: "RFC 6151"},
	{name: "SHA-1", posture: asset.Broken, source: "CRYPTO 2017"},
	{name: "SHA1", posture: asset.Broken, source: "CRYPTO 2017"},
	{name: "RC4", posture: asset.Broken, source: "RFC 7465"},
	{name: "DES", keySize: 56, posture: asset.Broken, source: "SP 800-131A"},
	{name: "3DES-EDE3-CBC", keySize: 168, posture: asset.Broken, source: "CCS 2016"},
	{name: "TripleDES", keySize: 168, posture: asset.Broken, source: "CCS 2016"},

	{name: "AES-128", keySize: 128, posture: asset.QuantumReduced, source: "Grover 1996"},
	{name: "AES-192", keySize: 192, posture: asset.QuantumReduced, source: "Grover 1996"},
	{name: "AES-256", keySize: 256, posture: asset.QuantumSafe, source: "Grover 1996"},
	{name: "ChaCha20-Poly1305", posture: asset.QuantumSafe, source: "Grover 1996"},
	{name: "SHA-256", posture: asset.QuantumReduced, source: "Brassard"},
	{name: "SHA3-256", posture: asset.QuantumReduced, source: "Brassard"},
	{name: "SHA-384", posture: asset.QuantumSafe, source: "Brassard"},
	{name: "SHA-512", posture: asset.QuantumSafe, source: "Brassard"},
	{name: "HMAC-SHA256", posture: asset.QuantumReduced, source: "Grover 1996"},

	{name: "SSLv3", kind: asset.Protocol, posture: asset.Broken, source: "RFC 7568"},
	{name: "TLS 1.0", kind: asset.Protocol, posture: asset.Broken, source: "RFC 8996"},
	{name: "TLS 1.1", kind: asset.Protocol, posture: asset.Broken, source: "RFC 8996"},
	{name: "TLS 1.2", kind: asset.Protocol, posture: asset.NotApplicable, source: "RFC 5246"},
	{name: "TLS 1.3", kind: asset.Protocol, posture: asset.NotApplicable, source: "RFC 8446"},
}

func TestEveryFixtureGetsTheVerdictItsRowPromises(t *testing.T) {
	for _, f := range fixtures {
		got := Apply(f.asset())
		if got.Posture != f.posture {
			t.Errorf("%s: posture = %s, want %s (%s)", f.name, got.Posture, f.posture, got.Rationale)
		}
		if !strings.Contains(got.Citation, f.source) {
			t.Errorf("%s: citation = %q, want it to name %s", f.name, got.Citation, f.source)
		}
		if got.Rationale == "" {
			t.Errorf("%s: no rationale; a posture nobody can check is not useful", f.name)
		}
	}
}

// A row no fixture reaches is a verdict nobody checks, so the corpus has to
// cover the table rather than a sample of it.
func TestEveryRowIsExercisedByAFixture(t *testing.T) {
	exercised := map[string]bool{}
	for _, f := range fixtures {
		if r, ok := Lookup(f.name, f.asset().Kind); ok {
			exercised[r.Family] = true
		}
	}
	for _, r := range Table {
		if !exercised[r.Family] {
			t.Errorf("no fixture reaches the %s row", r.Family)
		}
	}
}

// Two ways of not knowing: a family with no row, and a row that needs a size
// the finding never stated. Both arrive as unknown and both arrive bare.
func TestFixturesOutsideTheTableStayUnknown(t *testing.T) {
	for _, f := range []fixture{
		{name: "Serpent"},
		{name: "GOST R 34.11-2012"},
		{name: "AES"},
		{name: "SHA"},
		{name: "QUICv1", kind: asset.Protocol},
	} {
		got := Apply(f.asset())
		if got.Posture != asset.PostureUnknown {
			t.Errorf("%s: posture = %s, want unknown", f.name, got.Posture)
		}
		if got.Citation != "" {
			t.Errorf("%s: an unjudged finding cites %q", f.name, got.Citation)
		}
		if got.Rationale == "" {
			t.Errorf("%s: an unknown with no reason is a failure, not an answer", f.name)
		}
	}
}

// Where a size settles the verdict, the finding says which size settled it:
// AES-128 and AES-256 are not one inventory entry.
func TestSizedVerdictsNameTheSizeTheyWereSettledBy(t *testing.T) {
	for _, c := range []struct {
		fixture
		phrase string
	}{
		{fixture{name: "AES", keySize: 128, posture: asset.QuantumReduced}, "64 bits"},
		{fixture{name: "AES", keySize: 256, posture: asset.QuantumSafe}, "128 bits"},
		{fixture{name: "SHA-256", posture: asset.QuantumReduced}, "256-bit digest"},
		{fixture{name: "SHA-512", posture: asset.QuantumSafe}, "170 bits"},
	} {
		got := Apply(c.asset())
		if got.Posture != c.posture {
			t.Errorf("%s-%d: posture = %s, want %s", c.name, c.keySize, got.Posture, c.posture)
		}
		if !strings.Contains(got.Rationale, c.phrase) {
			t.Errorf("%s-%d: rationale = %q, want it to state %s", c.name, c.keySize, got.Rationale, c.phrase)
		}
	}
}
