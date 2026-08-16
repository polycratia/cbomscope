package classify

import (
	"strings"
	"testing"

	"github.com/polycratia/cbomscope/internal/asset"
)

func TestApplyPostures(t *testing.T) {
	cases := []struct {
		in   asset.Asset
		want asset.Posture
	}{
		{asset.Asset{Name: "RSA-2048", Algorithm: "RSA", KeySize: 2048}, asset.QuantumVulnerable},
		{asset.Asset{Name: "RSA-4096", Algorithm: "RSA", KeySize: 4096}, asset.QuantumVulnerable},
		{asset.Asset{Name: "ECDSA-P384", Algorithm: "ECDSA", KeySize: 384}, asset.QuantumVulnerable},
		{asset.Asset{Name: "Ed25519", Algorithm: "Ed25519"}, asset.QuantumVulnerable},
		{asset.Asset{Name: "X25519", Algorithm: "X25519"}, asset.QuantumVulnerable},
		{asset.Asset{Name: "MD5", Algorithm: "MD5"}, asset.Broken},
		{asset.Asset{Name: "SHA-1", Algorithm: "SHA-1"}, asset.Broken},
		{asset.Asset{Name: "3DES", Algorithm: "3DES"}, asset.Broken},
		{asset.Asset{Name: "AES", Algorithm: "AES", KeySize: 128}, asset.QuantumReduced},
		{asset.Asset{Name: "AES", Algorithm: "AES", KeySize: 256}, asset.QuantumSafe},
		{asset.Asset{Name: "ChaCha20-Poly1305", Algorithm: "ChaCha20-Poly1305", KeySize: 256}, asset.QuantumSafe},
		{asset.Asset{Name: "SHA-256", Algorithm: "SHA-256"}, asset.QuantumReduced},
		{asset.Asset{Name: "SHA-384", Algorithm: "SHA-384"}, asset.QuantumSafe},
		{asset.Asset{Name: "ML-KEM-768", Algorithm: "ML-KEM-768"}, asset.QuantumSafe},
		{asset.Asset{Name: "X25519MLKEM768", Algorithm: "X25519MLKEM768"}, asset.Hybrid},
	}
	for _, c := range cases {
		got := Apply(c.in)
		if got.Posture != c.want {
			t.Errorf("%s: posture = %s, want %s (%s)", c.in.Name, got.Posture, c.want, got.Rationale)
		}
		if got.Rationale == "" {
			t.Errorf("%s: no rationale; a posture nobody can check is not useful", c.in.Name)
		}
	}
}

// A protocol version is not the thing a quantum computer attacks, and saying
// "unknown" about TLS 1.3 would send a person to look at something fine.
func TestProtocolVersionsAreJudgedOnTheirOwnTerms(t *testing.T) {
	current := Apply(asset.Asset{Name: "TLS 1.3", Kind: asset.Protocol})
	if current.Posture != asset.NotApplicable {
		t.Errorf("TLS 1.3 = %s, want not_applicable", current.Posture)
	}
	if !strings.Contains(current.Rationale, "key exchange") {
		t.Errorf("rationale = %q, want it to point at what does carry the posture", current.Rationale)
	}

	old := Apply(asset.Asset{Name: "TLS 1.0", Kind: asset.Protocol})
	if old.Posture != asset.Broken {
		t.Errorf("TLS 1.0 = %s, want broken: it is deprecated today, quantum aside", old.Posture)
	}
}

// Two ways of not knowing, both of which must survive to the report.
func TestApplyAdmitsWhatItCannotJudge(t *testing.T) {
	unmapped := Apply(asset.Asset{Name: "Serpent", Algorithm: "Serpent"})
	if unmapped.Posture != asset.PostureUnknown {
		t.Errorf("posture = %s, want unknown for an algorithm outside the table", unmapped.Posture)
	}
	if !strings.Contains(unmapped.Rationale, "by hand") {
		t.Errorf("rationale = %q, want it to say a person has to judge this", unmapped.Rationale)
	}

	sizeless := Apply(asset.Asset{Name: "AES", Algorithm: "AES"})
	if sizeless.Posture != asset.PostureUnknown {
		t.Errorf("posture = %s, want unknown: AES-128 and AES-256 do not share a verdict", sizeless.Posture)
	}
}

// Hybrid must not collapse into either half: its whole point is that it holds
// if either one holds.
func TestHybridIsItsOwnAnswer(t *testing.T) {
	got := Apply(asset.Asset{Name: "X25519MLKEM768", Algorithm: "X25519MLKEM768"})
	if got.Posture != asset.Hybrid {
		t.Fatalf("posture = %s, want hybrid", got.Posture)
	}
	if !strings.Contains(got.Rationale, "either") {
		t.Errorf("rationale = %q, want it to explain the guarantee", got.Rationale)
	}
}

func TestApplyAllKeepsOrder(t *testing.T) {
	in := []asset.Asset{
		{Name: "MD5", Algorithm: "MD5"},
		{Name: "AES", Algorithm: "AES", KeySize: 256},
	}
	got := ApplyAll(in)
	if len(got) != 2 || got[0].Name != "MD5" || got[1].Name != "AES" {
		t.Fatalf("ApplyAll reordered its input: %+v", got)
	}
	if in[0].Posture != "" {
		t.Error("ApplyAll mutated the caller's slice")
	}
}
