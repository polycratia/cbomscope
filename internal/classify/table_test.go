package classify

import (
	"strings"
	"testing"

	"github.com/polycratia/cbomscope/internal/asset"
)

// A verdict a reader cannot check against a document is an opinion.
func TestEveryRowCitesItsSource(t *testing.T) {
	for _, r := range Table {
		if r.Family == "" || strings.ToUpper(r.Family) != r.Family {
			t.Errorf("family %q must be uppercase: names are matched uppercased", r.Family)
		}
		if r.Citation == "" {
			t.Errorf("%s: no citation", r.Family)
		}
		if r.Rationale == "" {
			t.Errorf("%s: no rationale", r.Family)
		}
		if r.Posture == "" && r.size == nil {
			t.Errorf("%s: neither a fixed posture nor a size rule", r.Family)
		}
	}
}

func TestClassifiedAssetsCarryTheirCitation(t *testing.T) {
	cases := []struct {
		in   asset.Asset
		want string
	}{
		{asset.Asset{Name: "RSA-2048", Algorithm: "RSA", KeySize: 2048}, "Shor"},
		{asset.Asset{Name: "ML-KEM-768", Algorithm: "ML-KEM-768"}, "FIPS 203"},
		{asset.Asset{Name: "SHA-1", Algorithm: "SHA-1"}, "CRYPTO 2017"},
		{asset.Asset{Name: "SHA-256", Algorithm: "SHA-256"}, "Brassard"},
		{asset.Asset{Name: "AES", Algorithm: "AES", KeySize: 128}, "Grover"},
		{asset.Asset{Name: "TLS 1.0", Kind: asset.Protocol}, "RFC 8996"},
	}
	for _, c := range cases {
		if got := Apply(c.in); !strings.Contains(got.Citation, c.want) {
			t.Errorf("%s: citation = %q, want it to name %s", c.in.Name, got.Citation, c.want)
		}
	}
}

// An answer the table does not have must not arrive with a source attached: a
// citation beside a gap makes the gap look checked.
func TestUnknownsCarryNoCitation(t *testing.T) {
	for _, in := range []asset.Asset{
		{Name: "Serpent", Algorithm: "Serpent"},
		{Name: "AES", Algorithm: "AES"},
		{Name: "QUICv1", Kind: asset.Protocol},
	} {
		got := Apply(in)
		if got.Posture != asset.PostureUnknown {
			t.Errorf("%s: posture = %s, want unknown", in.Name, got.Posture)
		}
		if got.Citation != "" {
			t.Errorf("%s: an unknown cites %q", in.Name, got.Citation)
		}
		if got.Rationale == "" {
			t.Errorf("%s: an unknown with no reason is a failure, not an answer", in.Name)
		}
	}
}

// The longest matching family wins, or SHA-1 would be judged as a digest size.
func TestLongestFamilyWins(t *testing.T) {
	broken, ok := Lookup("SHA-1", asset.Algorithm)
	if !ok || broken.Family != "SHA-1" {
		t.Errorf("SHA-1 matched %q, want the SHA-1 row", broken.Family)
	}
	sized, ok := Lookup("SHA-256", asset.Algorithm)
	if !ok || sized.Family != "SHA" {
		t.Errorf("SHA-256 matched %q, want the SHA row", sized.Family)
	}
	hybrid, ok := Lookup("X25519MLKEM768", asset.Algorithm)
	if !ok || hybrid.Posture != asset.Hybrid {
		t.Errorf("X25519MLKEM768 matched %q, want the hybrid row", hybrid.Family)
	}
}

// A protocol row judges protocol versions and nothing else.
func TestProtocolRowsStayOnProtocols(t *testing.T) {
	if r, ok := Lookup("TLS 1.3", asset.Algorithm); ok {
		t.Errorf("a TLS version matched %q as an algorithm", r.Family)
	}
	if r, ok := Lookup("RSA", asset.Protocol); ok {
		t.Errorf("an algorithm matched %q as a protocol", r.Family)
	}
}

// A row judged by size says so instead of showing an empty verdict.
func TestSizedRowsAreLabelled(t *testing.T) {
	sized, _ := Lookup("AES", asset.Algorithm)
	if sized.PostureLabel() != "by size" {
		t.Errorf("AES label = %q, want \"by size\"", sized.PostureLabel())
	}
	fixed, _ := Lookup("RSA", asset.Algorithm)
	if fixed.PostureLabel() != string(asset.QuantumVulnerable) {
		t.Errorf("RSA label = %q", fixed.PostureLabel())
	}
}
