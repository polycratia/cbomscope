package cbom

import (
	"testing"
	"time"

	"github.com/polycratia/cbomscope/internal/asset"
)

func propertiesOf(t *testing.T, a asset.Asset) *AlgorithmProperties {
	t.Helper()
	a.Kind = asset.Algorithm
	props := Build([]asset.Asset{a}, time.Now()).Components[0].CryptoProperties.AlgorithmProperties
	if props == nil {
		t.Fatalf("%s carries no algorithmProperties", a.Name)
	}
	return props
}

// A plan is written from the primitive, the size and the mode, not from the
// component name.
func TestAlgorithmPropertiesCarryTheParameters(t *testing.T) {
	cipher := propertiesOf(t, asset.Asset{
		Name: "TLS_AES_256_GCM_SHA384", Primitive: asset.AE,
		Algorithm: "AES", KeySize: 256, Mode: asset.GCM,
	})
	if cipher.Primitive != "ae" || cipher.Mode != "gcm" {
		t.Errorf("primitive/mode = %q/%q, want ae/gcm", cipher.Primitive, cipher.Mode)
	}
	if cipher.ParameterSetIdentifier != "256" {
		t.Errorf("parameterSetIdentifier = %q, want 256", cipher.ParameterSetIdentifier)
	}
	if cipher.NISTQuantumSecurityLevel != 5 {
		t.Errorf("nistQuantumSecurityLevel = %d, want 5: AES-256 defines category 5",
			cipher.NISTQuantumSecurityLevel)
	}

	curve := propertiesOf(t, asset.Asset{
		Name: "ECDSA-P-256", Primitive: asset.Signature,
		Algorithm: "ECDSA", Curve: "P-256", KeySize: 256,
	})
	if curve.Curve != "P-256" {
		t.Errorf("curve = %q, want P-256", curve.Curve)
	}

	kem := propertiesOf(t, asset.Asset{Name: "ML-KEM-768", Primitive: asset.KEM, Algorithm: "ML-KEM-768"})
	if kem.NISTQuantumSecurityLevel != 3 {
		t.Errorf("nistQuantumSecurityLevel = %d, want 3", kem.NISTQuantumSecurityLevel)
	}
}

// The key size is not the security level, and where the level is not published
// it is left out rather than interpolated.
func TestSecurityLevelIsNotTheKeySize(t *testing.T) {
	cases := []struct {
		in   asset.Asset
		want int
	}{
		{asset.Asset{Algorithm: "RSA", KeySize: 2048, Primitive: asset.PKE}, 112},
		{asset.Asset{Algorithm: "RSA", KeySize: 3072, Primitive: asset.PKE}, 128},
		{asset.Asset{Algorithm: "RSA", KeySize: 4096, Primitive: asset.PKE}, 0},
		{asset.Asset{Algorithm: "ECDSA", KeySize: 256, Primitive: asset.Signature}, 128},
		{asset.Asset{Algorithm: "Ed25519", KeySize: 256, Primitive: asset.Signature}, 128},
		{asset.Asset{Algorithm: "AES", KeySize: 128, Primitive: asset.BlockCipher}, 128},
		{asset.Asset{Algorithm: "3DES", KeySize: 168, Primitive: asset.BlockCipher}, 112},
		{asset.Asset{Algorithm: "AES", Primitive: asset.BlockCipher}, 0},
		{asset.Asset{Algorithm: "SHA-256", Primitive: asset.Hash}, 0},
	}
	for _, c := range cases {
		if got := propertiesOf(t, c.in).ClassicalSecurityLevel; got != c.want {
			t.Errorf("%s-%d: classicalSecurityLevel = %d, want %d",
				c.in.Algorithm, c.in.KeySize, got, c.want)
		}
	}
}

// A finding that stated no mode must not acquire one on the way out.
func TestUnstatedParametersStayOut(t *testing.T) {
	props := propertiesOf(t, asset.Asset{Name: "RSA", Algorithm: "RSA", Primitive: asset.PKE})
	if props.Mode != "" || props.Curve != "" || props.ParameterSetIdentifier != "" {
		t.Errorf("props = %+v, want the undetermined fields absent", props)
	}
}
