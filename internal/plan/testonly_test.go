package plan

import (
	"testing"

	"github.com/polycratia/cbomscope/internal/asset"
)

// The pair the package doc opens with: the same key, once in shipped code and
// once in a test helper. Only the first is work.
func TestTestOnlyAssetsLeaveTheRanking(t *testing.T) {
	shipped := asset.Asset{
		Name: "RSA-2048", Kind: asset.Algorithm, Primitive: asset.PKE,
		Posture:  asset.QuantumVulnerable,
		Location: asset.Location{File: "internal/token/sign.go", Line: 41},
	}
	inTest := asset.Asset{
		Name: "RSA-2048", Kind: asset.Algorithm, Primitive: asset.PKE,
		Posture: asset.QuantumVulnerable, TestOnly: true,
		Location: asset.Location{File: "internal/token/sign_test.go", Line: 12},
	}

	report := Build([]asset.Asset{shipped, inTest})
	if len(report.Items) != 1 || report.Items[0].Asset.Location.File != "internal/token/sign.go" {
		t.Fatalf("items = %+v, want only the key that ships", report.Items)
	}
	if len(report.TestOnly) != 1 || report.TestOnly[0].Location.File != "internal/token/sign_test.go" {
		t.Fatalf("test-only = %+v, want the key from the test file", report.TestOnly)
	}
	if len(report.Settled) != 0 {
		t.Errorf("settled = %+v: test code is not migrated work, it is work nobody has", report.Settled)
	}
}

// Counted rather than dropped: a tree whose only cryptography is in its tests
// must not report an empty inventory.
func TestTestOnlyFindingsAreStillReported(t *testing.T) {
	report := Build([]asset.Asset{{
		Name: "MD5", Kind: asset.Algorithm, Primitive: asset.Hash,
		Posture: asset.Broken, TestOnly: true,
		Location: asset.Location{File: "internal/hash/hash_test.go", Line: 7},
	}})
	if len(report.Items) != 0 {
		t.Errorf("items = %+v, want nothing ranked", report.Items)
	}
	if len(report.TestOnly) != 1 {
		t.Fatalf("test-only = %+v, want the one finding", report.TestOnly)
	}
}
