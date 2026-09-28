package plan

import (
	"slices"
	"strings"
	"testing"

	"github.com/polycratia/cbomscope/internal/asset"
)

func inFile(path string) asset.Location { return asset.Location{File: path, Line: 1} }

func onWire(host string) asset.Location { return asset.Location{Host: host} }

func names(items []Item) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Asset.Name)
	}
	return out
}

// The whole reason for the formula: three assets with the same posture are not
// the same piece of work.
func TestExposureAndLifetimeSeparateEqualPostures(t *testing.T) {
	report := Build([]asset.Asset{
		{
			Name: "dependency-signature", Posture: asset.QuantumVulnerable,
			Primitive: asset.Signature, Module: "example.com/dep@v1.0.0",
			Location: inFile("example.com/dep@v1.0.0/sign.go"),
		},
		{
			Name: "endpoint-key-exchange", Posture: asset.QuantumVulnerable,
			Primitive: asset.KeyAgree, Location: onWire("api.example.com:443"),
		},
		{
			Name: "first-party-signature", Posture: asset.QuantumVulnerable,
			Primitive: asset.Signature, Location: inFile("internal/token/sign.go"),
		},
	})
	want := []string{"endpoint-key-exchange", "first-party-signature", "dependency-signature"}
	if got := names(report.Items); !slices.Equal(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
	if report.Items[0].Score != 18 {
		t.Errorf("score = %d, want 18: 3 × (3 + 3)", report.Items[0].Score)
	}
}

// An unjudged asset sits in the middle: ranked last it would read as safe,
// ranked first a gap would outweigh a known problem.
func TestPostureOrdersAssetsThatShareAContext(t *testing.T) {
	same := func(name string, posture asset.Posture) asset.Asset {
		return asset.Asset{
			Name: name, Posture: posture, Primitive: asset.Hash,
			Location: inFile("internal/digest/" + name + ".go"),
		}
	}
	report := Build([]asset.Asset{
		same("reduced", asset.QuantumReduced),
		same("unjudged", asset.PostureUnknown),
		same("vulnerable", asset.QuantumVulnerable),
		same("brokentoday", asset.Broken),
	})
	want := []string{"brokentoday", "vulnerable", "unjudged", "reduced"}
	if got := names(report.Items); !slices.Equal(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

// Assets with nothing to migrate are reported as such. Dropping them would make
// the report read exactly like one that never examined them.
func TestSettledAssetsAreCountedNotDropped(t *testing.T) {
	report := Build([]asset.Asset{
		{Name: "ML-KEM-768", Posture: asset.QuantumSafe, Primitive: asset.KEM},
		{Name: "X25519MLKEM768", Posture: asset.Hybrid, Primitive: asset.KeyAgree},
		{Name: "TLS 1.3", Kind: asset.Protocol, Posture: asset.NotApplicable},
		{Name: "RSA-2048", Posture: asset.QuantumVulnerable, Primitive: asset.PKE},
	})
	if len(report.Items) != 1 || report.Items[0].Asset.Name != "RSA-2048" {
		t.Fatalf("ranked %v, want only the asset with work to do", names(report.Items))
	}
	if len(report.Settled) != 3 {
		t.Errorf("settled = %+v, want the three assets that need no migration", report.Settled)
	}
}

// A posture nobody set is a gap, not an answer.
func TestAnUnjudgedAssetIsRankedRatherThanSettled(t *testing.T) {
	report := Build([]asset.Asset{
		{Name: "Serpent", Posture: asset.PostureUnknown},
		{Name: "never-classified"},
	})
	if len(report.Items) != 2 {
		t.Fatalf("ranked %v, want both: neither has been judged safe", names(report.Items))
	}
	for _, item := range report.Items {
		if item.Posture.Weight != unjudged.Weight {
			t.Errorf("%s: posture weight = %d, want the unjudged weight", item.Asset.Name, item.Posture.Weight)
		}
	}
}

// Two listings over unchanged code have to be diffable, so the input order must
// not reach the output.
func TestOrderIsReproducible(t *testing.T) {
	in := []asset.Asset{
		{Name: "SHA-256", Posture: asset.QuantumReduced, Primitive: asset.Hash, Location: inFile("b.go")},
		{Name: "SHA-256", Posture: asset.QuantumReduced, Primitive: asset.Hash, Location: inFile("a.go")},
		{Name: "MD5-ish", Posture: asset.QuantumReduced, Primitive: asset.Hash, Location: inFile("c.go")},
	}
	lines := func(r Report) []string {
		out := make([]string, 0, len(r.Items))
		for _, item := range r.Items {
			out = append(out, item.Asset.Name+" "+item.Asset.Location.String())
		}
		return out
	}

	reversed := slices.Clone(in)
	slices.Reverse(reversed)
	first, second := lines(Build(in)), lines(Build(reversed))
	if !slices.Equal(first, second) {
		t.Errorf("input order reached the output: %v vs %v", first, second)
	}
	want := []string{"MD5-ish c.go:1", "SHA-256 a.go:1", "SHA-256 b.go:1"}
	if !slices.Equal(first, want) {
		t.Errorf("order = %v, want ties settled by name then position: %v", first, want)
	}
}

// A rank nobody can recompute is an opinion.
func TestEveryItemExplainsItsOwnScore(t *testing.T) {
	report := Build([]asset.Asset{
		{Name: "RSA-2048", Posture: asset.QuantumVulnerable, Primitive: asset.PKE, Location: inFile("sign.go")},
		{Name: "MD5", Posture: asset.Broken, Primitive: asset.Hash, Module: "example.com/dep@v1.0.0"},
		{Name: "X25519", Posture: asset.QuantumVulnerable, Primitive: asset.KeyAgree, Location: onWire("api.example.com:443")},
	})
	for _, item := range report.Items {
		if want := item.Posture.Weight * (item.Exposure.Weight + item.Lifetime.Weight); item.Score != want {
			t.Errorf("%s: score = %d, want %d from its own factors", item.Asset.Name, item.Score, want)
		}
		for _, f := range []Factor{item.Posture, item.Exposure, item.Lifetime} {
			if f.Name == "" || f.Reason == "" || f.Weight < 1 {
				t.Errorf("%s: factor %+v carries no name, no weight or no reason", item.Asset.Name, f)
			}
			if !strings.Contains(item.Arithmetic(), f.Name) {
				t.Errorf("%s: arithmetic %q never names %q", item.Asset.Name, item.Arithmetic(), f.Name)
			}
		}
	}
	if report.Formula != Formula {
		t.Errorf("formula = %q, want the rule the scores were produced by", report.Formula)
	}
}

func TestTheScaleIsPublishedWithItsReasons(t *testing.T) {
	if len(Scale) != 3 {
		t.Fatalf("got %d dimensions, want posture, exposure and lifetime", len(Scale))
	}
	for _, d := range Scale {
		if len(d.Factors) == 0 {
			t.Errorf("%s: no factors", d.Name)
		}
		seen := map[int]bool{}
		for _, f := range d.Factors {
			if f.Name == "" || f.Reason == "" {
				t.Errorf("%s: factor %+v has no name or no reason", d.Name, f)
			}
			if f.Weight < 1 {
				t.Errorf("%s: %s weighs %d; a factor that adds nothing is not a factor", d.Name, f.Name, f.Weight)
			}
			if seen[f.Weight] {
				t.Errorf("%s: weight %d appears twice; two factors that score the same are one factor", d.Name, f.Weight)
			}
			seen[f.Weight] = true
		}
	}
}
