package cbom

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/polycratia/cbomscope/internal/asset"
)

func sample() []asset.Asset {
	return []asset.Asset{
		{
			Name: "RSA-2048", Kind: asset.Algorithm, Primitive: asset.PKE,
			Algorithm: "RSA", KeySize: 2048,
			Posture: asset.QuantumVulnerable, Rationale: "Shor's algorithm solves the underlying factoring",
			Location: asset.Location{File: "internal/token/sign.go", Line: 42},
			Evidence: "rsa.GenerateKey() with 2048 bits",
		},
		{
			Name: "TLS 1.3", Kind: asset.Protocol,
			Posture:  asset.PostureUnknown,
			Location: asset.Location{Host: "api.example.com:443"},
		},
	}
}

func TestBuildShape(t *testing.T) {
	doc := Build(sample(), time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC))
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" {
		t.Errorf("header = %s %s, want CycloneDX 1.6", doc.BOMFormat, doc.SpecVersion)
	}
	if doc.Metadata.Timestamp != "2026-08-16T12:00:00Z" {
		t.Errorf("timestamp = %q, want RFC3339 in UTC", doc.Metadata.Timestamp)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("got %d components, want 2", len(doc.Components))
	}
	for _, c := range doc.Components {
		if c.Type != "cryptographic-asset" {
			t.Errorf("%s: type = %q, want cryptographic-asset", c.Name, c.Type)
		}
	}
}

// The posture is ours, not the spec's, so it must travel as a namespaced
// property. Writing it into a standard field would make the document lie to
// anything reading it by the spec.
func TestPostureTravelsAsANamespacedProperty(t *testing.T) {
	doc := Build(sample(), time.Now())
	body, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}

	var round struct {
		Components []struct {
			Name             string `json:"name"`
			CryptoProperties struct {
				AssetType           string `json:"assetType"`
				AlgorithmProperties *struct {
					Primitive              string `json:"primitive"`
					ParameterSetIdentifier string `json:"parameterSetIdentifier"`
				} `json:"algorithmProperties"`
			} `json:"cryptoProperties"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
			Evidence *struct {
				Occurrences []struct {
					Location string `json:"location"`
				} `json:"occurrences"`
			} `json:"evidence"`
		} `json:"components"`
	}
	if err := json.Unmarshal(body, &round); err != nil {
		t.Fatalf("document is not valid JSON: %v", err)
	}

	first := round.Components[0]
	if first.CryptoProperties.AssetType != "algorithm" {
		t.Errorf("assetType = %q, want algorithm", first.CryptoProperties.AssetType)
	}
	if first.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "2048" {
		t.Errorf("parameterSetIdentifier = %q, want 2048",
			first.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier)
	}
	found := map[string]string{}
	for _, p := range first.Properties {
		found[p.Name] = p.Value
	}
	if found["cbomscope:posture"] != "quantum_vulnerable" {
		t.Errorf("posture property = %q", found["cbomscope:posture"])
	}
	if found["cbomscope:rationale"] == "" {
		t.Error("rationale did not survive into the document")
	}
	if first.Evidence == nil || first.Evidence.Occurrences[0].Location != "internal/token/sign.go:42" {
		t.Errorf("occurrence = %+v, want the source position", first.Evidence)
	}
}

// Two scans of unchanged code must produce documents that can be diffed.
func TestReferencesAreStableAcrossRuns(t *testing.T) {
	first := Build(sample(), time.Now())
	second := Build(sample(), time.Now().Add(time.Hour))
	for i := range first.Components {
		if first.Components[i].BOMRef != second.Components[i].BOMRef {
			t.Errorf("component %d: bom-ref changed between runs", i)
		}
	}

	moved := sample()
	moved[0].Location.Line = 43
	if Build(moved, time.Now()).Components[0].BOMRef == first.Components[0].BOMRef {
		t.Error("an asset found somewhere else kept the same bom-ref")
	}
}

// A protocol has no key size and no primitive; the writer must not invent them.
func TestProtocolCarriesNoAlgorithmProperties(t *testing.T) {
	doc := Build(sample(), time.Now())
	protocol := doc.Components[1]
	if protocol.CryptoProperties.AssetType != "protocol" {
		t.Errorf("assetType = %q, want protocol", protocol.CryptoProperties.AssetType)
	}
	if protocol.CryptoProperties.AlgorithmProperties != nil {
		t.Errorf("algorithmProperties = %+v, want none on a protocol",
			protocol.CryptoProperties.AlgorithmProperties)
	}
}
