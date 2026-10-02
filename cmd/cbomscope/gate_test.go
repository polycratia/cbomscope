package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/polycratia/cbomscope/internal/asset"
)

// graded covers every rung of the ladder and both kinds of asset that imply no
// work at all.
var graded = []asset.Asset{
	{Name: "MD5", Posture: asset.Broken},
	{Name: "RSA-2048", Posture: asset.QuantumVulnerable},
	{Name: "Serpent", Posture: asset.PostureUnknown},
	{Name: "SHA-256", Posture: asset.QuantumReduced},
	{Name: "ML-KEM-768", Posture: asset.QuantumSafe},
	{Name: "TLS 1.3", Posture: asset.NotApplicable},
}

// The gate is a policy, not one posture: naming a rung has to catch everything
// standing above it, or a pipeline has to list the postures it fears and misses
// the next one that gets added.
func TestGateTripsOnEverythingAtLeastAsSeriousAsItsRung(t *testing.T) {
	for _, c := range []struct {
		failOn string
		want   int
	}{
		{"broken", 1},
		{"quantum_vulnerable", 2},
		{"unknown", 3},
		{"quantum_reduced", 4},
		{"none", 0},
		{"", 0},
	} {
		threshold, err := parseGate(c.failOn)
		if err != nil {
			t.Fatalf("-fail-on %q: %v", c.failOn, err)
		}
		if got := tripped(graded, threshold); len(got) != c.want {
			t.Errorf("-fail-on %q caught %d asset(s), want %d: %+v", c.failOn, len(got), c.want, got)
		}
	}
}

// Failing on a posture that implies no work would fail a build for having
// migrated, so it is refused rather than quietly accepted.
func TestGateRefusesARungThatImpliesNoWork(t *testing.T) {
	for _, failOn := range []string{"quantum_safe", "hybrid", "not_applicable"} {
		if _, err := parseGate(failOn); err == nil {
			t.Errorf("-fail-on %s was accepted", failOn)
		}
	}
}

// The two outputs have to stay two. A gate that appends its verdict to a
// document breaks every reader of that document.
func TestTheGateStaysOutOfMachineOutput(t *testing.T) {
	var buf bytes.Buffer
	err := run([]string{"scan", repo, "-json", "-fail-on", "quantum_reduced"}, &buf)
	var code exitCode
	if !errors.As(err, &code) || int(code) != 1 {
		t.Fatalf("err = %v, want exit 1", err)
	}
	var assets []asset.Asset
	if err := json.Unmarshal(buf.Bytes(), &assets); err != nil {
		t.Fatalf("the gate wrote prose into the JSON: %v\n%s", err, buf.String())
	}

	buf.Reset()
	if err := run([]string{"scan", repo, "-fail-on", "quantum_reduced"}, &buf); err == nil {
		t.Fatal("err = nil, want exit 1")
	}
	for _, want := range []string{"quantum_reduced or worse", "-fail-on quantum_reduced"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the printed gate never says %q:\n%s", want, buf.String())
		}
	}
}

// One policy for every command that takes an inventory, and the artifact is
// written before the gate is applied: a run that fails the build still wants
// the document it just produced.
func TestEveryInventoryCommandCarriesTheSameGate(t *testing.T) {
	document := filepath.Join(t.TempDir(), "cbom.json")
	for _, args := range [][]string{
		{"scan", repo, "-fail-on", "quantum_reduced"},
		{"plan", repo, "-fail-on", "quantum_reduced"},
		{"cbom", repo, "-fail-on", "quantum_reduced", "-o", document},
	} {
		var buf bytes.Buffer
		var code exitCode
		if err := run(args, &buf); !errors.As(err, &code) || int(code) != 1 {
			t.Errorf("%v: err = %v, want exit 1", args, err)
		}
	}
	body, err := os.ReadFile(document)
	if err != nil {
		t.Fatalf("the gate ate the document: %v", err)
	}
	var doc struct {
		Components []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || len(doc.Components) == 0 {
		t.Fatalf("the written document is empty or invalid: %v", err)
	}
}
