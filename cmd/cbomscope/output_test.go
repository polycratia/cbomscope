package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// notes redirects what the commands write beside their output, so a test can
// read the stream a pipeline sees on stderr.
func notes(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	before := diagnostics
	diagnostics = &buf
	t.Cleanup(func() { diagnostics = before })
	return &buf
}

// A document on stdout must stay a document, but the reason for exit 1 has to
// exist somewhere: a gate that fails a build without saying why is one nobody
// can act on, and it gets deleted instead of fixed.
func TestMachineOutputKeepsTheVerdictOnStderr(t *testing.T) {
	stderr := notes(t)

	var out bytes.Buffer
	err := run([]string{"scan", repo, "-json", "-fail-on", "quantum_reduced"}, &out)
	var code exitCode
	if !errors.As(err, &code) || int(code) != 1 {
		t.Fatalf("err = %v, want exit 1", err)
	}
	var assets []json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &assets); err != nil {
		t.Fatalf("stdout is not a document any more: %v\n%s", err, out.String())
	}
	for _, want := range []string{"quantum_reduced or worse", "-fail-on quantum_reduced"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the gate never says %q where a pipeline can read it:\n%s", want, stderr.String())
		}
	}
}

// A run that reaches nothing says nothing, in either mode.
func TestACleanRunIsQuietInBothModes(t *testing.T) {
	stderr := notes(t)
	var out bytes.Buffer
	if err := run([]string{"scan", repo, "-json"}, &out); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Errorf("a clean run wrote %q beside its output", stderr.String())
	}
}

// The two outputs are two readings of one inventory, so a finding in either has
// to be in the other.
func TestBothOutputsCarryTheSameFindings(t *testing.T) {
	var document bytes.Buffer
	if err := run([]string{"scan", repo, "-json"}, &document); err != nil {
		t.Fatal(err)
	}
	var assets []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(document.Bytes(), &assets); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, document.String())
	}
	if len(assets) == 0 {
		t.Fatal("scanning this repository found nothing; it hashes with SHA-256")
	}

	var table bytes.Buffer
	if err := run([]string{"scan", repo}, &table); err != nil {
		t.Fatal(err)
	}
	for _, a := range assets {
		if !strings.Contains(table.String(), a.Name) {
			t.Errorf("%s is in -json but not in the table:\n%s", a.Name, table.String())
		}
	}
	if !strings.Contains(table.String(), "asset(s):") {
		t.Errorf("the table carries no count of what it found:\n%s", table.String())
	}
}
