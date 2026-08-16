package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repo is the directory this test runs in: the tool's own source, which uses
// SHA-256 and is therefore a real thing to scan.
const repo = "../.."

// Go's flag package stops parsing at the first non-flag word. Every one of
// these forms is what a person actually types, and the one that broke first was
// "cbom . -o file".
func TestFlagsAreAcceptedAfterThePositionalArgument(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "cbom.json")

	var buf bytes.Buffer
	if err := run([]string{"cbom", repo, "-o", out}, &buf); err != nil {
		t.Fatalf("cbom <dir> -o <file>: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("document was not written: %v", err)
	}

	buf.Reset()
	if err := run([]string{"scan", repo, "-json"}, &buf); err != nil {
		t.Fatalf("scan <dir> -json: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "[") {
		t.Errorf("-json after the directory was ignored:\n%s", buf.String())
	}
}

func TestScanReportsItsOwnCryptography(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"scan", "-json", repo}, &buf); err != nil {
		t.Fatal(err)
	}
	var assets []struct {
		Name      string `json:"name"`
		Posture   string `json:"posture"`
		Rationale string `json:"rationale"`
		Location  struct {
			File string `json:"file"`
			Line int    `json:"line"`
		} `json:"location"`
	}
	if err := json.Unmarshal(buf.Bytes(), &assets); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(assets) == 0 {
		t.Fatal("scanning this repository found nothing; it hashes with SHA-256")
	}
	for _, a := range assets {
		if a.Posture == "" || a.Rationale == "" {
			t.Errorf("%s carries no verdict or no reason for it", a.Name)
		}
		if a.Location.File == "" || a.Location.Line == 0 {
			t.Errorf("%s has no source position", a.Name)
		}
	}
}

// The gate has to be quiet by default or it gets removed from CI on day one.
func TestGateFailsOnlyOnWhatIsBrokenToday(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"scan", repo}, &buf); err != nil {
		t.Errorf("a repository with no broken cryptography failed the default gate: %v", err)
	}

	buf.Reset()
	err := run([]string{"scan", repo, "-fail-on", "quantum_reduced"}, &buf)
	var code exitCode
	if !errors.As(err, &code) || int(code) != 1 {
		t.Errorf("err = %v, want exit 1 when the chosen posture is present", err)
	}

	buf.Reset()
	if err := run([]string{"scan", repo, "-fail-on", "none"}, &buf); err != nil {
		t.Errorf("-fail-on none still failed: %v", err)
	}
}

func TestGateRejectsAPostureThatDoesNotExist(t *testing.T) {
	var buf bytes.Buffer
	err := run([]string{"scan", repo, "-fail-on", "probably_fine"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "not a posture") {
		t.Errorf("err = %v, want a message listing the real postures", err)
	}
}

func TestCommandsValidateTheirArguments(t *testing.T) {
	cases := [][]string{
		{"scan"},
		{"scan", repo, repo},
		{"probe"},
		{"probe", "example.com"}, // no port
		{"cbom"},
		{"frobnicate"},
	}
	for _, args := range cases {
		var buf bytes.Buffer
		if err := run(args, &buf); err == nil {
			t.Errorf("%v was accepted, want an error", args)
		}
	}
}

func TestNoArgumentsPrintsUsage(t *testing.T) {
	var buf bytes.Buffer
	if err := run(nil, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "cbomscope scan") {
		t.Errorf("usage does not describe the commands:\n%s", buf.String())
	}
}
