package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/polycratia/cbomscope/internal/asset"
)

// fixture copies one of the stored source texts into a real .go file, since the
// scanner walks directories looking for that extension.
func fixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample", name))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "crypto.go"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func scanFixture(t *testing.T, name string) map[string]asset.Asset {
	t.Helper()
	found, err := Dir(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return byName(found)
}

func byName(assets []asset.Asset) map[string]asset.Asset {
	out := make(map[string]asset.Asset, len(assets))
	for _, a := range assets {
		out[a.Name] = a
	}
	return out
}

func TestDirReadsParametersOutOfTheCall(t *testing.T) {
	index := scanFixture(t, "crypto.go.txt")

	rsa2048, ok := index["RSA-2048"]
	if !ok {
		t.Fatalf("RSA-2048 not found; got %v", keys(index))
	}
	if rsa2048.KeySize != 2048 || rsa2048.Primitive != asset.PKE {
		t.Errorf("RSA-2048 = %+v, want a 2048-bit public-key asset", rsa2048)
	}
	if rsa2048.Location.Line == 0 {
		t.Error("finding has no line number; the reader cannot check it by hand")
	}

	ecdsaKey, ok := index["ECDSA-P256"]
	if !ok {
		t.Fatalf("ECDSA-P256 not found; got %v", keys(index))
	}
	if ecdsaKey.Curve != "P256" || ecdsaKey.KeySize != 256 {
		t.Errorf("ECDSA = %+v, want the curve read from elliptic.P256()", ecdsaKey)
	}
}

// The honest half: a size that only exists at run time is left unset rather
// than filled with a plausible default.
func TestDirLeavesRuntimeParametersUnset(t *testing.T) {
	found, err := Dir(fixture(t, "crypto.go.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var bare int
	for _, a := range found {
		if a.Algorithm == "RSA" && a.KeySize == 0 && a.Name == "RSA" {
			bare++
		}
	}
	if bare != 1 {
		t.Errorf("got %d RSA findings with an undetermined size, want exactly 1", bare)
	}
}

func TestDirFollowsImportAliases(t *testing.T) {
	if _, ok := scanFixture(t, "crypto.go.txt")["MD5"]; !ok {
		t.Error("MD5 imported under an alias was missed")
	}
}

// A tls.Config is configuration rather than a call: what the code asks for,
// against what a handshake later negotiates.
func TestDirReadsATLSConfigLiteral(t *testing.T) {
	index := scanFixture(t, "tlsconfig.go.txt")

	minimum, ok := index["TLS 1.2"]
	if !ok {
		t.Fatalf("MinVersion was not read as a protocol asset; got %v", keys(index))
	}
	if minimum.Kind != asset.Protocol || !strings.Contains(minimum.Evidence, "MinVersion") {
		t.Errorf("MinVersion = %+v, want a protocol asset naming the field it came from", minimum)
	}
	if minimum.Location.Line == 0 {
		t.Error("the configured version has no line number")
	}
	if _, ok := index["TLS 1.3"]; !ok {
		t.Errorf("MaxVersion was not read; got %v", keys(index))
	}

	// The suite name is the only place the cipher is stated, and it is read the
	// same way here as it is off a handshake.
	suite, ok := index["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
	if !ok {
		t.Fatalf("a configured cipher suite was not read; got %v", keys(index))
	}
	if suite.Algorithm != "AES" || suite.KeySize != 128 || suite.Mode != asset.GCM {
		t.Errorf("suite = %+v, want AES at 128 bits in GCM", suite)
	}
	if !strings.Contains(suite.Evidence, "CipherSuites") {
		t.Errorf("evidence = %q, want the field it was read from", suite.Evidence)
	}
	legacy, ok := index["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]
	if !ok {
		t.Fatalf("a configured 3DES suite was not read; got %v", keys(index))
	}
	if legacy.Algorithm != "3DES" || legacy.KeySize != 168 {
		t.Errorf("3DES suite = %+v, want 3DES at 168 bits", legacy)
	}

	hybrid, ok := index["X25519MLKEM768"]
	if !ok {
		t.Fatalf("a configured key exchange group was not read; got %v", keys(index))
	}
	if hybrid.Primitive != asset.KeyAgree || !strings.Contains(hybrid.Evidence, "CurvePreferences") {
		t.Errorf("group = %+v, want a key agreement asset naming the field", hybrid)
	}
	if _, ok := index["ECDH-P256"]; !ok {
		t.Errorf("tls.CurveP256 was not read as a group; got %v", keys(index))
	}
}

// A field assembled somewhere else is in the inventory with no value attached:
// the default the library would have chosen is not what this code configures.
func TestDirReportsAConfiguredFieldItCannotSee(t *testing.T) {
	index := scanFixture(t, "tlsconfig.go.txt")

	unstated, ok := index["unstated TLS version"]
	if !ok {
		t.Fatalf("a MinVersion set from a variable was dropped; got %v", keys(index))
	}
	if unstated.Kind != asset.Protocol || unstated.Location.Line == 0 {
		t.Errorf("undetermined version = %+v, want a protocol asset with a position", unstated)
	}
	for _, want := range []string{"MinVersion", "not determined"} {
		if !strings.Contains(unstated.Evidence, want) {
			t.Errorf("evidence = %q, want it to say %q", unstated.Evidence, want)
		}
	}
}

// The literal has to be a crypto/tls one: another package's Config that
// happens to have a MinVersion field is not cryptography.
func TestDirReadsOnlyATLSConfig(t *testing.T) {
	dir := t.TempDir()
	const source = `package p

import (
	"crypto/tls"

	"example.com/transport"
)

var _ = transport.Config{MinVersion: tls.VersionTLS10}
`
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := Dir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("found %+v, want nothing: the field belongs to another package's type", found)
	}
}

// Reading syntax rather than text is the whole reason this is an AST scanner.
func TestDirIgnoresMentionsInStringsAndComments(t *testing.T) {
	dir := t.TempDir()
	const source = `package p

// rsa.GenerateKey(rand.Reader, 4096) in a comment is not a call.
var note = "aes.NewCipher(key)"
`
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := Dir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("found %+v, want nothing: neither a comment nor a string is a call", found)
	}
}

func TestDirSkipsVendoredCode(t *testing.T) {
	dir := t.TempDir()
	vendored := filepath.Join(dir, "vendor", "example.com", "lib")
	if err := os.MkdirAll(vendored, 0o755); err != nil {
		t.Fatal(err)
	}
	const source = `package lib

import (
	"crypto/md5"
)

func h() any { return md5.New() }
`
	if err := os.WriteFile(filepath.Join(vendored, "lib.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := Dir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("found %+v in vendor/, which is somebody else's inventory", found)
	}
}

func TestFileReportsBrokenSyntax(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.go")
	if err := os.WriteFile(path, []byte("package p\nfunc ("), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := File(path); err == nil {
		t.Error("a file that does not parse was accepted silently")
	}
}

func keys(m map[string]asset.Asset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
