package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/polycratia/cbomscope/internal/asset"
)

// fixture copies the stored source text into a real .go file, since the scanner
// walks directories looking for that extension.
func fixture(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample", "crypto.go.txt"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "crypto.go"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func byName(assets []asset.Asset) map[string]asset.Asset {
	out := make(map[string]asset.Asset, len(assets))
	for _, a := range assets {
		out[a.Name] = a
	}
	return out
}

func TestDirReadsParametersOutOfTheCall(t *testing.T) {
	found, err := Dir(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	index := byName(found)

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
	found, err := Dir(fixture(t))
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
	found, err := Dir(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := byName(found)["MD5"]; !ok {
		t.Error("MD5 imported under an alias was missed")
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
