package scan

import (
	"os"
	"path/filepath"
	"testing"
)

const md5Source = `package dep

import "crypto/md5"

func sum(b []byte) [16]byte { return md5.Sum(b) }
`

const rsaSource = `package dep

import (
	"crypto/rand"
	"crypto/rsa"
)

func key() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }
`

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestModulesResolveFromTheCacheAndFromReplacements(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "modcache")
	t.Setenv("GOMODCACHE", cache)

	write(t, filepath.Join(cache, "example.com", "dep@v1.2.0", "dep.go"), md5Source)
	write(t, filepath.Join(cache, "github.com", "!burnt!sushi", "toml@v1.0.0", "toml.go"), "package toml\n")
	write(t, filepath.Join(root, "local", "local.go"), "package local\n")
	write(t, filepath.Join(root, "go.mod"), `module example.com/app

go 1.25

require (
	example.com/dep v1.2.0
	example.com/gone v0.1.0 // indirect
	github.com/BurntSushi/toml v1.0.0
)

require example.com/patched v2.0.0

replace example.com/patched => ./local
`)

	modules, err := Modules(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(modules) != 4 {
		t.Fatalf("got %d modules, want the 4 go.mod requires: %+v", len(modules), modules)
	}
	byPath := map[string]Module{}
	for _, m := range modules {
		byPath[m.Path] = m
	}

	if dir := byPath["example.com/dep"].Dir; dir != filepath.Join(cache, "example.com", "dep@v1.2.0") {
		t.Errorf("dep resolved to %q, want its module cache entry", dir)
	}
	if byPath["github.com/BurntSushi/toml"].Dir == "" {
		t.Error("a module with an uppercase letter was not found: the cache spells it with !")
	}
	gone := byPath["example.com/gone"]
	if gone.Dir != "" || !gone.Indirect {
		t.Errorf("gone = %+v, want an indirect module with no source on disk", gone)
	}
	patched := byPath["example.com/patched"]
	if patched.Dir != filepath.Join(root, "local") {
		t.Errorf("patched resolved to %q, want the directory the replace points at", patched.Dir)
	}
	if patched.Replaced != "example.com/patched@v2.0.0" {
		t.Errorf("replaced = %q, want the coordinate it was required as", patched.Replaced)
	}
}

func TestDepsAttributesEveryFindingToItsModule(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "modcache")
	t.Setenv("GOMODCACHE", cache)

	dep := filepath.Join(cache, "example.com", "dep@v1.2.0")
	write(t, filepath.Join(dep, "dep.go"), md5Source)
	write(t, filepath.Join(dep, "dep_test.go"), rsaSource)
	write(t, filepath.Join(dep, "testdata", "fixture.go"), rsaSource)
	write(t, filepath.Join(dep, "broken.go"), "package dep\nfunc (")
	write(t, filepath.Join(root, "go.mod"), `module example.com/app

go 1.25

require (
	example.com/dep v1.2.0
	example.com/gone v0.1.0
)
`)

	result, err := Deps(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assets) != 1 {
		t.Fatalf("got %+v, want only the finding in code a consumer links", result.Assets)
	}
	got := result.Assets[0]
	if got.Name != "MD5" {
		t.Errorf("name = %q, want MD5", got.Name)
	}
	if got.Module != "example.com/dep@v1.2.0" {
		t.Errorf("module = %q, want the dependency that introduced it", got.Module)
	}
	if got.Location.File != "example.com/dep@v1.2.0/dep.go" || got.Location.Line == 0 {
		t.Errorf("location = %q, want a position inside the module", got.Location.String())
	}
	if len(result.Read) != 1 {
		t.Errorf("read = %+v, want the one module that was on disk", result.Read)
	}
	if len(result.Missing) != 1 || result.Missing[0].Coordinate() != "example.com/gone@v0.1.0" {
		t.Errorf("missing = %+v, want the module whose source is not on disk", result.Missing)
	}
}

// A vendor directory is what the build compiles, so it answers instead of the
// cache — otherwise the inventory describes code that is not in the binary.
func TestDepsReadsAVendorDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GOMODCACHE", filepath.Join(root, "empty"))
	write(t, filepath.Join(root, "vendor", "example.com", "dep", "dep.go"), md5Source)
	write(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.25\n\nrequire example.com/dep v1.2.0\n")

	result, err := Deps(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assets) != 1 || result.Assets[0].Module != "example.com/dep@v1.2.0" {
		t.Fatalf("got %+v, want the vendored dependency attributed to its module", result.Assets)
	}
}

// go.mod is read as syntax, not as text: a directive inside a comment is not a
// dependency, and a replacement names what actually ships.
func TestCommentsAreNotDirectives(t *testing.T) {
	required, replacements := parseGoMod(`module example.com/app

// require example.com/ghost v9.9.9
require example.com/real v1.0.0 // indirect

replace example.com/real v1.0.0 => example.com/fork v1.0.1
`)
	if len(required) != 1 || required[0].Path != "example.com/real" || !required[0].Indirect {
		t.Fatalf("required = %+v, want only the real require", required)
	}
	r, ok := replacements["example.com/real@v1.0.0"]
	if !ok || r.path != "example.com/fork" || r.version != "v1.0.1" {
		t.Errorf("replacement = %+v (found=%v), want the fork it points at", r, ok)
	}
}
