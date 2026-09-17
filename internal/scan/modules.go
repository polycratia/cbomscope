package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/polycratia/cbomscope/internal/asset"
)

// Module is one dependency named in go.mod.
type Module struct {
	Path     string
	Version  string
	Indirect bool
	// Dir is where the module's source was found: the module cache, a vendor
	// directory, or the directory a replace directive points at. Empty when the
	// source is not on disk.
	Dir string
	// Replaced is the coordinate the module was required as, when a replace
	// directive redirected it. Path and Version then name what was read, which
	// is the code that actually ships.
	Replaced string
}

// Coordinate is path@version, the way a module is named everywhere outside
// go.mod itself.
func (m Module) Coordinate() string {
	if m.Version == "" {
		return m.Path
	}
	return m.Path + "@" + m.Version
}

// DepScan is what a dependency walk saw, and what it could not see.
type DepScan struct {
	Assets []asset.Asset
	// Read are the modules whose source was found and scanned.
	Read []Module
	// Missing are the required modules whose source is not on disk. They are
	// carried out of here rather than dropped: an inventory that silently skips
	// a module reads exactly like one that checked it and found nothing.
	Missing []Module
}

// Deps reads go.mod at root and reports the cryptography in the source of every
// dependency that is on disk, attributing each finding to the module that
// introduced it.
//
// Most of the cryptography a program executes was written by somebody else, and
// a dependency that still hashes with MD5 belongs in the inventory whether or
// not a first-party line mentions it.
func Deps(root string) (DepScan, error) {
	modules, err := Modules(root)
	if err != nil {
		return DepScan{}, err
	}
	var result DepScan
	for _, m := range modules {
		if m.Dir == "" {
			result.Missing = append(result.Missing, m)
			continue
		}
		found, err := moduleSource(m)
		if err != nil {
			return DepScan{}, fmt.Errorf("scan %s: %w", m.Coordinate(), err)
		}
		result.Assets = append(result.Assets, found...)
		result.Read = append(result.Read, m)
	}
	return result, nil
}

// moduleSource reads one module's own source.
//
// Somebody else's tree is read on different terms than ours: what a consumer
// never links — tests and testdata — is left out, and a file that does not
// parse is skipped rather than failing the whole inventory.
func moduleSource(m Module) ([]asset.Asset, error) {
	coordinate := m.Coordinate()
	var found []asset.Asset
	err := filepath.WalkDir(m.Dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == m.Dir {
				return nil
			}
			name := d.Name()
			if name == "vendor" || name == "testdata" ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		assets, err := File(path)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(m.Dir, path)
		if err != nil {
			return err
		}
		for i := range assets {
			assets[i].Module = coordinate
			// The position is written as the coordinate and the file inside it,
			// so a reader reaches the source from the finding alone.
			assets[i].Location.File = coordinate + "/" + filepath.ToSlash(rel)
		}
		found = append(found, assets...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

// Modules reads go.mod at root and locates the source of every module it
// requires, direct and indirect alike: an indirect dependency runs the same
// code as a direct one.
func Modules(root string) ([]Module, error) {
	body, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("read the dependency list: %w", err)
	}
	required, replacements := parseGoMod(string(body))
	cache := moduleCache()
	vendored := ""
	if dir := filepath.Join(root, "vendor"); isDir(dir) {
		vendored = dir
	}

	out := make([]Module, 0, len(required))
	for _, m := range required {
		if r, ok := replacementFor(replacements, m); ok {
			m.Replaced = m.Coordinate()
			if r.dir != "" {
				dir := filepath.FromSlash(r.dir)
				if !filepath.IsAbs(dir) {
					dir = filepath.Join(root, dir)
				}
				if isDir(dir) {
					m.Dir = dir
				}
				out = append(out, m)
				continue
			}
			m.Path, m.Version = r.path, r.version
		}
		m.Dir = locate(m, vendored, cache)
		out = append(out, m)
	}
	return out, nil
}

func locate(m Module, vendored, cache string) string {
	if vendored != "" {
		// A vendor directory is the build's answer; the cache is not consulted
		// beside it, or the inventory would describe code that is not compiled.
		if dir := filepath.Join(vendored, filepath.FromSlash(m.Path)); isDir(dir) {
			return dir
		}
		return ""
	}
	if cache == "" || m.Version == "" {
		return ""
	}
	dir := filepath.Join(cache, filepath.FromSlash(escape(m.Path))+"@"+escape(m.Version))
	if isDir(dir) {
		return dir
	}
	return ""
}

// escape is how the module cache spells a name on a case-insensitive file
// system: an uppercase letter becomes "!" and its lowercase.
func escape(s string) string {
	if s == strings.ToLower(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			b.WriteByte(c + ('a' - 'A'))
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func moduleCache() string {
	if dir := os.Getenv("GOMODCACHE"); dir != "" {
		return dir
	}
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		if i := strings.IndexByte(gopath, os.PathListSeparator); i >= 0 {
			gopath = gopath[:i]
		}
		return filepath.Join(gopath, "pkg", "mod")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "go", "pkg", "mod")
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// replacement is the right-hand side of a replace directive.
type replacement struct {
	path    string
	version string
	// dir is set when the directive points at a directory, which is the form
	// that carries no version.
	dir string
}

func replacementFor(replacements map[string]replacement, m Module) (replacement, bool) {
	if r, ok := replacements[m.Path+"@"+m.Version]; ok {
		return r, true
	}
	r, ok := replacements[m.Path]
	return r, ok
}

// parseGoMod reads the require and replace directives, in both the block and
// the single-line form. It reads the file rather than asking the go command,
// so an inventory can be taken without a toolchain and without a network.
func parseGoMod(body string) ([]Module, map[string]replacement) {
	var required []Module
	replacements := map[string]replacement{}

	block := ""
	for _, raw := range strings.Split(body, "\n") {
		indirect := strings.Contains(raw, "// indirect")
		line := raw
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		kind := block
		if block == "" {
			switch fields[0] {
			case "require", "replace":
				kind = fields[0]
				fields = fields[1:]
				if len(fields) == 1 && fields[0] == "(" {
					block = kind
					continue
				}
				if len(fields) == 0 {
					continue
				}
			default:
				continue
			}
		} else if fields[0] == ")" {
			block = ""
			continue
		}

		switch kind {
		case "require":
			if len(fields) >= 2 {
				required = append(required, Module{Path: fields[0], Version: fields[1], Indirect: indirect})
			}
		case "replace":
			if from, r, ok := parseReplace(fields); ok {
				replacements[from] = r
			}
		}
	}
	return required, replacements
}

func parseReplace(fields []string) (string, replacement, bool) {
	arrow := slices.Index(fields, "=>")
	if arrow <= 0 || arrow == len(fields)-1 {
		return "", replacement{}, false
	}
	left, right := fields[:arrow], fields[arrow+1:]
	from := left[0]
	if len(left) > 1 {
		from = left[0] + "@" + left[1]
	}
	if len(right) == 1 {
		// A replacement with no version is a directory, always.
		return from, replacement{dir: right[0]}, true
	}
	return from, replacement{path: right[0], version: right[1]}, true
}
