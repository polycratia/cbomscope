package cbom

import (
	"bytes"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/polycratia/cbomscope/internal/asset"
	"github.com/polycratia/cbomscope/internal/classify"
)

// The golden document is the whole output in one file: a fixture corpus run
// through the classification table and written as CycloneDX. A renamed
// property, a reworded rationale or a different shape shows up here as a diff
// rather than as a surprise in somebody's pipeline.
//
// Rewrite it, once the change is the intended one, with:
//
//	go test ./internal/cbom -update
var updateGolden = flag.Bool("update", false, "rewrite the golden CBOM from the current writer")

var goldenPath = filepath.Join("..", "..", "testdata", "golden", "cbom.json")

var goldenTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// redactedRef stands in for every bom-ref in the golden file. The references
// are truncated SHA-256 digests, which nobody can check by reading them, so
// they are asserted on their own terms and the file keeps a fixed placeholder
// that lets the rest of the document be compared literally.
const redactedRef = "crypto:0000000000000000"

// findings is one asset for every posture the classifier can reach, from both
// discovery paths: positions in source and a handshake, first-party code and a
// dependency.
func findings() []asset.Asset {
	return []asset.Asset{
		{
			Name: "RSA-2048", Kind: asset.Algorithm, Primitive: asset.PKE,
			Algorithm: "RSA", KeySize: 2048,
			Location: asset.Location{File: "internal/token/sign.go", Line: 41},
			Evidence: "rsa.GenerateKey(rand.Reader, 2048)",
		},
		{
			Name: "MD5", Kind: asset.Algorithm, Primitive: asset.Hash, Algorithm: "MD5",
			Location: asset.Location{File: "example.com/legacy@v1.4.0/checksum.go", Line: 31},
			Module:   "example.com/legacy@v1.4.0",
			Evidence: "md5.New()",
		},
		{
			Name: "TLS_AES_256_GCM_SHA384", Kind: asset.Algorithm, Primitive: asset.AE,
			Algorithm: "AES", KeySize: 256, Mode: asset.GCM,
			Location: asset.Location{Host: "api.example.com:443"},
			Evidence: "cipher suite TLS_AES_256_GCM_SHA384",
		},
		{
			Name: "SHA-256", Kind: asset.Algorithm, Primitive: asset.Hash, Algorithm: "SHA-256",
			Location: asset.Location{File: "internal/cbom/cbom.go", Line: 137},
			Evidence: "sha256.Sum256()",
		},
		{
			Name: "X25519MLKEM768", Kind: asset.Algorithm, Primitive: asset.KeyAgree,
			Algorithm: "X25519MLKEM768",
			Location:  asset.Location{Host: "api.example.com:443"},
			Evidence:  "group 0x11ec, offered X25519MLKEM768",
		},
		{
			Name: "TLS 1.3", Kind: asset.Protocol,
			Location: asset.Location{Host: "api.example.com:443"},
			Evidence: "negotiated version 0x0304",
		},
		{
			Name: "Serpent", Kind: asset.Algorithm, Primitive: asset.BlockCipher, Algorithm: "Serpent",
			Location: asset.Location{File: "internal/legacy/cipher.go", Line: 12},
			Evidence: "serpent.NewCipher(key)",
		},
	}
}

func TestGoldenDocumentIsUnchanged(t *testing.T) {
	doc := Build(classify.ApplyAll(findings()), goldenTime)

	seen := map[string]bool{}
	for i := range doc.Components {
		c := &doc.Components[i]
		digest := strings.TrimPrefix(c.BOMRef, "crypto:")
		if _, err := hex.DecodeString(digest); err != nil || len(digest) != 16 {
			t.Errorf("%s: bom-ref = %q, want crypto: and 16 hexadecimal characters", c.Name, c.BOMRef)
		}
		if seen[c.BOMRef] {
			t.Errorf("%s shares a bom-ref with an earlier component", c.Name)
		}
		seen[c.BOMRef] = true
		c.BOMRef = redactedRef
	}

	got, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read the golden document: %v", err)
	}
	if !bytes.Equal(got, want) {
		at, mine, theirs := firstDifference(got, want)
		t.Errorf("the document no longer matches %s at line %d:\n got: %s\nwant: %s\n"+
			"rerun with -update once the change is the intended one", goldenPath, at, mine, theirs)
	}
}

// A document that shows one posture says nothing about the others, so the
// corpus behind it carries every verdict the classifier can reach.
func TestTheGoldenCorpusCoversEveryPosture(t *testing.T) {
	seen := map[asset.Posture]bool{}
	for _, a := range classify.ApplyAll(findings()) {
		seen[a.Posture] = true
	}
	for _, p := range []asset.Posture{
		asset.Broken, asset.QuantumVulnerable, asset.QuantumReduced, asset.QuantumSafe,
		asset.Hybrid, asset.NotApplicable, asset.PostureUnknown,
	} {
		if !seen[p] {
			t.Errorf("nothing in the corpus is %s, so the document never shows what one looks like", p)
		}
	}
}

func firstDifference(got, want []byte) (int, string, string) {
	mine, theirs := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(mine) || i < len(theirs); i++ {
		if lineAt(mine, i) != lineAt(theirs, i) {
			return i + 1, lineAt(mine, i), lineAt(theirs, i)
		}
	}
	return 0, "", ""
}

func lineAt(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return "(end of file)"
}
