// Package cbom writes a cryptography bill of materials.
//
// The format is CycloneDX 1.6, which is where cryptographic assets are defined
// and — usefully — the same document family an SBOM already uses, so a CBOM can
// travel through tooling that exists.
package cbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/polycratia/cbomscope/internal/asset"
)

// Document is a CycloneDX 1.6 bill of materials holding cryptographic assets.
type Document struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    Metadata    `json:"metadata"`
	Components  []Component `json:"components"`
}

type Metadata struct {
	Timestamp string `json:"timestamp"`
	Tools     Tools  `json:"tools"`
	Component *struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"component,omitempty"`
}

type Tools struct {
	Components []ToolComponent `json:"components"`
}

type ToolComponent struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type Component struct {
	Type             string           `json:"type"`
	BOMRef           string           `json:"bom-ref"`
	Name             string           `json:"name"`
	CryptoProperties CryptoProperties `json:"cryptoProperties"`
	Properties       []Property       `json:"properties,omitempty"`
	Evidence         *Evidence        `json:"evidence,omitempty"`
}

type CryptoProperties struct {
	AssetType           string               `json:"assetType"`
	AlgorithmProperties *AlgorithmProperties `json:"algorithmProperties,omitempty"`
}

// AlgorithmProperties describes one algorithm the way CycloneDX 1.6 defines it.
// Every field keeps its spec meaning: parameterSetIdentifier names the variant
// that was used, and classicalSecurityLevel is strength in bits, which is a
// different number from the key size.
type AlgorithmProperties struct {
	Primitive                string `json:"primitive,omitempty"`
	ParameterSetIdentifier   string `json:"parameterSetIdentifier,omitempty"`
	Curve                    string `json:"curve,omitempty"`
	Mode                     string `json:"mode,omitempty"`
	ClassicalSecurityLevel   int    `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel int    `json:"nistQuantumSecurityLevel,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Evidence struct {
	Occurrences []Occurrence `json:"occurrences"`
}

type Occurrence struct {
	Location string `json:"location"`
}

// Build assembles a document from classified assets.
//
// The quantum posture is written as a namespaced property rather than a
// standard field, because CycloneDX has no field for it. Inventing a meaning
// for a standard field would make the document lie to anything that reads it
// by the spec.
func Build(assets []asset.Asset, at time.Time) *Document {
	doc := &Document{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: Metadata{
			Timestamp: at.UTC().Format(time.RFC3339),
			Tools:     Tools{Components: []ToolComponent{{Type: "application", Name: "cbomscope"}}},
		},
		Components: make([]Component, 0, len(assets)),
	}
	for _, a := range assets {
		doc.Components = append(doc.Components, component(a))
	}
	return doc
}

func component(a asset.Asset) Component {
	c := Component{
		Type:   "cryptographic-asset",
		BOMRef: reference(a),
		Name:   a.Name,
		CryptoProperties: CryptoProperties{
			AssetType: string(a.Kind),
		},
		Properties: []Property{
			{Name: "cbomscope:posture", Value: string(a.Posture)},
		},
	}
	if a.Rationale != "" {
		c.Properties = append(c.Properties, Property{Name: "cbomscope:rationale", Value: a.Rationale})
	}
	if a.Citation != "" {
		c.Properties = append(c.Properties, Property{Name: "cbomscope:citation", Value: a.Citation})
	}
	if a.Kind == asset.Algorithm {
		c.CryptoProperties.AlgorithmProperties = algorithmProperties(a)
	}
	if location := a.Location.String(); location != "unknown" {
		c.Evidence = &Evidence{Occurrences: []Occurrence{{Location: location}}}
	}
	return c
}

func algorithmProperties(a asset.Asset) *AlgorithmProperties {
	props := &AlgorithmProperties{
		Primitive:                string(a.Primitive),
		Curve:                    a.Curve,
		Mode:                     string(a.Mode),
		ClassicalSecurityLevel:   classicalSecurityLevel(a),
		NISTQuantumSecurityLevel: quantumSecurityLevel(a),
	}
	if a.KeySize > 0 {
		props.ParameterSetIdentifier = strconv.Itoa(a.KeySize)
	}
	return props
}

// modulusStrength pairs a modulus size with the strength NIST SP 800-57 gives
// it. Sizes between the published pairs are left out rather than interpolated:
// a migration gets budgeted from this number.
var modulusStrength = map[int]int{1024: 80, 2048: 112, 3072: 128, 7680: 192, 15360: 256}

// nistCategory is the NIST post-quantum security category an algorithm sits in.
// The categories are defined by these algorithms — category 1 is an AES-128 key
// search, category 2 a SHA-256 collision search — so the numbers are readings
// of the definition rather than estimates.
var nistCategory = map[string]int{
	"ML-KEM-512":  1,
	"ML-KEM-768":  3,
	"ML-KEM-1024": 5,
	"ML-DSA-44":   2,
	"ML-DSA-65":   3,
	"ML-DSA-87":   5,
	"SHA-256":     2,
	"SHA3-256":    2,
	"SHA-384":     4,
	"SHA3-384":    4,
}

// classicalSecurityLevel is the work an attacker faces today, in bits, which is
// not the key size: RSA-2048 is 2048 bits of modulus and about 112 bits of
// strength. It returns 0 wherever the number would be invented, because a wrong
// level is worse than an absent one.
func classicalSecurityLevel(a asset.Asset) int {
	name := family(a)
	// Triple DES has 168 bits of key and 112 bits of strength: a
	// meet-in-the-middle attack costs two encryptions, not three.
	if strings.HasPrefix(name, "3DES") || strings.Contains(name, "TRIPLEDES") {
		return 112
	}
	if a.KeySize == 0 {
		return 0
	}
	switch {
	case strings.HasPrefix(name, "RSA"), strings.HasPrefix(name, "DSA"), name == "DH":
		return modulusStrength[a.KeySize]
	case strings.HasPrefix(name, "EC"), strings.HasPrefix(name, "ED"),
		strings.HasPrefix(name, "X25519"), strings.HasPrefix(name, "X448"):
		// A discrete logarithm on an n-bit curve costs about 2^(n/2).
		return a.KeySize / 2
	}
	switch a.Primitive {
	case asset.BlockCipher, asset.AE, asset.MAC:
		return a.KeySize
	}
	return 0
}

func quantumSecurityLevel(a asset.Asset) int {
	name := family(a)
	if level, ok := nistCategory[name]; ok {
		return level
	}
	if strings.HasPrefix(name, "AES") {
		switch a.KeySize {
		case 128:
			return 1
		case 192:
			return 3
		case 256:
			return 5
		}
	}
	return 0
}

func family(a asset.Asset) string {
	if a.Algorithm != "" {
		return strings.ToUpper(a.Algorithm)
	}
	return strings.ToUpper(a.Name)
}

// reference is stable across runs so that two scans of unchanged code produce
// two documents that can be diffed.
func reference(a asset.Asset) string {
	sum := sha256.Sum256([]byte(a.Name + "|" + string(a.Kind) + "|" + a.Location.String() + "|" + a.Evidence))
	return "crypto:" + hex.EncodeToString(sum[:])[:16]
}

// Encode writes the document as indented JSON.
func (d *Document) Encode() ([]byte, error) {
	out, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
