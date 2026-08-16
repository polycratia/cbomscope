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

type AlgorithmProperties struct {
	Primitive              string `json:"primitive,omitempty"`
	ParameterSetIdentifier string `json:"parameterSetIdentifier,omitempty"`
	Curve                  string `json:"curve,omitempty"`
	ClassicalSecurityLevel int    `json:"classicalSecurityLevel,omitempty"`
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
	if a.Kind == asset.Algorithm {
		props := &AlgorithmProperties{
			Primitive:              string(a.Primitive),
			Curve:                  a.Curve,
			ClassicalSecurityLevel: a.KeySize,
		}
		if a.KeySize > 0 {
			props.ParameterSetIdentifier = strconv.Itoa(a.KeySize)
		}
		c.CryptoProperties.AlgorithmProperties = props
	}
	if location := a.Location.String(); location != "unknown" {
		c.Evidence = &Evidence{Occurrences: []Occurrence{{Location: location}}}
	}
	return c
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
