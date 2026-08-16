// Package scan finds cryptography in Go source code.
//
// It reads the syntax tree rather than grepping for names, so an import alias,
// a comment or a string that happens to say "rsa" does not become a finding.
// What it cannot see is stated plainly: a key size that arrives in a variable
// is reported as "not determined", never guessed.
package scan

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/polycratia/cbomscope/internal/asset"
)

// use describes what one call in one crypto package means.
type use struct {
	algorithm string
	primitive asset.Primitive
	keySize   int // fixed size where the function name implies it
}

// table maps import path -> function name -> what it tells us.
var table = map[string]map[string]use{
	"crypto/rsa": {
		"GenerateKey":     {algorithm: "RSA", primitive: asset.PKE},
		"SignPKCS1v15":    {algorithm: "RSA", primitive: asset.Signature},
		"SignPSS":         {algorithm: "RSA", primitive: asset.Signature},
		"EncryptOAEP":     {algorithm: "RSA", primitive: asset.PKE},
		"EncryptPKCS1v15": {algorithm: "RSA", primitive: asset.PKE},
	},
	"crypto/ecdsa": {
		"GenerateKey": {algorithm: "ECDSA", primitive: asset.Signature},
		"Sign":        {algorithm: "ECDSA", primitive: asset.Signature},
		"SignASN1":    {algorithm: "ECDSA", primitive: asset.Signature},
		"Verify":      {algorithm: "ECDSA", primitive: asset.Signature},
		"VerifyASN1":  {algorithm: "ECDSA", primitive: asset.Signature},
	},
	"crypto/ed25519": {
		"GenerateKey": {algorithm: "Ed25519", primitive: asset.Signature, keySize: 256},
		"Sign":        {algorithm: "Ed25519", primitive: asset.Signature, keySize: 256},
		"Verify":      {algorithm: "Ed25519", primitive: asset.Signature, keySize: 256},
	},
	"crypto/ecdh": {
		"P256":   {algorithm: "ECDH", primitive: asset.KeyAgree, keySize: 256},
		"P384":   {algorithm: "ECDH", primitive: asset.KeyAgree, keySize: 384},
		"P521":   {algorithm: "ECDH", primitive: asset.KeyAgree, keySize: 521},
		"X25519": {algorithm: "X25519", primitive: asset.KeyAgree, keySize: 256},
	},
	"crypto/aes": {
		"NewCipher": {algorithm: "AES", primitive: asset.BlockCipher},
	},
	"crypto/des": {
		"NewCipher":          {algorithm: "DES", primitive: asset.BlockCipher, keySize: 56},
		"NewTripleDESCipher": {algorithm: "3DES", primitive: asset.BlockCipher, keySize: 168},
	},
	"crypto/rc4": {
		"NewCipher": {algorithm: "RC4", primitive: asset.BlockCipher},
	},
	"crypto/md5": {
		"New": {algorithm: "MD5", primitive: asset.Hash},
		"Sum": {algorithm: "MD5", primitive: asset.Hash},
	},
	"crypto/sha1": {
		"New": {algorithm: "SHA-1", primitive: asset.Hash},
		"Sum": {algorithm: "SHA-1", primitive: asset.Hash},
	},
	"crypto/sha256": {
		"New":    {algorithm: "SHA-256", primitive: asset.Hash},
		"Sum256": {algorithm: "SHA-256", primitive: asset.Hash},
		"New224": {algorithm: "SHA-224", primitive: asset.Hash},
		"Sum224": {algorithm: "SHA-224", primitive: asset.Hash},
	},
	"crypto/sha512": {
		"New":    {algorithm: "SHA-512", primitive: asset.Hash},
		"Sum512": {algorithm: "SHA-512", primitive: asset.Hash},
		"New384": {algorithm: "SHA-384", primitive: asset.Hash},
		"Sum384": {algorithm: "SHA-384", primitive: asset.Hash},
	},
	"crypto/hmac": {
		"New": {algorithm: "HMAC", primitive: asset.MAC},
	},
	"golang.org/x/crypto/chacha20poly1305": {
		"New":  {algorithm: "ChaCha20-Poly1305", primitive: asset.BlockCipher, keySize: 256},
		"NewX": {algorithm: "ChaCha20-Poly1305", primitive: asset.BlockCipher, keySize: 256},
	},
	"crypto/mlkem": {
		"GenerateKey768":  {algorithm: "ML-KEM-768", primitive: asset.KEM},
		"GenerateKey1024": {algorithm: "ML-KEM-1024", primitive: asset.KEM},
	},
}

// curveNames maps elliptic.P256() and friends onto the curve they name.
var curveNames = map[string]int{"P224": 224, "P256": 256, "P384": 384, "P521": 521}

// Dir walks a directory and reports the cryptography it can see in Go sources.
func Dir(root string) ([]asset.Asset, error) {
	var found []asset.Asset
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// The root is whatever the caller asked for, including "." and
			// "../..", and must never be skipped by the rules below — that
			// silently turns a relative path into an empty inventory.
			if path == root {
				return nil
			}
			// Dependencies are somebody else's inventory, and dot-directories
			// are not source.
			if name := d.Name(); name == "vendor" || strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		assets, err := File(path)
		if err != nil {
			return err
		}
		found = append(found, assets...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

// File reports the cryptography visible in one Go file.
func File(path string) ([]asset.Asset, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}

	// Which local name stands for which crypto package in this file. Aliases
	// are why this reads imports instead of assuming the last path element.
	packages := map[string]string{}
	for _, imp := range file.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if _, watched := table[importPath]; !watched && importPath != "crypto/elliptic" {
			continue
		}
		local := path_base(importPath)
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				// A blank or dot import gives no call site to attribute.
				continue
			}
			local = imp.Name.Name
		}
		packages[local] = importPath
	}
	if len(packages) == 0 {
		return nil, nil
	}

	var found []asset.Asset
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		importPath, ok := packages[ident.Name]
		if !ok {
			return true
		}
		u, ok := table[importPath][sel.Sel.Name]
		if !ok {
			return true
		}

		position := fset.Position(call.Pos())
		a := asset.Asset{
			Name:      u.algorithm,
			Kind:      asset.Algorithm,
			Primitive: u.primitive,
			Algorithm: u.algorithm,
			KeySize:   u.keySize,
			Location:  asset.Location{File: position.Filename, Line: position.Line},
			Evidence:  ident.Name + "." + sel.Sel.Name + "()",
		}
		enrich(&a, importPath, sel.Sel.Name, call, packages)
		found = append(found, a)
		return true
	})
	return found, nil
}

// enrich pulls parameters out of the call where they are literal: the bit size
// of an RSA key, the curve of an ECDSA key. Anything computed at run time stays
// unset, which downstream reads as "not determined".
func enrich(a *asset.Asset, importPath, function string, call *ast.CallExpr, packages map[string]string) {
	switch {
	case importPath == "crypto/rsa" && function == "GenerateKey" && len(call.Args) >= 2:
		if bits, ok := intLiteral(call.Args[1]); ok {
			a.KeySize = bits
			a.Name = "RSA-" + strconv.Itoa(bits)
			a.Evidence += " with " + strconv.Itoa(bits) + " bits"
		}
	case importPath == "crypto/ecdsa" && function == "GenerateKey" && len(call.Args) >= 1:
		if curve, bits, ok := curveArgument(call.Args[0], packages); ok {
			a.Curve = curve
			a.KeySize = bits
			a.Name = "ECDSA-" + curve
			a.Evidence += " on " + curve
		}
	}
}

func intLiteral(expr ast.Expr) (int, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	n, err := strconv.Atoi(lit.Value)
	if err != nil {
		return 0, false
	}
	return n, true
}

// curveArgument reads elliptic.P256() written as an argument.
func curveArgument(expr ast.Expr, packages map[string]string) (string, int, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return "", 0, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", 0, false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok || packages[ident.Name] != "crypto/elliptic" {
		return "", 0, false
	}
	bits, ok := curveNames[sel.Sel.Name]
	if !ok {
		return "", 0, false
	}
	return sel.Sel.Name, bits, true
}

func path_base(importPath string) string {
	if i := strings.LastIndex(importPath, "/"); i >= 0 {
		return importPath[i+1:]
	}
	return importPath
}
