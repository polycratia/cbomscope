package scan

import (
	"path/filepath"
	"testing"
)

// A dependency's tests are left out of the inventory because a consumer never
// links them. Our own tests are the same kind of code, but dropping a finding
// from our own tree would hide an inventory somebody asked for, so it is marked
// instead of skipped.
func TestOurOwnTestCodeIsMarkedRatherThanSkipped(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "sign.go"), md5Source)
	write(t, filepath.Join(root, "sign_test.go"), rsaSource)
	write(t, filepath.Join(root, "testdata", "fixture.go"), rsaSource)

	found, err := Dir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 3 {
		t.Fatalf("got %+v, want all three findings: nothing in our own tree is skipped", found)
	}
	for _, a := range found {
		base := filepath.Base(a.Location.File)
		want := base == "sign_test.go" || base == "fixture.go"
		if a.TestOnly != want {
			t.Errorf("%s at %s: TestOnly = %v, want %v",
				a.Name, a.Location.String(), a.TestOnly, want)
		}
	}
}
