package totp

import (
	"testing"
)

var tIn []int64
var sha1Key string

func init() {
	// Common Test Parameters
	sha1Key = "12345678901234567890"
	//x := 30
	//d := 8
	tIn = []int64{ 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000 }
}

// Tests to add, incorrect key lengths, wrong digits etc etc.

func TestSHA1(t *testing.T) {
	expected := []string{ "94287082", "07081804", "14050471", "89005924", "69279037", "65353130" }

	for i, ti := range tIn {
		totp, _ := TOTP([]byte(sha1Key), ti, 30, 8, SHA1)
		if totp != expected[i] {
			t.Errorf("TOTP(%q) == %q, want %q", ti, totp, expected[i])
		}
	}
}