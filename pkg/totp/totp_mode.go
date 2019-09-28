package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// Encapsulate the supported modes of the TOTP function
type Mode int

const (
	SHA1 Mode = iota
	SHA256
	SHA512
)

// Return the string name of the mode
func (m Mode) String() string {
	return [...]string{"SHA1", "SHA256", "SHA512"}[m]
}

// Return the correct key size for the mode
func (m Mode) KeySize() int {
	return [...]int{20, 32, 64}[m]
}

// Return the correct hash function for creating a hash
func (m Mode) GetHash() func() hash.Hash {
	return [...]func() hash.Hash{sha1.New, sha256.New, sha512.New}[m]
}
