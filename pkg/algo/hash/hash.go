package hash

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"strings"
)

// Value is a wrapper for 16 byte array
type Value [16]byte

// FromString gets hash value from a base64 encoded string
func FromString(data string) (Value, error) {
	var result Value
	byteData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return result, fmt.Errorf("failed to decode base64 string %q, error: %w", data, err)
	}

	if len(result) != len(byteData) {
		return result, fmt.Errorf("base64 string %q contains %d bytes of data, expected %d",
			data, len(byteData), len(result))
	}
	for i := 0; i < len(result); i++ {
		result[i] = byteData[i]
	}
	return result, nil
}

// ToSlice converts 16 byte array to a byte slice
func (rcv Value) ToSlice() []byte {
	return rcv[:]
}

// String Hash 16 byte array to a base64 encoded string
func (rcv Value) String() string {
	return base64.StdEncoding.EncodeToString(rcv[:])
}

// Hasher is an interface for a class that is capable of computing hash values
// for an arbitrary byte array
type Hasher interface {
	Hash([]byte) Value
}

// MD5Hasher is a wrapper for md5 hash function
type MD5Hasher struct{}

// Hash computes md5 hash
func (rcv MD5Hasher) Hash(data []byte) Value {
	return md5.Sum(data)
}

type seededHasher struct {
	originalHasher Hasher
	seedHash       Value
}

// Hash is NOT thread safety
func (rcv *seededHasher) Hash(data []byte) Value {
	result := rcv.originalHasher.Hash(data)
	result = XORHashes(result, rcv.seedHash)
	return result
}

// NewSeededHasher builds a "shifted" hash function out of original
// allows you to "parametrize" you hash function computation
func NewSeededHasher(hasher Hasher, parts ...any) Hasher {
	if len(parts) == 0 {
		return hasher
	}

	var builder strings.Builder
	sep := ""
	for _, part := range parts {
		builder.WriteString(fmt.Sprintf("%v%v", sep, part))
		sep = "_"
	}
	strSeed := builder.String()
	seed := hasher.Hash([]byte(strSeed))
	return &seededHasher{
		originalHasher: hasher,
		seedHash:       seed,
	}
}

// XORHashes computes xored hash array
func XORHashes(left, right Value) Value {
	var output Value
	for i := 0; i < len(output); i++ {
		output[i] = left[i] ^ right[i]
	}
	return output
}
