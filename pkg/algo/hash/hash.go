package hash

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"unsafe"
)

// Hash is a constraint and is not "real" interfaces.
// Thus occurence of vars of type of constraints does not spawn an iterface object
type Hash interface {
	~[md5.Size]byte | ~[sha256.Size]byte
	ToSlice() []byte
	String() string
}

// FromString gets hash value from a base64 encoded string
func FromString[HashT Hash](data string) (HashT, error) {
	var result HashT
	byteData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return result, fmt.Errorf("failed to decode base64 string %q, error: %w", data, err)
	}

	dest := unsafe.Pointer(&result)
	if int(unsafe.Sizeof(result)) != len(byteData) {
		return result, fmt.Errorf("base64 string %q contains %d bytes of data, expected %d",
			data, len(byteData), int(unsafe.Sizeof(result)))
	}
	for i := 0; i < int(unsafe.Sizeof(result)); i++ {
		p := (*byte)(unsafe.Add(dest, i))
		*p = byteData[i]
	}
	return result, nil
}

// Byte16 is a wrapper for 16 byte array
type Byte16 [16]byte

// ToSlice converts 16 byte array to a byte slice
func (rcv Byte16) ToSlice() []byte {
	return rcv[:]
}

// String converts 16 byte array to a base64 encoded string
func (rcv Byte16) String() string {
	return base64.StdEncoding.EncodeToString(rcv[:])
}

// Byte32 is a wrapper for 32 byte array
type Byte32 [32]byte

// ToSlice converts 32 byte array to a byte slice
func (rcv Byte32) ToSlice() []byte {
	return rcv[:]
}

// String converts 32 byte array to a base64 encoded string
func (rcv Byte32) String() string {
	return base64.StdEncoding.EncodeToString(rcv[:])
}

// Hasher is an interface for a class that is capable of computing hash values
// for an arbitrary byte array
type Hasher[HashT Hash] interface {
	Hash([]byte) HashT
}

// MD5Hasher is a wrapper for md5 hash function
type MD5Hasher struct{}

// Hash computes md5 hash
func (rcv MD5Hasher) Hash(data []byte) Byte16 {
	return md5.Sum(data)
}

// SHA256Hahser is a wrapper for sha256 hash function
type SHA256Hahser struct{}

// Hash computes sha256 hash
func (rcv SHA256Hahser) Hash(data []byte) Byte32 {
	return sha256.Sum256(data)
}

type seededHasher[HashT Hash] struct {
	originalHasher Hasher[HashT]
	seedHash       HashT
}

// Hash is NOT thread safety
func (rcv *seededHasher[HashT]) Hash(data []byte) HashT {
	result := rcv.originalHasher.Hash(data)
	result = XORHashes(result, rcv.seedHash)
	return result
}

// NewSeededHasher builds a "shifted" hash function out of original
// allows you to "parametrize" you hash function computation
func NewSeededHasher[HashT Hash](hasher Hasher[HashT], parts ...any) Hasher[HashT] {
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
	return &seededHasher[HashT]{
		originalHasher: hasher,
		seedHash:       seed,
	}
}

// XORHashes computes xored hash array
func XORHashes[HashT Hash](left, right HashT) HashT {
	var output HashT
	for i := 0; i < len(output); i++ {
		output[i] = left[i] ^ right[i]
	}
	return output
}
