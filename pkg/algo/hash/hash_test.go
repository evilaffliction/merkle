package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntMinTableDriven(t *testing.T) {
	hasher := MD5Hasher{}
	geniusThoughts := "To be or not to"
	hashValue := hasher.Hash([]byte(geniusThoughts))
	md5HashValue := hashValue.String()

	assert.Equal(t, "C68UZChA4SK3gRZeClcKzg==", md5HashValue)
}

func TestBase54Conversions(t *testing.T) {
	hasher := MD5Hasher{}
	initialHash := hasher.Hash([]byte("pish pish ololo"))
	base64Encoded := initialHash.String()
	decodedHash, err := FromString(base64Encoded)
	assert.NoError(t, err)
	assert.EqualValues(t, initialHash, decodedHash)
}
