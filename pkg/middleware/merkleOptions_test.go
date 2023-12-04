package middleware

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfigCreation(t *testing.T) {
	cfg := newConfigFromOptions(
		WithAccessTokenCacheSize(42),
		WithAccessTokenLifeTime(10*time.Minute),
		WithAllowedDepthRange(3, 33),
		WithAllowedProofLeavesNum(77, 7),
	)
	assert.Equal(t, config{
		accessTokenCacheSize:     42,
		accessTokenLifeTime:      10 * time.Minute,
		minAllowedDepth:          3,
		maxAllowedDepth:          33,
		minAllowedProofLeavesNum: 7,
		maxAllowedProofLeavesNum: 77,
	}, cfg)
}
