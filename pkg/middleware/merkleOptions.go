package middleware

import (
	"time"
)

type config struct {
	accessTokenCacheSize     int
	accessTokenLifeTime      time.Duration
	minAllowedDepth          int
	maxAllowedDepth          int
	minAllowedProofLeavesNum int
	maxAllowedProofLeavesNum int
}

func newConfigFromOptions(opts ...Option) config {
	// default values
	cfg := config{
		accessTokenCacheSize:     1000,
		accessTokenLifeTime:      5 * time.Second,
		minAllowedDepth:          10,
		maxAllowedDepth:          25,
		minAllowedProofLeavesNum: 3,
		maxAllowedProofLeavesNum: 10,
	}

	// overrides
	for _, opt := range opts {
		opt(&cfg)
	}

	return cfg
}

// Option allows to customize Merkle middleware
type Option func(cfg *config)

// WithAccessTokenCacheSize allows to specify cache size for access token.
// Access tokens prohibit to reuse compute POW to create microbursts
func WithAccessTokenCacheSize(size int) Option {
	return func(cfg *config) {
		cfg.accessTokenCacheSize = size
	}
}

// WithAccessTokenLifeTime allows to specify how long access token will be accepted
// after creation
func WithAccessTokenLifeTime(d time.Duration) Option {
	return func(cfg *config) {
		cfg.accessTokenLifeTime = d
	}
}

// WithAllowedDepthRange allows to specify acceptable range of merkle tree depth.
// That allows to specify min and max job needed for a prover to genereate POW
func WithAllowedDepthRange(minDepth, maxDepth int) Option {
	if minDepth > maxDepth {
		minDepth, maxDepth = maxDepth, minDepth
	}
	return func(cfg *config) {
		cfg.minAllowedDepth = minDepth
		cfg.maxAllowedDepth = maxDepth
	}
}

// WithAllowedProofLeavesNum allows to specify acceptable range or mekle tree proof leaves num.
// That allows to specify volume of transfered POW and verifier's job to check it
func WithAllowedProofLeavesNum(minLeavesNum, maxLeavesNum int) Option {
	if minLeavesNum > maxLeavesNum {
		minLeavesNum, maxLeavesNum = maxLeavesNum, minLeavesNum
	}
	return func(cfg *config) {
		cfg.minAllowedProofLeavesNum = minLeavesNum
		cfg.maxAllowedProofLeavesNum = maxLeavesNum
	}
}
