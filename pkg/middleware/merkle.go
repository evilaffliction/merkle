package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/evilaffliction/merkle/pkg/algo/merkle/impl"
	"github.com/gin-gonic/gin"

	"github.com/evilaffliction/merkle/pkg/rest"

	"github.com/bluele/gcache"
)

// MerkleHeaderName represents a name for a header that contains PoW
const MerkleHeaderName = "Merkle-Check"

func validateMerkleHeader(
	header []string,
	accessTokenCache gcache.Cache,
	cfg config,
) error {
	if len(header) == 0 {
		return fmt.Errorf("no merkle auth header")
	}

	if len(header) > 1 {
		return fmt.Errorf("unexpected merkle header struct")
	}

	pow, err := impl.RestoreProofOfWorkFromJSON([]byte(header[0]))
	if err != nil {
		return fmt.Errorf("unexpected merkle header struct: %w", err)
	}

	accessTokenStr := pow.AccessToken()
	_, err = accessTokenCache.Get(accessTokenStr)
	switch {
	case errors.Is(err, gcache.KeyNotFoundError):
		// all is good, access token is fresh
	case err != nil:
		return fmt.Errorf("failed to verify request in cache history, error: %w", err)
	default:
		return fmt.Errorf("access tokent %s was already used", accessTokenStr)
	}

	if err := accessTokenCache.Set(accessTokenStr, struct{}{}); err != nil {
		return fmt.Errorf("failed to set cache, error: %w", err)
	}

	if pow.Depth() < 10 || pow.ProofLeavesNum() < 3 {
		return fmt.Errorf("prover work volume is too small")
	}

	if pow.Depth() > 25 || pow.ProofLeavesNum() > 10 {
		return fmt.Errorf("verifier is expected to have large amount of work")
	}

	accessToken, err := restoreAccessToken(accessTokenStr)
	if err != nil {
		return fmt.Errorf("failed to parse access token: %w", err)
	}

	now := time.Now().UnixMicro()
	if now < accessToken.TimeStampMicros {
		return fmt.Errorf("prover time stamp is in future")
	}

	// 5 seconds
	if now-accessToken.TimeStampMicros > cfg.accessTokenLifeTime.Microseconds() {
		return fmt.Errorf("prover time stamp is dated")
	}

	if err := pow.Verify(); err != nil {
		return fmt.Errorf("failed to verify pow: %w", err)
	}

	return nil
}

// GetMerkleMiddleware returns a fully ready gin-gonic middleware for a POW
// functionality based on merkle trees.
// One should use GenerateMerkleHeader to build a correct header for this middleware
func GetMerkleMiddleware(opts ...Option) gin.HandlerFunc {
	cfg := newConfigFromOptions(opts...)
	accessTokenCache := gcache.New(cfg.accessTokenCacheSize).Expiration(time.Minute).Build()
	return func(ctx *gin.Context) {
		if err := validateMerkleHeader(ctx.Request.Header[MerkleHeaderName], accessTokenCache, cfg); err != nil {
			// TODO: remove err details from a response for a better security
			rest.EndpointSecurityResponse(ctx, fmt.Errorf("merkle tree verification failed, error: %w", err))
			return
		}

		ctx.Next()
	}
}

// GenerateMerkleHeader generates compact, serialized PoW based on Merkle trees.
// Header from this function is supposed to be served by a middleware from GetMerkleMiddlware
func GenerateMerkleHeader(depth int, proofLeavesNum int, hashFunc string) (string, error) {
	accessToken := newAccessToken()
	tree, err := impl.NewTree(
		hashFunc,
		depth,
		proofLeavesNum,
		accessToken.String(),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create new merkle tree: %w", err)
	}

	pow, err := tree.GenerateProofOfWork()
	if err != nil {
		return "", fmt.Errorf("failed to generate proof of work: %w", err)
	}

	jsonData, err := json.Marshal(pow)
	if err != nil {
		return "", fmt.Errorf("failed to json marshal merkle header, error: %w", err)
	}

	return string(jsonData), nil
}
