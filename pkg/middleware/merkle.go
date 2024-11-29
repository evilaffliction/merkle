package middleware

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/evilaffliction/merkle/pkg/algo/merkle/impl"
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
		return InvalidInputError.New("no merkle auth header")
	}

	if len(header) > 1 {
		return InvalidInputError.New("unexpected merkle header struct, found several headers, expected only 1")
	}

	pow, err := impl.RestoreProofOfWorkFromJSON([]byte(header[0]))
	if err != nil {
		return InvalidInputError.Wrap(err, "unexpected merkle header struct")
	}

	accessTokenStr := pow.AccessToken()
	_, err = accessTokenCache.Get(accessTokenStr)
	switch {
	case errors.Is(err, gcache.KeyNotFoundError):
		// all is good, access token is fresh
	case err != nil:
		return InternalError.Wrap(err, "failed to verify request in cache history")
	default:
		return IncorrectMerkleError.New("access tokent %q was already used", accessTokenStr)
	}

	if err := accessTokenCache.Set(accessTokenStr, struct{}{}); err != nil {
		return InternalError.Wrap(err, "failed to set cache")
	}

	if pow.Depth() < cfg.minAllowedDepth || pow.ProofLeavesNum() < cfg.minAllowedProofLeavesNum {
		return InsufficientComplexityError.New("prover work volume is too small")
	}

	if pow.Depth() > cfg.maxAllowedDepth || pow.ProofLeavesNum() > cfg.maxAllowedProofLeavesNum {
		return OverwhelmingComplexityError.New("verifier is expected to have large amount of work")
	}

	accessToken, err := restoreAccessToken(accessTokenStr)
	if err != nil {
		return IncorrectMerkleError.Wrap(err, "failed to parse access token")
	}

	now := time.Now().UnixMicro()
	if now < accessToken.TimeStampMicros {
		return IncorrectMerkleError.New("prover time stamp is in future")
	}

	// 5 seconds
	if now-accessToken.TimeStampMicros > cfg.accessTokenLifeTime.Microseconds() {
		return IncorrectMerkleError.New("prover time stamp is dated")
	}

	if err := pow.Verify(); err != nil {
		return IncorrectMerkleError.Wrap(err, "failed to verify pow")
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
			rest.EndpointSecurityResponse(ctx, IncorrectMerkleError.Wrap(err, "merkle tree verification failed"))
			return
		}

		ctx.Next()
	}
}

// GenerateMerkleHeader generates compact, serialized PoW based on Merkle trees.
// Header from this function is supposed to be served by a middleware from GetMerkleMiddleware
func GenerateMerkleHeader(depth int, proofLeavesNum int, hashFunc string) (string, error) {
	accessToken := newAccessToken()
	tree, err := impl.NewTree(
		hashFunc,
		depth,
		proofLeavesNum,
		accessToken.String(),
	)
	if err != nil {
		return "", InternalError.Wrap(err, "failed to create new merkle tree")
	}

	pow := tree.GenerateProofOfWork()
	jsonData, err := json.Marshal(pow)
	if err != nil {
		return "", InternalError.Wrap(err, "failed to json marshal merkle header")
	}

	return string(jsonData), nil
}
