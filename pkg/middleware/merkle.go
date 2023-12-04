package middleware

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/evilaffliction/merkle/pkg/algo/hash"
	"github.com/evilaffliction/merkle/pkg/algo/merkle"
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

	var merkleData headerData
	if err := json.Unmarshal([]byte(header[0]), &merkleData); err != nil {
		return fmt.Errorf("unexpected merkle header struct")
	}
	_, err := accessTokenCache.Get(merkleData.AccessToken.String())
	switch {
	case err == gcache.KeyNotFoundError:
		// all is good, access token is fresh
	case err != nil:
		return fmt.Errorf("failed to verify request in cache history, error: %w", err)
	default:
		return fmt.Errorf("access tokent %s was already used", merkleData.AccessToken)
	}

	accessTokenCache.Set(merkleData.AccessToken.String(), struct{}{})

	if merkleData.Depth < 10 || merkleData.ProofLeavesNum < 3 {
		return fmt.Errorf("prover work volume is too small")
	}

	if merkleData.Depth > 25 || merkleData.ProofLeavesNum > 10 {
		return fmt.Errorf("verifier is expected to have large amount of work")
	}

	now := time.Now().UnixMicro()
	if now < merkleData.TimeStampMicros {
		return fmt.Errorf("prover time stamp is in future")
	}

	// 5 seconds
	if now-merkleData.TimeStampMicros > cfg.accessTokenLifeTime.Microseconds() {
		return fmt.Errorf("prover time stamp is dated")
	}

	nodesData, err := stringToNodes(merkleData.NodeData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal node data")
	}

	merkleNodesStats := make([]merkle.NodeStats, 0, len(nodesData))
	for _, nodeStats := range nodesData {
		merkleNodesStats = append(merkleNodesStats, merkle.NodeStats{
			Num:        nodeStats.Num,
			Value:      nodeStats.Value,
			IsSelected: nodeStats.IsSelected,
		})
	}

	switch merkleData.HashFunction {
	case "md5":
		hasher := hash.MD5Hasher{}
		givenPOW := &merkle.ProofOfWork[hash.Byte16, accessToken]{
			NodesStats: merkleNodesStats,
			Hasher:     hasher,
			Description: accessToken{
				TimeStampMicros: merkleData.TimeStampMicros,
				Value:           merkleData.AccessToken,
			},
			Depth:          merkleData.Depth,
			ProofLeavesNum: merkleData.ProofLeavesNum,
		}
		if err := givenPOW.Verify(); err != nil {
			return fmt.Errorf("merkle tree verification failed")
		}
	case "sha256":
		hasher := hash.SHA256Hahser{}
		givenPOW := &merkle.ProofOfWork[hash.Byte32, accessToken]{
			NodesStats: merkleNodesStats,
			Hasher:     hasher,
			Description: accessToken{
				TimeStampMicros: merkleData.TimeStampMicros,
				Value:           merkleData.AccessToken,
			},
			Depth:          merkleData.Depth,
			ProofLeavesNum: merkleData.ProofLeavesNum,
		}
		if err := givenPOW.Verify(); err != nil {
			return fmt.Errorf("merkle tree verification failed")
		}
	default:
		return fmt.Errorf("unsupported hash function")
	}

	return nil
}

// GetMerkleMiddlware returns a fully ready gin-gonic middleware for a POW
// functionality based on merkle trees.
// One should use GenerateMerkleHeader to build a correct header for this middleware
func GetMerkleMiddlware(opts ...Option) gin.HandlerFunc {
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
	accessToken := newAcessToken()
	var rawNodes []merkle.NodeStats
	switch hashFunc {
	case "md5":
		hasher := hash.MD5Hasher{}
		tree, err := merkle.NewTree(
			hasher,
			depth,
			proofLeavesNum,
			accessToken,
		)
		if err != nil {
			return "", err
		}
		generatedPOW, err := tree.GenerateProofOfWork()
		if err != nil {
			return "", err
		}
		rawNodes = generatedPOW.NodesStats
	case "sha256":
		hasher := hash.SHA256Hahser{}
		tree, err := merkle.NewTree(
			hasher,
			depth,
			proofLeavesNum,
			accessToken,
		)
		if err != nil {
			return "", err
		}
		generatedPOW, err := tree.GenerateProofOfWork()
		if err != nil {
			return "", err
		}
		rawNodes = generatedPOW.NodesStats
	default:
		return "", fmt.Errorf("unknown hash function %q", hashFunc)
	}

	convertedNodes := make([]node, 0, len(rawNodes))
	for _, rawNode := range rawNodes {
		convertedNodes = append(convertedNodes, node{
			Num:        rawNode.Num,
			Value:      rawNode.Value,
			IsSelected: rawNode.IsSelected,
		})
	}

	nodeData, err := nodesToString(convertedNodes)
	if err != nil {
		return "", fmt.Errorf("failed to marshal nodes, error: %w", err)
	}

	merkleData := headerData{
		TimeStampMicros: accessToken.TimeStampMicros,
		AccessToken:     accessToken.Value,
		HashFunction:    hashFunc,
		Depth:           depth,
		ProofLeavesNum:  proofLeavesNum,
		NodeData:        nodeData,
	}

	jsonData, err := json.Marshal(&merkleData)
	if err != nil {
		return "", fmt.Errorf("failed to json marshal merkle header, error: %w", err)
	}
	return string(jsonData), nil
}
