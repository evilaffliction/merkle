package impl

import (
	"encoding/json"
	"fmt"

	"github.com/evilaffliction/merkle/pkg/algo/hash"
	"github.com/evilaffliction/merkle/pkg/algo/merkle"
)

// nodeStats is a structure stores information about a merkle tree's node (not necessary a leaf)
type nodeStats struct {
	Num        int    `json:"num"`
	Value      string `json:"value"`
	IsSelected bool   `json:"bool,omitempty"`
}

// proofOfWork stores information about a computed Merkle tree without storing the whole tree
// Allows you to check that a prover has indeed computed the whole tree
type proofOfWork struct {
	NodesStats        []nodeStats `json:"node_stats"`
	HashName          string      `json:"hash_name"`
	Description       string      `json:"description"`
	DepthVal          int         `json:"depth"`
	ProofLeavesNumVal int         `json:"proof_leaves_num"`
}

// confirm interface's implementation
var _ merkle.ProofOfWork = (*proofOfWork)(nil)

// Verify verifies that a Merkle tree was originally built and
// a given proof of work was built from it
func (rcv *proofOfWork) Verify() error {
	hasher, err := hash.NameToHasher(rcv.HashName)
	if err != nil {
		return fmt.Errorf("unable to get hasher: %w", err)
	}
	seededHasher := hash.NewSeededHasher(hasher, rcv.Description, rcv.DepthVal, rcv.ProofLeavesNumVal)

	nodes := make(map[int]node, len(rcv.NodesStats))
	for _, nodeStats := range rcv.NodesStats {
		newHashVal, err := hash.FromString(nodeStats.Value)
		if err != nil {
			return err
		}
		nodes[nodeStats.Num] = node{
			hashValue: newHashVal,
		}
	}
	rootHash := computeHash(seededHasher, 0, rcv.DepthVal, nodes)

	if len(nodes) != 0 {
		return fmt.Errorf("malfmed proof of work, not all nodes were used to compute root hash")
	}

	expectedSelectedLeafNodes := selectProofLeavesByHash(rootHash, rcv.DepthVal, rcv.ProofLeavesNumVal)
	actualSelectedLeafNodes := make(map[int]struct{})
	for _, nodeStats := range rcv.NodesStats {
		if nodeStats.IsSelected {
			actualSelectedLeafNodes[nodeStats.Num] = struct{}{}
		}
	}
	if len(expectedSelectedLeafNodes) != len(actualSelectedLeafNodes) {
		return fmt.Errorf("expected number %d and acutal number %d of selected leafs are different",
			len(expectedSelectedLeafNodes), len(actualSelectedLeafNodes))
	}
	for expectedNodePos := range expectedSelectedLeafNodes {
		_, ok := actualSelectedLeafNodes[expectedNodePos]
		if !ok {
			return fmt.Errorf("node %d is expected to be selected, but it is not", expectedNodePos)
		}
	}

	return nil
}

func (rcv *proofOfWork) AccessToken() string {
	return rcv.Description
}

func (rcv *proofOfWork) Depth() int {
	return rcv.DepthVal
}

func (rcv *proofOfWork) ProofLeavesNum() int {
	return rcv.ProofLeavesNumVal
}

func RestoreProofOfWorkFromJSON(jsonData []byte) (merkle.ProofOfWork, error) {
	var res proofOfWork
	if err := json.Unmarshal(jsonData, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal json value to proof of work: %w", err)
	}
	return &res, nil
}
