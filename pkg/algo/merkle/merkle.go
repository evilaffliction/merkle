package merkle

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"reflect"
	"sort"

	"github.com/evilaffliction/merkle/pkg/algo/hash"
)

// Node is just a node with a hash function
type Node struct {
	hashValue hash.Value
}

// Tree represents a merkle tree that will be stored as an ordered list of nodes.
// No direct connection between nodes (father->sons, son->father) is going to be stored.
// Since Merkle tree is supposed to be a complete binary tree father's/sons' locations are
// deductable from the node number.
// Parametrized by
//
//	1: DescriptionT any description of a request that should be convertable to a string
type Tree struct {
	depth          int
	proofLeavesNum int
	hasher         hash.Hasher
	description    string
	nodes          []Node
}

// NewTree is a constructor for a Merkle tree
// It requires
//
//			1: "hasher" to bring crypto security
//			2: "depth" that allows you to bring higher CPU costs for a prover
//			3: "proofLeavesNum" that allows you to bring higher network cost
//	     	4: "description" that varies generation of a tree. Ideally it should encorporate a timestamp
func NewTree(
	hasher hash.Hasher,
	depth int,
	proofLeavesNum int,
	description string,
) (*Tree, error) {

	// the trivial case is not viable and brings error handling complexity -> remove it
	if depth <= 1 {
		return nil, fmt.Errorf("too shallow depth %d, expected to be at least 2", depth)
	}

	// Encoding depth and needed proofLeavesNum into description
	// it is needed to avoid malicious intents by varying them by a prover.
	// Customizing tree hash generation by a seed that depends on a income parameters
	seededHahser := hash.NewSeededHasher(hasher, description, depth, proofLeavesNum)

	nodeCount, err := getNodeCount(depth)
	if err != nil {
		return nil, fmt.Errorf("failed to get total node count for a merkle tree, error:error %w", err)
	}
	nonLeafNodeCount, err := getNodeCount(depth - 1)
	if err != nil {
		return nil, fmt.Errorf("failed to get total non-leaf node count for a merkle tree, error: %w", err)
	}

	// check that we do not demand too many proof nodes
	leafNodeCount := (nodeCount - nonLeafNodeCount)
	if proofLeavesNum > leafNodeCount/2 {
		return nil, fmt.Errorf("too many proof leaves (%d) required for a tree with depth %d, max allowed: %d",
			proofLeavesNum, depth, leafNodeCount/2)
	}

	// actual build process starts here
	nodes := make([]Node, nodeCount)

	// init build from leaves
	b := make([]byte, 8)
	for nodeNum := nodeCount - 1; nodeNum >= nonLeafNodeCount; nodeNum-- {
		binary.LittleEndian.PutUint64(b, uint64(nodeNum))
		nodeHashValue := seededHahser.Hash(b)
		nodes[nodeNum] = Node{
			hashValue: nodeHashValue,
		}
	}
	// build the rest of the tree, starting from the lowest (with greater depth) nodes
	for nodeNum := nonLeafNodeCount - 1; nodeNum >= 0; nodeNum-- {
		leftSonNum, rightSonNum, err := getChildrenNums(nodeNum, depth)
		if err != nil {
			// unreachable since we are sure that nodes have their children
			panic(err)
		}
		leftHash := nodes[leftSonNum].hashValue
		rightHash := nodes[rightSonNum].hashValue
		nodeHashValue := seededHahser.Hash(hash.XORHashes(leftHash, rightHash).ToSlice())
		nodes[nodeNum] = Node{
			hashValue: nodeHashValue,
		}
	}
	return &Tree{
		depth:          depth,
		proofLeavesNum: proofLeavesNum,
		hasher:         hasher,
		description:    description,
		nodes:          nodes,
	}, nil
}

// Verify allows you to check that a given Tree is correctly stored in termes of a Merkel tree
func (rcv *Tree) Verify() error {
	seededHahser := hash.NewSeededHasher(rcv.hasher, rcv.description, rcv.depth, rcv.proofLeavesNum)

	nodeCount, err := getNodeCount(rcv.depth)
	if err != nil {
		return fmt.Errorf("failed to get total node count for a merkle tree, error:error %w", err)
	}
	nonLeafNodeCount, err := getNodeCount(rcv.depth - 1)
	if err != nil {
		return fmt.Errorf("failed to get total non-leaf node count for a merkle tree, error: %w", err)
	}

	// check that we have indeed expected number of nodes
	if nodeCount != len(rcv.nodes) {
		return fmt.Errorf("Merkle tree with depth %d ecxpted to have %d nodes, actual count: %d",
			rcv.depth, nodeCount, len(rcv.nodes))
	}

	// check leaves
	b := make([]byte, 8)
	for nodeNum := nodeCount - 1; nodeNum >= nonLeafNodeCount; nodeNum-- {
		binary.LittleEndian.PutUint64(b, uint64(nodeNum))
		if !reflect.DeepEqual(rcv.nodes[nodeNum].hashValue, seededHahser.Hash(b)) {
			return fmt.Errorf("leaf node %d has incorrect hash value", nodeNum)
		}
	}

	// check non-leaf nodes
	for nodeNum := nonLeafNodeCount - 1; nodeNum >= 0; nodeNum-- {
		leftSonNum, rightSonNum, err := getChildrenNums(nodeNum, rcv.depth)
		if err != nil {
			panic(err)
		}
		tmpBuf := hash.XORHashes(rcv.nodes[leftSonNum].hashValue, rcv.nodes[rightSonNum].hashValue)
		expectedHash := seededHahser.Hash(tmpBuf.ToSlice())
		if !reflect.DeepEqual(rcv.nodes[nodeNum].hashValue, expectedHash) {
			return fmt.Errorf("non-leaf node %d has incorrect hash value", nodeNum)
		}
	}

	return nil
}

// NodeStats is a structure that allows you to store information about a node (not necessary a leaf)
// when stored in a ProofOfWork structure
type NodeStats struct {
	Num        int
	Value      string
	IsSelected bool
}

// ProofOfWork stores information about a computed Merkle tree without storing the whole tree
// Allows you to check that a prover has indeed computed the whole tree
type ProofOfWork struct {
	NodesStats     []NodeStats
	Hasher         hash.Hasher
	Description    string
	Depth          int
	ProofLeavesNum int
}

// selectProofLeafsByHash allows you to choose from wich leaves one should
// build a partial tree for a proof of work
func selectProofLeavesByHash(hashValue hash.Value, depth int, numOfProofLeafes int) (map[int]struct{}, error) {
	hashSeed := hashValue.ToSlice()
	if len(hashSeed) > 8 {
		hashSeed = hashSeed[0:8]
	}
	randomSeed := binary.BigEndian.Uint64(hashSeed)
	randSource := rand.NewSource(int64(randomSeed))
	pseudoRandomGenerator := rand.New(randSource)

	nodeCount, err := getNodeCount(depth)
	if err != nil {
		return nil, fmt.Errorf("failed to get total node count for a merkle tree, error:error %w", err)
	}
	nonLeafNodeCount, err := getNodeCount(depth - 1)
	if err != nil {
		return nil, fmt.Errorf("failed to get total non-leaf node count for a merkle tree, error: %w", err)
	}
	leafNodeCount := nodeCount - nonLeafNodeCount

	selectedIndexes := make(map[int]struct{}, numOfProofLeafes)
	for len(selectedIndexes) < numOfProofLeafes {
		newIndex := pseudoRandomGenerator.Int()%leafNodeCount + nonLeafNodeCount
		selectedIndexes[newIndex] = struct{}{}
	}

	return selectedIndexes, nil
}

// generateProofOfWorkWithSelectedLeafes builds proof of work by provided
// leafes. The building process starts from the leaves and goes up, level by level
// of a merkle tree
func (rcv *Tree) generateProofOfWorkWithSelectedLeafes(
	leaves map[int]struct{},
) (*ProofOfWork, error) {

	neededNodes := make([]int, 0, len(leaves)+2*rcv.depth) // euristic size assumption
	for leaf := range leaves {
		neededNodes = append(neededNodes, leaf)
	}

	curLevelNodes := leaves
	for i := 0; i < rcv.depth-1; i++ {
		fatherNodes := make(map[int]struct{})
		for curNodePos := range curLevelNodes {
			fatherNum, err := getFatherNum(curNodePos)
			if err != nil {
				return nil, err
			}
			fatherNodes[fatherNum] = struct{}{}
		}
		for fatherNodePos := range fatherNodes {
			leftSonNum, rightSonNum, err := getChildrenNums(fatherNodePos, rcv.depth)
			if err != nil {
				return nil, err
			}
			if _, ok := curLevelNodes[leftSonNum]; !ok {
				neededNodes = append(neededNodes, leftSonNum)
			}
			if _, ok := curLevelNodes[rightSonNum]; !ok {
				neededNodes = append(neededNodes, rightSonNum)
			}
		}

		curLevelNodes = fatherNodes
	}

	sort.SliceStable(neededNodes, func(i, j int) bool {
		return neededNodes[i] < neededNodes[j]
	})

	nodesStats := make([]NodeStats, 0, len(neededNodes))
	for _, nodeNum := range neededNodes {
		_, ok := leaves[nodeNum]
		nodesStats = append(nodesStats, NodeStats{
			Num:        nodeNum,
			Value:      rcv.nodes[nodeNum].hashValue.String(),
			IsSelected: ok,
		})
	}

	return &ProofOfWork{
		NodesStats:     nodesStats,
		Hasher:         rcv.hasher,
		Description:    rcv.description,
		Depth:          rcv.depth,
		ProofLeavesNum: rcv.proofLeavesNum,
	}, nil
}

// GenerateProofOfWork generates a proof of work from a fully built merkle tree
func (rcv *Tree) GenerateProofOfWork() (*ProofOfWork, error) {
	leaves, err := selectProofLeavesByHash(rcv.nodes[0].hashValue, rcv.depth, rcv.proofLeavesNum)
	if err != nil {
		return nil, fmt.Errorf("failed to select leaves for verification, error: %w", err)
	}
	return rcv.generateProofOfWorkWithSelectedLeafes(leaves)

}

func computeHash(
	hasher hash.Hasher,
	nodeNum int,
	depth int,
	computedNodes map[int]Node,
) (hash.Value, error) {

	_, ok := computedNodes[nodeNum]
	if ok {
		res := computedNodes[nodeNum].hashValue
		delete(computedNodes, nodeNum) // all nodes should be used exactly 1 time
		return res, nil
	}

	var defaultResult hash.Value
	leftSonNum, rightSonNum, err := getChildrenNums(nodeNum, depth)
	if err != nil {
		return defaultResult, err
	}
	leftHash, err := computeHash(hasher, leftSonNum, depth, computedNodes)
	if err != nil {
		return defaultResult, err
	}
	rightHash, err := computeHash(hasher, rightSonNum, depth, computedNodes)
	if err != nil {
		return defaultResult, err
	}

	return hasher.Hash(hash.XORHashes(leftHash, rightHash).ToSlice()), nil
}

// Verify verifies that a Merkle tree was originally built and
// a given proof of work was built from it
func (rcv *ProofOfWork) Verify() error {
	hasher := rcv.Hasher

	seededHahser := hash.NewSeededHasher(hasher, rcv.Description, rcv.Depth, rcv.ProofLeavesNum)

	nodes := make(map[int]Node, len(rcv.NodesStats))
	for _, nodeStats := range rcv.NodesStats {
		newHashVal, err := hash.FromString(nodeStats.Value)
		if err != nil {
			return err
		}
		nodes[nodeStats.Num] = Node {
			hashValue: newHashVal,
		}
	}
	rootHash, err := computeHash(seededHahser, 0, rcv.Depth, nodes)
	if err != nil {
		return fmt.Errorf("failed to compute root hash, error: %w", err)
	}

	if len(nodes) != 0 {
		return fmt.Errorf("malfmed proof of work, not all nodes were used to compute root hash")
	}

	expectedSelectedLeafNodes, err := selectProofLeavesByHash(rootHash, rcv.Depth, rcv.ProofLeavesNum)
	if err != nil {
		return fmt.Errorf("failed to select proof leaves, error: %w", err)
	}
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
