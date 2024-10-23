package impl

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"

	"github.com/joomcode/errorx"

	"github.com/evilaffliction/merkle/pkg/algo/hash"
	"github.com/evilaffliction/merkle/pkg/algo/merkle"
)

// Node is just a node with a hash function
type node struct {
	hashValue hash.Value
}

// tree represents a merkle tree that will be stored as an ordered list of nodes.
// every merkle tree is complete
//
// Nodes of tree a stored in array in order to improve performance.
// Functions in aux.go help to find father<->sons connection by their position in the "nodes" array.
type tree struct {
	depth          int
	proofLeavesNum int
	hashName       string
	description    string
	nodes          []node
}

func (rcv *tree) Depth() int {
	return rcv.depth
}

// NewTree is a constructor for a Merkle tree
// It requires
//
//			1: "hasher" to bring crypto security
//			2: "depth" that allows you to bring higher CPU costs for a prover
//			3: "proofLeavesNum" that allows you to bring higher network cost
//	     	4: "description" that varies generation of a tree. Ideally it should incorporate a timestamp
func NewTree(
	hashName string,
	depth int,
	proofLeavesNum int,
	description string,
) (merkle.Tree, error) {

	// the trivial case is not viable and brings error handling complexity -> remove it
	if depth <= 1 {
		return nil, errorx.IllegalArgument.New("too shallow depth %d, expected to be at least 2", depth)
	}

	hasher, err := hash.NameToHasher(hashName)
	if err != nil {
		return nil, errorx.IllegalArgument.Wrap(err, "failed to create hasher for merkle tree")
	}

	// Encoding depth and needed proofLeavesNum into description
	// it is needed to avoid malicious intents by varying them by a prover.
	// Customizing tree hash generation by a seed that depends on income parameters
	seededHasher := hash.NewSeededHasher(hasher, description, depth, proofLeavesNum)

	nodeCount := getNodeCount(depth)
	nonLeafNodeCount := getNodeCount(depth - 1)

	// check that we do not demand too many proof nodes
	leafNodeCount := nodeCount - nonLeafNodeCount
	if proofLeavesNum > leafNodeCount/2 {
		return nil, errorx.IllegalArgument.New("too many proof leaves (%d) required for a tree with depth %d, max allowed: %d",
			proofLeavesNum, depth, leafNodeCount/2)
	}

	// actual build process starts here
	nodes := make([]node, nodeCount)

	// init build from leaves
	b := make([]byte, 8)
	for nodeNum := nodeCount - 1; nodeNum >= nonLeafNodeCount; nodeNum-- {
		binary.LittleEndian.PutUint64(b, uint64(nodeNum))
		nodeHashValue := seededHasher.Hash(b)
		nodes[nodeNum] = node{
			hashValue: nodeHashValue,
		}
	}
	// build the rest of the tree, starting from the lowest (with greater depth) nodes
	for nodeNum := nonLeafNodeCount - 1; nodeNum >= 0; nodeNum-- {
		leftSonNum, rightSonNum := getChildrenNums(nodeNum, depth)
		leftHash := nodes[leftSonNum].hashValue
		rightHash := nodes[rightSonNum].hashValue
		nodeHashValue := seededHasher.Hash(hash.XORHashes(leftHash, rightHash).ToSlice())
		nodes[nodeNum] = node{
			hashValue: nodeHashValue,
		}
	}
	return &tree{
		depth:          depth,
		proofLeavesNum: proofLeavesNum,
		hashName:       hashName,
		description:    description,
		nodes:          nodes,
	}, nil
}

// Verify allows you to check that a given Tree is correctly stored in terms of a Merkel tree
func (rcv *tree) verify() error {
	hasher, _ := hash.NameToHasher(rcv.hashName)
	seededHasher := hash.NewSeededHasher(hasher, rcv.description, rcv.depth, rcv.proofLeavesNum)

	nodeCount := getNodeCount(rcv.depth)
	nonLeafNodeCount := getNodeCount(rcv.depth - 1)

	// check that we have indeed expected number of nodes
	if nodeCount != len(rcv.nodes) {
		return fmt.Errorf("merkle tree with depth %d ecxpted to have %d nodes, actual count: %d",
			rcv.depth, nodeCount, len(rcv.nodes))
	}

	// check leaves
	b := make([]byte, 8)
	for nodeNum := nodeCount - 1; nodeNum >= nonLeafNodeCount; nodeNum-- {
		binary.LittleEndian.PutUint64(b, uint64(nodeNum))
		if !rcv.nodes[nodeNum].hashValue.EqualsTo(seededHasher.Hash(b)) {
			return fmt.Errorf("leaf node %d has incorrect hash value", nodeNum)
		}
	}

	// check non-leaf nodes
	for nodeNum := nonLeafNodeCount - 1; nodeNum >= 0; nodeNum-- {
		leftSonNum, rightSonNum := getChildrenNums(nodeNum, rcv.depth)
		tmpBuf := hash.XORHashes(rcv.nodes[leftSonNum].hashValue, rcv.nodes[rightSonNum].hashValue)
		expectedHash := seededHasher.Hash(tmpBuf.ToSlice())
		if !rcv.nodes[nodeNum].hashValue.EqualsTo(expectedHash) {
			return fmt.Errorf("non-leaf node %d has incorrect hash value", nodeNum)
		}
	}

	return nil
}

// selectProofLeafsByHash allows you to choose from which leaves one should
// build a partial tree for a proof of work
func selectProofLeavesByHash(hashValue hash.Value, depth int, numOfProofLeaves int) map[int]struct{} {
	hashSeed := hashValue.ToSlice()
	if len(hashSeed) > 8 {
		hashSeed = hashSeed[0:8]
	}
	randomSeed := binary.BigEndian.Uint64(hashSeed)
	randSource := rand.NewSource(int64(randomSeed))
	pseudoRandomGenerator := rand.New(randSource)

	nodeCount := getNodeCount(depth)
	nonLeafNodeCount := getNodeCount(depth - 1)
	leafNodeCount := nodeCount - nonLeafNodeCount

	selectedIndexes := make(map[int]struct{}, numOfProofLeaves)
	for len(selectedIndexes) < numOfProofLeaves {
		newIndex := pseudoRandomGenerator.Int()%leafNodeCount + nonLeafNodeCount
		selectedIndexes[newIndex] = struct{}{}
	}

	return selectedIndexes
}

// generateProofOfWorkWithSelectedLeaves builds proof of work by provided
// leaves. The building process starts from the leaves and goes up, level by level
// of a merkle tree
func (rcv *tree) generateProofOfWorkWithSelectedLeaves(
	leaves map[int]struct{},
) merkle.ProofOfWork {

	neededNodes := make([]int, 0, len(leaves)+2*rcv.depth) // heuristic size assumption
	for leaf := range leaves {
		neededNodes = append(neededNodes, leaf)
	}

	curLevelNodes := leaves
	for i := 0; i < rcv.depth-1; i++ {
		fatherNodes := make(map[int]struct{}, len(curLevelNodes)/2)
		for curNodePos := range curLevelNodes {
			fatherNum := getFatherNum(curNodePos)
			fatherNodes[fatherNum] = struct{}{}
		}
		for fatherNodePos := range fatherNodes {
			leftSonNum, rightSonNum := getChildrenNums(fatherNodePos, rcv.depth)
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

	nodesStats := make([]nodeStats, 0, len(neededNodes))
	for _, nodeNum := range neededNodes {
		_, ok := leaves[nodeNum]
		nodesStats = append(nodesStats, nodeStats{
			Num:        nodeNum,
			Value:      rcv.nodes[nodeNum].hashValue.String(),
			IsSelected: ok,
		})
	}

	return &proofOfWork{
		NodesStats:        nodesStats,
		HashName:          rcv.hashName,
		Description:       rcv.description,
		DepthVal:          rcv.depth,
		ProofLeavesNumVal: rcv.proofLeavesNum,
	}
}

// GenerateProofOfWork generates a proof of work from a fully built merkle tree
func (rcv *tree) GenerateProofOfWork() merkle.ProofOfWork {
	leaves := selectProofLeavesByHash(rcv.nodes[0].hashValue, rcv.depth, rcv.proofLeavesNum)
	return rcv.generateProofOfWorkWithSelectedLeaves(leaves)
}

func computeHash(
	hasher hash.Hasher,
	nodeNum int,
	depth int,
	computedNodes map[int]node,
) hash.Value {

	_, ok := computedNodes[nodeNum]
	if ok {
		res := computedNodes[nodeNum].hashValue
		delete(computedNodes, nodeNum) // all nodes should be used exactly 1 time
		return res
	}

	leftSonNum, rightSonNum := getChildrenNums(nodeNum, depth)
	leftHash := computeHash(hasher, leftSonNum, depth, computedNodes)
	rightHash := computeHash(hasher, rightSonNum, depth, computedNodes)

	return hasher.Hash(hash.XORHashes(leftHash, rightHash).ToSlice())
}