package merkle

import (
	"fmt"
	"testing"

	"github.com/evilaffliction/merkle/pkg/algo/hash"

	"github.com/stretchr/testify/assert"
)

func TestTreeBuilding(t *testing.T) {
	hasher := hash.MD5Hasher{}
	tree, err := NewTree(hasher, 4, 2, "Mors sua, vita nostra")
	assert.NoError(t, err)
	assert.NotNil(t, tree)
	assert.NoError(t, tree.Verify())
}

func TestStabilityOfProofLeafesGeneration(t *testing.T) {
	hasher := hash.MD5Hasher{}
	someHash := hasher.Hash([]byte("To be, or not to be, that is the question:"))
	nodeNumsOriginal, err := selectProofLeavesByHash(someHash, 10, 15)
	assert.NoError(t, err)
	assert.Len(t, nodeNumsOriginal, 15)
	for nodeNum := range nodeNumsOriginal {
		isLeafNode, err := isLeaf(nodeNum, 10)
		assert.NoError(t, err)
		assert.True(t, isLeafNode)
	}
	for i := 0; i < 10; i++ {
		nodeNums, err := selectProofLeavesByHash(someHash, 10, 15)
		assert.NoError(t, err)
		assert.EqualValues(t, nodeNumsOriginal, nodeNums)
	}

	otherHash := hasher.Hash([]byte("Whether 'tis nobler in the mind to suffer"))
	otherNodeNums, err := selectProofLeavesByHash(otherHash, 10, 15)
	assert.NoError(t, err)
	assert.NotEqualValues(t, nodeNumsOriginal, otherNodeNums)
}

func TestCorrectnessOfProofOfWork(t *testing.T) {
	hasher := hash.MD5Hasher{}
	t.Run("depth_5_and_1_leaf_selected_manually", func(t *testing.T) {
		// example of a mekrle tree enumeration with depth 4
		// 1)                                 0
		// 2)                   1                          *2
		// 3)           *3             4            5               6
		// 4)        7       8     9     *10    11     12      13       14
		// 5)      15 16   17 18 19*20* 21 22  23 24  25 26   27 28    29 30
		// ------------------------------------------
		// node 20 is selected initially
		tree, err := NewTree(hasher, 5, 2, "Per aspera ad astra")
		assert.NoError(t, err)
		assert.NotNil(t, tree)
		assert.NoError(t, tree.Verify())

		selectedLeafes := map[int]struct{}{
			20: {},
		}
		currentPow, err := tree.generateProofOfWorkWithSelectedLeaves(selectedLeafes)
		assert.NoError(t, err)
		assert.NotNil(t, currentPow)
		assert.EqualValues(t, "Per aspera ad astra", currentPow.Description)
		assert.EqualValues(t, 5, currentPow.Depth)
		assert.Len(t, currentPow.NodesStats, 5)
		assert.EqualValues(t, currentPow.NodesStats[0].Num, 2)
		assert.EqualValues(t, currentPow.NodesStats[0].IsSelected, false)
		assert.EqualValues(t, currentPow.NodesStats[1].Num, 3)
		assert.EqualValues(t, currentPow.NodesStats[1].IsSelected, false)
		assert.EqualValues(t, currentPow.NodesStats[2].Num, 10)
		assert.EqualValues(t, currentPow.NodesStats[2].IsSelected, false)
		assert.EqualValues(t, currentPow.NodesStats[3].Num, 19)
		assert.EqualValues(t, currentPow.NodesStats[3].IsSelected, false)
		assert.EqualValues(t, currentPow.NodesStats[4].Num, 20)
		assert.EqualValues(t, currentPow.NodesStats[4].IsSelected, true)
	})
	t.Run("depth_5_and_4_leaf_selected_manually", func(t *testing.T) {
		// example of a mekrle tree enumeration with depth 4
		// 1)                                 0
		// 2)                   1                           2
		// 3)            3             4            5               6
		// 4)       *7       8    *9      10    11    *12      13      *14
		// 5)      15 16  *17*18 19 20 *21*22 *23*24  25 26   *27*28    29 30
		// ------------------------------------------
		// nodes 18, 21, 23, 28 are selected initially
		tree, err := NewTree(hasher, 5, 2, "No hablo espanol, senior")
		assert.NoError(t, err)
		assert.NotNil(t, tree)
		assert.NoError(t, tree.Verify())
		selectedLeafes := map[int]struct{}{
			18: {},
			21: {},
			23: {},
			28: {},
		}
		currentPow, err := tree.generateProofOfWorkWithSelectedLeaves(selectedLeafes)
		assert.NoError(t, err)
		assert.NotNil(t, currentPow)
		assert.EqualValues(t, "No hablo espanol, senior", currentPow.Description)
		assert.EqualValues(t, 5, currentPow.Depth)
		assert.Len(t, currentPow.NodesStats, 12)
		assert.EqualValues(t, currentPow.NodesStats[0].Num, 7)
		assert.EqualValues(t, currentPow.NodesStats[0].IsSelected, false)
		assert.EqualValues(t, currentPow.NodesStats[1].Num, 9)
		assert.EqualValues(t, currentPow.NodesStats[1].IsSelected, false)
		assert.EqualValues(t, currentPow.NodesStats[2].Num, 12)
		assert.EqualValues(t, currentPow.NodesStats[2].IsSelected, false)
		assert.EqualValues(t, currentPow.NodesStats[3].Num, 14)
		assert.EqualValues(t, currentPow.NodesStats[3].IsSelected, false)
		assert.EqualValues(t, currentPow.NodesStats[4].Num, 17)
		assert.EqualValues(t, currentPow.NodesStats[4].IsSelected, false)
		assert.EqualValues(t, currentPow.NodesStats[5].Num, 18)
		assert.EqualValues(t, currentPow.NodesStats[5].IsSelected, true)
		assert.EqualValues(t, currentPow.NodesStats[6].Num, 21)
		assert.EqualValues(t, currentPow.NodesStats[6].IsSelected, true)
		assert.EqualValues(t, currentPow.NodesStats[7].Num, 22)
		assert.EqualValues(t, currentPow.NodesStats[7].IsSelected, false)
		assert.EqualValues(t, currentPow.NodesStats[8].Num, 23)
		assert.EqualValues(t, currentPow.NodesStats[8].IsSelected, true)
		assert.EqualValues(t, currentPow.NodesStats[9].Num, 24)
		assert.EqualValues(t, currentPow.NodesStats[9].IsSelected, false)
		assert.EqualValues(t, currentPow.NodesStats[10].Num, 27)
		assert.EqualValues(t, currentPow.NodesStats[10].IsSelected, false)
		assert.EqualValues(t, currentPow.NodesStats[11].Num, 28)
		assert.EqualValues(t, currentPow.NodesStats[11].IsSelected, true)
	})
}

func TestProofOfWorkVerification(t *testing.T) {
	hasher := hash.MD5Hasher{}
	tree, err := NewTree(hasher, 21, 100, "Veni vidi vici")
	assert.NoError(t, err)
	assert.NotNil(t, tree)
	assert.NoError(t, tree.Verify())

	t.Run("Generated_POW_should_be_good", func(t *testing.T) {
		generatedPow, err := tree.GenerateProofOfWork()
		assert.NoError(t, err)
		assert.NotNil(t, generatedPow)

		err = generatedPow.Verify()
		assert.NoError(t, err)
	})

	t.Run("Changing_description_should_break_verification", func(t *testing.T) {
		generatedPow, _ := tree.GenerateProofOfWork()
		generatedPow.Description = "no no no"
		err = generatedPow.Verify()
		assert.Error(t, err)
	})

	t.Run("Extra_nodes_should_break_verification", func(t *testing.T) {
		generatedPow, _ := tree.GenerateProofOfWork()
		generatedPow.NodesStats = append(generatedPow.NodesStats, NodeStats{
			Num:        666,
			Value:      hasher.Hash([]byte("al diablo")).String(),
			IsSelected: false,
		})
		err = generatedPow.Verify()
		assert.Error(t, err)
	})
}

func Benchmark_MD5_GenerationProofOfWork(b *testing.B) {
	hasher := hash.MD5Hasher{}
	for i := 0; i < b.N; i++ {
		tree, err := NewTree(hasher, 20, 10, fmt.Sprintf("bench_%d", i))
		assert.NoError(b, err)
		assert.NotNil(b, tree)

		generatedPow, err := tree.GenerateProofOfWork()
		assert.NoError(b, err)
		assert.NotNil(b, generatedPow)
	}
}

func Benchmark_MD5_VerifyProofOfWork(b *testing.B) {
	hasher := hash.MD5Hasher{}
	tree, err := NewTree(hasher, 20, 10, "bench")
	assert.NoError(b, err)
	assert.NotNil(b, tree)

	generatedPow, err := tree.GenerateProofOfWork()
	assert.NoError(b, err)
	assert.NotNil(b, generatedPow)

	for i := 0; i < b.N; i++ {
		err := generatedPow.Verify()
		assert.NoError(b, err)
	}
}
