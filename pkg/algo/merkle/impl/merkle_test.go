package impl

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/evilaffliction/merkle/pkg/algo/hash"
)

func getTree(t *testing.T, depth int, proofLeavesNum int, description string) *tree {
	i, err := NewTree("md5", depth, proofLeavesNum, description)
	require.NoError(t, err)
	v, ok := i.(*tree)
	require.True(t, ok)
	require.NoError(t, v.verify())
	return v
}

func TestPlainTree(t *testing.T) {
	v := getTree(t, 4, 2, "Mors sua, vita nostra")
	require.NotNil(t, v)
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
	t.Run("depth_5_and_1_leaf_selected_manually", func(t *testing.T) {
		// example of a merkle tree enumeration with depth 4
		// 1)                                 0
		// 2)                   1                          *2
		// 3)           *3             4            5               6
		// 4)        7       8     9     *10    11     12      13       14
		// 5)      15 16   17 18 19*20* 21 22  23 24  25 26   27 28    29 30
		// ------------------------------------------
		// node 20 is selected initially

		rawTree := getTree(t, 5, 2, "Per aspera ad astra")

		selectedLeafes := map[int]struct{}{
			20: {},
		}
		currentPow, err := rawTree.generateProofOfWorkWithSelectedLeaves(selectedLeafes)
		assert.NoError(t, err)
		assert.NotNil(t, currentPow)
		rawPow := currentPow.(*proofOfWork)
		assert.EqualValues(t, "Per aspera ad astra", rawPow.Description)
		assert.EqualValues(t, 5, currentPow.Depth())
		assert.Len(t, rawPow.NodesStats, 5)
		assert.EqualValues(t, rawPow.NodesStats[0].Num, 2)
		assert.EqualValues(t, rawPow.NodesStats[0].IsSelected, false)
		assert.EqualValues(t, rawPow.NodesStats[1].Num, 3)
		assert.EqualValues(t, rawPow.NodesStats[1].IsSelected, false)
		assert.EqualValues(t, rawPow.NodesStats[2].Num, 10)
		assert.EqualValues(t, rawPow.NodesStats[2].IsSelected, false)
		assert.EqualValues(t, rawPow.NodesStats[3].Num, 19)
		assert.EqualValues(t, rawPow.NodesStats[3].IsSelected, false)
		assert.EqualValues(t, rawPow.NodesStats[4].Num, 20)
		assert.EqualValues(t, rawPow.NodesStats[4].IsSelected, true)
	})
	t.Run("depth_5_and_4_leaf_selected_manually", func(t *testing.T) {
		// example of a merkle tree enumeration with depth 4
		// 1)                                 0
		// 2)                   1                           2
		// 3)            3             4            5               6
		// 4)       *7       8    *9      10    11    *12      13      *14
		// 5)      15 16  *17*18 19 20 *21*22 *23*24  25 26   *27*28    29 30
		// ------------------------------------------
		// nodes 18, 21, 23, 28 are selected initially
		rawTree := getTree(t, 5, 2, "No hablo espanol, senior")

		selectedLeaves := map[int]struct{}{
			18: {},
			21: {},
			23: {},
			28: {},
		}
		currentPow, err := rawTree.generateProofOfWorkWithSelectedLeaves(selectedLeaves)
		assert.NoError(t, err)
		assert.NotNil(t, currentPow)
		rawPow := currentPow.(*proofOfWork)
		assert.EqualValues(t, "No hablo espanol, senior", rawPow.Description)
		assert.EqualValues(t, 5, currentPow.Depth())
		assert.Len(t, rawPow.NodesStats, 12)
		assert.EqualValues(t, rawPow.NodesStats[0].Num, 7)
		assert.EqualValues(t, rawPow.NodesStats[0].IsSelected, false)
		assert.EqualValues(t, rawPow.NodesStats[1].Num, 9)
		assert.EqualValues(t, rawPow.NodesStats[1].IsSelected, false)
		assert.EqualValues(t, rawPow.NodesStats[2].Num, 12)
		assert.EqualValues(t, rawPow.NodesStats[2].IsSelected, false)
		assert.EqualValues(t, rawPow.NodesStats[3].Num, 14)
		assert.EqualValues(t, rawPow.NodesStats[3].IsSelected, false)
		assert.EqualValues(t, rawPow.NodesStats[4].Num, 17)
		assert.EqualValues(t, rawPow.NodesStats[4].IsSelected, false)
		assert.EqualValues(t, rawPow.NodesStats[5].Num, 18)
		assert.EqualValues(t, rawPow.NodesStats[5].IsSelected, true)
		assert.EqualValues(t, rawPow.NodesStats[6].Num, 21)
		assert.EqualValues(t, rawPow.NodesStats[6].IsSelected, true)
		assert.EqualValues(t, rawPow.NodesStats[7].Num, 22)
		assert.EqualValues(t, rawPow.NodesStats[7].IsSelected, false)
		assert.EqualValues(t, rawPow.NodesStats[8].Num, 23)
		assert.EqualValues(t, rawPow.NodesStats[8].IsSelected, true)
		assert.EqualValues(t, rawPow.NodesStats[9].Num, 24)
		assert.EqualValues(t, rawPow.NodesStats[9].IsSelected, false)
		assert.EqualValues(t, rawPow.NodesStats[10].Num, 27)
		assert.EqualValues(t, rawPow.NodesStats[10].IsSelected, false)
		assert.EqualValues(t, rawPow.NodesStats[11].Num, 28)
		assert.EqualValues(t, rawPow.NodesStats[11].IsSelected, true)
	})
}

func TestProofOfWorkVerification(t *testing.T) {
	rawTree := getTree(t, 21, 100, "Veni vidi vici")

	t.Run("Generated_POW_should_be_good", func(t *testing.T) {
		generatedPow, err := rawTree.GenerateProofOfWork()
		assert.NoError(t, err)
		assert.NotNil(t, generatedPow)

		err = generatedPow.Verify()
		assert.NoError(t, err)
	})

	t.Run("Changing_description_should_break_verification", func(t *testing.T) {
		generatedPow, _ := rawTree.GenerateProofOfWork()
		rawPow := generatedPow.(*proofOfWork)
		rawPow.Description = "no no no"
		err := rawPow.Verify()
		assert.Error(t, err)
	})

	t.Run("Extra_nodes_should_break_verification", func(t *testing.T) {
		generatedPow, _ := rawTree.GenerateProofOfWork()
		rawPow := generatedPow.(*proofOfWork)
		rawPow.NodesStats = append(rawPow.NodesStats, nodeStats{
			Num:        666,
			Value:      hash.MD5Hasher{}.Hash([]byte("al diablo")).String(),
			IsSelected: false,
		})
		err := generatedPow.Verify()
		assert.Error(t, err)
	})
}

func Benchmark_MD5_GenerationProofOfWork(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t, err := NewTree("md5", 20, 10, fmt.Sprintf("bench_%d", i))
		assert.NoError(b, err)
		assert.NotNil(b, t)

		pow, err := t.GenerateProofOfWork()
		assert.NoError(b, err)
		assert.NotNil(b, pow)
	}
}

func Benchmark_MD5_VerifyProofOfWork(b *testing.B) {
	t, err := NewTree("md5", 20, 10, "bench")
	assert.NoError(b, err)
	assert.NotNil(b, t)

	pow, err := t.GenerateProofOfWork()
	assert.NoError(b, err)
	assert.NotNil(b, pow)

	for i := 0; i < b.N; i++ {
		err := pow.Verify()
		assert.NoError(b, err)
	}
}
