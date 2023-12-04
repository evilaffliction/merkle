package merkle

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// example of a mekrle tree enumeration with depth 4
// 1)                    0
// 2)           1                 2
// 3)       3        4        5        6
// 4)     7    8  9    10  11   12  13   14
// ------------------------------------------

func TestNodeCount(t *testing.T) {
	nodeCount, err := getNodeCount(1)
	assert.NoError(t, err)
	assert.EqualValues(t, 1, nodeCount)

	nodeCount, err = getNodeCount(4)
	assert.NoError(t, err)
	assert.EqualValues(t, 15, nodeCount)

	nodeCount, err = getNodeCount(10)
	assert.NoError(t, err)
	assert.EqualValues(t, 1023, nodeCount)

	nodeCount, err = getNodeCount(0)
	assert.NoError(t, err)
	assert.EqualValues(t, 0, nodeCount)

	nodeCount, err = getNodeCount(-42)
	assert.Error(t, err)
}

func TestGetFather(t *testing.T) {
	father, err := getFatherNum(0)
	assert.Error(t, err)

	father, err = getFatherNum(1)
	assert.NoError(t, err)
	assert.EqualValues(t, 0, father)

	father, err = getFatherNum(2)
	assert.NoError(t, err)
	assert.EqualValues(t, 0, father)

	father, err = getFatherNum(10)
	assert.NoError(t, err)
	assert.EqualValues(t, 4, father)

	father, err = getFatherNum(11)
	assert.NoError(t, err)
	assert.EqualValues(t, 5, father)

	father, err = getFatherNum(12)
	assert.NoError(t, err)
	assert.EqualValues(t, 5, father)

	father, err = getFatherNum(13)
	assert.NoError(t, err)
	assert.EqualValues(t, 6, father)

	father, err = getFatherNum(98713)
	assert.NoError(t, err)
	assert.EqualValues(t, 49356, father)
}

func TestIsLeaf(t *testing.T) {
	isLeafRes, err := isLeaf(0, 1)
	assert.NoError(t, err)
	assert.True(t, isLeafRes)

	for i := 0; i <= 6; i++ {
		isLeafRes, err = isLeaf(i, 4)
		assert.NoError(t, err)
		assert.False(t, isLeafRes)
	}
	for i := 7; i <= 14; i++ {
		isLeafRes, err = isLeaf(i, 4)
		assert.NoError(t, err)
		assert.True(t, isLeafRes)
	}

	for i := 15; i < 42; i++ {
		_, err = isLeaf(i, 4)
		assert.Error(t, err)
	}
}

func TestGetChildren(t *testing.T) {
	left, right, err := getChildrenNums(7, 4)
	assert.Error(t, err)

	left, right, err = getChildrenNums(1, 4)
	assert.NoError(t, err)
	assert.EqualValues(t, 3, left)
	assert.EqualValues(t, 4, right)

	left, right, err = getChildrenNums(6, 4)
	assert.NoError(t, err)
	assert.EqualValues(t, 13, left)
	assert.EqualValues(t, 14, right)
}
