package impl

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
	nodeCount := getNodeCount(1)
	assert.EqualValues(t, 1, nodeCount)

	nodeCount = getNodeCount(4)
	assert.EqualValues(t, 15, nodeCount)

	nodeCount = getNodeCount(10)
	assert.EqualValues(t, 1023, nodeCount)

	nodeCount = getNodeCount(0)
	assert.EqualValues(t, 0, nodeCount)

	assert.Panics(t, func() { getNodeCount(-42) })
}

func TestGetFather(t *testing.T) {
	assert.Panics(t, func() { getFatherNum(0) })

	father := getFatherNum(1)
	assert.EqualValues(t, 0, father)

	father = getFatherNum(2)
	assert.EqualValues(t, 0, father)

	father = getFatherNum(10)
	assert.EqualValues(t, 4, father)

	father = getFatherNum(11)
	assert.EqualValues(t, 5, father)

	father = getFatherNum(12)
	assert.EqualValues(t, 5, father)

	father = getFatherNum(13)
	assert.EqualValues(t, 6, father)

	father = getFatherNum(98713)
	assert.EqualValues(t, 49356, father)
}

func TestIsLeaf(t *testing.T) {
	isLeafRes := isLeaf(0, 1)
	assert.True(t, isLeafRes)

	for i := 0; i <= 6; i++ {
		isLeafRes = isLeaf(i, 4)
		assert.False(t, isLeafRes)
	}
	for i := 7; i <= 14; i++ {
		isLeafRes = isLeaf(i, 4)
		assert.True(t, isLeafRes)
	}

	for i := 15; i < 42; i++ {
		assert.Panics(t, func() { isLeaf(i, 4) })
	}
}

func TestGetChildren(t *testing.T) {
	assert.Panics(t, func() { getChildrenNums(7, 4) })

	left, right := getChildrenNums(1, 4)
	assert.EqualValues(t, 3, left)
	assert.EqualValues(t, 4, right)

	left, right = getChildrenNums(6, 4)
	assert.EqualValues(t, 13, left)
	assert.EqualValues(t, 14, right)
}
