package impl

import (
	"github.com/joomcode/errorx"
)

func getNodeCount(depth int) int {
	if depth < 0 {
		panic(errorx.Panic(errorx.IllegalArgument.New("merkle tree's depth should be a non-negative number, actual %d", depth)))
	}
	return (1 << depth) - 1
}

func getFatherNum(nodeNum int) int {
	if nodeNum < 0 {
		panic(errorx.Panic(errorx.IllegalArgument.New("node's number should be a non-negative number, actual %d", nodeNum)))
	}
	if nodeNum == 0 {
		panic(errorx.Panic(errorx.IllegalArgument.New("the root with id '0' have no father")))
	}
	return (nodeNum - 1) / 2
}

func isLeaf(nodeNum int, depth int) bool {
	nodeCount := getNodeCount(depth)

	if nodeNum >= nodeCount {
		panic(errorx.Panic(errorx.IllegalArgument.New("node's number %d (starts from 0) for the depth %d is greater than the tree size %d",
			nodeNum, depth, nodeCount)))
	}

	// the only node is the root, and it's a tree's only leaf
	if depth == 1 {
		return true
	}

	nonLeafNodeCount := getNodeCount(depth - 1)
	return nodeNum >= nonLeafNodeCount
}

func getChildrenNums(nodeNum int, depth int) (int, int) {
	if isLeaf(nodeNum, depth) {
		panic(errorx.Panic(errorx.IllegalArgument.New("node with num %d is a leaf, leaf nodes have no children", nodeNum)))
	}

	return nodeNum*2 + 1, nodeNum*2 + 2
}
