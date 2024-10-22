package impl

import (
	"fmt"
)

func getNodeCount(depth int) (int, error) {
	if depth < 0 {
		return 0, fmt.Errorf("merkle tree's depth should be a non-negative number, actual %d", depth)
	}
	return (1 << depth) - 1, nil
}

func getFatherNum(nodeNum int) (int, error) {
	if nodeNum < 0 {
		return 0, fmt.Errorf("node's number should be a non-negative number, actual %d", nodeNum)
	}
	if nodeNum == 0 {
		return 0, fmt.Errorf("the root with id '0' have no father")
	}
	return (nodeNum - 1) / 2, nil
}

func isLeaf(nodeNum int, depth int) (bool, error) {
	nodeCount, err := getNodeCount(depth)
	if err != nil {
		return false, fmt.Errorf("failed to determine whether a node is a leaf, error: %w", err)
	}

	if nodeNum >= nodeCount {
		return false, fmt.Errorf("node's number %d (starts from 0) for the depth %d is greater than the tree size %d",
			nodeNum, depth, nodeCount)
	}

	// the only node is the root and it's a tree's only leaf
	if depth == 1 {
		return true, nil
	}

	nonLeafNodeCount, err := getNodeCount(depth - 1)
	if err != nil {
		// unreachable: depth is more than 1
		panic(err)
	}

	return nodeNum >= nonLeafNodeCount, nil
}

func getChildrenNums(nodeNum int, depth int) (int, int, error) {
	isLeafNode, err := isLeaf(nodeNum, depth)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to find node's children, error: %w", err)
	}
	if isLeafNode {
		return 0, 0, fmt.Errorf("node with num %d is a leaf, leaf nodes have no children", nodeNum)
	}

	return nodeNum*2 + 1, nodeNum*2 + 2, nil
}
