package merkle

import (
	"github.com/joomcode/errorx"
)

var ErrorNamespace = errorx.NewNamespace("MerkleErrorNamespace")

var InvalidInput = ErrorNamespace.NewType("InvalidInput")
