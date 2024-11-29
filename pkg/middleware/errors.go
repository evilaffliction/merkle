package middleware

import (
	"github.com/joomcode/errorx"
)

var ErrorNamespace = errorx.NewNamespace("MerkleErrorNamespace")

var InvalidInputError = ErrorNamespace.NewType("InvalidInput")
var InternalError = ErrorNamespace.NewType("InternalError")
var InsufficientComplexityError = ErrorNamespace.NewType("InsufficientComplexity")
var OverwhelmingComplexityError = ErrorNamespace.NewType("OverwhelmingComplexity")
var IncorrectMerkleError = ErrorNamespace.NewType("IncorrectMerkle")
