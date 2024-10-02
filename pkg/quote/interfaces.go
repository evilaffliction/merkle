package quote

import "math/rand/v2"

// RandGenerator provides an interface for a random generator that is able to create a rand int in a given diapason
type RandGenerator interface {
	IntN(maxInt int) int
}

// interface check
var _ RandGenerator = (*rand.Rand)(nil)
