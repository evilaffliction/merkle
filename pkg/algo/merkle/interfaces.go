package merkle

type ProofOfWork interface {
	Verify() error
	AccessToken() string
	Depth() int
	ProofLeavesNum() int
}

type Tree interface {
	GenerateProofOfWork() (ProofOfWork, error)
	Depth() int
}
