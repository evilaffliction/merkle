package impl

import (
	"encoding/json"
	"testing"

	"github.com/evilaffliction/merkle/pkg/algo/merkle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONMarshalling(t *testing.T) {
	val := &proofOfWork{
		NodesStats: []nodeStats{
			{
				Num:        42,
				Value:      "King_Arthur",
				IsSelected: true,
			},
			{
				Num:   31415926535,
				Value: "Merlin",
			},
		},
		HashName:          "md5",
		Description:       "Excalibur",
		DepthVal:          999,
		ProofLeavesNumVal: 1,
	}

	i := merkle.ProofOfWork(val)

	jsonData, err := json.Marshal(i)
	require.NoError(t, err)
	require.NotEmpty(t, jsonData)

	restoredInterface, err := RestoreProofOfWorkFromJSON(jsonData)
	require.NoError(t, err)
	require.NotNil(t, restoredInterface)

	restoredVal, ok := restoredInterface.(*proofOfWork)
	require.True(t, ok)
	assert.Equal(t, *val, *restoredVal)
}
