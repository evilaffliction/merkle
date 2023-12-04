package middleware

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/evilaffliction/merkle/pkg/algo/hash"
)

// the shorter json tags, the more space efficient merkle POW
type node struct {
	Num        int    `json:"n"`
	Value      string `json:"v"`
	IsSelected bool   `json:"i,omitempty"`
}

func nodesToString(nodes []node) (string, error) {
	jsonData, err := json.Marshal(&nodes)
	if err != nil {
		return "", fmt.Errorf("failed to json marshal node data, error: %w", err)
	}
	var compressionBuffer bytes.Buffer
	gz, err := gzip.NewWriterLevel(&compressionBuffer, 9)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip writer, error: %w", err)
	}
	if _, err := gz.Write(jsonData); err != nil {
		return "", fmt.Errorf("failed to compress node data, error: %w", err)
	}
	if err := gz.Flush(); err != nil {
		return "", fmt.Errorf("failed to flush compressed node data, error: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", fmt.Errorf("failed to close compression procedure for node data, error: %w", err)
	}

	return base64.StdEncoding.EncodeToString(compressionBuffer.Bytes()), nil
}

func stringToNodes(data string) ([]node, error) {
	rawData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unhex data, error: %w", err)
	}
	compressedDataBuffer := bytes.NewBuffer(rawData)
	r, err := gzip.NewReader(compressedDataBuffer)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader for compressed node data, error: %w", err)
	}

	var decompressionBuffer bytes.Buffer
	if _, err := decompressionBuffer.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("failed to ungzip compressed node data, error: %w", err)
	}

	nodesJSONData := decompressionBuffer.Bytes()
	var result []node

	if err := json.Unmarshal(nodesJSONData, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal nodes json data, error: %w", err)
	}

	return result, nil
}

type accessToken struct {
	TimeStampMicros int64
	Value           hash.Byte16
}

func (rcv accessToken) String() string {
	return fmt.Sprintf("%d_%s", rcv.TimeStampMicros, rcv.Value.String())
}

func newAcessToken() accessToken {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(rand.New(rand.NewSource(time.Now().UnixNano())).Int()))
	return accessToken{
		TimeStampMicros: time.Now().UnixMicro(),
		Value:           hash.MD5Hasher{}.Hash(b),
	}
}

// the shorter json tags, the more space efficient merkle POW
type headerData struct {
	TimeStampMicros int64       `json:"t`
	AccessToken     hash.Byte16 `json:"a"`
	HashFunction    string      `json:"h`
	Depth           int         `json:"d"`
	ProofLeavesNum  int         `json:"p"`
	NodeData        string      `json:"n"`
}
