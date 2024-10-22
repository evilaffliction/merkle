package middleware

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/evilaffliction/merkle/pkg/algo/hash"
)

type accessToken struct {
	TimeStampMicros int64
	Value           hash.Value
}

func (rcv accessToken) String() string {
	return fmt.Sprintf("%d_%s", rcv.TimeStampMicros, rcv.Value.String())
}

func newAccessToken() accessToken {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(rand.New(rand.NewSource(time.Now().UnixNano())).Int()))
	return accessToken{
		TimeStampMicros: time.Now().UnixMicro(),
		Value:           hash.MD5Hasher{}.Hash(b),
	}
}

func restoreAccessToken(s string) (accessToken, error) {
	parts := strings.SplitN(s, "_", 2)
	if len(parts) != 2 {
		return accessToken{}, fmt.Errorf("unknown ")
	}

	ts, err := strconv.ParseInt(parts[0], 10, 0)
	if err != nil {
		return accessToken{}, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	v, err := hash.FromString(parts[1])
	if err != nil {
		return accessToken{}, fmt.Errorf("failed to pars hash value: %w", err)
	}

	return accessToken{
		TimeStampMicros: ts,
		Value:           v,
	}, nil
}
