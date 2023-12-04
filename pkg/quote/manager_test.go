package quote

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadingQuotes(t *testing.T) {
	data, err := os.ReadFile("../../data/test_quotes.txt")
	assert.NoError(t, err)
	assert.NotNil(t, data)

	m := NewInMemoryManagerImpl(int64(42))
	assert.NotNil(t, m)

	_, err = m.GetRandomQuote()
	assert.Error(t, err)
	m.LoadQuotesFromText(data, []byte{'\n'})
	quote, err := m.GetRandomQuote()
	assert.NoError(t, err)
	assert.NotEmpty(t, quote)
}
