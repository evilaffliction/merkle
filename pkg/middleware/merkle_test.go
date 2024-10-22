package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestMekleHeader(t *testing.T) {
	r := gin.Default()
	r.Use(GetMerkleMiddleware())
	r.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})

	t.Run("No_merkle_header_means_no_success", func(t *testing.T) {
		w := httptest.NewRecorder()

		req, _ := http.NewRequest("GET", "/ping", nil)

		r.ServeHTTP(w, req)
		assert.Equal(t, 406, w.Code)
		assert.NotEqual(t, "pong", w.Body.String())
	})

	t.Run("Fully_create_proof_of_work", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/ping", nil)
		assert.NoError(t, err)
		headerPayload, err := GenerateMerkleHeader(23, 5, "md5")
		assert.NoError(t, err)
		req.Header.Set(MerkleHeaderName, headerPayload)

		t.Run("fresh_pow_is_good", func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
			assert.Equal(t, "pong", w.Body.String())
		})

		t.Run("reusal_is_prohibitted", func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, 406, w.Code)
			assert.NotEqual(t, "pong", w.Body.String())
		})
	})
}
