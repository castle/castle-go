package castle

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureModeSignature(t *testing.T) {
	client, err := New("secret")
	require.NoError(t, err)

	// HMAC-SHA256("test", key="secret"), hex-encoded.
	expected := "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914"
	assert.Equal(t, expected, client.SecureModeSignature("test"))
}
