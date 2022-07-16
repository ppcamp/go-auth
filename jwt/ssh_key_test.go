package jwt_test

import (
	"testing"

	"github.com/ppcamp/go-auth/jwt"

	"github.com/stretchr/testify/require"
)

func TestParseSSHPrivateKey(t *testing.T) {
	assert := require.New(t)

	_, err := jwt.ParseSSHPrivateKey(jwtPrivate)
	assert.Nil(err)

	wrongKey := []rune(jwtPrivate)
	wrongKey[37] = rune('a')

	_, err = jwt.ParseSSHPrivateKey(string(wrongKey))
	assert.NotNil(err)
}
