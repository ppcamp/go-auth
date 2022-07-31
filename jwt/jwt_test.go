package jwt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ppcamp/go-auth/jwt"

	mjwt "github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
)

// TestGenerateAndSession test if everything went fine to generate the token. It also tests if we
// could parse it and if matches the same objects from the original session. It also checks if the
// token had expired or not, accordding to the tests cases.
func TestGenerateAndSession(t *testing.T) {
	assert := require.New(t)

	mockedUser := "mockedUser"

	privateKey, err := mjwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	assert.NoError(err)

	publicKey, err := mjwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
	assert.NoError(err)

	signer := &jwt.Jwt{
		SignSecret:   privateKey,
		VerifySecret: publicKey,
		Issuer:       "test-service",
	}

	type tk struct {
		exp time.Duration
		err error
	}

	tests := []tk{{exp: 1 * time.Second, err: nil}, {exp: 2 * time.Second, err: jwt.ErrFailToParse}}
	for _, test := range tests {
		session := &jwt.Session{
			Subject:  mockedUser,
			Audience: "web",
			Roles:    []string{"admin", "user"},
		}
		token, err := signer.Generate(session, test.exp)
		assert.NoError(err)

		claims, err := signer.Session(token)

		if test.err != nil {
			fn := func() bool { return errors.Is(err, test.err) }
			assert.Never(fn, test.exp-1*time.Second, 500*time.Millisecond)
		} else {
			assert.NoError(err)
			assert.EqualValues(session, claims.Session())
		}

	}
}
