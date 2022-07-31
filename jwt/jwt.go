package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

var (
	ErrTokenInvalid error = errors.New("token invalid")
	ErrFailToParse  error = errors.New("fail to parse")
)

type Parser interface {
	Session(signedToken string) (*Claims, error)
}

type Generator interface {
	Generate(session *Session, exp time.Duration) (string, error)
}

type Interface interface {
	Parser
	Generator
}

type Session struct {
	// Audience is equivalent to the destination (the app/device that will use this token)
	Audience string

	// Subject is used to retrieve who this token belongs to, usually it can be used as the user's
	// id
	Subject string

	// Roles is used to retrieve the user's access (RBAC).
	Roles []string
}

type Claims struct {
	Roles []string `json:"roles,omitempty"`
	*jwt.StandardClaims
}

func (s *Claims) Session() *Session { return &Session{s.Audience, s.Subject, s.Roles} }

// Jwt creates a new jwt encoder/decoder. To this implementation, I'm using
// an RSA algorithm
// Note
//
// - The HMAC signing method (HS256,HS384,HS512) expect []byte values for
// signing and validation
//
// - The RSA signing method (RS256,RS384,RS512) expect *rsa.PrivateKey for
// signing and *rsa.PublicKey for validation
//
// - The ECDSA signing method (ES256,ES384,ES512) expect *ecdsa.PrivateKey for
// signing and *ecdsa.PublicKey for validation
//
// - The EDSA signing method (Ed25519) expect ed25519.PrivateKey for signing
// and ed25519.PublicKey for validation
type Jwt struct {
	// SignSecret is a parsed private key string.
	//
	// Example
	//
	// secret := jwt.ParseRSAPrivateKeyFromPEM([]byte(mockOpenSSL))
	SignSecret *rsa.PrivateKey

	// VerifySecret is a parsed public key string used to verify if the token matches.
	//
	// Example
	//
	// secret := jwt.ParseRSAPublicKeyFromPEM([]byte(mockOpenSSL))
	VerifySecret *rsa.PublicKey

	// Issuer is the name of the service that is creating the token, it can be such as
	// "auth-microservice".
	Issuer string
}

// Generate some token for a given session
func (j *Jwt) Generate(session *Session, exp time.Duration) (string, error) {
	claims := Claims{
		StandardClaims: &jwt.StandardClaims{
			Issuer:    j.Issuer,
			ExpiresAt: time.Now().Add(exp).Unix(),
			IssuedAt:  time.Now().Unix(),
			Audience:  session.Audience,
			Subject:   session.Subject,
		},
		Roles: session.Roles,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(j.SignSecret)
}

// Parse does the decrypt of some token. It also checks for the correct alg
// using Go's reflection
func (j *Jwt) parse(signedToken string) (*Claims, error) {
	// used to check if the method matches
	keyFunc := func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.VerifySecret, nil
	}

	claims := new(Claims)
	if _, err := jwt.ParseWithClaims(signedToken, claims, keyFunc); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return claims, nil
}

func (j *Jwt) Session(signedToken string) (*Claims, error) {
	claims, err := j.parse(signedToken)
	if err != nil {
		return nil, ErrFailToParse
	}

	if err = claims.Valid(); err != nil {
		return nil, fmt.Errorf("claims aren't valid: %w", err)
	}

	return claims, nil
}
