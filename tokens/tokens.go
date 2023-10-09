package tokens

import (
	"auth/types"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	jwt "github.com/dvsekhvalnov/jose2go"
)

// returns a new JWT token
func GenJWT(GUID string, secret string, lifetime time.Duration) (string, error) {
	pObj := types.JwtPayload{
		Sub: GUID,
		Iat: time.Now().Unix(),
		Exp: (time.Now().Add(lifetime).Unix()),
	}
	payload, err := json.Marshal(pObj)
	if err != nil {
		return "", err
	}
	token, err := jwt.Sign(string(payload), jwt.HS512, []byte(secret))
	if err != nil {
		return "", err
	}
	return token, nil
}

// returns a new refresh token
func GenRefresh() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return fmt.Sprintf("%x", b), err
}
