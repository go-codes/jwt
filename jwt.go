package jwt

import (
	"errors"
	"fmt"
	jwtGo "github.com/dgrijalva/jwt-go"
	"time"
)

type Jwt struct {
	Conf Config
	Secret []byte
}

func New(conf Config) *Jwt {
	return &Jwt{
		Conf: conf,
		Secret: []byte(conf.Secret),
	}
}

func (j *Jwt) Token(data map[string]interface{}) (string, error) {
	nowUnix := time.Now().Unix()
	claims := jwtGo.MapClaims{
		"sub": "login token",
		"iat": nowUnix,
		"exp": nowUnix + int64(j.Conf.Lifetime),
	}

	for k, v := range data {
		claims[k] = v
	}
	token := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(j.Secret)

	return tokenString, err
}

func (j *Jwt) Verify (tokenStr string) (map[string]interface{}, error){
	token, err := jwtGo.Parse(tokenStr, func(token *jwtGo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtGo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.Secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwtGo.MapClaims)
	if !ok {
		return nil, errors.New("unparsable structured data")
	}
	return claims, nil
}