package wssecurity

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"time"
)

const AuthPattern = `^UsernameToken Username="(?P<Username>.+)", PasswordDigest="(?P<passwordDigest>.+)", Nonce="(?P<nonce>.+)", Created="(?P<created>.+)"$`
const AuthString = `UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"`
const NonceLength = 16

func ExtractHeaderProperties(decodedHeader string) map[string]string {
	exp := regexp.MustCompile(AuthPattern)
	match := exp.FindStringSubmatch(decodedHeader)

	result := make(map[string]string)
	for i, name := range exp.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}

	return result
}

func (s Security) GenerateAuthHeader() (string, *SecurityError) {
	nonce := make([]byte, NonceLength)
	_, nonceErr := rand.Read(nonce)
	if nonceErr != nil {
		return "", &SecurityError{Message: "Could not generate random nonce"}
	}

	encodedNonce := base64Encode(nonce)
	created := time.Now().Format(time.RFC3339)

	digest, err := s.GenerateDigest(encodedNonce, created)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		AuthString,
		s.Username,
		digest,
		base64Encode(nonce),
		created,
	), nil
}

func DecodeHeader(encodedHeader string) (string, *SecurityError) {
	decodedHeader, err := base64Decode(encodedHeader)
	if err != nil {
		return "", err
	}

	return decodedHeader, nil
}

func EncodeHeader(header string) string {
	return base64Encode([]byte(header))
}
