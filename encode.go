package wssecurity

import (
	"crypto/sha1"
	"encoding/base64"
)

func base64Decode(encodedString string) (string, *SecurityError) {
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		return "", NewSecurityError("Failed to base64 decode string")
	}

	return string(decodedBytes), nil
}

func base64Encode(content []byte) string {
	return base64.StdEncoding.EncodeToString(content)
}

func sha1Encode(plainString string) [20]byte {
	return sha1.Sum([]byte(plainString))
}
