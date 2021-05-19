package wssecurity

func (s Security) GenerateDigest(nonce, created string) (string, *SecurityError) {
	sha1Result := sha1Encode(
		nonce +
			created +
			s.Secret,
	)

	return base64Encode(sha1Result[:]), nil
}
