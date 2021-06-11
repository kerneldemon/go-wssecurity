package wssecurity

type Security struct {
	Username string
	Secret   string
	Lifetime int64
}

func NewSecurity(username, secret string, lifetime int64) *Security {
	return &Security{
		Username: username,
		Secret:   secret,
		Lifetime: lifetime,
	}
}

func (s Security) IsAuthSuccessful(decodedHeader string) (bool, *SecurityError) {
	headerProperties, err := ExtractHeaderProperties(decodedHeader)
	if err != nil {
		return false, err
	}

	if isValid, err := s.IsCreatedDateValid(headerProperties["created"]); !isValid {
		return false, err
	}

	decodedNonce, securityError := base64Decode(headerProperties["nonce"])
	if securityError != nil {
		return false, securityError
	}

	expectedDigest, err := s.GenerateDigest(decodedNonce, headerProperties["created"])
	if err != nil {
		return false, err
	}

	if expectedDigest != headerProperties["passwordDigest"] {
		return false, NewSecurityError("Password digest doesn't match")
	}

	if headerProperties["Username"] != s.Username {
		return false, NewSecurityError("Username mismatch")
	}

	return true, nil
}
