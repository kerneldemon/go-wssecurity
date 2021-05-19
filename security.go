package wssecurity

type Security struct {
	Username string
	Secret   string
	Lifetime int64
}

func (s Security) IsAuthSuccessful(decodedHeader string) (bool, *SecurityError) {
	headerProperties := ExtractHeaderProperties(decodedHeader)
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
		return false, &SecurityError{"Password digest doesn't match"}
	}

	if headerProperties["Username"] != s.Username {
		return false, &SecurityError{"Username mismatch"}
	}

	return true, nil
}
