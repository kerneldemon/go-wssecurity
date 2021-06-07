package wssecurity

import "testing"

func TestHeader_GenerateAuthHeader(t *testing.T) {
	s := Security{
		Username: "test-user",
		Secret:   "test-password",
		Lifetime: 60,
	}

	header, generateError := s.GenerateAuthHeader()
	successful, authError := s.IsAuthSuccessful(header)

	if !successful {
		t.Errorf("Failed to validate generated header: %v,%v", generateError, authError)
	}
}
