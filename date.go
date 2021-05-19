package wssecurity

import "time"

func (s Security) IsCreatedDateValid(createdDate string) (bool, *SecurityError) {
	t, err := time.Parse(time.RFC3339, createdDate)
	if err != nil {
		return false, &SecurityError{"Invalid created at"}
	}

	now := time.Now()
	if t.After(now) {
		return false, &SecurityError{"Created at is greater"}
	}

	if now.Unix()-t.Unix() > s.Lifetime {
		return false, &SecurityError{"Request expired"}
	}

	return true, nil
}
