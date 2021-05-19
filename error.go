package wssecurity

type SecurityError struct {
	Message string
}

func (m *SecurityError) Error() string {
	return m.Message
}
