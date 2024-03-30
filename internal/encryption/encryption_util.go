package encryption

import (
	"crypto/rand"
	"io"
)

// reserved: encryption algorithm id
const (
	AES_GCM_V1     byte = 0x10
	AES_GCM_CTR_V1 byte = 0x11
)

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
