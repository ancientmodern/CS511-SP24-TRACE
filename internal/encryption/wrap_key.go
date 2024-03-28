package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

func WrapKey(masterKey, dataKey []byte, mki string) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	iv, err := generateRandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	encryptedKey := gcm.Seal(nil, iv, dataKey, nil)

	// Convert the length of the original dataKey into a byte slice
	keyLengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(keyLengthBytes, uint32(len(dataKey)))

	// Prepend IV and MKI, and append the original key length to the encrypted key
	mkiBytes := []byte(mki) // Ensure this is of fixed length or has a delimiter
	wrappedKey := append(iv, encryptedKey...)
	wrappedKey = append(wrappedKey, keyLengthBytes...)
	wrappedKey = append(wrappedKey, mkiBytes...)

	return wrappedKey, nil
}
