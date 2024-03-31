package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// WrapMasterKey
// layout: iv (12 bytes == gcm.NonceSize) + encryptedMasterKey
func WrapMasterKey(masterKey, rootKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(rootKey)
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

	encryptedMasterKey := gcm.Seal(nil, iv, masterKey, nil) // no AAD here

	wrappedMasterKey := append(iv, encryptedMasterKey...)

	return wrappedMasterKey, nil
}

// UnwrapMasterKey
// layout: iv (12 bytes == gcm.NonceSize) + encryptedMasterKey
func UnwrapMasterKey(wrappedMasterKey, rootKey []byte) ([]byte, error) {
	if len(wrappedMasterKey) < 12 {
		return nil, fmt.Errorf("wrappedMasterKey is too short")
	}

	iv := wrappedMasterKey[:12]
	encryptedMasterKey := wrappedMasterKey[12:]

	block, err := aes.NewCipher(rootKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	masterKey, err := gcm.Open(nil, iv, encryptedMasterKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master key: %v", err)
	}

	return masterKey, nil
}

func GenerateNewMasterKey() ([]byte, error) {
	return generateRandomBytes(32)
}
