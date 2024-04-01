package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// WrapDataKey
// layout: iv (12 bytes == gcm.NonceSize) + encryptedDataKey
func WrapDataKey(dataKey, masterKey []byte) ([]byte, error) {
	//if len(mki) != 8 {
	//	return nil, fmt.Errorf("master key identifier must be 8 bytes long")
	//}

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

	encryptedDataKey := gcm.Seal(nil, iv, dataKey, nil) // no AAD here

	wrappedDataKey := append(iv, encryptedDataKey...)

	return wrappedDataKey, nil
}

// UnwrapDataKey
// layout: iv (12 bytes == gcm.NonceSize) + encryptedDataKey
func UnwrapDataKey(wrappedKey, masterKey []byte) ([]byte, error) {
	if len(wrappedKey) < 20 {
		return nil, fmt.Errorf("wrappedKey is too short")
	}

	iv := wrappedKey[:12]
	encryptedDataKey := wrappedKey[12:]

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	dataKey, err := gcm.Open(nil, iv, encryptedDataKey, nil)
	if err != nil {
		return nil, err
	}

	return dataKey, nil
}
