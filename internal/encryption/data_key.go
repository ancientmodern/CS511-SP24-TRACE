package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// WrapDataKey
// layout: mki (8 bytes) + iv (12 bytes == gcm.NonceSize) + encryptedKey
func WrapDataKey(dataKey, masterKey []byte, mki string) ([]byte, error) {
	if len(mki) != 8 {
		return nil, fmt.Errorf("master key identifier must be 8 bytes long")
	}

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

	wrappedDataKey := append([]byte(mki), iv...)
	wrappedDataKey = append(wrappedDataKey, encryptedDataKey...)

	return wrappedDataKey, nil
}

// UnwrapDataKey
// layout: mki (8 bytes) + iv (12 bytes == gcm.NonceSize) + encryptedKey
func UnwrapDataKey(wrappedKey, masterKey []byte) ([]byte, error) {
	if len(wrappedKey) < 20 {
		return nil, fmt.Errorf("wrappedKey is too short")
	}

	mki := wrappedKey[:8]
	iv := wrappedKey[8:20]
	encryptedKey := wrappedKey[20:]

	// 假设GetEncryptedMasterKey根据MKI返回加密的masterKey
	encryptedMasterKey, err := GetEncryptedMasterKey(string(mki))
	if err != nil {
		return nil, err
	}

	// 假设DecryptMasterKey使用rootKey解密encryptedMasterKey
	masterKey, err := DecryptMasterKey(encryptedMasterKey, rootKey)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 使用IV和masterKey解密encryptedKey
	dataKey, err := gcm.Open(nil, iv, encryptedKey, nil) // 依旧不使用AAD
	if err != nil {
		return nil, err
	}

	return dataKey, nil
}
