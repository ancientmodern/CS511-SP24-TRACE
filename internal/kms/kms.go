package kms

import "fmt"

func GetRootKey() ([]byte, error) {
	rootKey := []byte("example_sample_root_key_32_bytes")
	if len(rootKey) != 32 {
		return nil, fmt.Errorf("root key size does not equal to 32 bytes")
	}
	return rootKey, nil
}
