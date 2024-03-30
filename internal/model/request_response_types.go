package model

type WrapKeyRequest struct {
	Token    string `json:"token"`
	Table    string `json:"table"`
	Column   string `json:"column"`
	PlainKey string `json:"plain_key"`
}

type WrapKeyResponse struct {
	Code       int    `json:"code"`
	Error      string `json:"error,omitempty"`
	WrappedKey string `json:"wrapped_key"`
}

type UnwrapKeyRequest struct {
	Token      string `json:"token"`
	Table      string `json:"table"`
	Column     string `json:"column"`
	WrappedKey string `json:"wrapped_key"`
}

type UnwrapKeyResponse struct {
	Code     int    `json:"code"`
	Error    string `json:"error,omitempty"`
	PlainKey string `json:"plain_key"`
}
