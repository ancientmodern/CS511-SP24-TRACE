package model

type WrapKeyRequest struct {
	Table    string `json:"table"`
	Column   string `json:"column"`
	Footer   bool   `json:"footer"`
	PlainKey string `json:"plain_key"`
}

type WrapKeyResponse struct {
	Code       int    `json:"code"`
	Error      string `json:"error,omitempty"`
	WrappedKey string `json:"wrapped_key"`
}

type UnwrapKeyRequest struct {
	Table      string `json:"table"`
	Column     string `json:"column"`
	Footer     bool   `json:"footer"`
	WrappedKey string `json:"wrapped_key"`
}

type UnwrapKeyResponse struct {
	Code     int    `json:"code"`
	Error    string `json:"error,omitempty"`
	PlainKey string `json:"plain_key"`
}
