package handler

import (
	"fmt"
	"github.com/ancientmodern/keystore/internal/auth"
	"github.com/ancientmodern/keystore/internal/db"
	"github.com/ancientmodern/keystore/internal/encryption"
	"github.com/ancientmodern/keystore/internal/kms"
	"github.com/ancientmodern/keystore/internal/model"
	"github.com/labstack/echo/v4"
	"net/http"
)

type Handler struct {
	db db.Database
}

func NewHandler(database db.Database) *Handler {
	return &Handler{db: database}
}

func (h *Handler) WrapKey(c echo.Context) error {
	req := new(model.WrapKeyRequest)
	if err := c.Bind(req); err != nil {
		return c.String(http.StatusBadRequest, "bad request")
	}

	// 1. Authentication
	if !auth.Authentication(req.Token) {
		return c.JSON(http.StatusOK, model.WrapKeyResponse{
			Code:  -1,
			Error: "cannot authenticate the token",
		})
	}

	// 2. Authorization
	if !auth.Authorization(req.Token, req.Table, req.Column) {
		return c.JSON(http.StatusOK, model.WrapKeyResponse{
			Code:  -1,
			Error: fmt.Sprintf("do not have permission to access column %s in table %s", req.Column, req.Table),
		})
	}

	// 3. Check whether the table <-> master key mapping has been registered
	mki, err := h.db.GetMkiFromTableName(req.Table)
	if err != nil {
		return c.String(http.StatusInternalServerError, "internal database error")
	}

	// 4. TODO
	if mki == "" {

	} else {

	}

	resp := &model.WrapKeyResponse{
		Code:       0,
		WrappedKey: "sample_wrapped_key",
	}
	return c.JSON(http.StatusOK, resp)
}

func (h *Handler) UnwrapKey(c echo.Context) error {
	req := new(model.UnwrapKeyRequest)
	if err := c.Bind(req); err != nil {
		return c.String(http.StatusBadRequest, "bad request")
	}

	// 1. Authentication
	if !auth.Authentication(req.Token) {
		return c.JSON(http.StatusOK, model.WrapKeyResponse{
			Code:  -1,
			Error: "cannot authenticate the token",
		})
	}

	// 2. Authorization
	if !auth.Authorization(req.Token, req.Table, req.Column) {
		return c.JSON(http.StatusOK, model.WrapKeyResponse{
			Code:  -1,
			Error: fmt.Sprintf("do not have permission to access column %s in table %s", req.Column, req.Table),
		})
	}

	// 3. Verify the table <-> master key mapping has been registered
	mki, err := h.db.GetMkiFromTableName(req.Table)
	if err != nil {
		return c.String(http.StatusInternalServerError, "internal database error")
	}
	if mki == "" {
		return c.JSON(http.StatusOK, model.WrapKeyResponse{
			Code:  -1,
			Error: fmt.Sprintf("table %s has not been registered yet", req.Table),
		})
	}

	// 4. Get wrapped master key from the database
	wrappedMasterKey, err := h.db.GetWrappedMasterKeyFromMki(mki)
	if err != nil {
		return c.String(http.StatusInternalServerError, "internal database error")
	}

	// 5. Get root key from KMS
	rootKey, err := kms.GetRootKey()
	if err != nil {
		return c.String(http.StatusInternalServerError, "internal kms error")
	}

	// 6. Unwrap master key using the root key
	masterKey, err := encryption.UnwrapMasterKey([]byte(wrappedMasterKey), []byte(rootKey))
	if err != nil {
		return c.String(http.StatusInternalServerError, "internal encryption/decryption error")
	}

	// 7. Unwrap data key using the master key
	dataKey, err := encryption.UnwrapDataKey([]byte(req.WrappedKey), masterKey)
	if err != nil {
		return c.String(http.StatusInternalServerError, "internal encryption/decryption error")
	}

	// 8. Return plain text data key to user
	resp := &model.UnwrapKeyResponse{
		Code:     0,
		PlainKey: string(dataKey),
	}
	return c.JSON(http.StatusOK, resp)
}
