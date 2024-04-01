package handler

import (
	"fmt"
	"github.com/ancientmodern/keystore/internal/auth"
	"github.com/ancientmodern/keystore/internal/db"
	"github.com/ancientmodern/keystore/internal/enc"
	"github.com/ancientmodern/keystore/internal/kms"
	"github.com/ancientmodern/keystore/internal/model"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
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

	log.Info().Interface("request", req).Msg("WrapKey handler starts")

	// 0. Decode the provided data key using base64
	dataKeyBytes, err := enc.DecodeBase64(req.PlainKey)
	if err != nil {
		log.Error().Err(err).Msg("provided data key cannot be decoded using base64")
		return c.JSON(http.StatusOK, model.WrapKeyResponse{
			Code:  -1,
			Error: "provided data key cannot be decoded using base64",
		})
	}

	// 1. Authentication
	if !auth.Authentication(req.Token) {
		log.Error().Msg("Authentication failed")
		return c.JSON(http.StatusOK, model.WrapKeyResponse{
			Code:  -1,
			Error: "cannot authenticate the token",
		})
	}

	// 2. Authorization
	if !auth.Authorization(req.Token, req.Table, req.Column) {
		log.Error().Msg("Authorization failed")
		return c.JSON(http.StatusOK, model.WrapKeyResponse{
			Code:  -1,
			Error: fmt.Sprintf("do not have permission to access column %s in table %s", req.Column, req.Table),
		})
	}

	// 3. Get root key from KMS
	rootKeyBytes, err := kms.GetRootKey()
	if err != nil {
		log.Error().Err(err).Msg("GetRootKey failed")
		return c.String(http.StatusInternalServerError, "internal kms error")
	}

	// 4. Check whether the table <-> master key mapping has been registered
	mki, err := h.db.GetMkiFromTableName(req.Table)
	if err != nil {
		log.Error().Err(err).Msg("GetMkiFromTableName failed")
		return c.String(http.StatusInternalServerError, "internal database error")
	}

	var masterKeyBytes []byte
	if mki == "" {
		// 5.1. No existing mapping, generate a new master key
		masterKeyBytes, err = enc.GenerateNewMasterKey()
		if err != nil {
			log.Error().Err(err).Msg("GenerateNewMasterKey failed")
			return c.String(http.StatusInternalServerError, "internal encryption error")
		}

		// 5.2. Wrap new master key with the root key
		wrappedMasterKeyBytes, err := enc.WrapMasterKey(masterKeyBytes, rootKeyBytes)
		if err != nil {
			log.Error().Err(err).Msg("WrapMasterKey failed")
			return c.String(http.StatusInternalServerError, "internal encryption error")
		}

		// 5.3. Update the DB
		if err = h.db.AddMasterKeyAndTableMappingTx(enc.EncodeBase64(wrappedMasterKeyBytes), req.Table); err != nil {
			log.Error().Err(err).Msg("AddMasterKeyAndTableMappingTx failed")
			return c.String(http.StatusInternalServerError, "internal database error")
		}
	} else {
		// 6.1. Get wrapped master key from DB
		wrappedMasterKey, err := h.db.GetWrappedMasterKeyFromMki(mki)
		if err != nil {
			log.Error().Err(err).Msg("GetWrappedMasterKeyFromMki failed")
			return c.String(http.StatusInternalServerError, "internal database error")
		}

		// 6.2. Unwrap master key using the root key
		wrappedMasterKeyBytes, err := enc.DecodeBase64(wrappedMasterKey)
		if err != nil {
			log.Error().Err(err).Msg("retrieved wrappedMasterKey cannot be decoded using base64")
			return c.String(http.StatusOK, "internal encoding/decoding error")
		}

		masterKeyBytes, err = enc.UnwrapMasterKey(wrappedMasterKeyBytes, rootKeyBytes)
		if err != nil {
			log.Error().Err(err).Msg("UnwrapMasterKey failed")
			return c.String(http.StatusInternalServerError, "internal encryption/decryption error")
		}
	}

	// 7. Wrap data key using the master key
	wrappedDataKey, err := enc.WrapDataKey(dataKeyBytes, masterKeyBytes)
	if err != nil {
		log.Error().Err(err).Msg("WrapDataKey failed")
		return c.String(http.StatusInternalServerError, "internal encryption error")
	}

	// 8. Return wrapped data key to user
	resp := &model.WrapKeyResponse{
		Code:       0,
		WrappedKey: enc.EncodeBase64(wrappedDataKey),
	}
	log.Info().Interface("response", resp).Msg("WrapKey handler ends successfully")
	return c.JSON(http.StatusOK, resp)
}

func (h *Handler) UnwrapKey(c echo.Context) error {
	req := new(model.UnwrapKeyRequest)
	if err := c.Bind(req); err != nil {
		return c.String(http.StatusBadRequest, "bad request")
	}

	log.Info().Interface("request", req).Msg("UnwrapKey handler starts")

	// 0. Decode the provided data key using base64
	wrappedDataKeyBytes, err := enc.DecodeBase64(req.WrappedKey)
	if err != nil {
		log.Error().Err(err).Msg("provided wrapped data key cannot be decoded using base64")
		return c.JSON(http.StatusOK, model.UnwrapKeyResponse{
			Code:  -1,
			Error: "provided wrapped data key cannot be decoded using base64",
		})
	}

	// 1. Authentication
	if !auth.Authentication(req.Token) {
		log.Error().Msg("Authentication failed")
		return c.JSON(http.StatusOK, model.UnwrapKeyResponse{
			Code:  -1,
			Error: "cannot authenticate the token",
		})
	}

	// 2. Authorization
	if !auth.Authorization(req.Token, req.Table, req.Column) {
		log.Error().Msg("Authorization failed")
		return c.JSON(http.StatusOK, model.UnwrapKeyResponse{
			Code:  -1,
			Error: fmt.Sprintf("do not have permission to access column %s in table %s", req.Column, req.Table),
		})
	}

	// 3. Verify the table <-> master key mapping has been registered
	mki, err := h.db.GetMkiFromTableName(req.Table)
	if err != nil {
		log.Error().Err(err).Msg("GetMkiFromTableName failed")
		return c.String(http.StatusInternalServerError, "internal database error")
	}
	if mki == "" {
		log.Error().Msgf("table %s has not been registered yet", req.Table)
		return c.JSON(http.StatusOK, model.UnwrapKeyResponse{
			Code:  -1,
			Error: fmt.Sprintf("table %s has not been registered yet", req.Table),
		})
	}

	// 4. Get wrapped master key from DB
	wrappedMasterKey, err := h.db.GetWrappedMasterKeyFromMki(mki)
	if err != nil {
		log.Error().Err(err).Msg("GetWrappedMasterKeyFromMki failed")
		return c.String(http.StatusInternalServerError, "internal database error")
	}

	// 5. Get root key from KMS
	rootKeyBytes, err := kms.GetRootKey()
	if err != nil {
		log.Error().Err(err).Msg("GetRootKey failed")
		return c.String(http.StatusInternalServerError, "internal kms error")
	}

	// 6. Unwrap master key using the root key
	wrappedMasterKeyBytes, err := enc.DecodeBase64(wrappedMasterKey)
	if err != nil {
		log.Error().Err(err).Msg("retrieved wrappedMasterKey cannot be decoded using base64")
		return c.String(http.StatusOK, "internal encoding/decoding error")
	}

	masterKeyBytes, err := enc.UnwrapMasterKey(wrappedMasterKeyBytes, rootKeyBytes)
	if err != nil {
		log.Error().Err(err).Msg("UnwrapMasterKey failed")
		return c.String(http.StatusInternalServerError, "internal encryption/decryption error")
	}

	// 7. Unwrap data key using the master key
	dataKeyBytes, err := enc.UnwrapDataKey(wrappedDataKeyBytes, masterKeyBytes)
	if err != nil {
		log.Error().Err(err).Msg("UnwrapDataKey failed")
		return c.JSON(http.StatusOK, model.UnwrapKeyResponse{
			Code:  -1,
			Error: "provided data key cannot be unwrapped",
		})
	}

	// 8. Return plain text data key to user
	resp := &model.UnwrapKeyResponse{
		Code:     0,
		PlainKey: enc.EncodeBase64(dataKeyBytes),
	}
	log.Info().Interface("response", resp).Msg("UnwrapKey handler ends successfully")
	return c.JSON(http.StatusOK, resp)
}
