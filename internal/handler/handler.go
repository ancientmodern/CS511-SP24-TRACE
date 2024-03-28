package handler

import (
	"github.com/ancientmodern/keystore/internal/model"
	"github.com/labstack/echo/v4"
	"net/http"
)

func WrapKey(c echo.Context) error {
	req := new(model.WrapKeyRequest)
	if err := c.Bind(req); err != nil {
		return c.String(http.StatusBadRequest, "bad request")
	}

	// TODO

	resp := &model.WrapKeyResponse{
		Code:       0,
		WrappedKey: "sample_wrapped_key",
	}
	return c.JSON(http.StatusOK, resp)
}

func UnwrapKey(c echo.Context) error {
	req := new(model.UnwrapKeyRequest)
	if err := c.Bind(req); err != nil {
		return c.String(http.StatusBadRequest, "bad request")
	}

	// TODO

	resp := &model.UnwrapKeyResponse{
		Code:     0,
		PlainKey: "sample_plain_key",
	}
	return c.JSON(http.StatusOK, resp)
}
