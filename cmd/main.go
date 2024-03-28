package main

import (
	"github.com/ancientmodern/keystore/internal/handler"
	"net/http"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	e.POST("/wrapKey", handler.WrapKey)
	e.POST("/unwrapKey", handler.UnwrapKey)

	e.Logger.Fatal(e.Start(":1323"))
}
