package main

import (
	"github.com/ancientmodern/keystore/internal/db"
	"github.com/ancientmodern/keystore/internal/handler"
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
)

func main() {
	dbURL := "postgres://keystore:123456@localhost:5432/keystore"
	database, err := db.NewDatabase(dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer database.Close()

	h := handler.NewHandler(database)

	e := echo.New()

	// hello world
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	// real key management APIs
	e.POST("/wrapKey", h.WrapKey)
	e.POST("/unwrapKey", h.UnwrapKey)

	e.Logger.Fatal(e.Start(":1323"))
}
