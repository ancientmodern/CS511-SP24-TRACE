package db

import (
	"fmt"
	"strings"
)

type Database interface {
	Ping() error
	Close() error
	GetWrappedMasterKeyFromMki(mki string) (string, error)
	GetMkiFromTableName(tableName string) (string, error)
	AddMasterKeyAndTableMapping(wrappedMasterKey, tableName string) error
	//AddMasterKey(mki, wrappedMasterKey string) error
	//AddTableMapping(tableName, mki string) error
}

func NewDatabase(url string) (Database, error) {
	var db Database
	var err error
	if strings.HasPrefix(url, "postgres://") {
		db, err = NewPostgresDB(url)
	} else if strings.HasPrefix(url, "mysql://") {
		// db, err = NewMySQLDB(url)
	} else if strings.HasPrefix(url, "sqlite://") {
		// db, err = NewSQLiteDB(url)
	} else {
		err = fmt.Errorf("unsupported database type")
	}
	if err != nil {
		return nil, err
	}
	return db, nil
}
