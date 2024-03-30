package db

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresDB struct {
	pool *pgxpool.Pool
}

func NewPostgresDB(url string) (*PostgresDB, error) {
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		return nil, err
	}
	return &PostgresDB{pool: pool}, nil
}

func (db *PostgresDB) Ping() error {
	return db.pool.Ping(context.Background())
}

func (db *PostgresDB) Close() error {
	db.pool.Close()
	return nil
}

func (db *PostgresDB) GetWrappedMasterKeyFromMki(mki string) (string, error) {
	var wrappedMasterKey string
	err := db.pool.QueryRow(context.Background(),
		"SELECT wrapped_key FROM master_keys WHERE id = $1", mki).Scan(&wrappedMasterKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return wrappedMasterKey, nil
}

func (db *PostgresDB) GetMkiFromTableName(tableName string) (string, error) {
	var mki string
	err := db.pool.QueryRow(context.Background(),
		"SELECT mki FROM master_key_table_mapping WHERE table_name = $1", tableName).Scan(&mki)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return mki, nil
}

func (db *PostgresDB) AddMasterKeyAndTableMapping(wrappedMasterKey, tableName string) error {
	tx, err := db.pool.Begin(context.Background())
	if err != nil {
		return err
	}
	// Rollback is safe to call even if the tx is already closed, so if
	// the tx commits successfully, this is a no-op
	defer tx.Rollback(context.Background())

	var mki string
	err = tx.QueryRow(context.Background(),
		"INSERT INTO master_keys (wrapped_key) VALUES ($1) RETURNING id", wrappedMasterKey).Scan(&mki)
	if err != nil {
		return err
	}

	_, err = tx.Exec(context.Background(),
		"INSERT INTO master_key_table_mapping (table_name, mki) VALUES ($1, $2)", tableName, mki)
	if err != nil {
		return err
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return err
	}

	return nil
}

func (db *PostgresDB) AddMasterKey(mki, wrappedMasterKey string) error {
	_, err := db.pool.Exec(context.Background(),
		"INSERT INTO master_keys (id, wrapped_key) VALUES ($1, $2)", mki, wrappedMasterKey)
	return err
}

func (db *PostgresDB) AddTableMapping(tableName, mki string) error {
	_, err := db.pool.Exec(context.Background(),
		"INSERT INTO master_key_table_mapping (table_name, mki) VALUES ($1, $2)", tableName, mki)
	return err
}
