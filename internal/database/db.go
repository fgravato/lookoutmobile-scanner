package database

import (
	"context"
	"fmt"
	"sync"

	"github.com/tidwall/buntdb"
)

// DB represents the database interface
type DB interface {
	View(fn func(tx *buntdb.Tx) error) error
	Update(fn func(tx *buntdb.Tx) error) error
	Close() error
}

// Config holds database configuration
type Config struct {
	Path string
	// Add more configuration options as needed
}

// Store implements the DB interface
type Store struct {
	db   *buntdb.DB
	mu   sync.RWMutex
	path string
}

// NewStore creates a new database connection
func NewStore(cfg Config) (*Store, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("database path is required")
	}

	db, err := buntdb.Open(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Configure the database
	err = db.Update(func(tx *buntdb.Tx) error {
		// Create indexes if needed
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("configuring database: %w", err)
	}

	return &Store{
		db:   db,
		path: cfg.Path,
	}, nil
}

// View executes a read-only transaction
func (s *Store) View(fn func(tx *buntdb.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db.View(fn)
}

// Update executes a read-write transaction
func (s *Store) Update(fn func(tx *buntdb.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Update(fn)
}

// Close closes the database connection
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// WithTransaction executes a function within a transaction
func WithTransaction(ctx context.Context, db DB, fn func(tx *buntdb.Tx) error) error {
	var err error
	done := make(chan struct{})

	go func() {
		err = db.Update(fn)
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return err
	}
}
