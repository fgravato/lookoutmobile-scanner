package device

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tidwall/buntdb"
)

// Device represents a device in the system
type Device struct {
	GUID             string    `json:"guid"`
	OID              string    `json:"oid"`
	ParentDeviceGUID string    `json:"parent_device_guid"`
	ActivationStatus string    `json:"activation_status"`
	Platform         string    `json:"platform"`
	Software         Software  `json:"software"`
	ChildCount       int       `json:"child_count"`
	LastUpdated      time.Time `json:"last_updated"`
}

// Software represents device software information
type Software struct {
	SecurityPatchLevel string `json:"security_patch_level"`
	OSVersion          string `json:"os_version"`
}

// Repository defines the interface for device data operations
type Repository interface {
	Save(ctx context.Context, device *Device) error
	Get(ctx context.Context, guid string) (*Device, error)
	List(ctx context.Context) ([]Device, error)
	Update(ctx context.Context, device *Device) error
	Delete(ctx context.Context, guid string) error
	GetByPlatform(ctx context.Context, platform string) ([]Device, error)
	GetActiveDevices(ctx context.Context) ([]Device, error)
}

// Store implements the Repository interface
type Store struct {
	db DB
}

// DB interface defines the required database methods
type DB interface {
	View(fn func(tx *buntdb.Tx) error) error
	Update(fn func(tx *buntdb.Tx) error) error
}

// NewRepository creates a new device repository
func NewRepository(db DB) Repository {
	return &Store{db: db}
}

// Save stores a new device in the database
func (s *Store) Save(ctx context.Context, device *Device) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		device.LastUpdated = time.Now()
		data, err := json.Marshal(device)
		if err != nil {
			return fmt.Errorf("marshaling device: %w", err)
		}

		return s.db.Update(func(tx *buntdb.Tx) error {
			_, _, err := tx.Set(device.GUID, string(data), nil)
			if err != nil {
				return fmt.Errorf("saving device: %w", err)
			}
			return nil
		})
	}
}

// Get retrieves a device by GUID
func (s *Store) Get(ctx context.Context, guid string) (*Device, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		var device Device
		err := s.db.View(func(tx *buntdb.Tx) error {
			val, err := tx.Get(guid)
			if err != nil {
				if err == buntdb.ErrNotFound {
					return fmt.Errorf("device not found: %s", guid)
				}
				return fmt.Errorf("getting device: %w", err)
			}
			return json.Unmarshal([]byte(val), &device)
		})
		if err != nil {
			return nil, err
		}
		return &device, nil
	}
}

// List retrieves all devices
func (s *Store) List(ctx context.Context) ([]Device, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		var devices []Device
		err := s.db.View(func(tx *buntdb.Tx) error {
			return tx.Ascend("", func(key, value string) bool {
				var device Device
				if err := json.Unmarshal([]byte(value), &device); err != nil {
					return false
				}
				devices = append(devices, device)
				return true
			})
		})
		if err != nil {
			return nil, fmt.Errorf("listing devices: %w", err)
		}
		return devices, nil
	}
}

// Update modifies an existing device
func (s *Store) Update(ctx context.Context, device *Device) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		device.LastUpdated = time.Now()
		data, err := json.Marshal(device)
		if err != nil {
			return fmt.Errorf("marshaling device: %w", err)
		}

		return s.db.Update(func(tx *buntdb.Tx) error {
			_, err := tx.Get(device.GUID)
			if err != nil {
				if err == buntdb.ErrNotFound {
					return fmt.Errorf("device not found: %s", device.GUID)
				}
				return fmt.Errorf("checking device existence: %w", err)
			}

			_, _, err = tx.Set(device.GUID, string(data), nil)
			if err != nil {
				return fmt.Errorf("updating device: %w", err)
			}
			return nil
		})
	}
}

// Delete removes a device
func (s *Store) Delete(ctx context.Context, guid string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return s.db.Update(func(tx *buntdb.Tx) error {
			_, err := tx.Delete(guid)
			if err != nil {
				if err == buntdb.ErrNotFound {
					return fmt.Errorf("device not found: %s", guid)
				}
				return fmt.Errorf("deleting device: %w", err)
			}
			return nil
		})
	}
}

// GetByPlatform retrieves devices by platform
func (s *Store) GetByPlatform(ctx context.Context, platform string) ([]Device, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		var devices []Device
		err := s.db.View(func(tx *buntdb.Tx) error {
			return tx.Ascend("", func(key, value string) bool {
				var device Device
				if err := json.Unmarshal([]byte(value), &device); err != nil {
					return false
				}
				if device.Platform == platform {
					devices = append(devices, device)
				}
				return true
			})
		})
		if err != nil {
			return nil, fmt.Errorf("getting devices by platform: %w", err)
		}
		return devices, nil
	}
}

// GetActiveDevices retrieves all active devices
func (s *Store) GetActiveDevices(ctx context.Context) ([]Device, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		var devices []Device
		err := s.db.View(func(tx *buntdb.Tx) error {
			return tx.Ascend("", func(key, value string) bool {
				var device Device
				if err := json.Unmarshal([]byte(value), &device); err != nil {
					return false
				}
				if device.ActivationStatus == "ACTIVATED" {
					devices = append(devices, device)
				}
				return true
			})
		})
		if err != nil {
			return nil, fmt.Errorf("getting active devices: %w", err)
		}
		return devices, nil
	}
}
