package device

import (
	"context"
	"fmt"
	"time"
)

// Service defines the device business logic interface
type Service interface {
	CreateDevice(ctx context.Context, device *Device) error
	GetDevice(ctx context.Context, guid string) (*Device, error)
	ListDevices(ctx context.Context) ([]Device, error)
	UpdateDevice(ctx context.Context, device *Device) error
	DeleteDevice(ctx context.Context, guid string) error
	GetDevicesByPlatform(ctx context.Context, platform string) ([]Device, error)
	GetActiveDevices(ctx context.Context) ([]Device, error)
	GetDeviceStatistics(ctx context.Context) (*Statistics, error)
}

// Statistics represents device statistics
type Statistics struct {
	TotalDevices      int       `json:"total_devices"`
	ActiveDevices     int       `json:"active_devices"`
	AndroidDevices    int       `json:"android_devices"`
	IOSDevices        int       `json:"ios_devices"`
	ParentDevices     int       `json:"parent_devices"`
	ChildDevices      int       `json:"child_devices"`
	LastUpdated       time.Time `json:"last_updated"`
	VulnerableDevices int       `json:"vulnerable_devices"`
}

// DeviceService implements the Service interface
type DeviceService struct {
	repo Repository
}

// NewService creates a new device service
func NewService(repo Repository) Service {
	return &DeviceService{
		repo: repo,
	}
}

// CreateDevice handles device creation with validation
func (s *DeviceService) CreateDevice(ctx context.Context, device *Device) error {
	if err := validateDevice(device); err != nil {
		return fmt.Errorf("validating device: %w", err)
	}

	// Save device regardless of parent status
	if err := s.repo.Save(ctx, device); err != nil {
		return fmt.Errorf("saving device: %w", err)
	}

	// Try to update parent device if specified, but don't fail if parent doesn't exist
	if device.ParentDeviceGUID != "" {
		if parent, err := s.repo.Get(ctx, device.ParentDeviceGUID); err == nil {
			parent.ChildCount++
			if err := s.repo.Update(ctx, parent); err != nil {
				// Non-critical error, device is saved but parent update failed
				return fmt.Errorf("device saved but failed to update parent count: %w", err)
			}
		}
		// Parent not found is an acceptable state - it might be processed later
	}

	return nil
}

// GetDevice retrieves a device by GUID
func (s *DeviceService) GetDevice(ctx context.Context, guid string) (*Device, error) {
	if guid == "" {
		return nil, fmt.Errorf("device GUID is required")
	}
	return s.repo.Get(ctx, guid)
}

// ListDevices retrieves all devices
func (s *DeviceService) ListDevices(ctx context.Context) ([]Device, error) {
	return s.repo.List(ctx)
}

// UpdateDevice handles device updates with validation
func (s *DeviceService) UpdateDevice(ctx context.Context, device *Device) error {
	if err := validateDevice(device); err != nil {
		return fmt.Errorf("validating device: %w", err)
	}

	// Get existing device
	existing, err := s.repo.Get(ctx, device.GUID)
	if err != nil {
		return fmt.Errorf("getting existing device: %w", err)
	}

	// Update device first
	if err := s.repo.Update(ctx, device); err != nil {
		return fmt.Errorf("updating device: %w", err)
	}

	// Handle parent device relationship changes
	if existing.ParentDeviceGUID != device.ParentDeviceGUID {
		// Try to update old parent's child count
		if existing.ParentDeviceGUID != "" {
			if oldParent, err := s.repo.Get(ctx, existing.ParentDeviceGUID); err == nil {
				oldParent.ChildCount--
				if err := s.repo.Update(ctx, oldParent); err != nil {
					// Non-critical error, device is updated but parent count might be off
					return fmt.Errorf("device updated but failed to update old parent count: %w", err)
				}
			}
		}

		// Try to update new parent's child count
		if device.ParentDeviceGUID != "" {
			if newParent, err := s.repo.Get(ctx, device.ParentDeviceGUID); err == nil {
				newParent.ChildCount++
				if err := s.repo.Update(ctx, newParent); err != nil {
					// Non-critical error, device is updated but parent count might be off
					return fmt.Errorf("device updated but failed to update new parent count: %w", err)
				}
			}
		}
	}

	return nil
}

// DeleteDevice handles device deletion
func (s *DeviceService) DeleteDevice(ctx context.Context, guid string) error {
	if guid == "" {
		return fmt.Errorf("device GUID is required")
	}

	// Get device to check for parent relationship
	device, err := s.repo.Get(ctx, guid)
	if err != nil {
		return fmt.Errorf("getting device: %w", err)
	}

	// Delete device first
	if err := s.repo.Delete(ctx, guid); err != nil {
		return fmt.Errorf("deleting device: %w", err)
	}

	// Try to update parent's child count if parent exists
	if device.ParentDeviceGUID != "" {
		if parent, err := s.repo.Get(ctx, device.ParentDeviceGUID); err == nil {
			parent.ChildCount--
			if err := s.repo.Update(ctx, parent); err != nil {
				// Non-critical error, device is deleted but parent count might be off
				return fmt.Errorf("device deleted but failed to update parent count: %w", err)
			}
		}
		// Parent not found is acceptable - it might have been deleted already
	}

	return nil
}

// GetDevicesByPlatform retrieves devices by platform
func (s *DeviceService) GetDevicesByPlatform(ctx context.Context, platform string) ([]Device, error) {
	if platform == "" {
		return nil, fmt.Errorf("platform is required")
	}
	return s.repo.GetByPlatform(ctx, platform)
}

// GetActiveDevices retrieves all active devices
func (s *DeviceService) GetActiveDevices(ctx context.Context) ([]Device, error) {
	return s.repo.GetActiveDevices(ctx)
}

// GetDeviceStatistics calculates device statistics
func (s *DeviceService) GetDeviceStatistics(ctx context.Context) (*Statistics, error) {
	devices, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing devices: %w", err)
	}

	stats := &Statistics{
		TotalDevices: len(devices),
		LastUpdated:  time.Now(),
	}

	for _, device := range devices {
		if device.ActivationStatus == "ACTIVATED" {
			stats.ActiveDevices++
		}

		switch device.Platform {
		case "ANDROID":
			stats.AndroidDevices++
		case "IOS":
			stats.IOSDevices++
		}

		if device.ParentDeviceGUID == "" {
			stats.ParentDevices++
		} else {
			stats.ChildDevices++
		}

		// Count vulnerable devices based on version
		if isVulnerable(device) {
			stats.VulnerableDevices++
		}
	}

	return stats, nil
}

// validateDevice performs device validation
func validateDevice(device *Device) error {
	if device == nil {
		return fmt.Errorf("device is required")
	}
	if device.GUID == "" {
		return fmt.Errorf("device GUID is required")
	}
	if device.Platform != "ANDROID" && device.Platform != "IOS" {
		return fmt.Errorf("invalid platform: %s", device.Platform)
	}
	validStatuses := map[string]bool{
		"ACTIVATED":   true,
		"DEACTIVATED": true,
		"PENDING":     true,
	}
	if !validStatuses[device.ActivationStatus] {
		return fmt.Errorf("invalid activation status: %s", device.ActivationStatus)
	}
	return nil
}

// isVulnerable determines if a device is vulnerable based on its version
func isVulnerable(device Device) bool {
	if device.Platform == "ANDROID" {
		// Consider Android devices with security patches older than 6 months as vulnerable
		if device.Software.SecurityPatchLevel == "" {
			return true
		}
		patchDate, err := time.Parse("2006-01-02", device.Software.SecurityPatchLevel)
		if err != nil {
			return true
		}
		return time.Since(patchDate) > 180*24*time.Hour
	}

	if device.Platform == "IOS" {
		// Consider iOS devices with versions older than iOS 15 as vulnerable
		if device.Software.OSVersion == "" {
			return true
		}
		version := device.Software.OSVersion
		if len(version) > 2 && version[0:2] < "15" {
			return true
		}
	}

	return false
}
