package api

import "time"

// TokenResponse represents the OAuth token response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresAt   int64  `json:"expires_at"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// DevicesResponse represents the device list response
type DevicesResponse struct {
	Count   int      `json:"count"`
	Devices []Device `json:"devices"`
}

// Device represents a device in the API response
type Device struct {
	GUID             string   `json:"guid"`
	OID              string   `json:"oid"`
	ParentDeviceGUID string   `json:"parent_device_guid"`
	ActivationStatus string   `json:"activation_status"`
	Platform         string   `json:"platform"`
	Software         Software `json:"software"`
}

// Software represents device software information in the API response
type Software struct {
	SecurityPatchLevel string `json:"security_patch_level"`
	OSVersion          string `json:"os_version"`
}

// VulnerabilitiesResponse represents the vulnerability list response
type VulnerabilitiesResponse struct {
	Count           int             `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability represents a vulnerability in the API response
type Vulnerability struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	PublishedAt time.Time `json:"published_at"`
	CVE         string    `json:"cve"`
	CVSS        float64   `json:"cvss"`
}
