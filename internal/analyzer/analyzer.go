package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fgravato/lookoutmobile-scanner/internal/device"
)

// RiskLevel represents a device risk level
type RiskLevel string

const (
	RiskHigh   RiskLevel = "High"
	RiskMedium RiskLevel = "Medium"
	RiskLow    RiskLevel = "Low"
)

// SecurityStats represents security statistics for devices
type SecurityStats struct {
	RiskLevel       RiskLevel
	Count           int
	Description     string
	AffectedDevices []string
}

// UpdatePattern represents device update patterns
type UpdatePattern struct {
	UpdateTimespan    int      `json:"update_timespan"` // in months
	OldestPatch       string   `json:"oldest_patch"`
	NewestPatch       string   `json:"newest_patch"`
	UpdateFrequency   float64  `json:"update_frequency"`      // average months between updates
	UpdateGaps        []string `json:"update_gaps,omitempty"` // months with missing updates
	ComplianceMetrics struct {
		CompliantDevices    int     `json:"compliant_devices"`
		NonCompliantDevices int     `json:"non_compliant_devices"`
		ComplianceRate      float64 `json:"compliance_rate"`
		AverageDelay        float64 `json:"average_delay"` // average days to apply updates
	} `json:"compliance_metrics"`
}

// VersionDistribution represents OS version distribution
type VersionDistribution struct {
	Version     string  `json:"version"`
	Count       int     `json:"count"`
	Percentage  float64 `json:"percentage"`
	IsSupported bool    `json:"is_supported"`
}

// Analysis represents the complete device analysis
type Analysis struct {
	SecurityStats struct {
		Android map[RiskLevel]*SecurityStats `json:"android"`
		IOS     map[RiskLevel]*SecurityStats `json:"ios"`
	} `json:"security_stats"`
	UpdatePatterns struct {
		Android *UpdatePattern `json:"android,omitempty"`
		IOS     *UpdatePattern `json:"ios,omitempty"`
	} `json:"update_patterns"`
	VersionDistribution struct {
		Android []VersionDistribution `json:"android"`
		IOS     []VersionDistribution `json:"ios"`
	} `json:"version_distribution"`
	Timestamp time.Time `json:"timestamp"`
}

// Analyzer handles device analysis
type Analyzer struct {
	deviceService device.Service
}

// NewAnalyzer creates a new analyzer
func NewAnalyzer(deviceService device.Service) *Analyzer {
	return &Analyzer{
		deviceService: deviceService,
	}
}

// AnalyzeDevices performs comprehensive device analysis
func (a *Analyzer) AnalyzeDevices(ctx context.Context) (*Analysis, error) {
	devices, err := a.deviceService.ListDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing devices: %w", err)
	}

	analysis := &Analysis{
		SecurityStats: struct {
			Android map[RiskLevel]*SecurityStats `json:"android"`
			IOS     map[RiskLevel]*SecurityStats `json:"ios"`
		}{
			Android: initSecurityStats(),
			IOS:     initSecurityStats(),
		},
		Timestamp: time.Now(),
	}

	androidPatches := make(map[string]int)
	iosVersions := make(map[string]int)

	for _, d := range devices {
		deviceID := fmt.Sprintf("%s (%s)", d.GUID[:8], d.Platform)

		switch d.Platform {
		case "ANDROID":
			if d.Software.SecurityPatchLevel != "" {
				androidPatches[d.Software.SecurityPatchLevel]++
				risk := analyzeAndroidRisk(d.Software.SecurityPatchLevel)
				stats := analysis.SecurityStats.Android[risk]
				stats.Count++
				stats.AffectedDevices = append(stats.AffectedDevices, deviceID)
			}
		case "IOS":
			if d.Software.OSVersion != "" {
				iosVersions[d.Software.OSVersion]++
				risk := analyzeIOSRisk(d.Software.OSVersion)
				stats := analysis.SecurityStats.IOS[risk]
				stats.Count++
				stats.AffectedDevices = append(stats.AffectedDevices, deviceID)
			}
		}
	}

	// Analyze update patterns
	if len(androidPatches) > 0 {
		analysis.UpdatePatterns.Android = analyzeAndroidUpdatePatterns(androidPatches)
	}
	if len(iosVersions) > 0 {
		analysis.UpdatePatterns.IOS = analyzeIOSUpdatePatterns(iosVersions)
	}

	// Analyze version distribution
	analysis.VersionDistribution.Android = analyzeAndroidVersionDistribution(androidPatches)
	analysis.VersionDistribution.IOS = analyzeIOSVersionDistribution(iosVersions)

	return analysis, nil
}

func initSecurityStats() map[RiskLevel]*SecurityStats {
	return map[RiskLevel]*SecurityStats{
		RiskHigh: {
			RiskLevel:   RiskHigh,
			Description: "High risk devices requiring immediate attention",
		},
		RiskMedium: {
			RiskLevel:   RiskMedium,
			Description: "Medium risk devices requiring monitoring",
		},
		RiskLow: {
			RiskLevel:   RiskLow,
			Description: "Low risk devices meeting security requirements",
		},
	}
}

func analyzeAndroidRisk(patchLevel string) RiskLevel {
	patchDate, err := time.Parse("2006-01-02", patchLevel)
	if err != nil {
		return RiskHigh
	}

	monthsOld := int(time.Since(patchDate).Hours() / 24 / 30)

	switch {
	case monthsOld >= 12:
		return RiskHigh
	case monthsOld >= 6:
		return RiskMedium
	default:
		return RiskLow
	}
}

func analyzeIOSRisk(version string) RiskLevel {
	if version == "" {
		return RiskHigh
	}

	majorVersion := strings.Split(version, ".")[0]
	versionNum, err := strconv.Atoi(majorVersion)
	if err != nil {
		return RiskHigh
	}

	switch {
	case versionNum <= 15:
		return RiskHigh
	case versionNum <= 17:
		return RiskMedium
	default:
		return RiskLow
	}
}

func analyzeAndroidUpdatePatterns(patches map[string]int) *UpdatePattern {
	if len(patches) == 0 {
		return nil
	}

	var dates []time.Time
	for patch := range patches {
		if date, err := time.Parse("2006-01-02", patch); err == nil {
			dates = append(dates, date)
		}
	}

	if len(dates) == 0 {
		return nil
	}

	sort.Slice(dates, func(i, j int) bool {
		return dates[i].Before(dates[j])
	})

	oldestPatch := dates[0]
	newestPatch := dates[len(dates)-1]
	timespan := int(newestPatch.Sub(oldestPatch).Hours() / 24 / 30)

	pattern := &UpdatePattern{
		UpdateTimespan: timespan,
		OldestPatch:    oldestPatch.Format("2006-01-02"),
		NewestPatch:    newestPatch.Format("2006-01-02"),
	}

	// Calculate update frequency
	if len(dates) > 1 {
		pattern.UpdateFrequency = float64(timespan) / float64(len(dates)-1)
	}

	// Identify update gaps
	current := oldestPatch
	for current.Before(newestPatch) {
		monthKey := current.Format("2006-01")
		found := false
		for _, date := range dates {
			if date.Format("2006-01") == monthKey {
				found = true
				break
			}
		}
		if !found {
			pattern.UpdateGaps = append(pattern.UpdateGaps, monthKey)
		}
		current = current.AddDate(0, 1, 0)
	}

	return pattern
}

func analyzeIOSUpdatePatterns(versions map[string]int) *UpdatePattern {
	if len(versions) == 0 {
		return nil
	}

	var majorVersions []int
	for version := range versions {
		if major := strings.Split(version, ".")[0]; major != "" {
			if num, err := strconv.Atoi(major); err == nil {
				majorVersions = append(majorVersions, num)
			}
		}
	}

	if len(majorVersions) == 0 {
		return nil
	}

	sort.Ints(majorVersions)
	pattern := &UpdatePattern{
		UpdateTimespan: (majorVersions[len(majorVersions)-1] - majorVersions[0]) * 12, // approximate months
		OldestPatch:    fmt.Sprintf("iOS %d", majorVersions[0]),
		NewestPatch:    fmt.Sprintf("iOS %d", majorVersions[len(majorVersions)-1]),
	}

	if len(majorVersions) > 1 {
		pattern.UpdateFrequency = float64(pattern.UpdateTimespan) / float64(len(majorVersions)-1)
	}

	return pattern
}

func analyzeAndroidVersionDistribution(patches map[string]int) []VersionDistribution {
	var distribution []VersionDistribution
	total := 0
	for _, count := range patches {
		total += count
	}

	for version, count := range patches {
		date, err := time.Parse("2006-01-02", version)
		isSupported := err == nil && time.Since(date) < 180*24*time.Hour

		distribution = append(distribution, VersionDistribution{
			Version:     version,
			Count:       count,
			Percentage:  float64(count) / float64(total) * 100,
			IsSupported: isSupported,
		})
	}

	sort.Slice(distribution, func(i, j int) bool {
		return distribution[i].Version > distribution[j].Version
	})

	return distribution
}

func analyzeIOSVersionDistribution(versions map[string]int) []VersionDistribution {
	var distribution []VersionDistribution
	total := 0
	for _, count := range versions {
		total += count
	}

	for version, count := range versions {
		majorVersion := strings.Split(version, ".")[0]
		versionNum, _ := strconv.Atoi(majorVersion)
		isSupported := versionNum >= 15

		distribution = append(distribution, VersionDistribution{
			Version:     version,
			Count:       count,
			Percentage:  float64(count) / float64(total) * 100,
			IsSupported: isSupported,
		})
	}

	sort.Slice(distribution, func(i, j int) bool {
		vi := strings.Split(distribution[i].Version, ".")
		vj := strings.Split(distribution[j].Version, ".")
		if vi[0] != vj[0] {
			return vi[0] > vj[0]
		}
		return distribution[i].Version > distribution[j].Version
	})

	return distribution
}
