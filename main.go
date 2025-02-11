package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/fgravato/lookout-appgo/internal/analyzer"
	"github.com/fgravato/lookout-appgo/internal/api"
	"github.com/fgravato/lookout-appgo/internal/config"
	"github.com/fgravato/lookout-appgo/internal/database"
	"github.com/fgravato/lookout-appgo/internal/device"
)

func main() {
	// Parse command line flags
	localMode := flag.Bool("local", false, "Read from local database instead of API")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down gracefully...")
		cancel()
	}()

	// Initialize database
	db, err := database.NewStore(database.Config{
		Path: cfg.Database.Path,
	})
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}
	defer db.Close()

	// Initialize repository and service layers
	deviceRepo := device.NewRepository(db)
	deviceService := device.NewService(deviceRepo)

	// Initialize analyzer
	deviceAnalyzer := analyzer.NewAnalyzer(deviceService)

	if *localMode {
		// Read and analyze local data
		analysis, err := deviceAnalyzer.AnalyzeDevices(ctx)
		if err != nil {
			log.Fatalf("Error analyzing devices: %v", err)
		}

		// Pretty print analysis results
		printAnalysis(analysis)
	} else {
		// Initialize API client
		apiClient := api.NewClient(cfg.API)

		// Process devices from API
		if err := processDevices(ctx, apiClient, deviceService, deviceAnalyzer, cfg); err != nil {
			log.Fatalf("Error processing devices: %v", err)
		}
	}
}

func processDevices(ctx context.Context, apiClient *api.Client, deviceService device.Service, deviceAnalyzer *analyzer.Analyzer, cfg *config.Config) error {
	// Get initial device count
	initialResp, err := apiClient.GetDevices(ctx, "", 1)
	if err != nil {
		return fmt.Errorf("getting total device count: %w", err)
	}
	totalDevices := initialResp.Count
	fmt.Printf("Found %d total devices\n\n", totalDevices)

	var lastOID string
	processedCount := 0
	running := true

	for running {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			devicesResp, err := apiClient.GetDevices(ctx, lastOID, cfg.App.BatchSize)
			if err != nil {
				return fmt.Errorf("getting devices: %w", err)
			}

			// Check if we should stop processing
			if len(devicesResp.Devices) == 0 || processedCount >= totalDevices {
				running = false
				break
			}

			// Process devices in parallel using worker pool
			errChan := make(chan error, len(devicesResp.Devices))
			semaphore := make(chan struct{}, cfg.App.WorkerCount)

			for _, apiDevice := range devicesResp.Devices {
				semaphore <- struct{}{} // Acquire semaphore
				go func(d api.Device) {
					defer func() { <-semaphore }() // Release semaphore

					// Convert API device to domain device
					dev := &device.Device{
						GUID:             d.GUID,
						OID:              d.OID,
						ParentDeviceGUID: d.ParentDeviceGUID,
						ActivationStatus: d.ActivationStatus,
						Platform:         d.Platform,
						Software: device.Software{
							SecurityPatchLevel: d.Software.SecurityPatchLevel,
							OSVersion:          d.Software.OSVersion,
						},
					}

					// Create or update device
					if err := deviceService.CreateDevice(ctx, dev); err != nil {
						errChan <- fmt.Errorf("processing device %s: %w", d.GUID, err)
						return
					}

					errChan <- nil
				}(apiDevice)
			}

			// Wait for all workers to complete and check for errors
			for i := 0; i < len(devicesResp.Devices); i++ {
				if err := <-errChan; err != nil {
					return err
				}
			}

			processedCount += len(devicesResp.Devices)
			progress := float64(processedCount) / float64(totalDevices) * 100
			fmt.Printf("\rProgress: %.1f%% (%d/%d devices processed)", progress, processedCount, totalDevices)

			lastOID = devicesResp.Devices[len(devicesResp.Devices)-1].OID
		}
	}

	fmt.Printf("\nCompleted processing %d/%d devices (100%%)\n\n", processedCount, totalDevices)

	// Get and display analysis after processing
	analysis, err := deviceAnalyzer.AnalyzeDevices(ctx)
	if err != nil {
		return fmt.Errorf("analyzing devices: %w", err)
	}

	// Print analysis results
	printBasicStats(analysis)
	return nil
}

func printBasicStats(analysis *analyzer.Analysis) {
	fmt.Printf("\nDevice Statistics:\n")
	androidStats := analysis.SecurityStats.Android
	iosStats := analysis.SecurityStats.IOS

	fmt.Printf("\nAndroid Security Risks:\n")
	printRiskStats(androidStats)

	fmt.Printf("\niOS Security Risks:\n")
	printRiskStats(iosStats)

	if analysis.UpdatePatterns.Android != nil {
		fmt.Printf("\nAndroid Update Patterns:\n")
		fmt.Printf("- Update Timespan: %d months\n", analysis.UpdatePatterns.Android.UpdateTimespan)
		fmt.Printf("- Average Update Frequency: %.1f months\n", analysis.UpdatePatterns.Android.UpdateFrequency)
	}

	if analysis.UpdatePatterns.IOS != nil {
		fmt.Printf("\niOS Update Patterns:\n")
		fmt.Printf("- Update Timespan: %d months\n", analysis.UpdatePatterns.IOS.UpdateTimespan)
		fmt.Printf("- Average Update Frequency: %.1f months\n", analysis.UpdatePatterns.IOS.UpdateFrequency)
	}
}

func printAnalysis(analysis *analyzer.Analysis) {
	data, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		log.Printf("Error formatting analysis: %v", err)
		return
	}
	fmt.Println(string(data))
}

func printRiskStats(stats map[analyzer.RiskLevel]*analyzer.SecurityStats) {
	for _, risk := range []analyzer.RiskLevel{analyzer.RiskHigh, analyzer.RiskMedium, analyzer.RiskLow} {
		if stat := stats[risk]; stat.Count > 0 {
			fmt.Printf("- %s Risk: %d device(s)\n", risk, stat.Count)
			fmt.Printf("  Description: %s\n", stat.Description)
			if len(stat.AffectedDevices) > 0 {
				fmt.Printf("  Affected Devices: %v\n", stat.AffectedDevices)
			}
		}
	}
}
