package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/joho/godotenv"
    "github.com/tidwall/buntdb"
)

type Stats struct {
    ActiveDevices     int
    AndroidDevices    int
    IOSDevices        int
    VulnerableDevices int
    mu               sync.Mutex
}

type TokenResponse struct {
    AccessToken string `json:"access_token"`
    TokenType   string `json:"token_type"`
    ExpiresAt   int64  `json:"expires_at"`
    ExpiresIn   int    `json:"expires_in"`
    Scope       string `json:"scope"`
}

type Device struct {
    GUID             string `json:"guid"`
    OID              string `json:"oid"`
    ParentDeviceGUID string `json:"parent_device_guid"`
    ActivationStatus string `json:"activation_status"`
    Platform         string `json:"platform"`
    Software         struct {
        SecurityPatchLevel string `json:"security_patch_level"`
        OSVersion         string `json:"os_version"`
    } `json:"software"`
    ChildCount       int
}

type DevicesResponse struct {
    Count   int      `json:"count"`
    Devices []Device `json:"devices"`
}

type Vulnerability struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    Severity    string `json:"severity"`
}

type VulnerabilitiesResponse struct {
    Count           int            `json:"count"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Client struct {
    baseURL     string
    accessToken string
    httpClient  *http.Client
    stats       Stats
    db          *buntdb.DB
}

func getCurrentDirectory() string {
    dir, err := os.Getwd()
    if err != nil {
        return err.Error()
    }
    return dir
}

func NewClient(accessToken string) (*Client, error) {
    db, err := buntdb.Open("devices.db")
    if err != nil {
        return nil, fmt.Errorf("opening database: %v", err)
    }

    return &Client{
        baseURL:     "https://api.lookout.com",
        accessToken: accessToken,
        httpClient:  &http.Client{Timeout: 30 * time.Second},
        db:          db,
    }, nil
}

func (c *Client) Close() {
    if c.db != nil {
        c.db.Close()
    }
}

func (s *Stats) increment(field *int) {
    s.mu.Lock()
    *field++
    s.mu.Unlock()
}

func (c *Client) getAccessToken(applicationKey string) error {
    data := fmt.Sprintf("grant_type=client_credentials")
    req, err := http.NewRequest("POST", c.baseURL+"/oauth2/token", strings.NewReader(data))
    if err != nil {
        return fmt.Errorf("creating token request: %v", err)
    }

    req.Header.Set("Authorization", "Bearer "+applicationKey)
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("Accept", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("requesting token: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("token request failed with status: %d", resp.StatusCode)
    }

    var tokenResp TokenResponse
    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return fmt.Errorf("decoding token response: %v", err)
    }

    c.accessToken = tokenResp.AccessToken
    return nil
}

func (c *Client) saveDevice(device Device) error {
    deviceJSON, err := json.Marshal(device)
    if err != nil {
        return fmt.Errorf("marshaling device: %v", err)
    }

    err = c.db.Update(func(tx *buntdb.Tx) error {
        _, _, err := tx.Set(device.GUID, string(deviceJSON), nil)
        return err
    })
    return err
}

func (c *Client) getStoredDevice(guid string) (*Device, error) {
    var device Device
    err := c.db.View(func(tx *buntdb.Tx) error {
        val, err := tx.Get(guid)
        if err != nil {
            return err
        }
        return json.Unmarshal([]byte(val), &device)
    })
    if err != nil {
        return nil, err
    }
    return &device, nil
}

func (c *Client) getAllStoredDevices() ([]Device, error) {
    var devices []Device
    err := c.db.View(func(tx *buntdb.Tx) error {
        return tx.Ascend("", func(key, value string) bool {
            var device Device
            if err := json.Unmarshal([]byte(value), &device); err != nil {
                return false
            }
            devices = append(devices, device)
            return true
        })
    })
    return devices, err
}

func (c *Client) getDevices(lastOID string, limit int) (*DevicesResponse, error) {
    url := fmt.Sprintf("%s/mra/api/v2/devices?limit=%d", c.baseURL, limit)
    if lastOID != "" {
        url += "&oid=" + lastOID
    }

    fmt.Printf("\rFetching devices batch (last OID: %s)...", lastOID)

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, fmt.Errorf("creating devices request: %v", err)
    }

    req.Header.Set("Authorization", "Bearer "+c.accessToken)
    req.Header.Set("Accept", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("requesting devices: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusTooManyRequests {
        time.Sleep(5 * time.Second)
        return c.getDevices(lastOID, limit)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("devices request failed with status: %d", resp.StatusCode)
    }

    var devicesResp DevicesResponse
    if err := json.NewDecoder(resp.Body).Decode(&devicesResp); err != nil {
        return nil, fmt.Errorf("decoding devices response: %v", err)
    }

    return &devicesResp, nil
}

func (c *Client) getVulnerabilities(platform, version string) ([]Vulnerability, error) {
    var url string
    if platform == "ANDROID" {
        url = fmt.Sprintf("%s/mra/api/v2/os-vulns/android?aspl=%s", c.baseURL, version)
    } else {
        url = fmt.Sprintf("%s/mra/api/v2/os-vulns/ios?version=%s", c.baseURL, version)
    }

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, fmt.Errorf("creating vulnerabilities request: %v", err)
    }

    req.Header.Set("Authorization", "Bearer "+c.accessToken)
    req.Header.Set("Accept", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("requesting vulnerabilities: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusTooManyRequests {
        time.Sleep(5 * time.Second)
        return c.getVulnerabilities(platform, version)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("vulnerabilities request failed with status: %d", resp.StatusCode)
    }

    var vulnsResp VulnerabilitiesResponse
    if err := json.NewDecoder(resp.Body).Decode(&vulnsResp); err != nil {
        return nil, fmt.Errorf("decoding vulnerabilities response: %v", err)
    }

    return vulnsResp.Vulnerabilities, nil
}

func (c *Client) processDeviceBatch(devices []Device, parentDevices map[string]*Device, wg *sync.WaitGroup) {
    defer wg.Done()
    
    for _, device := range devices {
        if err := c.processDevice(device, parentDevices); err != nil {
            fmt.Printf("\nError processing device %s: %v\n", device.GUID, err)
        }
    }
}

func (c *Client) processDevice(device Device, parentDevices map[string]*Device) error {
    fmt.Printf("\rProcessing device: %s...", device.GUID)

    // Save device to local DB
    if err := c.saveDevice(device); err != nil {
        return fmt.Errorf("saving device: %v", err)
    }

    // Skip deactivated devices
    if device.ActivationStatus != "ACTIVATED" {
        return nil
    }

    // Handle child devices
    if device.ParentDeviceGUID != "" {
        if parent, exists := parentDevices[device.ParentDeviceGUID]; exists {
            parent.ChildCount++
            return nil
        }
    }

    c.stats.increment(&c.stats.ActiveDevices)
    if device.Platform == "ANDROID" {
        c.stats.increment(&c.stats.AndroidDevices)
        vulns, err := c.getVulnerabilities("ANDROID", device.Software.SecurityPatchLevel)
        if err != nil {
            return fmt.Errorf("getting Android vulnerabilities: %v", err)
        }
        if len(vulns) > 0 {
            c.stats.increment(&c.stats.VulnerableDevices)
        }
    } else if device.Platform == "IOS" {
        c.stats.increment(&c.stats.IOSDevices)
        vulns, err := c.getVulnerabilities("IOS", device.Software.OSVersion)
        if err != nil {
            return fmt.Errorf("getting iOS vulnerabilities: %v", err)
        }
        if len(vulns) > 0 {
            c.stats.increment(&c.stats.VulnerableDevices)
        }
    }

    return nil
}

func main() {
    if err := godotenv.Load(); err != nil {
        fmt.Printf("Error loading .env file: %v\n", err)
        fmt.Printf("Working directory: %s\n", getCurrentDirectory())
    }

    applicationKey := os.Getenv("APPLICATION_KEY")
    if applicationKey == "" {
        fmt.Println("APPLICATION_KEY not found in .env file")
        os.Exit(1)
    }

    client, err := NewClient("")
    if err != nil {
        fmt.Printf("Error creating client: %v\n", err)
        os.Exit(1)
    }
    defer client.Close()

    if len(os.Args) > 1 && os.Args[1] == "--local" {
        fmt.Println("Reading from local database...")
        devices, err := client.getAllStoredDevices()
        if err != nil {
            fmt.Printf("Error reading local devices: %v\n", err)
            os.Exit(1)
        }
        
        fmt.Printf("\nLocal Device Statistics:\n")
        fmt.Printf("Total Devices: %d\n", len(devices))
        
        androidCount := 0
        iosCount := 0
        for _, device := range devices {
            if device.Platform == "ANDROID" {
                androidCount++
            } else if device.Platform == "IOS" {
                iosCount++
            }
        }
        fmt.Printf("Android Devices: %d\n", androidCount)
        fmt.Printf("iOS Devices: %d\n", iosCount)
        return
    }

    fmt.Println("Getting access token...")
    if err := client.getAccessToken(applicationKey); err != nil {
        fmt.Printf("Error getting access token: %v\n", err)
        os.Exit(1)
    }

    parentDevices := make(map[string]*Device)
    var lastOID string
    const limit = 1000
    const numWorkers = 5 // Number of concurrent workers
    var wg sync.WaitGroup
    devicesChan := make(chan []Device, numWorkers)

    // Start worker goroutines
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for devices := range devicesChan {
                wg.Add(1)
                client.processDeviceBatch(devices, parentDevices, &wg)
            }
        }()
    }

    for {
        devicesResp, err := client.getDevices(lastOID, limit)
        if err != nil {
            fmt.Printf("Error getting devices: %v\n", err)
            os.Exit(1)
        }

        if len(devicesResp.Devices) == 0 {
            break
        }

        // Split devices into smaller batches for workers
        batchSize := (len(devicesResp.Devices) + numWorkers - 1) / numWorkers
        for i := 0; i < len(devicesResp.Devices); i += batchSize {
            end := i + batchSize
            if end > len(devicesResp.Devices) {
                end = len(devicesResp.Devices)
            }
            wg.Add(1)
            devicesChan <- devicesResp.Devices[i:end]
        }

        lastOID = devicesResp.Devices[len(devicesResp.Devices)-1].OID
    }

    close(devicesChan)
    wg.Wait()
    
    fmt.Printf("\nDevice Statistics:\n")
    fmt.Printf("Active Devices: %d\n", client.stats.ActiveDevices)
    fmt.Printf("Android Devices: %d\n", client.stats.AndroidDevices)
    fmt.Printf("iOS Devices: %d\n", client.stats.IOSDevices)
    fmt.Printf("Vulnerable Devices: %d\n", client.stats.VulnerableDevices)
}
