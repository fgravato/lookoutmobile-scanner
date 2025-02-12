# Lookout API Device Scanner

A Go application to scan and analyze devices using Lookout's Mobile Risk API.

## Features

- Retrieves device information from Lookout API
- Scans for vulnerabilities
- Local storage in BuntDB
- Multi-threaded processing
- Progress indicators
- Device statistics

## Prerequisites

- Go 1.16 or higher
- Lookout API application key

## Installation

```bash
git clone https://github.com/fgravato/lookoutmobile-scanner
cd lookoutmobile-scanner
go mod init lookoutmobile-scanner
go get github.com/joho/godotenv
go get github.com/tidwall/buntdb
```

## Configuration

1. Ensure the `data` directory exists in the project root (it will store the BuntDB database):
```bash
mkdir -p data
```

2. Create `.env` file in project root:
```
APPLICATION_KEY=your_lookout_application_key_here
```

## Usage

Fetch new data from API:
```bash
go run main.go
```

Read stored local data:
```bash
go run main.go --local
```

## Output

The application displays:
- Active Devices
- Android Devices
- iOS Devices
- Vulnerable Devices

Data is stored in `devices.db` for future access.

## Rate Limiting

The application includes automatic retry with exponential backoff for rate-limited requests.
