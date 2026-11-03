// Package csvparse decodes device-app inventory files (CSV and JSON) into a
// slice of App records. Used by both cmd/patched-import-scan and the
// POST /admin/import-scan/cve.pdf HTTP handler so the parsing logic lives once.
package csvparse

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// App is one row from an inventory file.
type App struct {
	DeviceName string `json:"deviceName"`
	AppName    string `json:"appName"`
	AppVersion string `json:"appVersion"`
}

// ParseCSV reads a CSV inventory export and returns the parsed rows.
// The header row is required. Accepted column name variants:
//
//	Device:  deviceName, device name, device
//	App:     appName, application, app name, app
//	Version: appVersion, version, app version  (optional column)
//
// Rows with an empty device or app name are silently skipped (Intune
// sometimes emits blank lines mid-export).
func ParseCSV(r io.Reader) ([]App, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read csv header: %w", err)
	}

	colIdx := map[string]int{}
	for i, h := range header {
		colIdx[strings.ToLower(strings.TrimSpace(h))] = i
	}

	deviceCol := findCol(colIdx, "devicename", "device name", "device")
	appCol := findCol(colIdx, "appname", "application", "app name", "app")
	versionCol := findCol(colIdx, "appversion", "version", "app version")

	if deviceCol < 0 || appCol < 0 {
		return nil, fmt.Errorf("csv missing required columns (device name + app name); headers: %v", header)
	}

	var apps []App
	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read csv row: %w", err)
		}
		a := App{
			DeviceName: colVal(row, deviceCol),
			AppName:    colVal(row, appCol),
			AppVersion: colVal(row, versionCol),
		}
		if a.DeviceName != "" && a.AppName != "" {
			apps = append(apps, a)
		}
	}
	return apps, nil
}

// ParseJSON decodes a JSON array of App objects.
func ParseJSON(r io.Reader) ([]App, error) {
	var apps []App
	if err := json.NewDecoder(r).Decode(&apps); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	return apps, nil
}

func findCol(idx map[string]int, names ...string) int {
	for _, name := range names {
		if i, ok := idx[name]; ok {
			return i
		}
	}
	return -1
}

func colVal(row []string, i int) string {
	if i < 0 || i >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[i])
}
