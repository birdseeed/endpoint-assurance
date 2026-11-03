package report

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"
)

func workbookWithNegativeSharedString(t *testing.T) *excelize.File {
	t.Helper()

	source := excelize.NewFile()
	t.Cleanup(func() { _ = source.Close() })
	if err := source.SetCellValue("Sheet1", "A1", "shared string"); err != nil {
		t.Fatalf("set shared-string cell: %v", err)
	}
	buffer, err := source.WriteToBuffer()
	if err != nil {
		t.Fatalf("serialise source workbook: %v", err)
	}

	reader, err := zip.NewReader(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
	if err != nil {
		t.Fatalf("open source workbook zip: %v", err)
	}
	var corrupted bytes.Buffer
	writer := zip.NewWriter(&corrupted)
	for _, file := range reader.File {
		entry, err := writer.CreateHeader(&file.FileHeader)
		if err != nil {
			t.Fatalf("create %s in corrupt workbook: %v", file.Name, err)
		}
		input, err := file.Open()
		if err != nil {
			t.Fatalf("open %s in source workbook: %v", file.Name, err)
		}
		content, err := io.ReadAll(input)
		_ = input.Close()
		if err != nil {
			t.Fatalf("read %s from source workbook: %v", file.Name, err)
		}
		if file.Name == "xl/worksheets/sheet1.xml" {
			before := string(content)
			after := strings.Replace(before, `<c r="A1" t="s"><v>0</v></c>`, `<c r="A1" t="s"><v>-1</v></c>`, 1)
			if after == before {
				t.Fatalf("source workbook did not contain the expected shared-string cell: %s", before)
			}
			content = []byte(after)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatalf("write %s to corrupt workbook: %v", file.Name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close corrupt workbook zip: %v", err)
	}

	workbook, err := excelize.OpenReader(bytes.NewReader(corrupted.Bytes()))
	if err != nil {
		t.Fatalf("open corrupt workbook: %v", err)
	}
	t.Cleanup(func() { _ = workbook.Close() })
	return workbook
}

func TestExcelizeNegativeSharedStringDoesNotPanic(t *testing.T) {
	t.Run("GetCellValue", func(t *testing.T) {
		workbook := workbookWithNegativeSharedString(t)
		if _, err := workbook.GetCellValue("Sheet1", "A1"); err == nil {
			t.Fatal("GetCellValue returned no error for shared-string index -1")
		} else if !strings.Contains(err.Error(), "-1") {
			t.Fatalf("GetCellValue error does not identify the invalid index: %v", err)
		}
	})

	t.Run("GetRows", func(t *testing.T) {
		workbook := workbookWithNegativeSharedString(t)
		rows, err := workbook.GetRows("Sheet1")
		if err != nil {
			if !strings.Contains(err.Error(), "-1") {
				t.Fatalf("GetRows error does not identify the invalid index: %v", err)
			}
			return
		}
		// GetRows intentionally discards individual cell conversion errors. The
		// v2.11.0 security contract is that the invalid index is bounds-checked,
		// so the cell is omitted or empty instead of panicking or yielding data.
		// Permit either row shape so a future fixed Excelize may preserve an empty
		// cell while still satisfying the security property.
		for _, row := range rows {
			for _, value := range row {
				if value != "" {
					t.Fatalf("GetRows returned data for invalid shared-string index: %#v", rows)
				}
			}
		}
	})
}
