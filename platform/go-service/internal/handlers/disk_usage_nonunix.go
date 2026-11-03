//go:build !unix

package handlers

import "errors"

func diskUsageBytes(string) (total, free, available float64, err error) {
	return 0, 0, 0, errors.New("filesystem usage is unavailable on this platform")
}
