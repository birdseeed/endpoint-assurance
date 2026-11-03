//go:build unix

package handlers

import "syscall"

func diskUsageBytes(path string) (total, free, available float64, err error) {
	var stat syscall.Statfs_t
	if err = syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0, err
	}
	bsize := float64(stat.Bsize)
	return float64(stat.Blocks) * bsize, float64(stat.Bfree) * bsize, float64(stat.Bavail) * bsize, nil
}
