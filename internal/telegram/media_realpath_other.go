//go:build !linux && !darwin

package telegram

import (
	"fmt"
	"os"
)

func resolveOpenedFDPath(*os.File) (string, error) {
	return "", fmt.Errorf("secure fd-to-path is unavailable on this platform")
}
