//go:build !linux && !darwin

package telegram

import "os"

const filePathSupported = false

func resolveOpenedFDPath(*os.File) (string, error) {
	return "", errFilePathUnsupported
}
