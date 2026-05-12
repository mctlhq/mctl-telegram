package mcp

import "fmt"

func fmtSprintfImpl(format string, a ...any) string {
	return fmt.Sprintf(format, a...)
}
