package fakeonly

import (
	"os/exec"
	"testing"
)

// T12: the glovo_real tag must not compile in this slice.
func TestGlovoRealTagDoesNotCompile(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	out, err := exec.Command("go", "build", "-tags", "glovo_real", ".").CombinedOutput()
	if err == nil {
		t.Fatalf("glovo_real build must fail, output: %s", out)
	}
}
