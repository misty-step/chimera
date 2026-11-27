//go:build unix

package inlet

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestM2_3_ClassifierTimeoutKillsEverythingItStarted: after the timeout the
// command and the children it left behind are gone — checked by pid, not by
// how long the call took.
func TestM2_3_ClassifierTimeoutKillsEverythingItStarted(t *testing.T) {
	dir := t.TempDir()
	script := "sleep 300 & echo $! > " + filepath.Join(dir, "child.pid") + "; echo $$ > " + filepath.Join(dir, "self.pid") + "; sleep 300"
	start := time.Now()
	_, err := (CommandClassifier{Argv: []string{"sh", "-c", script}, Timeout: 500 * time.Millisecond}).Classify(context.Background(), Nit{}, FolioSnapshot{})
	if err == nil || !strings.Contains(err.Error(), "timed out") || time.Since(start) > 20*time.Second {
		t.Fatalf("err=%v after %s", err, time.Since(start))
	}
	for _, name := range []string{"self.pid", "child.pid"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || pid <= 1 {
			t.Fatalf("%s: %q", name, raw)
		}
		gone := false
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
				gone = true
				break
			}
		}
		if !gone {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Errorf("%s: process %d outlived the classifier's timeout", name, pid)
		}
	}
}
