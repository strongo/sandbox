package sandbox_test

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/strongo/sandbox"
)

// TestRunOnce_Integration exercises the real Docker daemon. It is skipped under
// `go test -short` and when SANDBOX_INTEGRATION is not set, so the default
// `go test ./...` never requires a live daemon.
func TestRunOnce_Integration(t *testing.T) {
	if testing.Short() || os.Getenv("SANDBOX_INTEGRATION") == "" {
		t.Skip("set SANDBOX_INTEGRATION=1 and run without -short for the Docker integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Inject a source tree as a tar onto the writable workdir, have the
	// container read it, then collect a produced artifact — the exact shape the
	// coverage runner uses (git archive -> InputTar; coverprofile -> Collect).
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	body := "injected-source\n"
	_ = tw.WriteHeader(&tar.Header{Name: "input.txt", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte(body))
	_ = tw.Close()

	res, err := sandbox.RunOnce(ctx, sandbox.Job{
		Image:    "busybox:latest",
		InputTar: bytes.NewReader(tarBuf.Bytes()),
		InputDir: "/work",
		WorkDir:  "/work",
		// Echo the injected file back, and produce an artifact, then exit 0.
		Cmd:     []string{"sh", "-c", "cat /work/input.txt; echo hello-stdout; echo cov-data > /work/coverage.out"},
		Collect: []string{"/work/coverage.out"},
		Limits:  sandbox.Limits{CPUs: 1, MemoryMB: 256, PIDs: 128, Timeout: time.Minute, Network: "none"},
	})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, logs:\n%s", res.ExitCode, res.Logs)
	}
	if !strings.Contains(string(res.Logs), "hello-stdout") {
		t.Errorf("logs missing stdout: %q", res.Logs)
	}
	if !strings.Contains(string(res.Logs), "injected-source") {
		t.Errorf("logs missing injected file contents: %q", res.Logs)
	}
	if got := strings.TrimSpace(string(res.Artifacts["/work/coverage.out"])); got != "cov-data" {
		t.Errorf("artifact = %q, want cov-data", got)
	}
}
