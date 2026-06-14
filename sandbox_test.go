package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestBuildSpec_AppliesHardenedPresetAndLimits(t *testing.T) {
	j := Job{
		Image:   "runner:latest",
		Cmd:     []string{"go", "test", "./..."},
		Env:     map[string]string{"GOFLAGS": "-count=1"},
		WorkDir: "/repo",
		Mounts: []Mount{
			{Source: "/host/repo", Target: "/repo", ReadOnly: false},
			{Source: "/host/cache", Target: "/cache", ReadOnly: true},
		},
		Limits: Limits{CPUs: 2.0, MemoryMB: 1024, PIDs: 256, Network: "bridge"},
	}

	cfg, hc := buildSpec(j, "")

	if cfg.Image != "runner:latest" {
		t.Errorf("image = %q", cfg.Image)
	}
	if cfg.WorkingDir != "/repo" {
		t.Errorf("workdir = %q", cfg.WorkingDir)
	}
	if cfg.User != "65532:65532" {
		t.Errorf("user = %q, want non-root 65532:65532", cfg.User)
	}
	if got := strings.Join(cfg.Cmd, " "); got != "go test ./..." {
		t.Errorf("cmd = %q", got)
	}
	if len(cfg.Env) != 1 || cfg.Env[0] != "GOFLAGS=-count=1" {
		t.Errorf("env = %v", cfg.Env)
	}

	// Security flags from the shared preset — must always be on.
	if !hc.ReadonlyRootfs {
		t.Error("ReadonlyRootfs must be true")
	}
	if len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %v, want [ALL]", hc.CapDrop)
	}
	secOpt := map[string]bool{}
	for _, o := range hc.SecurityOpt {
		secOpt[o] = true
	}
	if !secOpt["no-new-privileges"] {
		t.Errorf("SecurityOpt = %v, want no-new-privileges", hc.SecurityOpt)
	}
	if secOpt["seccomp=default"] {
		t.Error("must not set seccomp=default (unparseable; daemon applies its default)")
	}
	if hc.Init == nil || !*hc.Init {
		t.Error("Init must be true")
	}
	// AutoRemove MUST be off so artifacts can be copied after exit.
	if hc.AutoRemove {
		t.Error("AutoRemove must be false for one-shot artifact collection")
	}

	// Limits.
	if hc.NanoCPUs != 2_000_000_000 {
		t.Errorf("NanoCPUs = %d, want 2e9", hc.NanoCPUs)
	}
	if hc.Memory != 1024*1024*1024 {
		t.Errorf("Memory = %d, want 1GiB", hc.Memory)
	}
	if hc.MemorySwap != hc.Memory {
		t.Errorf("MemorySwap = %d, want == Memory to disable swap", hc.MemorySwap)
	}
	if hc.PidsLimit == nil || *hc.PidsLimit != 256 {
		t.Errorf("PidsLimit = %v, want 256", hc.PidsLimit)
	}
	if string(hc.NetworkMode) != "bridge" {
		t.Errorf("NetworkMode = %q, want bridge", hc.NetworkMode)
	}

	// Mounts -> binds.
	wantBinds := map[string]bool{"/host/repo:/repo": true, "/host/cache:/cache:ro": true}
	if len(hc.Binds) != 2 {
		t.Fatalf("binds = %v, want 2", hc.Binds)
	}
	for _, b := range hc.Binds {
		if !wantBinds[b] {
			t.Errorf("unexpected bind %q", b)
		}
	}
}

func TestBuildSpec_DefaultNetworkWhenUnset(t *testing.T) {
	_, hc := buildSpec(Job{Image: "x"}, "")
	if string(hc.NetworkMode) != DefaultNetwork {
		t.Errorf("NetworkMode = %q, want default %q", hc.NetworkMode, DefaultNetwork)
	}
}

func TestReadSingleFileTar(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeTar := func(name, body string) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	writeTar("coverage.out", "mode: set\nfoo 1 1\n")
	_ = tw.Close()

	got, ok := readSingleFileTar(&buf, "coverage.out")
	if !ok {
		t.Fatal("want ok=true")
	}
	if string(got) != "mode: set\nfoo 1 1\n" {
		t.Errorf("contents = %q", got)
	}
}

func TestReadSingleFileTar_Missing(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.Close()
	if _, ok := readSingleFileTar(&buf, "nope.out"); ok {
		t.Error("want ok=false for empty tar")
	}
}

func TestReadSingleFileTar_SkipsDirEntries(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "dir/", Mode: 0o755, Typeflag: tar.TypeDir})
	_ = tw.WriteHeader(&tar.Header{Name: "dir/x.out", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("ok"))
	_ = tw.Close()

	got, ok := readSingleFileTar(&buf, "x.out")
	if !ok || string(got) != "ok" {
		t.Errorf("got %q ok=%v", got, ok)
	}
}

// --- fake docker client for runOnce ---

type fakeClient struct {
	inspectErr error // non-nil => image absent, triggers pull
	pulled     bool
	waitCode   int64
	waitErr    error // delivered on errCh instead of waitCh
	logs       []byte
	artifacts  map[string][]byte // srcPath -> file bytes
	killed     bool
	removed    bool
	started    bool

	copyToErr   error  // forced error from CopyToContainer
	copyToDst   string // captured dstPath
	copyToTar   []byte // captured tar bytes
	copyToCalls int

	volumeCreated bool
	volumeRemoved bool
}

func (f *fakeClient) ImageInspect(ctx context.Context, id string, _ ...client.ImageInspectOption) (image.InspectResponse, error) {
	return image.InspectResponse{}, f.inspectErr
}
func (f *fakeClient) ImagePull(ctx context.Context, ref string, _ image.PullOptions) (io.ReadCloser, error) {
	f.pulled = true
	return io.NopCloser(strings.NewReader("pulling...")), nil
}
func (f *fakeClient) ContainerCreate(ctx context.Context, _ *container.Config, _ *container.HostConfig, _ *network.NetworkingConfig, _ *ocispec.Platform, _ string) (container.CreateResponse, error) {
	return container.CreateResponse{ID: "cid-1"}, nil
}
func (f *fakeClient) ContainerStart(ctx context.Context, _ string, _ container.StartOptions) error {
	f.started = true
	return nil
}
func (f *fakeClient) ContainerWait(ctx context.Context, _ string, _ container.WaitCondition) (<-chan container.WaitResponse, <-chan error) {
	wc := make(chan container.WaitResponse, 1)
	ec := make(chan error, 1)
	if f.waitErr != nil {
		ec <- f.waitErr
	} else {
		wc <- container.WaitResponse{StatusCode: f.waitCode}
	}
	return wc, ec
}
func (f *fakeClient) ContainerLogs(ctx context.Context, _ string, _ container.LogsOptions) (io.ReadCloser, error) {
	// Frame the logs as a stdout-multiplexed stream so stdcopy decodes them.
	var buf bytes.Buffer
	w := stdcopy.NewStdWriter(&buf, stdcopy.Stdout)
	_, _ = w.Write(f.logs)
	return io.NopCloser(&buf), nil
}
func (f *fakeClient) ContainerKill(ctx context.Context, _, _ string) error {
	f.killed = true
	return nil
}
func (f *fakeClient) ContainerRemove(ctx context.Context, _ string, _ container.RemoveOptions) error {
	f.removed = true
	return nil
}
func (f *fakeClient) VolumeCreate(ctx context.Context, _ volume.CreateOptions) (volume.Volume, error) {
	f.volumeCreated = true
	return volume.Volume{Name: "vol-1"}, nil
}
func (f *fakeClient) VolumeRemove(ctx context.Context, _ string, _ bool) error {
	f.volumeRemoved = true
	return nil
}
func (f *fakeClient) CopyToContainer(ctx context.Context, _, dstPath string, content io.Reader, _ container.CopyToContainerOptions) error {
	f.copyToCalls++
	f.copyToDst = dstPath
	if f.copyToErr != nil {
		return f.copyToErr
	}
	b, _ := io.ReadAll(content)
	f.copyToTar = b
	return nil
}
func (f *fakeClient) CopyFromContainer(ctx context.Context, _, srcPath string) (io.ReadCloser, container.PathStat, error) {
	body, ok := f.artifacts[srcPath]
	if !ok {
		return nil, container.PathStat{}, io.EOF // mimic "no such file"
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	name := srcPath[strings.LastIndexByte(srcPath, '/')+1:]
	_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	return io.NopCloser(&buf), container.PathStat{}, nil
}

func TestRunOnce_HappyPath(t *testing.T) {
	fc := &fakeClient{
		waitCode:  0,
		logs:      []byte("PASS\nok\n"),
		artifacts: map[string][]byte{"/repo/coverage.out": []byte("mode: set\n")},
	}
	res, err := runOnce(context.Background(), fc, Job{
		Image:   "runner",
		Cmd:     []string{"go", "test"},
		Collect: []string{"/repo/coverage.out", "/repo/missing.out"},
	})
	if err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d", res.ExitCode)
	}
	if res.TimedOut {
		t.Error("TimedOut should be false")
	}
	if string(res.Logs) != "PASS\nok\n" {
		t.Errorf("logs = %q", res.Logs)
	}
	if string(res.Artifacts["/repo/coverage.out"]) != "mode: set\n" {
		t.Errorf("artifact = %q", res.Artifacts["/repo/coverage.out"])
	}
	if _, present := res.Artifacts["/repo/missing.out"]; present {
		t.Error("missing artifact should be omitted, not present")
	}
	if !fc.started || !fc.removed {
		t.Errorf("started=%v removed=%v, both want true", fc.started, fc.removed)
	}
}

func TestRunOnce_PullsWhenImageAbsent(t *testing.T) {
	fc := &fakeClient{inspectErr: io.EOF}
	if _, err := runOnce(context.Background(), fc, Job{Image: "absent"}); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if !fc.pulled {
		t.Error("expected ImagePull when image absent")
	}
}

func TestRunOnce_NonZeroExitIsResultNotError(t *testing.T) {
	fc := &fakeClient{waitCode: 2, logs: []byte("FAIL\n")}
	res, err := runOnce(context.Background(), fc, Job{Image: "runner"})
	if err != nil {
		t.Fatalf("runOnce returned error for non-zero exit: %v", err)
	}
	if res.ExitCode != 2 {
		t.Errorf("exit = %d, want 2", res.ExitCode)
	}
}

func TestRunOnce_TimeoutKillsAndFlags(t *testing.T) {
	// waitErr on a context that has already timed out => TimedOut path.
	fc := &fakeClient{waitErr: context.DeadlineExceeded}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure runCtx deadline is exceeded

	res, err := runOnce(ctx, fc, Job{Image: "runner", Limits: Limits{Timeout: time.Nanosecond}})
	if err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if !res.TimedOut {
		t.Error("TimedOut should be true")
	}
	if !fc.killed {
		t.Error("expected container kill on timeout")
	}
	if res.ExitCode != -1 {
		t.Errorf("exit = %d, want -1 on timeout", res.ExitCode)
	}
}

func TestRunOnce_WaitErrorWithoutTimeoutIsError(t *testing.T) {
	fc := &fakeClient{waitErr: io.ErrUnexpectedEOF}
	_, err := runOnce(context.Background(), fc, Job{Image: "runner"})
	if err == nil {
		t.Fatal("want error when wait fails outside a timeout")
	}
}

func TestRunOnce_InjectsInputTarBeforeStart(t *testing.T) {
	// Build a small tar to inject.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	_ = tw.WriteHeader(&tar.Header{Name: "main.go", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hello"))
	_ = tw.Close()
	tarBytes := tarBuf.Bytes()

	fc := &fakeClient{waitCode: 0}
	_, err := runOnce(context.Background(), fc, Job{
		Image:    "runner",
		InputTar: bytes.NewReader(tarBytes),
		InputDir: "/repo",
		WorkDir:  "/repo",
		Cmd:      []string{"go", "test"},
	})
	if err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if fc.copyToCalls != 1 {
		t.Fatalf("CopyToContainer calls = %d, want 1", fc.copyToCalls)
	}
	if fc.copyToDst != "/repo" {
		t.Errorf("dst = %q, want /repo", fc.copyToDst)
	}
	if !bytes.Equal(fc.copyToTar, tarBytes) {
		t.Errorf("injected tar bytes mismatch: got %d bytes, want %d", len(fc.copyToTar), len(tarBytes))
	}
	if !fc.started {
		t.Error("container should still start after injection")
	}
}

func TestRunOnce_NoInjectionWhenInputTarNil(t *testing.T) {
	fc := &fakeClient{waitCode: 0}
	if _, err := runOnce(context.Background(), fc, Job{Image: "runner"}); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if fc.copyToCalls != 0 {
		t.Errorf("CopyToContainer called %d times, want 0", fc.copyToCalls)
	}
}

func TestRunOnce_InjectionErrorIsFatalAndCleansUp(t *testing.T) {
	fc := &fakeClient{copyToErr: io.ErrClosedPipe}
	_, err := runOnce(context.Background(), fc, Job{
		Image:    "runner",
		InputTar: strings.NewReader("garbage"),
	})
	if err == nil {
		t.Fatal("want error when injection fails")
	}
	// Injection happens in the prep container; on failure the run must abort
	// before the main container and clean up the prep container + input volume.
	if !fc.removed {
		t.Error("prep container must still be removed after injection failure")
	}
	if !fc.volumeRemoved {
		t.Error("input volume must be removed after injection failure")
	}
}

func TestBuildSpec_InjectedInputDirIsVolumeNotTmpfs(t *testing.T) {
	// When a tar is injected, the input dir must be a writable VOLUME (present at
	// create time) — not tmpfs, which only mounts at start and would make the
	// pre-start CopyToContainer hit the read-only rootfs.
	_, hc := buildSpec(Job{Image: "x"}, "vol-9")
	if _, ok := hc.Tmpfs["/workspace"]; ok {
		t.Error("/workspace must NOT be tmpfs when an input volume is given")
	}
	found := false
	for _, m := range hc.Mounts {
		if string(m.Type) == "volume" && m.Target == "/workspace" && m.Source == "vol-9" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected named volume vol-9 at /workspace, got mounts %+v", hc.Mounts)
	}
}

func TestBuildSpec_NoInputTarKeepsWorkspaceTmpfs(t *testing.T) {
	// Without an injected tar, /workspace stays tmpfs (writes happen at runtime).
	_, hc := buildSpec(Job{Image: "x"}, "")
	if _, ok := hc.Tmpfs["/workspace"]; !ok {
		t.Error("/workspace tmpfs missing when no tar injected")
	}
}

func TestBuildSpec_CustomInputDirGetsWritableTmpfs(t *testing.T) {
	_, hc := buildSpec(Job{Image: "x", InputDir: "/repo"}, "")
	opt, ok := hc.Tmpfs["/repo"]
	if !ok {
		t.Fatal("custom InputDir /repo did not get a tmpfs mount")
	}
	if !strings.HasPrefix(opt, "rw,") {
		t.Errorf("/repo tmpfs opts = %q, want writable", opt)
	}
}

func TestBuildSpec_InputDirUnderWorkspaceReusesTmpfs(t *testing.T) {
	_, hc := buildSpec(Job{Image: "x", InputDir: "/workspace/src"}, "")
	// Nested under an existing tmpfs path => no separate mount added.
	if _, ok := hc.Tmpfs["/workspace/src"]; ok {
		t.Error("/workspace/src should reuse /workspace tmpfs, not add its own")
	}
}
