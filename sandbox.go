// Package sandbox provides a reusable, one-shot sandboxed command runner built
// on the same Docker client and hardened isolation preset
// (the isolation subpackage) that synchestra's long-lived runner uses.
//
// Where the synchestra runner targets long-lived agent-in-container sessions
// that register back over gRPC, this package fills the complementary need: run
// a single command to completion inside a locked-down container, capture its
// logs and selected artifact files, then always tear the container down. It is
// intended for external modules — e.g. a coverage runner that executes
// `go test -coverprofile` inside a cloned repo and collects the produced
// profiles.
//
// Security flags (read-only rootfs, CAP_DROP=ALL, non-root 65532,
// no-new-privileges, the daemon's default seccomp profile, init) are applied
// unconditionally via the shared isolation preset and cannot be weakened. The
// tunable knobs (CPU/memory/PID caps, network, timeout) live on Limits.
package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/strongo/sandbox/isolation"
)

// DefaultNetwork is the network mode used when Job.Limits.Network is empty.
//
// Tradeoff: a fully sealed sandbox would use "none", but the canonical workload
// for this package — `go test` against a cloned repo — needs network egress to
// reach the module proxy / GOPROXY and git. We therefore default to "bridge"
// (NAT egress, no inbound, no host network) rather than "none". The container is
// still hardened in every other dimension (read-only rootfs, dropped caps,
// non-root, seccomp). Callers that do not need egress should set
// Limits.Network = "none" explicitly.
const DefaultNetwork = "bridge"

// Mount describes a bind mount from the host filesystem into the container. It
// mirrors the existing internal Mount type so callers and the rest of the
// codebase speak the same shape.
//
// Mounts are intended for TRUSTED, read-only host data. Read-WRITE host bind
// mounts are discouraged for untrusted workloads (e.g. running arbitrary
// `go test` code): a malicious test could corrupt host files through the mount.
// To give untrusted code a writable source tree, inject it as a tar via
// Job.InputTar instead — the container then works on its own ephemeral copy on
// writable tmpfs, with no path back to the host filesystem.
type Mount struct {
	Source   string // host path
	Target   string // container path
	ReadOnly bool
}

// Limits are the tunable, non-security knobs of the hardened preset. Zero values
// mean "unset" (Docker default) except where noted.
type Limits struct {
	CPUs     float64       // CPU quota, e.g. 2.0; 0 = unlimited
	MemoryMB int64         // RAM cap in MiB; 0 = unlimited
	PIDs     int64         // max processes; 0 = unlimited
	Timeout  time.Duration // hard wall-clock kill; 0 = no timeout
	Network  string        // "none" | "bridge" | named network; empty = DefaultNetwork
}

// Job is one sandboxed command to run to completion.
type Job struct {
	Image   string            // runner image carrying the toolchain
	Cmd     []string          // command to run in the container
	Env     map[string]string // environment variables
	WorkDir string            // working directory inside the container
	Mounts  []Mount           // trusted, read-only bind mounts into the container

	// InputTar is an OPTIONAL tar archive of files/dirs handed to the workload as
	// a writable source tree, with no path back to the host filesystem. This is
	// the safe way to give untrusted code (e.g. `go test`) something to run on. A
	// `git archive` tarball can be passed straight in.
	//
	// It is injected into an ephemeral named VOLUME mounted at InputDir, not a
	// host bind mount: a trusted prep container creates the volume, chmods it so
	// the non-root run user can write, and the tar is copied in while that prep
	// container is running. The hardened main container then mounts the populated
	// volume; the volume is removed when RunOnce returns. (Copying into the
	// stopped main container instead would land on its rootfs and block the
	// volume from mounting — hence the prep step.)
	//
	// The image must provide a POSIX shell with `chmod` and `sleep` (busybox,
	// alpine, debian, golang, … all qualify). Tar entry paths are relative to
	// InputDir (entry "main.go" -> <InputDir>/main.go). Set WorkDir to InputDir
	// (or a subdir) to run Cmd there.
	InputTar io.Reader
	InputDir string // absolute dir the InputTar is unpacked into; defaults to "/workspace"

	Collect []string // absolute in-container paths to copy out after exit
	Limits  Limits
}

// Result is the outcome of a RunOnce call.
type Result struct {
	ExitCode  int               // container exit status
	Logs      []byte            // combined, de-multiplexed stdout+stderr
	Artifacts map[string][]byte // Collect path -> file bytes (missing paths are omitted)
	TimedOut  bool              // true if the container was killed at Limits.Timeout
}

// dockerClient is the subset of *client.Client that RunOnce needs. It keeps the
// Docker-free unit tests honest and is satisfied by the real client.
type dockerClient interface {
	ImageInspect(ctx context.Context, imageID string, opts ...client.ImageInspectOption) (image.InspectResponse, error)
	ImagePull(ctx context.Context, ref string, options image.PullOptions) (io.ReadCloser, error)
	ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, platform *ocispec.Platform, containerName string) (container.CreateResponse, error)
	ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error
	ContainerWait(ctx context.Context, containerID string, condition container.WaitCondition) (<-chan container.WaitResponse, <-chan error)
	ContainerLogs(ctx context.Context, containerID string, options container.LogsOptions) (io.ReadCloser, error)
	ContainerKill(ctx context.Context, containerID, signal string) error
	ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error
	CopyFromContainer(ctx context.Context, containerID, srcPath string) (io.ReadCloser, container.PathStat, error)
	CopyToContainer(ctx context.Context, containerID, dstPath string, content io.Reader, options container.CopyToContainerOptions) error
	VolumeCreate(ctx context.Context, options volume.CreateOptions) (volume.Volume, error)
	VolumeRemove(ctx context.Context, volumeID string, force bool) error
}

// DefaultInputDir is where Job.InputTar is unpacked when Job.InputDir is empty.
// It is one of the preset's writable tmpfs paths.
const DefaultInputDir = "/workspace"

// buildSpec turns a Job into the Docker container/host configs, applying the
// hardened isolation preset. It is pure (no Docker calls) so it can be unit
// tested without a daemon. AutoRemove is deliberately left false: we copy
// artifacts out AFTER the container exits and then remove it ourselves.
func buildSpec(j Job, inputVolume string) (*container.Config, *container.HostConfig) {
	env := make([]string, 0, len(j.Env))
	for k, v := range j.Env {
		env = append(env, k+"="+v)
	}

	cfg := &container.Config{
		Image:      j.Image,
		Cmd:        j.Cmd,
		Env:        env,
		WorkingDir: j.WorkDir,
		User:       isolation.NonRootUser,
	}

	netMode := j.Limits.Network
	if netMode == "" {
		netMode = DefaultNetwork
	}

	// Writable scratch space, since the rootfs is read-only. /workspace and
	// /tmp mirror the runner preset.
	tmpfs := map[string]string{
		"/workspace": "rw,size=512m,mode=1777",
		"/tmp":       "rw,size=128m",
	}

	// The input dir must be writable. When a tar is injected, CopyToContainer
	// runs BEFORE the container starts — but tmpfs mounts only materialize at
	// start, so a pre-start copy would land on the read-only rootfs and fail.
	// Back it with a named VOLUME (exists at create time, no host path) that
	// runOnce has already chmod'd 0777 via an init container so the non-root run
	// user can write into it. Without an injected tar, tmpfs is fine since all
	// writes happen at runtime after start.
	var volMounts []mount.Mount
	dir := inputDir(j)
	if inputVolume != "" {
		delete(tmpfs, dir)
		volMounts = append(volMounts, mount.Mount{Type: mount.TypeVolume, Source: inputVolume, Target: dir})
	} else if !coveredByTmpfs(dir, tmpfs) {
		tmpfs[dir] = "rw,size=512m,mode=1777"
	}

	preset := isolation.Preset{
		NanoCPUs:    int64(j.Limits.CPUs * 1e9),
		MemoryBytes: j.Limits.MemoryMB * 1024 * 1024,
		PidsLimit:   j.Limits.PIDs,
		NetworkMode: netMode,
		Tmpfs:       tmpfs,
		AutoRemove:  false,
	}.HostConfig()

	preset.Mounts = append(preset.Mounts, volMounts...)
	for _, m := range j.Mounts {
		preset.Binds = append(preset.Binds, bindString(m))
	}

	return cfg, preset
}

// inputDir returns the directory Job.InputTar unpacks into, defaulting to
// DefaultInputDir.
func inputDir(j Job) string {
	if j.InputDir != "" {
		return j.InputDir
	}
	return DefaultInputDir
}

// coveredByTmpfs reports whether dir is one of, or nested under, an existing
// tmpfs mount path (so it is already writable and needs no extra mount).
func coveredByTmpfs(dir string, tmpfs map[string]string) bool {
	for p := range tmpfs {
		if dir == p || strings.HasPrefix(dir, p+"/") {
			return true
		}
	}
	return false
}

func bindString(m Mount) string {
	s := m.Source + ":" + m.Target
	if m.ReadOnly {
		s += ":ro"
	}
	return s
}

// RunOnce pulls Image if it is not already present, creates a container with the
// hardened preset (tuned by Limits), runs Cmd to completion (or kills it at
// Limits.Timeout), captures combined stdout+stderr, copies out the Collect
// artifacts, and always removes the container before returning.
//
// The returned Result is populated on a best-effort basis: a non-zero ExitCode
// or a timeout is reported through Result, not as an error. A non-nil error
// means the run could not be carried out (pull/create/start/wait failure); even
// then the container is force-removed.
func RunOnce(ctx context.Context, j Job) (Result, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return Result{}, fmt.Errorf("sandbox: docker client: %w", err)
	}
	defer func() { _ = cli.Close() }()
	return runOnce(ctx, cli, j)
}

// runOnce is the testable core of RunOnce: it takes an injected dockerClient.
func runOnce(ctx context.Context, cli dockerClient, j Job) (Result, error) {
	if err := ensureImage(ctx, cli, j.Image); err != nil {
		return Result{}, err
	}

	// When injecting a source tree, back the workdir with a named volume (no
	// host path, writable at create time for the pre-start CopyToContainer).
	// The volume's mount point is created root-owned, so a short init container
	// chmods it 0777 before the hardened non-root container runs.
	var inputVolume string
	if j.InputTar != nil {
		v, err := cli.VolumeCreate(ctx, volume.CreateOptions{})
		if err != nil {
			return Result{}, fmt.Errorf("sandbox: create input volume: %w", err)
		}
		inputVolume = v.Name
		defer func() { _ = cli.VolumeRemove(context.WithoutCancel(ctx), inputVolume, true) }()
		// Populate + chmod the volume via a RUNNING prep container. The source
		// must be copied while a container with the volume actively mounted is
		// running — copying into a stopped container lands on its rootfs and then
		// blocks the volume from mounting in the main container.
		if err := prepInputVolume(ctx, cli, j.Image, inputVolume, inputDir(j), j.InputTar); err != nil {
			return Result{}, err
		}
	}

	cfg, hostCfg := buildSpec(j, inputVolume)
	created, err := cli.ContainerCreate(ctx, cfg, hostCfg, &network.NetworkingConfig{}, nil, "")
	if err != nil {
		return Result{}, fmt.Errorf("sandbox: container create: %w", err)
	}
	id := created.ID

	// Guaranteed teardown. Force-remove copes with a container still running
	// (e.g. an early error) and with AutoRemove being off.
	defer func() {
		_ = cli.ContainerRemove(context.WithoutCancel(ctx), id, container.RemoveOptions{Force: true, RemoveVolumes: true})
	}()

	// (Source injection already happened into the input volume via the prep
	// container above; the main container just mounts the populated volume.)

	// runCtx bounds the whole run by the wall-clock Timeout. When it fires we
	// SIGKILL the container so ContainerWait unblocks.
	runCtx := ctx
	var cancel context.CancelFunc
	if j.Limits.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, j.Limits.Timeout)
		defer cancel()
	}

	if err := cli.ContainerStart(runCtx, id, container.StartOptions{}); err != nil {
		return Result{}, fmt.Errorf("sandbox: container start: %w", err)
	}

	res := Result{Artifacts: map[string][]byte{}}

	waitCh, errCh := cli.ContainerWait(runCtx, id, container.WaitConditionNotRunning)
	select {
	case wr := <-waitCh:
		res.ExitCode = int(wr.StatusCode)
	case werr := <-errCh:
		if runCtx.Err() != nil {
			// Timeout (or parent cancellation): kill so the container stops,
			// then report the timeout rather than the wait error.
			_ = cli.ContainerKill(context.WithoutCancel(ctx), id, "SIGKILL")
			res.TimedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded)
			res.ExitCode = -1
		} else if werr != nil {
			return res, fmt.Errorf("sandbox: container wait: %w", werr)
		}
	}

	// Logs and artifacts are collected with the parent ctx so they survive a
	// run timeout (the container has already stopped at this point).
	res.Logs = collectLogs(ctx, cli, id)
	for _, p := range j.Collect {
		if b, ok := collectArtifact(ctx, cli, id, p); ok {
			res.Artifacts[p] = b
		}
	}

	return res, nil
}

// prepInputVolume populates and permissions the freshly-created input volume so
// the hardened non-root main container can both read the injected source and
// write outputs into the workdir. It runs a short, trusted prep container (as
// root) that chmods the mount point 0777 and then idles; while it is RUNNING
// (so the volume is actively mounted) the source tar is copied IN — copying into
// a stopped container would land on its rootfs and block the volume from
// mounting in the main container. The prep container runs no untrusted code and
// is always removed.
//
// The image must provide a POSIX shell with `chmod` and `sleep` (busybox,
// alpine, debian, golang, … all do).
func prepInputVolume(ctx context.Context, cli dockerClient, image, vol, dir string, tar io.Reader) error {
	cfg := &container.Config{
		Image: image,
		// chmod the mount point, then idle so we can copy into the live volume.
		Cmd: []string{"sh", "-c", "chmod 0777 '" + dir + "' && sleep 3600"},
	}
	hostCfg := &container.HostConfig{
		AutoRemove: false,
		Mounts:     []mount.Mount{{Type: mount.TypeVolume, Source: vol, Target: dir}},
	}
	created, err := cli.ContainerCreate(ctx, cfg, hostCfg, &network.NetworkingConfig{}, nil, "")
	if err != nil {
		return fmt.Errorf("sandbox: prep container create: %w", err)
	}
	id := created.ID
	defer func() {
		_ = cli.ContainerKill(context.WithoutCancel(ctx), id, "SIGKILL")
		_ = cli.ContainerRemove(context.WithoutCancel(ctx), id, container.RemoveOptions{Force: true})
	}()
	if err := cli.ContainerStart(ctx, id, container.StartOptions{}); err != nil {
		return fmt.Errorf("sandbox: prep container start: %w", err)
	}
	if tar != nil {
		if err := cli.CopyToContainer(ctx, id, dir, tar, container.CopyToContainerOptions{}); err != nil {
			return fmt.Errorf("sandbox: inject input tar at %s: %w", dir, err)
		}
	}
	return nil
}

// ensureImage pulls ref only if it is not already present locally.
func ensureImage(ctx context.Context, cli dockerClient, ref string) error {
	if _, err := cli.ImageInspect(ctx, ref); err == nil {
		return nil
	}
	rc, err := cli.ImagePull(ctx, ref, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("sandbox: image pull %q: %w", ref, err)
	}
	defer func() { _ = rc.Close() }()
	// Draining the pull stream blocks until the pull completes.
	_, _ = io.Copy(io.Discard, rc)
	return nil
}

// collectLogs reads and de-multiplexes the container's stdout+stderr into a
// single combined byte slice. Errors are swallowed: logs are best-effort.
func collectLogs(ctx context.Context, cli dockerClient, id string) []byte {
	rc, err := cli.ContainerLogs(ctx, id, container.LogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return nil
	}
	defer func() { _ = rc.Close() }()
	var buf bytes.Buffer
	// Non-TTY logs are stream-multiplexed; StdCopy strips the frame headers and
	// merges both streams into buf.
	if _, err := stdcopy.StdCopy(&buf, &buf, rc); err != nil {
		return buf.Bytes()
	}
	return buf.Bytes()
}

// collectArtifact copies srcPath out of the container and returns the file's
// bytes. CopyFromContainer returns a tar stream; for a single regular file the
// archive has exactly one entry, which we read out. A missing path (or any copy
// error) yields ok=false so the caller can simply omit it from Result.Artifacts.
func collectArtifact(ctx context.Context, cli dockerClient, id, srcPath string) (b []byte, ok bool) {
	rc, _, err := cli.CopyFromContainer(ctx, id, srcPath)
	if err != nil {
		return nil, false
	}
	defer func() { _ = rc.Close() }()
	return readSingleFileTar(rc, path.Base(srcPath))
}

// readSingleFileTar reads the first regular-file entry from a tar stream whose
// base name matches want and returns its bytes. Returns ok=false if no such
// entry exists.
func readSingleFileTar(r io.Reader, want string) (b []byte, ok bool) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, false
		}
		if err != nil {
			return nil, false
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if path.Base(hdr.Name) != want {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, false
		}
		return data, true
	}
}
