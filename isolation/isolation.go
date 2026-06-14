// Package isolation is the single source of truth for the hardened container
// security preset ("profile B" in the generic-runners design spec): read-only
// rootfs, all Linux capabilities dropped, a non-root user, no-new-privileges,
// the default seccomp profile, an init process to reap zombies, and CPU /
// memory / PID resource caps.
//
// Both the long-lived runner spawner (internal/host/runner) and the one-shot
// sandbox runner (pkg/sandbox) build their container HostConfig through this
// package so the security flags are defined in exactly one place. Callers layer
// their own non-security concerns (env, labels, mounts, network, tmpfs) on top
// of the returned HostConfig.
package isolation

import (
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/strslice"
)

// NonRootUser is the uid:gid the hardened preset runs containers as. It matches
// the `useradd -r -u 65532 -m nonroot` line in Dockerfile.runner.
const NonRootUser = "65532:65532"

// Preset describes the tunable knobs of the hardened isolation profile. The
// security-relevant flags (dropped capabilities, no-new-privileges, seccomp,
// read-only rootfs, init, non-root user) are NOT tunable — they are applied
// unconditionally by HostConfig so there is no way for a caller to silently
// weaken them.
type Preset struct {
	// NanoCPUs is the CPU quota in units of 1e-9 CPUs (e.g. 2_000_000_000 = 2
	// CPUs). Zero leaves it unset (unlimited).
	NanoCPUs int64
	// MemoryBytes caps RAM. Zero leaves it unset. MemorySwap is pinned equal
	// to MemoryBytes to disable swap usage.
	MemoryBytes int64
	// PidsLimit caps the number of processes. Zero leaves it unset.
	PidsLimit int64
	// NetworkMode is the Docker network the container attaches to (e.g.
	// "none", "bridge", or a user-defined network name). Empty leaves Docker's
	// default.
	NetworkMode string
	// Tmpfs maps container paths to tmpfs mount options (e.g.
	// "/workspace": "rw,size=512m,mode=1777"). Required because ReadonlyRootfs
	// is always true: writable scratch space must come from tmpfs (or bind
	// mounts the caller adds).
	Tmpfs map[string]string
	// AutoRemove asks Docker to delete the container once it exits. One-shot
	// callers that need to copy artifacts out AFTER exit must leave this false
	// and remove the container themselves.
	AutoRemove bool
}

// HostConfig returns a *container.HostConfig with the hardened security flags
// applied unconditionally and the tunable knobs from p filled in. The caller
// owns the returned value and may add non-security fields (Mounts, etc.) to it.
func (p Preset) HostConfig() *container.HostConfig {
	initTrue := true
	hc := &container.HostConfig{
		AutoRemove:     p.AutoRemove,
		Init:           &initTrue,
		ReadonlyRootfs: true,
		CapDrop:        strslice.StrSlice{"ALL"},
		SecurityOpt:    []string{"no-new-privileges", "seccomp=default"},
		Tmpfs:          p.Tmpfs,
	}
	if p.NetworkMode != "" {
		hc.NetworkMode = container.NetworkMode(p.NetworkMode)
	}
	res := container.Resources{
		NanoCPUs:   p.NanoCPUs,
		Memory:     p.MemoryBytes,
		MemorySwap: p.MemoryBytes, // == Memory disables swap
	}
	if p.PidsLimit != 0 {
		pl := p.PidsLimit
		res.PidsLimit = &pl
	}
	hc.Resources = res
	return hc
}
