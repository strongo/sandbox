package isolation

import (
	"strings"
	"testing"
)

func TestPreset_HostConfigAppliesHardenedFlags(t *testing.T) {
	hc := Preset{
		NanoCPUs:    2_000_000_000,
		MemoryBytes: 1024 * 1024 * 1024,
		PidsLimit:   256,
		NetworkMode: "bridge",
		Tmpfs:       map[string]string{"/workspace": "rw,size=512m"},
		AutoRemove:  true,
	}.HostConfig()

	// Security flags must always be on regardless of the tunable knobs.
	if !hc.ReadonlyRootfs {
		t.Error("ReadonlyRootfs must be true")
	}
	if len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %v, want [ALL]", hc.CapDrop)
	}
	sec := map[string]bool{}
	for _, o := range hc.SecurityOpt {
		sec[o] = true
	}
	// seccomp is intentionally NOT set: the daemon applies its built-in default
	// profile when no seccomp opt is given ("seccomp=default" is unparseable).
	if !sec["no-new-privileges"] {
		t.Errorf("SecurityOpt = %v, want no-new-privileges", hc.SecurityOpt)
	}
	for _, o := range hc.SecurityOpt {
		if strings.HasPrefix(o, "seccomp=") {
			t.Errorf("seccomp opt must not be set explicitly: %q", o)
		}
	}
	if hc.Init == nil || !*hc.Init {
		t.Error("Init must be true")
	}

	// Tunable knobs threaded through.
	if hc.NanoCPUs != 2_000_000_000 {
		t.Errorf("NanoCPUs = %d", hc.NanoCPUs)
	}
	if hc.Memory != 1024*1024*1024 || hc.MemorySwap != hc.Memory {
		t.Errorf("Memory/MemorySwap = %d/%d (swap should equal mem)", hc.Memory, hc.MemorySwap)
	}
	if hc.PidsLimit == nil || *hc.PidsLimit != 256 {
		t.Errorf("PidsLimit = %v, want 256", hc.PidsLimit)
	}
	if string(hc.NetworkMode) != "bridge" {
		t.Errorf("NetworkMode = %q", hc.NetworkMode)
	}
	if !hc.AutoRemove {
		t.Error("AutoRemove should pass through")
	}
}

func TestPreset_ZeroPidsAndNetworkLeftUnset(t *testing.T) {
	hc := Preset{}.HostConfig()
	if hc.PidsLimit != nil {
		t.Errorf("PidsLimit = %v, want nil when zero", hc.PidsLimit)
	}
	if hc.NetworkMode != "" {
		t.Errorf("NetworkMode = %q, want empty when unset", hc.NetworkMode)
	}
	// Security flags still on even with an all-zero preset.
	if !hc.ReadonlyRootfs || len(hc.CapDrop) == 0 {
		t.Error("hardened flags must hold for zero-value preset")
	}
}

func TestNonRootUserConstant(t *testing.T) {
	if NonRootUser != "65532:65532" {
		t.Errorf("NonRootUser = %q, want 65532:65532", NonRootUser)
	}
}
