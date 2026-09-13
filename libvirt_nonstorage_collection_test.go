package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
)

func TestLibvirtCooperativeMirrorStillDefersOnLateBusyControl(t *testing.T) {
	c, _, count := cooperativeFixture(t, `<mirror job="copy"/>`)
	var checks atomic.Int32
	c.control = func(libvirt.Domain) (uint32, error) {
		if checks.Add(1) > 1 {
			return uint32(libvirt.DomainControlJob), nil
		}
		return uint32(libvirt.DomainControlOk), nil
	}
	records, metadata, err := collectCooperativeDomainStats(c, &libvirtReadSafety{}, time.Now().Add(time.Second))
	if err != nil || len(records) != 1 || len(metadata) != 1 || count.Load() != 0 || checks.Load() != 2 {
		t.Fatalf("non-storage path bypassed the second control check: calls=%d checks=%d err=%v", count.Load(), checks.Load(), err)
	}
	stats := parseLibvirtStats(records[0].Params)
	if stats.CpuTimePresent || stats.MemCurPresent || len(stats.Nets) != 1 || stats.Nets[0].RxBytes != 100 || len(stats.Disks) != 1 {
		t.Fatalf("busy mirror lost inventory/network or fabricated CPU/memory: %+v", stats)
	}
}

func TestLibvirtCooperativeMirrorNonStoragePartialReplyAndTimeout(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprintf("timeout=%t", timeout), func(t *testing.T) {
			c, dom, _ := cooperativeFixture(t, `<mirror job="copy" ready="yes"/>`)
			original := c.stats
			var reads atomic.Int32
			c.stats = func(d []libvirt.Domain, groups, flags uint32) ([]libvirt.DomainStatsRecord, error) {
				if len(d) == 0 {
					return original(d, groups, flags)
				}
				reads.Add(1)
				if len(d) != 1 || d[0] != dom || groups&uint32(_domainStatsBlock) != 0 || flags != libvirtStatsNowait {
					return nil, fmt.Errorf("unsafe mirror request: %v %#x %#x", d, groups, flags)
				}
				if timeout {
					return nil, libvirt.Error{Code: uint32(libvirt.ErrOperationTimeout), Message: "monitor timeout"}
				}
				// A competing client can acquire the job after the idle check.
				// NOWAIT may return only host-side interface/state fields.
				return original(nil, uint32(_domainStatsState|_domainStatsInterface), flags)
			}
			safety := &libvirtReadSafety{}
			records, _, err := collectCooperativeDomainStats(c, safety, time.Now().Add(time.Second))
			if reads.Load() != 1 {
				t.Fatalf("expected one non-storage attempt without retry: %d", reads.Load())
			}
			if timeout {
				var remote libvirt.Error
				if !errors.As(err, &remote) || remote.Code != uint32(libvirt.ErrOperationTimeout) {
					t.Fatalf("non-storage timeout was swallowed: %v", err)
				}
				if _, _, err := collectCooperativeDomainStats(c, safety, time.Now().Add(time.Second)); !errors.Is(err, errLibvirtReadDeferred) || reads.Load() != 1 {
					t.Fatalf("non-storage timeout bypassed shared backoff: %v", err)
				}
				return
			}
			if err != nil || len(records) != 1 {
				t.Fatalf("partial non-storage reply failed: %v", err)
			}
			stats := parseLibvirtStats(records[0].Params)
			if stats.CpuTimePresent || stats.MemCurPresent || len(stats.Disks) != 1 || stats.Disks[0].RdBytesPresent || len(stats.Nets) != 1 || stats.Nets[0].TxBytes != 200 {
				t.Fatalf("partial reply fabricated data or lost identities/network: %+v", stats)
			}
		})
	}
}

func TestLibvirtCooperativeLateInvalidStatusDoesNotBecomeStorageOnlyDeferral(t *testing.T) {
	for _, state := range []string{"malformed", "wrong UUID", "async with block job"} {
		t.Run(state, func(t *testing.T) {
			c, dom, count := cooperativeFixture(t, `<mirror job="copy"/>`)
			safety := &libvirtReadSafety{runtimeStateDir: t.TempDir()}
			path := filepath.Join(safety.runtimeStateDir, dom.Name+".xml")
			var checks atomic.Int32
			c.control = func(libvirt.Domain) (uint32, error) {
				// Simulate a saved-status change after the ordinary runtime
				// guard, but before the final storage-specific guard reads it.
				if checks.Add(1) == 2 {
					status := `<domstatus`
					switch state {
					case "wrong UUID":
						status = `<domstatus><blockjobs active="yes"/><domain><uuid>wrong</uuid></domain></domstatus>`
					case "async with block job":
						status = fmt.Sprintf(`<domstatus><job type="none" async="migration out"/><blockjobs active="yes"/><domain><uuid>%s</uuid></domain></domstatus>`, validLibvirtDomainUUID(dom.UUID))
					}
					if err := os.WriteFile(path, []byte(status), 0600); err != nil {
						return 0, err
					}
				}
				return uint32(libvirt.DomainControlOk), nil
			}
			records, _, err := collectCooperativeDomainStats(c, safety, time.Now().Add(time.Second))
			if err != nil || len(records) != 1 || count.Load() != 0 || checks.Load() != 2 {
				t.Fatalf("late invalid/async status allowed a resource request: calls=%d checks=%d err=%v", count.Load(), checks.Load(), err)
			}
			if stats := parseLibvirtStats(records[0].Params); stats.CpuTimePresent || stats.MemCurPresent {
				t.Fatal("invalid status was treated as a storage-only deferral")
			}
		})
	}
}
