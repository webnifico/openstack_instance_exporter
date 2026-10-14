package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
)

func TestLibvirtCooperativeAsyncJobsDeferAllReadersBetweenMonitorCommands(t *testing.T) {
	for _, job := range []string{"migration out", "migration in", "save", "dump", "snapshot", "backup", "start", "unknown-job"} {
		t.Run(job, func(t *testing.T) {
			c, dom, count := cooperativeFixture(t, "")
			safety := &libvirtReadSafety{runtimeStateDir: t.TempDir()}
			status := fmt.Sprintf(`<domstatus><job type="none" async="%s"/><domain><uuid>%s</uuid></domain></domstatus>`, job, validLibvirtDomainUUID(dom.UUID))
			path := filepath.Join(safety.runtimeStateDir, dom.Name+".xml")
			if err := os.WriteFile(path, []byte(status), 0600); err != nil {
				t.Fatal(err)
			}
			c.control = func(libvirt.Domain) (uint32, error) {
				t.Error("queried control despite active async marker")
				return 0, nil
			}
			deadline := time.Now().Add(time.Second)
			records, _, err := collectCooperativeDomainStats(c, safety, deadline)
			if err != nil || len(records) != 1 || count.Load() != 0 {
				t.Fatalf("async domain enriched: %v", err)
			}
			if _, err := guardedDomainXML(c, safety, dom, deadline); !errors.Is(err, errLibvirtReadDeferred) {
				t.Fatal(err)
			}
			if _, _, _, _, err := guardedBlockJobInfo(c, safety, dom, "vdb", deadline); !errors.Is(err, errLibvirtReadDeferred) {
				t.Fatal(err)
			}
			// libvirtd removes the job marker on completion; regular statistics
			// must resume without an exporter restart or manual state reset.
			idle := fmt.Sprintf(`<domstatus><domain><uuid>%s</uuid></domain></domstatus>`, validLibvirtDomainUUID(dom.UUID))
			if err := os.WriteFile(path, []byte(idle), 0600); err != nil {
				t.Fatal(err)
			}
			c.control = nil
			if _, _, err := collectCooperativeDomainStats(c, safety, deadline); err != nil {
				t.Fatal(err)
			}
			if count.Load() != 1 {
				t.Fatal("statistics did not recover after async job")
			}
		})
	}
}

func TestLibvirtCooperativeRuntimeStatusValidation(t *testing.T) {
	_, dom, _ := cooperativeFixture(t, "")
	uuid := validLibvirtDomainUUID(dom.UUID)
	for _, status := range []string{
		`<domstatus`,
		`<domain><uuid>` + uuid + `</uuid></domain>`,
		`<domstatus><domain><uuid>wrong</uuid></domain></domstatus>`,
		`<domstatus><job/><domain><uuid>` + uuid + `</uuid></domain></domstatus>`,
		`<domstatus><job type="destroy" async="none"/><domain><uuid>` + uuid + `</uuid></domain></domstatus>`,
	} {
		if err := checkLibvirtRuntimeJobXML([]byte(status), dom); !errors.Is(err, errLibvirtReadDeferred) {
			t.Errorf("invalid/active status accepted: %s: %v", status, err)
		}
	}
	for _, job := range []string{"", `<job type="none" async="none"/>`} {
		if err := checkLibvirtRuntimeJobXML([]byte(`<domstatus>`+job+`<domain><uuid>`+uuid+`</uuid></domain></domstatus>`), dom); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLibvirtCooperativeRuntimeFileSafetyAndMissingPath(t *testing.T) {
	_, dom, _ := cooperativeFixture(t, "")
	s := &libvirtReadSafety{runtimeStateDir: t.TempDir()}
	if err := s.checkRuntimeJob(dom); err != nil {
		t.Fatalf("missing optional local state disabled API collection: %v", err)
	}
	path := filepath.Join(s.runtimeStateDir, dom.Name+".xml")
	if err := os.Symlink("/dev/zero", path); err != nil {
		t.Fatal(err)
	}
	if err := s.checkRuntimeJob(dom); !errors.Is(err, errLibvirtReadDeferred) {
		t.Fatal("followed status symlink")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(9 << 20); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if err := s.checkRuntimeJob(dom); !errors.Is(err, errLibvirtReadDeferred) {
		t.Fatal("oversize status was accepted")
	}
	for _, name := range []string{"", "..", "../outside", "nested/name", "name\x00suffix"} {
		bad := dom
		bad.Name = name
		if err := s.checkRuntimeJob(bad); !errors.Is(err, errLibvirtReadDeferred) {
			t.Errorf("unsafe name accepted: %q", name)
		}
	}
}

func TestLibvirtCooperativeDaemonTimeoutAlsoStartsSharedBackoff(t *testing.T) {
	c, _, _ := cooperativeFixture(t, "")
	original := c.stats
	c.stats = func(d []libvirt.Domain, s, f uint32) ([]libvirt.DomainStatsRecord, error) {
		if len(d) == 0 {
			return original(d, s, f)
		}
		return nil, fmt.Errorf("server response: %w", libvirt.Error{Code: uint32(libvirt.ErrOperationTimeout), Message: "cannot acquire state change lock"})
	}
	s := &libvirtReadSafety{}
	if _, _, err := collectCooperativeDomainStats(c, s, time.Now().Add(time.Second)); err == nil || !strings.Contains(err.Error(), "state change lock") {
		t.Fatalf("lost server error: %v", err)
	}
	if err := s.available(time.Now()); !errors.Is(err, errLibvirtReadDeferred) {
		t.Fatalf("server-side timeout did not stop other readers: %v", err)
	}
}

func TestLibvirtCooperativeRuntimeBlockJobsDeferStorageStatsAndRecover(t *testing.T) {
	for _, marker := range []string{
		`<blockjobs><blockjob type="copy" state="new"/></blockjobs>`,
		`<blockjobs><blockjob type="copy" state="ready" newstate="ready" jobflags="0x2"/></blockjobs>`,
		`<blockjobs><blockjob type="commit" state="running"/></blockjobs>`,
		`<blockjobs><blockjob type="pull" state="running"/></blockjobs>`,
		`<blockjobs><blockjob type="backup" state="running"/></blockjobs>`,
		`<blockjobs><blockjob type="future-job" state="unknown"/></blockjobs>`,
		`<blockjobs><blockjob/></blockjobs>`,
		`<blockjobs active="yes"/>`,
		`<blockjobs active="future-state"/>`,
		`<blockjobs active="no"><blockjob type="copy" state="ready"/></blockjobs>`,
	} {
		t.Run(marker, func(t *testing.T) {
			c, dom, count := cooperativeFixture(t, "")
			safety := &libvirtReadSafety{runtimeStateDir: t.TempDir()}
			path := filepath.Join(safety.runtimeStateDir, dom.Name+".xml")
			status := fmt.Sprintf(`<domstatus>%s<domain><uuid>%s</uuid></domain></domstatus>`, marker, validLibvirtDomainUUID(dom.UUID))
			if err := os.WriteFile(path, []byte(status), 0600); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			records, metadata, err := collectCooperativeDomainStats(c, safety, deadline)
			if err != nil || len(records) != 1 || len(metadata) != 1 || count.Load() != 1 {
				t.Fatalf("runtime block job lost non-storage statistics: count=%d metadata=%d err=%v", count.Load(), len(metadata), err)
			}
			stats := parseLibvirtStats(records[0].Params)
			if !stats.CpuTimePresent || !stats.MemCurPresent || len(stats.Disks) != 1 || stats.Disks[0].CapacityPresent || stats.Disks[0].RdBytesPresent {
				t.Fatal("storage deferral lost CPU/memory or entered block statistics")
			}
			c.block = func(libvirt.Domain, string) (int32, int32, uint64, uint64, uint64, error) {
				return 1, 1, 0, 25, 100, nil
			}
			if _, _, current, total, err := guardedBlockJobInfo(c, safety, dom, "vdb", deadline); err != nil || current != 25 || total != 100 {
				t.Fatalf("lost lightweight progress observation: %d/%d %v", current, total, err)
			}
			idle := fmt.Sprintf(`<domstatus><blockjobs active="no"/><domain><uuid>%s</uuid></domain></domstatus>`, validLibvirtDomainUUID(dom.UUID))
			if err := os.WriteFile(path, []byte(idle), 0600); err != nil {
				t.Fatal(err)
			}
			recovered, _, err := collectCooperativeDomainStats(c, safety, deadline)
			if err != nil || len(recovered) != 1 || count.Load() != 2 {
				t.Fatalf("statistics did not resume: count=%d err=%v", count.Load(), err)
			}
			if disk := parseLibvirtStats(recovered[0].Params).Disks[0]; !disk.CapacityPresent || disk.Capacity != 1024 || !disk.RdBytesPresent || disk.RdBytes != 42 {
				t.Fatalf("block statistics did not recover: %+v", disk)
			}
		})
	}
}

func TestLibvirtCooperativeRuntimeMirrorAppearingAfterXMLDefersOnlyStorageStats(t *testing.T) {
	c, dom, count := cooperativeFixture(t, "")
	safety := &libvirtReadSafety{runtimeStateDir: t.TempDir()}
	originalXML := c.xml
	c.xml = func(d libvirt.Domain) (string, error) {
		status := fmt.Sprintf(`<domstatus><domain><uuid>%s</uuid><devices><disk><mirror job="copy" ready="yes"/></disk></devices></domain></domstatus>`, validLibvirtDomainUUID(dom.UUID))
		if err := os.WriteFile(filepath.Join(safety.runtimeStateDir, dom.Name+".xml"), []byte(status), 0600); err != nil {
			t.Fatal(err)
		}
		return originalXML(d)
	}
	records, _, err := collectCooperativeDomainStats(c, safety, time.Now().Add(time.Second))
	if err != nil || len(records) != 1 || count.Load() != 1 {
		t.Fatalf("storage job appearing after public XML lost non-storage statistics: %d %v", count.Load(), err)
	}
	stats := parseLibvirtStats(records[0].Params)
	if !stats.CpuTimePresent || !stats.MemCurPresent || len(stats.Disks) != 1 || stats.Disks[0].CapacityPresent || stats.Disks[0].RdBytesPresent {
		t.Fatal("late runtime mirror did not defer only storage statistics")
	}
}
