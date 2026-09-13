package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	libvirt "github.com/digitalocean/go-libvirt"
)

// ControlInfo can report OK between monitor commands of an asynchronous job.
// When local libvirtd status is available, inspect its saved job marker without
// querying QEMU (DomainGetJobInfo itself would take the monitor job). This is
// an additional, read-only guard; nonstandard/missing state directories leave
// the public control API and mandatory NOWAIT checks in force.
func (s *libvirtReadSafety) checkRuntimeJob(dom libvirt.Domain) error {
	return s.checkRuntimeJobMode(dom, false)
}

// Block jobs do not necessarily create the top-level async job marker or a
// public disk mirror. Bulk statistics may probe every storage node, so defer
// the block group for any saved block job, including ready jobs awaiting their
// pivot. CPU/memory statistics and lightweight progress observation keep using
// the ordinary control guard.
func (s *libvirtReadSafety) checkRuntimeStatsJob(dom libvirt.Domain) error {
	return s.checkRuntimeJobMode(dom, true)
}

func (s *libvirtReadSafety) checkRuntimeJobMode(dom libvirt.Domain, storageStats bool) error {
	if s == nil || s.runtimeStateDir == "" {
		return nil
	}
	name := dom.Name
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00") {
		return fmt.Errorf("%w: unsafe domain name for local job observation", errLibvirtReadDeferred)
	}
	path := filepath.Join(s.runtimeStateDir, name+".xml")
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: local job status unavailable", errLibvirtReadDeferred)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	const maxStatusBytes = 8 << 20
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxStatusBytes {
		return fmt.Errorf("%w: invalid local job status file", errLibvirtReadDeferred)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStatusBytes+1))
	if err != nil || len(data) > maxStatusBytes {
		return fmt.Errorf("%w: incomplete local job status", errLibvirtReadDeferred)
	}
	return checkLibvirtRuntimeJobXMLMode(data, dom, storageStats)
}

func checkLibvirtRuntimeJobXML(data []byte, dom libvirt.Domain) error {
	return checkLibvirtRuntimeJobXMLMode(data, dom, false)
}

func checkLibvirtRuntimeJobXMLMode(data []byte, dom libvirt.Domain, storageStats bool) error {
	var status struct {
		XMLName xml.Name `xml:"domstatus"`
		UUID    string   `xml:"domain>uuid"`
		Job     *struct {
			Type  string `xml:"type,attr"`
			Async string `xml:"async,attr"`
		} `xml:"job"`
		BlockJobs *struct {
			Active string     `xml:"active,attr"`
			Jobs   []struct{} `xml:"blockjob"`
		} `xml:"blockjobs"`
		Disks []struct {
			Mirror *struct{} `xml:"mirror"`
		} `xml:"domain>devices>disk"`
	}
	if err := xml.Unmarshal(data, &status); err != nil {
		return fmt.Errorf("%w: invalid local job status XML", errLibvirtReadDeferred)
	}
	if uuid := validLibvirtDomainUUID(dom.UUID); uuid == "" || strings.TrimSpace(status.UUID) != uuid {
		return fmt.Errorf("%w: local job status UUID mismatch", errLibvirtReadDeferred)
	}
	if status.Job != nil {
		// Recognize the idle marker only. Every non-idle or unrecognized job
		// defers monitor work, including migration, save/dump and backup.
		if status.Job.Type != "none" || status.Job.Async != "none" {
			return fmt.Errorf("%w: local Libvirt job is active", errLibvirtReadDeferred)
		}
	}
	if storageStats {
		if jobs := status.BlockJobs; jobs != nil && (len(jobs.Jobs) != 0 || (jobs.Active != "" && jobs.Active != "no")) {
			return fmt.Errorf("%w: local Libvirt block job is active", errLibvirtStorageStatsDeferred)
		}
		for _, disk := range status.Disks {
			if disk.Mirror != nil {
				return fmt.Errorf("%w: local Libvirt storage mirror is active", errLibvirtStorageStatsDeferred)
			}
		}
	}
	return nil
}
