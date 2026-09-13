package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
)

const (
	libvirtStatsNowait = uint32(1 << 29)
	libvirtReadWorkers = 4
	libvirtReadBackoff = time.Minute
	libvirtReadLimit   = 8
)

var errLibvirtReadDeferred = errors.New("Libvirt observation deferred")

// A storage-only deferral still permits CPU, memory and interface statistics.
// Keep it distinguishable from an unreadable status file or an async job,
// which must continue to defer all monitor-dependent observations.
var errLibvirtStorageStatsDeferred = fmt.Errorf("%w: storage statistics", errLibvirtReadDeferred)

// A socket deadline bounds our wait, not a request already executing inside
// libvirtd. Share these guards across stats, XML, progress, and reconnects.
// Keep a raw request's slot until it exits and pause all readers after timeout.
type libvirtReadSafety struct {
	mu              sync.Mutex
	inflight        map[string]struct{}
	resumeAfter     time.Time
	runtimeStateDir string
}

func (s *libvirtReadSafety) available(now time.Time) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Before(s.resumeAfter) {
		return fmt.Errorf("%w: timeout backoff until %s", errLibvirtReadDeferred, s.resumeAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

func (s *libvirtReadSafety) pause(now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if until := now.Add(libvirtReadBackoff); until.After(s.resumeAfter) {
		s.resumeAfter = until
	}
}

func (s *libvirtReadSafety) begin(key string, deadline time.Time) (func(), error) {
	if !time.Now().Before(deadline) {
		return nil, fmt.Errorf("%w: deadline reached before request", errLibvirtReadDeferred)
	}
	if s == nil {
		return func() {}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Now().Before(s.resumeAfter) {
		return nil, fmt.Errorf("%w: timeout backoff", errLibvirtReadDeferred)
	}
	if _, exists := s.inflight[key]; exists {
		return nil, fmt.Errorf("%w: domain request still in flight", errLibvirtReadDeferred)
	}
	if len(s.inflight) >= libvirtReadLimit {
		return nil, fmt.Errorf("%w: reader capacity exhausted", errLibvirtReadDeferred)
	}
	if s.inflight == nil {
		s.inflight = make(map[string]struct{})
	}
	s.inflight[key] = struct{}{}
	return func() {
		s.mu.Lock()
		delete(s.inflight, key)
		s.mu.Unlock()
	}, nil
}

// Use only the documented read APIs. No QMP passthrough, direct monitor socket,
// image-opening helper, mutating operation, or blocking stats retry is allowed.
type libvirtObservationClient interface {
	ConnectGetAllDomainStats([]libvirt.Domain, uint32, uint32) ([]libvirt.DomainStatsRecord, error)
	DomainGetControlInfo(libvirt.Domain, uint32) (uint32, uint32, uint64, error)
	DomainGetXMLDesc(libvirt.Domain, libvirt.DomainXMLFlags) (string, error)
	DomainGetBlockJobInfo(libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error)
}

// GetControlInfo observes libvirtd's control state without issuing a QEMU
// monitor command. Defer XML/progress when the monitor is reported busy.
// NOWAIT additionally closes the check/acquire race for domain stats. Libvirt
// has no NOWAIT flag for XML or block-job progress, nor a cancellable monitor
// deadline; these checks cannot promise zero contention in upstream daemons.
func checkLibvirtDomainIdle(c libvirtObservationClient, s *libvirtReadSafety, dom libvirt.Domain, deadline time.Time) error {
	if err := s.available(time.Now()); err != nil {
		return err
	}
	if !time.Now().Before(deadline) {
		return fmt.Errorf("%w: deadline reached", errLibvirtReadDeferred)
	}
	if err := s.checkRuntimeJob(dom); err != nil {
		return err
	}
	state, _, _, err := c.DomainGetControlInfo(dom, 0)
	if err != nil {
		s.observeError(err)
		return fmt.Errorf("domain control observation: %w", err)
	}
	if state != uint32(libvirt.DomainControlOk) {
		return fmt.Errorf("%w: domain control state %d", errLibvirtReadDeferred, state)
	}
	if !time.Now().Before(deadline) {
		return fmt.Errorf("%w: deadline reached after control observation", errLibvirtReadDeferred)
	}
	return s.available(time.Now())
}

func guardedDomainXML(c libvirtObservationClient, s *libvirtReadSafety, dom libvirt.Domain, deadline time.Time) (string, error) {
	end, err := s.begin(volumeRetypeDomainKey(dom), deadline)
	if err != nil {
		return "", err
	}
	defer end()
	flags := libvirt.DomainXMLFlags(0)
	if dom.ID < 0 {
		// Read the persistent definition even if this domain starts after the
		// inventory snapshot. Inactive XML never requires live monitor data.
		flags = libvirt.DomainXMLInactive
	} else if err := checkLibvirtDomainIdle(c, s, dom, deadline); err != nil {
		return "", err
	}
	xml, err := c.DomainGetXMLDesc(dom, flags)
	s.observeError(err)
	return xml, err
}

func guardedBlockJobInfo(c libvirtObservationClient, s *libvirtReadSafety, dom libvirt.Domain, disk string, deadline time.Time) (int32, int32, uint64, uint64, error) {
	end, err := s.begin(volumeRetypeDomainKey(dom), deadline)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer end()
	if err := checkLibvirtDomainIdle(c, s, dom, deadline); err != nil {
		return 0, 0, 0, 0, err
	}
	found, typ, _, current, total, err := c.DomainGetBlockJobInfo(dom, disk, 0)
	s.observeError(err)
	return found, typ, current, total, err
}

func observeDomainForStats(c libvirtObservationClient, s *libvirtReadSafety, base libvirt.DomainStatsRecord, deadline time.Time) (libvirt.DomainStatsRecord, *DomainStatic, error) {
	dom := base.Dom
	if dom.ID < 0 {
		// Retained inactive definitions are inventory-only. Metadata preflight
		// uses their separate five-minute cache and guarded inactive XML.
		return base, nil, nil
	}
	end, err := s.begin(volumeRetypeDomainKey(dom), deadline)
	if err != nil {
		return base, nil, err
	}
	defer end()
	if err := checkLibvirtDomainIdle(c, s, dom, deadline); err != nil {
		return base, nil, err
	}
	desc, err := c.DomainGetXMLDesc(dom, 0)
	if err != nil {
		s.observeError(err)
		return base, nil, err
	}
	var live struct {
		UUID  string `xml:"uuid"`
		Disks []struct {
			Mirror *struct{} `xml:"mirror"`
		} `xml:"devices>disk"`
	}
	if err := xml.Unmarshal([]byte(desc), &live); err != nil {
		return base, nil, fmt.Errorf("domain observation XML: %w", err)
	}
	uuid := validLibvirtDomainUUID(dom.UUID)
	if uuid == "" || strings.TrimSpace(live.UUID) != uuid {
		return base, nil, fmt.Errorf("domain observation XML UUID does not match requested domain")
	}
	meta, err := parseDomainStaticFromXML(uuid, dom.Name, desc)
	if err != nil {
		return base, nil, err
	}
	storageDeferred := false
	for _, disk := range live.Disks {
		if disk.Mirror != nil {
			// Covers every mirror (copy, active commit, unknown job, local and
			// network disks), not just RBD retypes. Bulk stats can perform slow
			// storage-size probing while holding the monitor lock even with
			// NOWAIT. Exclude the block group for the entire VM, while still
			// requesting CPU, memory and interface statistics when idle.
			storageDeferred = true
			break
		}
	}
	if err := checkLibvirtDomainIdle(c, s, dom, deadline); err != nil {
		return domainStatsWithDiskIdentity(base, meta), meta, err
	}
	if err := s.checkRuntimeStatsJob(dom); err != nil {
		if !errors.Is(err, errLibvirtStorageStatsDeferred) {
			return domainStatsWithDiskIdentity(base, meta), meta, err
		}
		storageDeferred = true
	}
	if !time.Now().Before(deadline) {
		return domainStatsWithDiskIdentity(base, meta), meta, fmt.Errorf("%w: deadline reached after storage job observation", errLibvirtReadDeferred)
	}
	stats := uint32(_domainStatsState | _domainStatsCpuTotal | _domainStatsBalloon | _domainStatsVcpu | _domainStatsInterface)
	if !storageDeferred {
		stats |= uint32(_domainStatsBlock)
	}
	records, err := c.ConnectGetAllDomainStats([]libvirt.Domain{dom}, stats, libvirtStatsNowait)
	if err != nil {
		s.observeError(err)
		return base, meta, err
	}
	if len(records) != 1 || records[0].Dom.UUID != dom.UUID || records[0].Dom.ID != dom.ID {
		return base, meta, fmt.Errorf("domain identity changed during statistics observation")
	}
	if storageDeferred {
		// The non-block reply has no disk inventory. Retain identities from
		// this cycle's XML without manufacturing counters or capacity.
		return domainStatsWithDiskIdentity(records[0], meta), meta, nil
	}
	return records[0], meta, nil
}

func domainStatsWithDiskIdentity(base libvirt.DomainStatsRecord, meta *DomainStatic) libvirt.DomainStatsRecord {
	base.Params = append([]libvirt.TypedParam(nil), base.Params...)
	for i, disk := range meta.Disks {
		base.Params = append(base.Params, libvirt.TypedParam{Field: fmt.Sprintf("block.%d.name", i), Value: libvirt.TypedParamValue{D: 7, I: disk.TargetDev}})
	}
	base.Params = append(base.Params, libvirt.TypedParam{Field: "block.count", Value: libvirt.TypedParamValue{D: 2, I: uint32(len(meta.Disks))}})
	return base
}

func collectCooperativeDomainStats(c libvirtObservationClient, s *libvirtReadSafety, deadline time.Time) ([]libvirt.DomainStatsRecord, map[string]*DomainStatic, error) {
	collectionEnd, err := s.begin("collection", deadline)
	if err != nil {
		return nil, nil, err
	}
	defer collectionEnd()
	end, err := s.begin("inventory", deadline)
	if err != nil {
		return nil, nil, err
	}
	// Neither group enters the QEMU monitor. Keep inventory complete even
	// when some domains cannot safely provide dynamic resource statistics.
	records, err := c.ConnectGetAllDomainStats(nil, uint32(_domainStatsState|_domainStatsInterface), libvirtStatsNowait)
	end()
	if err != nil {
		s.observeError(err)
		return nil, nil, err
	}
	metadata := make(map[string]*DomainStatic, len(records))
	type result struct {
		index  int
		record libvirt.DomainStatsRecord
		meta   *DomainStatic
		err    error
	}
	jobs := make(chan int)
	done := make(chan result, len(records))
	var workers sync.WaitGroup
	for i := 0; i < min(libvirtReadWorkers, len(records)); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				record, meta, err := observeDomainForStats(c, s, records[index], deadline)
				done <- result{index, record, meta, err}
			}
		}()
	}
	for i := range records {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	close(done)
	var firstErr error
	for result := range done {
		if result.err != nil && !errors.Is(result.err, errLibvirtReadDeferred) {
			if firstErr == nil {
				firstErr = result.err
			}
			continue
		}
		records[result.index] = result.record
		if result.meta != nil {
			metadata[result.meta.InstanceUUID] = result.meta
		}
	}
	if firstErr != nil {
		return nil, nil, firstErr
	}
	return records, metadata, nil
}

func (s *libvirtReadSafety) observeError(err error) {
	if err == nil {
		return
	}
	var remote libvirt.Error
	if errors.As(err, &remote) && remote.Code == uint32(libvirt.ErrOperationTimeout) {
		s.pause(time.Now())
	}
}
