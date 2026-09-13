package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// Discovery is intentionally bounded because it requires domain XML reads.
	// Once discovered, active jobs use the much cheaper dedicated poll loop.
	volumeRetypeDiscoverySweep     = 30 * time.Second
	volumeRetypeDiscoveryMaxBatch  = 256
	volumeRetypeRPCWorkers         = 4
	volumeRetypeActivePollInterval = 5 * time.Second
	volumeRetypeBlockPollInterval  = 15 * time.Second
	volumeRetypeBlockErrorBackoff  = 30 * time.Second
	volumeRetypeReadyStalledAfter  = 10 * time.Minute
	volumeRetypeCompletionTTL      = time.Hour
	volumeRetypeCompletionMax      = 256

	volumeRetypeStatusActive       = 1
	volumeRetypeStatusSuccess      = 2
	volumeRetypeStatusUnsuccessful = 3
	volumeRetypeStatusUnknown      = 4
	volumeRetypeStatusReady        = 5
	volumeRetypeStatusReadyStalled = 6
)

type volumeRetypeCursorClass uint8

const (
	volumeRetypeCursorCollectionBlock volumeRetypeCursorClass = iota
	volumeRetypeCursorDiscoveryBlock
	volumeRetypeCursorCompletionXML
	volumeRetypeCursorDiscoveryXML
	volumeRetypeCursorActivePollBlock
	volumeRetypeCursorActivePollXML
	volumeRetypeCursorClassCount
)

type volumeRetypeKey struct {
	InstanceUUID string
	DiskPath     string
}

// Active jobs are indexed by their one possible live location (instance and
// disk). Recent terminal rows use the complete exported operation identity so
// a new retype on the same disk can coexist with the prior result.
type volumeRetypeCompletionKey struct {
	InstanceUUID    string
	DiskPath        string
	SourceName      string
	DestinationName string
}

type volumeRetypeJob struct {
	Domain                libvirt.Domain
	DomainName            string
	ServerName            string
	InstanceUUID          string
	ProjectUUID           string
	ProjectName           string
	UserUUID              string
	VolumeUUID            string
	DiskType              string
	DiskPath              string
	DestinationVolumeUUID string
	DestinationDiskType   string
	SourceName            string
	DestinationName       string
	Ready                 bool
	ReadyObservedAt       time.Time
	ProgressPercent       float64
	ProgressAvailable     bool
	ObservationAttempted  bool
	ObservationHealthy    bool
	NextBlockPollAt       time.Time
	ObservedStartAt       time.Time
	ConfirmedAt           time.Time
}

type volumeRetypeCompletion struct {
	Job         volumeRetypeJob
	Result      string
	CompletedAt time.Time
}

type volumeRetypeResultCounters struct {
	Success      uint64
	Unsuccessful uint64
	Unknown      uint64
}

// volumeRetypeMetricState is an immutable scrape snapshot. Lifecycle rows and
// their process-local result counters must be copied while holding the same
// lock so one scrape cannot combine rows from one lifecycle transition with
// counters from another.
type volumeRetypeMetricState struct {
	Jobs      map[volumeRetypeKey]volumeRetypeJob
	Completed map[volumeRetypeCompletionKey]volumeRetypeCompletion
	Results   volumeRetypeResultCounters
}

type volumeRetypeCandidate struct {
	DiskPath              string
	VolumeUUID            string
	DiskType              string
	DestinationVolumeUUID string
	DestinationDiskType   string
	SourceName            string
	DestinationName       string
	Ready                 bool
}

type volumeRetypeXMLState struct {
	Sources    map[string]string
	CopyJobs   map[string]struct{}
	Candidates map[string]volumeRetypeCandidate
}

type volumeRetypeXMLResult struct {
	State      volumeRetypeXMLState
	RPCStarted bool
	Err        error
}

type volumeRetypeBlockRequest struct {
	Key      volumeRetypeKey
	Domain   libvirt.Domain
	DiskPath string
}

type volumeRetypeBlockResult struct {
	Found      bool
	JobType    int32
	Current    uint64
	End        uint64
	RPCStarted bool
	Err        error
}

func volumeRetypeOperationMatchesCandidate(job volumeRetypeJob, candidate volumeRetypeCandidate) bool {
	return job.SourceName == candidate.SourceName &&
		job.DestinationName == candidate.DestinationName
}

func volumeRetypeCompletionKeyForJob(job volumeRetypeJob) volumeRetypeCompletionKey {
	instanceUUID := job.InstanceUUID
	if instanceUUID == "" {
		instanceUUID = validLibvirtDomainUUID(job.Domain.UUID)
	}
	return volumeRetypeCompletionKey{
		InstanceUUID:    instanceUUID,
		DiskPath:        job.DiskPath,
		SourceName:      job.SourceName,
		DestinationName: job.DestinationName,
	}
}

var (
	errVolumeRetypeRPCAlreadyInFlight = errors.New("Libvirt block-job RPC already in flight for domain")
	errVolumeRetypeRPCCapacity        = errors.New("Libvirt block-job RPC capacity exhausted")
)

func volumeRetypeDomainKey(domain libvirt.Domain) string {
	if uuid := validLibvirtDomainUUID(domain.UUID); uuid != "" {
		return uuid
	}
	return strings.TrimSpace(domain.Name)
}

func (mc *MetricsCollector) beginVolumeRetypeBlockRPC(domain libvirt.Domain) error {
	key := volumeRetypeDomainKey(domain)
	if key == "" {
		return fmt.Errorf("Libvirt block-job RPC domain identity is empty")
	}
	mc.volumeRetypeRPCMu.Lock()
	defer mc.volumeRetypeRPCMu.Unlock()
	if mc.volumeRetypeRPCInflight == nil {
		mc.volumeRetypeRPCInflight = make(map[string]struct{})
	}
	if _, exists := mc.volumeRetypeRPCInflight[key]; exists {
		return errVolumeRetypeRPCAlreadyInFlight
	}
	// This map is cleared only after the underlying RPC goroutine exits. The
	// bound therefore remains effective even when a caller has already timed
	// out and returned, preventing abandoned calls from accumulating.
	if len(mc.volumeRetypeRPCInflight) >= volumeRetypeRPCWorkers {
		return errVolumeRetypeRPCCapacity
	}
	mc.volumeRetypeRPCInflight[key] = struct{}{}
	return nil
}

func (mc *MetricsCollector) endVolumeRetypeBlockRPC(domain libvirt.Domain) {
	key := volumeRetypeDomainKey(domain)
	if key == "" {
		return
	}
	mc.volumeRetypeRPCMu.Lock()
	delete(mc.volumeRetypeRPCInflight, key)
	mc.volumeRetypeRPCMu.Unlock()
}

func isCanonicalUUID(value string) bool {
	parts := strings.Split(value, "-")
	lengths := [...]int{8, 4, 4, 4, 12}
	if len(parts) != len(lengths) {
		return false
	}
	for index, part := range parts {
		if len(part) != lengths[index] {
			return false
		}
		for _, character := range part {
			if !((character >= '0' && character <= '9') ||
				(character >= 'a' && character <= 'f') ||
				(character >= 'A' && character <= 'F')) {
				return false
			}
		}
	}
	return true
}

func cinderRBDSourceIdentity(source DiskSource) (diskType, volumeUUID, sourceName string, ok bool) {
	if !strings.EqualFold(strings.TrimSpace(source.Protocol), "rbd") {
		return "", "", "", false
	}
	name := strings.TrimSpace(source.Name)
	pool, image, found := strings.Cut(name, "/")
	pool = strings.TrimSpace(pool)
	image = strings.TrimSpace(image)
	if !found || pool == "" || image == "" || strings.Contains(image, "/") {
		return "", "", "", false
	}
	const prefix = "volume-"
	if !strings.HasPrefix(image, prefix) || !isCanonicalUUID(strings.TrimPrefix(image, prefix)) {
		return "", "", "", false
	}
	return pool, image, pool + "/" + image, true
}

func parseVolumeRetypeXML(xmlDescription string) (volumeRetypeXMLState, error) {
	var domainXML struct {
		XMLName xml.Name `xml:"domain"`
		DomainXML
	}
	if err := xml.Unmarshal([]byte(xmlDescription), &domainXML); err != nil {
		return volumeRetypeXMLState{}, fmt.Errorf("parse volume retype domain XML: %w", err)
	}

	state := volumeRetypeXMLState{
		Sources:    make(map[string]string),
		CopyJobs:   make(map[string]struct{}),
		Candidates: make(map[string]volumeRetypeCandidate),
	}
	for _, disk := range domainXML.Devices.Disks {
		if disk.Device != "disk" {
			continue
		}
		diskPath := strings.TrimSpace(disk.Target.Dev)
		if diskPath == "" {
			continue
		}
		_, _, currentName, currentOK := cinderRBDSourceIdentity(disk.Source)
		if currentOK {
			state.Sources[diskPath] = currentName
		}
		if !strings.EqualFold(strings.TrimSpace(disk.Mirror.Job), "copy") {
			continue
		}
		// Track copy-job presence independently from whether its source and
		// destination can be identified as Cinder RBD images. For an already
		// known operation, an incomplete or unsupported mirror identity is not
		// proof that the mirror disappeared and must never synthesize a terminal
		// outcome.
		state.CopyJobs[diskPath] = struct{}{}
		diskType, volumeUUID, sourceName, sourceOK := cinderRBDSourceIdentity(disk.Source)
		destinationDiskType, destinationVolumeUUID, destinationName, destinationOK := cinderRBDSourceIdentity(disk.Mirror.Source)
		if !sourceOK || !destinationOK || sourceName == destinationName {
			continue
		}
		state.Candidates[diskPath] = volumeRetypeCandidate{
			DiskPath:              diskPath,
			VolumeUUID:            volumeUUID,
			DiskType:              diskType,
			DestinationVolumeUUID: destinationVolumeUUID,
			DestinationDiskType:   destinationDiskType,
			SourceName:            sourceName,
			DestinationName:       destinationName,
			Ready:                 strings.EqualFold(strings.TrimSpace(disk.Mirror.Ready), "yes"),
		}
	}
	return state, nil
}

func volumeRetypeProgress(current, end uint64) (float64, bool) {
	// Libvirt documents end=1 as a sentinel for block jobs without a usable
	// byte total. Such jobs remain active but do not publish a false percentage.
	if end <= 1 {
		return 0, false
	}
	progress := 100 * float64(current) / float64(end)
	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}
	return progress, true
}

func volumeRetypeJobFromCandidate(
	domain libvirt.Domain,
	meta *DomainStatic,
	candidate volumeRetypeCandidate,
	now time.Time,
) volumeRetypeJob {
	job := volumeRetypeJob{
		Domain:                domain,
		DomainName:            strings.TrimSpace(domain.Name),
		DiskPath:              candidate.DiskPath,
		VolumeUUID:            candidate.VolumeUUID,
		DiskType:              candidate.DiskType,
		DestinationVolumeUUID: candidate.DestinationVolumeUUID,
		DestinationDiskType:   candidate.DestinationDiskType,
		SourceName:            candidate.SourceName,
		DestinationName:       candidate.DestinationName,
		Ready:                 candidate.Ready,
		ObservedStartAt:       now,
		ConfirmedAt:           now,
	}
	if job.Ready {
		job.ReadyObservedAt = now
		job.ProgressPercent = 100
		job.ProgressAvailable = true
	}
	return updateVolumeRetypeJobMetadata(job, meta, domain)
}

func refreshVolumeRetypeJobFromCandidate(
	previous volumeRetypeJob,
	domain libvirt.Domain,
	meta *DomainStatic,
	candidate volumeRetypeCandidate,
	now time.Time,
) volumeRetypeJob {
	updated := volumeRetypeJobFromCandidate(domain, meta, candidate, now)
	if !volumeRetypeOperationMatchesCandidate(previous, candidate) {
		return updated
	}
	if !previous.ObservedStartAt.IsZero() {
		updated.ObservedStartAt = previous.ObservedStartAt
	}
	// This is the first observed ready timestamp for this operation. Libvirt
	// changes ready="yes" to "pivot" or "abort" during finalization; retain the
	// history even while the current ready flag is no longer "yes".
	if !previous.ReadyObservedAt.IsZero() {
		updated.ReadyObservedAt = previous.ReadyObservedAt
	}
	if meta == nil {
		updated.ServerName = previous.ServerName
		updated.InstanceUUID = previous.InstanceUUID
		updated.ProjectUUID = previous.ProjectUUID
		updated.ProjectName = previous.ProjectName
		updated.UserUUID = previous.UserUUID
	}
	updated.ProgressPercent = previous.ProgressPercent
	updated.ProgressAvailable = previous.ProgressAvailable
	updated.ObservationAttempted = previous.ObservationAttempted
	updated.ObservationHealthy = previous.ObservationHealthy
	updated.NextBlockPollAt = previous.NextBlockPollAt
	if updated.Ready {
		updated.ProgressPercent = 100
		updated.ProgressAvailable = true
	}
	return updated
}

func volumeRetypeBlockPollDue(job volumeRetypeJob, now time.Time) bool {
	return job.NextBlockPollAt.IsZero() || !now.Before(job.NextBlockPollAt)
}

func applyVolumeRetypeBlockResult(
	job volumeRetypeJob,
	result volumeRetypeBlockResult,
	now time.Time,
) volumeRetypeJob {
	job.ObservationAttempted = true
	job.ObservationHealthy = result.Err == nil
	if result.Err != nil {
		if !job.Ready {
			job.ProgressAvailable = false
		}
		job.NextBlockPollAt = now.Add(volumeRetypeBlockErrorBackoff)
		return job
	}
	job.NextBlockPollAt = now.Add(volumeRetypeBlockPollInterval)
	if result.Found && result.JobType == int32(libvirt.DomainBlockJobTypeCopy) {
		if job.Ready {
			// A ready mirror independently proves logical copy completion, even
			// when block-info has only the cur=end=1 sentinel for an empty copy.
			job.ProgressPercent, job.ProgressAvailable = 100, true
		} else {
			job.ProgressPercent, job.ProgressAvailable = volumeRetypeProgress(result.Current, result.End)
		}
	} else {
		job.ProgressAvailable = false
	}
	return job
}

func markVolumeRetypeObservationUnavailable(job volumeRetypeJob, now time.Time) volumeRetypeJob {
	job.ObservationAttempted = true
	job.ObservationHealthy = false
	if !job.Ready {
		job.ProgressAvailable = false
	}
	if job.NextBlockPollAt.IsZero() || !job.NextBlockPollAt.After(now) {
		job.NextBlockPollAt = now.Add(volumeRetypeBlockErrorBackoff)
	}
	return job
}

func updateVolumeRetypeJobMetadata(job volumeRetypeJob, meta *DomainStatic, domain libvirt.Domain) volumeRetypeJob {
	job.Domain = domain
	job.DomainName = strings.TrimSpace(domain.Name)
	if meta == nil {
		return job
	}
	job.ServerName = strings.TrimSpace(meta.Name)
	job.InstanceUUID = meta.InstanceUUID
	job.ProjectUUID = meta.ProjectUUID
	job.ProjectName = meta.ProjectName
	job.UserUUID = meta.UserUUID
	return job
}

func (mc *MetricsCollector) volumeRetypeCycleBudget() time.Duration {
	budget := mc.effectiveLibvirtRPCTimeout()
	halfInterval := mc.effectiveCollectionInterval() / 2
	if halfInterval > 0 && halfInterval < budget {
		budget = halfInterval
	}
	if budget < 250*time.Millisecond {
		budget = 250 * time.Millisecond
	}
	return budget
}

func (mc *MetricsCollector) takeVolumeRetypeDiscoveryDomains(domainStats []libvirt.DomainStatsRecord) []libvirt.Domain {
	if len(domainStats) == 0 {
		mc.volumeRetypeMu.Lock()
		mc.volumeRetypeDiscoveryCursor = 0
		mc.volumeRetypeMu.Unlock()
		return nil
	}
	domains := make([]libvirt.Domain, 0, len(domainStats))
	for _, record := range domainStats {
		if validLibvirtDomainUUID(record.Dom.UUID) != "" {
			domains = append(domains, record.Dom)
		}
	}
	sort.Slice(domains, func(left, right int) bool {
		leftUUID := validLibvirtDomainUUID(domains[left].UUID)
		rightUUID := validLibvirtDomainUUID(domains[right].UUID)
		if leftUUID != rightUUID {
			return leftUUID < rightUUID
		}
		return domains[left].Name < domains[right].Name
	})
	if len(domains) == 0 {
		return nil
	}

	interval := mc.effectiveCollectionInterval()
	cyclesPerSweep := int((volumeRetypeDiscoverySweep + interval - 1) / interval)
	if cyclesPerSweep < 1 {
		cyclesPerSweep = 1
	}
	batchSize := (len(domains) + cyclesPerSweep - 1) / cyclesPerSweep
	if batchSize < 1 {
		batchSize = 1
	}
	if batchSize > volumeRetypeDiscoveryMaxBatch {
		batchSize = volumeRetypeDiscoveryMaxBatch
	}

	mc.volumeRetypeMu.Lock()
	start := mc.volumeRetypeDiscoveryCursor % len(domains)
	mc.volumeRetypeDiscoveryCursor = (start + batchSize) % len(domains)
	mc.volumeRetypeMu.Unlock()

	selected := make([]libvirt.Domain, 0, batchSize)
	for offset := 0; offset < batchSize; offset++ {
		selected = append(selected, domains[(start+offset)%len(domains)])
	}
	return selected
}

func (mc *MetricsCollector) readVolumeRetypeBlockJob(
	conn *libvirt.Libvirt,
	domain libvirt.Domain,
	diskPath string,
	deadline time.Time,
) volumeRetypeBlockResult {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return volumeRetypeBlockResult{Err: &libvirtRPCTimeoutError{
			Operation: "Libvirt block-job RPC",
			Detail:    "deadline exceeded",
		}}
	}
	if err := mc.beginVolumeRetypeBlockRPC(domain); err != nil {
		return volumeRetypeBlockResult{Err: err}
	}
	// Acquiring the global/per-domain guard and being scheduled can consume the
	// shared cycle budget. Do not start a Libvirt call after its absolute
	// deadline; no goroutine owns the guard yet, so release it here.
	remaining = time.Until(deadline)
	if remaining <= 0 {
		mc.endVolumeRetypeBlockRPC(domain)
		return volumeRetypeBlockResult{Err: &libvirtRPCTimeoutError{
			Operation: "Libvirt block-job RPC",
			Detail:    "deadline exceeded before RPC start",
		}}
	}
	type rpcResult struct {
		found   int32
		jobType int32
		current uint64
		end     uint64
		err     error
	}
	resultCh := make(chan rpcResult, 1)
	go func() {
		result := func() rpcResult {
			defer mc.endVolumeRetypeBlockRPC(domain)
			var found, jobType int32
			var current, end uint64
			var err error
			if mc.libvirtBlockJobRPCOverride != nil {
				found, jobType, _, current, end, err = mc.libvirtBlockJobRPCOverride(conn, domain, diskPath, 0)
			} else if conn == nil {
				err = fmt.Errorf("Libvirt connection is nil")
			} else {
				found, jobType, current, end, err = guardedBlockJobInfo(conn, mc.libvirtSafety, domain, diskPath, deadline)
			}
			return rpcResult{found: found, jobType: jobType, current: current, end: end, err: err}
		}()
		// Release the in-flight guard before publishing the result. The domain
		// worker may issue its next serialized disk query immediately after the
		// receive completes.
		resultCh <- result
	}()

	// Measure the timer from the absolute shared deadline rather than from the
	// earlier entry timestamp. If setup exhausted the budget, the underlying
	// goroutine retains the in-flight guard until it exits.
	remaining = time.Until(deadline)
	if remaining <= 0 {
		mc.libvirtSafety.pause(time.Now())
		mc.abortLibvirtConnection(conn)
		return volumeRetypeBlockResult{Err: &libvirtRPCTimeoutError{
			Operation:  "Libvirt block-job RPC",
			RPCStarted: true,
			Detail:     "deadline exceeded",
		}, RPCStarted: true}
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		return volumeRetypeBlockResult{
			Found:      result.found != 0,
			JobType:    result.jobType,
			Current:    result.current,
			End:        result.end,
			RPCStarted: true,
			Err:        result.err,
		}
	case <-timer.C:
		mc.libvirtSafety.pause(time.Now())
		mc.abortLibvirtConnection(conn)
		return volumeRetypeBlockResult{Err: &libvirtRPCTimeoutError{
			Operation:  "Libvirt block-job RPC",
			Wait:       remaining,
			RPCStarted: true,
		}, RPCStarted: true}
	}
}

func volumeRetypeWorkerCount(items int) int {
	if items <= 0 {
		return 0
	}
	if items < volumeRetypeRPCWorkers {
		return items
	}
	return volumeRetypeRPCWorkers
}

func (mc *MetricsCollector) rotateVolumeRetypeRPCOrder(
	ordered []string,
	cursorClass volumeRetypeCursorClass,
) ([]string, int) {
	if len(ordered) < 2 {
		return ordered, 0
	}
	mc.volumeRetypeRPCMu.Lock()
	start := mc.volumeRetypeRPCCursors[cursorClass] % len(ordered)
	mc.volumeRetypeRPCMu.Unlock()

	rotated := make([]string, 0, len(ordered))
	rotated = append(rotated, ordered[start:]...)
	rotated = append(rotated, ordered[:start]...)
	return rotated, start
}

func (mc *MetricsCollector) advanceVolumeRetypeRPCCursor(
	itemCount int,
	observedStart int,
	advance int,
	cursorClass volumeRetypeCursorClass,
) {
	if itemCount < 2 || advance <= 0 {
		return
	}
	mc.volumeRetypeRPCMu.Lock()
	cursor := &mc.volumeRetypeRPCCursors[cursorClass]
	current := *cursor % itemCount
	// Lifecycle polls are serialized in production. Retain this comparison so
	// direct concurrent callers cannot advance a generation they did not read.
	if current == observedStart {
		*cursor = (observedStart + advance) % itemCount
	}
	mc.volumeRetypeRPCMu.Unlock()
}

// volumeRetypeRPCStartedAdvance returns the amount by which a round-robin
// cursor should move after one bounded RPC pass. Ordinarily this is the
// contiguous prefix of calls that started. A domain can, however, already have
// a timed-out raw call in flight while later domains still use the remaining
// global capacity. In that case, begin at the first call that really started
// and advance through its contiguous run. This moves the blocked head behind
// later work without treating a completely capacity-starved pass as progress.
func volumeRetypeRPCStartedAdvance(ordered []string, started map[string]bool) int {
	firstStarted := -1
	for index, key := range ordered {
		if started[key] {
			firstStarted = index
			break
		}
	}
	if firstStarted < 0 {
		return 0
	}

	advance := firstStarted + 1
	for index := firstStarted + 1; index < len(ordered); index++ {
		if !started[ordered[index]] {
			break
		}
		advance = index + 1
	}
	return advance
}

func (mc *MetricsCollector) rotateVolumeRetypeDomainDisks(
	domainKey string,
	requests []volumeRetypeBlockRequest,
) ([]volumeRetypeBlockRequest, int) {
	if len(requests) < 2 {
		return requests, 0
	}
	mc.volumeRetypeRPCMu.Lock()
	if mc.volumeRetypeDiskCursors == nil {
		mc.volumeRetypeDiskCursors = make(map[string]int)
	}
	start := mc.volumeRetypeDiskCursors[domainKey] % len(requests)
	mc.volumeRetypeRPCMu.Unlock()

	rotated := make([]volumeRetypeBlockRequest, 0, len(requests))
	rotated = append(rotated, requests[start:]...)
	rotated = append(rotated, requests[:start]...)
	return rotated, start
}

func (mc *MetricsCollector) advanceVolumeRetypeDomainDiskCursor(
	domainKey string,
	requestCount int,
	observedStart int,
) {
	if requestCount < 2 {
		return
	}
	mc.volumeRetypeRPCMu.Lock()
	if mc.volumeRetypeDiskCursors == nil {
		mc.volumeRetypeDiskCursors = make(map[string]int)
	}
	current := mc.volumeRetypeDiskCursors[domainKey] % requestCount
	// Production lifecycle polls are serialized, but avoid a double advance if
	// a direct concurrent caller has already moved this domain's cursor.
	if current == observedStart {
		mc.volumeRetypeDiskCursors[domainKey] = (observedStart + 1) % requestCount
	}
	mc.volumeRetypeRPCMu.Unlock()
}

func (mc *MetricsCollector) pruneVolumeRetypeDiskCursors(jobs map[volumeRetypeKey]volumeRetypeJob) {
	jobCounts := make(map[string]int)
	for key, job := range jobs {
		domainKey := volumeRetypeDomainKey(job.Domain)
		if domainKey == "" {
			domainKey = key.InstanceUUID
		}
		jobCounts[domainKey]++
	}

	mc.volumeRetypeRPCMu.Lock()
	for domainKey := range mc.volumeRetypeDiskCursors {
		if jobCounts[domainKey] < 2 {
			delete(mc.volumeRetypeDiskCursors, domainKey)
		}
	}
	mc.volumeRetypeRPCMu.Unlock()
}

func (mc *MetricsCollector) queryVolumeRetypeBlockJobs(
	conn *libvirt.Libvirt,
	requests []volumeRetypeBlockRequest,
	deadline time.Time,
	cursorClass volumeRetypeCursorClass,
) map[volumeRetypeKey]volumeRetypeBlockResult {
	results := make(map[volumeRetypeKey]volumeRetypeBlockResult, len(requests))
	if len(requests) == 0 {
		return results
	}
	type domainRequestGroup struct {
		domainKey string
		requests  []volumeRetypeBlockRequest
	}
	type keyedResult struct {
		key       volumeRetypeKey
		domainKey string
		result    volumeRetypeBlockResult
	}
	grouped := make(map[string][]volumeRetypeBlockRequest)
	groupOrder := make([]string, 0)
	for _, request := range requests {
		key := volumeRetypeDomainKey(request.Domain)
		if _, exists := grouped[key]; !exists {
			groupOrder = append(groupOrder, key)
		}
		grouped[key] = append(grouped[key], request)
	}
	for domainKey, domainRequests := range grouped {
		sort.Slice(domainRequests, func(left, right int) bool {
			if domainRequests[left].DiskPath != domainRequests[right].DiskPath {
				return domainRequests[left].DiskPath < domainRequests[right].DiskPath
			}
			if domainRequests[left].Key.InstanceUUID != domainRequests[right].Key.InstanceUUID {
				return domainRequests[left].Key.InstanceUUID < domainRequests[right].Key.InstanceUUID
			}
			return domainRequests[left].Key.DiskPath < domainRequests[right].Key.DiskPath
		})
		grouped[domainKey] = domainRequests
	}
	sort.Strings(groupOrder)
	groupOrder, groupStart := mc.rotateVolumeRetypeRPCOrder(groupOrder, cursorClass)
	jobs := make(chan domainRequestGroup, len(groupOrder))
	completed := make(chan keyedResult, len(requests))
	var workers sync.WaitGroup
	for worker := 0; worker < volumeRetypeWorkerCount(len(groupOrder)); worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for group := range jobs {
				ordered, start := mc.rotateVolumeRetypeDomainDisks(group.domainKey, group.requests)
				cursorAdvanced := false
				for _, request := range ordered {
					result := mc.readVolumeRetypeBlockJob(conn, request.Domain, request.DiskPath, deadline)
					if result.RPCStarted && !cursorAdvanced {
						mc.advanceVolumeRetypeDomainDiskCursor(group.domainKey, len(ordered), start)
						cursorAdvanced = true
					}
					completed <- keyedResult{
						key:       request.Key,
						domainKey: group.domainKey,
						result:    result,
					}
				}
			}
		}()
	}
	for _, key := range groupOrder {
		jobs <- domainRequestGroup{domainKey: key, requests: grouped[key]}
	}
	close(jobs)
	workers.Wait()
	close(completed)
	startedDomains := make(map[string]bool, len(groupOrder))
	for result := range completed {
		results[result.key] = result.result
		startedDomains[result.domainKey] = startedDomains[result.domainKey] || result.result.RPCStarted
	}
	startedAdvance := volumeRetypeRPCStartedAdvance(groupOrder, startedDomains)
	mc.advanceVolumeRetypeRPCCursor(len(groupOrder), groupStart, startedAdvance, cursorClass)
	return results
}

func (mc *MetricsCollector) fetchVolumeRetypeXML(
	conn *libvirt.Libvirt,
	domains map[string]libvirt.Domain,
	deadline time.Time,
	cursorClass volumeRetypeCursorClass,
) map[string]volumeRetypeXMLResult {
	results := make(map[string]volumeRetypeXMLResult, len(domains))
	if len(domains) == 0 {
		return results
	}
	type request struct {
		uuid   string
		domain libvirt.Domain
	}
	type keyedResult struct {
		uuid   string
		result volumeRetypeXMLResult
	}
	jobs := make(chan request, len(domains))
	completed := make(chan keyedResult, len(domains))
	var workers sync.WaitGroup
	for worker := 0; worker < volumeRetypeWorkerCount(len(domains)); worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				xmlDescription, rpcStarted, err := mc.im.readDomainXMLDescWithRPCState(item.domain, conn, deadline)
				if err == nil {
					var state volumeRetypeXMLState
					state, err = parseVolumeRetypeXML(xmlDescription)
					completed <- keyedResult{uuid: item.uuid, result: volumeRetypeXMLResult{State: state, RPCStarted: rpcStarted, Err: err}}
					continue
				}
				var timeoutErr *libvirtRPCTimeoutError
				if errors.As(err, &timeoutErr) && timeoutErr.RPCStarted {
					mc.abortLibvirtConnection(conn)
				}
				completed <- keyedResult{uuid: item.uuid, result: volumeRetypeXMLResult{RPCStarted: rpcStarted, Err: err}}
			}
		}()
	}
	orderedUUIDs := make([]string, 0, len(domains))
	for uuid := range domains {
		orderedUUIDs = append(orderedUUIDs, uuid)
	}
	sort.Strings(orderedUUIDs)
	orderedUUIDs, xmlStart := mc.rotateVolumeRetypeRPCOrder(orderedUUIDs, cursorClass)
	for _, uuid := range orderedUUIDs {
		jobs <- request{uuid: uuid, domain: domains[uuid]}
	}
	close(jobs)
	workers.Wait()
	close(completed)
	for result := range completed {
		results[result.uuid] = result.result
	}
	startedDomains := make(map[string]bool, len(orderedUUIDs))
	for uuid, result := range results {
		startedDomains[uuid] = result.RPCStarted
	}
	startedAdvance := volumeRetypeRPCStartedAdvance(orderedUUIDs, startedDomains)
	mc.advanceVolumeRetypeRPCCursor(len(orderedUUIDs), xmlStart, startedAdvance, cursorClass)
	return results
}

func addVolumeRetypeResult(counters *volumeRetypeResultCounters, result string) {
	switch result {
	case "success":
		counters.Success++
	case "unsuccessful":
		counters.Unsuccessful++
	default:
		counters.Unknown++
	}
}

func volumeRetypeStatusCode(result string) float64 {
	switch result {
	case "success":
		return volumeRetypeStatusSuccess
	case "unsuccessful":
		return volumeRetypeStatusUnsuccessful
	default:
		return volumeRetypeStatusUnknown
	}
}

func volumeRetypeActiveMaxAge(collectionInterval time.Duration) time.Duration {
	maxAge := 2 * volumeRetypeDiscoverySweep
	if intervalAge := 4 * collectionInterval; intervalAge > maxAge {
		maxAge = intervalAge
	}
	return maxAge
}

// Tests may drive the lifecycle with a synthetic future clock. Production
// callers use the wall clock, and slow RPC work must never schedule the next
// poll or freshness deadline from a timestamp captured before that work.
func volumeRetypeObservationTime(reference time.Time) time.Time {
	observed := time.Now()
	if reference.After(observed) {
		return reference
	}
	return observed
}

func evictUnconfirmedVolumeRetype(
	jobs map[volumeRetypeKey]volumeRetypeJob,
	key volumeRetypeKey,
) {
	// Loss of telemetry is not a terminal Cinder outcome. Remove the stale
	// active identity without publishing a completion or incrementing a result
	// counter; a later rediscovery begins a fresh observation.
	delete(jobs, key)
}

func pruneVolumeRetypeCompletions(
	completed map[volumeRetypeCompletionKey]volumeRetypeCompletion,
	now time.Time,
) {
	for key, completion := range completed {
		if completion.CompletedAt.IsZero() || now.After(completion.CompletedAt.Add(volumeRetypeCompletionTTL)) {
			delete(completed, key)
		}
	}
	if len(completed) <= volumeRetypeCompletionMax {
		return
	}
	keys := make([]volumeRetypeCompletionKey, 0, len(completed))
	for key := range completed {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		leftTime := completed[keys[left]].CompletedAt
		rightTime := completed[keys[right]].CompletedAt
		if !leftTime.Equal(rightTime) {
			return leftTime.Before(rightTime)
		}
		if keys[left].InstanceUUID != keys[right].InstanceUUID {
			return keys[left].InstanceUUID < keys[right].InstanceUUID
		}
		if keys[left].DiskPath != keys[right].DiskPath {
			return keys[left].DiskPath < keys[right].DiskPath
		}
		if keys[left].SourceName != keys[right].SourceName {
			return keys[left].SourceName < keys[right].SourceName
		}
		return keys[left].DestinationName < keys[right].DestinationName
	})
	for _, key := range keys[:len(keys)-volumeRetypeCompletionMax] {
		delete(completed, key)
	}
}

func finishVolumeRetype(
	jobs map[volumeRetypeKey]volumeRetypeJob,
	completed map[volumeRetypeCompletionKey]volumeRetypeCompletion,
	counters *volumeRetypeResultCounters,
	key volumeRetypeKey,
	job volumeRetypeJob,
	result string,
	now time.Time,
) {
	if job.ObservedStartAt.IsZero() {
		job.ObservedStartAt = job.ConfirmedAt
	}
	if job.ObservedStartAt.IsZero() {
		job.ObservedStartAt = now
	}
	job.ProgressAvailable = false
	completed[volumeRetypeCompletionKeyForJob(job)] = volumeRetypeCompletion{Job: job, Result: result, CompletedAt: now}
	addVolumeRetypeResult(counters, result)
	delete(jobs, key)
}

func classifyVolumeRetypeResult(job volumeRetypeJob, state volumeRetypeXMLState) string {
	currentSource, exists := state.Sources[job.DiskPath]
	if !exists {
		return "unknown"
	}
	switch currentSource {
	case job.DestinationName:
		return "success"
	case job.SourceName:
		return "unsuccessful"
	default:
		return "unknown"
	}
}

func sortedVolumeRetypeKeys(jobs map[volumeRetypeKey]volumeRetypeJob) []volumeRetypeKey {
	keys := make([]volumeRetypeKey, 0, len(jobs))
	for key := range jobs {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].InstanceUUID != keys[right].InstanceUUID {
			return keys[left].InstanceUUID < keys[right].InstanceUUID
		}
		return keys[left].DiskPath < keys[right].DiskPath
	})
	return keys
}

func sortedVolumeRetypeCompletionKeys(
	completed map[volumeRetypeCompletionKey]volumeRetypeCompletion,
) []volumeRetypeCompletionKey {
	keys := make([]volumeRetypeCompletionKey, 0, len(completed))
	for key := range completed {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].InstanceUUID != keys[right].InstanceUUID {
			return keys[left].InstanceUUID < keys[right].InstanceUUID
		}
		if keys[left].DiskPath != keys[right].DiskPath {
			return keys[left].DiskPath < keys[right].DiskPath
		}
		if keys[left].SourceName != keys[right].SourceName {
			return keys[left].SourceName < keys[right].SourceName
		}
		return keys[left].DestinationName < keys[right].DestinationName
	})
	return keys
}

func (mc *MetricsCollector) refreshVolumeRetypes(
	domainStats []libvirt.DomainStatsRecord,
	metadata map[string]*DomainStatic,
) {
	if !mc.volumeRetypeEnabled {
		return
	}
	mc.volumeRetypePollMu.Lock()
	defer mc.volumeRetypePollMu.Unlock()

	cycleStartedAt := time.Now()
	mc.volumeRetypeMu.Lock()
	jobs := make(map[volumeRetypeKey]volumeRetypeJob, len(mc.volumeRetypeJobs))
	for key, job := range mc.volumeRetypeJobs {
		jobs[key] = job
	}
	completed := make(map[volumeRetypeCompletionKey]volumeRetypeCompletion, len(mc.volumeRetypeCompleted))
	for key, completion := range mc.volumeRetypeCompleted {
		completed[key] = completion
	}
	counters := mc.volumeRetypeResults
	mc.volumeRetypeMu.Unlock()
	pruneVolumeRetypeCompletions(completed, cycleStartedAt)

	activeDomains := make(map[string]libvirt.Domain, len(domainStats))
	for _, record := range domainStats {
		instanceUUID := validLibvirtDomainUUID(record.Dom.UUID)
		if instanceUUID != "" {
			activeDomains[instanceUUID] = record.Dom
		}
	}
	for _, key := range sortedVolumeRetypeKeys(jobs) {
		if _, active := activeDomains[key.InstanceUUID]; active {
			continue
		}
		evictUnconfirmedVolumeRetype(jobs, key)
	}

	mc.libvirtMu.Lock()
	conn := mc.libvirtConn
	mc.libvirtMu.Unlock()
	if conn == nil && (mc.libvirtBlockJobRPCOverride == nil || mc.im.domainXMLDescOverride == nil) {
		observedAt := volumeRetypeObservationTime(cycleStartedAt)
		maxAge := volumeRetypeActiveMaxAge(mc.effectiveCollectionInterval())
		for key, job := range jobs {
			job = markVolumeRetypeObservationUnavailable(job, observedAt)
			jobs[key] = job
			if job.ConfirmedAt.IsZero() || observedAt.Sub(job.ConfirmedAt) > maxAge {
				evictUnconfirmedVolumeRetype(jobs, key)
			}
		}
		pruneVolumeRetypeCompletions(completed, observedAt)
		mc.volumeRetypeMu.Lock()
		mc.volumeRetypeJobs = jobs
		mc.volumeRetypeCompleted = completed
		mc.volumeRetypeResults = counters
		mc.volumeRetypeMu.Unlock()
		mc.pruneVolumeRetypeDiskCursors(jobs)
		return
	}

	decisionAt := volumeRetypeObservationTime(cycleStartedAt)
	knownRequests := make([]volumeRetypeBlockRequest, 0, len(jobs))
	for _, key := range sortedVolumeRetypeKeys(jobs) {
		if !volumeRetypeBlockPollDue(jobs[key], decisionAt) {
			continue
		}
		domain, active := activeDomains[key.InstanceUUID]
		if !active {
			continue
		}
		knownRequests = append(knownRequests, volumeRetypeBlockRequest{Key: key, Domain: domain, DiskPath: key.DiskPath})
	}
	knownResults := mc.queryVolumeRetypeBlockJobs(
		conn,
		knownRequests,
		time.Now().Add(mc.volumeRetypeCycleBudget()),
		volumeRetypeCursorCollectionBlock,
	)
	knownObservedAt := volumeRetypeObservationTime(decisionAt)

	completionDomains := make(map[string]libvirt.Domain)
	for key, result := range knownResults {
		if result.Err != nil || !result.Found || result.JobType != int32(libvirt.DomainBlockJobTypeCopy) {
			completionDomains[key.InstanceUUID] = activeDomains[key.InstanceUUID]
		}
	}
	// Completion confirmation runs first with a fresh budget. General discovery
	// cannot keep a finished operation active on the dashboard.
	xmlResults := mc.fetchVolumeRetypeXML(
		conn,
		completionDomains,
		time.Now().Add(mc.volumeRetypeCycleBudget()),
		volumeRetypeCursorCompletionXML,
	)
	discoveryDomains := make(map[string]libvirt.Domain)
	for _, domain := range mc.takeVolumeRetypeDiscoveryDomains(domainStats) {
		instanceUUID := validLibvirtDomainUUID(domain.UUID)
		if instanceUUID != "" {
			if _, alreadyInspected := completionDomains[instanceUUID]; !alreadyInspected {
				discoveryDomains[instanceUUID] = domain
			}
		}
	}
	for instanceUUID, result := range mc.fetchVolumeRetypeXML(
		conn,
		discoveryDomains,
		time.Now().Add(mc.volumeRetypeCycleBudget()),
		volumeRetypeCursorDiscoveryXML,
	) {
		xmlResults[instanceUUID] = result
	}
	xmlObservedAt := volumeRetypeObservationTime(knownObservedAt)

	collectionHadErrors := false
	for _, result := range knownResults {
		if result.Err != nil {
			collectionHadErrors = true
		}
	}
	for _, result := range xmlResults {
		if result.Err != nil {
			collectionHadErrors = true
		}
	}

	for _, key := range sortedVolumeRetypeKeys(jobs) {
		job := jobs[key]
		domain, active := activeDomains[key.InstanceUUID]
		if !active {
			continue
		}
		job = updateVolumeRetypeJobMetadata(job, metadata[key.InstanceUUID], domain)
		poll, polled := knownResults[key]
		xmlResult, inspected := xmlResults[key.InstanceUUID]
		candidate, candidateActive := xmlResult.State.Candidates[key.DiskPath]
		_, copyJobPresent := xmlResult.State.CopyJobs[key.DiskPath]
		if inspected && xmlResult.Err == nil && candidateActive &&
			!volumeRetypeOperationMatchesCandidate(job, candidate) {
			// XML is newer than the block-info request. Retain the old operation's
			// observed result, then start the replacement with clean timing and
			// progress state. The earlier block result may belong to the old job.
			finishVolumeRetype(
				jobs,
				completed,
				&counters,
				key,
				job,
				classifyVolumeRetypeResult(job, xmlResult.State),
				xmlObservedAt,
			)
			replacement := volumeRetypeJobFromCandidate(
				domain,
				metadata[key.InstanceUUID],
				candidate,
				xmlObservedAt,
			)
			delete(completed, volumeRetypeCompletionKeyForJob(replacement))
			jobs[key] = replacement
			continue
		}
		if polled {
			job = applyVolumeRetypeBlockResult(job, poll, knownObservedAt)
		}
		// The XML inspection happened after the block-info query. If the mirror
		// has disappeared, that newer observation is authoritative for this
		// cycle even when the earlier query still reported a copy job.
		if inspected && xmlResult.Err == nil && !copyJobPresent {
			finishVolumeRetype(jobs, completed, &counters, key, job, classifyVolumeRetypeResult(job, xmlResult.State), xmlObservedAt)
			continue
		}

		if polled && poll.Err == nil && poll.Found && poll.JobType == int32(libvirt.DomainBlockJobTypeCopy) {
			job.ConfirmedAt = knownObservedAt
			if inspected && xmlResult.Err == nil && candidateActive {
				job = refreshVolumeRetypeJobFromCandidate(job, domain, metadata[key.InstanceUUID], candidate, xmlObservedAt)
			}
			jobs[key] = job
			continue
		}

		if inspected && xmlResult.Err == nil && candidateActive {
			updated := refreshVolumeRetypeJobFromCandidate(job, domain, metadata[key.InstanceUUID], candidate, xmlObservedAt)
			job = updated
			jobs[key] = job
			continue
		}

		// A missing inspection must not turn a running operation into a false
		// completion. A failed block-job query already removed stale progress.
		jobs[key] = job
	}

	newRequests := make([]volumeRetypeBlockRequest, 0)
	newCandidates := make(map[volumeRetypeKey]volumeRetypeCandidate)
	for instanceUUID, xmlResult := range xmlResults {
		if xmlResult.Err != nil {
			continue
		}
		domain, active := activeDomains[instanceUUID]
		if !active {
			continue
		}
		paths := make([]string, 0, len(xmlResult.State.Candidates))
		for diskPath := range xmlResult.State.Candidates {
			paths = append(paths, diskPath)
		}
		sort.Strings(paths)
		for _, diskPath := range paths {
			key := volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: diskPath}
			if _, exists := jobs[key]; exists {
				continue
			}
			candidate := xmlResult.State.Candidates[diskPath]
			newCandidates[key] = candidate
			newRequests = append(newRequests, volumeRetypeBlockRequest{Key: key, Domain: domain, DiskPath: diskPath})
		}
	}
	newResults := mc.queryVolumeRetypeBlockJobs(
		conn,
		newRequests,
		time.Now().Add(mc.volumeRetypeCycleBudget()),
		volumeRetypeCursorDiscoveryBlock,
	)
	newObservedAt := volumeRetypeObservationTime(xmlObservedAt)
	for _, result := range newResults {
		if result.Err != nil {
			collectionHadErrors = true
		}
	}
	for _, request := range newRequests {
		candidate := newCandidates[request.Key]
		result := newResults[request.Key]
		if result.Err == nil && (!result.Found || result.JobType != int32(libvirt.DomainBlockJobTypeCopy)) {
			continue
		}
		job := volumeRetypeJobFromCandidate(request.Domain, metadata[request.Key.InstanceUUID], candidate, xmlObservedAt)
		job = applyVolumeRetypeBlockResult(job, result, newObservedAt)
		if result.Err == nil && result.Found && result.JobType == int32(libvirt.DomainBlockJobTypeCopy) {
			job.ConfirmedAt = newObservedAt
		}
		delete(completed, volumeRetypeCompletionKeyForJob(job))
		jobs[request.Key] = job
	}

	expiryAt := volumeRetypeObservationTime(newObservedAt)
	maxAge := volumeRetypeActiveMaxAge(mc.effectiveCollectionInterval())
	for key, job := range jobs {
		if job.ConfirmedAt.IsZero() || expiryAt.Sub(job.ConfirmedAt) > maxAge {
			evictUnconfirmedVolumeRetype(jobs, key)
		}
	}
	pruneVolumeRetypeCompletions(completed, expiryAt)

	mc.volumeRetypeMu.Lock()
	mc.volumeRetypeJobs = jobs
	mc.volumeRetypeCompleted = completed
	mc.volumeRetypeResults = counters
	mc.volumeRetypeMu.Unlock()
	mc.pruneVolumeRetypeDiskCursors(jobs)
	if collectionHadErrors {
		atomic.AddUint64(&mc.hostCollectionErrors, 1)
	}
}

// refreshActiveVolumeRetypes polls only operations that discovery has already
// found. The common idle case performs no Libvirt RPCs.
func (mc *MetricsCollector) refreshActiveVolumeRetypes(now time.Time) {
	if !mc.volumeRetypeEnabled {
		return
	}
	mc.volumeRetypePollMu.Lock()
	defer mc.volumeRetypePollMu.Unlock()
	cycleStartedAt := volumeRetypeObservationTime(now)

	mc.volumeRetypeMu.Lock()
	jobs := make(map[volumeRetypeKey]volumeRetypeJob, len(mc.volumeRetypeJobs))
	for key, job := range mc.volumeRetypeJobs {
		jobs[key] = job
	}
	completed := make(map[volumeRetypeCompletionKey]volumeRetypeCompletion, len(mc.volumeRetypeCompleted))
	for key, completion := range mc.volumeRetypeCompleted {
		completed[key] = completion
	}
	counters := mc.volumeRetypeResults
	mc.volumeRetypeMu.Unlock()
	pruneVolumeRetypeCompletions(completed, cycleStartedAt)

	commit := func() {
		mc.volumeRetypeMu.Lock()
		mc.volumeRetypeJobs = jobs
		mc.volumeRetypeCompleted = completed
		mc.volumeRetypeResults = counters
		mc.volumeRetypeMu.Unlock()
		mc.pruneVolumeRetypeDiskCursors(jobs)
	}
	if len(jobs) == 0 {
		commit()
		return
	}

	mc.libvirtMu.Lock()
	conn := mc.libvirtConn
	mc.libvirtMu.Unlock()
	if conn == nil && (mc.libvirtBlockJobRPCOverride == nil || mc.im.domainXMLDescOverride == nil) {
		observedAt := volumeRetypeObservationTime(cycleStartedAt)
		maxAge := volumeRetypeActiveMaxAge(mc.effectiveCollectionInterval())
		for key, job := range jobs {
			job = markVolumeRetypeObservationUnavailable(job, observedAt)
			jobs[key] = job
			if job.ConfirmedAt.IsZero() || observedAt.Sub(job.ConfirmedAt) > maxAge {
				evictUnconfirmedVolumeRetype(jobs, key)
			}
		}
		pruneVolumeRetypeCompletions(completed, observedAt)
		commit()
		return
	}

	requests := make([]volumeRetypeBlockRequest, 0, len(jobs))
	for _, key := range sortedVolumeRetypeKeys(jobs) {
		job := jobs[key]
		if !volumeRetypeBlockPollDue(job, cycleStartedAt) {
			continue
		}
		requests = append(requests, volumeRetypeBlockRequest{
			Key:      key,
			Domain:   job.Domain,
			DiskPath: key.DiskPath,
		})
	}
	results := mc.queryVolumeRetypeBlockJobs(
		conn,
		requests,
		time.Now().Add(mc.volumeRetypeCycleBudget()),
		volumeRetypeCursorActivePollBlock,
	)
	blockObservedAt := volumeRetypeObservationTime(cycleStartedAt)

	inspectionDomains := make(map[string]libvirt.Domain)
	for key, job := range jobs {
		inspectionDomains[key.InstanceUUID] = job.Domain
	}
	collectionHadErrors := false
	for _, result := range results {
		if result.Err != nil {
			collectionHadErrors = true
		}
	}
	// Block-job progress does not expose Libvirt's mirror ready flag. Inspect
	// each domain that has a known job no more often than five seconds after the
	// prior refresh completes. Progress queries are independently rate-limited,
	// and one XML read covers every active disk in a domain.
	xmlResults := mc.fetchVolumeRetypeXML(
		conn,
		inspectionDomains,
		time.Now().Add(mc.volumeRetypeCycleBudget()),
		volumeRetypeCursorActivePollXML,
	)
	xmlObservedAt := volumeRetypeObservationTime(blockObservedAt)
	for _, result := range xmlResults {
		if result.Err != nil {
			collectionHadErrors = true
		}
	}

	for _, key := range sortedVolumeRetypeKeys(jobs) {
		job := jobs[key]
		poll, polled := results[key]
		xmlResult, inspected := xmlResults[key.InstanceUUID]
		candidate, candidateActive := xmlResult.State.Candidates[key.DiskPath]
		_, copyJobPresent := xmlResult.State.CopyJobs[key.DiskPath]
		if inspected && xmlResult.Err == nil && candidateActive &&
			!volumeRetypeOperationMatchesCandidate(job, candidate) {
			finishVolumeRetype(
				jobs,
				completed,
				&counters,
				key,
				job,
				classifyVolumeRetypeResult(job, xmlResult.State),
				xmlObservedAt,
			)
			replacement := volumeRetypeJobFromCandidate(job.Domain, nil, candidate, xmlObservedAt)
			replacement = updateVolumeRetypeJobMetadata(replacement, nil, job.Domain)
			replacement.ServerName = job.ServerName
			replacement.InstanceUUID = job.InstanceUUID
			replacement.ProjectUUID = job.ProjectUUID
			replacement.ProjectName = job.ProjectName
			replacement.UserUUID = job.UserUUID
			delete(completed, volumeRetypeCompletionKeyForJob(replacement))
			jobs[key] = replacement
			continue
		}
		if polled {
			job = applyVolumeRetypeBlockResult(job, poll, blockObservedAt)
		}
		// XML is collected after block-info. Prefer its newer proof that the
		// mirror vanished over an earlier successful copy-job response.
		if inspected && xmlResult.Err == nil && !copyJobPresent {
			finishVolumeRetype(jobs, completed, &counters, key, job, classifyVolumeRetypeResult(job, xmlResult.State), xmlObservedAt)
			continue
		}
		if polled && poll.Err == nil && poll.Found && poll.JobType == int32(libvirt.DomainBlockJobTypeCopy) {
			job.ConfirmedAt = blockObservedAt
			if inspected && xmlResult.Err == nil && candidateActive {
				job = refreshVolumeRetypeJobFromCandidate(job, job.Domain, nil, candidate, xmlObservedAt)
			}
			jobs[key] = job
			continue
		}

		if inspected && xmlResult.Err == nil && candidateActive {
			updated := refreshVolumeRetypeJobFromCandidate(job, job.Domain, nil, candidate, xmlObservedAt)
			jobs[key] = updated
			continue
		}

		// Retain identity through a missing inspection. A failed block-job query
		// already removed stale progress and set observation health to zero.
		jobs[key] = job
	}

	expiryAt := volumeRetypeObservationTime(xmlObservedAt)
	maxAge := volumeRetypeActiveMaxAge(mc.effectiveCollectionInterval())
	for key, job := range jobs {
		if job.ConfirmedAt.IsZero() || expiryAt.Sub(job.ConfirmedAt) > maxAge {
			evictUnconfirmedVolumeRetype(jobs, key)
		}
	}
	pruneVolumeRetypeCompletions(completed, expiryAt)
	commit()
	if collectionHadErrors {
		atomic.AddUint64(&mc.hostCollectionErrors, 1)
	}
}

func (mc *MetricsCollector) runVolumeRetypePoller(interval time.Duration, shutdown <-chan struct{}) {
	if !mc.volumeRetypeEnabled {
		return
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-shutdown:
			return
		case <-timer.C:
			// Both channels can be ready during shutdown. Do not let select's
			// random choice start another Libvirt observation after termination.
			select {
			case <-shutdown:
				return
			default:
			}
			// The full scrape cycle owns the shared connection while it gathers
			// stats, metadata, and retype state. Skip instead of overlapping it;
			// the completion-paced timer prevents a queued catch-up burst.
			if mc.volumeRetypeLibvirtWorkMu.TryLock() {
				mc.refreshActiveVolumeRetypes(time.Now())
				mc.volumeRetypeLibvirtWorkMu.Unlock()
			}
			timer.Reset(interval)
		}
	}
}

func (mc *MetricsCollector) startVolumeRetypePoller() {
	mc.runVolumeRetypePoller(volumeRetypeActivePollInterval, mc.shutdownChan)
}

func (mc *MetricsCollector) volumeRetypeMetricStateSnapshot() volumeRetypeMetricState {
	state := volumeRetypeMetricState{
		Jobs:      make(map[volumeRetypeKey]volumeRetypeJob),
		Completed: make(map[volumeRetypeCompletionKey]volumeRetypeCompletion),
	}
	if mc == nil {
		return state
	}

	mc.volumeRetypeMu.Lock()
	state.Jobs = make(map[volumeRetypeKey]volumeRetypeJob, len(mc.volumeRetypeJobs))
	for key, job := range mc.volumeRetypeJobs {
		state.Jobs[key] = job
	}
	state.Completed = make(map[volumeRetypeCompletionKey]volumeRetypeCompletion, len(mc.volumeRetypeCompleted))
	for key, completion := range mc.volumeRetypeCompleted {
		state.Completed[key] = completion
	}
	state.Results = mc.volumeRetypeResults
	mc.volumeRetypeMu.Unlock()
	return state
}

func (mc *MetricsCollector) volumeRetypeResultMetricsForState(state volumeRetypeMetricState) []prometheus.Metric {
	if mc == nil || !mc.volumeRetypeEnabled || mc.hostVolumeRetypeResultsTotalDesc == nil {
		return nil
	}
	counters := state.Results
	return []prometheus.Metric{
		prometheus.MustNewConstMetric(mc.hostVolumeRetypeResultsTotalDesc, prometheus.CounterValue, float64(counters.Success), "success"),
		prometheus.MustNewConstMetric(mc.hostVolumeRetypeResultsTotalDesc, prometheus.CounterValue, float64(counters.Unsuccessful), "unsuccessful"),
		prometheus.MustNewConstMetric(mc.hostVolumeRetypeResultsTotalDesc, prometheus.CounterValue, float64(counters.Unknown), "unknown"),
	}
}

func (mc *MetricsCollector) volumeRetypeResultMetrics() []prometheus.Metric {
	return mc.volumeRetypeResultMetricsForState(mc.volumeRetypeMetricStateSnapshot())
}

func volumeRetypeMetricLabels(job volumeRetypeJob) []string {
	return []string{
		job.DomainName,
		job.ServerName,
		job.InstanceUUID,
		job.ProjectUUID,
		job.ProjectName,
		job.UserUUID,
		job.VolumeUUID,
		job.DiskType,
		job.DiskPath,
		job.DestinationVolumeUUID,
		job.DestinationDiskType,
	}
}

func volumeRetypeTimestamp(timestamp time.Time) float64 {
	if timestamp.IsZero() {
		return 0
	}
	return float64(timestamp.UnixNano()) / float64(time.Second)
}

func volumeRetypeActiveStatusCode(job volumeRetypeJob, now time.Time) float64 {
	if !job.Ready {
		return volumeRetypeStatusActive
	}
	if !job.ReadyObservedAt.IsZero() &&
		!now.Before(job.ReadyObservedAt.Add(volumeRetypeReadyStalledAfter)) {
		return volumeRetypeStatusReadyStalled
	}
	return volumeRetypeStatusReady
}

func (mc *MetricsCollector) volumeRetypeMetricsForMetricState(
	now time.Time,
	progressTrusted bool,
	state volumeRetypeMetricState,
) []prometheus.Metric {
	if mc == nil || !mc.volumeRetypeEnabled || mc.im == nil || mc.im.instanceDiskRetypeActiveDesc == nil {
		return nil
	}
	jobs := state.Jobs
	completed := state.Completed

	maxAge := volumeRetypeActiveMaxAge(mc.effectiveCollectionInterval())
	metrics := make([]prometheus.Metric, 0, (len(jobs)+len(completed))*6)
	for _, key := range sortedVolumeRetypeKeys(jobs) {
		job := jobs[key]
		if job.ConfirmedAt.IsZero() || now.Sub(job.ConfirmedAt) > maxAge {
			continue
		}
		labels := volumeRetypeMetricLabels(job)
		metrics = append(metrics, prometheus.MustNewConstMetric(
			mc.im.instanceDiskRetypeActiveDesc,
			prometheus.GaugeValue,
			1,
			labels...,
		))
		metrics = append(metrics, prometheus.MustNewConstMetric(
			mc.im.instanceDiskRetypeStatusCodeDesc,
			prometheus.GaugeValue,
			volumeRetypeActiveStatusCode(job, now),
			labels...,
		))
		if progressTrusted && job.ObservationAttempted {
			observationHealthy := 0.0
			if job.ObservationHealthy {
				observationHealthy = 1
			}
			metrics = append(metrics, prometheus.MustNewConstMetric(
				mc.im.instanceDiskRetypeObservationHealthyDesc,
				prometheus.GaugeValue,
				observationHealthy,
				labels...,
			))
		}
		metrics = append(metrics, prometheus.MustNewConstMetric(
			mc.im.instanceDiskRetypeStartTimestampDesc,
			prometheus.GaugeValue,
			volumeRetypeTimestamp(job.ObservedStartAt),
			labels...,
		))
		if !job.ReadyObservedAt.IsZero() {
			metrics = append(metrics, prometheus.MustNewConstMetric(
				mc.im.instanceDiskRetypeReadyTimestampDesc,
				prometheus.GaugeValue,
				volumeRetypeTimestamp(job.ReadyObservedAt),
				labels...,
			))
		}
		if progressTrusted && job.ProgressAvailable {
			metrics = append(metrics, prometheus.MustNewConstMetric(
				mc.im.instanceDiskRetypeProgressDesc,
				prometheus.GaugeValue,
				job.ProgressPercent,
				labels...,
			))
		}
	}

	activeOperations := make(map[volumeRetypeCompletionKey]struct{}, len(jobs))
	for _, job := range jobs {
		activeOperations[volumeRetypeCompletionKeyForJob(job)] = struct{}{}
	}
	for _, key := range sortedVolumeRetypeCompletionKeys(completed) {
		completion := completed[key]
		if completion.CompletedAt.IsZero() || now.After(completion.CompletedAt.Add(volumeRetypeCompletionTTL)) {
			continue
		}
		if _, active := activeOperations[key]; active {
			continue
		}
		labels := volumeRetypeMetricLabels(completion.Job)
		metrics = append(metrics,
			prometheus.MustNewConstMetric(mc.im.instanceDiskRetypeActiveDesc, prometheus.GaugeValue, 0, labels...),
			prometheus.MustNewConstMetric(mc.im.instanceDiskRetypeStatusCodeDesc, prometheus.GaugeValue, volumeRetypeStatusCode(completion.Result), labels...),
			prometheus.MustNewConstMetric(mc.im.instanceDiskRetypeStartTimestampDesc, prometheus.GaugeValue, volumeRetypeTimestamp(completion.Job.ObservedStartAt), labels...),
			prometheus.MustNewConstMetric(mc.im.instanceDiskRetypeEndTimestampDesc, prometheus.GaugeValue, volumeRetypeTimestamp(completion.CompletedAt), labels...),
		)
		if !completion.Job.ReadyObservedAt.IsZero() {
			metrics = append(metrics, prometheus.MustNewConstMetric(
				mc.im.instanceDiskRetypeReadyTimestampDesc,
				prometheus.GaugeValue,
				volumeRetypeTimestamp(completion.Job.ReadyObservedAt),
				labels...,
			))
		}
	}
	return metrics
}

func (mc *MetricsCollector) volumeRetypeMetricsForSourceState(now time.Time, progressTrusted bool) []prometheus.Metric {
	return mc.volumeRetypeMetricsForMetricState(now, progressTrusted, mc.volumeRetypeMetricStateSnapshot())
}

func (mc *MetricsCollector) volumeRetypeMetricBatch(now time.Time, progressTrusted bool) []prometheus.Metric {
	if mc == nil || !mc.volumeRetypeEnabled {
		return nil
	}
	state := mc.volumeRetypeMetricStateSnapshot()
	metrics := mc.volumeRetypeResultMetricsForState(state)
	return append(metrics, mc.volumeRetypeMetricsForMetricState(now, progressTrusted, state)...)
}

func (mc *MetricsCollector) volumeRetypeMetrics(now time.Time) []prometheus.Metric {
	return mc.volumeRetypeMetricsForSourceState(now, true)
}

func (mc *MetricsCollector) volumeRetypeCachedFallbackMetrics(now time.Time) []prometheus.Metric {
	// A failed Libvirt cycle cannot validate a prior byte cursor. Preserve only
	// recently confirmed active-job identity and lifecycle timestamps, omit
	// per-job progress and query-health observations that are not currently
	// trustworthy, then let the normal freshness bound remove the identity.
	return mc.volumeRetypeMetricsForSourceState(now, false)
}
