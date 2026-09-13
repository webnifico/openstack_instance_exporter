package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const volumeRetypeOIEFamilyCount = 144

var volumeRetypeMetricDescriptors = []string{
	"oie_host_volume_retype_results_total|result",
	"oie_instance_disk_retype_active|domain,server_name,instance_uuid,project_uuid,project_name,user_uuid,volume_uuid,disk_type,disk_path,destination_volume_uuid,destination_disk_type",
	"oie_instance_disk_retype_progress_percent|domain,server_name,instance_uuid,project_uuid,project_name,user_uuid,volume_uuid,disk_type,disk_path,destination_volume_uuid,destination_disk_type",
	"oie_instance_disk_retype_status_code|domain,server_name,instance_uuid,project_uuid,project_name,user_uuid,volume_uuid,disk_type,disk_path,destination_volume_uuid,destination_disk_type",
	"oie_instance_disk_retype_observation_healthy|domain,server_name,instance_uuid,project_uuid,project_name,user_uuid,volume_uuid,disk_type,disk_path,destination_volume_uuid,destination_disk_type",
	"oie_instance_disk_retype_start_timestamp_seconds|domain,server_name,instance_uuid,project_uuid,project_name,user_uuid,volume_uuid,disk_type,disk_path,destination_volume_uuid,destination_disk_type",
	"oie_instance_disk_retype_ready_timestamp_seconds|domain,server_name,instance_uuid,project_uuid,project_name,user_uuid,volume_uuid,disk_type,disk_path,destination_volume_uuid,destination_disk_type",
	"oie_instance_disk_retype_end_timestamp_seconds|domain,server_name,instance_uuid,project_uuid,project_name,user_uuid,volume_uuid,disk_type,disk_path,destination_volume_uuid,destination_disk_type",
}

func volumeRetypeMetricFamilyNames() map[string]struct{} {
	names := make(map[string]struct{}, len(volumeRetypeMetricDescriptors))
	for _, descriptor := range volumeRetypeMetricDescriptors {
		name, _, _ := strings.Cut(descriptor, "|")
		names[name] = struct{}{}
	}
	return names
}

func TestVolumeRetypeOperationMetricsShareLabelsForOneGrafanaRow(t *testing.T) {
	var expectedLabels string
	for _, descriptor := range volumeRetypeMetricDescriptors {
		parts := strings.SplitN(descriptor, "|", 2)
		if len(parts) != 2 || parts[0] == "oie_host_volume_retype_results_total" {
			continue
		}
		if expectedLabels == "" {
			expectedLabels = parts[1]
			continue
		}
		if parts[1] != expectedLabels {
			t.Fatalf("%s labels=%q, want common retype labels %q", parts[0], parts[1], expectedLabels)
		}
	}
	if expectedLabels == "" {
		t.Fatal("no per-operation retype descriptors were checked")
	}
}

func TestVolumeRetypeMetricContractIsExact(t *testing.T) {
	descriptors, _ := descriptorContract(t)
	if len(descriptors) != inventoryOIEFamilyCount {
		t.Fatalf("metric families=%d, want %d", len(descriptors), inventoryOIEFamilyCount)
	}
	want := make(map[string]struct{}, len(volumeRetypeMetricDescriptors))
	for _, descriptor := range volumeRetypeMetricDescriptors {
		want[descriptor] = struct{}{}
	}
	for _, descriptor := range descriptors {
		if _, exists := want[descriptor]; exists {
			delete(want, descriptor)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing retype descriptors: %v", want)
	}
}

func TestVolumeRetypeMetricHelpDoesNotOverstateCinderAuthority(t *testing.T) {
	mc, _, _, _ := newVolumeRetypeTestCollector(t)
	descriptions := []string{
		mc.im.instanceDiskRetypeActiveDesc.String(),
		mc.im.instanceDiskRetypeStatusCodeDesc.String(),
		mc.im.instanceDiskRetypeStartTimestampDesc.String(),
		mc.im.instanceDiskRetypeEndTimestampDesc.String(),
		mc.hostVolumeRetypeResultsTotalDesc.String(),
	}
	joined := strings.Join(descriptions, "\n")
	for _, required := range []string{
		"successful XML inspection",
		"live source matches the saved destination",
		"not authoritative Cinder status",
		"not authoritative Cinder outcomes",
		"first observed the Libvirt block-copy job",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("retype metric HELP omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"2 completed successfully",
		"observed the Cinder volume retype reach a terminal state",
		"Observed terminal Cinder volume retype outcomes",
	} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("retype metric HELP overstates Cinder authority with %q", forbidden)
		}
	}
}

const activeVolumeRetypeXML = `<domain>
  <devices>
    <disk type="network" device="disk">
      <source protocol="rbd" name="volumes/volume-d2d5547f-8b38-42e3-95ba-40e720dc4259"/>
      <mirror type="network" job="copy">
        <source protocol="rbd" name="premium/volume-b885bfa5-bb3f-47b7-bd49-3980fae73ce8"/>
      </mirror>
      <target dev="vde" bus="virtio"/>
    </disk>
  </devices>
</domain>`

func volumeRetypeOperationXML(sourceName, destinationName string, ready bool) string {
	readyAttribute := ""
	if ready {
		readyAttribute = ` ready="yes"`
	}
	return fmt.Sprintf(`<domain><devices><disk type="network" device="disk"><source protocol="rbd" name="%s"/><mirror type="network" job="copy"%s><source protocol="rbd" name="%s"/></mirror><target dev="vde" bus="virtio"/></disk></devices></domain>`, sourceName, readyAttribute, destinationName)
}

func TestVolumeRetypeXMLRecognizesOnlyCinderRBDCopies(t *testing.T) {
	state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
	if err != nil {
		t.Fatal(err)
	}
	candidate, exists := state.Candidates["vde"]
	if !exists {
		t.Fatal("active Cinder RBD mirror was not recognized")
	}
	if candidate.DiskType != "volumes" || candidate.VolumeUUID != "volume-d2d5547f-8b38-42e3-95ba-40e720dc4259" {
		t.Fatalf("source identity=%+v", candidate)
	}
	if candidate.DestinationDiskType != "premium" || candidate.DestinationVolumeUUID != "volume-b885bfa5-bb3f-47b7-bd49-3980fae73ce8" {
		t.Fatalf("destination identity=%+v", candidate)
	}
	if got := state.Sources["vde"]; got != candidate.SourceName {
		t.Fatalf("current source=%q, want %q", got, candidate.SourceName)
	}
	if candidate.Ready {
		t.Fatal("copying mirror was incorrectly marked ready")
	}

	readyXML := strings.Replace(activeVolumeRetypeXML, `job="copy"`, `job="copy" ready="yes"`, 1)
	state, err = parseVolumeRetypeXML(readyXML)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Candidates["vde"].Ready {
		t.Fatal("ready Libvirt mirror was not recognized")
	}

	genericCopy := strings.ReplaceAll(activeVolumeRetypeXML, "volume-d2d5547f-8b38-42e3-95ba-40e720dc4259", "snapshot-base")
	state, err = parseVolumeRetypeXML(genericCopy)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Candidates) != 0 {
		t.Fatalf("generic block copy was mislabeled as a Cinder retype: %+v", state.Candidates)
	}
	if _, present := state.CopyJobs["vde"]; !present {
		t.Fatal("generic copy-job presence was lost with its unsupported identity")
	}
}

func TestVolumeRetypeKnownCopyWithUnparseableMirrorIdentityDoesNotComplete(t *testing.T) {
	const incompleteMirrorXML = `<domain><devices><disk type="network" device="disk"><source protocol="rbd" name="volumes/volume-d2d5547f-8b38-42e3-95ba-40e720dc4259"/><mirror type="network" job="copy"><source protocol="rbd"/></mirror><target dev="vde" bus="virtio"/></disk></devices></domain>`

	for _, test := range []struct {
		name    string
		refresh func(*MetricsCollector, []libvirt.DomainStatsRecord, map[string]*DomainStatic)
	}{
		{
			name: "full collection",
			refresh: func(mc *MetricsCollector, records []libvirt.DomainStatsRecord, metadata map[string]*DomainStatic) {
				mc.refreshVolumeRetypes(records, metadata)
			},
		},
		{
			name: "fast poller",
			refresh: func(mc *MetricsCollector, _ []libvirt.DomainStatsRecord, _ map[string]*DomainStatic) {
				mc.refreshActiveVolumeRetypes(time.Now())
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
			activeState, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
			if err != nil {
				t.Fatal(err)
			}
			job := volumeRetypeJobFromCandidate(domain, meta, activeState.Candidates["vde"], time.Now())
			job.NextBlockPollAt = time.Time{}
			key := volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}
			mc.volumeRetypeJobs[key] = job
			mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
				return 0, 0, 0, 0, 0, nil
			}
			mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
				return incompleteMirrorXML, nil
			}

			test.refresh(mc, []libvirt.DomainStatsRecord{{Dom: domain}}, map[string]*DomainStatic{instanceUUID: meta})

			mc.volumeRetypeMu.Lock()
			_, active := mc.volumeRetypeJobs[key]
			completed := len(mc.volumeRetypeCompleted)
			counters := mc.volumeRetypeResults
			mc.volumeRetypeMu.Unlock()
			if !active {
				t.Fatal("known operation was falsely completed while its copy mirror remained present")
			}
			if completed != 0 || counters != (volumeRetypeResultCounters{}) {
				t.Fatalf("incomplete mirror identity synthesized terminal state: completed=%d counters=%+v", completed, counters)
			}
		})
	}
}

func TestVolumeRetypeProgressUsesPercentAndRejectsMissingTotals(t *testing.T) {
	tests := []struct {
		current uint64
		end     uint64
		want    float64
		ok      bool
	}{
		{current: 127136694272, end: 1234900680704, want: 10.295297, ok: true},
		{current: 0, end: 100, want: 0, ok: true},
		{current: 150, end: 100, want: 100, ok: true},
		{current: 1, end: 1, ok: false},
		{current: 0, end: 0, ok: false},
	}
	for _, test := range tests {
		got, ok := volumeRetypeProgress(test.current, test.end)
		if ok != test.ok || (ok && math.Abs(got-test.want) > 0.000001) {
			t.Errorf("progress(%d,%d)=(%.9f,%v), want (%.9f,%v)", test.current, test.end, got, ok, test.want, test.ok)
		}
	}
}

func TestVolumeRetypeReadyBecomesStalledAfterTenMinutes(t *testing.T) {
	readyAt := time.Date(2026, time.September, 4, 1, 0, 0, 0, time.UTC)
	job := volumeRetypeJob{Ready: true, ReadyObservedAt: readyAt}
	if got := volumeRetypeActiveStatusCode(job, readyAt.Add(volumeRetypeReadyStalledAfter-time.Nanosecond)); got != volumeRetypeStatusReady {
		t.Fatalf("status before ready-stalled threshold=%v, want %d", got, volumeRetypeStatusReady)
	}
	if got := volumeRetypeActiveStatusCode(job, readyAt.Add(volumeRetypeReadyStalledAfter)); got != volumeRetypeStatusReadyStalled {
		t.Fatalf("status at ready-stalled threshold=%v, want %d", got, volumeRetypeStatusReadyStalled)
	}
	job.Ready = false
	if got := volumeRetypeActiveStatusCode(job, readyAt.Add(24*time.Hour)); got != volumeRetypeStatusActive {
		t.Fatalf("copying job status=%v, want %d", got, volumeRetypeStatusActive)
	}
}

func newVolumeRetypeTestCollector(t *testing.T) (*MetricsCollector, libvirt.Domain, string, *DomainStatic) {
	t.Helper()
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:         "qemu:///system",
		VolumeRetypeEnable: true,
		WorkerCount:        4,
		CollectionInterval: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(mc.shutdownChan) })
	uuid, instanceUUID := dataIntegrityE2EUUID()
	domain := libvirt.Domain{Name: "instance-0000342e", UUID: uuid}
	meta := &DomainStatic{
		Name:         "retype-server",
		InstanceUUID: instanceUUID,
		ProjectUUID:  "project-uuid",
		ProjectName:  "Project Name",
		UserUUID:     "user-uuid",
	}
	return mc, domain, instanceUUID, meta
}

func metricDTO(t *testing.T, metric interface{ Write(*dto.Metric) error }) *dto.Metric {
	t.Helper()
	message := &dto.Metric{}
	if err := metric.Write(message); err != nil {
		t.Fatal(err)
	}
	return message
}

func TestVolumeRetypeLifecycleEmitsActiveAndRecentTerminalStates(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	records := []libvirt.DomainStatsRecord{{Dom: domain}}
	metadata := map[string]*DomainStatic{instanceUUID: meta}

	var stateMu sync.Mutex
	xmlDescription := activeVolumeRetypeXML
	found := int32(1)
	current := uint64(127136694272)
	end := uint64(1234900680704)
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		stateMu.Lock()
		defer stateMu.Unlock()
		return xmlDescription, nil
	}
	mc.libvirtBlockJobRPCOverride = func(_ *libvirt.Libvirt, _ libvirt.Domain, diskPath string, _ uint32) (int32, int32, uint64, uint64, uint64, error) {
		if diskPath != "vde" {
			t.Errorf("block-job path=%q, want vde", diskPath)
		}
		stateMu.Lock()
		defer stateMu.Unlock()
		return found, int32(libvirt.DomainBlockJobTypeCopy), 0, current, end, nil
	}

	mc.refreshVolumeRetypes(records, metadata)
	metrics := mc.volumeRetypeMetrics(time.Now())
	if len(metrics) != 5 {
		t.Fatalf("active metrics=%d, want active, progress, status, observation health, and start", len(metrics))
	}
	seen := make(map[string]*dto.Metric)
	for _, metric := range metrics {
		name := descNameRE.FindStringSubmatch(metric.Desc().String())[1]
		seen[name] = metricDTO(t, metric)
	}
	active := seen["oie_instance_disk_retype_active"]
	progress := seen["oie_instance_disk_retype_progress_percent"]
	status := seen["oie_instance_disk_retype_status_code"]
	observation := seen["oie_instance_disk_retype_observation_healthy"]
	start := seen["oie_instance_disk_retype_start_timestamp_seconds"]
	if active == nil || active.GetGauge().GetValue() != 1 {
		t.Fatalf("active metric=%v", active)
	}
	if progress == nil || math.Abs(progress.GetGauge().GetValue()-10.295297) > 0.000001 {
		t.Fatalf("progress metric=%v", progress)
	}
	if status == nil || status.GetGauge().GetValue() != volumeRetypeStatusActive {
		t.Fatalf("status metric=%v", status)
	}
	if observation == nil || observation.GetGauge().GetValue() != 1 {
		t.Fatalf("observation health metric=%v", observation)
	}
	if start == nil || start.GetGauge().GetValue() <= 0 {
		t.Fatalf("start metric=%v", start)
	}
	labels := dataIntegrityMetricLabels(active)
	for _, required := range []string{
		`domain="instance-0000342e"`,
		`server_name="retype-server"`,
		`volume_uuid="volume-d2d5547f-8b38-42e3-95ba-40e720dc4259"`,
		`disk_type="volumes"`,
		`disk_path="vde"`,
		`destination_volume_uuid="volume-b885bfa5-bb3f-47b7-bd49-3980fae73ce8"`,
		`destination_disk_type="premium"`,
	} {
		if !strings.Contains(labels, required) {
			t.Errorf("active labels %s omit %s", labels, required)
		}
	}

	stateMu.Lock()
	current = end
	xmlDescription = strings.Replace(activeVolumeRetypeXML, `job="copy"`, `job="copy" ready="yes"`, 1)
	stateMu.Unlock()
	mc.refreshVolumeRetypes(records, metadata)
	metrics = mc.volumeRetypeMetrics(time.Now())
	if len(metrics) != 6 {
		t.Fatalf("copy-ready metrics=%d, want active, progress, status, observation health, start, and ready timestamp", len(metrics))
	}
	seen = make(map[string]*dto.Metric)
	for _, metric := range metrics {
		name := descNameRE.FindStringSubmatch(metric.Desc().String())[1]
		seen[name] = metricDTO(t, metric)
	}
	if got := seen["oie_instance_disk_retype_active"].GetGauge().GetValue(); got != 1 {
		t.Fatalf("copy-ready active=%v, want 1", got)
	}
	if got := seen["oie_instance_disk_retype_status_code"].GetGauge().GetValue(); got != volumeRetypeStatusReady {
		t.Fatalf("copy-ready status=%v, want %d", got, volumeRetypeStatusReady)
	}
	if got := seen["oie_instance_disk_retype_progress_percent"].GetGauge().GetValue(); got != 100 {
		t.Fatalf("copy-ready progress=%v, want 100", got)
	}
	readyObserved := seen["oie_instance_disk_retype_ready_timestamp_seconds"]
	if readyObserved == nil || readyObserved.GetGauge().GetValue() <= 0 {
		t.Fatalf("copy-ready timestamp=%v", readyObserved)
	}
	mc.refreshVolumeRetypes(records, metadata)
	seen = make(map[string]*dto.Metric)
	for _, metric := range mc.volumeRetypeMetrics(time.Now()) {
		name := descNameRE.FindStringSubmatch(metric.Desc().String())[1]
		seen[name] = metricDTO(t, metric)
	}
	if got := seen["oie_instance_disk_retype_ready_timestamp_seconds"].GetGauge().GetValue(); got != readyObserved.GetGauge().GetValue() {
		t.Fatalf("ready observation changed from %v to %v", readyObserved.GetGauge().GetValue(), got)
	}

	stateMu.Lock()
	found = 0
	xmlDescription = `<domain><devices><disk type="network" device="disk"><source protocol="rbd" name="premium/volume-b885bfa5-bb3f-47b7-bd49-3980fae73ce8"/><target dev="vde"/></disk></devices></domain>`
	stateMu.Unlock()
	mc.refreshVolumeRetypes(records, metadata)
	metrics = mc.volumeRetypeMetrics(time.Now())
	if len(metrics) != 5 {
		t.Fatalf("completed retype metrics=%d, want active, status, start, ready, and end", len(metrics))
	}
	seen = make(map[string]*dto.Metric)
	for _, metric := range metrics {
		name := descNameRE.FindStringSubmatch(metric.Desc().String())[1]
		seen[name] = metricDTO(t, metric)
	}
	if got := seen["oie_instance_disk_retype_active"].GetGauge().GetValue(); got != 0 {
		t.Fatalf("completed active=%v, want 0", got)
	}
	if got := seen["oie_instance_disk_retype_status_code"].GetGauge().GetValue(); got != volumeRetypeStatusSuccess {
		t.Fatalf("completed status=%v, want %d", got, volumeRetypeStatusSuccess)
	}
	if seen["oie_instance_disk_retype_progress_percent"] != nil {
		t.Fatal("completed retype retained a progress series")
	}
	if got := seen["oie_instance_disk_retype_ready_timestamp_seconds"].GetGauge().GetValue(); got != readyObserved.GetGauge().GetValue() {
		t.Fatalf("completed ready observation=%v, want %v", got, readyObserved.GetGauge().GetValue())
	}
	if got := seen["oie_instance_disk_retype_end_timestamp_seconds"].GetGauge().GetValue(); got <= start.GetGauge().GetValue() {
		t.Fatalf("completion timestamp=%v, start=%v", got, start.GetGauge().GetValue())
	}
	mc.volumeRetypeMu.Lock()
	if mc.volumeRetypeResults.Success != 1 || mc.volumeRetypeResults.Unsuccessful != 0 || mc.volumeRetypeResults.Unknown != 0 {
		t.Fatalf("success counters=%+v", mc.volumeRetypeResults)
	}
	mc.volumeRetypeMu.Unlock()

	stateMu.Lock()
	found = 1
	xmlDescription = activeVolumeRetypeXML
	stateMu.Unlock()
	mc.refreshVolumeRetypes(records, metadata)
	stateMu.Lock()
	found = 0
	xmlDescription = `<domain><devices><disk type="network" device="disk"><source protocol="rbd" name="volumes/volume-d2d5547f-8b38-42e3-95ba-40e720dc4259"/><target dev="vde"/></disk></devices></domain>`
	stateMu.Unlock()
	mc.refreshVolumeRetypes(records, metadata)
	mc.volumeRetypeMu.Lock()
	if mc.volumeRetypeResults.Unsuccessful != 1 {
		t.Fatalf("unsuccessful counters=%+v", mc.volumeRetypeResults)
	}
	mc.volumeRetypeMu.Unlock()

	stateMu.Lock()
	found = 1
	xmlDescription = activeVolumeRetypeXML
	stateMu.Unlock()
	mc.refreshVolumeRetypes(records, metadata)
	stateMu.Lock()
	found = 0
	xmlDescription = `<domain><devices><disk type="network" device="disk"><source protocol="rbd" name="archive/volume-11111111-1111-4111-8111-111111111111"/><target dev="vde"/></disk></devices></domain>`
	stateMu.Unlock()
	mc.refreshVolumeRetypes(records, metadata)
	mc.volumeRetypeMu.Lock()
	if mc.volumeRetypeResults.Unknown != 1 {
		t.Fatalf("unknown counters=%+v", mc.volumeRetypeResults)
	}
	mc.volumeRetypeMu.Unlock()
}

func TestVolumeRetypeNewerXMLCompletionWinsOverEarlierBlockJobResult(t *testing.T) {
	for _, test := range []struct {
		name    string
		refresh func(*MetricsCollector, []libvirt.DomainStatsRecord, map[string]*DomainStatic)
	}{
		{
			name: "full collection",
			refresh: func(mc *MetricsCollector, records []libvirt.DomainStatsRecord, metadata map[string]*DomainStatic) {
				mc.refreshVolumeRetypes(records, metadata)
			},
		},
		{
			name: "fast poller",
			refresh: func(mc *MetricsCollector, _ []libvirt.DomainStatsRecord, _ map[string]*DomainStatic) {
				mc.refreshActiveVolumeRetypes(time.Now())
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
			activeState, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
			if err != nil {
				t.Fatal(err)
			}
			job := volumeRetypeJobFromCandidate(domain, meta, activeState.Candidates["vde"], time.Now())
			job.NextBlockPollAt = time.Time{}
			key := volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}
			mc.volumeRetypeJobs[key] = job

			// Model a pivot between the two ordered observations: block-info first
			// still sees COPY, while the subsequent XML already has the destination
			// as its live source and no mirror.
			mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
				return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, 100, 100, nil
			}
			mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
				return `<domain><devices><disk type="network" device="disk"><source protocol="rbd" name="premium/volume-b885bfa5-bb3f-47b7-bd49-3980fae73ce8"/><target dev="vde"/></disk></devices></domain>`, nil
			}

			test.refresh(mc, []libvirt.DomainStatsRecord{{Dom: domain}}, map[string]*DomainStatic{instanceUUID: meta})

			mc.volumeRetypeMu.Lock()
			defer mc.volumeRetypeMu.Unlock()
			if _, active := mc.volumeRetypeJobs[key]; active {
				t.Fatal("newer terminal XML was ignored in favor of the earlier block-job response")
			}
			completion, exists := mc.volumeRetypeCompleted[volumeRetypeCompletionKeyForJob(job)]
			if !exists || completion.Result != "success" {
				t.Fatalf("completion=%+v exists=%v, want successful terminal observation", completion, exists)
			}
			if mc.volumeRetypeResults.Success != 1 {
				t.Fatalf("result counters=%+v, want one success", mc.volumeRetypeResults)
			}
		})
	}
}

func TestVolumeRetypeIdleDomainsDoNotCreateBlockRPCsOrSeries(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	blockCalls := 0
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		return `<domain><devices><disk type="network" device="disk"><source protocol="rbd" name="volumes/volume-d2d5547f-8b38-42e3-95ba-40e720dc4259"/><target dev="vde"/></disk></devices></domain>`, nil
	}
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		blockCalls++
		return 0, 0, 0, 0, 0, nil
	}
	mc.refreshVolumeRetypes(
		[]libvirt.DomainStatsRecord{{Dom: domain}},
		map[string]*DomainStatic{instanceUUID: meta},
	)
	if blockCalls != 0 {
		t.Fatalf("idle domain caused %d block-job RPCs, want zero", blockCalls)
	}
	if got := len(mc.volumeRetypeMetrics(time.Now())); got != 0 {
		t.Fatalf("idle domain emitted %d per-volume retype metrics", got)
	}
}

func TestVolumeRetypeFastPollUpdatesProgressAndPublishesCompletion(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	records := []libvirt.DomainStatsRecord{{Dom: domain}}
	metadata := map[string]*DomainStatic{instanceUUID: meta}

	var stateMu sync.Mutex
	xmlDescription := activeVolumeRetypeXML
	found := int32(1)
	current := uint64(10)
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		stateMu.Lock()
		defer stateMu.Unlock()
		return xmlDescription, nil
	}
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		stateMu.Lock()
		defer stateMu.Unlock()
		return found, int32(libvirt.DomainBlockJobTypeCopy), 0, current, 100, nil
	}

	mc.refreshVolumeRetypes(records, metadata)
	key := volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}
	mc.volumeRetypeMu.Lock()
	observedStart := mc.volumeRetypeJobs[key].ObservedStartAt
	mc.volumeRetypeMu.Unlock()
	if observedStart.IsZero() {
		t.Fatal("initial discovery omitted the observed start timestamp")
	}

	stateMu.Lock()
	current = 60
	stateMu.Unlock()
	pollAt := time.Now().Add(volumeRetypeBlockPollInterval)
	mc.refreshActiveVolumeRetypes(pollAt)
	mc.volumeRetypeMu.Lock()
	job := mc.volumeRetypeJobs[key]
	mc.volumeRetypeMu.Unlock()
	if !job.ProgressAvailable || job.ProgressPercent != 60 {
		t.Fatalf("fast-polled progress=%v/%v, want 60/true", job.ProgressPercent, job.ProgressAvailable)
	}
	if !job.ObservedStartAt.Equal(observedStart) {
		t.Fatalf("fast poll changed observed start from %v to %v", observedStart, job.ObservedStartAt)
	}
	if job.Ready || !job.ReadyObservedAt.IsZero() {
		t.Fatalf("copying job was incorrectly marked ready: %+v", job)
	}

	stateMu.Lock()
	current = 100
	xmlDescription = strings.Replace(activeVolumeRetypeXML, `job="copy"`, `job="copy" ready="yes"`, 1)
	stateMu.Unlock()
	readyAt := pollAt.Add(volumeRetypeActivePollInterval)
	mc.refreshActiveVolumeRetypes(readyAt)
	mc.volumeRetypeMu.Lock()
	job = mc.volumeRetypeJobs[key]
	mc.volumeRetypeMu.Unlock()
	if !job.Ready || !job.ReadyObservedAt.Equal(readyAt) {
		t.Fatalf("fast poll did not publish copy-ready at %v: %+v", readyAt, job)
	}
	seen := make(map[string]*dto.Metric)
	for _, metric := range mc.volumeRetypeMetrics(readyAt) {
		name := descNameRE.FindStringSubmatch(metric.Desc().String())[1]
		seen[name] = metricDTO(t, metric)
	}
	if got := seen["oie_instance_disk_retype_status_code"].GetGauge().GetValue(); got != volumeRetypeStatusReady {
		t.Fatalf("fast-polled ready status=%v, want %d", got, volumeRetypeStatusReady)
	}
	if got := seen["oie_instance_disk_retype_ready_timestamp_seconds"].GetGauge().GetValue(); got != volumeRetypeTimestamp(readyAt) {
		t.Fatalf("fast-polled ready timestamp=%v, want %v", got, volumeRetypeTimestamp(readyAt))
	}

	stateMu.Lock()
	found = 0
	xmlDescription = `<domain><devices><disk type="network" device="disk"><source protocol="rbd" name="premium/volume-b885bfa5-bb3f-47b7-bd49-3980fae73ce8"/><target dev="vde"/></disk></devices></domain>`
	stateMu.Unlock()
	completedAt := readyAt.Add(volumeRetypeActivePollInterval)
	mc.refreshActiveVolumeRetypes(completedAt)
	mc.volumeRetypeMu.Lock()
	_, stillActive := mc.volumeRetypeJobs[key]
	completion, retained := mc.volumeRetypeCompleted[volumeRetypeCompletionKeyForJob(job)]
	mc.volumeRetypeMu.Unlock()
	if stillActive || !retained {
		t.Fatalf("fast completion state active=%v retained=%v", stillActive, retained)
	}
	if completion.Result != "success" || !completion.CompletedAt.Equal(completedAt) {
		t.Fatalf("fast completion=%+v", completion)
	}
}

func TestVolumeRetypeFastPollDoesNoWorkWithoutActiveJobs(t *testing.T) {
	mc, _, _, _ := newVolumeRetypeTestCollector(t)
	blockCalls := 0
	xmlCalls := 0
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		blockCalls++
		return 0, 0, 0, 0, 0, nil
	}
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		xmlCalls++
		return "<domain/>", nil
	}
	mc.refreshActiveVolumeRetypes(time.Now())
	if blockCalls != 0 || xmlCalls != 0 {
		t.Fatalf("idle fast poll made block/XML calls=%d/%d", blockCalls, xmlCalls)
	}
}

func TestVolumeRetypeBlockPollingIsRateLimitedAndBacksOffAfterFailure(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	records := []libvirt.DomainStatsRecord{{Dom: domain}}
	metadata := map[string]*DomainStatic{instanceUUID: meta}
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		return activeVolumeRetypeXML, nil
	}

	var stateMu sync.Mutex
	blockCalls := 0
	failNext := false
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		stateMu.Lock()
		defer stateMu.Unlock()
		blockCalls++
		if failNext {
			failNext = false
			return 0, 0, 0, 0, 0, fmt.Errorf("cannot acquire state change lock")
		}
		return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, 25, 100, nil
	}

	mc.refreshVolumeRetypes(records, metadata)
	key := volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}
	mc.volumeRetypeMu.Lock()
	nextPoll := mc.volumeRetypeJobs[key].NextBlockPollAt
	mc.volumeRetypeMu.Unlock()
	if nextPoll.IsZero() {
		t.Fatal("initial block-job query did not schedule its next poll")
	}

	mc.refreshActiveVolumeRetypes(nextPoll.Add(-time.Nanosecond))
	stateMu.Lock()
	if blockCalls != 1 {
		t.Fatalf("block-job calls before interval=%d, want 1", blockCalls)
	}
	failNext = true
	stateMu.Unlock()

	mc.refreshActiveVolumeRetypes(nextPoll)
	mc.volumeRetypeMu.Lock()
	job := mc.volumeRetypeJobs[key]
	mc.volumeRetypeMu.Unlock()
	stateMu.Lock()
	if blockCalls != 2 {
		t.Fatalf("block-job calls at interval=%d, want 2", blockCalls)
	}
	stateMu.Unlock()
	if !job.ObservationAttempted || job.ObservationHealthy || job.ProgressAvailable {
		t.Fatalf("failed observation state=%+v", job)
	}
	wantRetry := nextPoll.Add(volumeRetypeBlockErrorBackoff)
	if !job.NextBlockPollAt.Equal(wantRetry) {
		t.Fatalf("retry=%v, want %v", job.NextBlockPollAt, wantRetry)
	}

	seen := make(map[string]*dto.Metric)
	for _, metric := range mc.volumeRetypeMetrics(nextPoll) {
		name := descNameRE.FindStringSubmatch(metric.Desc().String())[1]
		seen[name] = metricDTO(t, metric)
	}
	if got := seen["oie_instance_disk_retype_observation_healthy"].GetGauge().GetValue(); got != 0 {
		t.Fatalf("failed observation metric=%v, want 0", got)
	}
	if seen["oie_instance_disk_retype_progress_percent"] != nil {
		t.Fatal("failed observation retained stale progress")
	}

	mc.refreshActiveVolumeRetypes(wantRetry.Add(-time.Nanosecond))
	stateMu.Lock()
	if blockCalls != 2 {
		t.Fatalf("block-job calls during backoff=%d, want 2", blockCalls)
	}
	stateMu.Unlock()
	mc.refreshActiveVolumeRetypes(wantRetry)
	mc.volumeRetypeMu.Lock()
	job = mc.volumeRetypeJobs[key]
	mc.volumeRetypeMu.Unlock()
	stateMu.Lock()
	if blockCalls != 3 {
		t.Fatalf("block-job calls after backoff=%d, want 3", blockCalls)
	}
	stateMu.Unlock()
	if !job.ObservationHealthy || !job.ProgressAvailable || job.ProgressPercent != 25 {
		t.Fatalf("recovered observation state=%+v", job)
	}
}

func TestVolumeRetypeBlockQueriesAreSerializedWithinDomain(t *testing.T) {
	mc, domain, instanceUUID, _ := newVolumeRetypeTestCollector(t)
	var stateMu sync.Mutex
	activeCalls := 0
	maximumCalls := 0
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		stateMu.Lock()
		activeCalls++
		if activeCalls > maximumCalls {
			maximumCalls = activeCalls
		}
		stateMu.Unlock()
		time.Sleep(10 * time.Millisecond)
		stateMu.Lock()
		activeCalls--
		stateMu.Unlock()
		return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, 1, 10, nil
	}

	requests := []volumeRetypeBlockRequest{
		{Key: volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vdb"}, Domain: domain, DiskPath: "vdb"},
		{Key: volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vdc"}, Domain: domain, DiskPath: "vdc"},
	}
	results := mc.queryVolumeRetypeBlockJobs(nil, requests, time.Now().Add(time.Second), volumeRetypeCursorCollectionBlock)
	if len(results) != len(requests) {
		t.Fatalf("block-job results=%d, want %d", len(results), len(requests))
	}
	for key, result := range results {
		if result.Err != nil {
			t.Fatalf("block-job result %v failed: %v", key, result.Err)
		}
	}
	stateMu.Lock()
	defer stateMu.Unlock()
	if maximumCalls != 1 {
		t.Fatalf("same-domain concurrent block-job calls=%d, want 1", maximumCalls)
	}
}

func TestVolumeRetypeBlockQueriesRotateDisksWithinDomain(t *testing.T) {
	mc, domain, instanceUUID, _ := newVolumeRetypeTestCollector(t)
	requests := []volumeRetypeBlockRequest{
		{Key: volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vdc"}, Domain: domain, DiskPath: "vdc"},
		{Key: volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vda"}, Domain: domain, DiskPath: "vda"},
		{Key: volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vdb"}, Domain: domain, DiskPath: "vdb"},
	}

	var observed []string
	mc.libvirtBlockJobRPCOverride = func(_ *libvirt.Libvirt, _ libvirt.Domain, diskPath string, _ uint32) (int32, int32, uint64, uint64, uint64, error) {
		observed = append(observed, diskPath)
		return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, 1, 10, nil
	}

	wantOrders := [][]string{
		{"vda", "vdb", "vdc"},
		{"vdb", "vdc", "vda"},
		{"vdc", "vda", "vdb"},
	}
	for pass, want := range wantOrders {
		observed = nil
		results := mc.queryVolumeRetypeBlockJobs(nil, requests, time.Now().Add(time.Second), volumeRetypeCursorCollectionBlock)
		if len(results) != len(requests) {
			t.Fatalf("pass %d results=%d, want %d", pass, len(results), len(requests))
		}
		if !slices.Equal(observed, want) {
			t.Fatalf("pass %d disk order=%v, want %v", pass, observed, want)
		}
	}

	if got := len(mc.volumeRetypeDiskCursors); got != 1 {
		t.Fatalf("disk cursor entries=%d, want one active multi-disk domain", got)
	}
	job := volumeRetypeJob{Domain: domain, InstanceUUID: instanceUUID, DiskPath: "vda"}
	mc.pruneVolumeRetypeDiskCursors(map[volumeRetypeKey]volumeRetypeJob{
		{InstanceUUID: instanceUUID, DiskPath: "vda"}: job,
	})
	if got := len(mc.volumeRetypeDiskCursors); got != 0 {
		t.Fatalf("disk cursor entries after domain drops below two jobs=%d, want zero", got)
	}
}

func TestVolumeRetypeDiskCursorAdvancesOnlyAfterRPCStarts(t *testing.T) {
	mc, domain, instanceUUID, _ := newVolumeRetypeTestCollector(t)
	requests := []volumeRetypeBlockRequest{
		{Key: volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vdb"}, Domain: domain, DiskPath: "vdb"},
		{Key: volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vda"}, Domain: domain, DiskPath: "vda"},
	}

	reservations := make([]libvirt.Domain, volumeRetypeRPCWorkers)
	for index := range reservations {
		uuid, _ := scalingUUID(index + 100)
		reservations[index] = libvirt.Domain{Name: fmt.Sprintf("reserved-%d", index), UUID: uuid}
		if err := mc.beginVolumeRetypeBlockRPC(reservations[index]); err != nil {
			t.Fatalf("reserve global RPC slot %d: %v", index, err)
		}
	}
	results := mc.queryVolumeRetypeBlockJobs(nil, requests, time.Now().Add(time.Second), volumeRetypeCursorCollectionBlock)
	for key, result := range results {
		if !errors.Is(result.Err, errVolumeRetypeRPCCapacity) || result.RPCStarted {
			t.Fatalf("capacity-limited result %v=%+v, want not-started capacity error", key, result)
		}
	}
	for _, reservation := range reservations {
		mc.endVolumeRetypeBlockRPC(reservation)
	}

	var observed []string
	mc.libvirtBlockJobRPCOverride = func(_ *libvirt.Libvirt, _ libvirt.Domain, diskPath string, _ uint32) (int32, int32, uint64, uint64, uint64, error) {
		observed = append(observed, diskPath)
		return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, 1, 10, nil
	}
	results = mc.queryVolumeRetypeBlockJobs(nil, requests, time.Now().Add(time.Second), volumeRetypeCursorCollectionBlock)
	if len(results) != len(requests) {
		t.Fatalf("post-capacity results=%d, want %d", len(results), len(requests))
	}
	if want := []string{"vda", "vdb"}; !slices.Equal(observed, want) {
		t.Fatalf("first executable disk order=%v, want unadvanced order %v", observed, want)
	}
}

func TestVolumeRetypeTimedOutRPCPreventsDuplicateDomainQuery(t *testing.T) {
	mc, domain, _, _ := newVolumeRetypeTestCollector(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	var callsMu sync.Mutex
	calls := 0
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		enteredOnce.Do(func() { close(entered) })
		<-release
		return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, 1, 10, nil
	}

	first := mc.readVolumeRetypeBlockJob(nil, domain, "vdb", time.Now().Add(20*time.Millisecond))
	if first.Err == nil || !strings.Contains(first.Err.Error(), "timed out") {
		t.Fatalf("first query error=%v, want local timeout", first.Err)
	}
	<-entered
	second := mc.readVolumeRetypeBlockJob(nil, domain, "vdc", time.Now().Add(time.Second))
	if second.Err == nil || !strings.Contains(second.Err.Error(), "already in flight") {
		t.Fatalf("second query error=%v, want in-flight protection", second.Err)
	}
	callsMu.Lock()
	if calls != 1 {
		t.Fatalf("RPC calls while first was blocked=%d, want 1", calls)
	}
	callsMu.Unlock()
	close(release)

	deadline := time.After(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		mc.volumeRetypeRPCMu.Lock()
		inflight := len(mc.volumeRetypeRPCInflight)
		mc.volumeRetypeRPCMu.Unlock()
		if inflight == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("completed block-job RPC remained marked in flight")
		case <-ticker.C:
		}
	}
}

func TestVolumeRetypeBlockRPCGuardEnforcesGlobalCapacity(t *testing.T) {
	mc, _, _, _ := newVolumeRetypeTestCollector(t)
	domains := make([]libvirt.Domain, volumeRetypeRPCWorkers+1)
	for index := range domains {
		uuid, _ := scalingUUID(index + 1)
		domains[index] = libvirt.Domain{Name: fmt.Sprintf("domain-%d", index), UUID: uuid}
	}

	for index := 0; index < volumeRetypeRPCWorkers; index++ {
		if err := mc.beginVolumeRetypeBlockRPC(domains[index]); err != nil {
			t.Fatalf("reserve RPC slot %d: %v", index, err)
		}
	}

	if err := mc.beginVolumeRetypeBlockRPC(domains[volumeRetypeRPCWorkers]); !errors.Is(err, errVolumeRetypeRPCCapacity) {
		t.Fatalf("fifth RPC reservation error=%v, want capacity exhaustion", err)
	}
	if err := mc.beginVolumeRetypeBlockRPC(domains[0]); !errors.Is(err, errVolumeRetypeRPCAlreadyInFlight) {
		t.Fatalf("duplicate domain reservation error=%v, want already in flight", err)
	}

	mc.endVolumeRetypeBlockRPC(domains[0])
	if err := mc.beginVolumeRetypeBlockRPC(domains[volumeRetypeRPCWorkers]); err != nil {
		t.Fatalf("reuse released RPC capacity: %v", err)
	}

	for index := 1; index < len(domains); index++ {
		mc.endVolumeRetypeBlockRPC(domains[index])
	}
	mc.volumeRetypeRPCMu.Lock()
	inflight := len(mc.volumeRetypeRPCInflight)
	mc.volumeRetypeRPCMu.Unlock()
	if inflight != 0 {
		t.Fatalf("released RPC guards left %d calls in flight", inflight)
	}
}

func TestVolumeRetypeRPCOrderRotatesFairlyAcrossDomains(t *testing.T) {
	mc, _, _, _ := newVolumeRetypeTestCollector(t)
	const domainCount = 10
	seen := make(map[string]struct{}, domainCount)
	ordered := make([]string, 0, domainCount)
	for index := 0; index < domainCount; index++ {
		ordered = append(ordered, fmt.Sprintf("domain-%02d", index))
	}
	for pass := 0; pass < 3; pass++ {
		rotated, start := mc.rotateVolumeRetypeRPCOrder(ordered, volumeRetypeCursorCollectionBlock)
		advance := volumeRetypeWorkerCount(len(rotated))
		for _, domainKey := range rotated[:advance] {
			seen[domainKey] = struct{}{}
		}
		mc.advanceVolumeRetypeRPCCursor(len(ordered), start, advance, volumeRetypeCursorCollectionBlock)
	}
	if len(seen) != domainCount {
		t.Fatalf("three rotated worker batches reached %d/%d domains", len(seen), domainCount)
	}
}

func TestVolumeRetypeRPCOrderMovesPastHungHeadAndCoversLaterDomains(t *testing.T) {
	mc, _, _, _ := newVolumeRetypeTestCollector(t)
	const domainCount = 10
	ordered := make([]string, 0, domainCount)
	for index := 0; index < domainCount; index++ {
		ordered = append(ordered, fmt.Sprintf("domain-%02d", index))
	}
	hungHead := ordered[0]
	seen := make(map[string]struct{}, domainCount-1)

	// Model one timed-out raw RPC that retains the first domain's guard. Three
	// later domains can still start in each pass because the global limit is
	// four. The hung head must not pin the cursor at zero and starve domains
	// outside the first worker window.
	for pass := 0; pass < 4; pass++ {
		rotated, start := mc.rotateVolumeRetypeRPCOrder(ordered, volumeRetypeCursorCollectionBlock)
		started := make(map[string]bool, volumeRetypeRPCWorkers-1)
		for _, domainKey := range rotated {
			if domainKey == hungHead {
				continue
			}
			started[domainKey] = true
			seen[domainKey] = struct{}{}
			if len(started) == volumeRetypeRPCWorkers-1 {
				break
			}
		}
		advance := volumeRetypeRPCStartedAdvance(rotated, started)
		if advance == 0 {
			t.Fatalf("pass %d made no cursor progress despite started RPCs: %v", pass, started)
		}
		mc.advanceVolumeRetypeRPCCursor(len(ordered), start, advance, volumeRetypeCursorCollectionBlock)
	}

	if len(seen) != domainCount-1 {
		t.Fatalf("hung-head rotation reached %d/%d later domains: %v", len(seen), domainCount-1, seen)
	}

	// A pass in which global capacity prevents every raw call from starting is
	// not progress and must retain the current ordering for the next retry.
	_, before := mc.rotateVolumeRetypeRPCOrder(ordered, volumeRetypeCursorCollectionBlock)
	if advance := volumeRetypeRPCStartedAdvance(ordered, nil); advance != 0 {
		t.Fatalf("all-blocked pass advance=%d, want 0", advance)
	}
	mc.advanceVolumeRetypeRPCCursor(len(ordered), before, 0, volumeRetypeCursorCollectionBlock)
	_, after := mc.rotateVolumeRetypeRPCOrder(ordered, volumeRetypeCursorCollectionBlock)
	if after != before {
		t.Fatalf("all-blocked pass moved cursor from %d to %d", before, after)
	}
}

func TestVolumeRetypeRPCCursorClassesAreIndependent(t *testing.T) {
	mc, _, _, _ := newVolumeRetypeTestCollector(t)
	ordered := []string{
		"domain-00",
		"domain-01",
		"domain-02",
		"domain-03",
		"domain-04",
		"domain-05",
	}

	_, collectionStart := mc.rotateVolumeRetypeRPCOrder(ordered, volumeRetypeCursorCollectionBlock)
	mc.advanceVolumeRetypeRPCCursor(
		len(ordered),
		collectionStart,
		4,
		volumeRetypeCursorCollectionBlock,
	)
	_, discoveryStart := mc.rotateVolumeRetypeRPCOrder(ordered[:2], volumeRetypeCursorDiscoveryBlock)
	mc.advanceVolumeRetypeRPCCursor(
		2,
		discoveryStart,
		1,
		volumeRetypeCursorDiscoveryBlock,
	)
	_, xmlStart := mc.rotateVolumeRetypeRPCOrder(ordered[:3], volumeRetypeCursorCompletionXML)
	mc.advanceVolumeRetypeRPCCursor(
		3,
		xmlStart,
		2,
		volumeRetypeCursorCompletionXML,
	)

	for _, test := range []struct {
		class volumeRetypeCursorClass
		want  int
	}{
		{class: volumeRetypeCursorCollectionBlock, want: 4},
		{class: volumeRetypeCursorDiscoveryBlock, want: 1},
		{class: volumeRetypeCursorCompletionXML, want: 2},
		{class: volumeRetypeCursorDiscoveryXML, want: 0},
		{class: volumeRetypeCursorActivePollBlock, want: 0},
		{class: volumeRetypeCursorActivePollXML, want: 0},
	} {
		_, got := mc.rotateVolumeRetypeRPCOrder(ordered, test.class)
		if got != test.want {
			t.Errorf("cursor class %d start=%d, want %d", test.class, got, test.want)
		}
	}
}

func TestVolumeRetypeBlockDomainCursorDoesNotAdvanceWithoutRPCStart(t *testing.T) {
	mc, _, _, _ := newVolumeRetypeTestCollector(t)
	const domainCount = 8
	requests := make([]volumeRetypeBlockRequest, 0, domainCount)
	for index := 0; index < domainCount; index++ {
		uuid, _ := scalingUUID(index + 200)
		domain := libvirt.Domain{Name: fmt.Sprintf("domain-%02d", index), UUID: uuid}
		requests = append(requests, volumeRetypeBlockRequest{
			Key: volumeRetypeKey{
				InstanceUUID: validLibvirtDomainUUID(uuid),
				DiskPath:     "vda",
			},
			Domain:   domain,
			DiskPath: "vda",
		})
	}
	mc.volumeRetypeRPCMu.Lock()
	mc.volumeRetypeRPCCursors[volumeRetypeCursorCollectionBlock] = 4
	mc.volumeRetypeRPCMu.Unlock()

	reservations := make([]libvirt.Domain, volumeRetypeRPCWorkers)
	for index := range reservations {
		uuid, _ := scalingUUID(index + 300)
		reservations[index] = libvirt.Domain{Name: fmt.Sprintf("reserved-%d", index), UUID: uuid}
		if err := mc.beginVolumeRetypeBlockRPC(reservations[index]); err != nil {
			t.Fatalf("reserve global block-job slot %d: %v", index, err)
		}
	}
	results := mc.queryVolumeRetypeBlockJobs(nil, requests, time.Now().Add(time.Second), volumeRetypeCursorCollectionBlock)
	for key, result := range results {
		if result.RPCStarted || !errors.Is(result.Err, errVolumeRetypeRPCCapacity) {
			t.Fatalf("capacity-limited result %v=%+v, want a not-started result", key, result)
		}
	}
	mc.volumeRetypeRPCMu.Lock()
	cursor := mc.volumeRetypeRPCCursors[volumeRetypeCursorCollectionBlock]
	mc.volumeRetypeRPCMu.Unlock()
	if cursor != 4 {
		t.Fatalf("block domain cursor=%d after no-start cycle, want 4", cursor)
	}
	for _, reservation := range reservations {
		mc.endVolumeRetypeBlockRPC(reservation)
	}
}

func TestVolumeRetypeXMLDomainCursorDoesNotAdvanceWithoutRPCStart(t *testing.T) {
	mc, _, _, _ := newVolumeRetypeTestCollector(t)
	const domainCount = 8
	domains := make(map[string]libvirt.Domain, domainCount)
	for index := 0; index < domainCount; index++ {
		uuid, _ := scalingUUID(index + 400)
		domains[validLibvirtDomainUUID(uuid)] = libvirt.Domain{
			Name: fmt.Sprintf("domain-%02d", index),
			UUID: uuid,
		}
	}
	mc.volumeRetypeRPCMu.Lock()
	mc.volumeRetypeRPCCursors[volumeRetypeCursorCompletionXML] = 4
	mc.volumeRetypeRPCMu.Unlock()
	mc.im.xmlRPCSem = make(chan struct{}, volumeRetypeRPCWorkers)
	for index := 0; index < volumeRetypeRPCWorkers; index++ {
		mc.im.xmlRPCSem <- struct{}{}
	}

	results := mc.fetchVolumeRetypeXML(nil, domains, time.Now().Add(25*time.Millisecond), volumeRetypeCursorCompletionXML)
	for uuid, result := range results {
		if result.RPCStarted {
			t.Fatalf("capacity-limited XML result %s=%+v, want a not-started result", uuid, result)
		}
		var timeoutErr *libvirtRPCTimeoutError
		if !errors.As(result.Err, &timeoutErr) {
			t.Fatalf("capacity-limited XML result %s=%v, want timeout", uuid, result.Err)
		}
	}
	mc.volumeRetypeRPCMu.Lock()
	cursor := mc.volumeRetypeRPCCursors[volumeRetypeCursorCompletionXML]
	mc.volumeRetypeRPCMu.Unlock()
	if cursor != 4 {
		t.Fatalf("XML domain cursor=%d after no-start cycle, want 4", cursor)
	}
	for index := 0; index < volumeRetypeRPCWorkers; index++ {
		<-mc.im.xmlRPCSem
	}
}

func TestVolumeRetypePollWindowStartsAfterObservationCompletes(t *testing.T) {
	for _, test := range []struct {
		name     string
		result   volumeRetypeBlockResult
		interval time.Duration
	}{
		{
			name:     "success",
			result:   volumeRetypeBlockResult{Found: true, JobType: int32(libvirt.DomainBlockJobTypeCopy), Current: 50, End: 100},
			interval: volumeRetypeBlockPollInterval,
		},
		{
			name:     "failure",
			result:   volumeRetypeBlockResult{Err: fmt.Errorf("state-change lock unavailable")},
			interval: volumeRetypeBlockErrorBackoff,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
			state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
			if err != nil {
				t.Fatal(err)
			}
			job := volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], time.Now())
			job.NextBlockPollAt = time.Time{}
			key := volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}
			mc.volumeRetypeJobs[key] = job
			mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
				return activeVolumeRetypeXML, nil
			}
			mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
				time.Sleep(50 * time.Millisecond)
				return boolToInt32(test.result.Found), test.result.JobType, 0, test.result.Current, test.result.End, test.result.Err
			}

			mc.refreshActiveVolumeRetypes(time.Now())
			finishedAt := time.Now()
			mc.volumeRetypeMu.Lock()
			updated := mc.volumeRetypeJobs[key]
			mc.volumeRetypeMu.Unlock()
			minimum := finishedAt.Add(test.interval - 20*time.Millisecond)
			if updated.NextBlockPollAt.Before(minimum) {
				t.Fatalf("next poll=%v, want no earlier than %v after completed RPC", updated.NextBlockPollAt, minimum)
			}
		})
	}
}

func boolToInt32(value bool) int32 {
	if value {
		return 1
	}
	return 0
}

func TestVolumeRetypePollerIsCompletionPaced(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
	if err != nil {
		t.Fatal(err)
	}
	job := volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], time.Now())
	job.NextBlockPollAt = time.Now().Add(time.Hour)
	mc.volumeRetypeJobs[volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}] = job

	var startsMu sync.Mutex
	starts := make([]time.Time, 0, 3)
	thirdStarted := make(chan struct{})
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		startsMu.Lock()
		starts = append(starts, time.Now())
		if len(starts) == 3 {
			close(thirdStarted)
		}
		startsMu.Unlock()
		time.Sleep(25 * time.Millisecond)
		return activeVolumeRetypeXML, nil
	}
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		t.Fatal("rate-limited block query unexpectedly ran")
		return 0, 0, 0, 0, 0, nil
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		mc.runVolumeRetypePoller(10*time.Millisecond, stop)
		close(done)
	}()
	select {
	case <-thirdStarted:
	case <-time.After(time.Second):
		t.Fatal("completion-paced poller did not run three times")
	}
	close(stop)
	<-done
	startsMu.Lock()
	defer startsMu.Unlock()
	for index := 1; index < 3; index++ {
		if separation := starts[index].Sub(starts[index-1]); separation < 30*time.Millisecond {
			t.Fatalf("poll starts separated by %v, want completed work plus interval", separation)
		}
	}
}

func TestVolumeRetypeFastPollerSkipsFullLibvirtWorkPhase(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
	if err != nil {
		t.Fatal(err)
	}
	job := volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], time.Now())
	job.NextBlockPollAt = time.Now().Add(time.Hour)
	mc.volumeRetypeJobs[volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}] = job

	xmlCalled := make(chan struct{}, 1)
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		xmlCalled <- struct{}{}
		return activeVolumeRetypeXML, nil
	}
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, 1, 10, nil
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	mc.volumeRetypeLibvirtWorkMu.Lock()
	go func() {
		mc.runVolumeRetypePoller(10*time.Millisecond, stop)
		close(done)
	}()
	time.Sleep(35 * time.Millisecond)
	select {
	case <-xmlCalled:
		t.Fatal("fast poller overlapped the full Libvirt work phase")
	default:
	}
	mc.volumeRetypeLibvirtWorkMu.Unlock()
	select {
	case <-xmlCalled:
	case <-time.After(time.Second):
		t.Fatal("fast poller did not resume after the Libvirt work phase")
	}
	close(stop)
	<-done
}

func TestVolumeRetypeFastPollerDoesNotOverlapCollectorLibvirtPhase(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
	if err != nil {
		t.Fatal(err)
	}
	job := volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], time.Now())
	job.NextBlockPollAt = time.Now().Add(time.Hour)
	mc.volumeRetypeJobs[volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}] = job

	collectionEntered := make(chan struct{})
	releaseCollection := make(chan struct{})
	mc.fetchDomainStatsOverride = func() ([]libvirt.DomainStatsRecord, float64, error) {
		close(collectionEntered)
		<-releaseCollection
		return nil, 0, fmt.Errorf("planned collection stop")
	}
	xmlCalled := make(chan struct{}, 1)
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		xmlCalled <- struct{}{}
		return activeVolumeRetypeXML, nil
	}
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, 1, 10, nil
	}

	metrics := make(chan prometheus.Metric, 1024)
	collectionDone := make(chan struct{})
	go func() {
		mc.collectHeavy(metrics)
		close(collectionDone)
	}()
	<-collectionEntered
	stop := make(chan struct{})
	pollerDone := make(chan struct{})
	go func() {
		mc.runVolumeRetypePoller(10*time.Millisecond, stop)
		close(pollerDone)
	}()
	time.Sleep(35 * time.Millisecond)
	select {
	case <-xmlCalled:
		t.Fatal("fast poller overlapped collectHeavy's Libvirt phase")
	default:
	}
	close(releaseCollection)
	select {
	case <-collectionDone:
	case <-time.After(time.Second):
		t.Fatal("collector did not leave the planned Libvirt phase")
	}
	select {
	case <-xmlCalled:
	case <-time.After(time.Second):
		t.Fatal("fast poller did not resume after collectHeavy released Libvirt work")
	}
	close(stop)
	<-pollerDone
}

func TestVolumeRetypeXMLWorkerQueueDeadlineDoesNotAbortSharedConnection(t *testing.T) {
	mc, domain, instanceUUID, _ := newVolumeRetypeTestCollector(t)
	conn := &libvirt.Libvirt{}
	mc.libvirtConn = conn
	mc.im.xmlRPCSem = make(chan struct{}, 1)
	mc.im.xmlRPCSem <- struct{}{}

	results := mc.fetchVolumeRetypeXML(
		conn,
		map[string]libvirt.Domain{instanceUUID: domain},
		time.Now().Add(20*time.Millisecond),
		volumeRetypeCursorCompletionXML,
	)
	result := results[instanceUUID]
	var timeoutErr *libvirtRPCTimeoutError
	if !errors.As(result.Err, &timeoutErr) || timeoutErr.RPCStarted {
		t.Fatalf("worker-queue result=%v, want local timeout before RPC start", result.Err)
	}
	mc.libvirtMu.Lock()
	retained := mc.libvirtConn
	mc.libvirtMu.Unlock()
	if retained != conn {
		t.Fatal("local worker-queue timeout aborted the shared Libvirt connection")
	}
	<-mc.im.xmlRPCSem
}

func TestVolumeRetypeXMLWireTimeoutAbortsSharedConnection(t *testing.T) {
	mc, domain, instanceUUID, _ := newVolumeRetypeTestCollector(t)
	conn := &libvirt.Libvirt{}
	mc.libvirtConn = conn
	release := make(chan struct{})
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		<-release
		return activeVolumeRetypeXML, nil
	}
	results := mc.fetchVolumeRetypeXML(
		conn,
		map[string]libvirt.Domain{instanceUUID: domain},
		time.Now().Add(20*time.Millisecond),
		volumeRetypeCursorCompletionXML,
	)
	close(release)
	result := results[instanceUUID]
	var timeoutErr *libvirtRPCTimeoutError
	if !errors.As(result.Err, &timeoutErr) || !timeoutErr.RPCStarted {
		t.Fatalf("wire result=%v, want timeout after RPC start", result.Err)
	}
	mc.libvirtMu.Lock()
	retained := mc.libvirtConn
	mc.libvirtMu.Unlock()
	if retained != nil {
		t.Fatal("wire timeout did not abort the shared Libvirt connection")
	}
}

func TestVolumeRetypeUnconfirmedEvictionDoesNotCreateOrDuplicateTerminalResult(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	records := []libvirt.DomainStatsRecord{{Dom: domain}}
	metadata := map[string]*DomainStatic{instanceUUID: meta}
	var stateMu sync.Mutex
	xmlDescription := activeVolumeRetypeXML
	found := int32(1)
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		stateMu.Lock()
		defer stateMu.Unlock()
		return xmlDescription, nil
	}
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		stateMu.Lock()
		defer stateMu.Unlock()
		return found, int32(libvirt.DomainBlockJobTypeCopy), 0, 25, 100, nil
	}

	mc.refreshVolumeRetypes(records, metadata)
	key := volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}
	mc.refreshVolumeRetypes(nil, nil)
	mc.volumeRetypeMu.Lock()
	_, activeAfterLoss := mc.volumeRetypeJobs[key]
	terminalAfterLoss := len(mc.volumeRetypeCompleted)
	countersAfterLoss := mc.volumeRetypeResults
	mc.volumeRetypeMu.Unlock()
	if activeAfterLoss || terminalAfterLoss != 0 || countersAfterLoss != (volumeRetypeResultCounters{}) {
		t.Fatalf("unconfirmed eviction active=%v terminals=%d counters=%+v", activeAfterLoss, terminalAfterLoss, countersAfterLoss)
	}

	mc.refreshVolumeRetypes(records, metadata)
	stateMu.Lock()
	found = 0
	xmlDescription = `<domain><devices><disk type="network" device="disk"><source protocol="rbd" name="premium/volume-b885bfa5-bb3f-47b7-bd49-3980fae73ce8"/><target dev="vde"/></disk></devices></domain>`
	stateMu.Unlock()
	mc.refreshVolumeRetypes(records, metadata)
	mc.volumeRetypeMu.Lock()
	counters := mc.volumeRetypeResults
	terminalCount := len(mc.volumeRetypeCompleted)
	mc.volumeRetypeMu.Unlock()
	if counters.Success != 1 || counters.Unsuccessful != 0 || counters.Unknown != 0 || terminalCount != 1 {
		t.Fatalf("rediscovered terminal outcome counters=%+v terminals=%d, want one success", counters, terminalCount)
	}
}

func TestVolumeRetypeReplacementOnSameDiskStartsFreshAndRetainsPriorResult(t *testing.T) {
	for _, fast := range []bool{false, true} {
		t.Run(fmt.Sprintf("fast=%v", fast), func(t *testing.T) {
			mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
			records := []libvirt.DomainStatsRecord{{Dom: domain}}
			metadata := map[string]*DomainStatic{instanceUUID: meta}
			const (
				sourceA      = "volumes/volume-d2d5547f-8b38-42e3-95ba-40e720dc4259"
				destinationA = "premium/volume-b885bfa5-bb3f-47b7-bd49-3980fae73ce8"
				destinationB = "archive/volume-11111111-1111-4111-8111-111111111111"
			)
			var stateMu sync.Mutex
			xmlDescription := volumeRetypeOperationXML(sourceA, destinationA, false)
			current := uint64(25)
			mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
				stateMu.Lock()
				defer stateMu.Unlock()
				return xmlDescription, nil
			}
			mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
				stateMu.Lock()
				defer stateMu.Unlock()
				return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, current, 100, nil
			}

			mc.refreshVolumeRetypes(records, metadata)
			key := volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}
			mc.volumeRetypeMu.Lock()
			first := mc.volumeRetypeJobs[key]
			first.NextBlockPollAt = time.Time{}
			mc.volumeRetypeJobs[key] = first
			mc.volumeRetypeMu.Unlock()
			time.Sleep(time.Millisecond)
			stateMu.Lock()
			xmlDescription = volumeRetypeOperationXML(destinationA, destinationB, false)
			current = 80
			stateMu.Unlock()
			if fast {
				mc.refreshActiveVolumeRetypes(time.Now())
			} else {
				mc.refreshVolumeRetypes(records, metadata)
			}

			mc.volumeRetypeMu.Lock()
			replacement := mc.volumeRetypeJobs[key]
			prior, retained := mc.volumeRetypeCompleted[volumeRetypeCompletionKeyForJob(first)]
			counters := mc.volumeRetypeResults
			mc.volumeRetypeMu.Unlock()
			if !retained || prior.Result != "success" || counters.Success != 1 {
				t.Fatalf("prior operation retained=%v result=%q counters=%+v", retained, prior.Result, counters)
			}
			if replacement.SourceName != destinationA || replacement.DestinationName != destinationB {
				t.Fatalf("replacement identity=%s -> %s", replacement.SourceName, replacement.DestinationName)
			}
			if !replacement.ObservedStartAt.After(first.ObservedStartAt) {
				t.Fatalf("replacement start=%v did not follow prior start=%v", replacement.ObservedStartAt, first.ObservedStartAt)
			}
			if replacement.ProgressAvailable || replacement.ObservationAttempted || replacement.Ready || !replacement.NextBlockPollAt.IsZero() {
				t.Fatalf("replacement inherited prior observation state: %+v", replacement)
			}
			if got := len(mc.volumeRetypeMetrics(time.Now())); got != 7 {
				t.Fatalf("replacement plus prior terminal metrics=%d, want separate active and terminal rows", got)
			}
		})
	}
}

func TestVolumeRetypeDiscoveryRacePreservesPriorCompletionUntilCandidateAccepted(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
	if err != nil {
		t.Fatal(err)
	}
	job := volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], time.Now().Add(-time.Minute))
	completionKey := volumeRetypeCompletionKeyForJob(job)
	mc.volumeRetypeCompleted[completionKey] = volumeRetypeCompletion{
		Job:         job,
		Result:      "unsuccessful",
		CompletedAt: time.Now(),
	}
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		return activeVolumeRetypeXML, nil
	}
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		return 0, 0, 0, 0, 0, nil
	}

	mc.refreshVolumeRetypes(
		[]libvirt.DomainStatsRecord{{Dom: domain}},
		map[string]*DomainStatic{instanceUUID: meta},
	)
	mc.volumeRetypeMu.Lock()
	_, retained := mc.volumeRetypeCompleted[completionKey]
	activeJobs := len(mc.volumeRetypeJobs)
	mc.volumeRetypeMu.Unlock()
	if !retained || activeJobs != 0 {
		t.Fatalf("candidate/block-info race retained prior=%v active jobs=%d", retained, activeJobs)
	}
}

func TestVolumeRetypeCompletionRetentionIsTimeAndSizeBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	completed := make(map[volumeRetypeCompletionKey]volumeRetypeCompletion)
	for index := 0; index < volumeRetypeCompletionMax+44; index++ {
		key := volumeRetypeCompletionKey{InstanceUUID: fmt.Sprintf("instance-%03d", index), DiskPath: "vdb"}
		completed[key] = volumeRetypeCompletion{
			Job:         volumeRetypeJob{InstanceUUID: key.InstanceUUID, DiskPath: key.DiskPath},
			Result:      "success",
			CompletedAt: now.Add(time.Duration(index) * time.Second),
		}
	}
	pruneVolumeRetypeCompletions(completed, now.Add(time.Duration(volumeRetypeCompletionMax+44)*time.Second))
	if len(completed) != volumeRetypeCompletionMax {
		t.Fatalf("retained completions=%d, want %d", len(completed), volumeRetypeCompletionMax)
	}
	if _, retained := completed[volumeRetypeCompletionKey{InstanceUUID: "instance-000", DiskPath: "vdb"}]; retained {
		t.Fatal("oldest completion survived the hard cap")
	}
	if _, retained := completed[volumeRetypeCompletionKey{InstanceUUID: "instance-299", DiskPath: "vdb"}]; !retained {
		t.Fatal("newest completion was removed by the hard cap")
	}
	pruneVolumeRetypeCompletions(completed, now.Add(2*volumeRetypeCompletionTTL))
	if len(completed) != 0 {
		t.Fatalf("expired completions=%d, want zero", len(completed))
	}
}

func TestCollectReplacesStaleCachedRetypeSnapshotWithLiveCompletion(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	job := volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], now.Add(-time.Minute))
	job.ProgressAvailable = true
	job.ProgressPercent = 25
	key := volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}
	mc.volumeRetypeJobs[key] = job
	mc.cacheMu.Lock()
	mc.cachedMetrics = append(mc.volumeRetypeMetrics(now), mc.volumeRetypeResultMetrics()...)
	mc.cacheInitialized = true
	mc.cacheMu.Unlock()

	mc.volumeRetypeMu.Lock()
	delete(mc.volumeRetypeJobs, key)
	mc.volumeRetypeCompleted[volumeRetypeCompletionKeyForJob(job)] = volumeRetypeCompletion{Job: job, Result: "success", CompletedAt: now}
	mc.volumeRetypeResults.Success = 1
	mc.volumeRetypeMu.Unlock()

	metricCh := make(chan prometheus.Metric, 32)
	mc.Collect(metricCh)
	close(metricCh)
	values := make(map[string][]float64)
	for metric := range metricCh {
		name := descNameRE.FindStringSubmatch(metric.Desc().String())[1]
		message := metricDTO(t, metric)
		if message.Gauge != nil {
			values[name] = append(values[name], message.GetGauge().GetValue())
		}
	}
	if got := values["oie_instance_disk_retype_active"]; len(got) != 1 || got[0] != 0 {
		t.Fatalf("scraped active values=%v, want only terminal zero", got)
	}
	if got := values["oie_instance_disk_retype_status_code"]; len(got) != 1 || got[0] != volumeRetypeStatusSuccess {
		t.Fatalf("scraped status values=%v, want only success", got)
	}
	if got := values["oie_instance_disk_retype_progress_percent"]; len(got) != 0 {
		t.Fatalf("scrape replayed stale progress=%v", got)
	}
}

func TestCollectSuppressesRetypeProgressWhileLibvirtSourceIsDegraded(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	job := volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], now)
	job.ConfirmedAt = now
	job.ProgressAvailable = true
	job.ProgressPercent = 73
	job.ObservationAttempted = true
	job.ObservationHealthy = true
	mc.volumeRetypeMu.Lock()
	mc.volumeRetypeJobs[volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}] = job
	mc.volumeRetypeResults.Success = 2
	mc.volumeRetypeMu.Unlock()
	mc.cacheMu.Lock()
	mc.cacheInitialized = true
	mc.cachedLibvirtAvailable = false
	mc.cacheMu.Unlock()

	collect := func() (map[string][]float64, map[string]float64) {
		t.Helper()
		metricCh := make(chan prometheus.Metric, 32)
		mc.Collect(metricCh)
		close(metricCh)
		gauges := make(map[string][]float64)
		results := make(map[string]float64)
		for metric := range metricCh {
			name := descNameRE.FindStringSubmatch(metric.Desc().String())[1]
			message := metricDTO(t, metric)
			if message.Gauge != nil {
				gauges[name] = append(gauges[name], message.GetGauge().GetValue())
			}
			if name != "oie_host_volume_retype_results_total" || message.Counter == nil {
				continue
			}
			for _, label := range message.Label {
				if label.GetName() == "result" {
					results[label.GetValue()] = message.GetCounter().GetValue()
				}
			}
		}
		return gauges, results
	}

	mc.recordLibvirtCollectionResult(true, now)
	mc.recordLibvirtCollectionResult(false, now.Add(time.Second))
	gauges, results := collect()
	if got := gauges["oie_instance_disk_retype_active"]; len(got) != 1 || got[0] != 1 {
		t.Fatalf("degraded active identity=%v, want one active operation", got)
	}
	if got := gauges["oie_instance_disk_retype_progress_percent"]; len(got) != 0 {
		t.Fatalf("degraded scrape exposed stale progress=%v", got)
	}
	if got := gauges["oie_instance_disk_retype_observation_healthy"]; len(got) != 0 {
		t.Fatalf("degraded scrape synthesized per-job observation health=%v", got)
	}
	if got := results["success"]; got != 2 {
		t.Fatalf("degraded result counter=%v, want 2", got)
	}

	// A newer atomic source-health value must not be combined with an older
	// cached metric generation.
	mc.recordLibvirtCollectionResult(true, now.Add(2*time.Second))
	gauges, _ = collect()
	if got := gauges["oie_instance_disk_retype_progress_percent"]; len(got) != 0 {
		t.Fatalf("old cached generation used newer source health: progress=%v", got)
	}

	// Commit the next full-cycle generation atomically with its trust bit, then
	// prove that a later uncommitted health change cannot alter that generation.
	mc.cacheMu.Lock()
	mc.cachedLibvirtAvailable = true
	mc.cacheMu.Unlock()
	mc.recordLibvirtCollectionResult(false, now.Add(3*time.Second))
	gauges, results = collect()
	if got := gauges["oie_instance_disk_retype_progress_percent"]; len(got) != 1 || got[0] != 73 {
		t.Fatalf("healthy scrape progress=%v, want 73", got)
	}
	if got := gauges["oie_instance_disk_retype_observation_healthy"]; len(got) != 1 || got[0] != 1 {
		t.Fatalf("healthy observation health=%v, want one", got)
	}
	if got := results["success"]; got != 2 {
		t.Fatalf("healthy result counter=%v, want 2", got)
	}
}

func TestCollectUsesOneRetypeStateSnapshotForCountersAndRows(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
	if err != nil {
		t.Fatal(err)
	}
	job := volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], time.Now())
	job.ConfirmedAt = time.Now()
	job.ProgressAvailable = true
	job.ObservationAttempted = true
	job.ObservationHealthy = true
	key := volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}
	mc.volumeRetypeMu.Lock()
	mc.volumeRetypeJobs[key] = job
	mc.volumeRetypeMu.Unlock()
	mc.cacheMu.Lock()
	mc.cacheInitialized = true
	mc.cachedLibvirtAvailable = true
	mc.cacheMu.Unlock()
	mc.recordLibvirtCollectionResult(true, time.Now())

	started := make(chan struct{})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var generation uint64
		close(started)
		for {
			select {
			case <-stop:
				return
			default:
			}
			generation++
			mc.volumeRetypeMu.Lock()
			updated := mc.volumeRetypeJobs[key]
			updated.ProgressPercent = float64(generation % 101)
			mc.volumeRetypeJobs[key] = updated
			mc.volumeRetypeResults.Success = generation
			mc.volumeRetypeMu.Unlock()
		}
	}()
	<-started
	defer func() {
		close(stop)
		<-done
	}()

	for iteration := 0; iteration < 1000; iteration++ {
		metricCh := make(chan prometheus.Metric, 32)
		mc.Collect(metricCh)
		close(metricCh)
		var (
			progress     float64
			success      float64
			progressSeen bool
			successSeen  bool
		)
		for metric := range metricCh {
			name := descNameRE.FindStringSubmatch(metric.Desc().String())[1]
			message := metricDTO(t, metric)
			switch name {
			case "oie_instance_disk_retype_progress_percent":
				progress = message.GetGauge().GetValue()
				progressSeen = true
			case "oie_host_volume_retype_results_total":
				for _, label := range message.Label {
					if label.GetName() == "result" && label.GetValue() == "success" {
						success = message.GetCounter().GetValue()
						successSeen = true
					}
				}
			}
		}
		if !progressSeen || !successSeen {
			t.Fatalf("iteration %d missing progress=%v or success counter=%v", iteration, progressSeen, successSeen)
		}
		if want := float64(uint64(success) % 101); progress != want {
			t.Fatalf("iteration %d mixed lifecycle snapshots: progress=%v success=%v want progress=%v", iteration, progress, success, want)
		}
	}
}

func TestVolumeRetypeCachedFallbackSuppressesProgressAndExpiresActiveIdentity(t *testing.T) {
	mc, domain, instanceUUID, meta := newVolumeRetypeTestCollector(t)
	state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
	if err != nil {
		t.Fatal(err)
	}
	candidate := state.Candidates["vde"]
	confirmedAt := time.Now()
	job := volumeRetypeJobFromCandidate(domain, meta, candidate, confirmedAt)
	job.ProgressAvailable = true
	job.ProgressPercent = 50
	key := volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}
	mc.volumeRetypeMu.Lock()
	mc.volumeRetypeJobs[key] = job
	mc.volumeRetypeMu.Unlock()
	mc.recordLibvirtCollectionResult(true, confirmedAt)

	mc.cacheMu.Lock()
	mc.cachedMetrics = mc.volumeRetypeMetrics(confirmedAt)
	mc.cacheMu.Unlock()
	collectFallback := func() map[string]int {
		t.Helper()
		metrics := make(chan prometheus.Metric, 128)
		if !mc.emitCachedMetricsWithLiveHealth(metrics, 1, 1, 1) {
			t.Fatal("cached fallback was unavailable")
		}
		close(metrics)
		families := make(map[string]int)
		for metric := range metrics {
			match := descNameRE.FindStringSubmatch(metric.Desc().String())
			if len(match) == 2 {
				families[match[1]]++
			}
		}
		return families
	}

	families := collectFallback()
	if families["oie_instance_disk_retype_active"] != 1 {
		t.Fatalf("recent cached active series=%d, want one", families["oie_instance_disk_retype_active"])
	}
	if families["oie_instance_disk_retype_progress_percent"] != 0 {
		t.Fatalf("cached fallback replayed %d stale progress series", families["oie_instance_disk_retype_progress_percent"])
	}
	if families["oie_instance_disk_retype_status_code"] != 1 ||
		families["oie_instance_disk_retype_start_timestamp_seconds"] != 1 {
		t.Fatalf("cached fallback omitted active lifecycle fields: %v", families)
	}

	mc.volumeRetypeMu.Lock()
	job = mc.volumeRetypeJobs[key]
	job.ConfirmedAt = time.Now().Add(-3 * time.Minute)
	mc.volumeRetypeJobs[key] = job
	mc.volumeRetypeMu.Unlock()
	families = collectFallback()
	if families["oie_instance_disk_retype_active"] != 0 ||
		families["oie_instance_disk_retype_progress_percent"] != 0 ||
		families["oie_instance_disk_retype_status_code"] != 0 ||
		families["oie_instance_disk_retype_start_timestamp_seconds"] != 0 {
		t.Fatalf("expired cached retype series survived: %v", families)
	}
}

func TestVolumeRetypeDiscoveryIsBoundedAndCoversThousandDomains(t *testing.T) {
	mc, _, _, _ := newVolumeRetypeTestCollector(t)
	records := make([]libvirt.DomainStatsRecord, 1000)
	for index := range records {
		uuid, _ := scalingUUID(index + 1)
		records[index].Dom = libvirt.Domain{Name: "domain", UUID: uuid}
	}
	seen := make(map[string]struct{}, len(records))
	for cycle := 0; cycle < 4; cycle++ {
		batch := mc.takeVolumeRetypeDiscoveryDomains(records)
		if len(batch) != volumeRetypeDiscoveryMaxBatch {
			t.Fatalf("cycle %d discovery batch=%d, want %d", cycle, len(batch), volumeRetypeDiscoveryMaxBatch)
		}
		for _, domain := range batch {
			seen[validLibvirtDomainUUID(domain.UUID)] = struct{}{}
		}
	}
	if len(seen) != 1000 {
		t.Fatalf("four discovery batches covered %d domains, want 1000", len(seen))
	}

	large := make([]libvirt.DomainStatsRecord, 2000)
	for index := range large {
		uuid, _ := scalingUUID(index + 1)
		large[index].Dom = libvirt.Domain{Name: "domain", UUID: uuid}
	}
	if got := len(mc.takeVolumeRetypeDiscoveryDomains(large)); got != volumeRetypeDiscoveryMaxBatch {
		t.Fatalf("large discovery batch=%d, cap=%d", got, volumeRetypeDiscoveryMaxBatch)
	}
}

func TestVolumeRetypeDashboardsAreFullWidthSingleRowTables(t *testing.T) {
	dashboardPanels := map[string]int{
		"examples/grafana_dashboard_example/openstack_instance_exporter_cluster.json": 24001,
		"examples/grafana_dashboard_example/openstack_instance_exporter_project.json": 24002,
	}
	for dashboardPath, panelID := range dashboardPanels {
		data, err := os.ReadFile(dashboardPath)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		var matches []map[string]any
		var inspect func(any)
		inspect = func(value any) {
			switch typed := value.(type) {
			case map[string]any:
				if id, _ := typed["id"].(float64); int(id) == panelID {
					matches = append(matches, typed)
				}
				for _, child := range typed {
					inspect(child)
				}
			case []any:
				for _, child := range typed {
					inspect(child)
				}
			}
		}
		inspect(document["panels"])
		if len(matches) != 1 {
			t.Fatalf("%s retype panel matches=%d, want one", dashboardPath, len(matches))
		}
		panel := matches[0]
		grid, _ := panel["gridPos"].(map[string]any)
		if panel["type"] != "table" || int(grid["w"].(float64)) != 24 {
			t.Fatalf("%s retype panel type/grid=%v/%v", dashboardPath, panel["type"], grid)
		}
		panelJSON, _ := json.Marshal(panel)
		panelText := string(panelJSON)
		for _, metric := range []string{
			"oie_instance_disk_retype_active",
			"oie_instance_disk_retype_progress_percent",
			"oie_instance_disk_retype_status_code",
			"oie_instance_disk_retype_observation_healthy",
			"oie_instance_disk_retype_start_timestamp_seconds",
			"oie_instance_disk_retype_ready_timestamp_seconds",
			"oie_instance_disk_retype_end_timestamp_seconds",
		} {
			if !strings.Contains(panelText, metric) {
				t.Errorf("%s retype panel omits %s", dashboardPath, metric)
			}
		}
		if strings.Contains(panelText, `"stacking"`) {
			t.Fatalf("%s retype table contains a stacking configuration", dashboardPath)
		}
		for _, obsolete := range []string{
			`"Source Type"`,
			`"Destination Type"`,
			`"Source Volume"`,
			`"Destination Volume"`,
		} {
			if strings.Contains(panelText, obsolete) {
				t.Errorf("%s retype table retains misleading column name %s", dashboardPath, obsolete)
			}
		}
		for _, required := range []string{
			"Attached-Volume Retypes Only — Active and Recent",
			"only volumes attached to active Libvirt domains",
			"Detached or available-volume retypes",
			"they are not visible here",
			"OIE does not query Cinder",
			"Cinder remains authoritative for migration status",
			"Root/boot volumes are included",
			"Source RBD Pool",
			"Destination RBD Pool",
			"not Cinder volume-type names",
			"Source RBD Image",
			"Destination RBD Image",
			"RBD image basenames that retain the volume- prefix",
			"strip that prefix before passing either value to openstack volume show",
			"completion-paced fast poller",
			"no more often than every 5 seconds",
			"after the preceding attempt completes",
			"no more often than every 15 seconds after the preceding query completes",
			"waits 30 seconds after a failed query completes",
			"discovery remains bounded",
			"still runs during normal collections when no retype is known",
			"only the idle fast-poller and block-job paths make no Libvirt calls",
			"merged into one table row",
			"exact same source/destination identity",
			"only its newest retained row is kept",
			"Status 5 means Libvirt reports the copy ready and awaiting pivot",
			"Status 6 means that copy-ready state has remained for at least 10 minutes",
			"non-terminal and does not prove Cinder success",
			"Status 4 is emitted only when a successful XML inspection finds the mirror gone",
			"too old to reconfirm expires without a terminal status",
			"Copying",
			"Copy Ready / Awaiting Pivot",
			"Ready Stalled / Awaiting Pivot",
			"Libvirt Job Present",
			"Libvirt Observation",
			"Unavailable",
			"First Observed",
			"Copy Ready Observed",
			"Terminal Observed",
			"not authoritative Cinder API lifecycle timestamps",
			"in-memory exporter-process state and reset on exporter restart",
			"retained for one hour",
			"at most 256",
			"not Ceph physical allocation",
			"or an ETA",
			"Thin-provisioned or sparse",
			"fstrim/TRIM",
			"not time-linear",
			`"valueLabel":"retype_field"`,
			`"format":"time_series"`,
			`\"job\", \".+\"`,
			`* 1`,
			`* 1000`,
		} {
			if !strings.Contains(panelText, required) {
				t.Errorf("%s retype panel omits %q", dashboardPath, required)
			}
		}
		if strings.Contains(panelText, `"format":"table"`) {
			t.Fatalf("%s retype query uses long-table format instead of mergeable time-series frames", dashboardPath)
		}
		targets, _ := panel["targets"].([]any)
		if len(targets) != 1 {
			t.Fatalf("%s retype panel targets=%d, want one combined target", dashboardPath, len(targets))
		}
		target, _ := targets[0].(map[string]any)
		if target["instant"] != true || target["range"] != false {
			t.Fatalf("%s retype target must be one instant time-series query", dashboardPath)
		}
		transformations, _ := panel["transformations"].([]any)
		if len(transformations) != 3 {
			t.Fatalf("%s retype transformations=%d, want labels-to-fields, merge, then organizer", dashboardPath, len(transformations))
		}
		firstTransformation, _ := transformations[0].(map[string]any)
		if firstTransformation["id"] != "labelsToFields" {
			t.Fatalf("%s first retype transformation=%v, want labelsToFields", dashboardPath, firstTransformation["id"])
		}
	}

	dashboardFiles, err := filepath.Glob("examples/grafana_dashboard_example/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range dashboardFiles {
		if _, expected := dashboardPanels[path]; expected {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var dashboard dashboardDocumentationDashboard
		if err := json.Unmarshal(content, &dashboard); err != nil {
			t.Fatal(err)
		}
		for _, panel := range dashboardDocumentationFlattenPanels(dashboard.Panels) {
			if strings.Contains(dashboardDocumentationPanelExpressions(panel), "oie_instance_disk_retype_") {
				t.Errorf("retype panel duplicated in %s", path)
			}
		}
	}
}

func TestVolumeRetypeReadyStalledWarningAlertContract(t *testing.T) {
	const alertName = "OpenStackInstanceVolumeRetypeReadyStalled"
	alerts := loadCurrentAlertRules(t)
	found := 0
	for _, group := range alerts.Groups {
		for _, rule := range group.Rules {
			if rule.Alert != alertName {
				continue
			}
			found++
			expression := normalizedAlertExpression(rule.Expr)
			for _, required := range []string{
				`oie_instance_disk_retype_status_code{job="openstack-instance-exporter"} == 6`,
				`and on (instance, job)`,
				`oie_host_libvirt_ok{job="openstack-instance-exporter"}`,
				`== 1`,
			} {
				if !strings.Contains(expression, required) {
					t.Errorf("%s expression omits %q: %s", alertName, required, expression)
				}
			}
			if rule.For != "1m" || rule.Labels["severity"] != "warning" {
				t.Errorf("%s for/severity=%q/%q, want 1m/warning", alertName, rule.For, rule.Labels["severity"])
			}
			if !strings.Contains(rule.Annotations["description"], "at least ten minutes") ||
				!strings.Contains(rule.Annotations["description"], "Nova and Cinder") {
				t.Errorf("%s annotation does not explain the stalled observation and authoritative sources", alertName)
			}
		}
	}
	if found != 1 {
		t.Fatalf("%s definitions=%d, want exactly one", alertName, found)
	}
}

func TestVolumeRetypeReadyStalledWarningAlertLifecycleWithPromtool(t *testing.T) {
	const alertName = "OpenStackInstanceVolumeRetypeReadyStalled"
	alerts := loadCurrentAlertRules(t)
	var selected *alertValidationPromtoolRule
	for _, group := range alerts.Groups {
		for _, rule := range group.Rules {
			if rule.Alert != alertName {
				continue
			}
			selected = &alertValidationPromtoolRule{
				Alert:  rule.Alert,
				Expr:   normalizedAlertExpression(rule.Expr),
				For:    rule.For,
				Labels: rule.Labels,
			}
		}
	}
	if selected == nil {
		t.Fatalf("%s is missing", alertName)
	}

	operationLabels := alertValidationInstanceLabels()
	operationLabels["disk_path"] = "vda"
	operationLabels["disk_type"] = "premium"
	operationLabels["volume_uuid"] = "volume-11111111-1111-1111-1111-111111111111"
	operationLabels["destination_disk_type"] = "volumes"
	operationLabels["destination_volume_uuid"] = "volume-22222222-2222-2222-2222-222222222222"
	healthLabels := map[string]string{
		"instance": operationLabels["instance"],
		"job":      operationLabels["job"],
	}
	expectedLabels := alertValidationCopyLabels(operationLabels)
	expectedLabels["severity"] = "warning"
	values := func(value float64) string {
		return alertValidationValues(3, func(int) float64 { return value })
	}
	groups := []alertValidationPromtoolTestGroup{
		{
			Name:     "ready stalled with healthy Libvirt fires",
			Interval: "1m",
			InputSeries: []alertValidationPromtoolInputSeries{
				{Series: alertValidationSeries("oie_instance_disk_retype_status_code", operationLabels), Values: values(volumeRetypeStatusReadyStalled)},
				{Series: alertValidationSeries("oie_host_libvirt_ok", healthLabels), Values: values(1)},
			},
			AlertRuleTest: []alertValidationPromtoolAlertTest{{
				EvalTime: "1m",
				Alert:    alertName,
				Expected: []alertValidationPromtoolExpectedAlert{{Labels: expectedLabels}},
			}},
		},
		{
			Name:     "ordinary copy ready does not fire",
			Interval: "1m",
			InputSeries: []alertValidationPromtoolInputSeries{
				{Series: alertValidationSeries("oie_instance_disk_retype_status_code", operationLabels), Values: values(volumeRetypeStatusReady)},
				{Series: alertValidationSeries("oie_host_libvirt_ok", healthLabels), Values: values(1)},
			},
			AlertRuleTest: []alertValidationPromtoolAlertTest{{EvalTime: "2m", Alert: alertName}},
		},
		{
			Name:     "unhealthy Libvirt source suppresses warning",
			Interval: "1m",
			InputSeries: []alertValidationPromtoolInputSeries{
				{Series: alertValidationSeries("oie_instance_disk_retype_status_code", operationLabels), Values: values(volumeRetypeStatusReadyStalled)},
				{Series: alertValidationSeries("oie_host_libvirt_ok", healthLabels), Values: values(0)},
			},
			AlertRuleTest: []alertValidationPromtoolAlertTest{{EvalTime: "2m", Alert: alertName}},
		},
	}
	for i := range groups {
		groups[i].InputSeries = append(groups[i].InputSeries, alertValidationPromtoolInputSeries{Series: alertValidationSeries("oie:libvirt_ready_5m", healthLabels), Values: "1x4"})
	}
	alertValidationRunPromtoolRules(t, "volume retype ready-stalled warning", []alertValidationPromtoolRule{*selected}, groups)
}

func TestVolumeRetypeObservationWarningAlertContract(t *testing.T) {
	const alertName = "OpenStackInstanceVolumeRetypeObservationUnhealthy"
	alerts := loadCurrentAlertRules(t)
	found := 0
	for _, group := range alerts.Groups {
		for _, rule := range group.Rules {
			if rule.Alert != alertName {
				continue
			}
			found++
			expression := normalizedAlertExpression(rule.Expr)
			for _, required := range []string{
				`oie_instance_disk_retype_observation_healthy{job="openstack-instance-exporter"} == 0`,
				`and on (instance, job)`,
				`oie_host_libvirt_ok{job="openstack-instance-exporter"}`,
				`unless on (instance, job, instance_uuid, disk_path, volume_uuid, destination_volume_uuid)`,
				`oie_instance_disk_retype_status_code{job="openstack-instance-exporter"} == 6`,
			} {
				if !strings.Contains(expression, required) {
					t.Errorf("%s expression omits %q: %s", alertName, required, expression)
				}
			}
			if rule.For != "2m" || rule.Labels["severity"] != "warning" {
				t.Errorf("%s for/severity=%q/%q, want 2m/warning", alertName, rule.For, rule.Labels["severity"])
			}
			if !strings.Contains(rule.Annotations["description"], "state-lock contention") ||
				!strings.Contains(rule.Annotations["description"], "does not by itself prove") {
				t.Errorf("%s annotation does not bound the observation failure semantics", alertName)
			}
		}
	}
	if found != 1 {
		t.Fatalf("%s definitions=%d, want exactly one", alertName, found)
	}
}

func TestVolumeRetypeObservationWarningAlertLifecycleWithPromtool(t *testing.T) {
	const alertName = "OpenStackInstanceVolumeRetypeObservationUnhealthy"
	alerts := loadCurrentAlertRules(t)
	var selected *alertValidationPromtoolRule
	for _, group := range alerts.Groups {
		for _, rule := range group.Rules {
			if rule.Alert == alertName {
				selected = &alertValidationPromtoolRule{
					Alert:  rule.Alert,
					Expr:   normalizedAlertExpression(rule.Expr),
					For:    rule.For,
					Labels: rule.Labels,
				}
			}
		}
	}
	if selected == nil {
		t.Fatalf("%s is missing", alertName)
	}

	operationLabels := alertValidationInstanceLabels()
	operationLabels["disk_path"] = "vda"
	operationLabels["disk_type"] = "premium"
	operationLabels["volume_uuid"] = "volume-11111111-1111-1111-1111-111111111111"
	operationLabels["destination_disk_type"] = "volumes"
	operationLabels["destination_volume_uuid"] = "volume-22222222-2222-2222-2222-222222222222"
	healthLabels := map[string]string{
		"instance": operationLabels["instance"],
		"job":      operationLabels["job"],
	}
	expectedLabels := alertValidationCopyLabels(operationLabels)
	expectedLabels["severity"] = "warning"
	constant := func(value float64) string {
		return alertValidationValues(4, func(int) float64 { return value })
	}
	groups := []alertValidationPromtoolTestGroup{
		{
			Name:     "persistent retype observation failure fires",
			Interval: "1m",
			InputSeries: []alertValidationPromtoolInputSeries{
				{Series: alertValidationSeries("oie_instance_disk_retype_observation_healthy", operationLabels), Values: constant(0)},
				{Series: alertValidationSeries("oie_instance_disk_retype_status_code", operationLabels), Values: constant(volumeRetypeStatusActive)},
				{Series: alertValidationSeries("oie_host_libvirt_ok", healthLabels), Values: constant(1)},
			},
			AlertRuleTest: []alertValidationPromtoolAlertTest{{
				EvalTime: "2m",
				Alert:    alertName,
				Expected: []alertValidationPromtoolExpectedAlert{{Labels: expectedLabels}},
			}},
		},
		{
			Name:     "recovered observation does not fire",
			Interval: "1m",
			InputSeries: []alertValidationPromtoolInputSeries{
				{Series: alertValidationSeries("oie_instance_disk_retype_observation_healthy", operationLabels), Values: "0 0 1 1"},
				{Series: alertValidationSeries("oie_instance_disk_retype_status_code", operationLabels), Values: constant(volumeRetypeStatusActive)},
				{Series: alertValidationSeries("oie_host_libvirt_ok", healthLabels), Values: constant(1)},
			},
			AlertRuleTest: []alertValidationPromtoolAlertTest{{EvalTime: "3m", Alert: alertName}},
		},
		{
			Name:     "host-wide Libvirt failure suppresses duplicate warning",
			Interval: "1m",
			InputSeries: []alertValidationPromtoolInputSeries{
				{Series: alertValidationSeries("oie_instance_disk_retype_observation_healthy", operationLabels), Values: constant(0)},
				{Series: alertValidationSeries("oie_instance_disk_retype_status_code", operationLabels), Values: constant(volumeRetypeStatusActive)},
				{Series: alertValidationSeries("oie_host_libvirt_ok", healthLabels), Values: constant(0)},
			},
			AlertRuleTest: []alertValidationPromtoolAlertTest{{EvalTime: "3m", Alert: alertName}},
		},
		{
			Name:     "ready-stalled operation suppresses duplicate warning",
			Interval: "1m",
			InputSeries: []alertValidationPromtoolInputSeries{
				{Series: alertValidationSeries("oie_instance_disk_retype_observation_healthy", operationLabels), Values: constant(0)},
				{Series: alertValidationSeries("oie_instance_disk_retype_status_code", operationLabels), Values: constant(volumeRetypeStatusReadyStalled)},
				{Series: alertValidationSeries("oie_host_libvirt_ok", healthLabels), Values: constant(1)},
			},
			AlertRuleTest: []alertValidationPromtoolAlertTest{{EvalTime: "3m", Alert: alertName}},
		},
	}
	for i := range groups {
		groups[i].InputSeries = append(groups[i].InputSeries, alertValidationPromtoolInputSeries{Series: alertValidationSeries("oie:libvirt_ready_5m", healthLabels), Values: "1x4"})
	}
	alertValidationRunPromtoolRules(t, "volume retype observation warning", []alertValidationPromtoolRule{*selected}, groups)
}

func TestDiskCapacityPanelsDescribeLibvirtRatherThanCephUsage(t *testing.T) {
	for _, path := range []string{
		"examples/grafana_dashboard_example/openstack_instance_exporter_cluster.json",
		"examples/grafana_dashboard_example/openstack_instance_exporter_project.json",
	} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		for _, required := range []string{
			"highest-written offset",
			"Both lines use the same cohort",
			"not the number of bytes physically allocated",
			"Use Ceph-native telemetry for authoritative backend consumption",
			"omitted rather than replaced with physical/container size",
			"and on(instance, domain, instance_uuid, disk_path)",
		} {
			if !strings.Contains(text, required) {
				t.Errorf("%s omits storage-semantics wording %q", path, required)
			}
		}
		for _, misleading := range []string{
			`"legendFormat": "Allocated"`,
			`"legendFormat": "Allocation -`,
			"actual host allocation per project",
		} {
			if strings.Contains(text, misleading) {
				t.Errorf("%s retains misleading disk-usage wording %q", path, misleading)
			}
		}
	}
}
