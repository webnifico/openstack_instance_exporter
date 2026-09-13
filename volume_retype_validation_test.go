package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func TestVolumeRetypeReadySentinelOnFirstDiscovery(t *testing.T) {
	for _, cursor := range [][2]uint64{{1, 1}, {0, 1}, {0, 0}, {25, 100}} {
		t.Run(fmt.Sprintf("%d/%d", cursor[0], cursor[1]), func(t *testing.T) {
			mc, domain, uuid, meta := newVolumeRetypeTestCollector(t)
			mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
				return strings.Replace(activeVolumeRetypeXML, `job="copy"`, `job="copy" ready="yes"`, 1), nil
			}
			mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
				return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, cursor[0], cursor[1], nil
			}
			mc.refreshVolumeRetypes([]libvirt.DomainStatsRecord{{Dom: domain}}, map[string]*DomainStatic{uuid: meta})
			job := mc.volumeRetypeJobs[volumeRetypeKey{InstanceUUID: uuid, DiskPath: "vde"}]
			if !job.Ready || !job.ProgressAvailable || job.ProgressPercent != 100 || !job.ObservationHealthy {
				t.Fatalf("first ready observation lost XML-confirmed progress: %+v", job)
			}
			found := false
			for _, metric := range mc.volumeRetypeMetrics(time.Now()) {
				if metric.Desc() == mc.im.instanceDiskRetypeProgressDesc {
					found = metricDTO(t, metric).GetGauge().GetValue() == 100
				}
			}
			if !found {
				t.Fatal("ready discovery did not expose 100 percent in Prometheus")
			}
		})
	}
}

func TestVolumeRetypeReadyTimestampSurvivesFinalization(t *testing.T) {
	for _, fast := range []bool{false, true} {
		for _, phase := range []string{"pivot", "abort"} {
			t.Run(fmt.Sprintf("fast=%v/%s", fast, phase), func(t *testing.T) {
				mc, domain, uuid, meta := newVolumeRetypeTestCollector(t)
				state, err := parseVolumeRetypeXML(strings.Replace(activeVolumeRetypeXML, `job="copy"`, `job="copy" ready="yes"`, 1))
				if err != nil {
					t.Fatal(err)
				}
				job := volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], time.Now().Add(-time.Minute))
				job.NextBlockPollAt = time.Now().Add(time.Minute)
				key := volumeRetypeKey{InstanceUUID: uuid, DiskPath: "vde"}
				mc.volumeRetypeJobs[key] = job
				xmlDescription := strings.Replace(activeVolumeRetypeXML, `job="copy"`, `job="copy" ready="`+phase+`"`, 1)
				mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) { return xmlDescription, nil }
				mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
					return 0, 0, 0, 0, 0, nil
				}
				refresh := func() {
					if fast {
						mc.refreshActiveVolumeRetypes(time.Now())
					} else {
						mc.refreshVolumeRetypes([]libvirt.DomainStatsRecord{{Dom: domain}}, map[string]*DomainStatic{uuid: meta})
					}
				}
				refresh()
				current, active := mc.volumeRetypeJobs[key]
				if !active || len(mc.volumeRetypeCompleted) != 0 || !current.ReadyObservedAt.Equal(job.ReadyObservedAt) {
					t.Fatalf("%s lost ready history or prematurely completed: active=%v ready=%v want=%v", phase, active, current.ReadyObservedAt, job.ReadyObservedAt)
				}
				finalSource, outcome := job.DestinationName, "success"
				if phase == "abort" {
					finalSource, outcome = job.SourceName, "unsuccessful"
				}
				xmlDescription = fmt.Sprintf(`<domain><devices><disk device="disk"><source protocol="rbd" name="%s"/><target dev="vde"/></disk></devices></domain>`, finalSource)
				refresh()
				completion, exists := mc.volumeRetypeCompleted[volumeRetypeCompletionKeyForJob(job)]
				if !exists || completion.Result != outcome || !completion.Job.ReadyObservedAt.Equal(job.ReadyObservedAt) {
					t.Fatalf("terminal observation lost ready history or outcome: %+v", completion)
				}
				refresh()
				counters := mc.volumeRetypeResults
				if counters.Success+counters.Unsuccessful+counters.Unknown != 1 {
					t.Fatalf("terminal result counted more than once: %+v", counters)
				}
			})
		}
	}
}

func TestVolumeRetypeConnectionLossExpiresWithoutTerminalResult(t *testing.T) {
	for _, fast := range []bool{false, true} {
		for _, ready := range []bool{false, true} {
			t.Run(fmt.Sprintf("fast=%v/ready=%v", fast, ready), func(t *testing.T) {
				mc, domain, uuid, meta := newVolumeRetypeTestCollector(t)
				state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
				if err != nil {
					t.Fatal(err)
				}
				candidate := state.Candidates["vde"]
				candidate.Ready = ready
				job := volumeRetypeJobFromCandidate(domain, meta, candidate, time.Now())
				job.ProgressAvailable, job.ProgressPercent = true, 25
				job.ObservationAttempted, job.ObservationHealthy = true, true
				key := volumeRetypeKey{InstanceUUID: uuid, DiskPath: "vde"}
				mc.volumeRetypeJobs[key] = job
				refresh := func() {
					if fast {
						mc.refreshActiveVolumeRetypes(time.Now())
					} else {
						mc.refreshVolumeRetypes([]libvirt.DomainStatsRecord{{Dom: domain}}, map[string]*DomainStatic{uuid: meta})
					}
				}
				refresh()
				current, active := mc.volumeRetypeJobs[key]
				if !active || current.ObservationHealthy || (!ready && current.ProgressAvailable) || !current.NextBlockPollAt.After(time.Now()) {
					t.Fatalf("connection loss left healthy progress or discarded fresh identity: %+v", current)
				}
				for _, metric := range mc.volumeRetypeCachedFallbackMetrics(time.Now()) {
					if metric.Desc() == mc.im.instanceDiskRetypeProgressDesc || metric.Desc() == mc.im.instanceDiskRetypeObservationHealthyDesc {
						t.Fatal("unavailable main source exposed live progress/query health")
					}
				}
				current.ConfirmedAt = time.Now().Add(-volumeRetypeActiveMaxAge(mc.effectiveCollectionInterval()) - time.Second)
				mc.volumeRetypeJobs[key] = current
				refresh()
				if len(mc.volumeRetypeJobs) != 0 || len(mc.volumeRetypeCompleted) != 0 || mc.volumeRetypeResults != (volumeRetypeResultCounters{}) {
					t.Fatal("connection loss did not expire silently")
				}
			})
		}
	}
}

func TestVolumeRetypeShutdownDoesNotStartAnotherObservation(t *testing.T) {
	mc, domain, uuid, meta := newVolumeRetypeTestCollector(t)
	state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
	if err != nil {
		t.Fatal(err)
	}
	mc.volumeRetypeJobs[volumeRetypeKey{InstanceUUID: uuid, DiskPath: "vde"}] = volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], time.Now())
	var calls atomic.Int32
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		calls.Add(1)
		return activeVolumeRetypeXML, nil
	}
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		calls.Add(1)
		return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, 25, 100, nil
	}
	shutdown := make(chan struct{})
	close(shutdown)
	for attempt := 0; attempt < 64; attempt++ {
		mc.runVolumeRetypePoller(0, shutdown)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("closed shutdown channel allowed %d new Libvirt observations", got)
	}
}

func TestVolumeRetypeInvalidXMLDoesNotCreateTerminalResult(t *testing.T) {
	for _, fast := range []bool{false, true} {
		for _, description := range []string{`<domain><devices>`, `<unrelated/>`} {
			t.Run(fmt.Sprintf("fast=%v/%s", fast, description), func(t *testing.T) {
				mc, domain, uuid, meta := newVolumeRetypeTestCollector(t)
				state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
				if err != nil {
					t.Fatal(err)
				}
				key := volumeRetypeKey{InstanceUUID: uuid, DiskPath: "vde"}
				job := volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], time.Now())
				mc.volumeRetypeJobs[key] = job
				mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) { return description, nil }
				mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
					return 0, 0, 0, 0, 0, fmt.Errorf("progress unavailable")
				}
				if fast {
					mc.refreshActiveVolumeRetypes(time.Now())
				} else {
					mc.refreshVolumeRetypes([]libvirt.DomainStatsRecord{{Dom: domain}}, map[string]*DomainStatic{uuid: meta})
				}
				current, active := mc.volumeRetypeJobs[key]
				if !active || !current.ConfirmedAt.Equal(job.ConfirmedAt) || current.ObservationHealthy || len(mc.volumeRetypeCompleted) != 0 || mc.volumeRetypeResults != (volumeRetypeResultCounters{}) {
					t.Fatalf("invalid XML incorrectly confirmed/completed the job: active=%v current=%+v counters=%+v", active, current, mc.volumeRetypeResults)
				}
			})
		}
	}
}

func TestVolumeRetypeConcurrentRefreshAndScrapeCountsCompletionOnce(t *testing.T) {
	mc, domain, uuid, meta := newVolumeRetypeTestCollector(t)
	state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
	if err != nil {
		t.Fatal(err)
	}
	job := volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], time.Now())
	mc.volumeRetypeJobs[volumeRetypeKey{InstanceUUID: uuid, DiskPath: "vde"}] = job
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		return fmt.Sprintf(`<domain><devices><disk device="disk"><source protocol="rbd" name="%s"/><target dev="vde"/></disk></devices></domain>`, job.DestinationName), nil
	}
	mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
		return 0, 0, 0, 0, 0, nil
	}
	mc.backgroundOnce.Do(func() {})
	mc.cacheInitialized, mc.cachedLibvirtAvailable = true, true
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(mc)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for worker := 0; worker < 6; worker++ {
		workers.Add(1)
		go func(kind int) {
			defer workers.Done()
			<-start
			for attempt := 0; attempt < 20; attempt++ {
				switch kind % 3 {
				case 0:
					mc.refreshVolumeRetypes([]libvirt.DomainStatsRecord{{Dom: domain}}, map[string]*DomainStatic{uuid: meta})
				case 1:
					mc.refreshActiveVolumeRetypes(time.Now())
				case 2:
					if _, err := registry.Gather(); err != nil {
						t.Errorf("concurrent scrape: %v", err)
					}
				}
			}
		}(worker)
	}
	close(start)
	workers.Wait()
	if len(mc.volumeRetypeJobs) != 0 || len(mc.volumeRetypeCompleted) != 1 || mc.volumeRetypeResults != (volumeRetypeResultCounters{Success: 1}) {
		t.Fatalf("concurrent lifecycle work duplicated/lost completion: active=%d completed=%d counters=%+v", len(mc.volumeRetypeJobs), len(mc.volumeRetypeCompleted), mc.volumeRetypeResults)
	}
}

func TestVolumeRetypeTerminalMetricsFollowObservedFinalSource(t *testing.T) {
	for _, fast := range []bool{false, true} {
		for _, outcome := range []string{"destination", "original", "unmatched", "detached"} {
			t.Run(fmt.Sprintf("fast=%v/%s", fast, outcome), func(t *testing.T) {
				mc, domain, uuid, meta := newVolumeRetypeTestCollector(t)
				state, err := parseVolumeRetypeXML(activeVolumeRetypeXML)
				if err != nil {
					t.Fatal(err)
				}
				job := volumeRetypeJobFromCandidate(domain, meta, state.Candidates["vde"], time.Now())
				mc.volumeRetypeJobs[volumeRetypeKey{InstanceUUID: uuid, DiskPath: "vde"}] = job
				finalSource := job.DestinationName
				want := float64(volumeRetypeStatusSuccess)
				switch outcome {
				case "original":
					finalSource, want = job.SourceName, volumeRetypeStatusUnsuccessful
				case "unmatched", "detached":
					finalSource, want = "archive/volume-11111111-1111-4111-8111-111111111111", volumeRetypeStatusUnknown
				}
				description := fmt.Sprintf(`<domain><devices><disk device="disk"><source protocol="rbd" name="%s"/><target dev="vde"/></disk></devices></domain>`, finalSource)
				if outcome == "detached" {
					description = `<domain><devices/></domain>`
				}
				mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) { return description, nil }
				mc.libvirtBlockJobRPCOverride = func(*libvirt.Libvirt, libvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
					return 0, 0, 0, 0, 0, nil
				}
				if fast {
					mc.refreshActiveVolumeRetypes(time.Now())
				} else {
					mc.refreshVolumeRetypes([]libvirt.DomainStatsRecord{{Dom: domain}}, map[string]*DomainStatic{uuid: meta})
				}
				statusSeen, endSeen := false, false
				for _, metric := range mc.volumeRetypeMetrics(time.Now()) {
					value := metricDTO(t, metric).GetGauge().GetValue()
					switch metric.Desc() {
					case mc.im.instanceDiskRetypeActiveDesc:
						if value != 0 {
							t.Fatal("terminal operation still reports active")
						}
					case mc.im.instanceDiskRetypeStatusCodeDesc:
						statusSeen = value == want
					case mc.im.instanceDiskRetypeEndTimestampDesc:
						endSeen = value >= volumeRetypeTimestamp(job.ObservedStartAt)
					case mc.im.instanceDiskRetypeProgressDesc, mc.im.instanceDiskRetypeObservationHealthyDesc:
						t.Fatal("terminal operation retained live progress/query health")
					}
				}
				if !statusSeen || !endSeen {
					t.Fatalf("terminal metrics disagree with observed source: status=%v end=%v", statusSeen, endSeen)
				}
			})
		}
	}
}
