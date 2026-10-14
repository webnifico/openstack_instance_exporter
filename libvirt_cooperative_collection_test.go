package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
)

type cooperativeTestClient struct {
	stats    func([]libvirt.Domain, uint32, uint32) ([]libvirt.DomainStatsRecord, error)
	control  func(libvirt.Domain) (uint32, error)
	xml      func(libvirt.Domain) (string, error)
	xmlFlags func(libvirt.Domain, libvirt.DomainXMLFlags) (string, error)
	block    func(libvirt.Domain, string) (int32, int32, uint64, uint64, uint64, error)
}

func (c *cooperativeTestClient) ConnectGetAllDomainStats(d []libvirt.Domain, s, f uint32) ([]libvirt.DomainStatsRecord, error) {
	return c.stats(d, s, f)
}
func (c *cooperativeTestClient) DomainGetControlInfo(d libvirt.Domain, _ uint32) (uint32, uint32, uint64, error) {
	if c.control == nil {
		return 0, 0, 0, nil
	}
	s, e := c.control(d)
	return s, 0, 0, e
}
func (c *cooperativeTestClient) DomainGetXMLDesc(d libvirt.Domain, flags libvirt.DomainXMLFlags) (string, error) {
	if c.xmlFlags != nil {
		return c.xmlFlags(d, flags)
	}
	return c.xml(d)
}
func (c *cooperativeTestClient) DomainGetBlockJobInfo(d libvirt.Domain, p string, _ uint32) (int32, int32, uint64, uint64, uint64, error) {
	if c.block == nil {
		return 0, 0, 0, 0, 0, errors.New("unexpected progress query")
	}
	return c.block(d, p)
}

func cooperativeFixture(t *testing.T, mirror string) (*cooperativeTestClient, libvirt.Domain, *atomic.Int32) {
	t.Helper()
	dom, uuid := dataIntegrityDomain(0x79, "instance-cooperative")
	dom.ID = 7
	count := &atomic.Int32{}
	c := &cooperativeTestClient{}
	c.xml = func(libvirt.Domain) (string, error) {
		return fmt.Sprintf(`<domain><uuid>%s</uuid><devices><disk type="network" device="disk"><source protocol="rbd" name="premium/volume-1"/><target dev="vdb"/>%s</disk></devices></domain>`, uuid, mirror), nil
	}
	c.stats = func(doms []libvirt.Domain, stats, flags uint32) ([]libvirt.DomainStatsRecord, error) {
		if flags&libvirtStatsNowait == 0 {
			return nil, errors.New("blocking statistics requested")
		}
		r := libvirt.DomainStatsRecord{Dom: dom, Params: []libvirt.TypedParam{
			typedParam("state.state", int32(libvirt.DomainRunning)),
			typedParam("net.count", uint32(1)), typedParam("net.0.name", "tap0"),
			typedParam("net.0.rx.bytes", uint64(100)), typedParam("net.0.tx.bytes", uint64(200)),
		}}
		if len(doms) == 0 {
			if stats != uint32(_domainStatsState|_domainStatsInterface) {
				return nil, errors.New("inventory request entered monitor")
			}
		} else {
			if len(doms) != 1 || doms[0] != dom {
				return nil, errors.New("wrong domain for enrichment")
			}
			count.Add(1)
			if stats&uint32(_domainStatsCpuTotal) != 0 {
				r.Params = append(r.Params, typedParam("cpu.time", uint64(900)))
			}
			if stats&uint32(_domainStatsVcpu) != 0 {
				r.Params = append(r.Params, typedParam("vcpu.current", uint32(2)))
			}
			if stats&uint32(_domainStatsBalloon) != 0 {
				r.Params = append(r.Params, typedParam("balloon.current", uint64(1048576)), typedParam("balloon.usable", uint64(262144)))
			}
			if stats&uint32(_domainStatsBlock) != 0 {
				r.Params = append(r.Params, typedParam("block.count", uint32(1)), typedParam("block.0.name", "vdb"), typedParam("block.0.rd.bytes", uint64(42)), typedParam("block.0.capacity", uint64(1024)))
			}
		}
		return []libvirt.DomainStatsRecord{r}, nil
	}
	return c, dom, count
}

func TestLibvirtCooperativeMirrorsRetainNonStorageMeasurements(t *testing.T) {
	for _, mirror := range []string{
		`<mirror type="network" job="copy" ready="yes"/>`,
		`<mirror type="network" job="copy" ready="pivot"/>`,
		`<mirror type="network" job="copy" ready="abort"/>`,
		`<mirror type="network" job="copy"/>`,
		`<mirror type="file" job="copy"/>`,
		`<mirror type="file" job="active-commit" ready="pivot"/>`,
		`<mirror job="future-job"/>`,
		`<mirror/>`,
	} {
		t.Run(mirror, func(t *testing.T) {
			c, dom, count := cooperativeFixture(t, mirror)
			records, meta, err := collectCooperativeDomainStats(c, &libvirtReadSafety{}, time.Now().Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if count.Load() != 1 {
				t.Fatal("mirror domain lost its non-storage statistics request")
			}
			if len(records) != 1 || records[0].Dom != dom || len(meta) != 1 {
				t.Fatal("lost active inventory/metadata")
			}
			s := parseLibvirtStats(records[0].Params)
			if !s.BlockCountPresent || len(s.Disks) != 1 || s.Disks[0].Name != "vdb" {
				t.Fatal("lost disk identity")
			}
			if s.Disks[0].RdBytesPresent || s.Disks[0].CapacityPresent {
				t.Fatal("mirror domain entered storage statistics")
			}
			if !s.CpuTimePresent || s.CpuTime != 900 || !s.VcpuCurrentPresent || s.VcpuCurrent != 2 ||
				!s.MemCurPresent || s.MemCur != 1048576 || !s.MemUsablePresent || s.MemUsable != 262144 ||
				len(s.Nets) != 1 || !s.Nets[0].RxBytesPresent || s.Nets[0].RxBytes != 100 || !s.Nets[0].TxBytesPresent || s.Nets[0].TxBytes != 200 {
				t.Fatalf("mirror domain lost CPU, memory or network measurements: %+v", s)
			}
		})
	}
}

func TestLibvirtCooperativeBusyControlSkipsEveryDomainReader(t *testing.T) {
	for _, state := range []uint32{uint32(libvirt.DomainControlOccupied), uint32(libvirt.DomainControlJob), uint32(libvirt.DomainControlError), 99} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			c, dom, count := cooperativeFixture(t, "")
			c.control = func(libvirt.Domain) (uint32, error) { return state, nil }
			c.xml = func(libvirt.Domain) (string, error) { t.Error("busy domain XML was queried"); return "", nil }
			c.block = func(libvirt.Domain, string) (int32, int32, uint64, uint64, uint64, error) {
				t.Error("busy progress was queried")
				return 0, 0, 0, 0, 0, nil
			}
			safety := &libvirtReadSafety{}
			deadline := time.Now().Add(time.Second)
			records, _, err := collectCooperativeDomainStats(c, safety, deadline)
			if err != nil || len(records) != 1 || count.Load() != 0 {
				t.Fatalf("busy stats: %v %v %v", records, count.Load(), err)
			}
			if _, err := guardedDomainXML(c, safety, dom, deadline); !errors.Is(err, errLibvirtReadDeferred) {
				t.Fatalf("XML: %v", err)
			}
			if _, _, _, _, err := guardedBlockJobInfo(c, safety, dom, "vdb", deadline); !errors.Is(err, errLibvirtReadDeferred) {
				t.Fatalf("progress: %v", err)
			}
		})
	}
}

func TestLibvirtCooperativeOperationStartingDuringPreflightIsDeferred(t *testing.T) {
	c, _, count := cooperativeFixture(t, "")
	var control atomic.Int32
	c.control = func(libvirt.Domain) (uint32, error) {
		if control.Add(1) > 1 {
			return uint32(libvirt.DomainControlJob), nil
		}
		return 0, nil
	}
	records, meta, err := collectCooperativeDomainStats(c, &libvirtReadSafety{}, time.Now().Add(time.Second))
	if err != nil || len(records) != 1 || len(meta) != 1 || count.Load() != 0 {
		t.Fatalf("did not yield: calls=%d error=%v", count.Load(), err)
	}
}

func TestLibvirtCooperativeNowaitRaceRetainsPartialObservation(t *testing.T) {
	c, dom, _ := cooperativeFixture(t, "")
	original := c.stats
	c.stats = func(d []libvirt.Domain, s, f uint32) ([]libvirt.DomainStatsRecord, error) {
		if len(d) == 0 {
			return original(d, s, f)
		}
		// Another client acquires the job after our control check. The daemon
		// can return partial fields because the request carries NOWAIT.
		if f&libvirtStatsNowait == 0 {
			return nil, errors.New("request would queue behind operation")
		}
		return []libvirt.DomainStatsRecord{{Dom: dom, Params: []libvirt.TypedParam{typedParam("state.state", int32(libvirt.DomainRunning))}}}, nil
	}
	records, _, err := collectCooperativeDomainStats(c, &libvirtReadSafety{}, time.Now().Add(time.Second))
	if err != nil || len(records) != 1 {
		t.Fatal(err)
	}
	if parseLibvirtStats(records[0].Params).CpuTimePresent {
		t.Fatal("missing CPU counter became present")
	}
}

func TestLibvirtCooperativeHealthyCollectionRetainsOriginalMeasurements(t *testing.T) {
	c, _, count := cooperativeFixture(t, "")
	records, meta, err := collectCooperativeDomainStats(c, &libvirtReadSafety{}, time.Now().Add(time.Second))
	if err != nil || count.Load() != 1 || len(meta) != 1 {
		t.Fatalf("collection: %v", err)
	}
	s := parseLibvirtStats(records[0].Params)
	if !s.CpuTimePresent || s.CpuTime != 900 || !s.Disks[0].RdBytesPresent || s.Disks[0].RdBytes != 42 || !s.Disks[0].CapacityPresent || s.Disks[0].Capacity != 1024 {
		t.Fatalf("changed measured values: %+v", s)
	}
}

func TestLibvirtCooperativeControlFailureHasNoBlockingFallback(t *testing.T) {
	c, dom, count := cooperativeFixture(t, "")
	c.control = func(libvirt.Domain) (uint32, error) { return 0, errors.New("control API unsupported") }
	c.xml = func(libvirt.Domain) (string, error) {
		t.Error("XML queried after unavailable control state")
		return "", nil
	}
	safety := &libvirtReadSafety{}
	if _, _, err := collectCooperativeDomainStats(c, safety, time.Now().Add(time.Second)); err == nil {
		t.Fatal("unknown control state accepted")
	}
	if _, err := guardedDomainXML(c, safety, dom, time.Now().Add(time.Second)); err == nil {
		t.Fatal("unknown XML control state accepted")
	}
	if count.Load() != 0 {
		t.Fatal("unsafe stats fallback")
	}
}

func TestLibvirtCooperativeDeadlinePreventsLateMonitorQuery(t *testing.T) {
	c, _, count := cooperativeFixture(t, "")
	deadline := time.Now().Add(20 * time.Millisecond)
	c.control = func(libvirt.Domain) (uint32, error) { time.Sleep(30 * time.Millisecond); return 0, nil }
	_, _, err := collectCooperativeDomainStats(c, &libvirtReadSafety{}, deadline)
	if err != nil {
		t.Fatal(err)
	}
	if count.Load() != 0 {
		t.Fatal("late control reply started monitor work")
	}
}

func TestLibvirtCooperativeSharedBackoffProtectsAllReadersAndReconnect(t *testing.T) {
	c, dom, _ := cooperativeFixture(t, "")
	c.stats = func([]libvirt.Domain, uint32, uint32) ([]libvirt.DomainStatsRecord, error) {
		t.Error("stats during backoff")
		return nil, nil
	}
	c.control = func(libvirt.Domain) (uint32, error) { t.Error("control during backoff"); return 0, nil }
	safety := &libvirtReadSafety{}
	safety.pause(time.Now())
	deadline := time.Now().Add(time.Second)
	if _, _, err := collectCooperativeDomainStats(c, safety, deadline); !errors.Is(err, errLibvirtReadDeferred) {
		t.Fatal(err)
	}
	if _, err := guardedDomainXML(c, safety, dom, deadline); !errors.Is(err, errLibvirtReadDeferred) {
		t.Fatal(err)
	}
	if _, _, _, _, err := guardedBlockJobInfo(c, safety, dom, "vdb", deadline); !errors.Is(err, errLibvirtReadDeferred) {
		t.Fatal(err)
	}
	mc := &MetricsCollector{libvirtSafety: safety}
	if _, err := mc.getLibvirtConn(); !errors.Is(err, errLibvirtReadDeferred) {
		t.Fatalf("reconnect was attempted: %v", err)
	}
	if err := safety.available(time.Now().Add(libvirtReadBackoff + time.Second)); err != nil {
		t.Fatalf("backoff never recovers: %v", err)
	}
}

func TestLibvirtCooperativeInflightSurvivesTimeoutAndOtherReaderTypes(t *testing.T) {
	c, dom, _ := cooperativeFixture(t, "")
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	c.xml = func(libvirt.Domain) (string, error) { close(started); <-release; return "<domain/>", nil }
	safety := &libvirtReadSafety{}
	go func() { defer close(finished); _, _ = guardedDomainXML(c, safety, dom, time.Now().Add(time.Second)) }()
	<-started
	if _, _, _, _, err := guardedBlockJobInfo(c, safety, dom, "vdb", time.Now().Add(time.Second)); !errors.Is(err, errLibvirtReadDeferred) {
		t.Fatalf("progress overlapped raw XML: %v", err)
	}
	safety.pause(time.Now())
	// Expire the backoff without releasing the raw request: the independent
	// in-flight guard must still reject another request on that domain.
	safety.mu.Lock()
	safety.resumeAfter = time.Time{}
	safety.mu.Unlock()
	if _, _, _, _, err := guardedBlockJobInfo(c, safety, dom, "vdb", time.Now().Add(time.Second)); !errors.Is(err, errLibvirtReadDeferred) {
		t.Fatalf("lost raw request guard: %v", err)
	}
	unblock()
	<-finished
	end, err := safety.begin(volumeRetypeDomainKey(dom), time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	end()
}

func TestLibvirtCooperativeRejectsUnexpectedDomainIdentity(t *testing.T) {
	for _, phase := range []string{"xml", "stats"} {
		t.Run(phase, func(t *testing.T) {
			c, _, _ := cooperativeFixture(t, "")
			if phase == "xml" {
				c.xml = func(libvirt.Domain) (string, error) { return `<domain><uuid>wrong</uuid></domain>`, nil }
			} else {
				original := c.stats
				c.stats = func(d []libvirt.Domain, s, f uint32) ([]libvirt.DomainStatsRecord, error) {
					r, e := original(d, s, f)
					if len(d) > 0 {
						r[0].Dom.ID++
					}
					return r, e
				}
			}
			if _, _, err := collectCooperativeDomainStats(c, &libvirtReadSafety{}, time.Now().Add(time.Second)); err == nil {
				t.Fatal("accepted replaced domain")
			}
		})
	}
}

func TestLibvirtCooperativeProductionQueriesUseSharedSafetyLayer(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	queries := map[string]bool{"ConnectGetAllDomainStats": true, "DomainGetXMLDesc": true, "DomainGetBlockJobInfo": true, "DomainGetControlInfo": true}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if queries[selector.Sel.Name] && path != "libvirt_cooperative_collection.go" {
				t.Errorf("unguarded production query in %s: %s", path, selector.Sel.Name)
			}
			return true
		})
	}
	data, err := os.ReadFile("libvirt_cooperative_collection.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"QemuMonitorCommand(", "DomainBlockJobAbort(", "DomainBlockInfo("} {
		if strings.Contains(string(data), unsafe) {
			t.Errorf("unexpected invasive fallback: %s", unsafe)
		}
	}
}

func TestLibvirtCooperativeRetainsInactiveInventoryWithoutMonitorQueries(t *testing.T) {
	c, active, count := cooperativeFixture(t, "")
	inactive, _ := dataIntegrityDomain(0x78, "instance-inactive-cooperative")
	inactive.ID = -1
	original := c.stats
	c.stats = func(d []libvirt.Domain, stats, flags uint32) ([]libvirt.DomainStatsRecord, error) {
		if len(d) == 0 {
			if flags != libvirtStatsNowait {
				return nil, fmt.Errorf("inventory unexpectedly filters inactive definitions: %d", flags)
			}
			records, err := original(d, stats, flags)
			return append(records, libvirt.DomainStatsRecord{Dom: inactive, Params: []libvirt.TypedParam{typedParam("state.state", int32(libvirt.DomainShutoff))}}), err
		}
		if d[0].ID < 0 {
			return nil, errors.New("inactive domain entered monitor enrichment")
		}
		return original(d, stats, flags)
	}
	c.control = func(dom libvirt.Domain) (uint32, error) {
		if dom.ID < 0 {
			return 0, errors.New("inactive control queried")
		}
		return uint32(libvirt.DomainControlOk), nil
	}
	records, metadata, err := collectCooperativeDomainStats(c, &libvirtReadSafety{}, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Dom != active || records[1].Dom != inactive || count.Load() != 1 || len(metadata) != 1 {
		t.Fatalf("inventory or enrichment changed: records=%v metadata=%d calls=%d", records, len(metadata), count.Load())
	}
	if parseLibvirtStats(records[1].Params).CpuTimePresent {
		t.Fatal("inactive resource data fabricated")
	}
}

func TestLibvirtCooperativeInactiveXMLAlwaysUsesPersistentDefinition(t *testing.T) {
	c, dom, _ := cooperativeFixture(t, "")
	dom.ID = -1
	c.control = func(libvirt.Domain) (uint32, error) {
		t.Error("inactive metadata queried live domain control")
		return 0, errors.New("inactive domain has no monitor")
	}
	var reads atomic.Int32
	c.xmlFlags = func(got libvirt.Domain, flags libvirt.DomainXMLFlags) (string, error) {
		if got != dom || flags != libvirt.DomainXMLInactive {
			return "", fmt.Errorf("persistent definition required even during a concurrent start: %v %d", got, flags)
		}
		reads.Add(1)
		return c.xml(got)
	}
	safety := &libvirtReadSafety{}
	if _, err := guardedDomainXML(c, safety, dom, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	safety.pause(time.Now())
	if _, err := guardedDomainXML(c, safety, dom, time.Now().Add(time.Second)); !errors.Is(err, errLibvirtReadDeferred) {
		t.Fatalf("inactive XML bypassed shared backoff: %v", err)
	}
	if reads.Load() != 1 {
		t.Fatalf("unexpected XML reads: %d", reads.Load())
	}
}
