package main

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"libvirt.org/go/libvirt"
)

// -----------------------------------------------------------------------------
// Enums & Basic Types
// -----------------------------------------------------------------------------

// Conntrack Status Bits (Linux Kernel defaults)
const (
	IPS_SEEN_REPLY = (1 << 1)
	IPS_ASSURED    = (1 << 2)
)

type ContactDirection int

const (
	ContactAny ContactDirection = iota
	ContactOut
	ContactIn
)

func parseContactDirection(s string) ContactDirection {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "any":
		return ContactAny
	case "in", "inbound", "dst":
		return ContactIn
	case "out", "outbound", "src":
		return ContactOut
	default:
		return ContactOut
	}
}

func (d ContactDirection) String() string {
	switch d {
	case ContactAny:
		return "any"
	case ContactIn:
		return "in"
	default:
		return "out"
	}
}

func flowDirection(ipSet map[string]struct{}, ct ConntrackEntry) string {
	_, isVMsrc := ipSet[ct.Src]
	_, isVMdst := ipSet[ct.Dst]
	if isVMsrc && !isVMdst {
		return "out"
	}
	if isVMdst && !isVMsrc {
		return "in"
	}
	return "any"
}

// -----------------------------------------------------------------------------
// Configuration Structs
// -----------------------------------------------------------------------------

type ScoringConfig struct {
	ResourceWeight float64
	ThreatWeight   float64
	TorSignal      float64
	RelaySignal    float64
	SpamSignal     float64
	EmergingSignal float64
	CustomSignal   float64
	BehaviorSignal float64
}

type CollectorConfig struct {
	LibvirtURI             string
	Threshold              ThresholdConfig
	BehaviorThresholds     BehaviorThresholds
	Scoring                ScoringConfig
	WorkerCount            int
	OutboundBehaviorEnable bool
	InboundBehaviorEnable  bool
	ThreatFileEnable       bool
	ThreatFilePath         string
	ThreatFileMinInterval  time.Duration
	HostThreats            HostThreatsConfig
	TorExit                ThreatListConfig
	TorRelay               ThreatListConfig
	Spamhaus               SpamhausConfig
	Emerging               ThreatListConfig
	Custom                 CustomListConfig
	MinAttentionScore      float64
	CollectionInterval     time.Duration
}

type ThresholdConfig struct {
	Read         map[string]int
	Write        map[string]int
	DefaultRead  int
	DefaultWrite int
}

type BehaviorThresholds struct {
	OutboundFlowsTotal int
	InboundFlowsTotal  int
}

type HostThreatsConfig struct {
	Enable          bool
	IPsAllowPrivate bool
	Interfaces      map[string]struct{}
}

type ThreatListConfig struct {
	Enable    bool
	URL       string
	Refresh   time.Duration
	Direction ContactDirection
}

type SpamhausConfig struct {
	Enable    bool
	URLv4     string
	URLv6     string
	Refresh   time.Duration
	Direction ContactDirection
}

type CustomListConfig struct {
	Enable    bool
	Path      string
	Refresh   time.Duration
	Direction ContactDirection
}

// -----------------------------------------------------------------------------
// Data Structures
// -----------------------------------------------------------------------------

type DomainStatic struct {
	Name            string
	InstanceUUID    string
	UserUUID        string
	UserName        string
	ProjectUUID     string
	ProjectName     string
	FlavorName      string
	VCPUCount       int
	MemMB           int
	RootType        string
	CreatedAt       string
	MetadataVersion string
	FixedIPs        []IP
	Disks           []DomainDisk
	Interfaces      []string
}

type DomainXML struct {
	UUID     string `xml:"uuid"`
	Metadata struct {
		NovaInstance struct {
			NovaPackage struct {
				Version string `xml:"version,attr"`
			} `xml:"package"`
			NovaName     string `xml:"name"`
			CreationTime string `xml:"creationTime"`
			NovaFlavor   struct {
				FlavorName string `xml:"name,attr"`
				MemoryMB   int    `xml:"memory"`
				VCPUs      int    `xml:"vcpus"`
			} `xml:"flavor"`
			NovaOwner struct {
				NovaUser struct {
					UserName string `xml:",chardata"`
					UserUUID string `xml:"uuid,attr"`
				} `xml:"user"`
				NovaProject struct {
					ProjectName string `xml:",chardata"`
					ProjectUUID string `xml:"uuid,attr"`
				} `xml:"project"`
			} `xml:"owner"`
			NovaRoot struct {
				RootType string `xml:"type,attr"`
				RootUUID string `xml:"uuid,attr"`
			} `xml:"root"`
			NovaPorts struct {
				Ports []struct {
					PortUUID string `xml:"uuid,attr"`
					IPs      []struct {
						Address   string `xml:"address,attr"`
						IPVersion string `xml:"ipVersion,attr"`
					} `xml:"ip"`
				} `xml:",any"`
			} `xml:"ports"`
		} `xml:"instance"`
	} `xml:"metadata"`
	Devices struct {
		Disks      []Disk      `xml:"disk"`
		Interfaces []Interface `xml:"interface"`
	} `xml:"devices"`
}

type Disk struct {
	Device string `xml:"device,attr"`
	Type   string `xml:"type,attr"`
	Source struct {
		Protocol string `xml:"protocol,attr"`
		File     string `xml:"file,attr"`
		Name     string `xml:"name,attr"`
	} `xml:"source"`
	Target struct {
		Dev string `xml:"dev,attr"`
	} `xml:"target"`
}

type Interface struct {
	Target struct {
		Dev string `xml:"dev,attr"`
	} `xml:"target"`
	IPs []IP `xml:"ip"`
}

type IP struct {
	Address string `xml:"address,attr"`
	Family  string `xml:"family,attr"`
	Prefix  string `xml:"prefix,attr"`
}

type DomainDisk struct {
	Device     string
	Type       string
	SourceName string
	SourceFile string
	TargetDev  string
}

type ConntrackEntry struct {
	Src     string
	Dst     string
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Status  uint32
	Zone    uint16
	Bytes   uint64
	Packets uint64
}

type OnionooSummary struct {
	Relays []struct {
		OrAddresses []string `json:"or_addresses"`
	} `json:"relays"`
}

type cpuSample struct {
	total uint64
	ts    time.Time
}

type diskSample struct {
	rdReq int64
	wrReq int64
	ts    time.Time
}

// -----------------------------------------------------------------------------
// Behavior Keys & Maps
// -----------------------------------------------------------------------------

// BehaviorKey replaces string concatenation (InstanceUUID + "|" + IP)
type BehaviorKey struct {
	InstanceUUID string
	IP           string
}

// AnomalyKey uses BehaviorKey and adds threshold type
type AnomalyKey struct {
	BehaviorKey
	ThresholdKey string // "outbound" or "inbound"
}

type outboundPrev struct {
	remotes map[string]struct{}
}

type outboundPrevDstPorts struct {
	ports map[uint16]struct{}
}

type AnomalyState struct {
	AvgFlows     float64
	FlowVariance float64
	SampleCount  int64
}

type BehaviorContext struct {
	HostIPs []string
}

type behaviorStats struct {
	remotes        map[string]struct{}
	remoteZones    map[string]uint16
	perRemote      map[string]int
	dstPorts       map[uint16]struct{}
	perDstPort     map[uint16]int
	flows          int
	unreplied      int
	bytes          uint64
	packets        uint64
	sampleRemote   string
	sampleDstPort  uint16
	multicastCount int
	icmpCount      int
}

type metricDescGroup struct {
	uniqueRemotes      *prometheus.Desc
	newRemotes         *prometheus.Desc
	flows              *prometheus.Desc
	maxSingleRemote    *prometheus.Desc
	uniqueDstPorts     *prometheus.Desc
	newDstPorts        *prometheus.Desc
	maxSingleDstPort   *prometheus.Desc
	thresholdConfigKey string
}

type hostAgg struct {
	mu       sync.Mutex
	disks    int
	fixedIPs int
	projects map[string]struct{}
	vcpus    int
	metrics  []prometheus.Metric
}

// -----------------------------------------------------------------------------
// Managers
// -----------------------------------------------------------------------------

type InstanceManager struct {
	libvirtURI            string
	workerCount           int
	domainMetaMu          sync.RWMutex
	domainMeta            map[string]*DomainStatic
	activeInstancesMu     sync.RWMutex
	activeInstances       map[string]struct{}
	readThreshold         map[string]int
	writeThreshold        map[string]int
	defaultReadThreshold  int
	defaultWriteThreshold int
	cpuMu                 sync.Mutex
	cpuSamples            map[string]cpuSample
	diskMu                sync.Mutex
	diskSamples           map[string]diskSample

	instanceInfoDesc                    *prometheus.Desc
	instanceDiskReadAlertThresholdDesc  *prometheus.Desc
	instanceDiskWriteAlertThresholdDesc *prometheus.Desc
	instanceDiskReadGbytesTotalDesc     *prometheus.Desc
	instanceDiskWriteGbytesTotalDesc    *prometheus.Desc
	instanceDiskReadRequestsTotalDesc   *prometheus.Desc
	instanceDiskWriteRequestsTotalDesc  *prometheus.Desc
	instanceDiskInfoDesc                *prometheus.Desc
	instanceCpuVcpuPercentDesc          *prometheus.Desc
	instanceCpuVcpuCountDesc            *prometheus.Desc
	instanceMemAllocatedMBDesc          *prometheus.Desc
	instanceMemUsedMBDesc               *prometheus.Desc
	instanceNetRxGbytesTotalDesc        *prometheus.Desc
	instanceNetTxGbytesTotalDesc        *prometheus.Desc
	instanceNetRxPacketsTotalDesc       *prometheus.Desc
	instanceNetTxPacketsTotalDesc       *prometheus.Desc
	instanceNetRxErrorsTotalDesc        *prometheus.Desc
	instanceNetTxErrorsTotalDesc        *prometheus.Desc
	instanceNetRxDroppedTotalDesc       *prometheus.Desc
	instanceNetTxDroppedTotalDesc       *prometheus.Desc
}

type ThreatManager struct {
	httpClient   *http.Client
	shutdownChan chan struct{}

	torExitEnabled            bool
	torExitURL                string
	torExitRefresh            time.Duration
	torExitSet                map[string]struct{}
	torExitMu                 sync.RWMutex
	torExitDir                ContactDirection
	torExitLastSuccessUnix    float64
	torExitLastRefreshSeconds float64
	torExitEntries            int
	torExitRefreshErrors      uint64

	torRelayEnabled            bool
	torRelayURL                string
	torRelayRefresh            time.Duration
	torRelaySet                map[string]struct{}
	torRelayMu                 sync.RWMutex
	torRelayDir                ContactDirection
	torRelayLastSuccessUnix    float64
	torRelayLastRefreshSeconds float64
	torRelayEntries            int
	torRelayRefreshErrors      uint64

	spamEnabled            bool
	spamURL                string
	spamV6URL              string
	spamRefresh            time.Duration
	spamNets               []*net.IPNet
	spamBucketsV4          map[string][]*net.IPNet
	spamBucketsV6          map[string][]*net.IPNet
	spamMu                 sync.RWMutex
	spamDir                ContactDirection
	spamLastSuccessUnix    float64
	spamLastRefreshSeconds float64
	spamEntries            int
	spamRefreshErrors      uint64

	emThreatsEnabled            bool
	emThreatsURL                string
	emThreatsRefresh            time.Duration
	emThreatsSet                map[string]struct{}
	emThreatsMu                 sync.RWMutex
	emThreatsDir                ContactDirection
	emThreatsLastSuccessUnix    float64
	emThreatsLastRefreshSeconds float64
	emThreatsEntries            int
	emThreatsRefreshErrors      uint64

	customListEnabled            bool
	customListPath               string
	customListRefresh            time.Duration
	customListSet                map[string]struct{}
	customListMu                 sync.RWMutex
	customListDir                ContactDirection
	customListLastSuccessUnix    float64
	customListLastRefreshSeconds float64
	customListEntries            int
	customListRefreshErrors      uint64

	threatCountMu   sync.Mutex
	torExitCount    map[string]float64
	torRelayCount   map[string]float64
	spamCount       map[string]float64
	emThreatsCount  map[string]float64
	customListCount map[string]float64

	threatFileEnabled     bool
	threatFilePath        string
	threatFile            *os.File
	threatFileMu          sync.Mutex
	threatFileMinInterval time.Duration
	threatLastHitMu       sync.Mutex
	threatLastHit         map[string]time.Time

	hostThreatsEnabled  bool
	hostThreatHitsMu    sync.RWMutex
	hostThreatHits      map[string]map[string]string
	hostIPsAllowPrivate bool
	hostInterfaces      map[string]struct{}

	instanceTorExitContactsTotalDesc           *prometheus.Desc
	instanceTorExitActiveFlowsDesc             *prometheus.Desc
	hostTorExitRefreshLastSuccessTimestampDesc *prometheus.Desc
	hostTorExitRefreshDurationSecondsDesc      *prometheus.Desc
	hostTorExitRefreshErrorsTotalDesc          *prometheus.Desc
	hostTorExitEntriesDesc                     *prometheus.Desc

	instanceTorRelayContactsTotalDesc           *prometheus.Desc
	instanceTorRelayActiveFlowsDesc             *prometheus.Desc
	hostTorRelayRefreshLastSuccessTimestampDesc *prometheus.Desc
	hostTorRelayRefreshDurationSecondsDesc      *prometheus.Desc
	hostTorRelayRefreshErrorsTotalDesc          *prometheus.Desc
	hostTorRelayEntriesDesc                     *prometheus.Desc

	instanceSpamhausContactsTotalDesc           *prometheus.Desc
	instanceSpamhausActiveFlowsDesc             *prometheus.Desc
	hostSpamhausRefreshLastSuccessTimestampDesc *prometheus.Desc
	hostSpamhausRefreshDurationSecondsDesc      *prometheus.Desc
	hostSpamhausRefreshErrorsTotalDesc          *prometheus.Desc
	hostSpamhausEntriesDesc                     *prometheus.Desc

	instanceEmergingThreatsContactsTotalDesc           *prometheus.Desc
	instanceEmergingThreatsActiveFlowsDesc             *prometheus.Desc
	hostEmergingThreatsRefreshLastSuccessTimestampDesc *prometheus.Desc
	hostEmergingThreatsRefreshDurationSecondsDesc      *prometheus.Desc
	hostEmergingThreatsRefreshErrorsTotalDesc          *prometheus.Desc
	hostEmergingThreatsEntriesDesc                     *prometheus.Desc

	instanceCustomlistContactsTotalDesc           *prometheus.Desc
	instanceCustomlistActiveFlowsDesc             *prometheus.Desc
	hostCustomlistRefreshLastSuccessTimestampDesc *prometheus.Desc
	hostCustomlistRefreshDurationSecondsDesc      *prometheus.Desc
	hostCustomlistRefreshErrorsTotalDesc          *prometheus.Desc
	hostCustomlistEntriesDesc                     *prometheus.Desc

	hostThreatListedDesc *prometheus.Desc
}

type ConntrackManager struct {
	outboundBehaviorEnabled bool
	inboundBehaviorEnabled  bool
	behaviorThresholds      BehaviorThresholds

	outboundMu           sync.Mutex
	outboundPrev         map[BehaviorKey]outboundPrev
	outboundPrevDstPorts map[BehaviorKey]outboundPrevDstPorts

	inboundMu           sync.Mutex
	inboundPrev         map[BehaviorKey]outboundPrev
	inboundPrevDstPorts map[BehaviorKey]outboundPrevDstPorts

	behaviorStateMu sync.Mutex
	behaviorState   map[AnomalyKey]*AnomalyState

	conntrackReadErrors uint64

	LogThreat func(tag, event, domain, instanceUUID, projectUUID, projectName, userUUID string, kvpairs ...interface{})

	instanceConntrackIPFlowsDesc         *prometheus.Desc
	instanceConntrackIPFlowsInboundDesc  *prometheus.Desc
	instanceConntrackIPFlowsOutboundDesc *prometheus.Desc

	instanceOutboundUniqueRemotesDesc         *prometheus.Desc
	instanceOutboundNewRemotesDesc            *prometheus.Desc
	instanceOutboundFlowsDesc                 *prometheus.Desc
	instanceOutboundMaxFlowsSingleRemoteDesc  *prometheus.Desc
	instanceOutboundUniqueDstPortsDesc        *prometheus.Desc
	instanceOutboundNewDstPortsDesc           *prometheus.Desc
	instanceOutboundMaxFlowsSingleDstPortDesc *prometheus.Desc

	instanceInboundUniqueRemotesDesc         *prometheus.Desc
	instanceInboundNewRemotesDesc            *prometheus.Desc
	instanceInboundFlowsDesc                 *prometheus.Desc
	instanceInboundMaxFlowsSingleRemoteDesc  *prometheus.Desc
	instanceInboundUniqueDstPortsDesc        *prometheus.Desc
	instanceInboundNewDstPortsDesc           *prometheus.Desc
	instanceInboundMaxFlowsSingleDstPortDesc *prometheus.Desc
}

type MetricsCollector struct {
	shutdownEvents     prometheus.Counter
	shutdownChan       chan struct{}
	minAttentionScore  float64
	scoring            ScoringConfig
	collectionInterval time.Duration
	backgroundOnce     sync.Once
	cacheMu            sync.RWMutex
	cachedMetrics      []prometheus.Metric

	// Persistence for Libvirt
	libvirtConn *libvirt.Connect
	libvirtMu   sync.Mutex

	im *InstanceManager
	tm *ThreatManager
	cm *ConntrackManager

	hostCollectionErrors uint64
	lastCycleEndUnixNano int64

	hostMemTotalMBDesc                     *prometheus.Desc
	hostLibvirtActiveVMsDesc               *prometheus.Desc
	hostCpuActiveVcpusDesc                 *prometheus.Desc
	hostActiveDisksDesc                    *prometheus.Desc
	hostActiveFixedIPsDesc                 *prometheus.Desc
	hostActiveProjectsDesc                 *prometheus.Desc
	hostCpuThreadsDesc                     *prometheus.Desc
	hostCollectionErrorsTotalDesc          *prometheus.Desc
	hostCollectionCycleDurationSecondsDesc *prometheus.Desc
	hostCollectionCycleLagSecondsDesc      *prometheus.Desc
	hostLibvirtListDurationSecondsDesc     *prometheus.Desc
	hostConntrackReadDurationSecondsDesc   *prometheus.Desc
	hostConntrackEntriesDesc               *prometheus.Desc
	hostGoHeapAllocBytesDesc               *prometheus.Desc
	hostConntrackReadErrorsTotalDesc       *prometheus.Desc
	hostConntrackMaxDesc                   *prometheus.Desc
	hostConntrackUtilizationDesc           *prometheus.Desc
	hostCacheCleanupDurationSecondsDesc    *prometheus.Desc

	instanceResourceScoreDesc  *prometheus.Desc
	instanceThreatScoreDesc    *prometheus.Desc
	instanceAttentionScoreDesc *prometheus.Desc
}
