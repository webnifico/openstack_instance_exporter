package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

// -----------------------------------------------------------------------------
// Enums & Basic Types
// -----------------------------------------------------------------------------

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

// Resource EWMA State
// -----------------------------------------------------------------------------

type axisEWMA struct {
	Fast        float64
	Slow        float64
	Initialized bool
}

type IntelHistory struct {
	EWMA        float64
	Initialized bool
}

type SeverityConfig struct {
	BehaviorWeight float64
	ResourceWeight float64
	ThreatWeight   float64
}

type CollectorConfig struct {
	LibvirtURI                     string
	BehaviorThresholds             BehaviorThresholds
	BehaviorSensitivity            float64
	BehaviorPortsConfigPath        string
	BehaviorRulesConfigPath        string
	BehaviorExternalRules          []BehaviorRule
	BehaviorEWMATauFast            time.Duration
	BehaviorEWMATauSlow            time.Duration
	BehaviorPortsInboundMonitored  map[uint16]string
	BehaviorPortsOutboundMonitored map[uint16]string
	Severity                       SeverityConfig
	WorkerCount                    int
	OutboundBehaviorEnable         bool
	InboundBehaviorEnable          bool
	ConntrackAcctEnabled           bool
	ConntrackRawRcvBufBytes        int
	ConntrackIPv4Enable            bool
	ConntrackIPv6Enable            bool
	ThreatLogMinInterval           time.Duration
	HostThreats                    HostThreatsConfig
	TorExit                        ThreatListConfig
	TorRelay                       ThreatListConfig
	Spamhaus                       SpamhausConfig
	Emerging                       ThreatListConfig
	Custom                         CustomListConfig
	CollectionInterval             time.Duration
}

type BehaviorThresholds struct {
	OutboundFlowsTotal int
	InboundFlowsTotal  int
}

type BehaviorPortsConfigStatus struct {
	Path          string
	Status        string
	Using         string
	InboundPorts  int
	OutboundPorts int
	Err           string
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
// LibvirtData Structures (Manual Parsing)
// -----------------------------------------------------------------------------

type ParsedStats struct {
	State      int
	CpuTime    uint64
	CpuUser    uint64
	CpuSystem  uint64
	Vcpus      map[int]*VcpuStat
	MemMax     uint64
	MemCur     uint64
	MemUsable  uint64 // Available RAM (Total - Used)
	MemRss     uint64 // Actual Host RAM
	MajorFault uint64
	MinorFault uint64
	SwapIn     uint64
	SwapOut    uint64
	Disks      map[int]*DiskStat
	Nets       map[int]*NetStat
}

type VcpuStat struct {
	State uint64
	Time  uint64
	Wait  uint64
	Delay uint64
}

type DiskStat struct {
	Name       string
	RdReqs     uint64
	RdBytes    uint64
	RdTime     uint64
	WrReqs     uint64
	WrBytes    uint64
	WrTime     uint64
	FlReqs     uint64
	FlTime     uint64
	Physical   uint64
	Capacity   uint64
	Allocation uint64
}

type NetStat struct {
	Name    string
	RxBytes uint64
	RxPkts  uint64
	RxErrs  uint64
	RxDrop  uint64
	TxBytes uint64
	TxPkts  uint64
	TxErrs  uint64
	TxDrop  uint64
}

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
	PortUUIDs       []string // Added missing field
	PortIPsByUUID   map[string][]IP
	Disks           []DomainDisk
	Interfaces      []string
	LastUpdated     time.Time
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

type ConntrackFlowLite struct {
	SrcIP          IPKey
	DstIP          IPKey
	SrcPort        uint16
	DstPort        uint16
	Proto          uint8
	Zone           uint16
	ForwardPackets uint64
	ForwardBytes   uint64
	ReversePackets uint64
}

// IPKey is a 16-byte array used as a map key to avoid string allocations.
// IPv4 addresses are stored as IPv4-mapped IPv6 (::ffff:1.2.3.4).
type IPKey [16]byte

type PairKey struct {
	A IPKey
	B IPKey
}

type VMIPIdentity struct {
	InstanceUUID string
	IP           IPKey
}

type ConntrackAgg struct {
	VMIndex map[VMIPIdentity]uint32

	FlowsIn  []int
	FlowsOut []int

	OutboundStats []*behaviorStats
	InboundStats  []*behaviorStats

	SpamhausHits        map[string]map[PairKey]ConntrackEntry
	SpamhausHitsDropped map[string]uint64
	ProviderHits        map[string]map[string]map[PairKey]ConntrackEntry
	ProviderHitsDropped map[string]map[string]uint64
}

type OnionooSummary struct {
	Relays []struct {
		OrAddresses []string `json:"or_addresses"`
	} `json:"relays"`
}

// -----------------------------------------------------------------------------
// Sample Structures
// -----------------------------------------------------------------------------

type cpuSample struct {
	total uint64
	steal uint64
	wait  uint64
	ts    time.Time
}

type diskSample struct {
	rdReq   int64
	wrReq   int64
	rdBytes int64
	wrBytes int64
	rdTime  int64
	wrTime  int64
	flReq   int64
	flTime  int64
	ts      time.Time
}

type memSample struct {
	swapIn     uint64
	swapOut    uint64
	majorFault uint64
	minorFault uint64
	ts         time.Time
}

type netSample struct {
	rxPkts uint64
	txPkts uint64
	rxDrop uint64
	txDrop uint64
	ts     time.Time
}

// -----------------------------------------------------------------------------
// Behavior Maps
// -----------------------------------------------------------------------------

type BehaviorKey struct {
	InstanceUUID string
	IP           IPKey
}

type outboundPrev struct {
	remotes map[IPKey]struct{}
}

type outboundPrevDstPorts struct {
	ports map[uint16]struct{}
}

type BehaviorContext struct {
	HostIPs          map[string]struct{}
	HostIPKeys       map[IPKey]struct{}
	HostConntrackMax uint64
}

type behaviorAlertKey struct {
	InstanceUUID string
	IP           IPKey
	Direction    string
	Kind         string
}

type behaviorEmitKey struct {
	InstanceUUID string
	IP           IPKey
	Direction    string
}

type behaviorPersistState struct {
	Hits          int
	FirstSeenUnix int64
	LastSeenUnix  int64
}

type behaviorEmitState struct {
	LastKind         string
	LastPriority     string
	LastSeverityBand string
	LastTopRemote    string
	LastTopDstPort   uint16
	LastEmitUnix     int64
}

type BehaviorFeature struct {
	Direction string

	ThresholdFlows int
	LocalScanHits  int
	InfraHits      int
	InfraMaxFlows  int
	PublicRemotes  int

	MetadataHits           int
	MetadataMaxFlows       int
	MetadataUnrepliedRatio float64

	BGPFlows     int
	GeneveFlows  int
	SMTPFlows    int
	StratumFlows int

	AdminPortFlows int

	Flows                       int
	UniqueRemotes               int
	NewRemotes                  int
	UniqueDstPorts              int
	NewDstPorts                 int
	MaxSingleRemote             int
	MaxSingleDstPort            int
	TopDstPort                  uint16
	UnmonitoredPortFlows        int
	UnmonitoredUniqueDstPorts   int
	MaxSingleUnmonitoredDstPort int
	TopUnmonitoredDstPort       uint16
	SynergyDarkScan             bool
	SynergyDarkPhysics          bool
	UnrepliedRatio              float64
	MulticastCount              int
	ICMPCount                   int
	UDPCount                    int

	BytesPerFlow   float64
	PacketsPerFlow float64

	HostImpactPercent float64

	RemoteMapCapped bool
	PortMapCapped   bool

	ConntrackAcct bool
}

type behaviorEWMAState struct {
	LastSeenUnix  int64
	Flows         axisEWMA
	UniqueRemotes axisEWMA
	UniquePorts   axisEWMA
	Unreplied     axisEWMA
	BytesPerFlow  axisEWMA
	PktsPerFlow   axisEWMA
}

type behaviorIdentityKey struct {
	InstanceUUID string
	IP           IPKey
	Direction    string // "outbound" or "inbound"
}

type behaviorStats struct {
	trackAcct bool

	remotes            map[IPKey]struct{}
	remoteZones        map[IPKey]uint16
	remoteIsPrivate    map[IPKey]bool
	perRemote          map[IPKey]int
	perRemoteUnreplied map[IPKey]int
	dstPorts           map[uint16]struct{}
	perDstPort         map[uint16]int
	flows              int
	unreplied          int
	bytes              uint64
	packets            uint64
	sampleRemote       IPKey
	sampleRemoteSet    bool
	sampleDstPort      uint16
	multicastCount     int
	icmpCount          int
	udpCount           int

	remoteMapCapped bool
	portMapCapped   bool
}

type metricDescGroup struct {
	uniqueRemotes      *prometheus.Desc
	newRemotes         *prometheus.Desc
	flows              *prometheus.Desc
	maxSingleRemote    *prometheus.Desc
	uniqueDstPorts     *prometheus.Desc
	newDstPorts        *prometheus.Desc
	maxSingleDstPort   *prometheus.Desc
	bytesPerFlow       *prometheus.Desc
	packetsPerFlow     *prometheus.Desc
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
// Host CPU State
// -----------------------------------------------------------------------------

type HostCpuState struct {
	prevTotal   float64
	prevIdle    float64
	initialized bool
	mu          sync.Mutex
}

// -----------------------------------------------------------------------------
// Managers
// -----------------------------------------------------------------------------

const shardCount = 32

type domainXMLInflight struct {
	wg   sync.WaitGroup
	meta *DomainStatic
	err  error
}

type InstanceManager struct {
	libvirtURI        string
	workerCount       int
	xmlInflightMu     sync.Mutex
	xmlInflight       map[string]*domainXMLInflight
	xmlRPCSem         chan struct{}
	domainMetaMu      sync.RWMutex
	domainMeta        map[string]*DomainStatic
	activeInstancesMu sync.RWMutex
	activeInstances   map[string]struct{}

	vmIPIndexMu        sync.RWMutex
	vmIPSet            map[IPKey]struct{}
	SetAtomic          atomic.Value
	vmIPToInstance     map[IPKey]string
	vmIPKeysByInstance map[string][]IPKey

	// Sharded locks for high concurrency
	cpuMu       [shardCount]sync.Mutex
	cpuSamples  [shardCount]map[string]cpuSample
	diskMu      [shardCount]sync.Mutex
	diskSamples [shardCount]map[string]diskSample
	memMu       [shardCount]sync.Mutex
	memSamples  [shardCount]map[string]memSample

	netMu      [shardCount]sync.Mutex
	netSamples [shardCount]map[string]netSample

	instanceInfoDesc  *prometheus.Desc
	instanceStateDesc *prometheus.Desc

	instanceDiskReadGbytesTotalDesc     *prometheus.Desc
	instanceDiskWriteGbytesTotalDesc    *prometheus.Desc
	instanceDiskReadRequestsTotalDesc   *prometheus.Desc
	instanceDiskWriteRequestsTotalDesc  *prometheus.Desc
	instanceDiskReadSecondsTotalDesc    *prometheus.Desc
	instanceDiskWriteSecondsTotalDesc   *prometheus.Desc
	instanceDiskFlushRequestsTotalDesc  *prometheus.Desc
	instanceDiskFlushSecondsTotalDesc   *prometheus.Desc
	instanceDiskCapacityBytesDesc       *prometheus.Desc
	instanceDiskAllocationBytesDesc     *prometheus.Desc
	instanceDiskInfoDesc                *prometheus.Desc
	instanceDiskReadIopsDesc            *prometheus.Desc
	instanceDiskWriteIopsDesc           *prometheus.Desc
	instanceDiskFlushIopsDesc           *prometheus.Desc
	instanceDiskReadLatencySecondsDesc  *prometheus.Desc
	instanceDiskWriteLatencySecondsDesc *prometheus.Desc
	instanceDiskFlushLatencySecondsDesc *prometheus.Desc

	instanceCpuVcpuPercentDesc       *prometheus.Desc
	instanceCpuVcpuCountDesc         *prometheus.Desc
	instanceCpuStealSecondsTotalDesc *prometheus.Desc
	instanceCpuWaitSecondsTotalDesc  *prometheus.Desc

	instanceMemAllocatedMBDesc      *prometheus.Desc
	instanceMemUsedMBDesc           *prometheus.Desc
	instanceMemSwapInBytesDesc      *prometheus.Desc
	instanceMemSwapOutBytesDesc     *prometheus.Desc
	instanceMemMajorFaultsTotalDesc *prometheus.Desc
	instanceMemMinorFaultsTotalDesc *prometheus.Desc
	instanceMemRSSMBDesc            *prometheus.Desc
	instanceHugetlbPgAllocDesc      *prometheus.Desc
	instanceHugetlbPgFailDesc       *prometheus.Desc

	instanceNetRxGbytesTotalDesc  *prometheus.Desc
	instanceNetTxGbytesTotalDesc  *prometheus.Desc
	instanceNetRxPacketsTotalDesc *prometheus.Desc
	instanceNetTxPacketsTotalDesc *prometheus.Desc
	instanceNetRxErrorsTotalDesc  *prometheus.Desc
	instanceNetTxErrorsTotalDesc  *prometheus.Desc
	instanceNetRxDroppedTotalDesc *prometheus.Desc
	instanceNetTxDroppedTotalDesc *prometheus.Desc
}

type IPThreatProvider struct {
	Name            string
	Enabled         bool
	URL             string
	RefreshInterval time.Duration
	Direction       ContactDirection
	LogTag          string
	Fetcher         func() (map[IPKey]struct{}, error)
	Logger          ComponentLogger
	Mu              sync.RWMutex
	Set             map[IPKey]struct{}
	SetAtomic       atomic.Value
	LastSuccess     float64
	LastDuration    float64
	EntryCount      int
	ErrorCount      uint64

	PrevHits   map[string]map[string]struct{}
	PrevHitsMu sync.Mutex

	InstanceContactsTotalDesc     *prometheus.Desc
	InstanceActiveFlowsDesc       *prometheus.Desc
	HostRefreshLastSuccessDesc    *prometheus.Desc
	HostRefreshDurationDesc       *prometheus.Desc
	HostRefreshErrorsDesc         *prometheus.Desc
	HostEntriesDesc               *prometheus.Desc
	InstanceContactsMetricName    string
	InstanceActiveMetricName      string
	HostRefreshLastMetricName     string
	HostRefreshDurationMetricName string
	HostRefreshErrorsMetricName   string
	HostEntriesMetricName         string

	CountMu  sync.Mutex
	CountMap map[string]float64
}

type ThreatManager struct {
	httpClient   *http.Client
	shutdownChan chan struct{}

	Providers []*IPThreatProvider

	spamEnabled            bool
	spamURL                string
	spamV6URL              string
	spamRefresh            time.Duration
	spamNetsV4             []*net.IPNet
	spamNetsV6             []*net.IPNet
	spamWideV4             []*net.IPNet
	spamWideV6             []*net.IPNet
	spamBucketsV4          map[uint16][]*net.IPNet
	spamBucketsV6          map[uint32][]*net.IPNet
	spamMu                 sync.RWMutex
	spamDir                ContactDirection
	spamLastSuccessUnix    float64
	spamLastRefreshSeconds float64
	spamEntries            int
	spamRefreshErrors      uint64
	spamCount              map[string]float64
	spamCountMu            sync.Mutex

	spamPrevHits   map[string]map[string]struct{}
	spamPrevHitsMu sync.Mutex

	instanceSpamhausContactsTotalDesc           *prometheus.Desc
	instanceSpamhausActiveFlowsDesc             *prometheus.Desc
	hostSpamhausRefreshLastSuccessTimestampDesc *prometheus.Desc
	hostSpamhausRefreshDurationSecondsDesc      *prometheus.Desc
	hostSpamhausRefreshErrorsTotalDesc          *prometheus.Desc
	hostSpamhausEntriesDesc                     *prometheus.Desc

	threatLogMinInterval time.Duration
	threatLastHitMu      sync.Mutex
	threatLastHit        map[string]time.Time

	hostThreatsEnabled   bool
	hostThreatHitsMu     sync.RWMutex
	hostThreatHits       map[string]map[string]string
	hostIPsAllowPrivate  bool
	hostInterfaces       map[string]struct{}
	hostThreatListedDesc *prometheus.Desc
}

type ConntrackManager struct {
	outboundBehaviorEnabled bool
	inboundBehaviorEnabled  bool
	behaviorThresholds      BehaviorThresholds
	conntrackAcctEnabled    bool
	behaviorSensitivity     float64

	behaviorEWMATauFast time.Duration
	behaviorEWMATauSlow time.Duration

	behaviorInboundPortNames  map[uint16]string
	behaviorOutboundPortNames map[uint16]string
	externalBehaviorRules     []BehaviorRule

	conntrackRawRcvBufBytes int
	conntrackIPv4Enable     bool
	conntrackIPv6Enable     bool

	ovnMapper *OVNMapper

	outboundMu           [shardCount]sync.Mutex
	outboundPrev         [shardCount]map[BehaviorKey]outboundPrev
	outboundPrevDstPorts [shardCount]map[BehaviorKey]outboundPrevDstPorts
	outboundPrevLastSeen [shardCount]map[BehaviorKey]int64

	inboundMu           [shardCount]sync.Mutex
	inboundPrev         [shardCount]map[BehaviorKey]outboundPrev
	inboundPrevDstPorts [shardCount]map[BehaviorKey]outboundPrevDstPorts
	inboundPrevLastSeen [shardCount]map[BehaviorKey]int64

	behaviorEWMAMu [shardCount]sync.Mutex
	behaviorEWMA   [shardCount]map[behaviorIdentityKey]*behaviorEWMAState

	behaviorAlertMu sync.Mutex
	behaviorPersist map[behaviorAlertKey]*behaviorPersistState
	behaviorEmit    map[behaviorEmitKey]*behaviorEmitState

	conntrackReadErrors uint64

	conntrackRawOK               uint64
	conntrackRawENOBUFSTotal     uint64
	conntrackRawParseErrorsTotal uint64
	conntrackLastSuccessUnix     int64

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
	instanceOutboundBytesPerFlowDesc          *prometheus.Desc
	instanceOutboundPacketsPerFlowDesc        *prometheus.Desc

	instanceInboundUniqueRemotesDesc         *prometheus.Desc
	instanceInboundNewRemotesDesc            *prometheus.Desc
	instanceInboundFlowsDesc                 *prometheus.Desc
	instanceInboundMaxFlowsSingleRemoteDesc  *prometheus.Desc
	instanceInboundUniqueDstPortsDesc        *prometheus.Desc
	instanceInboundNewDstPortsDesc           *prometheus.Desc
	instanceInboundMaxFlowsSingleDstPortDesc *prometheus.Desc
	instanceInboundBytesPerFlowDesc          *prometheus.Desc
	instanceInboundPacketsPerFlowDesc        *prometheus.Desc
}

type MetricsCollector struct {
	shutdownChan       chan struct{}
	scoring            SeverityConfig
	collectionInterval time.Duration
	backgroundOnce     sync.Once
	cacheMu            sync.RWMutex
	cachedMetrics      []prometheus.Metric

	collectionMu sync.Mutex

	// Intel EWMA state
	intelHistory map[string]*IntelHistory
	intelMu      sync.Mutex

	// Pure Go Libvirt
	libvirtConn *libvirt.Libvirt
	libvirtMu   sync.Mutex

	im *InstanceManager
	tm *ThreatManager
	cm *ConntrackManager

	// Host Stats State
	hostCpuState HostCpuState

	hostCollectionErrors uint64
	cycleSeq             uint64
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
	hostConntrackRawOkDesc                 *prometheus.Desc
	hostConntrackRawENOBUFSTotalDesc       *prometheus.Desc
	hostConntrackRawParseErrorsTotalDesc   *prometheus.Desc
	hostConntrackLastSuccessTimestampDesc  *prometheus.Desc
	hostConntrackStaleSecondsDesc          *prometheus.Desc
	hostConntrackMaxDesc                   *prometheus.Desc
	hostConntrackUtilizationDesc           *prometheus.Desc
	hostCacheCleanupDurationSecondsDesc    *prometheus.Desc

	hostCpuUsagePercentDesc *prometheus.Desc
	hostMemFreeMBDesc       *prometheus.Desc
	hostMemAvailableMBDesc  *prometheus.Desc

	instanceResourceSeverityDesc   *prometheus.Desc
	instanceThreatListSeverityDesc *prometheus.Desc
	instanceAttentionSeverityDesc  *prometheus.Desc
	instanceBehaviorSeverityDesc   *prometheus.Desc

	instanceResourceCpuSeverityDesc  *prometheus.Desc
	instanceResourceMemSeverityDesc  *prometheus.Desc
	instanceResourceDiskSeverityDesc *prometheus.Desc
	instanceResourceNetSeverityDesc  *prometheus.Desc

	resourceV2Mu sync.Mutex
	resourceV2   map[string]*resourceV2State
}
