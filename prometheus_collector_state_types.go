package main

import (
	"github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

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
	ConntrackNetlinkRecvTimeout    time.Duration
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

	conntrackNetlinkRecvTimeout time.Duration
	conntrackRawRcvBufBytes     int
	conntrackIPv4Enable         bool
	conntrackIPv6Enable         bool

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
