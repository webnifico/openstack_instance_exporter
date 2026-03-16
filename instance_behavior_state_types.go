package main

const (
	maxRemoteMapSize = 5000
	maxPortMapSize   = 2048
	remoteHistoryCap = 2048
	portHistoryCap   = 2048

	behaviorIdentityTTLSeconds int64 = 2 * 60 * 60

	behaviorPrevKeyTTLSeconds int64 = 24 * 60 * 60

	behaviorAlertCooldownSeconds  int64 = 180  //3m
	behaviorAlertHeartbeatSeconds int64 = 7200 //2h

	behaviorEWMATauFastDefaultSeconds float64 = 180
	behaviorEWMATauSlowDefaultSeconds float64 = 600

	lowThroughputBytesPerFlow     = 1000
	heavyThroughputBytesPerFlow   = 100000
	lowThroughputPacketsPerFlow   = 10
	heavyThroughputPacketsPerFlow = 100
)

type behaviorAnomalies struct {
	Flows          float64
	Remotes        float64
	Ports          float64
	Unreplied      float64
	BytesPerFlow   float64
	PacketsPerFlow float64
	Signal         float64
}

type axisEWMA struct {
	Fast        float64
	Slow        float64
	Initialized bool
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
type BehaviorKey struct {
	InstanceUUID string
	IP           IPKey
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

type BehaviorEvidence struct {
	TopRemoteShare float64
	TopPortShare   float64
	EvidenceMode   string
}

type RuleThresholds struct {
	MetadataHammerHits       int
	MetadataProbeHits        int
	MetadataProbeUnreplied   float64
	InfraLateralUnreplied    float64
	InfraLateralShareOfTotal float64

	DarkUnreplied          float64
	DarkFlowsWithUnreplied int
	DarkFlowsTotal         int

	SMTPFlows              int
	SMTPRemotes            int
	SMTPUnreplied          float64
	SMTPPortDominanceShare float64

	StratumFlows      int
	StratumMaxRemotes int

	DNSMinUDP          int
	DNSMinBytesPerFlow float64
	DNSUnreplied       float64

	UDPFanoutUDP       int
	UDPFanoutUnreplied float64
	UDPFanoutRemotes   int
}

type RuleCtx struct {
	Thresholds    RuleThresholds
	DstPortCounts map[uint16]int
}
type BehaviorRule struct {
	ID     string
	Dir    string
	When   func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool
	Kind   func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string
	Reason func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string
	Source string
}

type externalBehaviorRulesFile struct {
	PortSets map[string][]int          `yaml:"port_sets"`
	Rules    []externalBehaviorRuleYML `yaml:"rules"`
}
type externalBehaviorRuleYML struct {
	ID        string `yaml:"id"`
	Direction string `yaml:"direction"`
	PortSet   string `yaml:"port_set"`
	Ports     []int  `yaml:"ports"`

	FlowsMin         int `yaml:"flows_min"`
	UniqueRemotesMin int `yaml:"unique_remotes_min"`

	Ratios struct {
		Unreplied float64 `yaml:"unreplied"`
	} `yaml:"ratios"`

	EvidenceMode      string  `yaml:"evidence_mode"`
	TopRemoteShareMin float64 `yaml:"top_remote_share_min"`
	TopPortShareMin   float64 `yaml:"top_port_share_min"`

	Kind   string `yaml:"kind"`
	Reason string `yaml:"reason"`
}
type BehaviorRulesConfigStatus struct {
	Status   string
	Path     string
	Rules    int
	PortSets int
	Err      string
}

type behaviorRuleLogState struct {
	LastSuppressedUnix int64
	LastSummaryUnix    int64
}

type behaviorAlertEvidence struct {
	TopRemoteIP    string
	TopDstPort     uint16
	TopDstPortName string
	TopRemoteShare float64
	TopPortShare   float64
	EvidenceMode   string
}

type behaviorScaler struct {
	sens float64
}
