package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type IntelHistory struct {
	EWMA        float64
	Initialized bool
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
