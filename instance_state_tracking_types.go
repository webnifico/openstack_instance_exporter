package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"sync/atomic"
	"time"
)

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
type outboundPrev struct {
	remotes map[IPKey]struct{}
}
type outboundPrevDstPorts struct {
	ports map[uint16]struct{}
}
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
