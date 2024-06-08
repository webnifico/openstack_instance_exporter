package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"libvirt.org/go/libvirt"
)

// Validate and unmarshal JSON
func UnmarshalProto(jsonData []byte, pb proto.Message) error {
	if !json.Valid(jsonData) {
		return fmt.Errorf("invalid JSON")
	}
	return protojson.Unmarshal(jsonData, pb)
}

type DomainXML struct {
	UUID     string `xml:"uuid"`
	Metadata struct {
		NovaInstance struct {
			NovaName    string `xml:"name"`
			NovaFlavor  struct {
				FlavorName string `xml:"name,attr"`
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
}

type CacheEntry struct {
	data        interface{}
	lastUpdated time.Time
}

type Cache struct {
	mu         sync.RWMutex
	data       map[string]CacheEntry
	expiration time.Duration
}

func NewCache(expiration time.Duration) *Cache {
	return &Cache{
		data:       make(map[string]CacheEntry),
		expiration: expiration,
	}
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.data[key]
	if !ok || time.Since(entry.lastUpdated) > c.expiration {
		return nil, false
	}

	return entry.data, true
}

func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = CacheEntry{
		data:        value,
		lastUpdated: time.Now(),
	}
}

type MetricsCollector struct {
	conn               *libvirt.Connect
	readThreshold      map[string]int
	writeThreshold     map[string]int
	defaultReadThreshold int
	defaultWriteThreshold int
	diskReadThresholds *prometheus.Desc
	diskWriteThresholds *prometheus.Desc
	diskReadBytes      *prometheus.Desc
	diskWriteBytes     *prometheus.Desc
	diskReadRequests   *prometheus.Desc
	diskWriteRequests  *prometheus.Desc
	cpuUsage           *prometheus.Desc
	networkRxBytes     *prometheus.Desc
	networkTxBytes     *prometheus.Desc
	networkRxPackets   *prometheus.Desc
	networkTxPackets   *prometheus.Desc
	networkRxErrors    *prometheus.Desc
	networkTxErrors    *prometheus.Desc
	networkRxDropped   *prometheus.Desc
	networkTxDropped   *prometheus.Desc
	staticCache        *Cache
	dynamicCache       *Cache
	collectionInterval time.Duration
	enableLogging      bool
}

func NewMetricsCollector(uri string, readThresholds map[string]int, writeThresholds map[string]int, defaultReadThreshold int, defaultWriteThreshold int, staticCacheExpiration time.Duration, dynamicCacheExpiration time.Duration, collectionInterval time.Duration, enableLogging bool) (*MetricsCollector, error) {
	conn, err := libvirt.NewConnect(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %v", err)
	}

	mc := &MetricsCollector{
		conn:               conn,
		readThreshold:      readThresholds,
		writeThreshold:     writeThresholds,
		defaultReadThreshold: defaultReadThreshold,
		defaultWriteThreshold: defaultWriteThreshold,
		diskReadThresholds: prometheus.NewDesc("oie_disk_r_alert_threshold", "Disk read alert threshold", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "hypervisor", "disk_uuid", "disk_type", "disk_path"}, nil),
		diskWriteThresholds: prometheus.NewDesc("oie_disk_w_alert_threshold", "Disk write alert threshold", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "hypervisor", "disk_uuid", "disk_type", "disk_path"}, nil),
		diskReadBytes:      prometheus.NewDesc("oie_disk_r_gbytes", "Disk read gigabytes", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "hypervisor", "disk_uuid", "disk_type", "disk_path"}, nil),
		diskWriteBytes:     prometheus.NewDesc("oie_disk_w_gbytes", "Disk write gigabytes", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "hypervisor", "disk_uuid", "disk_type", "disk_path"}, nil),
		diskReadRequests:   prometheus.NewDesc("oie_disk_r_requests", "Disk read requests", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "hypervisor", "disk_uuid", "disk_type", "disk_path"}, nil),
		diskWriteRequests:  prometheus.NewDesc("oie_disk_w_requests", "Disk write requests", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "hypervisor", "disk_uuid", "disk_type", "disk_path"}, nil),
		cpuUsage:           prometheus.NewDesc("oie_cpu_percent", "CPU usage percentage", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "hypervisor"}, nil),
		networkRxBytes:     prometheus.NewDesc("oie_net_rx_gbytes", "Network receive gigabytes", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "hypervisor"}, nil),
		networkTxBytes:     prometheus.NewDesc("oie_net_tx_gbytes", "Network transmit gigabytes", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "hypervisor"}, nil),
		networkRxPackets:   prometheus.NewDesc("oie_net_rx_pkt_total", "Network receive packets", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "hypervisor"}, nil),
		networkTxPackets:   prometheus.NewDesc("oie_net_tx_pkt_total", "Network transmit packets", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "hypervisor"}, nil),
		networkRxErrors:    prometheus.NewDesc("oie_net_rx_er_total", "Network receive errors", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "hypervisor"}, nil),
		networkTxErrors:    prometheus.NewDesc("oie_net_tx_er_total", "Network transmit errors", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "hypervisor"}, nil),
		networkRxDropped:   prometheus.NewDesc("oie_net_rx_drp_total", "Network receive dropped packets", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "hypervisor"}, nil),
		networkTxDropped:   prometheus.NewDesc("oie_net_tx_drp_total", "Network transmit dropped packets", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "hypervisor"}, nil),
		staticCache:        NewCache(staticCacheExpiration),
		dynamicCache:       NewCache(dynamicCacheExpiration),
		collectionInterval: collectionInterval,
		enableLogging:      enableLogging,
	}

	go mc.startBackgroundCollection()

	return mc, nil
}

func (mc *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- mc.diskReadThresholds
	ch <- mc.diskWriteThresholds
	ch <- mc.diskReadBytes
	ch <- mc.diskWriteBytes
	ch <- mc.diskReadRequests
	ch <- mc.diskWriteRequests
	ch <- mc.cpuUsage
	ch <- mc.networkRxBytes
	ch <- mc.networkTxBytes
	ch <- mc.networkRxPackets
	ch <- mc.networkTxPackets
	ch <- mc.networkRxErrors
	ch <- mc.networkTxErrors
	ch <- mc.networkRxDropped
	ch <- mc.networkTxDropped
}

func (mc *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	if mc.enableLogging {
		log.Println("Serving metrics from cache")
	}

	// Collect metrics from cache
	metrics := mc.collectCachedMetrics()
	for _, metric := range metrics {
		ch <- metric
	}
}

func (mc *MetricsCollector) startBackgroundCollection() {
	for {
		if mc.enableLogging {
			log.Println("Background collection of metrics")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		domains, err := mc.conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)
		if err != nil {
			log.Printf("failed to list domains: %v\n", err)
			continue
		}

		if mc.enableLogging {
			log.Printf("Found %d active domains\n", len(domains))
		}

		var wg sync.WaitGroup
		for _, domain := range domains {
			wg.Add(1)
			go func(domain libvirt.Domain) {
				defer wg.Done()
				mc.collectDomainMetrics(ctx, domain)
			}(domain)
		}
		wg.Wait()

		time.Sleep(mc.collectionInterval)
	}
}

func roundToTwoDecimals(value float64) float64 {
	return math.Round(value*100) / 100
}

func calculateCPUUsage(domain libvirt.Domain, vcpuCount int) (float64, error) {
	initialCpuTime, err := domain.GetCPUStats(-1, 0, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to get initial CPU stats: %v", err)
	}
	initialTime := time.Now()

	time.Sleep(1 * time.Second)

	finalCpuTime, err := domain.GetCPUStats(-1, 0, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to get final CPU stats: %v", err)
	}
	finalTime := time.Now()

	elapsedCpuTime := finalCpuTime[0].CpuTime - initialCpuTime[0].CpuTime
	elapsedTime := finalTime.Sub(initialTime).Nanoseconds()

	if elapsedTime == 0 || vcpuCount == 0 {
		return 0, fmt.Errorf("invalid elapsed time or vcpu count")
	}

	cpuUsage := (float64(elapsedCpuTime) / float64(elapsedTime)) * 100 / float64(vcpuCount)

	if cpuUsage > 100 {
		cpuUsage = 100
	}

	return cpuUsage, nil
}

func parseDiskType(sourceName string) (string, string) {
	parts := strings.Split(sourceName, "/")
	if len(parts) > 1 {
		return parts[0], parts[1]
	}
	return "unknown", "unknown"
}

func (mc *MetricsCollector) collectDomainMetrics(ctx context.Context, domain libvirt.Domain) {
	name, err := domain.GetName()
	if err != nil {
		log.Printf("failed to get domain name: %v\n", err)
		return
	}

	hypervisor, err := mc.conn.GetHostname()
	if err != nil {
		log.Printf("failed to get hypervisor hostname: %v\n", err)
		return
	}

	instanceUUID, err := domain.GetUUIDString()
	if err != nil {
		log.Printf("failed to get domain UUID: %v\n", err)
		return
	}

	xmlDesc, err := domain.GetXMLDesc(0)
	if err != nil {
		log.Printf("failed to get domain XML description: %v\n", err)
		return
	}

	var domainXML DomainXML
	if err := xml.Unmarshal([]byte(xmlDesc), &domainXML); err != nil {
		log.Printf("failed to parse domain XML: %v\n", err)
		return
	}

	userUUID := domainXML.Metadata.NovaInstance.NovaOwner.NovaUser.UserUUID
	projectUUID := domainXML.Metadata.NovaInstance.NovaOwner.NovaProject.ProjectUUID
	vcpuCount := domainXML.Metadata.NovaInstance.NovaFlavor.VCPUs

	const bytesToGigabytes = 1.0 / (1024 * 1024 * 1024)

	// Cache key for this domain
	dynamicCacheKey := fmt.Sprintf("dynamic-%s-%s", hypervisor, instanceUUID)

	// Fetch dynamic values freshly or from cache
	var dynamicMetrics []prometheus.Metric
	if cachedData, found := mc.dynamicCache.Get(dynamicCacheKey); found {
		if mc.enableLogging {
			log.Printf("Using cached dynamic data for domain %s", instanceUUID)
		}
		dynamicMetrics = cachedData.([]prometheus.Metric)
	} else {
		if mc.enableLogging {
			log.Printf("Fetching new dynamic data for domain %s", instanceUUID)
		}
		var diskMetricsWg sync.WaitGroup
		encountered := make(map[string]bool)
		for _, disk := range domainXML.Devices.Disks {
			if disk.Device == "disk" {
				diskMetricsWg.Add(1)
				go func(disk Disk) {
					defer diskMetricsWg.Done()
					dev := disk.Target.Dev
					stats, err := domain.BlockStats(dev)
					if err != nil {
						log.Printf("failed to get block stats: %v\n", err)
						return
					}

					var diskType, volumeUUID string
					if disk.Type == "file" {
						diskType = "local"
						volumeUUID = disk.Source.File
					} else {
						diskType, volumeUUID = parseDiskType(disk.Source.Name)
					}
					diskPath := disk.Target.Dev

					key := fmt.Sprintf("%s-%s", diskType, diskPath)
					if encountered[key] {
						return
					}
					encountered[key] = true

					dynamicMetrics = append(dynamicMetrics,
						prometheus.MustNewConstMetric(
							mc.diskReadBytes,
							prometheus.CounterValue,
							roundToTwoDecimals(float64(stats.RdBytes)*bytesToGigabytes),
							name, instanceUUID, userUUID, projectUUID, hypervisor, volumeUUID, diskType, diskPath,
						),
						prometheus.MustNewConstMetric(
							mc.diskWriteBytes,
							prometheus.CounterValue,
							roundToTwoDecimals(float64(stats.WrBytes)*bytesToGigabytes),
							name, instanceUUID, userUUID, projectUUID, hypervisor, volumeUUID, diskType, diskPath,
						),
						prometheus.MustNewConstMetric(
							mc.diskReadRequests,
							prometheus.CounterValue,
							float64(stats.RdReq),
							name, instanceUUID, userUUID, projectUUID, hypervisor, volumeUUID, diskType, diskPath,
						),
						prometheus.MustNewConstMetric(
							mc.diskWriteRequests,
							prometheus.CounterValue,
							float64(stats.WrReq),
							name, instanceUUID, userUUID, projectUUID, hypervisor, volumeUUID, diskType, diskPath,
						),
					)

					// Match the disk type and set the correct thresholds
					readThreshold, writeThreshold := mc.defaultReadThreshold, mc.defaultWriteThreshold
					if threshold, ok := mc.readThreshold[diskType]; ok {
						readThreshold = threshold
					}
					if threshold, ok := mc.writeThreshold[diskType]; ok {
						writeThreshold = threshold
					}

					dynamicMetrics = append(dynamicMetrics,
						prometheus.MustNewConstMetric(
							mc.diskReadThresholds,
							prometheus.GaugeValue,
							float64(readThreshold),
							name, instanceUUID, userUUID, projectUUID, hypervisor, volumeUUID, diskType, diskPath,
						),
						prometheus.MustNewConstMetric(
							mc.diskWriteThresholds,
							prometheus.GaugeValue,
							float64(writeThreshold),
							name, instanceUUID, userUUID, projectUUID, hypervisor, volumeUUID, diskType, diskPath,
						),
					)

					if mc.enableLogging {
						log.Printf("Domain: %s, Disk: %s, DiskType: %s, ReadBytes: %d, WriteBytes: %d, ReadRequests: %d, WriteRequests: %d, ReadThreshold: %d, WriteThreshold: %d",
							name, diskPath, diskType, stats.RdBytes, stats.WrBytes, stats.RdReq, stats.WrReq, readThreshold, writeThreshold)
					}
				}(disk)
			}
		}
		diskMetricsWg.Wait()

		cpuUsage, err := calculateCPUUsage(domain, vcpuCount)
		if err != nil {
			log.Printf("failed to calculate CPU usage: %v\n", err)
			return
		}

		dynamicMetrics = append(dynamicMetrics,
			prometheus.MustNewConstMetric(
				mc.cpuUsage,
				prometheus.GaugeValue,
				roundToTwoDecimals(cpuUsage),
				name, instanceUUID, userUUID, projectUUID, hypervisor,
			),
		)

		if mc.enableLogging {
			log.Printf("Domain: %s, CPUUsage: %.2f%%", name, cpuUsage)
		}

		var netMetricsWg sync.WaitGroup
		for _, iface := range domainXML.Devices.Interfaces {
			netMetricsWg.Add(1)
			go func(iface Interface) {
				defer netMetricsWg.Done()
				interfaceName := iface.Target.Dev
				stats, err := domain.InterfaceStats(interfaceName)
				if err != nil {
					log.Printf("failed to get interface stats for %s: %v\n", interfaceName, err)
					return
				}

				netRxBytes := uint64(stats.RxBytes)
				netTxBytes := uint64(stats.TxBytes)
				netRxPackets := uint64(stats.RxPackets)
				netTxPackets := uint64(stats.TxPackets)
				netRxErrs := uint64(stats.RxErrs)
				netTxErrs := uint64(stats.TxErrs)
				netRxDrop := uint64(stats.RxDrop)
				netTxDrop := uint64(stats.TxDrop)

				if mc.enableLogging {
					log.Printf("Domain: %s, Interface: %s, RxBytes: %d, TxBytes: %d, RxPackets: %d, TxPackets: %d, RxErrors: %d, TxErrors: %d, RxDropped: %d, TxDropped: %d",
						name, interfaceName, netRxBytes, netTxBytes, netRxPackets, netTxPackets, netRxErrs, netTxErrs, netRxDrop, netTxDrop)
				}

				dynamicMetrics = append(dynamicMetrics,
					prometheus.MustNewConstMetric(
						mc.networkRxBytes,
						prometheus.CounterValue,
						roundToTwoDecimals(float64(netRxBytes)*bytesToGigabytes),
						name, interfaceName, instanceUUID, userUUID, projectUUID, hypervisor,
					),
					prometheus.MustNewConstMetric(
						mc.networkTxBytes,
						prometheus.CounterValue,
						roundToTwoDecimals(float64(netTxBytes)*bytesToGigabytes),
						name, interfaceName, instanceUUID, userUUID, projectUUID, hypervisor,
					),
					prometheus.MustNewConstMetric(
						mc.networkRxPackets,
						prometheus.CounterValue,
						float64(netRxPackets),
						name, interfaceName, instanceUUID, userUUID, projectUUID, hypervisor,
					),
					prometheus.MustNewConstMetric(
						mc.networkTxPackets,
						prometheus.CounterValue,
						float64(netTxPackets),
						name, interfaceName, instanceUUID, userUUID, projectUUID, hypervisor,
					),
					prometheus.MustNewConstMetric(
						mc.networkRxErrors,
						prometheus.CounterValue,
						float64(netRxErrs),
						name, interfaceName, instanceUUID, userUUID, projectUUID, hypervisor,
					),
					prometheus.MustNewConstMetric(
						mc.networkTxErrors,
						prometheus.CounterValue,
						float64(netTxErrs),
						name, interfaceName, instanceUUID, userUUID, projectUUID, hypervisor,
					),
					prometheus.MustNewConstMetric(
						mc.networkRxDropped,
						prometheus.CounterValue,
						float64(netRxDrop),
						name, interfaceName, instanceUUID, userUUID, projectUUID, hypervisor,
					),
					prometheus.MustNewConstMetric(
						mc.networkTxDropped,
						prometheus.CounterValue,
						float64(netTxDrop),
						name, interfaceName, instanceUUID, userUUID, projectUUID, hypervisor,
					),
				)
			}(iface)
		}
		netMetricsWg.Wait()

		mc.dynamicCache.Set(dynamicCacheKey, dynamicMetrics)
	}

	// Send dynamic metrics to cache
	mc.dynamicCache.Set(dynamicCacheKey, dynamicMetrics)
}

func (mc *MetricsCollector) collectCachedMetrics() []prometheus.Metric {
	var cachedMetrics []prometheus.Metric
	mc.staticCache.mu.RLock()
	for _, entry := range mc.staticCache.data {
		cachedMetrics = append(cachedMetrics, entry.data.([]prometheus.Metric)...)
	}
	mc.staticCache.mu.RUnlock()

	mc.dynamicCache.mu.RLock()
	for _, entry := range mc.dynamicCache.data {
		cachedMetrics = append(cachedMetrics, entry.data.([]prometheus.Metric)...)
	}
	mc.dynamicCache.mu.RUnlock()

	return cachedMetrics
}

func parseThresholds(thresholds string, defaultThreshold int) map[string]int {
	result := make(map[string]int)
	if thresholds == "" {
		// Set default thresholds if none are provided
		result["default"] = defaultThreshold
		return result
	}
	pairs := strings.Split(thresholds, ",")
	for _, pair := range pairs {
		kv := strings.Split(pair, ":")
		if len(kv) == 2 {
			value, err := strconv.Atoi(kv[1])
			if err == nil {
				result[kv[0]] = value
			}
		}
	}
	return result
}

func main() {
	var listenAddress string
	var metricsPath string
	var libvirtURI string
	var readThresholds string
	var writeThresholds string
	var staticCacheExpiration time.Duration
	var dynamicCacheExpiration time.Duration
	var collectionInterval time.Duration
	var enableLogging bool
	var defaultReadThreshold int
	var defaultWriteThreshold int

	flag.StringVar(&listenAddress, "web.listen-address", "0.0.0.0:9120", "Address to listen on for web interface and telemetry.")
	flag.StringVar(&metricsPath, "web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	flag.StringVar(&libvirtURI, "libvirt.uri", "qemu:///system", "Libvirt URI from which to extract metrics.")
	flag.StringVar(&readThresholds, "read.thresholds", "", "Comma-separated list of read thresholds. eg -read.thresholds='default:500'")
	flag.StringVar(&writeThresholds, "write.thresholds", "", "Comma-separated list of write thresholds. eg -write.thresholds='default:500'")
	flag.DurationVar(&staticCacheExpiration, "static.cache.expiration", 1*time.Hour, "Expiration duration for the cache of static values")
	flag.DurationVar(&dynamicCacheExpiration, "dynamic.cache.expiration", 10*time.Second, "Expiration duration for the cache of dynamic values")
	flag.DurationVar(&collectionInterval, "collection.interval", 10*time.Second, "Interval at which to collect metrics in the background")
	flag.BoolVar(&enableLogging, "enable_logging", false, "Enable detailed logging of metrics data")
	flag.IntVar(&defaultReadThreshold, "default.read.threshold", 100, "Default read threshold if none provided")
	flag.IntVar(&defaultWriteThreshold, "default.write.threshold", 100, "Default write threshold if none provided")
	flag.Parse()

	readThresholdMap := parseThresholds(readThresholds, defaultReadThreshold)
	writeThresholdMap := parseThresholds(writeThresholds, defaultWriteThreshold)

	collector, err := NewMetricsCollector(libvirtURI, readThresholdMap, writeThresholdMap, defaultReadThreshold, defaultWriteThreshold, staticCacheExpiration, dynamicCacheExpiration, collectionInterval, enableLogging)
	if err != nil {
		fmt.Printf("Error creating collector: %v\n", err)
		return
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)

	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	http.Handle(metricsPath, handler)
	fmt.Printf("Beginning to serve on %s\n", listenAddress)
	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		fmt.Printf("Error starting HTTP server: %v\n", err)
	}
}
