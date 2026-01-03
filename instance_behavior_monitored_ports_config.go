package main

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"strings"
)

type behaviorPortsConfigFile struct {
	Behavior struct {
		Ports struct {
			InboundMonitored  map[int]string `yaml:"inbound_monitored"`
			OutboundMonitored map[int]string `yaml:"outbound_monitored"`
		} `yaml:"ports"`
	} `yaml:"behavior"`
}

func builtinBehaviorInboundMonitoredPorts() map[uint16]string {
	return map[uint16]string{
		// --- Remote Access & Infrastructure ---
		20:   "ftp_data",
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		69:   "tftp",
		514:  "syslog",
		873:  "rsync",
		3389: "rdp",
		5900: "vnc",
		5601: "kibana",
		5985: "winrm",
		5986: "winrm_tls",

		// --- Active Directory & Windows Enterprise ---
		88:   "kerberos",
		135:  "msrpc",
		137:  "netbios_ns",
		138:  "netbios_dgm",
		139:  "netbios_ssn",
		389:  "ldap",
		445:  "smb",
		464:  "kpasswd",
		636:  "ldaps",
		3268: "ldap_gc",
		3269: "ldap_gc_ssl",

		// --- Cloud Native, Containers & Orchestration ---
		2375:  "docker",
		2376:  "docker_tls",
		2379:  "etcd_client",
		2380:  "etcd_server",
		4646:  "nomad_http",
		5000:  "docker_registry",
		6443:  "k8s_api",
		8200:  "vault",
		8500:  "consul",
		10250: "k8s_kubelet",
		10255: "k8s_kubelet_readonly",
		10256: "k8s_health",

		// --- Databases & Data Stores ---
		1433:  "mssql",
		1521:  "oracle",
		2049:  "nfs",
		2181:  "zookeeper",
		3306:  "mysql",
		4333:  "mnsql",
		5432:  "postgres",
		5672:  "rabbitmq",
		5984:  "couchdb",
		6379:  "redis",
		7000:  "cassandra_intra",
		7001:  "cassandra_tls",
		7474:  "neo4j",
		8086:  "influxdb",
		9042:  "cassandra_client",
		9092:  "kafka",
		9200:  "elasticsearch",
		9300:  "elasticsearch_transport",
		11211: "memcached",
		27017: "mongodb",

		// --- Web, Proxy & Load Balancing ---
		80:   "http",
		443:  "https",
		3128: "squid_proxy",
		8000: "http_alt_8000",
		8008: "http_alt_8008",
		8080: "http_alt",
		8443: "https_alt",
		8888: "http_alt_8888",
		9090: "prometheus",

		// --- Mail Services ---
		25:  "smtp",
		110: "pop3",
		143: "imap",
		465: "smtps",
		587: "submission",
		993: "imaps",
		995: "pop3s",

		// --- VPN, Tunneling & Network Services ---
		53:   "dns",
		179:  "bgp",
		111:  "rpcbind",
		123:  "ntp",
		161:  "snmp",
		500:  "ike",
		1194: "openvpn",
		1701: "l2tp",
		1723: "pptp",
		4500: "ipsec_nat",
		6081: "geneve",
		5353: "mdns",

		// --- High Risk / Reflection / Legacy ---
		19:   "chargen",
		1900: "ssdp",
		6667: "irc",
	}
}
func builtinBehaviorOutboundMonitoredPorts() map[uint16]string {
	return map[uint16]string{
		// --- Standard Outbound Traffic ---
		21:  "ftp",
		22:  "ssh",
		25:  "smtp",
		53:  "dns",
		179: "bgp",
		67:  "dhcp_server",
		68:  "dhcp_client",
		80:  "http",
		123: "ntp",
		443: "https",

		// --- Suspicious Indicators ---
		23:   "telnet",
		69:   "tftp",
		1080: "socks_proxy",
		3128: "squid_proxy",
		3389: "rdp",
		3333: "stratum",
		4444: "stratum_alt",
		5900: "vnc",
		6667: "irc",
		8080: "http_alt",
		8888: "http_alt_8888",
		9001: "tor_orport",
		9050: "tor_socks",
		9418: "git",
		6081: "geneve",
		8333: "stratum_alt_8333",

		// --- Lateral Movement Indicators ---
		88:    "kerberos",
		111:   "rpcbind",
		135:   "msrpc",
		137:   "netbios_ns",
		389:   "ldap",
		445:   "smb",
		514:   "syslog_exfil",
		5985:  "winrm",
		6443:  "k8s_api",
		10250: "k8s_kubelet",

		// --- Mail & Messaging ---
		110: "pop3",
		143: "imap",
		465: "smtps",
		587: "submission",
		993: "imaps",
		995: "pop3s",

		// --- Data Stores ---
		1433:  "mssql",
		1521:  "oracle",
		2049:  "nfs",
		3306:  "mysql",
		5432:  "postgres",
		6379:  "redis",
		9200:  "elasticsearch",
		27017: "mongodb",
	}
}
func validateBehaviorPortMap(in map[int]string) (map[uint16]string, error) {
	out := make(map[uint16]string, len(in))
	for port, name := range in {
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port %d", port)
		}
		n := strings.TrimSpace(name)
		if n == "" {
			return nil, fmt.Errorf("empty name for port %d", port)
		}
		out[uint16(port)] = n
	}
	return out, nil
}
func BuildBehaviorPortMaps(path string) (map[uint16]string, map[uint16]string, BehaviorPortsConfigStatus) {
	builtinIn := builtinBehaviorInboundMonitoredPorts()
	builtinOut := builtinBehaviorOutboundMonitoredPorts()

	status := BehaviorPortsConfigStatus{Path: path}

	p := strings.TrimSpace(path)
	if p == "" {
		status.Status = "not_configured"
		status.Using = "builtin"
		status.InboundPorts = len(builtinIn)
		status.OutboundPorts = len(builtinOut)
		return builtinIn, builtinOut, status
	}

	b, err := os.ReadFile(p)
	if err != nil {
		status.Status = "missing"
		status.Using = "builtin"
		status.Err = err.Error()
		status.InboundPorts = len(builtinIn)
		status.OutboundPorts = len(builtinOut)
		return builtinIn, builtinOut, status
	}

	var cfg behaviorPortsConfigFile
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		status.Status = "parse_error"
		status.Using = "builtin"
		status.Err = err.Error()
		status.InboundPorts = len(builtinIn)
		status.OutboundPorts = len(builtinOut)
		return builtinIn, builtinOut, status
	}

	inProvided := len(cfg.Behavior.Ports.InboundMonitored) > 0
	outProvided := len(cfg.Behavior.Ports.OutboundMonitored) > 0

	if !inProvided && !outProvided {
		status.Status = "invalid"
		status.Using = "builtin"
		status.Err = "no inbound_monitored or outbound_monitored ports defined"
		status.InboundPorts = len(builtinIn)
		status.OutboundPorts = len(builtinOut)
		return builtinIn, builtinOut, status
	}

	inMap := builtinIn
	outMap := builtinOut

	if inProvided {
		parsed, err := validateBehaviorPortMap(cfg.Behavior.Ports.InboundMonitored)
		if err != nil {
			status.Status = "invalid"
			status.Using = "builtin"
			status.Err = err.Error()
			status.InboundPorts = len(builtinIn)
			status.OutboundPorts = len(builtinOut)
			return builtinIn, builtinOut, status
		}
		inMap = parsed
	}

	if outProvided {
		parsed, err := validateBehaviorPortMap(cfg.Behavior.Ports.OutboundMonitored)
		if err != nil {
			status.Status = "invalid"
			status.Using = "builtin"
			status.Err = err.Error()
			status.InboundPorts = len(builtinIn)
			status.OutboundPorts = len(builtinOut)
			return builtinIn, builtinOut, status
		}
		outMap = parsed
	}

	status.Status = "loaded"
	if inProvided && outProvided {
		status.Using = "file"
	} else {
		status.Using = "mixed"
	}
	status.InboundPorts = len(inMap)
	status.OutboundPorts = len(outMap)

	return inMap, outMap, status
}
