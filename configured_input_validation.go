package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type startupConfiguredInputs struct {
	explicitlySet       map[string]struct{}
	hostThreatsEnabled  bool
	hostInterfacesCSV   string
	interfaceByName     func(string) (*net.Interface, error)
	logFileEnabled      bool
	logFilePath         string
	libvirtURI          string
	directions          map[string]string
	behaviorConfigPaths map[string]string
}

func explicitlyConfiguredFlags(flagSet *flag.FlagSet) map[string]struct{} {
	configured := make(map[string]struct{})
	if flagSet == nil {
		return configured
	}
	flagSet.Visit(func(value *flag.Flag) {
		configured[value.Name] = struct{}{}
	})
	return configured
}

func startupFlagWasExplicitlySet(configured map[string]struct{}, name string) bool {
	_, ok := configured[name]
	return ok
}

func validateExplicitThreatInputs(cfg CollectorConfig, configured map[string]struct{}) error {
	validateProvider := func(enabled bool, prefix, urlFlag, rawURL string, refresh time.Duration) error {
		if enabled || startupFlagWasExplicitlySet(configured, prefix+".refresh") {
			if refresh < 0 {
				return fmt.Errorf("%s.refresh must be zero or greater", prefix)
			}
		}
		if enabled || startupFlagWasExplicitlySet(configured, urlFlag) {
			if err := validateThreatFeedURL(urlFlag, rawURL); err != nil {
				return err
			}
		}
		return nil
	}

	if err := validateProvider(cfg.TorExit.Enable, "tor.exit", "tor.exit.url", cfg.TorExit.URL, cfg.TorExit.Refresh); err != nil {
		return err
	}
	if err := validateProvider(cfg.TorRelay.Enable, "tor.relay", "tor.relay.url", cfg.TorRelay.URL, cfg.TorRelay.Refresh); err != nil {
		return err
	}
	if err := validateProvider(cfg.Emerging.Enable, "emergingthreats", "emergingthreats.url", cfg.Emerging.URL, cfg.Emerging.Refresh); err != nil {
		return err
	}

	if cfg.Spamhaus.Enable || startupFlagWasExplicitlySet(configured, "spamhaus.refresh") {
		if cfg.Spamhaus.Refresh < 0 {
			return fmt.Errorf("spamhaus.refresh must be zero or greater")
		}
	}
	spamhausURLs := []struct {
		flagName string
		rawURL   string
	}{
		{flagName: "spamhaus.url", rawURL: cfg.Spamhaus.URLv4},
		{flagName: "spamhaus.ipv6.url", rawURL: cfg.Spamhaus.URLv6},
	}
	configuredSpamhausURLs := 0
	for _, value := range spamhausURLs {
		trimmedURL := strings.TrimSpace(value.rawURL)
		if startupFlagWasExplicitlySet(configured, value.flagName) && value.rawURL != "" && trimmedURL == "" {
			return fmt.Errorf("%s must not contain only whitespace", value.flagName)
		}
		if trimmedURL == "" {
			continue
		}
		configuredSpamhausURLs++
		if cfg.Spamhaus.Enable || startupFlagWasExplicitlySet(configured, value.flagName) {
			if err := validateThreatFeedURL(value.flagName, value.rawURL); err != nil {
				return err
			}
		}
	}
	if cfg.Spamhaus.Enable && configuredSpamhausURLs == 0 {
		return fmt.Errorf("spamhaus requires at least one configured feed URL")
	}

	if cfg.Custom.Enable || startupFlagWasExplicitlySet(configured, "customlist.refresh") {
		if cfg.Custom.Refresh < 0 {
			return fmt.Errorf("customlist.refresh must be zero or greater")
		}
	}
	customPathExplicit := startupFlagWasExplicitlySet(configured, "customlist.path")
	customPath := strings.TrimSpace(cfg.Custom.Path)
	if customPathExplicit && customPath == "" {
		return fmt.Errorf("customlist.path must not be empty when explicitly configured")
	}
	if cfg.Custom.Enable && customPath == "" {
		return fmt.Errorf("customlist.path must not be empty when customlist is enabled")
	}
	if customPath != "" && (cfg.Custom.Enable || customPathExplicit) {
		if strings.IndexByte(cfg.Custom.Path, 0) >= 0 {
			return fmt.Errorf("customlist.path contains a NUL byte")
		}
		set, err := (&ThreatManager{}).fetchFileLines(cfg.Custom.Path)
		if err != nil {
			return fmt.Errorf("customlist.path is not usable: %w", err)
		}
		if err := validateThreatIPSet(set); err != nil {
			return fmt.Errorf("customlist.path is invalid: %w", err)
		}
	}

	return nil
}

func validateThreatFeedURL(name, rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || rawURL != strings.TrimSpace(rawURL) || parsed.Host == "" || parsed.Hostname() == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Opaque != "" ||
		strings.HasSuffix(parsed.Host, ":") {
		return fmt.Errorf("%s must be an HTTP(S) URL without embedded credentials", name)
	}
	if port := parsed.Port(); port != "" {
		value, conversionErr := strconv.Atoi(port)
		if conversionErr != nil || value < 1 || value > 65535 {
			return fmt.Errorf("%s must use a TCP port between 1 and 65535", name)
		}
	}
	return nil
}

func validateConfiguredHostInterfaces(enabled, explicitlyConfigured bool, csv string, interfaceByName func(string) (*net.Interface, error)) error {
	if strings.TrimSpace(csv) == "" {
		if enabled || explicitlyConfigured {
			return fmt.Errorf("host.interfaces must not be empty when enabled or explicitly configured")
		}
		return nil
	}
	if interfaceByName == nil {
		return fmt.Errorf("host.interfaces cannot be validated")
	}

	for _, rawName := range strings.Split(csv, ",") {
		name := strings.TrimSpace(rawName)
		if name == "" {
			return fmt.Errorf("host.interfaces contains an empty interface name")
		}
		if strings.IndexByte(name, 0) >= 0 {
			return fmt.Errorf("host.interfaces contains an invalid interface name")
		}
		iface, err := interfaceByName(name)
		if err != nil {
			return fmt.Errorf("host.interfaces interface %q is unavailable: %w", name, err)
		}
		if iface == nil || iface.Name != name {
			return fmt.Errorf("host.interfaces interface %q is unavailable", name)
		}
	}
	return nil
}

func hostInterfacesForStartup(enabled, explicitlyConfigured bool, csv string) string {
	if enabled && !explicitlyConfigured && strings.TrimSpace(csv) == "" {
		return "bgp-nic"
	}
	return csv
}

func validateConfiguredLogFile(enabled bool, path string) error {
	if !enabled {
		return nil
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("log.file.path must not be empty when log.file.enable is true")
	}
	if strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("log.file.path contains a NUL byte")
	}
	info, err := os.Stat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("log.file.path must name a regular file")
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("log.file.path cannot be inspected: %w", err)
	}
	parentInfo, parentErr := os.Stat(filepath.Dir(path))
	if parentErr != nil {
		return fmt.Errorf("log.file.path parent is not usable: %w", parentErr)
	}
	if !parentInfo.IsDir() {
		return fmt.Errorf("log.file.path parent must be a directory")
	}
	return nil
}

func validateListenAddress(address string) error {
	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("web.listen-address must not be empty")
	}
	return nil
}

func validateLibvirtURI(uri string) error {
	if uri == "" || uri != strings.TrimSpace(uri) {
		return fmt.Errorf("libvirt.uri must not be empty or surrounded by whitespace")
	}
	_, err := libvirtSocketPathFromURI(uri)
	return err
}

func validateExplicitDirections(configured map[string]struct{}, values map[string]string) error {
	orderedNames := []string{
		"contacts.direction",
		"tor.exit.direction",
		"tor.relay.direction",
		"spamhaus.direction",
		"emergingthreats.direction",
		"customlist.direction",
	}
	for _, name := range orderedNames {
		value := values[name]
		trimmed := strings.TrimSpace(value)
		if name == "contacts.direction" {
			if trimmed == "" {
				return fmt.Errorf("contacts.direction must not be empty")
			}
		} else if value == "" {
			// The exact empty default inherits contacts.direction.
			continue
		} else if trimmed == "" {
			return fmt.Errorf("%s must not contain only whitespace", name)
		}
		if _, err := parseContactDirection(value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func validateBehaviorConfigPaths(configured map[string]struct{}, paths map[string]string) error {
	for _, name := range []string{"behavior.ports_config", "behavior.rules_config"} {
		path := paths[name]
		if startupFlagWasExplicitlySet(configured, name) && path == "" {
			return fmt.Errorf("%s must not be empty when explicitly configured", name)
		}
		if path != strings.TrimSpace(path) {
			return fmt.Errorf("%s must not contain surrounding whitespace", name)
		}
		if strings.IndexByte(path, 0) >= 0 {
			return fmt.Errorf("%s contains a NUL byte", name)
		}
	}
	return nil
}

func validateConfiguredInputs(cfg CollectorConfig, inputs startupConfiguredInputs) error {
	if err := validateExplicitThreatInputs(cfg, inputs.explicitlySet); err != nil {
		return err
	}
	if err := validateConfiguredHostInterfaces(
		inputs.hostThreatsEnabled,
		startupFlagWasExplicitlySet(inputs.explicitlySet, "host.interfaces"),
		inputs.hostInterfacesCSV,
		inputs.interfaceByName,
	); err != nil {
		return err
	}
	if err := validateConfiguredLogFile(inputs.logFileEnabled, inputs.logFilePath); err != nil {
		return err
	}
	if err := validateLibvirtURI(inputs.libvirtURI); err != nil {
		return err
	}
	if err := validateExplicitDirections(inputs.explicitlySet, inputs.directions); err != nil {
		return err
	}
	return validateBehaviorConfigPaths(inputs.explicitlySet, inputs.behaviorConfigPaths)
}
