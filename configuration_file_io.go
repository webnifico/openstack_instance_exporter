package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

const maximumBehaviorConfigFileBytes = int64(1 << 20)

// readStableRegularConfigFile prevents a configured FIFO, device, oversized
// file, or concurrently replaced file from becoming an unbounded startup read.
func readStableRegularConfigFile(path, field string, maximumBytes int64) ([]byte, error) {
	if path == "" || path != strings.TrimSpace(path) || strings.IndexByte(path, 0) >= 0 {
		return nil, fmt.Errorf("%s must be a non-empty path without surrounding whitespace", field)
	}
	if maximumBytes <= 0 {
		return nil, fmt.Errorf("%s size limit is invalid", field)
	}

	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be opened: %w", field, err)
	}
	defer file.Close()

	initial, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s cannot be inspected: %w", field, err)
	}
	if !initial.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must name a regular file", field)
	}
	if initial.Size() > maximumBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", field, maximumBytes)
	}

	body, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read: %w", field, err)
	}
	if int64(len(body)) > maximumBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", field, maximumBytes)
	}
	if int64(len(body)) != initial.Size() {
		return nil, fmt.Errorf("%s changed while being read", field)
	}

	final, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s cannot be reinspected: %w", field, err)
	}
	if !os.SameFile(initial, final) || final.Size() != initial.Size() || !final.ModTime().Equal(initial.ModTime()) {
		return nil, fmt.Errorf("%s changed while being read", field)
	}
	return body, nil
}

func rejectExplicitYAMLNulls(body []byte, field string) error {
	var document yaml.Node
	if err := yaml.Unmarshal(body, &document); err != nil {
		return nil // The typed strict decoder returns the authoritative parse error.
	}
	var walk func(*yaml.Node) error
	walk = func(node *yaml.Node) error {
		if node == nil {
			return nil
		}
		if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
			return fmt.Errorf("%s contains an explicit null value at line %d", field, node.Line)
		}
		for _, child := range node.Content {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(&document)
}
