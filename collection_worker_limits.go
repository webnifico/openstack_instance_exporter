package main

import "runtime"

const maxDomainWorkers = 64

func effectiveDomainWorkerCount(configured int) int {
	workers := configured
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > maxDomainWorkers {
		workers = maxDomainWorkers
	}
	return workers
}
