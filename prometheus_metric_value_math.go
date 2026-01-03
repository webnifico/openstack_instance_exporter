package main

import (
	"math"
)

const bytesToGigabytes = 1.0 / (1024 * 1024 * 1024)
const bytesToMegabytes = 1.0 / (1024 * 1024)

// roundToFiveDecimals keeps floating-point values stable for metric emission.
func roundToFiveDecimals(value float64) float64 {
	return math.Round(value*100000) / 100000
}
func clamp01(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}
func clampInt01To100(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}
