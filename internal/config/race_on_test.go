//go:build race

package config

// raceEnabled skips wall-clock bounds: the race detector slows the
// (linear) YAML parse about 15x.
const raceEnabled = true
