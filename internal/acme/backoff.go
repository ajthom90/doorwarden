package acme

import "time"

// Backoff schedule per certificate set: 1m, 2m, 4m, ... capped at 6h, plus
// up to 10% jitter (never shortening the base delay, never above the cap).
const (
	backoffBase = time.Minute
	backoffCap  = 6 * time.Hour
	jitterFrac  = 0.10
)

// backoffDelay is the wait after the failures-th consecutive failure
// (failures >= 1). jitter is a value in [0,1).
func backoffDelay(failures int, jitter float64) time.Duration {
	if failures < 1 {
		failures = 1
	}
	d := backoffBase
	for i := 1; i < failures && d < backoffCap; i++ {
		d *= 2
	}
	if d > backoffCap {
		d = backoffCap
	}
	if jitter < 0 {
		jitter = 0
	}
	if jitter >= 1 {
		jitter = 0.999
	}
	d += time.Duration(float64(d) * jitterFrac * jitter)
	if d > backoffCap {
		d = backoffCap
	}
	return d
}
