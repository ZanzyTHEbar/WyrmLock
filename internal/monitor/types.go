package monitor

// ProcessInfo represents information about a monitored process
type ProcessInfo struct {
	PID     int
	Command string
	Allowed bool
}
