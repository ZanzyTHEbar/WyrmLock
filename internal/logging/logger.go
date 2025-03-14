package logging

import (
	"io"
	"log"
	"os"
	"sync"
)

// Logger provides application-wide logging functionality
type Logger struct {
	logger  *log.Logger
	verbose bool
	mu      sync.Mutex
}

// Global logger instance
var (
	DefaultLogger *Logger
	once          sync.Once
)

// InitLogger initializes the global logger
func InitLogger(prefix string, verbose bool) {
	once.Do(func() {
		DefaultLogger = NewLogger(prefix, verbose)
	})
}

// NewLogger creates a new logger instance
func NewLogger(prefix string, verbose bool) *Logger {
	logger := log.New(os.Stdout, prefix+" ", log.LstdFlags)

	return &Logger{
		logger:  logger,
		verbose: verbose,
	}
}

// SetVerbose changes the verbosity level of the logger
func (l *Logger) SetVerbose(verbose bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.verbose = verbose
}

// SetOutput sets the output destination for the logger
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logger.SetOutput(w)
}

// Debug logs debug messages (only in verbose mode)
func (l *Logger) Debug(v ...interface{}) {
	if l.verbose {
		l.mu.Lock()
		defer l.mu.Unlock()

		l.logger.SetPrefix("[DEBUG] ")
		l.logger.Print(v...)
	}
}

// Debugf logs formatted debug messages (only in verbose mode)
func (l *Logger) Debugf(format string, v ...interface{}) {
	if l.verbose {
		l.mu.Lock()
		defer l.mu.Unlock()

		l.logger.SetPrefix("[DEBUG] ")
		l.logger.Printf(format, v...)
	}
}

// Info logs informational messages
func (l *Logger) Info(v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logger.SetPrefix("[INFO] ")
	l.logger.Print(v...)
}

// Infof logs formatted informational messages
func (l *Logger) Infof(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logger.SetPrefix("[INFO] ")
	l.logger.Printf(format, v...)
}

// Warn logs warning messages
func (l *Logger) Warn(v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logger.SetPrefix("[WARN] ")
	l.logger.Print(v...)
}

// Warnf logs formatted warning messages
func (l *Logger) Warnf(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logger.SetPrefix("[WARN] ")
	l.logger.Printf(format, v...)
}

// Error logs error messages
func (l *Logger) Error(v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logger.SetPrefix("[ERROR] ")
	l.logger.Print(v...)
}

// Errorf logs formatted error messages
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logger.SetPrefix("[ERROR] ")
	l.logger.Printf(format, v...)
}

// Fatal logs fatal messages and exits the application
func (l *Logger) Fatal(v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logger.SetPrefix("[FATAL] ")
	l.logger.Fatal(v...)
}

// Fatalf logs formatted fatal messages and exits the application
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logger.SetPrefix("[FATAL] ")
	l.logger.Fatalf(format, v...)
}
