// Package monitor provides process monitoring and control functionality
package monitor

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"applock-go/internal/logging"
)

var (
	// ErrInvalidProcess indicates the process could not be verified
	ErrInvalidProcess = errors.New("process verification failed")
	// ErrPathMismatch indicates the process path does not match expected path
	ErrPathMismatch = errors.New("process path mismatch")
	// ErrHashMismatch indicates the process executable hash does not match expected hash
	ErrHashMismatch = errors.New("process executable hash mismatch")
	// ErrPermissionDenied indicates permission was denied when verifying the process
	ErrPermissionDenied = errors.New("permission denied when verifying process")
	// ErrExecutableNotFound indicates the process executable could not be found
	ErrExecutableNotFound = errors.New("process executable not found")
)

// HashAlgorithm specifies the hash algorithm to use for executable verification
type HashAlgorithm string

const (
	// SHA256 is the SHA-256 hash algorithm
	SHA256 HashAlgorithm = "sha256"
	// SHA512 is the SHA-512 hash algorithm
	SHA512 HashAlgorithm = "sha512"
)

// ProcessHashCache caches executable hashes to reduce disk I/O
type ProcessHashCache struct {
	cache     map[string]string // Path -> hash mapping
	algorithm HashAlgorithm     // Hash algorithm in use
	mu        sync.RWMutex      // Mutex for concurrent access
	maxSize   int               // Maximum cache size
	expiry    time.Duration     // Cache entry expiry
	lastCheck map[string]time.Time // Last check time for each path
}

// NewProcessHashCache creates a new process hash cache
func NewProcessHashCache(algorithm HashAlgorithm, maxSize int, expiry time.Duration) *ProcessHashCache {
	return &ProcessHashCache{
		cache:     make(map[string]string),
		algorithm: algorithm,
		maxSize:   maxSize,
		expiry:    expiry,
		lastCheck: make(map[string]time.Time),
	}
}

// Get retrieves a hash from the cache or computes it if not present
func (c *ProcessHashCache) Get(path string) (string, error) {
	// Normalize the path
	normalizedPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to normalize path: %w", err)
	}
	path = normalizedPath

	// Check cache first
	c.mu.RLock()
	hash, ok := c.cache[path]
	lastCheck := c.lastCheck[path]
	c.mu.RUnlock()

	// If found and not expired, return from cache
	if ok && time.Since(lastCheck) < c.expiry {
		return hash, nil
	}

	// Compute hash
	hash, err = computeFileHash(path, c.algorithm)
	if err != nil {
		return "", err
	}

	// Update cache
	c.mu.Lock()
	defer c.mu.Unlock()

	// Enforce cache size limit with basic LRU (remove oldest entries)
	if len(c.cache) >= c.maxSize {
		var oldestPath string
		var oldestTime time.Time
		
		// Initialize with first entry
		for p, t := range c.lastCheck {
			oldestPath = p
			oldestTime = t
			break
		}
		
		// Find oldest entry
		for p, t := range c.lastCheck {
			if t.Before(oldestTime) {
				oldestPath = p
				oldestTime = t
			}
		}
		
		// Remove oldest entry
		delete(c.cache, oldestPath)
		delete(c.lastCheck, oldestPath)
	}

	// Add new entry
	c.cache[path] = hash
	c.lastCheck[path] = time.Now()

	return hash, nil
}

// Clear empties the cache
func (c *ProcessHashCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache = make(map[string]string)
	c.lastCheck = make(map[string]time.Time)
}

// computeFileHash generates a hash for the specified file
func computeFileHash(path string, algorithm HashAlgorithm) (string, error) {
	// Open the file for reading
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrExecutableNotFound
		}
		if os.IsPermission(err) {
			return "", ErrPermissionDenied
		}
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Choose hash algorithm
	var hash io.Writer
	
	switch algorithm {
	case SHA256:
		h := sha256.New()
		hash = h
		defer func() {
			if err == nil {
				err = nil // Placeholder for any cleanup needed
			}
		}()
	case SHA512:
		h := sha512.New()
		hash = h
		defer func() {
			if err == nil {
				err = nil // Placeholder for any cleanup needed
			}
		}()
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	// Compute hash
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	// Return hash as hex string
	var hashBytes []byte
	
	switch algorithm {
	case SHA256:
		hashBytes = hash.(interface{ Sum([]byte) []byte }).Sum(nil)
	case SHA512:
		hashBytes = hash.(interface{ Sum([]byte) []byte }).Sum(nil)
	}
	
	return hex.EncodeToString(hashBytes), nil
}

// ProcessVerifier verifies process identity and integrity
type ProcessVerifier struct {
	logger    *logging.Logger
	hashCache *ProcessHashCache
	// Known good hashes for applications
	knownHashes map[string]map[string]string // app name -> path -> hash
	mu          sync.RWMutex
}

// NewProcessVerifier creates a new process verifier
func NewProcessVerifier(logger *logging.Logger) *ProcessVerifier {
	return &ProcessVerifier{
		logger: logger,
		hashCache: NewProcessHashCache(
			SHA256,          // Use SHA-256 by default
			100,             // Cache up to 100 entries
			10*time.Minute,  // Cache expires after 10 minutes
		),
		knownHashes: make(map[string]map[string]string),
	}
}

// AddKnownHash adds a known good hash for an application
func (v *ProcessVerifier) AddKnownHash(appName, path, hash string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	
	// Initialize inner map if not exists
	if _, ok := v.knownHashes[appName]; !ok {
		v.knownHashes[appName] = make(map[string]string)
	}
	
	// Add hash
	v.knownHashes[appName][path] = hash
	v.logger.Debugf("Added known hash for %s at %s: %s", appName, path, hash)
}

// VerifyProcess verifies a process based on its path and executable hash
func (v *ProcessVerifier) VerifyProcess(pid int, appName string) error {
	// Get process information
	procInfo, err := GetProcessInfo(pid)
	if err != nil {
		return fmt.Errorf("failed to get process info: %w", err)
	}
	
	// Get process executable path
	execPath := procInfo.Command
	
	// Verify path against expected paths
	v.mu.RLock()
	pathMap, ok := v.knownHashes[appName]
	v.mu.RUnlock()
	
	if !ok {
		// No known hashes for this app, fall back to simple basename comparison
		baseName := filepath.Base(execPath)
		if baseName != appName && baseName != appName+".exe" {
			return fmt.Errorf("%w: expected %s, got %s", 
				ErrPathMismatch, appName, baseName)
		}
		
		// Log warning about falling back to simple name matching
		v.logger.Warnf("No known hashes for %s, falling back to name matching", appName)
		return nil
	}
	
	// Check if path is among known paths
	var pathMatched bool
	var matchedPath string
	
	for knownPath := range pathMap {
		// Use simple substring matching to handle path variations
		if strings.HasSuffix(execPath, knownPath) {
			pathMatched = true
			matchedPath = knownPath
			break
		}
	}
	
	if !pathMatched {
		return fmt.Errorf("%w: path %s not recognized for %s", 
			ErrPathMismatch, execPath, appName)
	}
	
	// Get expected hash
	expectedHash := pathMap[matchedPath]
	
	// If no hash defined, skip hash verification
	if expectedHash == "" {
		v.logger.Debugf("No hash defined for %s at %s, skipping hash verification", 
			appName, matchedPath)
		return nil
	}
	
	// Compute hash of the executable
	actualHash, err := v.hashCache.Get(execPath)
	if err != nil {
		if errors.Is(err, ErrPermissionDenied) {
			v.logger.Warnf("Permission denied when hashing %s: %v", execPath, err)
			return fmt.Errorf("%w: %v", ErrPermissionDenied, err)
		}
		if errors.Is(err, ErrExecutableNotFound) {
			v.logger.Warnf("Executable not found: %s", execPath)
			return fmt.Errorf("%w: %v", ErrExecutableNotFound, err)
		}
		return fmt.Errorf("failed to hash executable: %w", err)
	}
	
	// Compare hash
	if actualHash != expectedHash {
		v.logger.Warnf("Hash mismatch for %s: expected %s, got %s", 
			execPath, expectedHash, actualHash)
		return fmt.Errorf("%w: hash mismatch for %s", ErrHashMismatch, execPath)
	}
	
	v.logger.Debugf("Successfully verified process %d (%s): path and hash match", 
		pid, appName)
	return nil
}

// GetProcessInfo retrieves information about a process by PID
func GetProcessInfo(pid int) (*ProcessInfo, error) {
	// Construct paths to proc files
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	
	// Read the executable path
	execPath, err := os.Readlink(exePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("process %d no longer exists", pid)
		}
		if os.IsPermission(err) {
			return nil, fmt.Errorf("permission denied when accessing process %d", pid)
		}
		return nil, fmt.Errorf("failed to read executable path: %w", err)
	}
	
	// Read the command line
	cmdlineBytes, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read command line: %w", err)
	}
	
	// Command line arguments are separated by null bytes
	cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
	
	// Read stat file to get parent PID and state
	statBytes, err := os.ReadFile(statPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read stat file: %w", err)
	}
	
	// Parse stat file (format is complicated, we just need a few fields)
	statFields := strings.Fields(string(statBytes))
	
	// Check if we have enough fields
	if len(statFields) < 5 {
		return nil, fmt.Errorf("invalid stat file format for process %d", pid)
	}
	
	// Get process state (field 3)
	state := statFields[2]
	
	// Get parent PID (field 4)
	var ppid int
	_, err = fmt.Sscanf(statFields[3], "%d", &ppid)
	if err != nil {
		return nil, fmt.Errorf("failed to parse parent PID: %w", err)
	}
	
	// Return process info
	return &ProcessInfo{
		PID:       pid,
		Command:   execPath,
		ExecHash:  "", // Will be computed on demand
		ParentPID: ppid,
		CmdLine:   cmdline,
		State:     processStateFromString(state),
	}, nil
}

// processStateFromString converts a proc state character to our state string
func processStateFromString(state string) string {
	switch state {
	case "R":
		return ProcessStateRunning
	case "S", "D":
		return ProcessStateRunning // Sleeping/waiting are still "running" for our purposes
	case "T":
		return ProcessStateSuspended
	case "Z", "X":
		return ProcessStateTerminated
	default:
		return "unknown"
	}
} 