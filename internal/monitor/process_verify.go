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
	"strconv"
	"strings"
	"sync"
	"time"

	appErrors "wyrmlock/internal/errors"
	"wyrmlock/internal/logging"

	"github.com/ZanzyTHEbar/errbuilder-go"
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
	var errs errbuilder.ErrorMap

	normalizedPath, err := filepath.Abs(path)
	if err != nil {
		errs.Set("path", path)
		return "", appErrors.WithDetails(
			appErrors.MonitorError(fmt.Sprintf("failed to normalize path: %v", err)),
			errs,
		)
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
			var errs errbuilder.ErrorMap
			errs.Set("path", path)
			errs.Set("error_type", "not_found")
			return "", appErrors.WithDetails(
				appErrors.ProcessVerificationError("executable not found"),
				errs,
			)
		}
		if os.IsPermission(err) {
			var errs errbuilder.ErrorMap
			errs.Set("path", path)
			errs.Set("error_type", "permission_denied")
			return "", appErrors.WithDetails(
				appErrors.PermissionDenied("permission denied when accessing executable"),
				errs,
			)
		}
		var errs errbuilder.ErrorMap
		errs.Set("path", path)
		errs.Set("error_type", "file_access")
		return "", appErrors.WithDetails(
			appErrors.MonitorError(fmt.Sprintf("failed to open file: %v", err)),
			errs,
		)
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
		var errs errbuilder.ErrorMap
		errs.Set("algorithm", string(algorithm))
		errs.Set("supported_algorithms", "sha256,sha512")
		return "", appErrors.WithDetails(
			appErrors.MonitorError(fmt.Sprintf("unsupported hash algorithm: %s", algorithm)),
			errs,
		)
	}

	// Compute hash
	if _, err := io.Copy(hash, file); err != nil {
		var errs errbuilder.ErrorMap
		errs.Set("path", path)
		errs.Set("algorithm", string(algorithm))
		return "", appErrors.WithDetails(
			appErrors.MonitorError(fmt.Sprintf("failed to hash file: %v", err)),
			errs,
		)
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
		var errs errbuilder.ErrorMap
		errs.Set("pid", fmt.Sprintf("%d", pid))
		errs.Set("app_name", appName)
		return appErrors.WithDetails(
			appErrors.ProcessVerificationError(fmt.Sprintf("failed to get process info: %v", err)),
			errs,
		)
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
			var errs errbuilder.ErrorMap
			errs.Set("pid", fmt.Sprintf("%d", pid))
			errs.Set("app_name", appName)
			errs.Set("exec_path", execPath)
			errs.Set("base_name", baseName)
			errs.Set("verification_type", "name")
			return appErrors.WithDetails(
				appErrors.ProcessVerificationError(fmt.Sprintf("expected %s, got %s", appName, baseName)),
				errs,
			)
		}
		
		v.logger.Debugf("Process %d verified by name (%s)", pid, baseName)
		return nil
	}
	
	// Check if the exact path is expected
	knownHash, pathMatch := pathMap[execPath]
	
	// If there's no exact path match, try normalized path comparisons
	if !pathMatch {
		foundMatch := false
		
		for knownPath := range pathMap {
			// Check for same basename (simple case)
			if filepath.Base(knownPath) == filepath.Base(execPath) {
				knownHash = pathMap[knownPath]
				foundMatch = true
				break
			}
			
			// Check for relative path match (more complex case)
			knownPathRel, err1 := filepath.Rel("/", knownPath)
			execPathRel, err2 := filepath.Rel("/", execPath)
			
			if err1 == nil && err2 == nil && knownPathRel == execPathRel {
				knownHash = pathMap[knownPath]
				foundMatch = true
				break
			}
		}
		
		if !foundMatch {
			var errs errbuilder.ErrorMap
			errs.Set("pid", fmt.Sprintf("%d", pid))
			errs.Set("app_name", appName)
			errs.Set("exec_path", execPath)
			errs.Set("known_paths", fmt.Sprintf("%v", pathMap))
			errs.Set("verification_type", "path")
			return appErrors.WithDetails(
				appErrors.ProcessVerificationError(fmt.Sprintf("path %s not recognized for %s", execPath, appName)),
				errs,
			)
		}
	}
	
	// If we have a hash to verify against, compute the actual hash
	if knownHash != "" {
		// Compute hash of the executable
		actualHash, err := v.hashCache.Get(execPath)
		if err != nil {
			// Check for specific error types
			if errors.Is(err, ErrPermissionDenied) {
				var errs errbuilder.ErrorMap
				errs.Set("pid", fmt.Sprintf("%d", pid))
				errs.Set("app_name", appName)
				errs.Set("exec_path", execPath)
				return appErrors.WithDetails(
					appErrors.PermissionDenied(fmt.Sprintf("permission denied when verifying process: %v", err)),
					errs,
				)
			}
			
			if errors.Is(err, ErrExecutableNotFound) {
				var errs errbuilder.ErrorMap
				errs.Set("pid", fmt.Sprintf("%d", pid))
				errs.Set("app_name", appName)
				errs.Set("exec_path", execPath)
				return appErrors.WithDetails(
					appErrors.ProcessVerificationError(fmt.Sprintf("executable not found: %v", err)),
					errs,
				)
			}
			
			var errs errbuilder.ErrorMap
			errs.Set("pid", fmt.Sprintf("%d", pid))
			errs.Set("app_name", appName)
			errs.Set("exec_path", execPath)
			return appErrors.WithDetails(
				appErrors.MonitorError(fmt.Sprintf("failed to hash executable: %v", err)),
				errs,
			)
		}
		
		// Compare hashes
		if actualHash != knownHash {
			v.logger.Warnf("Hash mismatch for %s (PID %d): expected %s, got %s",
				execPath, pid, knownHash, actualHash)
				
			var errs errbuilder.ErrorMap
			errs.Set("pid", fmt.Sprintf("%d", pid))
			errs.Set("app_name", appName)
			errs.Set("exec_path", execPath)
			errs.Set("expected_hash", knownHash)
			errs.Set("actual_hash", actualHash)
			errs.Set("verification_type", "hash")
			return appErrors.WithDetails(
				appErrors.ProcessVerificationError(fmt.Sprintf("hash mismatch for %s", execPath)),
				errs,
			)
		}
		
		v.logger.Debugf("Process %d verified by hash (%s: %s)", pid, execPath, actualHash)
	} else {
		// No hash available, verified by path only
		v.logger.Debugf("Process %d verified by path only (%s)", pid, execPath)
	}
	
	return nil
}

// GetProcessInfo retrieves detailed information about a process
func GetProcessInfo(pid int) (*ProcessInfo, error) {
	// Get process executable path
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		if os.IsNotExist(err) {
			var errs errbuilder.ErrorMap
			errs.Set("pid", fmt.Sprintf("%d", pid))
			return nil, appErrors.WithDetails(
				appErrors.NotFound(fmt.Sprintf("process %d no longer exists", pid)),
				errs,
			)
		}
		if os.IsPermission(err) {
			var errs errbuilder.ErrorMap
			errs.Set("pid", fmt.Sprintf("%d", pid))
			return nil, appErrors.WithDetails(
				appErrors.PermissionDenied(fmt.Sprintf("permission denied when accessing process %d", pid)),
				errs,
			)
		}
		var errs errbuilder.ErrorMap
		errs.Set("pid", fmt.Sprintf("%d", pid))
		return nil, appErrors.WithDetails(
			appErrors.MonitorError(fmt.Sprintf("failed to read executable path: %v", err)),
			errs,
		)
	}

	// Read command line
	cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		var errs errbuilder.ErrorMap
		errs.Set("pid", fmt.Sprintf("%d", pid))
		return nil, appErrors.WithDetails(
			appErrors.MonitorError(fmt.Sprintf("failed to read command line: %v", err)),
			errs,
		)
	}

	// Replace null bytes with spaces for a more readable cmdline
	cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)

	// Read process stat file for more information
	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		var errs errbuilder.ErrorMap
		errs.Set("pid", fmt.Sprintf("%d", pid))
		return nil, appErrors.WithDetails(
			appErrors.MonitorError(fmt.Sprintf("failed to read stat file: %v", err)),
			errs,
		)
	}

	// Parse stat file
	statParts := strings.Fields(string(statBytes))
	if len(statParts) < 5 {
		var errs errbuilder.ErrorMap
		errs.Set("pid", fmt.Sprintf("%d", pid))
		errs.Set("stat_parts_count", fmt.Sprintf("%d", len(statParts)))
		return nil, appErrors.WithDetails(
			appErrors.MonitorError(fmt.Sprintf("invalid stat file format for process %d", pid)),
			errs,
		)
	}

	// Extract parent PID from stat file
	ppid, err := strconv.Atoi(statParts[3])
	if err != nil {
		var errs errbuilder.ErrorMap
		errs.Set("pid", fmt.Sprintf("%d", pid))
		errs.Set("ppid_str", statParts[3])
		return nil, appErrors.WithDetails(
			appErrors.MonitorError(fmt.Sprintf("failed to parse parent PID: %v", err)),
			errs,
		)
	}

	// Get process state
	state := processStateFromString(statParts[2])

	return &ProcessInfo{
		PID:       pid,
		Command:   exePath,
		ExecHash:  "", // Hash is not computed by default to avoid expensive I/O
		ParentPID: ppid,
		Allowed:   false, // Default to false, should be set by caller
		StartTime: time.Now().Unix(),
		CmdLine:   cmdline,
		State:     state,
	}, nil
}

// processStateFromString converts a /proc/[pid]/stat state character to a readable state string
func processStateFromString(state string) string {
	switch state {
	case "R":
		return ProcessStateRunning
	case "S", "D":
		return ProcessStateRunning // Sleeping or waiting, still considered running
	case "T":
		return ProcessStateSuspended
	case "Z", "X":
		return ProcessStateTerminated
	default:
		return ProcessStateRunning // Default to running for unknown states
	}
} 