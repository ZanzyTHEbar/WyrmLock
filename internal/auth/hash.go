package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// compareBcrypt compares a plaintext password with a bcrypt hash
func compareBcrypt(password, hash []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(hash, password)
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("bcrypt comparison error: %w", err)
	}
	return true, nil
}

// compareArgon2id compares a plaintext password with an argon2id hash
// Format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
func compareArgon2id(password, encodedHash []byte) (bool, error) {
	parts := strings.Split(string(encodedHash), "$")
	if len(parts) != 6 {
		return false, errors.New("invalid argon2id hash format")
	}

	if parts[1] != "argon2id" {
		return false, errors.New("invalid hash type")
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, errors.New("invalid hash version")
	}

	if version != 19 {
		return false, errors.New("incompatible argon2id version")
	}

	// Parse params
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false, errors.New("invalid hash parameters")
	}

	var memory uint32
	var time uint32
	var threads uint8

	_, err = fmt.Sscanf(params[0], "m=%d", &memory)
	if err != nil {
		return false, errors.New("invalid memory parameter")
	}

	_, err = fmt.Sscanf(params[1], "t=%d", &time)
	if err != nil {
		return false, errors.New("invalid time parameter")
	}

	_, err = fmt.Sscanf(params[2], "p=%d", &threads)
	if err != nil {
		return false, errors.New("invalid threads parameter")
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	// Compute hash for comparison
	computedHash := argon2.IDKey(password, salt, time, memory, threads, uint32(len(decodedHash)))

	// Time-constant comparison
	return subtle.ConstantTimeCompare(decodedHash, computedHash) == 1, nil
}

// compareScrypt compares a plaintext password with a scrypt hash
// Format: $scrypt$N=<N>,r=<r>,p=<p>$<salt>$<hash>
func compareScrypt(password, encodedHash []byte) (bool, error) {
	parts := strings.Split(string(encodedHash), "$")
	if len(parts) != 5 {
		return false, errors.New("invalid scrypt hash format")
	}

	if parts[1] != "scrypt" {
		return false, errors.New("invalid hash type")
	}

	// Parse params
	params := strings.Split(parts[2], ",")
	if len(params) != 3 {
		return false, errors.New("invalid hash parameters")
	}

	var n, r, p int
	_, err := fmt.Sscanf(params[0], "N=%d", &n)
	if err != nil {
		return false, errors.New("invalid N parameter")
	}

	_, err = fmt.Sscanf(params[1], "r=%d", &r)
	if err != nil {
		return false, errors.New("invalid r parameter")
	}

	_, err = fmt.Sscanf(params[2], "p=%d", &p)
	if err != nil {
		return false, errors.New("invalid p parameter")
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	// Compute hash for comparison
	computedHash, err := scrypt.Key(password, salt, 1<<uint(n), r, p, len(decodedHash))
	if err != nil {
		return false, fmt.Errorf("scrypt computation error: %w", err)
	}

	// Time-constant comparison
	return subtle.ConstantTimeCompare(decodedHash, computedHash) == 1, nil
}

// comparePBKDF2 compares a plaintext password with a PBKDF2 hash
// Format: $pbkdf2-sha256$iterations=<i>$<salt>$<hash>
func comparePBKDF2(password, encodedHash []byte) (bool, error) {
	parts := strings.Split(string(encodedHash), "$")
	if len(parts) != 5 {
		return false, errors.New("invalid PBKDF2 hash format")
	}

	if parts[1] != "pbkdf2-sha256" {
		return false, errors.New("invalid hash type or algorithm")
	}

	// Parse iterations
	var iterations int
	_, err := fmt.Sscanf(parts[2], "iterations=%d", &iterations)
	if err != nil {
		return false, errors.New("invalid iterations parameter")
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	// Compute hash for comparison
	computedHash := pbkdf2.Key(password, salt, iterations, len(decodedHash), sha256.New)

	// Time-constant comparison
	return subtle.ConstantTimeCompare(decodedHash, computedHash) == 1, nil
}

// Create hash functions for traditional authentication

// GenerateHash creates a password hash using the specified algorithm
func GenerateHash(password []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case "bcrypt":
		return generateBcryptHash(password)
	case "argon2id":
		return generateArgon2idHash(password)
	case "scrypt":
		return generateScryptHash(password)
	case "pbkdf2":
		return generatePBKDF2Hash(password)
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// generateBcryptHash creates a bcrypt hash of a password
func generateBcryptHash(password []byte) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bcrypt hash: %w", err)
	}
	return hash, nil
}

// generateArgon2idHash creates an argon2id hash of a password
func generateArgon2idHash(password []byte) ([]byte, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Parameters for argon2id
	const memory = 65536  // 64MB
	const iterations = 3  // Number of iterations
	const parallelism = 2 // Number of parallel threads
	const keyLength = 32  // Length of the derived key

	// Generate hash
	hash := argon2.IDKey(password, salt, iterations, memory, parallelism, keyLength)

	// Format the result as: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	encodedHash := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, iterations, parallelism, saltB64, hashB64)

	return []byte(encodedHash), nil
}

// generateScryptHash creates a scrypt hash of a password
func generateScryptHash(password []byte) ([]byte, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Parameters for scrypt
	const n = 16384   // CPU/memory cost parameter (N)
	const r = 8       // Block size parameter (r)
	const p = 1       // Parallelization parameter (p)
	const keyLen = 32 // Length of the derived key

	// Generate hash
	hash, err := scrypt.Key(password, salt, n, r, p, keyLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate scrypt hash: %w", err)
	}

	// Format as: $scrypt$N=%d,r=%d,p=%d$%s$%s
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	encodedHash := fmt.Sprintf("$scrypt$N=%d,r=%d,p=%d$%s$%s",
		n, r, p, saltB64, hashB64)

	return []byte(encodedHash), nil
}

// generatePBKDF2Hash creates a PBKDF2-SHA256 hash of a password
func generatePBKDF2Hash(password []byte) ([]byte, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Parameters for PBKDF2
	const iterations = 100000 // Number of iterations
	const keyLen = 32         // Length of the derived key

	// Generate hash
	hash := pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)

	// Format as: $pbkdf2-sha256$iterations=%d$%s$%s
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	encodedHash := fmt.Sprintf("$pbkdf2-sha256$iterations=%d$%s$%s",
		iterations, saltB64, hashB64)

	return []byte(encodedHash), nil
}
