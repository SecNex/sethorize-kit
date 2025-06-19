package helper

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2 struct {
	Params *Argon2Params
}

type Argon2Params struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func NewArgon2Default() *Argon2 {
	return &Argon2{
		Params: &Argon2Params{
			Memory:      64 * 1024, // 64 MB
			Time:        2,
			Parallelism: 4,
			SaltLength:  16,
			KeyLength:   32,
		},
	}
}

func (a *Argon2) ExtractParams(hash string) (*Argon2Params, []byte, []byte, error) {
	// Format: $argon2id$v=19$m=65536,t=2,p=4$base64(salt)$base64(hash)
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return nil, nil, nil, fmt.Errorf("ungültiges Argon2-Hash-Format")
	}

	// Parse parameter string (m=65536,t=2,p=4)
	paramParts := strings.Split(parts[3], ",")
	if len(paramParts) != 3 {
		return nil, nil, nil, fmt.Errorf("ungültige Parameter")
	}

	var memory uint32
	var time uint32
	var parallelism uint8

	for _, param := range paramParts {
		kv := strings.Split(param, "=")
		if len(kv) != 2 {
			return nil, nil, nil, fmt.Errorf("ungültiges Parameter-Format")
		}

		switch kv[0] {
		case "m":
			val, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return nil, nil, nil, err
			}
			memory = uint32(val)
		case "t":
			val, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return nil, nil, nil, err
			}
			time = uint32(val)
		case "p":
			val, err := strconv.ParseUint(kv[1], 10, 8)
			if err != nil {
				return nil, nil, nil, err
			}
			parallelism = uint8(val)
		}
	}

	// Decode salt and hash
	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}

	hashBytes, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}

	params := &Argon2Params{
		Memory:      memory,
		Time:        time,
		Parallelism: parallelism,
		SaltLength:  uint32(len(salt)),
		KeyLength:   uint32(len(hashBytes)),
	}

	return params, salt, hashBytes, nil
}

func (a *Argon2) Compare(password string, hash string) (bool, error) {
	params, salt, expectedHash, err := a.ExtractParams(hash)
	if err != nil {
		return false, err
	}

	// Hash das eingegebene Passwort mit den extrahierten Parametern
	computedHash := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Parallelism, params.KeyLength)

	// Vergleiche die Hashes
	if len(computedHash) != len(expectedHash) {
		return false, nil
	}

	for i := range computedHash {
		if computedHash[i] != expectedHash[i] {
			return false, nil
		}
	}

	return true, nil
}

func (a *Argon2) Hash(password string) (string, error) {
	// Generiere zufälliges Salt
	salt := make([]byte, a.Params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Generiere Hash
	hash := argon2.IDKey([]byte(password), salt, a.Params.Time, a.Params.Memory, a.Params.Parallelism, a.Params.KeyLength)

	// Encodiere Salt und Hash
	encodedSalt := base64.StdEncoding.EncodeToString(salt)
	encodedHash := base64.StdEncoding.EncodeToString(hash)

	// Erstelle Standard Argon2-Format
	result := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		a.Params.Memory,
		a.Params.Time,
		a.Params.Parallelism,
		encodedSalt,
		encodedHash,
	)

	return result, nil
}
