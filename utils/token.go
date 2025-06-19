package utils

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateToken(length int) string {
	token := make([]byte, length)
	rand.Read(token)
	return base64.StdEncoding.EncodeToString(token)
}
