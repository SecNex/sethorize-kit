package auth

import (
	"github.com/secnex/sethorize-kit/handler"
	"github.com/secnex/sethorize-kit/helper"
	"gorm.io/gorm"
)

type AuthHandler struct {
	Handler    *handler.Handler
	KeyManager *helper.KeyManager
}

func NewAuthHandler(db *gorm.DB, keyManager *helper.KeyManager) *AuthHandler {
	return &AuthHandler{
		Handler:    handler.NewHandler(db),
		KeyManager: keyManager,
	}
}
