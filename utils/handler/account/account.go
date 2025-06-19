package account

import (
	"github.com/secnex/sethorize-kit/handler"
	"github.com/secnex/sethorize-kit/helper"
	"gorm.io/gorm"
)

type AccountHandler struct {
	Handler    *handler.Handler
	KeyManager *helper.KeyManager
}

func NewAccountHandler(db *gorm.DB, keyManager *helper.KeyManager) *AccountHandler {
	return &AccountHandler{
		Handler:    handler.NewHandler(db),
		KeyManager: keyManager,
	}
}
