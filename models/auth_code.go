package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/secnex/sethorize-kit/helper"
	"gorm.io/gorm"
)

type AuthCode struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ClientID    uuid.UUID      `gorm:"type:uuid;not null"`
	UserID      uuid.UUID      `gorm:"type:uuid;not null"`
	Code        string         `gorm:"type:varchar(255);not null"`
	Scopes      pq.StringArray `gorm:"type:text[]" json:"scopes"`
	RedirectURI string         `gorm:"type:varchar(255);not null"`
	UsedAt      time.Time      `gorm:"type:timestamp;default:null"`
	CreatedAt   time.Time      `gorm:"autoCreateTime"`
	ExpiresAt   time.Time      `gorm:"type:timestamp;not null"`
}

func (AuthCode) TableName() string {
	return "auth_codes"
}

func (a *AuthCode) BeforeCreate(tx *gorm.DB) (err error) {
	a.ExpiresAt = time.Now().Add(time.Minute * 5)

	argon2 := helper.NewArgon2Default()
	hash, err := argon2.Hash(a.Code)
	if err != nil {
		return err
	}
	a.Code = hash
	return
}
